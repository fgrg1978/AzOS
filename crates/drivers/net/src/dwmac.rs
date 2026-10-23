// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Synopsys DesignWare Ethernet QoS MAC (the "dwmac 4.x/5.x" core, Linux
//! `stmmac`'s `dwmac4` family): one DMA channel, one MTL queue pair, the
//! station management (MDIO) interface and the PHY behind it.
//!
//! First user: the VisionFive 2's `gmac0` (`starfive,jh7110-dwmac`, compatible
//! `snps,dwmac-5.20`, `jh7110.dtsi` `ethernet@16030000`), wired to a Motorcomm
//! YT8531 RGMII PHY at MDIO address 0 (`jh7110-common.dtsi`, `phy0`), the
//! brain link without the ESP32 bridge. The driver is generic over the
//! register window ([`Hw`]) and the DMA domain ([`DmaOps`]), so the whole
//! bring-up sequence, the descriptor rings and the MDIO/PHY state machine run
//! on the host against a model of the device (`tests/host/drivers-tests`,
//! `dwmac_tests.rs`); [`board`] (feature `vf2`) is the statics, the interrupt
//! hook and the [`NetDevice`] face the kernel uses.
//!
//! # What the DTS settles, and what it does not
//!
//! From `jh7110.dtsi` `gmac0`: `rx-fifo-depth`/`tx-fifo-depth` = 2048,
//! `snps,fixed-burst`, `snps,no-pbl-x8`, `snps,force_thresh_dma_mode`,
//! `snps,txpbl`/`rxpbl` = 16, `snps,axi-config` (`blen` 256/128/64/32,
//! `wr_osr_lmt`/`rd_osr_lmt` = 15), one `macirq` = PLIC source 7. From the
//! board: `phy-mode = "rgmii-id"`, PHY address 0. All of that is encoded in
//! [`Config::JH7110_GMAC0`].
//!
//! The register offsets, bit positions and descriptor layouts below are the
//! DWC Ethernet QoS databook's, as Linux names them in
//! `drivers/net/ethernet/stmicro/stmmac/{dwmac4.h,dwmac4_dma.h,
//! dwmac4_descs.h}` (and `dwmac-starfive.c`, plus `drivers/net/phy/motorcomm.c`
//! for the YT8531). **[verify]** The pinned Linux tree's
//! sparse set did not carry those files when this was written, so the
//! constants are recalled, not read: once the tree has them, diff every
//! constant in [`reg`], [`mac`], [`dma`] and [`desc`] against them. The core's
//! `MAC_VERSION` is checked at init, so a window that is not this IP is
//! refused instead of being written to.
//!
//! # Cache coherence
//!
//! The JH7110's DMA masters are not coherent with the CPU (`azos_dma::cache`).
//! A cache line holds four 16-byte descriptors, and the device writes the
//! status of one while the CPU writes the next: cleaning a shared line would
//! write the CPU's stale copy over the device's write-back. So every descriptor
//! sits alone in a [`DESC_STRIDE`]-byte line and the channel is told to skip
//! the rest (`DSL`, [`dsl_words`]); every buffer is line-aligned and a whole
//! number of lines. Each hand-over is bracketed by the `DmaOps` sync calls, and
//! the host test asserts their order against the register writes.
//!
//! # Not done here
//!
//! The clock and reset enables (`aoncrg` GMAC0 AXI/AHB), the `aon_syscon`
//! interface-mode select and the TX-clock mux (`starfive,tx-use-rgmii-clk`)
//! belong to the SoC framework (`azos_drv_soc`), and the YT8531's RGMII delay
//! and drive-strength registers (`rx-internal-delay-ps` etc. in the board DTS)
//! to a PHY driver that has `motorcomm.c` to read. Until then the driver relies
//! on what the boot firmware left running and on the PHY's strapped defaults.

use azos_dma::Direction;
use azos_drv_api::net::{NetError, ETH_FRAME_MAX};

// ── Register map ────────────────────────────────────────────────────────

/// Offsets from the window base. **[verify]** against `dwmac4.h` /
/// `dwmac4_dma.h`.
pub mod reg {
    pub const MAC_CONFIGURATION: usize = 0x000;
    pub const MAC_PACKET_FILTER: usize = 0x008;
    pub const MAC_Q0_TX_FLOW_CTRL: usize = 0x070;
    pub const MAC_RX_FLOW_CTRL: usize = 0x090;
    pub const MAC_RXQ_CTRL0: usize = 0x0A0;
    pub const MAC_INTERRUPT_ENABLE: usize = 0x0B4;
    pub const MAC_VERSION: usize = 0x110;
    pub const MAC_MDIO_ADDRESS: usize = 0x200;
    pub const MAC_MDIO_DATA: usize = 0x204;
    pub const MAC_ADDRESS0_HIGH: usize = 0x300;
    pub const MAC_ADDRESS0_LOW: usize = 0x304;

    pub const MTL_OPERATION_MODE: usize = 0xC00;
    pub const MTL_TXQ0_OPERATION_MODE: usize = 0xD00;
    pub const MTL_RXQ0_OPERATION_MODE: usize = 0xD30;

    pub const DMA_MODE: usize = 0x1000;
    pub const DMA_SYSBUS_MODE: usize = 0x1004;
    pub const DMA_CH0_CONTROL: usize = 0x1100;
    pub const DMA_CH0_TX_CONTROL: usize = 0x1104;
    pub const DMA_CH0_RX_CONTROL: usize = 0x1108;
    pub const DMA_CH0_TXDESC_HADDR: usize = 0x1110;
    pub const DMA_CH0_TXDESC_LADDR: usize = 0x1114;
    pub const DMA_CH0_RXDESC_HADDR: usize = 0x1118;
    pub const DMA_CH0_RXDESC_LADDR: usize = 0x111C;
    pub const DMA_CH0_TXDESC_TAIL: usize = 0x1120;
    pub const DMA_CH0_RXDESC_TAIL: usize = 0x1128;
    pub const DMA_CH0_TXDESC_LEN: usize = 0x112C;
    pub const DMA_CH0_RXDESC_LEN: usize = 0x1130;
    pub const DMA_CH0_INTR_ENA: usize = 0x1134;
    pub const DMA_CH0_STATUS: usize = 0x1160;

    /// Bytes of register window the driver touches (the DTS `reg` is 64 KiB;
    /// the last register used ends below this).
    pub const WINDOW: usize = 0x2000;
}

/// `MAC_CONFIGURATION`, `MAC_PACKET_FILTER`, `MAC_RXQ_CTRL0`, `MAC_VERSION`,
/// `MAC_MDIO_ADDRESS`.
pub mod mac {
    pub const CFG_RE: u32 = 1 << 0;
    pub const CFG_TE: u32 = 1 << 1;
    pub const CFG_DM: u32 = 1 << 13;
    pub const CFG_FES: u32 = 1 << 14;
    pub const CFG_PS: u32 = 1 << 15;
    /// Strip the pad and the FCS of every received frame.
    pub const CFG_CST: u32 = 1 << 21;
    pub const CFG_ACS: u32 = 1 << 20;

    /// Pass all multicast frames (ARP is broadcast, but IPv6 and mDNS are
    /// multicast and the stack filters).
    pub const FILTER_PM: u32 = 1 << 4;

    /// RX queue 0 enabled for generic/DCB use.
    pub const RXQ0_DCB: u32 = 2;

    pub const VERSION_SNPS_MASK: u32 = 0xFF;
    /// The first core with the dwmac4 register map (4.00).
    pub const VERSION_MIN: u32 = 0x40;

    pub const MDIO_GB: u32 = 1 << 0;
    pub const MDIO_GOC_SHIFT: u32 = 2;
    pub const MDIO_GOC_WRITE: u32 = 1 << MDIO_GOC_SHIFT;
    pub const MDIO_GOC_READ: u32 = 3 << MDIO_GOC_SHIFT;
    pub const MDIO_CR_SHIFT: u32 = 8;
    pub const MDIO_RDA_SHIFT: u32 = 16;
    pub const MDIO_PA_SHIFT: u32 = 21;
}

/// MTL queue and DMA channel fields.
pub mod dma {
    pub const MODE_SWR: u32 = 1 << 0;

    pub const SYSBUS_FB: u32 = 1 << 0;
    pub const SYSBUS_BLEN_32: u32 = 1 << 4;
    pub const SYSBUS_BLEN_64: u32 = 1 << 5;
    pub const SYSBUS_BLEN_128: u32 = 1 << 6;
    pub const SYSBUS_BLEN_256: u32 = 1 << 7;
    pub const SYSBUS_RD_OSR_SHIFT: u32 = 16;
    pub const SYSBUS_WR_OSR_SHIFT: u32 = 24;

    /// `DMA_CH0_CONTROL.DSL`: words skipped between descriptors.
    pub const CTRL_DSL_SHIFT: u32 = 18;
    pub const CTRL_DSL_MAX: u32 = 7;

    pub const TX_CTRL_ST: u32 = 1 << 0;
    /// Operate on a second frame before the first one's status is written.
    pub const TX_CTRL_OSF: u32 = 1 << 4;
    pub const TX_CTRL_PBL_SHIFT: u32 = 16;

    pub const RX_CTRL_SR: u32 = 1 << 0;
    pub const RX_CTRL_RBSZ_SHIFT: u32 = 1;
    pub const RX_CTRL_RBSZ_MASK: u32 = 0x3FFF << 1;
    pub const RX_CTRL_PBL_SHIFT: u32 = 16;

    /// `DMA_CH0_INTR_ENA` / `DMA_CH0_STATUS` (the 4.10+ positions of the
    /// summary bits: normal 15, abnormal 14).
    pub const INT_RI: u32 = 1 << 6;
    pub const INT_RBU: u32 = 1 << 7;
    pub const INT_FBE: u32 = 1 << 12;
    pub const INT_AIS: u32 = 1 << 14;
    pub const INT_NIS: u32 = 1 << 15;
    /// What the driver listens to: a received frame, the RX ring running dry,
    /// a fatal bus error, and the two summaries that carry them.
    pub const INT_ENABLED: u32 = INT_RI | INT_RBU | INT_FBE | INT_NIS | INT_AIS;

    /// `MTL_TXQ0_OPERATION_MODE`: queue enabled; threshold mode with the
    /// 64-byte threshold (`snps,force_thresh_dma_mode`).
    pub const MTL_TXQEN: u32 = 2 << 2;
    pub const MTL_TQS_SHIFT: u32 = 16;
    pub const MTL_RQS_SHIFT: u32 = 20;
}

// ── Descriptors ─────────────────────────────────────────────────────────

/// What the 16-byte hardware descriptor words mean. **[verify]** against
/// `dwmac4_descs.h`.
pub mod desc {
    /// TX, driver to device: `des2`.
    pub const TDES2_B1_LEN_MASK: u32 = 0x3FFF;
    pub const TDES2_IOC: u32 = 1 << 31;
    /// TX, driver to device: `des3`.
    pub const TDES3_LEN_MASK: u32 = 0x7FFF;
    pub const TDES3_LD: u32 = 1 << 28;
    pub const TDES3_FD: u32 = 1 << 29;
    pub const TDES3_CTXT: u32 = 1 << 30;
    pub const TDES3_OWN: u32 = 1 << 31;
    /// TX write-back: error summary.
    pub const TDES3_ES: u32 = 1 << 15;

    /// RX, driver to device: `des3`.
    pub const RDES3_BUF1V: u32 = 1 << 24;
    pub const RDES3_IOC: u32 = 1 << 30;
    /// RX write-back: `des3`.
    pub const RDES3_LEN_MASK: u32 = 0x7FFF;
    pub const RDES3_ES: u32 = 1 << 15;
    pub const RDES3_LD: u32 = 1 << 28;
    pub const RDES3_FD: u32 = 1 << 29;
    pub const RDES3_CTXT: u32 = 1 << 30;
    pub const RDES3_OWN: u32 = 1 << 31;
}

/// Bytes the hardware reads per descriptor.
pub const DESC_BYTES: usize = 16;
/// One descriptor per cache line (the JH7110's U74 line is 64 bytes).
pub const DESC_STRIDE: usize = 64;
/// Receive buffer: a whole frame (1518 with FCS, 1522 tagged) in one buffer,
/// a multiple of the cache line and of the AXI width.
pub const BUF_SIZE: usize = 1536;
/// Descriptors per RX ring. One is always left unposted, so the device never
/// finds the ring full and the tail pointer never equals the head.
pub const RX_N: usize = 32;
/// Receive buffers: one per posted descriptor.
pub const RX_BUFS: usize = RX_N - 1;
/// Descriptors per TX ring.
pub const TX_N: usize = 16;
/// Frames one [`Dwmac::rx_harvest`] hands out.
pub const RX_BATCH: usize = 16;

/// One descriptor, alone in its cache line.
#[repr(C, align(64))]
pub struct Desc(pub [u32; 4]);

/// One frame buffer, line-aligned.
#[repr(C, align(64))]
pub struct Buf(pub [u8; BUF_SIZE]);

/// The memory the device reads and writes: both rings and every buffer. The
/// kernel keeps one in a static; a test keeps one on the heap.
#[repr(C, align(64))]
pub struct DmaMem {
    rx_desc: [Desc; RX_N],
    tx_desc: [Desc; TX_N],
    rx_buf: [Buf; RX_BUFS],
    tx_buf: [Buf; TX_N],
}

impl DmaMem {
    pub const fn new() -> Self {
        DmaMem {
            rx_desc: [const { Desc([0; 4]) }; RX_N],
            tx_desc: [const { Desc([0; 4]) }; TX_N],
            rx_buf: [const { Buf([0; BUF_SIZE]) }; RX_BUFS],
            tx_buf: [const { Buf([0; BUF_SIZE]) }; TX_N],
        }
    }
}

/// `DSL` for a descriptor of [`DESC_BYTES`] in a slot of `stride` bytes on an
/// AXI bus `bus_bytes` wide: the words to skip after each descriptor. `None`
/// when the field cannot express it (the stride is not a multiple of the bus
/// width, or the skip exceeds the 3-bit field).
pub const fn dsl_words(stride: usize, bus_bytes: usize) -> Option<u32> {
    if bus_bytes == 0 || stride < DESC_BYTES || (stride - DESC_BYTES) % bus_bytes != 0 {
        return None;
    }
    let words = ((stride - DESC_BYTES) / bus_bytes) as u32;
    if words > dma::CTRL_DSL_MAX { None } else { Some(words) }
}

/// TX descriptor words for one whole frame in one buffer, owned by the device.
/// `des3` carries OWN last in the driver's write order; the words are returned
/// in order so the caller can publish `des3` after the rest.
pub const fn tx_words(buf_bus: u64, len: usize, ioc: bool) -> [u32; 4] {
    [
        buf_bus as u32,
        (buf_bus >> 32) as u32,
        (len as u32 & desc::TDES2_B1_LEN_MASK) | if ioc { desc::TDES2_IOC } else { 0 },
        desc::TDES3_OWN | desc::TDES3_FD | desc::TDES3_LD | (len as u32 & desc::TDES3_LEN_MASK),
    ]
}

/// RX descriptor words handing a buffer to the device.
pub const fn rx_words(buf_bus: u64) -> [u32; 4] {
    [
        buf_bus as u32,
        (buf_bus >> 32) as u32,
        0,
        desc::RDES3_OWN | desc::RDES3_IOC | desc::RDES3_BUF1V,
    ]
}

/// What the device wrote back into an RX descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxStatus {
    /// Still the device's.
    Device,
    /// A context descriptor (timestamps): nothing to deliver.
    Context,
    /// A frame, or a piece of one.
    Frame { len: usize, first: bool, last: bool, error: bool },
}

/// Decode `des3` of an RX descriptor. The length is the device's word and
/// untrusted: it is 15 bits wide while a buffer holds [`BUF_SIZE`].
pub const fn rx_status(des3: u32) -> RxStatus {
    if des3 & desc::RDES3_OWN != 0 {
        return RxStatus::Device;
    }
    if des3 & desc::RDES3_CTXT != 0 {
        return RxStatus::Context;
    }
    RxStatus::Frame {
        len: (des3 & desc::RDES3_LEN_MASK) as usize,
        first: des3 & desc::RDES3_FD != 0,
        last: des3 & desc::RDES3_LD != 0,
        error: des3 & desc::RDES3_ES != 0,
    }
}

// ── MDIO and the PHY ────────────────────────────────────────────────────

/// Clause 22 registers and the YT8531's identity. **[verify]** the ID against
/// `motorcomm.c` (`PHY_ID_YT8531`).
pub mod phy {
    pub const BMCR: u8 = 0;
    pub const BMSR: u8 = 1;
    pub const PHYSID1: u8 = 2;
    pub const PHYSID2: u8 = 3;
    pub const ADVERTISE: u8 = 4;
    pub const LPA: u8 = 5;
    pub const CTRL1000: u8 = 9;
    pub const STAT1000: u8 = 10;

    pub const BMCR_RESET: u16 = 1 << 15;
    pub const BMCR_ANENABLE: u16 = 1 << 12;
    pub const BMCR_ANRESTART: u16 = 1 << 9;
    pub const BMSR_LSTATUS: u16 = 1 << 2;
    pub const BMSR_ANEGCOMPLETE: u16 = 1 << 5;

    /// 10/100 half and full duplex plus the CSMA selector.
    pub const ADVERTISE_ALL_10_100: u16 = 0x01E1;
    pub const ADVERTISE_1000FULL: u16 = 1 << 9;

    pub const ID_YT8531: u32 = 0x4F51_E91B;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Speed {
    M10,
    M100,
    M1000,
}

/// The negotiated link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    pub up: bool,
    pub speed: Speed,
    pub full_duplex: bool,
}

impl Link {
    pub const DOWN: Link = Link { up: false, speed: Speed::M10, full_duplex: false };
}

/// IEEE 802.3 clause 28/40 priority resolution from our advertisement
/// (`ADVERTISE`, `CTRL1000`) and the partner's (`LPA`, `STAT1000`): 1000FD,
/// 1000HD, 100FD, 100HD, 10FD, 10HD. `None` when nothing is common.
pub const fn resolve_link(adv: u16, lpa: u16, ctrl1000: u16, stat1000: u16) -> Option<(Speed, bool)> {
    // STAT1000 reports the partner's 1000BASE-T abilities at bits 11:10,
    // CTRL1000 holds ours at bits 9:8.
    let g = ctrl1000 & (stat1000 >> 2);
    if g & (1 << 9) != 0 {
        return Some((Speed::M1000, true));
    }
    if g & (1 << 8) != 0 {
        return Some((Speed::M1000, false));
    }
    let n = adv & lpa;
    if n & (1 << 8) != 0 {
        Some((Speed::M100, true))
    } else if n & (1 << 7) != 0 {
        Some((Speed::M100, false))
    } else if n & (1 << 6) != 0 {
        Some((Speed::M10, true))
    } else if n & (1 << 5) != 0 {
        Some((Speed::M10, false))
    } else {
        None
    }
}

/// `MAC_CONFIGURATION` speed and duplex bits for a link: GMII is `PS=0`,
/// 100 is `PS=1 FES=1`, 10 is `PS=1 FES=0`.
pub const fn config_bits(speed: Speed, full_duplex: bool) -> u32 {
    let s = match speed {
        Speed::M1000 => 0,
        Speed::M100 => mac::CFG_PS | mac::CFG_FES,
        Speed::M10 => mac::CFG_PS,
    };
    s | if full_duplex { mac::CFG_DM } else { 0 }
}

// ── Environment ─────────────────────────────────────────────────────────

/// The register window and a monotonic clock.
pub trait Hw {
    fn rd(&self, off: usize) -> u32;
    fn wr(&self, off: usize, val: u32);
    /// Monotonic microseconds.
    fn now_us(&self) -> u64;
}

/// The DMA domain the NIC sits in: mapping and the cache maintenance of a
/// non-coherent master (a no-op behind a coherent one).
pub trait DmaOps: Copy {
    /// Map `len` bytes at the kernel address `ptr`; the bus address.
    fn map(&self, ptr: *const u8, len: usize, dir: Direction) -> Result<u64, ()>;
    /// Start the domain enforcing; after every buffer is mapped.
    fn enable(&self) -> Result<(), ()>;
    /// # Safety
    /// `[ptr, ptr + len)` must be mapped kernel memory.
    unsafe fn sync_for_device(&self, ptr: *const u8, len: usize, dir: Direction);
    /// # Safety
    /// `[ptr, ptr + len)` must be mapped kernel memory.
    unsafe fn sync_for_cpu(&self, ptr: *const u8, len: usize, dir: Direction);
}

impl DmaOps for azos_drv_virtio::virtio::Dma {
    fn map(&self, ptr: *const u8, len: usize, dir: Direction) -> Result<u64, ()> {
        azos_drv_virtio::virtio::Dma::map(self, ptr, len, dir)
    }
    fn enable(&self) -> Result<(), ()> {
        azos_drv_virtio::virtio::Dma::enable(self)
    }
    unsafe fn sync_for_device(&self, ptr: *const u8, len: usize, dir: Direction) {
        unsafe { azos_drv_virtio::virtio::Dma::sync_for_device(self, ptr, len, dir) }
    }
    unsafe fn sync_for_cpu(&self, ptr: *const u8, len: usize, dir: Direction) {
        unsafe { azos_drv_virtio::virtio::Dma::sync_for_cpu(self, ptr, len, dir) }
    }
}

/// Volatile access to the window at `base`.
#[derive(Clone, Copy)]
pub struct Mmio {
    base: usize,
}

impl Mmio {
    pub const fn new(base: usize) -> Self {
        Mmio { base }
    }
}

impl Hw for Mmio {
    #[inline(always)]
    fn rd(&self, off: usize) -> u32 {
        // SAFETY: the board maps `[base, base + reg::WINDOW)` (board_map.rs).
        unsafe { core::ptr::read_volatile((self.base + off) as *const u32) }
    }
    #[inline(always)]
    fn wr(&self, off: usize, val: u32) {
        // SAFETY: as `rd`.
        unsafe { core::ptr::write_volatile((self.base + off) as *mut u32, val) }
    }
    fn now_us(&self) -> u64 {
        let t = azos_drv_sys::timebase::now();
        let f = azos_drv_sys::timebase::TIMER_FREQ;
        (t / f) * 1_000_000 + (t % f) * 1_000_000 / f
    }
}

// ── Configuration ───────────────────────────────────────────────────────

/// Everything about one instance that is not in the silicon.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// MDIO address of the PHY.
    pub phy_addr: u8,
    /// Used when the firmware left no valid station address in the MAC.
    pub fallback_mac: [u8; 6],
    /// Width of the AXI data bus, in bytes, for `DSL`. **[verify]**
    pub axi_bus_bytes: usize,
    /// `MAC_MDIO_ADDRESS.CR`: the MDC divider for the CSR clock. 7 divides by
    /// 324, which keeps MDC under 2.5 MHz for any CSR clock up to 800 MHz.
    pub mdio_cr: u32,
    pub rx_fifo: u32,
    pub tx_fifo: u32,
    pub txpbl: u32,
    pub rxpbl: u32,
    pub axi_wr_osr: u32,
    pub axi_rd_osr: u32,
    /// How long `init` waits for the first link-up, in microseconds.
    pub link_wait_us: u64,
}

impl Config {
    /// `gmac0` of the JH7110 on the VisionFive 2 (see the module doc for the
    /// DTS lines). The fallback address is locally administered and the same
    /// on every board: set one per board before putting two on a network.
    pub const JH7110_GMAC0: Config = Config {
        phy_addr: 0,
        fallback_mac: [0x02, 0x41, 0x7A, 0x4F, 0x53, 0x01],
        axi_bus_bytes: 8,
        mdio_cr: 7,
        rx_fifo: 2048,
        tx_fifo: 2048,
        txpbl: 16,
        rxpbl: 16,
        axi_wr_osr: 15,
        axi_rd_osr: 15,
        link_wait_us: 2_500_000,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// `MAC_VERSION` is not a dwmac4/5 core (the value read is attached).
    UnsupportedCore(u32),
    /// The DMA soft reset did not finish (the PHY's RX clock missing is the
    /// usual cause on RGMII).
    ResetTimeout,
    /// The MDIO busy bit did not clear.
    MdioTimeout,
    /// Nothing answers at the PHY address.
    NoPhy,
    /// A PHY other than the YT8531 answers (its ID attached).
    UnknownPhy(u32),
    /// The PHY's reset bit did not clear.
    PhyResetTimeout,
    /// A ring or buffer was refused by the DMA domain.
    DmaMap,
    /// The stride/bus-width pair cannot be expressed in `DSL`.
    BadStride,
}

/// Counters, for the link-change log line.
#[derive(Clone, Copy, Default, Debug)]
pub struct Stats {
    pub tx_frames: u64,
    pub rx_frames: u64,
    /// The device flagged the frame (TX error summary, RX error summary).
    pub tx_errors: u64,
    pub rx_errors: u64,
    /// RX descriptors dropped without delivery: spanning buffers, runts.
    pub rx_dropped: u64,
}

/// What an interrupt found, after acknowledging it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct IrqCause {
    /// A frame arrived, or the RX ring ran dry: look at the ring.
    pub rx: bool,
    /// The bus faulted: the channel has stopped.
    pub fatal: bool,
}

/// Acknowledge the channel-0 interrupt: read the status, write the handled
/// bits back (write-1-to-clear), say what it was. Touches only `DMA_CH0_STATUS`,
/// so it needs no lock against the thread driving the rings.
pub fn irq_ack<H: Hw>(hw: &H) -> IrqCause {
    let st = hw.rd(reg::DMA_CH0_STATUS);
    let handled = st & dma::INT_ENABLED;
    if handled != 0 {
        hw.wr(reg::DMA_CH0_STATUS, handled);
    }
    IrqCause {
        rx: st & (dma::INT_RI | dma::INT_RBU) != 0,
        fatal: st & dma::INT_FBE != 0,
    }
}

// ── The driver ──────────────────────────────────────────────────────────

/// One MAC with its rings. Not internally locked: the kernel wraps it in a
/// lock ([`board`]) and calls [`irq_ack`] without it.
pub struct Dwmac<H: Hw, D: DmaOps> {
    hw: H,
    dma: D,
    cfg: Config,
    mem: *mut DmaMem,
    rx_desc_bus: u64,
    tx_desc_bus: u64,
    rx_buf_bus: u64,
    tx_buf_bus: u64,
    mac: [u8; 6],
    link: Link,
    last_link_us: u64,
    /// Producer index and count of the TX ring: `tx_tail` is the oldest frame
    /// the device may still own.
    tx_head: usize,
    tx_tail: usize,
    tx_inflight: usize,
    tx_batch: bool,
    tx_unannounced: bool,
    /// Next RX descriptor the device fills, and the first one not posted
    /// (the tail pointer). The posted descriptors are `rx_next..rx_post`,
    /// always `RX_N - 1` of them.
    rx_next: usize,
    rx_post: usize,
    /// Which buffer each posted descriptor carries. Descriptors must be
    /// posted in ring order, so a buffer returns to whichever descriptor is
    /// next, not to the one it came out of.
    rx_buf_of: [u8; RX_N],
    /// Dropping the rest of a frame that spilled over its first buffer.
    rx_skipping: bool,
    stats: Stats,
}

// SAFETY: `mem` points at the `DmaMem` the owner of the `Dwmac` was given
// exclusively for its lifetime.
unsafe impl<H: Hw + Send, D: DmaOps + Send> Send for Dwmac<H, D> {}

/// MDC is idle between frames; give a transaction this long.
const MDIO_TIMEOUT_US: u64 = 10_000;
const SOFT_RESET_TIMEOUT_US: u64 = 10_000;
const PHY_RESET_TIMEOUT_US: u64 = 500_000;
/// How often a quiet receive path looks at the PHY.
pub const LINK_POLL_US: u64 = 500_000;

impl<H: Hw, D: DmaOps> Dwmac<H, D> {
    /// Bring the MAC, its DMA channel and the PHY up and start receiving.
    /// `mem` must stay valid and unaliased for the life of the driver.
    pub fn init(hw: H, dma: D, cfg: Config, mem: *mut DmaMem) -> Result<Self, Error> {
        let version = hw.rd(reg::MAC_VERSION);
        if version & mac::VERSION_SNPS_MASK < mac::VERSION_MIN {
            return Err(Error::UnsupportedCore(version));
        }
        let dsl = dsl_words(DESC_STRIDE, cfg.axi_bus_bytes).ok_or(Error::BadStride)?;

        // The station address the firmware programmed, before the reset
        // clears it.
        let fw_mac = Self::read_mac(&hw);
        let mac = if fw_mac != [0; 6] && fw_mac[0] & 1 == 0 { fw_mac } else { cfg.fallback_mac };

        // SAFETY: `mem` is valid (caller contract); only addresses are taken.
        let (rx_desc, tx_desc, rx_buf, tx_buf) = unsafe {
            (
                core::ptr::addr_of!((*mem).rx_desc) as *const u8,
                core::ptr::addr_of!((*mem).tx_desc) as *const u8,
                core::ptr::addr_of!((*mem).rx_buf) as *const u8,
                core::ptr::addr_of!((*mem).tx_buf) as *const u8,
            )
        };
        let map = |p: *const u8, len: usize, dir: Direction| dma.map(p, len, dir).map_err(|_| Error::DmaMap);
        let rx_desc_bus = map(rx_desc, RX_N * DESC_STRIDE, Direction::Bidirectional)?;
        let tx_desc_bus = map(tx_desc, TX_N * DESC_STRIDE, Direction::Bidirectional)?;
        let rx_buf_bus = map(rx_buf, RX_BUFS * BUF_SIZE, Direction::FromDevice)?;
        let tx_buf_bus = map(tx_buf, TX_N * BUF_SIZE, Direction::ToDevice)?;
        dma.enable().map_err(|_| Error::DmaMap)?;

        let mut d = Dwmac {
            hw,
            dma,
            cfg,
            mem,
            rx_desc_bus,
            tx_desc_bus,
            rx_buf_bus,
            tx_buf_bus,
            mac,
            link: Link::DOWN,
            last_link_us: 0,
            tx_head: 0,
            tx_tail: 0,
            tx_inflight: 0,
            tx_batch: false,
            tx_unannounced: false,
            rx_next: 0,
            rx_post: 0,
            rx_buf_of: [0; RX_N],
            rx_skipping: false,
            stats: Stats::default(),
        };
        d.soft_reset()?;
        d.program_mac();
        d.program_mtl();
        d.program_dma(dsl);
        d.post_all_rx();
        d.phy_start()?;
        d.start_dma();
        d.wait_link(cfg.link_wait_us);
        Ok(d)
    }

    fn read_mac(hw: &H) -> [u8; 6] {
        let hi = hw.rd(reg::MAC_ADDRESS0_HIGH);
        let lo = hw.rd(reg::MAC_ADDRESS0_LOW);
        [lo as u8, (lo >> 8) as u8, (lo >> 16) as u8, (lo >> 24) as u8, hi as u8, (hi >> 8) as u8]
    }

    fn wait_clear(&self, off: usize, mask: u32, timeout_us: u64) -> bool {
        let t0 = self.hw.now_us();
        loop {
            if self.hw.rd(off) & mask == 0 {
                return true;
            }
            if self.hw.now_us().wrapping_sub(t0) > timeout_us {
                return false;
            }
        }
    }

    fn soft_reset(&mut self) -> Result<(), Error> {
        self.hw.wr(reg::DMA_MODE, dma::MODE_SWR);
        if self.wait_clear(reg::DMA_MODE, dma::MODE_SWR, SOFT_RESET_TIMEOUT_US) {
            Ok(())
        } else {
            Err(Error::ResetTimeout)
        }
    }

    /// Station address, receive filter and frame handling. Transmit and
    /// receive stay disabled until the link is up.
    fn program_mac(&mut self) {
        let m = self.mac;
        self.hw.wr(reg::MAC_ADDRESS0_HIGH, (1 << 31) | (m[4] as u32) | (m[5] as u32) << 8);
        self.hw.wr(
            reg::MAC_ADDRESS0_LOW,
            (m[0] as u32) | (m[1] as u32) << 8 | (m[2] as u32) << 16 | (m[3] as u32) << 24,
        );
        self.hw.wr(reg::MAC_PACKET_FILTER, mac::FILTER_PM);
        self.hw.wr(reg::MAC_Q0_TX_FLOW_CTRL, 0);
        self.hw.wr(reg::MAC_RX_FLOW_CTRL, 0);
        self.hw.wr(reg::MAC_RXQ_CTRL0, mac::RXQ0_DCB);
        self.hw.wr(reg::MAC_INTERRUPT_ENABLE, 0);
        self.hw.wr(reg::MAC_CONFIGURATION, mac::CFG_CST | mac::CFG_ACS);
    }

    /// One transmit queue, one receive queue, threshold mode at 64 bytes
    /// (`snps,force_thresh_dma_mode`), FIFOs sized from the DTS depths.
    fn program_mtl(&mut self) {
        self.hw.wr(reg::MTL_OPERATION_MODE, 0);
        let tqs = (self.cfg.tx_fifo / 256).saturating_sub(1);
        let rqs = (self.cfg.rx_fifo / 256).saturating_sub(1);
        self.hw.wr(reg::MTL_TXQ0_OPERATION_MODE, dma::MTL_TXQEN | (tqs << dma::MTL_TQS_SHIFT));
        self.hw.wr(reg::MTL_RXQ0_OPERATION_MODE, rqs << dma::MTL_RQS_SHIFT);
    }

    fn program_dma(&mut self, dsl: u32) {
        let c = &self.cfg;
        self.hw.wr(
            reg::DMA_SYSBUS_MODE,
            dma::SYSBUS_FB
                | dma::SYSBUS_BLEN_256
                | dma::SYSBUS_BLEN_128
                | dma::SYSBUS_BLEN_64
                | dma::SYSBUS_BLEN_32
                | (c.axi_rd_osr << dma::SYSBUS_RD_OSR_SHIFT)
                | (c.axi_wr_osr << dma::SYSBUS_WR_OSR_SHIFT),
        );
        self.hw.wr(reg::DMA_CH0_CONTROL, dsl << dma::CTRL_DSL_SHIFT);
        self.hw.wr(reg::DMA_CH0_TX_CONTROL, dma::TX_CTRL_OSF | (c.txpbl << dma::TX_CTRL_PBL_SHIFT));
        self.hw.wr(
            reg::DMA_CH0_RX_CONTROL,
            ((BUF_SIZE as u32) << dma::RX_CTRL_RBSZ_SHIFT & dma::RX_CTRL_RBSZ_MASK)
                | (c.rxpbl << dma::RX_CTRL_PBL_SHIFT),
        );
        self.hw.wr(reg::DMA_CH0_TXDESC_HADDR, (self.tx_desc_bus >> 32) as u32);
        self.hw.wr(reg::DMA_CH0_TXDESC_LADDR, self.tx_desc_bus as u32);
        self.hw.wr(reg::DMA_CH0_RXDESC_HADDR, (self.rx_desc_bus >> 32) as u32);
        self.hw.wr(reg::DMA_CH0_RXDESC_LADDR, self.rx_desc_bus as u32);
        self.hw.wr(reg::DMA_CH0_TXDESC_LEN, TX_N as u32 - 1);
        self.hw.wr(reg::DMA_CH0_RXDESC_LEN, RX_N as u32 - 1);
        self.hw.wr(reg::DMA_CH0_TXDESC_TAIL, self.tx_desc_bus as u32);
    }

    fn start_dma(&mut self) {
        let tx = self.hw.rd(reg::DMA_CH0_TX_CONTROL);
        self.hw.wr(reg::DMA_CH0_TX_CONTROL, tx | dma::TX_CTRL_ST);
        let rx = self.hw.rd(reg::DMA_CH0_RX_CONTROL);
        self.hw.wr(reg::DMA_CH0_RX_CONTROL, rx | dma::RX_CTRL_SR);
        self.hw.wr(reg::DMA_CH0_STATUS, !0);
        self.hw.wr(reg::DMA_CH0_INTR_ENA, dma::INT_ENABLED);
    }

    // ── descriptor access ──────────────────────────────────────────────

    fn rx_desc(&self, i: usize) -> *mut Desc {
        debug_assert!(i < RX_N);
        // SAFETY: `i` is in range; the pointer is into `mem`.
        unsafe { core::ptr::addr_of_mut!((*self.mem).rx_desc[i]) }
    }
    fn tx_desc(&self, i: usize) -> *mut Desc {
        debug_assert!(i < TX_N);
        // SAFETY: as `rx_desc`.
        unsafe { core::ptr::addr_of_mut!((*self.mem).tx_desc[i]) }
    }
    fn rx_buf(&self, i: usize) -> *mut u8 {
        // SAFETY: as `rx_desc`.
        unsafe { core::ptr::addr_of_mut!((*self.mem).rx_buf[i]) as *mut u8 }
    }
    fn tx_buf(&self, i: usize) -> *mut u8 {
        // SAFETY: as `rx_desc`.
        unsafe { core::ptr::addr_of_mut!((*self.mem).tx_buf[i]) as *mut u8 }
    }

    /// Write `w` into `d` with `des3` (the ownership word) last, and hand the
    /// line to the device. `dma_wmb`: the body before OWN as the device sees
    /// them (`fence(Release)` is `dmb ish` on aarch64, not the outer domain).
    fn publish(&self, d: *mut Desc, w: [u32; 4]) {
        let p = d as *mut u32;
        // SAFETY: `d` is a descriptor of `mem`.
        unsafe {
            core::ptr::write_volatile(p, w[0]);
            core::ptr::write_volatile(p.add(1), w[1]);
            core::ptr::write_volatile(p.add(2), w[2]);
            azos_dma::order::dma_wmb();
            core::ptr::write_volatile(p.add(3), w[3]);
            self.dma.sync_for_device(d as *const u8, DESC_STRIDE, Direction::Bidirectional);
        }
    }

    /// The descriptor's `des3` after taking the line back from the device.
    /// Every caller decides on OWN in it, then reads what the device wrote (the
    /// frame, the status): `dma_rmb` keeps those reads after this one.
    fn des3(&self, d: *mut Desc) -> u32 {
        // SAFETY: `d` is a descriptor of `mem`.
        let d3 = unsafe {
            self.dma.sync_for_cpu(d as *const u8, DESC_STRIDE, Direction::Bidirectional);
            core::ptr::read_volatile((d as *const u32).add(3))
        };
        azos_dma::order::dma_rmb();
        d3
    }

    // ── receive ────────────────────────────────────────────────────────

    /// Post buffer `buf` on descriptor `desc`.
    fn rx_give(&mut self, desc: usize, buf: usize) {
        self.rx_buf_of[desc] = buf as u8;
        // SAFETY: buffer `buf` is in `mem`.
        unsafe { self.dma.sync_for_device(self.rx_buf(buf), BUF_SIZE, Direction::FromDevice) };
        self.publish(self.rx_desc(desc), rx_words(self.rx_buf_bus + (buf * BUF_SIZE) as u64));
    }

    /// At start: every buffer posted, one descriptor short of the ring.
    fn post_all_rx(&mut self) {
        for i in 0..RX_BUFS {
            self.rx_give(i, i);
        }
        self.rx_next = 0;
        self.rx_post = RX_BUFS;
        self.announce_rx();
    }

    /// The tail write is the doorbell: `io_wmb` orders the descriptors before
    /// it for the device.
    fn announce_rx(&self) {
        azos_dma::order::io_wmb();
        let tail = self.rx_desc_bus + (self.rx_post * DESC_STRIDE) as u64;
        self.hw.wr(reg::DMA_CH0_RXDESC_TAIL, tail as u32);
    }

    /// Take up to `out.len()` received frames off the ring, in arrival order.
    /// Each entry is `(descriptor, length)`; the bytes are at
    /// [`Self::rx_frame`] and stay valid until [`Self::rx_release`] gives the
    /// descriptors back. Returns `(frames, descriptors)`: the second counts
    /// every descriptor consumed, dropped ones included, and is what
    /// `rx_release` wants.
    ///
    /// The device's status word is untrusted: a frame is delivered only if it
    /// is one whole, error-free buffer of at least an Ethernet header, and its
    /// length is clamped to the buffer.
    pub fn rx_harvest(&mut self, out: &mut [(u16, u16)]) -> (usize, usize) {
        let mut frames = 0;
        let mut used = 0;
        while frames < out.len() && used < RX_BUFS {
            let d = (self.rx_next + used) % RX_N;
            match rx_status(self.des3(self.rx_desc(d))) {
                RxStatus::Device => break,
                RxStatus::Context => {}
                RxStatus::Frame { len, first, last, error } => {
                    if self.rx_skipping || !(first && last) {
                        // A frame that did not fit one buffer, and the rest of it.
                        self.stats.rx_dropped += 1;
                        self.rx_skipping = !last;
                    } else if error {
                        self.stats.rx_errors += 1;
                    } else if len < 14 {
                        self.stats.rx_dropped += 1;
                    } else {
                        let len = len.min(BUF_SIZE);
                        let buf = self.rx_buf_of[d] as usize;
                        // SAFETY: buffer `buf` is in `mem`.
                        unsafe { self.dma.sync_for_cpu(self.rx_buf(buf), len, Direction::FromDevice) };
                        out[frames] = (d as u16, len as u16);
                        frames += 1;
                        self.stats.rx_frames += 1;
                    }
                }
            }
            used += 1;
        }
        self.rx_next = (self.rx_next + used) % RX_N;
        (frames, used)
    }

    /// The bytes of a harvested frame.
    pub fn rx_frame(&self, desc: u16, len: u16) -> &[u8] {
        let buf = self.rx_buf_of[desc as usize] as usize;
        // SAFETY: `desc`/`len` came from `rx_harvest`: the buffer is inside
        // `mem` and is not the device's until `rx_release`.
        unsafe { core::slice::from_raw_parts(self.rx_buf(buf), len as usize) }
    }

    /// The descriptor the next harvest starts at.
    pub fn rx_first(&self) -> usize {
        self.rx_next
    }

    /// Give the buffers of the `used` descriptors a harvest consumed (it
    /// started at `first`) back to the device, on the next free descriptors in
    /// ring order, and announce them with one tail write.
    pub fn rx_release(&mut self, first: usize, used: usize) {
        for k in 0..used {
            let buf = self.rx_buf_of[(first + k) % RX_N] as usize;
            self.rx_give(self.rx_post, buf);
            self.rx_post = (self.rx_post + 1) % RX_N;
        }
        if used != 0 {
            self.announce_rx();
        }
    }

    /// Whether the next RX descriptor holds something: a cheap look, no
    /// state change.
    pub fn rx_ready(&self) -> bool {
        rx_status(self.des3(self.rx_desc(self.rx_next))) != RxStatus::Device
    }

    // ── transmit ───────────────────────────────────────────────────────

    /// Free the descriptors the device has finished with.
    fn tx_reclaim(&mut self) {
        while self.tx_inflight > 0 {
            let d3 = self.des3(self.tx_desc(self.tx_tail));
            if d3 & desc::TDES3_OWN != 0 {
                break;
            }
            if d3 & desc::TDES3_ES != 0 {
                self.stats.tx_errors += 1;
            }
            self.tx_tail = (self.tx_tail + 1) % TX_N;
            self.tx_inflight -= 1;
        }
    }

    /// Queue `frame` (a whole Ethernet frame without FCS) for transmission.
    pub fn send(&mut self, frame: &[u8]) -> Result<usize, NetError> {
        if !self.link.up {
            return Err(NetError::NotReady);
        }
        if frame.is_empty() || frame.len() > ETH_FRAME_MAX {
            return Err(NetError::BadLength);
        }
        // One descriptor is never used: with the ring full the producer index
        // would equal the consumer's, and the device reads head == tail as
        // "nothing to do".
        if self.tx_inflight >= TX_N - 1 {
            self.tx_reclaim();
            if self.tx_inflight >= TX_N - 1 {
                return Err(NetError::QueueFull);
            }
        }
        let i = self.tx_head;
        let buf = self.tx_buf(i);
        // SAFETY: buffer `i` is in `mem`, the device is done with it
        // (reclaimed or never used), and `frame.len() <= BUF_SIZE`.
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), buf, frame.len());
            self.dma.sync_for_device(buf, frame.len(), Direction::ToDevice);
        }
        let bus = self.tx_buf_bus + (i * BUF_SIZE) as u64;
        self.publish(self.tx_desc(i), tx_words(bus, frame.len(), false));
        self.tx_head = (i + 1) % TX_N;
        self.tx_inflight += 1;
        self.stats.tx_frames += 1;
        if self.tx_batch {
            self.tx_unannounced = true;
        } else {
            self.announce_tx();
        }
        Ok(frame.len())
    }

    /// As [`Self::announce_rx`].
    fn announce_tx(&mut self) {
        azos_dma::order::io_wmb();
        let tail = self.tx_desc_bus + (self.tx_head * DESC_STRIDE) as u64;
        self.hw.wr(reg::DMA_CH0_TXDESC_TAIL, tail as u32);
        self.tx_unannounced = false;
    }

    /// Until [`Self::tx_batch_end`], `send` queues without announcing.
    pub fn tx_batch_begin(&mut self) {
        self.tx_batch = true;
    }

    /// Announce everything the batch queued with one tail write.
    pub fn tx_batch_end(&mut self) {
        self.tx_batch = false;
        if self.tx_unannounced {
            self.announce_tx();
        }
    }

    // ── MDIO and the PHY ───────────────────────────────────────────────

    fn mdio_op(&self, reg: u8, goc: u32, data: Option<u16>) -> Result<u32, Error> {
        if !self.wait_clear(reg::MAC_MDIO_ADDRESS, mac::MDIO_GB, MDIO_TIMEOUT_US) {
            return Err(Error::MdioTimeout);
        }
        if let Some(v) = data {
            self.hw.wr(reg::MAC_MDIO_DATA, v as u32);
        }
        self.hw.wr(
            reg::MAC_MDIO_ADDRESS,
            (self.cfg.phy_addr as u32) << mac::MDIO_PA_SHIFT
                | (reg as u32) << mac::MDIO_RDA_SHIFT
                | self.cfg.mdio_cr << mac::MDIO_CR_SHIFT
                | goc
                | mac::MDIO_GB,
        );
        if !self.wait_clear(reg::MAC_MDIO_ADDRESS, mac::MDIO_GB, MDIO_TIMEOUT_US) {
            return Err(Error::MdioTimeout);
        }
        Ok(self.hw.rd(reg::MAC_MDIO_DATA))
    }

    /// Clause 22 read of PHY register `r`.
    pub fn mdio_read(&self, r: u8) -> Result<u16, Error> {
        self.mdio_op(r, mac::MDIO_GOC_READ, None).map(|v| v as u16)
    }

    /// Clause 22 write of PHY register `r`.
    pub fn mdio_write(&self, r: u8, v: u16) -> Result<(), Error> {
        self.mdio_op(r, mac::MDIO_GOC_WRITE, Some(v)).map(|_| ())
    }

    /// Check the PHY, reset it and start auto-negotiation at every speed it
    /// shares with us.
    fn phy_start(&mut self) -> Result<(), Error> {
        let id1 = self.mdio_read(phy::PHYSID1)? as u32;
        let id2 = self.mdio_read(phy::PHYSID2)? as u32;
        let id = id1 << 16 | id2;
        if id1 == 0xFFFF || id1 == 0 && id2 == 0 {
            return Err(Error::NoPhy);
        }
        if id != phy::ID_YT8531 {
            return Err(Error::UnknownPhy(id));
        }
        self.mdio_write(phy::BMCR, phy::BMCR_RESET)?;
        let t0 = self.hw.now_us();
        while self.mdio_read(phy::BMCR)? & phy::BMCR_RESET != 0 {
            if self.hw.now_us().wrapping_sub(t0) > PHY_RESET_TIMEOUT_US {
                return Err(Error::PhyResetTimeout);
            }
        }
        self.mdio_write(phy::ADVERTISE, phy::ADVERTISE_ALL_10_100)?;
        self.mdio_write(phy::CTRL1000, phy::ADVERTISE_1000FULL)?;
        self.mdio_write(phy::BMCR, phy::BMCR_ANENABLE | phy::BMCR_ANRESTART)
    }

    /// Read the PHY and bring the MAC in line with the link. Returns the
    /// link when it changed.
    pub fn link_update(&mut self) -> Option<Link> {
        let now = self.phy_link().unwrap_or(Link::DOWN);
        if now == self.link {
            return None;
        }
        self.apply_link(now);
        self.link = now;
        Some(now)
    }

    fn phy_link(&self) -> Result<Link, Error> {
        // Link status latches low: the first read reports a drop since the
        // last one, the second the present.
        let _ = self.mdio_read(phy::BMSR)?;
        let bmsr = self.mdio_read(phy::BMSR)?;
        if bmsr & phy::BMSR_LSTATUS == 0 || bmsr & phy::BMSR_ANEGCOMPLETE == 0 {
            return Ok(Link::DOWN);
        }
        let adv = self.mdio_read(phy::ADVERTISE)?;
        let lpa = self.mdio_read(phy::LPA)?;
        let ctrl = self.mdio_read(phy::CTRL1000)?;
        let stat = self.mdio_read(phy::STAT1000)?;
        Ok(match resolve_link(adv, lpa, ctrl, stat) {
            Some((speed, full_duplex)) => Link { up: true, speed, full_duplex },
            None => Link::DOWN,
        })
    }

    fn apply_link(&mut self, l: Link) {
        let mut c = self.hw.rd(reg::MAC_CONFIGURATION);
        c &= !(mac::CFG_PS | mac::CFG_FES | mac::CFG_DM | mac::CFG_TE | mac::CFG_RE);
        c |= config_bits(l.speed, l.full_duplex);
        self.hw.wr(reg::MAC_CONFIGURATION, c);
        if l.up {
            self.hw.wr(reg::MAC_CONFIGURATION, c | mac::CFG_TE | mac::CFG_RE);
        }
    }

    fn wait_link(&mut self, budget_us: u64) {
        let t0 = self.hw.now_us();
        loop {
            self.link_update();
            if self.link.up || self.hw.now_us().wrapping_sub(t0) >= budget_us {
                break;
            }
        }
        self.last_link_us = self.hw.now_us();
    }

    /// For the receive path to call when it finds the ring empty: looks at the
    /// PHY at most every [`LINK_POLL_US`]. Returns the link when it changed.
    pub fn link_poll(&mut self) -> Option<Link> {
        let now = self.hw.now_us();
        if now.wrapping_sub(self.last_link_us) < LINK_POLL_US {
            return None;
        }
        self.last_link_us = now;
        self.link_update()
    }

    pub fn link(&self) -> Link {
        self.link
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }
}

// ── Kernel instance ─────────────────────────────────────────────────────

/// The statics, the interrupt hook and the [`NetDevice`] face of the VF2's
/// `gmac0`: what `net_device` dispatches to. Compiled for the board only,
/// because the rings are ~75 KiB of `.bss`.
#[cfg(feature = "vf2")]
pub mod board {
    use super::*;
    use azos_drv_api::net::NetDevice;
    use azos_drv_virtio::virtio::Dma;
    use azos_sync::SpinLock;
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

    const BASE: usize = azos_drv_base::platform::hw::ETH0_BASE;

    struct Mem(UnsafeCell<DmaMem>);
    // SAFETY: handed to exactly one `Dwmac` by `init`, under `STATE`'s lock.
    unsafe impl Sync for Mem {}
    static MEM: Mem = Mem(UnsafeCell::new(DmaMem::new()));

    static STATE: SpinLock<Option<Dwmac<Mmio, Dma>>> = SpinLock::new(None);
    static READY: AtomicBool = AtomicBool::new(false);
    /// The PLIC source `enable_irq` armed; `u32::MAX` while polled.
    static IRQ_LINE: AtomicU32 = AtomicU32::new(u32::MAX);
    /// An RX interrupt (or the ring running dry) since the last drain found
    /// the ring empty. Only consulted in interrupt mode.
    static RX_PENDING: AtomicBool = AtomicBool::new(true);
    /// The channel reported a fatal bus error (set in the interrupt, reported
    /// by the next drain: no printing in an interrupt).
    static FATAL: AtomicBool = AtomicBool::new(false);

    /// Bring `gmac0` up. The clocks and resets must already run (see the
    /// module doc); a window that is not a dwmac core is refused.
    pub fn init(cfg: Config) -> Result<(), Error> {
        let mut st = STATE.lock();
        if st.is_some() {
            return Ok(());
        }
        let dev = Dwmac::init(Mmio::new(BASE), Dma::mmio(BASE), cfg, MEM.0.get())?;
        let (mac, link) = (dev.mac(), dev.link());
        *st = Some(dev);
        READY.store(true, Ordering::Release);
        azos_drv_sys::kprintln!(
            "[ETH] dwmac gmac0 @ {:#x}: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, link {}",
            BASE, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], link_str(link)
        );
        Ok(())
    }

    fn link_str(l: Link) -> &'static str {
        match (l.up, l.speed, l.full_duplex) {
            (false, _, _) => "down",
            (true, Speed::M1000, true) => "up 1000 full",
            (true, Speed::M1000, false) => "up 1000 half",
            (true, Speed::M100, true) => "up 100 full",
            (true, Speed::M100, false) => "up 100 half",
            (true, Speed::M10, true) => "up 10 full",
            (true, Speed::M10, false) => "up 10 half",
        }
    }

    /// Switch to interrupt mode on PLIC source `line` (the number the
    /// kernel's dispatcher will pass to [`irq`]). Call before the line is
    /// unmasked. `false` when there is no NIC.
    pub fn enable_irq(line: u32) -> bool {
        if !READY.load(Ordering::Acquire) {
            return false;
        }
        IRQ_LINE.store(line, Ordering::Release);
        true
    }

    /// Whether the receive path is woken by interrupts.
    #[inline]
    pub fn irq_driven() -> bool {
        IRQ_LINE.load(Ordering::Acquire) != u32::MAX
    }

    /// Interrupt hook: `line` is what the interrupt controller reported.
    /// `true` when it is this NIC's: the device is acknowledged and the RX
    /// gate opened; the caller wakes whatever drains the ring. Lock-free.
    #[inline]
    pub fn irq(line: u32) -> bool {
        if line != IRQ_LINE.load(Ordering::Acquire) {
            return false;
        }
        let cause = irq_ack(&Mmio::new(BASE));
        if cause.rx {
            RX_PENDING.store(true, Ordering::Release);
        }
        if cause.fatal {
            FATAL.store(true, Ordering::Relaxed);
        }
        true
    }

    /// When the PHY is next looked at, in microseconds on the driver's clock:
    /// a lock-free test for the receive path that returns without the lock.
    static NEXT_LINK_US: AtomicU64 = AtomicU64::new(0);

    /// The receive path found nothing to do; look at the PHY if it is time.
    fn poll_link_if_due() {
        let now = Mmio::new(BASE).now_us();
        if now < NEXT_LINK_US.load(Ordering::Relaxed) {
            return;
        }
        NEXT_LINK_US.store(now + LINK_POLL_US, Ordering::Relaxed);
        if let Some(d) = STATE.lock().as_mut() {
            if let Some(l) = d.link_poll() {
                report(l, d.stats());
            }
        }
    }

    /// Log a link change and the counters.
    fn report(l: Link, s: Stats) {
        azos_drv_sys::kprintln!(
            "[ETH] link {} (tx {} err {}, rx {} err {} drop {})",
            link_str(l), s.tx_frames, s.tx_errors, s.rx_frames, s.rx_errors, s.rx_dropped
        );
    }

    /// The `NetDevice` face; zero-sized, every method forwards to the static.
    pub struct DwmacNetDevice;

    impl NetDevice for DwmacNetDevice {
        #[inline]
        fn send(&self, frame: &[u8]) -> Result<usize, NetError> {
            match STATE.lock().as_mut() {
                Some(d) => d.send(frame),
                None => Err(NetError::NotReady),
            }
        }

        fn recv(&self, buf: &mut [u8]) -> Result<usize, NetError> {
            let mut n = 0;
            self.recv_batch(1, &mut |f| {
                n = f.len().min(buf.len());
                buf[..n].copy_from_slice(&f[..n]);
            });
            Ok(n)
        }

        #[inline]
        fn mac(&self) -> [u8; 6] {
            STATE.lock().as_ref().map_or([0; 6], |d| d.mac())
        }

        #[inline]
        fn is_ready(&self) -> bool {
            READY.load(Ordering::Acquire)
        }

        #[inline]
        fn tx_batch_begin(&self) {
            if let Some(d) = STATE.lock().as_mut() {
                d.tx_batch_begin();
            }
        }

        #[inline]
        fn tx_batch_end(&self) {
            if let Some(d) = STATE.lock().as_mut() {
                d.tx_batch_end();
            }
        }

        /// One lock to take the batch off the ring, none while `f` runs (it
        /// may send), one to hand the descriptors back. A single consumer
        /// (the net poll task) is assumed: two overlapping drains would
        /// release out of ring order.
        fn recv_batch(&self, max: usize, f: &mut dyn FnMut(&[u8])) -> usize {
            if irq_driven() && !RX_PENDING.load(Ordering::Acquire) {
                poll_link_if_due();
                return 0;
            }
            let mut got = [(0u16, 0u16); RX_BATCH];
            let mut views = [(core::ptr::null::<u8>(), 0usize); RX_BATCH];
            let (first, frames, used) = {
                let mut st = STATE.lock();
                let Some(d) = st.as_mut() else { return 0 };
                let first = d.rx_first();
                let (frames, used) = d.rx_harvest(&mut got[..max.min(RX_BATCH)]);
                for (v, &(desc, len)) in views.iter_mut().zip(&got[..frames]) {
                    let b = d.rx_frame(desc, len);
                    *v = (b.as_ptr(), b.len());
                }
                if used == 0 {
                    if irq_driven() {
                        // Empty: close the gate, then look once more so a
                        // frame landing in between is not lost.
                        RX_PENDING.store(false, Ordering::SeqCst);
                        if d.rx_ready() {
                            RX_PENDING.store(true, Ordering::Release);
                        }
                    }
                    if let Some(l) = d.link_poll() {
                        report(l, d.stats());
                    }
                    if FATAL.swap(false, Ordering::Relaxed) {
                        azos_drv_sys::kerr!("[ETH] DMA bus error: the channel has stopped");
                    }
                }
                (first, frames, used)
            };
            for &(p, n) in &views[..frames] {
                // SAFETY: the bytes are in the static `MEM`, which does not
                // move, and the descriptors stay the CPU's until the release
                // below (single consumer).
                f(unsafe { core::slice::from_raw_parts(p, n) });
            }
            if used != 0 {
                if let Some(d) = STATE.lock().as_mut() {
                    d.rx_release(first, used);
                }
            }
            frames
        }
    }
}
