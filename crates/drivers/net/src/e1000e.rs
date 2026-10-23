// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Intel e1000e Ethernet (Kconfig `DRV_E1000E`, cargo feature `e1000e`):
//! the 82574L QEMU models and the PCH LAN controllers (I217, I218, I219).
//!
//! The ids the bus binds it to are in `crates/drivers/net/hwbus.ids`; it is
//! one more backend of the NIC table of [`crate::net_device`].
//!
//! # Shape
//!
//! Two parts in this file and a shared one beside it:
//!
//! * **The wire format** (always compiled when the module is): register
//!   offsets and bits, the three descriptor layouts, the ring cursors, the
//!   MAC and link decoding, and [`E1000eWire`], which plugs them into the
//!   shared device half. No MMIO, no memory the device sees, no `unsafe`,
//!   so `tests/host/drivers-tests` runs every function against the e1000e
//!   software developer's manual's layouts on the host.
//! * **The device** (`feature = "e1000e"`): the reset, the queue set-up and
//!   the [`E1000eNetDevice`] entry points `net_device` forwards to.
//! * **[`crate::pci_nic`]**, shared with igc: the rings and buffers, the
//!   receive and transmit paths, the interrupt hook, the MSI wiring and the
//!   order of the bring-up.
//!
//! # Rings and buffers
//!
//! One receive ring and one transmit ring, in `.bss`, one 2 KiB buffer per
//! descriptor (`E1000E_RX_DESCS`, `E1000E_TX_DESCS`). The device is never
//! handed a caller's memory: `send` copies the frame into the descriptor's
//! staging buffer and returns, `recv` copies the frame out of the receive
//! buffer and re-posts it. Everything is mapped through the function's DMA
//! domain (`azos_drv_virtio::virtio::Dma`) before the controller is started,
//! the same way the virtio NIC's buffers are.
//!
//! The receive and transmit sides have a lock each, so a frame the stack
//! answers from inside the receive path can be sent without waiting for the
//! receive lock (`recv` copies out and drops nothing it holds across the
//! caller: the default `recv_batch` calls it once per frame).
//!
//! # Descriptor formats (Kconfig `E1000E_EXT_DESC`)
//!
//! Receive: the *legacy* write-back overlays the buffer address with the
//! length, checksum, status and errors; the *extended* one (selected by
//! `RFCTL.EXTEN`) carries a status-and-error word, the length and the VLAN
//! tag, and is what the Linux driver speaks. Both are 16 bytes and both have
//! status in the same low byte, so which one is in use only changes where
//! [`rx_status`] reads the length and the errors from. Transmit: the legacy
//! data descriptor has a 16-bit length, the extended data descriptor
//! (`DEXT` with `DTYP = 1`) a 20-bit one; the status write-back (`DD`) is in
//! the same place in both.
//!
//! # Interrupts
//!
//! One MSI when the machine routes it: the receive causes (`RXT0`, `RXDMT0`,
//! `RXO`) and the link-status change are unmasked in `IMS`; the transmit
//! side is reclaimed lazily by `send`. [`msi_irq`] runs in the interrupt
//! path: it reads `ICR` (which clears it), notes a link change, counts, and
//! takes no lock. Without a route the controller runs polled and
//! [`irq_driven`] is false.
//!
//! # Not done (needs the hardware)
//!
//! The I219 is behind the ME and an LPC-attached PHY power state; a cold
//! board may need the LANPHYPC toggle and the ULP exit that Linux's
//! `ich8lan.c` does before the PHY answers, and the Skylake-and-later parts
//! have the descriptor-ring flush workaround (`PCICFG_DESC_RING_STATUS`).
//! None of that is here: the QEMU model needs none of it and a wrong guess
//! at the vendor's chicken bits is worse than a missing one. The driver
//! reads the MAC the controller's own NVM load left in `RAL0/RAH0`.

#[cfg(not(target_endian = "little"))]
compile_error!("e1000e descriptors are little-endian words read as native u64s");

// ---------------------------------------------------------------------
// Registers (offsets from BAR 0) and bits
// ---------------------------------------------------------------------

pub const REG_CTRL: usize = 0x0000;
pub const REG_STATUS: usize = 0x0008;
pub const REG_EECD: usize = 0x0010;
pub const REG_ICR: usize = 0x00c0;
pub const REG_IMS: usize = 0x00d0;
pub const REG_IMC: usize = 0x00d8;
/// The interrupt block at 0xc0: the 8254x's, kept by the 82574 and by the
/// 82576 (the igb family, which igc drives as QEMU's `-device igb`).
pub const IRQ_REGS: crate::pci_nic::IrqRegs = crate::pci_nic::IrqRegs { icr: REG_ICR, ims: REG_IMS, imc: REG_IMC };
pub const REG_RCTL: usize = 0x0100;
pub const REG_TCTL: usize = 0x0400;
pub const REG_TIPG: usize = 0x0410;
pub const REG_RDBAL: usize = 0x2800;
pub const REG_RDBAH: usize = 0x2804;
pub const REG_RDLEN: usize = 0x2808;
pub const REG_RDH: usize = 0x2810;
pub const REG_RDT: usize = 0x2818;
pub const REG_RXDCTL: usize = 0x2828;
pub const REG_TDBAL: usize = 0x3800;
pub const REG_TDBAH: usize = 0x3804;
pub const REG_TDLEN: usize = 0x3808;
pub const REG_TDH: usize = 0x3810;
pub const REG_TDT: usize = 0x3818;
pub const REG_TXDCTL: usize = 0x3828;
pub const REG_RXCSUM: usize = 0x5000;
pub const REG_RFCTL: usize = 0x5008;
/// Multicast table array: 128 dwords.
pub const REG_MTA: usize = 0x5200;
pub const MTA_DWORDS: usize = 128;
pub const REG_RAL0: usize = 0x5400;
pub const REG_RAH0: usize = 0x5404;

pub const CTRL_SLU: u32 = 1 << 6;
pub const CTRL_FRCSPD: u32 = 1 << 11;
pub const CTRL_FRCDPX: u32 = 1 << 12;
pub const CTRL_RST: u32 = 1 << 26;
pub const CTRL_VME: u32 = 1 << 30;
pub const CTRL_PHY_RST: u32 = 1 << 31;
/// `CTRL` bits bring-up clears: forced speed and duplex (the link is
/// auto-negotiated), VLAN mode, and the PHY reset line.
pub const CTRL_CLEAR: u32 = CTRL_FRCSPD | CTRL_FRCDPX | CTRL_VME | CTRL_PHY_RST;

pub const STATUS_LU: u32 = 1 << 1;
pub const STATUS_SPEED_MASK: u32 = 0xc0;

pub const RCTL_EN: u32 = 1 << 1;
pub const RCTL_MPE: u32 = 1 << 4;
pub const RCTL_BAM: u32 = 1 << 15;
pub const RCTL_SECRC: u32 = 1 << 26;
/// Receive control: enabled, broadcast accepted, every multicast accepted
/// (the stack's own filter decides), the CRC stripped; `BSIZE` and `BSEX`
/// left 0 = 2048-byte buffers ([`BUF_SIZE`]).
pub const RCTL_RUN: u32 = RCTL_EN | RCTL_BAM | RCTL_MPE | RCTL_SECRC;

pub const TCTL_EN: u32 = 1 << 1;
pub const TCTL_PSP: u32 = 1 << 3;
pub const TCTL_RTLC: u32 = 1 << 24;
/// Transmit control: enabled, short frames padded to 60 bytes, the
/// collision threshold 15 and distance 63 the manual gives for full duplex,
/// late collisions retransmitted.
pub const TCTL_RUN: u32 = TCTL_EN | TCTL_PSP | TCTL_RTLC | (15 << 4) | (63 << 12);
/// Inter-packet gap for copper: IPGT 8, IPGR1 8, IPGR2 6.
pub const TIPG_COPPER: u32 = 8 | (8 << 10) | (6 << 20);

pub const XDCTL_GRAN: u32 = 1 << 24;
pub const XDCTL_QUEUE_ENABLE: u32 = 1 << 25;
pub const RFCTL_EXTEN: u32 = 1 << 15;
pub const EECD_AUTO_RD: u32 = 1 << 9;
pub const RAH_AV: u32 = 1 << 31;

/// Interrupt causes (`ICR`, `IMS`, `IMC`).
pub const ICR_LSC: u32 = 1 << 2;
pub const ICR_RXDMT0: u32 = 1 << 4;
pub const ICR_RXO: u32 = 1 << 6;
pub const ICR_RXT0: u32 = 1 << 7;
/// What wakes the receive path.
pub const ICR_RX: u32 = ICR_RXT0 | ICR_RXDMT0 | ICR_RXO;
/// What `IMS` unmasks in interrupt mode.
pub const IMS_RUN: u32 = ICR_RX | ICR_LSC;

// ---------------------------------------------------------------------
// Rings
// ---------------------------------------------------------------------

/// Bytes of one descriptor, in every format.
pub const DESC_BYTES: usize = 16;
/// Bytes of one receive or transmit buffer (`RCTL.BSIZE` = 0).
pub const BUF_SIZE: usize = 2048;
/// The largest frame `send` takes: header plus 1500 bytes of payload.
pub const TX_FRAME_MAX: usize = 1514;
/// The ring length is programmed in 128-byte units.
pub const RING_MULTIPLE: usize = 128 / DESC_BYTES;

/// Bytes the controller is told the ring of `n` descriptors holds.
pub const fn ring_bytes(n: usize) -> u32 {
    (n * DESC_BYTES) as u32
}

/// The index after `i` in a ring of `n`.
pub const fn ring_next(i: u16, n: usize) -> u16 {
    if i as usize + 1 >= n { 0 } else { i + 1 }
}

/// One descriptor as two little-endian words. What each means depends on the
/// ring and the direction (see the constructors and decoders below).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Desc {
    pub lo: u64,
    pub hi: u64,
}

const _: () = assert!(core::mem::size_of::<Desc>() == DESC_BYTES);

// ---- Receive ----

/// A receive descriptor handed to the controller: the buffer's bus address,
/// nothing else. The same in the legacy and the extended format.
pub const fn rx_post(buf_bus: u64) -> Desc {
    Desc { lo: buf_bus, hi: 0 }
}

/// Receive status bits (the low byte of the status word, both formats).
pub const RXD_STAT_DD: u8 = 1 << 0;
pub const RXD_STAT_EOP: u8 = 1 << 1;
/// Receive error bits (an `errors` byte; in the extended format the top
/// byte of the status-and-error word): CRC/alignment (`CE`), symbol (`SE`),
/// sequence (`SEQ`), carrier extension (`CXE`) and RX data (`RXE`). The
/// checksum errors (`TCPE`, `IPE`) are not here: no offload is enabled, so
/// they carry no meaning.
pub const RXD_ERR_FRAME: u8 = 0x01 | 0x02 | 0x04 | 0x10 | 0x80;

/// What a written-back receive descriptor says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxStatus {
    /// The controller is done with the descriptor.
    pub done: bool,
    /// Last descriptor of its frame.
    pub eop: bool,
    /// Bytes written to the buffer (CRC stripped).
    pub len: u16,
    /// A frame error bit is set ([`RXD_ERR_FRAME`]).
    pub bad: bool,
}

/// Decode the write-back of a receive descriptor from its second word.
///
/// Legacy: length in bits 15:0, checksum 31:16, status 39:32, errors 47:40.
/// Extended: the status-and-error word in 31:0 (status in its low byte,
/// errors in its top byte), length in 47:32, VLAN tag in 63:48.
pub const fn rx_status(hi: u64, extended: bool) -> RxStatus {
    let (status, errors, len) = if extended {
        (hi as u8, (hi >> 24) as u8, (hi >> 32) as u16)
    } else {
        ((hi >> 32) as u8, (hi >> 40) as u8, hi as u16)
    };
    RxStatus {
        done: status & RXD_STAT_DD != 0,
        eop: status & RXD_STAT_EOP != 0,
        len,
        bad: errors & RXD_ERR_FRAME != 0,
    }
}

/// Whether a written-back descriptor is a frame the stack should see:
/// complete in one descriptor, error-free, at least an Ethernet header, and
/// one the caller's buffer can hold. `discarding` is set while the tail of a
/// frame that spilled over several descriptors drains (the buffers are
/// 2 KiB and jumbo frames are off, so it is a hardware misbehaviour, not a
/// case to deliver).
pub const fn rx_accept(st: &RxStatus, discarding: bool, room: usize) -> bool {
    !discarding && st.eop && !st.bad && st.len as usize >= 14 && st.len as usize <= room
}

/// Receive-side bookkeeping, apart from the memory: which descriptor is next
/// to read and how many consumed ones have not been given back to the
/// controller (written to `RDT`) yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxCursor {
    pub clean: u16,
    pub unposted: u16,
    /// The tail of a frame the driver dropped is still arriving.
    pub discarding: bool,
}

impl RxCursor {
    pub const fn new() -> Self {
        RxCursor { clean: 0, unposted: 0, discarding: false }
    }

    /// The `RDT` that hands every descriptor but one to the controller: the
    /// one before `clean` stays with the driver, so a full ring (head ==
    /// tail) cannot be mistaken for an empty one. Initially `n - 1`.
    pub const fn rdt(&self, n: usize) -> u16 {
        if self.clean == 0 { (n - 1) as u16 } else { self.clean - 1 }
    }

    /// Consume the descriptor at `clean`: returns its index. The caller
    /// re-posts it ([`rx_post`]) before the next `flush_due`.
    pub fn take(&mut self, n: usize) -> u16 {
        let i = self.clean;
        self.clean = ring_next(i, n);
        self.unposted = self.unposted.saturating_add(1);
        i
    }

    /// Whether `unposted` descriptors are enough to be worth an `RDT` write
    /// now (`batch` of them); the write is also made whenever the ring is
    /// found empty, so nothing waits behind a half batch.
    pub const fn flush_due(&self, batch: u16) -> bool {
        self.unposted >= batch
    }

    pub fn flushed(&mut self) {
        self.unposted = 0;
    }
}

// ---- Transmit ----

/// Transmit command bits (the byte above the length, both formats).
pub const TXD_CMD_EOP: u8 = 1 << 0;
pub const TXD_CMD_IFCS: u8 = 1 << 1;
pub const TXD_CMD_RS: u8 = 1 << 3;
pub const TXD_CMD_DEXT: u8 = 1 << 5;
/// `DTYP` = 1 (data descriptor), bits 23:20 of the extended format.
pub const TXD_DTYP_DATA: u64 = 1 << 20;
/// Descriptor done, in the status nibble of the second dword.
pub const TXD_STAT_DD: u64 = 1;

/// A transmit descriptor for one whole frame in one buffer: end of packet,
/// the FCS appended by the controller, a status write-back when done.
///
/// Legacy: length in 15:0 of the second word's low dword, command in 31:24.
/// Extended: length in 19:0, `DTYP` in 23:20, command (with `DEXT`) in 31:24.
pub const fn tx_frame(buf_bus: u64, len: usize, extended: bool) -> Desc {
    let cmd = (TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS) as u64;
    let dword = if extended {
        (len as u64 & 0xf_ffff) | TXD_DTYP_DATA | ((cmd | TXD_CMD_DEXT as u64) << 24)
    } else {
        (len as u64 & 0xffff) | (cmd << 24)
    };
    Desc { lo: buf_bus, hi: dword }
}

/// Has the controller written the transmit descriptor back? (`DD`, bit 0 of
/// the second dword's status nibble: the same place in both formats.)
pub const fn tx_done(hi: u64) -> bool {
    (hi >> 32) & TXD_STAT_DD != 0
}

/// Transmit-side bookkeeping: the oldest descriptor the controller may
/// still own (`clean`) and the next to fill (`tail`). One slot stays empty,
/// so `clean == tail` means empty and `next(tail) == clean` full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxCursor {
    pub clean: u16,
    pub tail: u16,
}

impl TxCursor {
    pub const fn new() -> Self {
        TxCursor { clean: 0, tail: 0 }
    }

    pub const fn full(&self, n: usize) -> bool {
        ring_next(self.tail, n) == self.clean
    }

    /// Claim the slot at `tail`: returns its index, `None` when full.
    pub fn push(&mut self, n: usize) -> Option<u16> {
        if self.full(n) {
            return None;
        }
        let i = self.tail;
        self.tail = ring_next(i, n);
        Some(i)
    }

    /// Give back the descriptors the controller has finished, oldest first,
    /// stopping at the first that `done` says is still in flight. Returns
    /// how many.
    pub fn reclaim(&mut self, n: usize, mut done: impl FnMut(u16) -> bool) -> usize {
        let mut freed = 0;
        while self.clean != self.tail && done(self.clean) {
            self.clean = ring_next(self.clean, n);
            freed += 1;
        }
        freed
    }
}

/// Whether a send must write `TDT` now: outside a batch, or when `pending`
/// frames have piled up to `batch_max`.
pub const fn tx_doorbell_due(depth: u16, pending: u16, batch_max: u16) -> bool {
    depth == 0 || pending >= batch_max
}

// ---------------------------------------------------------------------
// MAC, link
// ---------------------------------------------------------------------

/// The station address `RAL0`/`RAH0` hold: the controller's NVM load puts
/// it there at reset. `None` for the values an unprogrammed or unreadable
/// register file gives: all zero, all ones, or a multicast address.
pub const fn mac_from_ra(ral: u32, rah: u32) -> Option<[u8; 6]> {
    let mac = [ral as u8, (ral >> 8) as u8, (ral >> 16) as u8, (ral >> 24) as u8, rah as u8, (rah >> 8) as u8];
    let mut zero = true;
    let mut ones = true;
    let mut i = 0;
    while i < 6 {
        zero &= mac[i] == 0;
        ones &= mac[i] == 0xff;
        i += 1;
    }
    if zero || ones || mac[0] & 1 != 0 {
        None
    } else {
        Some(mac)
    }
}

/// `RAL0` and `RAH0` that make `mac` the one unicast filter (address valid).
pub const fn ra_from_mac(mac: [u8; 6]) -> (u32, u32) {
    let ral = mac[0] as u32 | (mac[1] as u32) << 8 | (mac[2] as u32) << 16 | (mac[3] as u32) << 24;
    let rah = mac[4] as u32 | (mac[5] as u32) << 8 | RAH_AV;
    (ral, rah)
}

/// What `STATUS` says about the link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    pub up: bool,
    /// 10, 100 or 1000 (0 when the link is down).
    pub mbps: u16,
}

pub const fn link_from_status(status: u32) -> Link {
    if status & STATUS_LU == 0 {
        return Link { up: false, mbps: 0 };
    }
    let mbps = match status & STATUS_SPEED_MASK {
        0x00 => 10,
        0x40 => 100,
        _ => 1000,
    };
    Link { up: true, mbps }
}

/// Whether an `ICR` value carries a cause that makes the receive path run.
pub const fn icr_wakes_rx(icr: u32) -> bool {
    icr & ICR_RX != 0
}

// ---------------------------------------------------------------------
// The wire map, as the shared device half runs it
// ---------------------------------------------------------------------

/// Kconfig `E1000E_EXT_DESC`.
pub const EXT: bool = azos_limits::E1000E_EXT_DESC;

/// e1000e's register map, descriptors and link decoding for
/// [`crate::pci_nic`], the device half this driver shares with igc.
pub struct E1000eWire;

impl crate::pci_nic::Wire for E1000eWire {
    const NAME: &'static str = "e1000e";
    const RX: crate::pci_nic::RingRegs = crate::pci_nic::RingRegs {
        bal: REG_RDBAL,
        bah: REG_RDBAH,
        len: REG_RDLEN,
        head: REG_RDH,
        tail: REG_RDT,
        ctl: REG_RXDCTL,
    };
    const TX: crate::pci_nic::RingRegs = crate::pci_nic::RingRegs {
        bal: REG_TDBAL,
        bah: REG_TDBAH,
        len: REG_TDLEN,
        head: REG_TDH,
        tail: REG_TDT,
        ctl: REG_TXDCTL,
    };
    const IRQ: crate::pci_nic::IrqRegs = IRQ_REGS;

    #[inline(always)]
    fn rx_status(hi: u64) -> RxStatus {
        rx_status(hi, EXT)
    }

    #[inline(always)]
    fn tx_frame(buf_bus: u64, len: usize) -> Desc {
        tx_frame(buf_bus, len, EXT)
    }

    #[inline(always)]
    fn link(status: u32) -> Link {
        link_from_status(status)
    }
}

// ---------------------------------------------------------------------
// The device
// ---------------------------------------------------------------------

#[cfg(feature = "e1000e")]
pub use device::*;

#[cfg(feature = "e1000e")]
mod device {
    use super::*;
    use crate::pci_nic::{Chip, IrqRegs, Mem, Nic, NicError, Regs, Wire};
    use azos_drv_api::net::{NetDevice, NetError};
    use azos_drv_virtio::virtio::pci::msix_selftest::MsiRoute;
    use azos_pci::{BarWindow, ConfigSpace, FunctionInfo};

    /// Kconfig `E1000E_RX_DESCS` / `E1000E_TX_DESCS`.
    const RX_N: usize = azos_limits::E1000E_RX_DESCS as usize;
    const TX_N: usize = azos_limits::E1000E_TX_DESCS as usize;

    static MEM: Mem<RX_N, TX_N> = Mem::new();
    static NIC: Nic<E1000eWire, RX_N, TX_N> = Nic::new(&MEM);

    impl Chip for E1000eWire {
        type Model = ();
        /// Kconfig `E1000E_LINK_WAIT_MS`.
        const LINK_WAIT_US: u64 = azos_limits::E1000E_LINK_WAIT_MS as u64 * 1000;

        fn identify(_info: &FunctionInfo) -> Result<(), NicError> {
            Ok(())
        }

        fn irq_regs(_model: ()) -> IrqRegs {
            IRQ_REGS
        }

        /// Manual reset: mask interrupts, stop both engines, let in-flight
        /// DMA finish, then `CTRL.RST`; the bit clears itself.
        fn reset(r: &Regs<Self>, _info: &FunctionInfo, _model: ()) -> Result<(), NicError> {
            r.quiesce();
            if !r.reset_via(CTRL_RST) {
                return Err(NicError::ResetTimeout);
            }
            r.after_reset();
            r.link_setup();
            Ok(())
        }

        fn start_queues(r: &Regs<Self>, rx_ring_bus: u64, tx_ring_bus: u64, rx_n: usize, tx_n: usize) {
            // Transmit ring, then receive ring, then the engines.
            r.describe_ring(&Self::TX, tx_ring_bus, tx_n);
            r.zero_ring(&Self::TX);
            r.wr(REG_TXDCTL, r.rd(REG_TXDCTL) | XDCTL_GRAN | XDCTL_QUEUE_ENABLE);
            r.wr(REG_TIPG, TIPG_COPPER);
            r.describe_ring(&Self::RX, rx_ring_bus, rx_n);
            r.zero_ring(&Self::RX);
            r.wr(REG_RXDCTL, r.rd(REG_RXDCTL) | XDCTL_GRAN | XDCTL_QUEUE_ENABLE);
            // The 82574 and the PCH parts report the queue enable bit
            // sticky (Linux waits for it).
            r.await_queues();
            // No checksum offload; extended descriptors on request.
            r.wr(REG_RXCSUM, 0);
            if EXT {
                r.wr(REG_RFCTL, r.rd(REG_RFCTL) | RFCTL_EXTEN);
            } else {
                r.wr(REG_RFCTL, r.rd(REG_RFCTL) & !RFCTL_EXTEN);
            }
            r.wr(REG_TCTL, TCTL_RUN);
            r.wr(REG_RCTL, RCTL_RUN);
        }

        fn detail(_model: (), f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "desc={}", if EXT { "ext" } else { "legacy" })
        }
    }

    /// Bring up the e1000e function `info` as a NIC of the table (see
    /// [`Nic::init_pci`]).
    pub fn init_pci<C, R>(
        cfg: &mut C,
        info: &FunctionInfo,
        window: &mut BarWindow,
        route: &mut R,
    ) -> Result<(), NicError>
    where
        C: ConfigSpace,
        R: MsiRoute,
    {
        NIC.init_pci(cfg, info, window, route)
    }

    /// Interrupt-path hook: `true` when `token` is this NIC's vector (see
    /// [`Nic::msi_irq`]).
    #[inline]
    pub fn msi_irq(token: u32) -> bool {
        NIC.msi_irq(token)
    }

    /// `true` once the NIC's MSI is programmed.
    pub fn irq_driven() -> bool {
        NIC.irq_driven()
    }

    /// Receive interrupts taken so far.
    pub fn rx_irq_count() -> u32 {
        NIC.rx_irq_count()
    }

    /// `NetDevice` over the shared NIC, as `EthNetDevice` and
    /// `VirtioNetDevice` are over theirs.
    pub struct E1000eNetDevice;

    impl NetDevice for E1000eNetDevice {
        #[inline]
        fn send(&self, frame: &[u8]) -> Result<usize, NetError> {
            NIC.send(frame)
        }
        #[inline]
        fn recv(&self, buf: &mut [u8]) -> Result<usize, NetError> {
            NIC.recv(buf)
        }
        fn mac(&self) -> [u8; 6] {
            NIC.mac()
        }
        fn is_ready(&self) -> bool {
            NIC.is_ready()
        }
        #[inline]
        fn tx_batch_begin(&self) {
            NIC.tx_batch_begin()
        }
        #[inline]
        fn tx_batch_end(&self) {
            NIC.tx_batch_end()
        }
        #[inline]
        fn tx_watch(&self) -> Option<u64> {
            NIC.tx_watch()
        }
    }
}

// ---------------------------------------------------------------------
// Host tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// **Discriminates.** The legacy and the extended write-back put the
    /// length and the status in different places: the same hardware words
    /// decode differently, and each format decodes its own. Swap the two
    /// arms of `rx_status` and both halves fail.
    #[test]
    fn rx_status_reads_each_format_where_the_manual_puts_it() {
        // Legacy: length 0x0123, checksum 0xbeef, status DD|EOP, errors 0.
        let legacy = 0x0123 | 0xbeef << 16 | ((RXD_STAT_DD | RXD_STAT_EOP) as u64) << 32;
        let st = rx_status(legacy, false);
        assert_eq!(st, RxStatus { done: true, eop: true, len: 0x0123, bad: false });
        // Extended: status-and-error word 0x00000003 in 31:0, length 0x0456
        // in 47:32, VLAN tag in 63:48.
        let ext = 0x3 | 0x0456 << 32 | 0x8100 << 48;
        let st = rx_status(ext, true);
        assert_eq!(st, RxStatus { done: true, eop: true, len: 0x0456, bad: false });
        // Read with the wrong format, neither is right.
        assert_ne!(rx_status(legacy, true).len, 0x0123);
        assert_ne!(rx_status(ext, false).len, 0x0456);
    }

    /// **Discriminates.** A descriptor the controller has not written back
    /// reads as not done, whatever length garbage the buffer address left
    /// behind in the legacy overlay; a frame error sets `bad` in both
    /// formats (the legacy errors byte, the extended word's top byte), and
    /// a checksum-only error does not.
    #[test]
    fn rx_status_done_and_errors() {
        assert!(!rx_status(0x0600, false).done);
        assert!(!rx_status(0x0600 << 32, true).done);
        let dd_eop = (RXD_STAT_DD | RXD_STAT_EOP) as u64;
        // CRC error (bit 0 of the errors byte).
        assert!(rx_status(dd_eop << 32 | 0x01 << 40 | 60, false).bad);
        assert!(rx_status(dd_eop | 0x01 << 24 | 60 << 32, true).bad);
        // RXE (bit 7).
        assert!(rx_status(dd_eop << 32 | 0x80 << 40 | 60, false).bad);
        assert!(rx_status(dd_eop | 0x80 << 24 | 60 << 32, true).bad);
        // TCPE and IPE only: not a frame error.
        assert!(!rx_status(dd_eop << 32 | 0x60 << 40 | 60, false).bad);
        assert!(!rx_status(dd_eop | 0x60 << 24 | 60 << 32, true).bad);
    }

    /// **Discriminates.** What the stack is handed: one whole good frame
    /// that fits. A part of a frame (no EOP), an errored one, a runt, one
    /// the caller cannot hold, and anything while the tail of a dropped
    /// frame drains are each refused; flipping any one condition of
    /// `rx_accept` fails its line.
    #[test]
    fn rx_accept_refuses_everything_but_a_whole_good_frame() {
        let good = RxStatus { done: true, eop: true, len: 60, bad: false };
        assert!(rx_accept(&good, false, 1514));
        assert!(!rx_accept(&RxStatus { eop: false, ..good }, false, 1514), "no EOP");
        assert!(!rx_accept(&RxStatus { bad: true, ..good }, false, 1514), "errors");
        assert!(!rx_accept(&RxStatus { len: 13, ..good }, false, 1514), "shorter than a header");
        assert!(rx_accept(&RxStatus { len: 14, ..good }, false, 1514), "exactly a header");
        assert!(!rx_accept(&RxStatus { len: 1515, ..good }, false, 1514), "does not fit");
        assert!(rx_accept(&RxStatus { len: 1514, ..good }, false, 1514), "exactly fits");
        assert!(!rx_accept(&good, true, 1514), "draining a dropped frame");
    }

    /// **Discriminates.** Both transmit layouts bit for bit: the legacy has
    /// a 16-bit length and the command in 31:24 (EOP|IFCS|RS = 0x0b); the
    /// extended adds `DTYP` = 1 and `DEXT` (0x20 in the command byte) and
    /// has a 20-bit length. A frame of 1514 bytes fits both; one of 70000
    /// bytes shows the legacy truncates at 16 bits and the extended at 20.
    #[test]
    fn tx_frame_encodes_both_layouts() {
        let legacy = tx_frame(0x1000, 60, false);
        assert_eq!(legacy.lo, 0x1000);
        assert_eq!(legacy.hi, 0x0b00_003c);
        let ext = tx_frame(0x1000, 60, true);
        assert_eq!(ext.lo, 0x1000);
        assert_eq!(ext.hi, 0x2b10_003c);
        assert_eq!(tx_frame(0, 1514, false).hi & 0xffff, 1514);
        assert_eq!(tx_frame(0, 70000, false).hi & 0xffff_ffff, 0x0b00_0000 | (70000 & 0xffff));
        assert_eq!(tx_frame(0, 70000, true).hi & 0xf_ffff, 70000);
    }

    /// **Discriminates.** `DD` is bit 0 of the second dword's status
    /// nibble in both transmit formats, and a descriptor the driver filled
    /// (command bits, length, no status) is not done.
    #[test]
    fn tx_done_reads_the_status_nibble() {
        assert!(!tx_done(tx_frame(0x1000, 60, false).hi));
        assert!(!tx_done(tx_frame(0x1000, 60, true).hi));
        assert!(tx_done(tx_frame(0x1000, 60, false).hi | 1 << 32));
        assert!(tx_done(tx_frame(0x1000, 60, true).hi | 1 << 32));
        // Bit 0 of the low dword is the length, not a status.
        assert!(!tx_done(1));
    }

    /// **Discriminates.** The station address byte order: `RAL0` carries
    /// bytes 0-3 least significant first, `RAH0` bytes 4-5, and its AV bit
    /// is not part of the address. Unprogrammed values are refused: zeros,
    /// ones, and a multicast address (bit 0 of the first byte).
    #[test]
    fn mac_from_ra_orders_bytes_and_refuses_junk() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let (ral, rah) = ra_from_mac(mac);
        assert_eq!(ral, 0x1200_5452);
        assert_eq!(rah, 0x8000_5634);
        assert_eq!(mac_from_ra(ral, rah), Some(mac));
        assert_eq!(mac_from_ra(ral, rah & !RAH_AV), Some(mac), "AV is not part of the address");
        assert_eq!(mac_from_ra(0, 0), None);
        assert_eq!(mac_from_ra(!0, 0xffff), None);
        assert_eq!(mac_from_ra(0x1200_5453, rah), None, "multicast");
    }

    /// **Discriminates.** Link from `STATUS`: down is down whatever the
    /// speed bits say; up reports 10, 100, and 1000 for both encodings of
    /// gigabit (0x80 and 0xc0).
    #[test]
    fn link_from_status_decodes_speed() {
        assert_eq!(link_from_status(0x40), Link { up: false, mbps: 0 });
        assert_eq!(link_from_status(STATUS_LU), Link { up: true, mbps: 10 });
        assert_eq!(link_from_status(STATUS_LU | 0x40), Link { up: true, mbps: 100 });
        assert_eq!(link_from_status(STATUS_LU | 0x80), Link { up: true, mbps: 1000 });
        assert_eq!(link_from_status(STATUS_LU | 0xc0), Link { up: true, mbps: 1000 });
    }

    /// **Discriminates.** The transmit cursor keeps one slot empty: a ring
    /// of 8 takes 7 frames, refuses the 8th, and takes it again once one
    /// completes, with the indices wrapping past the end.
    #[test]
    fn tx_cursor_fills_to_n_minus_one_and_wraps() {
        let n = 8;
        let mut c = TxCursor::new();
        for i in 0..7 {
            assert_eq!(c.push(n), Some(i));
        }
        assert!(c.full(n));
        assert_eq!(c.push(n), None);
        // The controller finishes the first three.
        let mut done = [true, true, true, false, false, false, false, false];
        let freed = c.reclaim(n, |i| done[i as usize]);
        assert_eq!(freed, 3);
        assert!(!c.full(n));
        // Three more fit, wrapping past index 7.
        assert_eq!(c.push(n), Some(7));
        assert_eq!(c.push(n), Some(0));
        assert_eq!(c.push(n), Some(1));
        assert!(c.full(n));
        // Reclaim stops at the first descriptor still in flight, even if a
        // later one reads done.
        done = [false, true, true, false, true, true, true, true];
        assert_eq!(c.reclaim(n, |i| done[i as usize]), 0, "descriptor 3 is oldest and not done");
    }

    /// **Discriminates.** The doorbell: outside a batch every frame rings
    /// it; inside one only the frame that reaches the bound does, and the
    /// batch end flushes the rest.
    #[test]
    fn tx_doorbell_due_follows_the_batch() {
        assert!(tx_doorbell_due(0, 1, 8));
        assert!(!tx_doorbell_due(1, 1, 8));
        assert!(!tx_doorbell_due(2, 7, 8));
        assert!(tx_doorbell_due(1, 8, 8));
    }

    /// **Discriminates.** The receive tail: before any frame it is `n - 1`
    /// (one descriptor stays with the driver); after consuming `k` it is
    /// `k - 1`, wrapping to `n - 1` at `k = n`. A tail equal to the next
    /// descriptor to read would hand the controller a ring it reads as
    /// empty.
    #[test]
    fn rx_cursor_tail_trails_the_read_index_by_one() {
        let n = 8;
        let mut c = RxCursor::new();
        assert_eq!(c.rdt(n), 7);
        assert_eq!(c.take(n), 0);
        assert_eq!(c.rdt(n), 0);
        for _ in 1..7 {
            c.take(n);
        }
        assert_eq!(c.clean, 7);
        assert_eq!(c.rdt(n), 6);
        assert_eq!(c.take(n), 7);
        assert_eq!(c.clean, 0);
        assert_eq!(c.rdt(n), 7, "full circle");
    }

    /// **Discriminates.** The `RDT` write is batched: not due until `batch`
    /// descriptors are waiting, due then, and clear after it is made.
    #[test]
    fn rx_cursor_batches_the_tail_write() {
        let n = 64;
        let mut c = RxCursor::new();
        for _ in 0..7 {
            c.take(n);
        }
        assert!(!c.flush_due(8));
        c.take(n);
        assert!(c.flush_due(8));
        c.flushed();
        assert!(!c.flush_due(8));
        assert_eq!(c.unposted, 0);
    }

    /// The software model of the controller used below: it owns the ring
    /// from `RDH` to `RDT`, writes a frame into the buffer of the next
    /// descriptor it owns and writes the descriptor back.
    struct FakeRx {
        ring: [Desc; 8],
        head: usize,
        ext: bool,
    }

    impl FakeRx {
        fn deliver(&mut self, tail: usize, len: u16, eop: bool, errors: u8) -> bool {
            if self.head == tail {
                return false; // the controller owns nothing: frame dropped
            }
            let status = RXD_STAT_DD | if eop { RXD_STAT_EOP } else { 0 };
            self.ring[self.head].hi = if self.ext {
                status as u64 | (errors as u64) << 24 | (len as u64) << 32
            } else {
                len as u64 | (status as u64) << 32 | (errors as u64) << 40
            };
            self.head = (self.head + 1) % 8;
            true
        }
    }

    /// The whole receive handshake against that model, in both formats: a
    /// burst of frames is read back in order with the right lengths, a
    /// frame the controller had no room for is the only one lost, the
    /// ring runs dry exactly when it should and refills after the tail
    /// write. **Discriminates** a cursor that mis-orders, skips or
    /// re-reads a descriptor, and a tail that is off by one (the model
    /// drops a frame when `head == tail`).
    #[test]
    fn rx_ring_round_trips_a_burst_in_both_formats() {
        for ext in [false, true] {
            let n = 8;
            let mut dev = FakeRx { ring: [rx_post(0); 8], head: 0, ext };
            let mut cur = RxCursor::new();
            let mut tail = cur.rdt(n) as usize;
            // Eight arrive; the controller owns descriptors 0..=6 only.
            let accepted: usize = (0..8).map(|i| dev.deliver(tail, 60 + i, true, 0) as usize).sum();
            assert_eq!(accepted, 7, "one descriptor always stays with the driver");
            let mut got = [0u16; 8];
            let mut k = 0;
            loop {
                let st = rx_status(dev.ring[cur.clean as usize].hi, ext);
                if !st.done {
                    break;
                }
                assert!(rx_accept(&st, cur.discarding, 1514));
                got[k] = st.len;
                k += 1;
                let i = cur.take(n);
                dev.ring[i as usize] = rx_post(0x1000 * i as u64); // re-posted: DD cleared
            }
            assert_eq!(&got[..7], &[60, 61, 62, 63, 64, 65, 66]);
            assert_eq!(k, 7);
            tail = cur.rdt(n) as usize;
            cur.flushed();
            assert_eq!(tail, 6);
            // The ring is whole again: the next burst is accepted.
            assert!(dev.deliver(tail, 100, true, 0));
            assert!(rx_status(dev.ring[cur.clean as usize].hi, ext).done);
            assert_eq!(rx_status(dev.ring[cur.clean as usize].hi, ext).len, 100);
        }
    }

    /// **Discriminates.** A frame that spilled over two descriptors is
    /// dropped whole: the first (no EOP) and the second (EOP) are both
    /// refused, and the frame after them is delivered. A cursor that
    /// forgets to arm `discarding` delivers the second half as a frame.
    #[test]
    fn rx_split_frame_is_dropped_as_a_whole() {
        let first = RxStatus { done: true, eop: false, len: 2048, bad: false };
        let second = RxStatus { done: true, eop: true, len: 300, bad: false };
        let next = RxStatus { done: true, eop: true, len: 90, bad: false };
        let mut discarding = false;
        let mut verdicts = [false; 3];
        for (i, st) in [first, second, next].iter().enumerate() {
            verdicts[i] = rx_accept(st, discarding, 1514);
            discarding = !st.eop;
        }
        assert_eq!(verdicts, [false, false, true]);
    }

    /// **Discriminates.** The values that program the controller, against
    /// the manual's register maps: the ring length is in 128-byte units, a
    /// ring of 64 receive descriptors is 1024 bytes, and the control words
    /// are what bring-up writes (enable bit, broadcast, strip CRC).
    #[test]
    fn programmed_values() {
        assert_eq!(RING_MULTIPLE, 8);
        assert_eq!(ring_bytes(64), 1024);
        assert_eq!(RCTL_RUN, 1 << 1 | 1 << 4 | 1 << 15 | 1 << 26);
        assert_eq!(TCTL_RUN, 0x0100_000a | 15 << 4 | 63 << 12);
        assert_eq!(TIPG_COPPER, 0x0060_2008);
        assert_eq!(IMS_RUN, 0x80 | 0x10 | 0x40 | 0x04);
        assert!(icr_wakes_rx(ICR_RXT0));
        assert!(!icr_wakes_rx(ICR_LSC), "a link change alone is not a frame");
    }
}
