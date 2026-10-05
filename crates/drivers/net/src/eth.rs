// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Ethernet driver skeleton — real NIC (complements VirtIO net for QEMU).
///
/// QEMU: no real Ethernet controller (use virtio-net instead); all ops return -1.
/// VF2:  address confirmed (`platform::hw::ETH0_BASE`, `gmac0@16030000`),
/// IP identity WRONG (U05-1, 2026-09-26): mainline `jh7110.dtsi` names this
/// node `compatible = "starfive,jh7110-dwmac", "snps,dwmac-5.20"` — a
/// Synopsys DesignWare QoS MAC (`stmmac` family) — not Cadence MACB/GEM.
/// Every register below (`NCR`/`NCFGR`/`RBQP`, this module's whole
/// register model) is the wrong IP's layout; unconditional on no board
/// today (`boot_hooks.rs`'s `vf2` MMIO map does not map `ETH0_BASE`), so
/// this is known-wrong dead code, not a live mis-program — left unrewritten
/// this pass (`stmmac`'s register model is a real driver's worth of work,
/// not a base-address fix).


/// How many bytes of a received frame may be copied out.
///
/// `frame_len` comes from the RX descriptor, which the **hardware** writes:
/// the MACB length field is 13 bits, so it can report up to 8191 while a DMA
/// slot holds `buf_size` (1536) and the ring's whole buffer static is only
/// `DESC_COUNT * buf_size`. Bounding by the caller's buffer alone is not
/// enough -- it was safe only because the one caller passes `ETH_FRAME_MAX`
/// (1514), i.e. safe by the caller's choice rather than by this driver's own
/// limit. A caller with a larger buffer, or a jumbo-frame change, would have
/// `copy_nonoverlapping` read past the static: adjacent frames first, then
/// unrelated kernel memory, into a buffer the network stack then parses.
///
/// A free function outside the `vf2` cfg on purpose, so the bound is testable
/// on a host without the MMIO half of the driver. `virtio::net` documents the
/// identical rule and was hardened first; this is the same class in the driver
/// that did not get the fix.
#[inline]
pub fn rx_copy_len(frame_len: usize, caller_buf: usize, buf_size: usize) -> usize {
    frame_len.min(caller_buf).min(buf_size)
}

/// Ethernet statistics counters.
#[derive(Clone, Copy)]
pub struct EthStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes:   u64,
    pub rx_bytes:   u64,
}

impl EthStats {
    pub const fn new() -> Self {
        EthStats { tx_packets: 0, rx_packets: 0, tx_bytes: 0, rx_bytes: 0 }
    }
}

// ── QEMU: no real Ethernet (use virtio-net) ─────────────────────────────────

#[cfg(not(feature = "vf2"))]
mod stub {
    #[allow(unused_imports)]
    use super::*;

    /// Initialise Ethernet.  Returns -1 on QEMU (no real NIC).
    pub fn eth_init() -> i32 {
        azos_drv_sys::kprintln!("[ETH] Not available (QEMU virt -- use virtio-net)");
        -1
    }

    /// Send an Ethernet frame.  Returns -1 (not available on QEMU).
    pub fn eth_send(_data: &[u8]) -> i32 { -1 }

    /// Receive an Ethernet frame.  Returns -1 (not available on QEMU).
    pub fn eth_recv(_buf: &mut [u8]) -> i32 { -1 }

    /// Get MAC address.  Returns all zeros on QEMU.
    pub fn eth_mac_addr() -> [u8; 6] { [0u8; 6] }

    pub fn eth_is_ready() -> bool { false }

    pub fn eth_info() {
        azos_drv_sys::kconsoleln!("[ETH] Not available (QEMU virt)");
        azos_drv_sys::kconsoleln!("[ETH]   Use virtio-net for network access");
    }
}

#[cfg(not(feature = "vf2"))]
pub use stub::*;

// ── VisionFive 2 / JH7110: Cadence MACB/GEM Ethernet ───────────────────────
//
// JH7110 has two Cadence GEM (Gigabit Ethernet MAC) controllers.
// ETH0 at 0x16030000 — primary interface (RGMII to PHY).
//
// Register map (Cadence GEM, 32-bit, offsets from base):
//   0x00  NCR    — Network Control: tx_en, rx_en, loopback, stats_clr
//   0x04  NCFGR  — Network Config: speed, full_duplex, copy_all, no_broadcast
//   0x08  NSR    — Network Status: link, MDIO idle, PHY management done
//   0x14  TSR    — Transmit Status: tx_complete, tx_err, tx_go
//   0x18  RBQP   — Receive Buffer Queue Pointer (descriptor ring base)
//   0x1C  TBQP   — Transmit Buffer Queue Pointer (descriptor ring base)
//   0x24  ISR    — Interrupt Status: rx_complete, tx_complete, errors
//   0x28  IER    — Interrupt Enable Register
//   0x2C  IDR    — Interrupt Disable Register
//   0x34  MAN    — PHY Maintenance (MDIO read/write)
//   0x88  SA1B   — Specific Address 1 Bottom (MAC bytes 0..3, little-endian)
//   0x8C  SA1T   — Specific Address 1 Top (MAC bytes 4..5)

#[cfg(feature = "vf2")]
mod macb {
    use super::*;
    use azos_sync::SpinLock;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const MACB_BASE: usize = azos_drv_base::platform::hw::ETH0_BASE;

    // Register offsets
    const NCR:   usize = 0x00;
    const NCFGR: usize = 0x04;
    const NSR:   usize = 0x08;
    const TSR:   usize = 0x14;
    const RBQP:  usize = 0x18;
    const TBQP:  usize = 0x1C;
    const ISR:   usize = 0x24;
    const IER:   usize = 0x28;
    const IDR:   usize = 0x2C;
    const MAN:   usize = 0x34;
    const SA1B:  usize = 0x88;
    const SA1T:  usize = 0x8C;

    // NCR bits
    const NCR_TX_EN:   u32 = 1 << 3;
    const NCR_RX_EN:   u32 = 1 << 2;
    const NCR_CLR_ST:  u32 = 1 << 5;  // clear statistics
    const NCR_TX_GO:   u32 = 1 << 9;  // start transmission

    // NCFGR bits
    const NCFGR_FD:    u32 = 1 << 1;  // full duplex
    const NCFGR_SPD:   u32 = 1 << 0;  // 100 Mbps
    const NCFGR_CAF:   u32 = 1 << 4;  // copy all frames (promiscuous)

    // TX descriptor word1 bits
    const TX_USED:     u32 = 1 << 31; // bit 31: used (available to software)
    const TX_WRAP:     u32 = 1 << 30; // bit 30: wrap (last descriptor in ring)
    const TX_LAST:     u32 = 1 << 15; // bit 15: last buffer of frame
    const TX_LEN_MASK: u32 = 0x3FFF;  // bits 13:0: buffer length

    // RX descriptor word0 bits
    const RX_ADDR_MASK: u32 = !0x3;   // bits 31:2: buffer address (4-byte aligned)
    const RX_OWN:       u32 = 1 << 0; // bit 0: ownership (0=SW, 1=HW)
    const RX_WRAP:      u32 = 1 << 1; // bit 1: wrap (last descriptor in ring)

    // RX descriptor word1 bits
    const RX_LEN_MASK: u32 = 0x1FFF;  // bits 12:0: received frame length
    const RX_SOF:      u32 = 1 << 14; // start of frame
    const RX_EOF:      u32 = 1 << 15; // end of frame

    // ── Descriptor ring sizing ──────────────────────────────────────────────────
    const DESC_COUNT: usize = 4;
    const BUF_SIZE:   usize = 1536; // must fit full Ethernet frame (1514) + alignment
    const RING_WORDS: usize = DESC_COUNT * 2; // 4 descriptors x 2 words each

    // ── Static DMA descriptor rings and buffers ─────────────────────────────────
    //
    // Cadence MACB DMA requires descriptor rings at fixed physical addresses.
    // We use static mutable arrays because:
    //   1. DMA descriptors must persist at stable addresses for hardware access.
    //   2. no_std bare-metal — no allocator available at init time.
    //   3. Each access is behind unsafe{} with proper volatile semantics.
    //
    // Alignment: descriptors must be 8-byte aligned (Cadence GEM spec).
    //            Buffers must be 4-byte aligned for DMA word access.
    #[repr(C, align(8))]
    struct DescRing([u32; RING_WORDS]);
    #[repr(C, align(4))]
    struct DmaBufs([u8; DESC_COUNT * BUF_SIZE]);

    static mut RX_RING: DescRing = DescRing([0u32; RING_WORDS]);
    static mut TX_RING: DescRing = DescRing([0u32; RING_WORDS]);
    static mut RX_BUFS: DmaBufs  = DmaBufs([0u8; DESC_COUNT * BUF_SIZE]);
    static mut TX_BUFS: DmaBufs  = DmaBufs([0u8; DESC_COUNT * BUF_SIZE]);

    /// Next TX descriptor index to use (round-robin).
    static TX_HEAD: AtomicUsize = AtomicUsize::new(0);
    /// Next RX descriptor index to check for received frames.
    static RX_HEAD: AtomicUsize = AtomicUsize::new(0);

    /// Set once eth_init() completes successfully.
    static INIT_DONE: AtomicBool = AtomicBool::new(false);

    static STATS: SpinLock<EthStats> = SpinLock::new(EthStats::new());

    #[inline(always)]
    fn rd(off: usize) -> u32 {
        unsafe { core::ptr::read_volatile((MACB_BASE + off) as *const u32) }
    }

    #[inline(always)]
    fn wr(off: usize, val: u32) {
        unsafe { core::ptr::write_volatile((MACB_BASE + off) as *mut u32, val) }
    }

    /// Initialise Cadence MACB Ethernet on JH7110.
    ///
    /// Sets up TX/RX descriptor rings, configures the MAC for 100 Mbps
    /// full-duplex, and enables TX/RX in the Network Control Register.
    /// Returns 0 on success.
    pub fn eth_init() -> i32 {
        let nsr = rd(NSR);
        let ncfgr_cur = rd(NCFGR);
        azos_drv_sys::kprintln!("[ETH] JH7110 Cadence MACB @ {:#010x}", MACB_BASE);
        azos_drv_sys::kprintln!("[ETH]   NSR={:#010x}  NCFGR={:#010x}", nsr, ncfgr_cur);

        // ── Disable TX/RX while we set up descriptor rings ──────────────────
        let ncr = rd(NCR);
        wr(NCR, ncr & !(NCR_TX_EN | NCR_RX_EN));

        // Clear statistics
        wr(NCR, rd(NCR) | NCR_CLR_ST);

        // ── Disable all interrupts — we use polling ─────────────────────────
        wr(IDR, 0xFFFF_FFFF);
        // Clear any pending interrupt status by reading ISR
        let _ = rd(ISR);

        // ── Initialise RX descriptor ring ───────────────────────────────────
        //
        // Each RX descriptor: word0 = buffer address | ownership | wrap
        //                     word1 = 0 (filled by hardware on receive)
        //
        // Ownership bit (word0 bit 0):
        //   0 = descriptor owned by hardware (ready to receive)
        //   1 = descriptor owned by software (frame received, SW must process)
        unsafe {
            let rx_bufs = core::ptr::addr_of!(RX_BUFS) as *const u8;
            let rx_ring = core::ptr::addr_of_mut!(RX_RING) as *mut u32;
            for i in 0..DESC_COUNT {
                let buf_addr = rx_bufs.add(i * BUF_SIZE) as u32;
                let mut w0 = buf_addr & RX_ADDR_MASK; // clear low 2 bits
                // Do NOT set RX_OWN — leave bit 0 = 0 means hardware owns it
                if i == DESC_COUNT - 1 {
                    w0 |= RX_WRAP; // mark last descriptor as wrap
                }
                core::ptr::write_volatile(rx_ring.add(i * 2), w0);
                core::ptr::write_volatile(rx_ring.add(i * 2 + 1), 0);
            }
            RX_HEAD.store(0, Ordering::Relaxed);
        }

        // ── Initialise TX descriptor ring ───────────────────────────────────
        //
        // Each TX descriptor: word0 = buffer address
        //                     word1 = TX_USED | length | flags
        //
        // TX_USED (bit 31) = 1 means "available to software" (hardware done).
        // We mark all descriptors as USED so the driver can claim them for send.
        unsafe {
            let tx_bufs = core::ptr::addr_of!(TX_BUFS) as *const u8;
            let tx_ring = core::ptr::addr_of_mut!(TX_RING) as *mut u32;
            for i in 0..DESC_COUNT {
                let buf_addr = tx_bufs.add(i * BUF_SIZE) as u32;
                let mut w1 = TX_USED; // mark as available to software
                if i == DESC_COUNT - 1 {
                    w1 |= TX_WRAP; // mark last descriptor as wrap
                }
                core::ptr::write_volatile(tx_ring.add(i * 2), buf_addr);
                core::ptr::write_volatile(tx_ring.add(i * 2 + 1), w1);
            }
            TX_HEAD.store(0, Ordering::Relaxed);
        }

        // ── Program descriptor ring base addresses into MACB ────────────────
        let rbqp = core::ptr::addr_of!(RX_RING) as u32;
        let tbqp = core::ptr::addr_of!(TX_RING) as u32;
        wr(RBQP, rbqp);
        wr(TBQP, tbqp);

        azos_drv_sys::kprintln!("[ETH]   RBQP={:#010x}  TBQP={:#010x}", rbqp, tbqp);

        // ── Configure MAC: full duplex, 100 Mbps, copy all frames ───────────
        wr(NCFGR, NCFGR_FD | NCFGR_SPD | NCFGR_CAF);

        // ── Enable TX and RX ────────────────────────────────────────────────
        let ncr_new = rd(NCR) | NCR_TX_EN | NCR_RX_EN;
        wr(NCR, ncr_new);

        // ── PHY maintenance — read PHY ID to confirm MDIO link ──────────────
        // MAN register: write a clause-22 read for PHY addr 0, reg 2 (PHYID1)
        // Format: SOF=01, OP=10(read), PHYAD=5bits, REGAD=5bits, TA=10
        let man_read_phyid = (0b01 << 30) | (0b10 << 28) | (0 << 23) | (2 << 18) | (0b10 << 16);
        wr(MAN, man_read_phyid);
        // Note: PHY read is async; result available after MDIO completes.
        // For init we just fire-and-forget; actual PHY negotiation is
        // typically handled by U-Boot/OpenSBI before kernel boot.

        // Read MAC address
        let mac = eth_mac_addr();
        azos_drv_sys::kprintln!("[ETH]   MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        // ── Clear TSR to acknowledge any prior TX status ────────────────────
        let tsr = rd(TSR);
        wr(TSR, tsr); // write-1-to-clear

        // ── Enable RX complete and TX complete interrupts (for future use) ──
        wr(IER, (1 << 1) | (1 << 7)); // bit 1 = rx_complete, bit 7 = tx_complete

        azos_drv_sys::kprintln!("[ETH]   NCR={:#010x}  NCFGR={:#010x} (TX+RX enabled)",
            rd(NCR), rd(NCFGR));

        INIT_DONE.store(true, Ordering::Release);
        0
    }

    /// Send an Ethernet frame via DMA.
    ///
    /// Finds a free TX descriptor (word1 bit 31 = USED), copies `data` into
    /// the corresponding DMA buffer, programs the descriptor, and triggers
    /// transmission.  Returns number of bytes sent, or -1 on failure.
    pub fn eth_send(data: &[u8]) -> i32 {
        if !INIT_DONE.load(Ordering::Acquire) {
            return -1;
        }
        if data.is_empty() || data.len() > BUF_SIZE {
            return -1;
        }

        unsafe {
            let idx = TX_HEAD.load(Ordering::Relaxed);
            let tx_ring = core::ptr::addr_of_mut!(TX_RING) as *mut u32;
            let w1 = core::ptr::read_volatile(tx_ring.add(idx * 2 + 1));

            // Check if descriptor is available (USED bit set by hardware = done)
            if w1 & TX_USED == 0 {
                // All TX descriptors busy — ring full
                return -1;
            }

            // Copy frame data into the DMA buffer
            let tx_bufs = core::ptr::addr_of_mut!(TX_BUFS) as *mut u8;
            let buf_ptr = tx_bufs.add(idx * BUF_SIZE);
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr, data.len());

            // Program descriptor: set buffer address
            let buf_addr = buf_ptr as u32;
            core::ptr::write_volatile(tx_ring.add(idx * 2), buf_addr);

            // Build word1: clear USED (give to hardware), set LAST, set length
            // Preserve WRAP bit from the existing descriptor.
            let wrap = if idx == DESC_COUNT - 1 { TX_WRAP } else { 0 };
            let new_w1 = wrap | TX_LAST | ((data.len() as u32) & TX_LEN_MASK);
            core::ptr::write_volatile(tx_ring.add(idx * 2 + 1), new_w1);

            // Advance TX head (round-robin)
            TX_HEAD.store((idx + 1) % DESC_COUNT, Ordering::Relaxed);

            // Trigger transmission by setting TX start bit in NCR
            let ncr = rd(NCR);
            wr(NCR, ncr | NCR_TX_GO);
        }

        // Update statistics
        let len = data.len();
        {
            let mut stats = STATS.lock();
            stats.tx_packets += 1;
            stats.tx_bytes += len as u64;
        }

        len as i32
    }

    /// Receive an Ethernet frame into `buf`.
    ///
    /// Checks the RX descriptor ring for completed frames (word0 bit 0 = 1
    /// means ownership transferred to software).  Copies the frame into `buf`
    /// and returns the number of bytes received, or 0 if no frame is available.
    pub fn eth_recv(buf: &mut [u8]) -> i32 {
        if !INIT_DONE.load(Ordering::Acquire) {
            return 0;
        }

        unsafe {
            let idx = RX_HEAD.load(Ordering::Relaxed);
            let rx_ring = core::ptr::addr_of_mut!(RX_RING) as *mut u32;
            let w0 = core::ptr::read_volatile(rx_ring.add(idx * 2));
            let w1 = core::ptr::read_volatile(rx_ring.add(idx * 2 + 1));

            // Check ownership: bit 0 of word0.  1 = software owns (frame received).
            if w0 & RX_OWN == 0 {
                // Hardware still owns this descriptor — no frame ready
                return 0;
            }

            // Validate: check for start-of-frame and end-of-frame in a single
            // descriptor (we use 512-byte buffers, typical frames fit in one).
            if w1 & RX_SOF == 0 || w1 & RX_EOF == 0 {
                // Multi-buffer frame or error — reclaim descriptor and skip.
                let new_w0 = w0 & !(RX_OWN);
                core::ptr::write_volatile(rx_ring.add(idx * 2), new_w0);
                core::ptr::write_volatile(rx_ring.add(idx * 2 + 1), 0);
                RX_HEAD.store((idx + 1) % DESC_COUNT, Ordering::Relaxed);
                return 0;
            }

            // Extract received frame length from word1 bits 12:0
            //
            // **Clamped to BUF_SIZE as well as to the caller's buffer.**
            // `RX_LEN_MASK` is 13 bits, so the hardware can report up to 8191
            // while a DMA slot is 1536 and the whole `RX_BUFS` static is only
            // `DESC_COUNT * BUF_SIZE` = 6144 bytes. Bounding by `buf.len()`
            // alone was safe only because the one caller passes
            // `ETH_FRAME_MAX` (1514) -- safe by the caller's buffer size
            // rather than by this driver's own bound. A caller with a larger
            // buffer, or a jumbo-frame change, would make
            // `copy_nonoverlapping` read past the static: adjacent frames
            // first, then unrelated kernel memory, straight into a buffer the
            // network stack parses. Not reachable today; a guarantee by
            // construction is exactly what a hardware bring-up invalidates.
            let frame_len = (w1 & RX_LEN_MASK) as usize;
            let copy_len = super::rx_copy_len(frame_len, buf.len(), BUF_SIZE);

            // Copy frame data from DMA buffer to user buffer
            let rx_bufs = core::ptr::addr_of!(RX_BUFS) as *const u8;
            let src = rx_bufs.add(idx * BUF_SIZE);
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), copy_len);

            // Reclaim descriptor: clear ownership bit (give back to hardware),
            // preserve wrap bit and buffer address.
            let buf_addr = rx_bufs.add(idx * BUF_SIZE) as u32;
            let mut new_w0 = buf_addr & RX_ADDR_MASK;
            if idx == DESC_COUNT - 1 {
                new_w0 |= RX_WRAP;
            }
            // word0 bit 0 = 0 → hardware owns it again
            core::ptr::write_volatile(rx_ring.add(idx * 2), new_w0);
            core::ptr::write_volatile(rx_ring.add(idx * 2 + 1), 0);

            // Advance RX head
            RX_HEAD.store((idx + 1) % DESC_COUNT, Ordering::Relaxed);

            // Update statistics
            {
                let mut stats = STATS.lock();
                stats.rx_packets += 1;
                stats.rx_bytes += copy_len as u64;
            }

            copy_len as i32
        }
    }

    /// Read MAC address from SA1B/SA1T registers.
    pub fn eth_mac_addr() -> [u8; 6] {
        let sa1b = rd(SA1B);
        let sa1t = rd(SA1T);
        [
            (sa1b & 0xFF) as u8,
            ((sa1b >> 8) & 0xFF) as u8,
            ((sa1b >> 16) & 0xFF) as u8,
            ((sa1b >> 24) & 0xFF) as u8,
            (sa1t & 0xFF) as u8,
            ((sa1t >> 8) & 0xFF) as u8,
        ]
    }

    pub fn eth_is_ready() -> bool {
        INIT_DONE.load(Ordering::Acquire)
    }

    pub fn eth_info() {
        let mac = eth_mac_addr();
        let nsr = rd(NSR);
        let stats = STATS.lock();
        let link = if nsr & (1 << 1) != 0 { "UP" } else { "DOWN" };
        azos_drv_sys::kconsoleln!("[ETH] JH7110 Cadence MACB @ {:#010x}", MACB_BASE);
        azos_drv_sys::kconsoleln!("[ETH]   MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        azos_drv_sys::kconsoleln!("[ETH]   Link: {} (NSR={:#010x})", link, nsr);
        azos_drv_sys::kconsoleln!("[ETH]   TX: {} packets, {} bytes", stats.tx_packets, stats.tx_bytes);
        azos_drv_sys::kconsoleln!("[ETH]   RX: {} packets, {} bytes", stats.rx_packets, stats.rx_bytes);
        let ncr_val = rd(NCR);
        let tx_en = if ncr_val & NCR_TX_EN != 0 { "yes" } else { "no" };
        let rx_en = if ncr_val & NCR_RX_EN != 0 { "yes" } else { "no" };
        azos_drv_sys::kconsoleln!("[ETH]   TX enabled: {}  RX enabled: {}", tx_en, rx_en);
        if INIT_DONE.load(Ordering::Acquire) {
            azos_drv_sys::kconsoleln!("[ETH]   Descriptor rings: {} TX, {} RX ({} byte bufs)",
                DESC_COUNT, DESC_COUNT, BUF_SIZE);
        } else {
            azos_drv_sys::kconsoleln!("[ETH]   Driver not initialised");
        }
    }
}

#[cfg(feature = "vf2")]
pub use macb::*;

// ── NetDevice ────────────────────────────────────────────────────────────
//
// A thin, zero-sized adapter over the free-function API above — the same
// pattern `UartDriver` (`azos_drv_sys::uart_driver`) uses over `azos_drv_sys::uart::*`.
// The stub/macb split stays exactly as it is; this just gives the two
// backends (this one and `virtio::net`) one call shape `net_device::select`
// can dispatch through.
use azos_drv_api::net::{NetDevice, NetError};

pub struct EthNetDevice;

impl NetDevice for EthNetDevice {
    /// `eth_send` returns a negative sentinel for "not available" (always
    /// the case on QEMU — see `stub` above) and the byte count otherwise.
    /// It does not distinguish "not ready" from "frame rejected", so every
    /// negative result maps to `NotReady`; a real per-cause split would mean
    /// changing `eth_send`'s own return type, which every other caller of
    /// this module (none today — see the crate's ownership note) would also
    /// have to absorb.
    #[inline]
    fn send(&self, frame: &[u8]) -> Result<usize, NetError> {
        let n = eth_send(frame);
        if n < 0 { Err(NetError::NotReady) } else { Ok(n as usize) }
    }

    /// Mirrors `net_raw_recv`'s old inline mapping exactly: negative or zero
    /// both mean "nothing to report right now", not an error.
    #[inline]
    fn recv(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        let n = eth_recv(buf);
        Ok(if n > 0 { n as usize } else { 0 })
    }

    #[inline]
    fn mac(&self) -> [u8; 6] {
        eth_mac_addr()
    }

    #[inline]
    fn is_ready(&self) -> bool {
        eth_is_ready()
    }
}
