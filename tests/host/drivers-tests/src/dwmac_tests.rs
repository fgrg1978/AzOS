// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Synopsys DesignWare QoS driver (`crates/drivers/net/src/dwmac.rs`)
//! against a model of the device: its register file, a Clause 22 PHY behind
//! the MDIO interface, and a DMA engine that walks the very descriptor rings
//! the driver built (with the stride the driver programmed into `DSL`).
//!
//! What the model checks beyond "the frame came out": the engine refuses to
//! run on a ring the driver set up inconsistently (stride, length, tail), and
//! every cache-maintenance call and register write goes into one log, so the
//! hand-over order a non-coherent master needs (buffer, then descriptor, then
//! the tail doorbell; the descriptor taken back before it is read) is asserted
//! rather than assumed. The model cannot tell whether the register OFFSETS
//! match the silicon: that is the `[verify]` list in the module doc.
//!
//! Wired by `mod dwmac_tests;` in `lib.rs`.

use super::dwmac::*;
use azos_dma::Direction;
use azos_drv_api::net::NetError;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;

// ── The model ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ev {
    Wr(usize, u32),
    SyncDev(u64, usize, Direction),
    SyncCpu(u64, usize, Direction),
}

#[derive(Clone, Copy)]
struct Partner {
    lpa: u16,
    stat1000: u16,
}

/// A partner that offers everything up to gigabit full duplex.
const GIGABIT: Partner = Partner { lpa: 0x01E1, stat1000: 0x0800 | 0x0400 };
/// A 100BASE-TX full duplex partner.
const HUNDRED: Partner = Partner { lpa: 0x0101, stat1000: 0 };

struct Sim {
    regs: RefCell<HashMap<usize, u32>>,
    log: RefCell<Vec<Ev>>,
    t: Cell<u64>,
    phy: RefCell<[u16; 32]>,
    partner: Cell<Option<Partner>>,
    link_ok: Cell<bool>,
    // knobs
    reset_stuck: Cell<bool>,
    mdio_stuck: Cell<bool>,
    phy_reset_stuck: Cell<bool>,
    tx_hold: Cell<bool>,
    // engines
    mdio_busy: Cell<u32>,
    bmcr_reset_left: Cell<u32>,
    tx_cur: Cell<usize>,
    rx_cur: Cell<usize>,
    rx_tail: Cell<usize>,
    wire: RefCell<Vec<Vec<u8>>>,
    tx_seen: RefCell<Vec<[u32; 4]>>,
}

impl Sim {
    fn new(partner: Option<Partner>) -> &'static Sim {
        let s = Sim {
            regs: RefCell::new(HashMap::new()),
            log: RefCell::new(Vec::new()),
            t: Cell::new(0),
            phy: RefCell::new([0; 32]),
            partner: Cell::new(partner),
            link_ok: Cell::new(false),
            reset_stuck: Cell::new(false),
            mdio_stuck: Cell::new(false),
            phy_reset_stuck: Cell::new(false),
            tx_hold: Cell::new(false),
            mdio_busy: Cell::new(0),
            bmcr_reset_left: Cell::new(0),
            tx_cur: Cell::new(0),
            rx_cur: Cell::new(0),
            rx_tail: Cell::new(0),
            wire: RefCell::new(Vec::new()),
            tx_seen: RefCell::new(Vec::new()),
        };
        s.regs.borrow_mut().insert(reg::MAC_VERSION, 0x0000_3052);
        {
            let mut p = s.phy.borrow_mut();
            p[phy::PHYSID1 as usize] = (phy::ID_YT8531 >> 16) as u16;
            p[phy::PHYSID2 as usize] = phy::ID_YT8531 as u16;
        }
        Box::leak(Box::new(s))
    }

    fn reg(&self, off: usize) -> u32 {
        self.regs.borrow().get(&off).copied().unwrap_or(0)
    }

    fn set(&self, off: usize, v: u32) {
        self.regs.borrow_mut().insert(off, v);
    }

    fn writes(&self, off: usize) -> Vec<u32> {
        self.log.borrow().iter().filter_map(|e| match e { Ev::Wr(o, v) if *o == off => Some(*v), _ => None }).collect()
    }

    /// Index in the log of the first write to `off` (panics if none).
    fn first_write(&self, off: usize) -> usize {
        self.log.borrow().iter().position(|e| matches!(e, Ev::Wr(o, _) if *o == off)).expect("register never written")
    }

    fn mdio(&self, v: u32) {
        let pa = ((v >> 21) & 0x1F) as u8;
        let ra = ((v >> 16) & 0x1F) as usize;
        let goc = (v >> 2) & 3;
        let data = self.reg(reg::MAC_MDIO_DATA) as u16;
        let mut p = self.phy.borrow_mut();
        if goc == 3 {
            let val = if pa != 0 {
                0xFFFF
            } else {
                match ra {
                    0 => {
                        let left = self.bmcr_reset_left.get();
                        if left > 0 && !self.phy_reset_stuck.get() {
                            self.bmcr_reset_left.set(left - 1);
                        }
                        let reset = if left > 0 || self.phy_reset_stuck.get() { phy::BMCR_RESET } else { 0 };
                        (p[0] & !phy::BMCR_RESET) | reset
                    }
                    1 if self.link_ok.get() => phy::BMSR_LSTATUS | phy::BMSR_ANEGCOMPLETE,
                    1 => 0,
                    5 => self.partner.get().map_or(0, |q| q.lpa),
                    10 => self.partner.get().map_or(0, |q| q.stat1000),
                    _ => p[ra],
                }
            };
            self.set(reg::MAC_MDIO_DATA, val as u32);
        } else if goc == 1 && pa == 0 {
            if ra == 0 {
                if data & phy::BMCR_RESET != 0 {
                    self.bmcr_reset_left.set(3);
                }
                if data & phy::BMCR_ANRESTART != 0 && self.partner.get().is_some() {
                    self.link_ok.set(true);
                }
            }
            p[ra] = data;
        }
        self.mdio_busy.set(2);
    }

    // The ring geometry as the driver programmed it, checked for consistency.
    fn ring(&self, hi: usize, lo: usize, len: usize) -> (u64, usize, usize) {
        let base = (self.reg(hi) as u64) << 32 | self.reg(lo) as u64;
        let dsl = (self.reg(reg::DMA_CH0_CONTROL) >> dma::CTRL_DSL_SHIFT) & 7;
        let stride = DESC_BYTES + 8 * dsl as usize;
        assert_eq!(stride, DESC_STRIDE, "DSL does not match the stride the driver lays descriptors at");
        assert_eq!(base % 64, 0, "descriptor ring not line-aligned");
        (base, stride, self.reg(len) as usize + 1)
    }

    fn tx_engine(&self) {
        let (base, stride, n) = self.ring(reg::DMA_CH0_TXDESC_HADDR, reg::DMA_CH0_TXDESC_LADDR, reg::DMA_CH0_TXDESC_LEN);
        assert_eq!(n, TX_N);
        let tail = self.reg(reg::DMA_CH0_TXDESC_TAIL).wrapping_sub(base as u32) as usize / stride;
        assert!(tail < n, "tail pointer outside the ring");
        while self.tx_cur.get() != tail && !self.tx_hold.get() {
            let d = (base + (self.tx_cur.get() * stride) as u64) as *mut u32;
            // SAFETY: the ring is the test's `DmaMem`, identity-mapped.
            let w = unsafe { [d.read(), d.add(1).read(), d.add(2).read(), d.add(3).read()] };
            if w[3] & desc::TDES3_OWN == 0 {
                break; // the device would stall on a descriptor it does not own
            }
            assert!(w[3] & desc::TDES3_FD != 0 && w[3] & desc::TDES3_LD != 0, "one buffer per frame");
            let len = (w[2] & desc::TDES2_B1_LEN_MASK) as usize;
            assert_eq!(len, (w[3] & desc::TDES3_LEN_MASK) as usize);
            let addr = ((w[1] as u64) << 32 | w[0] as u64) as *const u8;
            // SAFETY: the buffer address is a `tx_buf` slot of the test's `DmaMem`.
            self.wire.borrow_mut().push(unsafe { std::slice::from_raw_parts(addr, len) }.to_vec());
            self.tx_seen.borrow_mut().push(w);
            // SAFETY: as above; write-back clears OWN.
            unsafe { d.add(3).write(desc::TDES3_FD | desc::TDES3_LD) };
            self.tx_cur.set((self.tx_cur.get() + 1) % n);
        }
    }

    /// The wire delivers `frame`; `len_field` and `flags` are what the device
    /// writes back (a lying device, when they disagree with the frame).
    fn inject_raw(&self, frame: &[u8], len_field: u32, flags: u32) -> bool {
        let (base, stride, n) = self.ring(reg::DMA_CH0_RXDESC_HADDR, reg::DMA_CH0_RXDESC_LADDR, reg::DMA_CH0_RXDESC_LEN);
        assert_eq!(n, RX_N);
        if self.rx_cur.get() == self.rx_tail.get() {
            self.set(reg::DMA_CH0_STATUS, self.reg(reg::DMA_CH0_STATUS) | dma::INT_RBU | dma::INT_AIS);
            return false;
        }
        let d = (base + (self.rx_cur.get() * stride) as u64) as *mut u32;
        // SAFETY: the ring is the test's `DmaMem`, identity-mapped.
        let w = unsafe { [d.read(), d.add(1).read(), d.add(2).read(), d.add(3).read()] };
        assert!(w[3] & desc::RDES3_OWN != 0, "the device was given a descriptor it does not own");
        assert!(w[3] & desc::RDES3_BUF1V != 0);
        let addr = ((w[1] as u64) << 32 | w[0] as u64) as *mut u8;
        let n_copy = frame.len().min(BUF_SIZE);
        // SAFETY: the address is an `rx_buf` slot of the test's `DmaMem`.
        unsafe {
            std::ptr::copy_nonoverlapping(frame.as_ptr(), addr, n_copy);
            d.add(3).write(flags | (len_field & desc::RDES3_LEN_MASK));
        }
        self.rx_cur.set((self.rx_cur.get() + 1) % n);
        self.set(reg::DMA_CH0_STATUS, self.reg(reg::DMA_CH0_STATUS) | dma::INT_RI | dma::INT_NIS);
        true
    }

    fn inject(&self, frame: &[u8]) -> bool {
        self.inject_raw(frame, frame.len() as u32, desc::RDES3_FD | desc::RDES3_LD)
    }
}

impl Hw for &'static Sim {
    fn rd(&self, off: usize) -> u32 {
        if off == reg::MAC_MDIO_ADDRESS {
            if self.mdio_stuck.get() {
                return mac::MDIO_GB;
            }
            let b = self.mdio_busy.get();
            if b > 0 {
                self.mdio_busy.set(b - 1);
                return self.reg(off) | mac::MDIO_GB;
            }
            return self.reg(off) & !mac::MDIO_GB;
        }
        if off == reg::DMA_MODE && self.reset_stuck.get() {
            return self.reg(off) | dma::MODE_SWR;
        }
        self.reg(off)
    }

    fn wr(&self, off: usize, val: u32) {
        self.log.borrow_mut().push(Ev::Wr(off, val));
        match off {
            reg::DMA_MODE if val & dma::MODE_SWR != 0 => {
                // A reset clears the station address and the rings.
                self.set(reg::MAC_ADDRESS0_HIGH, 0);
                self.set(reg::MAC_ADDRESS0_LOW, 0);
                self.set(off, if self.reset_stuck.get() { val } else { 0 });
            }
            reg::MAC_MDIO_ADDRESS => {
                self.set(off, val);
                if val & mac::MDIO_GB != 0 {
                    self.mdio(val);
                }
            }
            reg::DMA_CH0_STATUS => self.set(off, self.reg(off) & !val),
            reg::DMA_CH0_TXDESC_TAIL => {
                self.set(off, val);
                if self.reg(reg::DMA_CH0_TX_CONTROL) & dma::TX_CTRL_ST != 0
                    && self.reg(reg::MAC_CONFIGURATION) & mac::CFG_TE != 0
                {
                    self.tx_engine();
                }
            }
            reg::DMA_CH0_RXDESC_TAIL => {
                self.set(off, val);
                let (base, stride, _) =
                    self.ring(reg::DMA_CH0_RXDESC_HADDR, reg::DMA_CH0_RXDESC_LADDR, reg::DMA_CH0_RXDESC_LEN);
                self.rx_tail.set(val.wrapping_sub(base as u32) as usize / stride);
            }
            _ => self.set(off, val),
        }
    }

    fn now_us(&self) -> u64 {
        self.t.set(self.t.get() + 10);
        self.t.get()
    }
}

impl DmaOps for &'static Sim {
    fn map(&self, ptr: *const u8, _len: usize, _dir: Direction) -> Result<u64, ()> {
        Ok(ptr as u64)
    }
    fn enable(&self) -> Result<(), ()> {
        Ok(())
    }
    unsafe fn sync_for_device(&self, ptr: *const u8, len: usize, dir: Direction) {
        self.log.borrow_mut().push(Ev::SyncDev(ptr as u64, len, dir));
    }
    unsafe fn sync_for_cpu(&self, ptr: *const u8, len: usize, dir: Direction) {
        self.log.borrow_mut().push(Ev::SyncCpu(ptr as u64, len, dir));
    }
}

fn cfg() -> Config {
    Config { link_wait_us: 2_000, ..Config::JH7110_GMAC0 }
}

fn mem() -> *mut DmaMem {
    Box::leak(Box::new(DmaMem::new()))
}

type Nic = Dwmac<&'static Sim, &'static Sim>;

fn bring_up(partner: Option<Partner>) -> (Nic, &'static Sim) {
    let s = Sim::new(partner);
    // The firmware left a station address behind.
    s.set(reg::MAC_ADDRESS0_HIGH, 0x8000_0000 | 0x5544);
    s.set(reg::MAC_ADDRESS0_LOW, 0x2211_00AA);
    (Nic::init(s, s, cfg(), mem()).expect("bring-up"), s)
}

fn frame(tag: u8, len: usize) -> Vec<u8> {
    let mut f = vec![tag; len];
    f[0..6].copy_from_slice(&[0xFF; 6]);
    f[12..14].copy_from_slice(&0x88B5u16.to_be_bytes());
    f
}

// ── Pure pieces ─────────────────────────────────────────────────────────

mod pure {
    use super::*;

    /// **Discriminates.** One descriptor per cache line and a skip the 3-bit
    /// field can express: 64 bytes on a 64-bit bus is 6 words. A 32-bit bus
    /// would need 12 (refused, not truncated), and a stride that is not a
    /// whole number of bus words is refused too. The real `Desc` must be
    /// exactly the stride the arithmetic assumes.
    #[test]
    fn the_descriptor_skip_matches_the_descriptor_layout() {
        assert_eq!(dsl_words(64, 8), Some(6));
        assert_eq!(dsl_words(16, 8), Some(0));
        assert_eq!(dsl_words(64, 16), Some(3));
        assert_eq!(dsl_words(64, 4), None, "12 words do not fit three bits");
        assert_eq!(dsl_words(60, 8), None);
        assert_eq!(dsl_words(64, 0), None);
        assert_eq!(dsl_words(8, 8), None, "smaller than a descriptor");
        assert_eq!(std::mem::size_of::<Desc>(), DESC_STRIDE);
        assert_eq!(std::mem::align_of::<Desc>(), DESC_STRIDE);
        assert_eq!(std::mem::align_of::<Buf>(), 64);
        assert_eq!(BUF_SIZE % 64, 0, "a buffer is a whole number of cache lines");
        assert!(BUF_SIZE >= 1522, "a tagged frame fits one buffer");
        assert_eq!(Config::JH7110_GMAC0.axi_bus_bytes, 8);
    }

    /// **Discriminates.** The TX word layout: the 64-bit bus address split low
    /// and high, the length in both the buffer and the frame fields, OWN with
    /// FD and LD (one buffer per frame).
    #[test]
    fn tx_descriptor_words() {
        let w = tx_words(0x1_2345_6780, 60, false);
        assert_eq!(w[0], 0x2345_6780);
        assert_eq!(w[1], 1);
        assert_eq!(w[2], 60);
        assert_eq!(w[3], desc::TDES3_OWN | desc::TDES3_FD | desc::TDES3_LD | 60);
        assert_eq!(tx_words(0, 1514, true)[2], 1514 | desc::TDES2_IOC);
        // The length cannot spill into the flag bits.
        assert_eq!(tx_words(0, 0x1_FFFF, false)[3] & !(desc::TDES3_OWN | desc::TDES3_FD | desc::TDES3_LD), 0x7FFF);
    }

    #[test]
    fn rx_descriptor_words() {
        let w = rx_words(0x2_0000_0040);
        assert_eq!((w[0], w[1], w[2]), (0x40, 2, 0));
        assert_eq!(w[3], desc::RDES3_OWN | desc::RDES3_IOC | desc::RDES3_BUF1V);
    }

    /// **Discriminates.** The write-back decode: ownership first (a descriptor
    /// the device still owns is never read for a length), context descriptors
    /// apart, and the 15-bit length passed through untouched for the caller
    /// to clamp.
    #[test]
    fn rx_status_decode() {
        assert_eq!(rx_status(desc::RDES3_OWN | 0x7FFF), RxStatus::Device);
        assert_eq!(rx_status(desc::RDES3_CTXT), RxStatus::Context);
        assert_eq!(
            rx_status(desc::RDES3_FD | desc::RDES3_LD | 98),
            RxStatus::Frame { len: 98, first: true, last: true, error: false }
        );
        assert_eq!(
            rx_status(desc::RDES3_ES | desc::RDES3_LD | 0x7FFF),
            RxStatus::Frame { len: 0x7FFF, first: false, last: true, error: true }
        );
    }

    /// **Discriminates.** Priority resolution: the best common mode wins, a
    /// gigabit mode needs both ends, and a partner with nothing in common
    /// resolves to no link.
    #[test]
    fn link_resolution_priority() {
        let all = 0x01E1;
        assert_eq!(resolve_link(all, 0x01E1, 0x0200, 0x0800), Some((Speed::M1000, true)));
        assert_eq!(resolve_link(all, 0x01E1, 0x0200, 0x0400), Some((Speed::M100, true)), "we advertise 1000 full only");
        assert_eq!(resolve_link(all, 0x0101, 0x0200, 0), Some((Speed::M100, true)));
        assert_eq!(resolve_link(all, 0x0081, 0x0200, 0), Some((Speed::M100, false)));
        assert_eq!(resolve_link(all, 0x0041, 0x0200, 0), Some((Speed::M10, true)));
        assert_eq!(resolve_link(all, 0x0021, 0x0200, 0), Some((Speed::M10, false)));
        assert_eq!(resolve_link(all, 0x0001, 0x0200, 0), None);
        // We did not advertise gigabit: a gigabit partner gives 100.
        assert_eq!(resolve_link(all, 0x01E1, 0, 0x0800), Some((Speed::M100, true)));
        // Half duplex gigabit when both offer it.
        assert_eq!(resolve_link(all, 0x01E1, 0x0100, 0x0400), Some((Speed::M1000, false)));
    }

    #[test]
    fn mac_speed_bits() {
        assert_eq!(config_bits(Speed::M1000, true), mac::CFG_DM);
        assert_eq!(config_bits(Speed::M100, true), mac::CFG_PS | mac::CFG_FES | mac::CFG_DM);
        assert_eq!(config_bits(Speed::M10, false), mac::CFG_PS);
    }
}

// ── Bring-up ────────────────────────────────────────────────────────────

mod bring_up_sequence {
    use super::*;

    /// **Discriminates.** A window that is not a dwmac4/5 core (the Cadence
    /// MACB `eth.rs` was written against reads something else here) is
    /// refused before a single register is written.
    #[test]
    fn a_foreign_core_is_refused_untouched() {
        let s = Sim::new(Some(GIGABIT));
        s.set(reg::MAC_VERSION, 0x0000_0716);
        assert_eq!(Nic::init(s, s, cfg(), mem()).err(), Some(Error::UnsupportedCore(0x716)));
        assert!(s.log.borrow().is_empty(), "wrote to a window that is not this IP");
    }

    #[test]
    fn a_reset_that_never_finishes_is_an_error() {
        let s = Sim::new(Some(GIGABIT));
        s.reset_stuck.set(true);
        assert_eq!(Nic::init(s, s, cfg(), mem()).err(), Some(Error::ResetTimeout));
    }

    /// **Discriminates.** The programmed values: ring bases and lengths are the
    /// addresses of the memory handed in, `DSL` is the stride, the buffer size
    /// is the real one, the FIFOs follow the DTS depths, and the channel is
    /// started only AFTER its rings are set (starting a channel on a ring base
    /// of zero makes the device fetch descriptors from address 0).
    #[test]
    fn the_channel_is_programmed_before_it_is_started() {
        let (_nic, s) = bring_up(Some(GIGABIT));
        assert_eq!(s.reg(reg::DMA_CH0_CONTROL) >> dma::CTRL_DSL_SHIFT & 7, 6);
        assert_eq!(s.reg(reg::DMA_CH0_TXDESC_LEN), TX_N as u32 - 1);
        assert_eq!(s.reg(reg::DMA_CH0_RXDESC_LEN), RX_N as u32 - 1);
        assert_eq!(s.reg(reg::DMA_CH0_RX_CONTROL) & dma::RX_CTRL_RBSZ_MASK, (BUF_SIZE as u32) << 1);
        assert_eq!(s.reg(reg::DMA_CH0_RX_CONTROL) >> 16 & 0x3F, 16, "rxpbl");
        assert_eq!(s.reg(reg::DMA_CH0_TX_CONTROL) >> 16 & 0x3F, 16, "txpbl");
        assert_eq!(s.reg(reg::MTL_TXQ0_OPERATION_MODE) >> dma::MTL_TQS_SHIFT & 0x1FF, 7, "2048-byte FIFO");
        assert_eq!(s.reg(reg::MTL_RXQ0_OPERATION_MODE) >> dma::MTL_RQS_SHIFT & 0x3FF, 7);
        let sysbus = s.reg(reg::DMA_SYSBUS_MODE);
        assert_eq!(sysbus & dma::SYSBUS_FB, dma::SYSBUS_FB, "snps,fixed-burst");
        assert_eq!(sysbus >> dma::SYSBUS_RD_OSR_SHIFT & 0xF, 15);
        assert_eq!(sysbus >> dma::SYSBUS_WR_OSR_SHIFT & 0xF, 15);
        assert_ne!(s.reg(reg::DMA_CH0_TXDESC_LADDR), 0);
        assert_ne!(s.reg(reg::DMA_CH0_RXDESC_LADDR), 0);
        assert_eq!(s.reg(reg::DMA_CH0_TX_CONTROL) & dma::TX_CTRL_ST, dma::TX_CTRL_ST);
        assert_eq!(s.reg(reg::DMA_CH0_RX_CONTROL) & dma::RX_CTRL_SR, dma::RX_CTRL_SR);
        assert_eq!(s.reg(reg::DMA_CH0_INTR_ENA), dma::INT_ENABLED);

        let started = s
            .log
            .borrow()
            .iter()
            .position(|e| matches!(e, Ev::Wr(o, v) if (*o == reg::DMA_CH0_RX_CONTROL || *o == reg::DMA_CH0_TX_CONTROL) && v & 1 == 1))
            .unwrap();
        for off in [reg::DMA_CH0_TXDESC_LADDR, reg::DMA_CH0_RXDESC_LADDR, reg::DMA_CH0_RXDESC_TAIL, reg::DMA_CH0_RXDESC_LEN] {
            assert!(s.first_write(off) < started, "{off:#x} programmed after the channel started");
        }
        assert!(s.first_write(reg::DMA_MODE) < s.first_write(reg::DMA_CH0_TXDESC_LADDR), "reset first");
    }

    /// **Discriminates.** The RX ring is posted before the channel runs, all
    /// but one descriptor, with the tail at the first unposted one. A tail at
    /// the ring end (all posted) would make the device think the ring empty.
    #[test]
    fn the_receive_ring_starts_one_short() {
        let (_nic, s) = bring_up(Some(GIGABIT));
        let base = (s.reg(reg::DMA_CH0_RXDESC_HADDR) as u64) << 32 | s.reg(reg::DMA_CH0_RXDESC_LADDR) as u64;
        assert_eq!(s.reg(reg::DMA_CH0_RXDESC_TAIL), (base as u32).wrapping_add(((RX_N - 1) * DESC_STRIDE) as u32));
        // Every posted descriptor was handed over line by line.
        let descs = s.log.borrow().iter().filter(|e| matches!(e, Ev::SyncDev(a, DESC_STRIDE, Direction::Bidirectional) if *a >= base && *a < base + (RX_N * DESC_STRIDE) as u64)).count();
        assert_eq!(descs, RX_N - 1);
    }

    /// **Discriminates.** The station address the firmware left is kept across
    /// the reset (which clears it); with none, the configured one is used.
    #[test]
    fn the_station_address_survives_the_reset() {
        let (nic, s) = bring_up(Some(GIGABIT));
        assert_eq!(nic.mac(), [0xAA, 0x00, 0x11, 0x22, 0x44, 0x55]);
        assert_eq!(s.reg(reg::MAC_ADDRESS0_LOW), 0x2211_00AA);
        assert_eq!(s.reg(reg::MAC_ADDRESS0_HIGH), 0x8000_5544);

        let s = Sim::new(Some(GIGABIT));
        let nic = Nic::init(s, s, cfg(), mem()).unwrap();
        assert_eq!(nic.mac(), Config::JH7110_GMAC0.fallback_mac);
        // A multicast address in the registers is no station address either.
        let s = Sim::new(Some(GIGABIT));
        s.set(reg::MAC_ADDRESS0_LOW, 0x0000_0001);
        let nic = Nic::init(s, s, cfg(), mem()).unwrap();
        assert_eq!(nic.mac(), Config::JH7110_GMAC0.fallback_mac);
    }

    /// **Discriminates.** Transmit and receive stay off until the PHY reports a
    /// link, and then run at the negotiated speed: gigabit leaves `PS`/`FES`
    /// clear, 100 Mbit sets both. Without a partner they never come on.
    #[test]
    fn the_mac_follows_the_link() {
        let (nic, s) = bring_up(Some(GIGABIT));
        assert_eq!(nic.link(), Link { up: true, speed: Speed::M1000, full_duplex: true });
        let c = s.reg(reg::MAC_CONFIGURATION);
        assert_eq!(c & (mac::CFG_TE | mac::CFG_RE), mac::CFG_TE | mac::CFG_RE);
        assert_eq!(c & (mac::CFG_PS | mac::CFG_FES), 0);
        assert_eq!(c & mac::CFG_DM, mac::CFG_DM);

        let (nic, s) = bring_up(Some(HUNDRED));
        assert_eq!(nic.link(), Link { up: true, speed: Speed::M100, full_duplex: true });
        assert_eq!(s.reg(reg::MAC_CONFIGURATION) & (mac::CFG_PS | mac::CFG_FES), mac::CFG_PS | mac::CFG_FES);

        let (nic, s) = bring_up(None);
        assert!(!nic.link().up);
        assert_eq!(s.reg(reg::MAC_CONFIGURATION) & (mac::CFG_TE | mac::CFG_RE), 0);
    }

    /// **Discriminates.** Auto-negotiation advertises 10/100 and gigabit full
    /// duplex, after the PHY was reset and the reset bit cleared.
    #[test]
    fn the_phy_is_reset_then_negotiates() {
        let (_nic, s) = bring_up(Some(GIGABIT));
        let p = s.phy.borrow();
        assert_eq!(p[phy::ADVERTISE as usize], 0x01E1);
        assert_eq!(p[phy::CTRL1000 as usize], 0x0200);
        assert_eq!(p[phy::BMCR as usize], phy::BMCR_ANENABLE | phy::BMCR_ANRESTART);
    }
}

// ── MDIO and the PHY ────────────────────────────────────────────────────

mod mdio_and_phy {
    use super::*;

    /// **Discriminates.** The station-management frame: PHY address in 25:21,
    /// register in 20:16, the clock divider in 11:8, read opcode 11 in 3:2,
    /// busy in bit 0. Swap two fields and the PHY answers the wrong register.
    #[test]
    fn the_mdio_frame_is_encoded_as_the_databook_has_it() {
        let (nic, s) = bring_up(Some(GIGABIT));
        s.log.borrow_mut().clear();
        let _ = nic.mdio_read(phy::PHYSID2).unwrap();
        let w = s.writes(reg::MAC_MDIO_ADDRESS);
        assert_eq!(w, vec![(0 << 21) | (3 << 16) | (7 << 8) | (3 << 2) | 1]);

        s.log.borrow_mut().clear();
        nic.mdio_write(phy::CTRL1000, 0x0200).unwrap();
        assert_eq!(s.writes(reg::MAC_MDIO_DATA), vec![0x0200], "data goes in before the command");
        assert_eq!(s.writes(reg::MAC_MDIO_ADDRESS), vec![(9 << 16) | (7 << 8) | (1 << 2) | 1]);
        assert!(s.first_write(reg::MAC_MDIO_DATA) < s.first_write(reg::MAC_MDIO_ADDRESS));
    }

    #[test]
    fn a_stuck_mdio_bus_is_a_timeout_not_a_hang() {
        let s = Sim::new(Some(GIGABIT));
        s.mdio_stuck.set(true);
        assert_eq!(Nic::init(s, s, cfg(), mem()).err(), Some(Error::MdioTimeout));
    }

    /// **Discriminates.** Nothing at the PHY address reads all ones; a PHY
    /// that is not the YT8531 is reported with its ID, not driven blind.
    #[test]
    fn the_phy_is_identified_before_it_is_touched() {
        let s = Sim::new(Some(GIGABIT));
        s.phy.borrow_mut()[phy::PHYSID1 as usize] = 0xFFFF;
        assert_eq!(Nic::init(s, s, cfg(), mem()).err(), Some(Error::NoPhy));

        let s = Sim::new(Some(GIGABIT));
        {
            let mut p = s.phy.borrow_mut();
            p[phy::PHYSID1 as usize] = 0x0022;
            p[phy::PHYSID2 as usize] = 0x1622;
        }
        assert_eq!(Nic::init(s, s, cfg(), mem()).err(), Some(Error::UnknownPhy(0x0022_1622)));
        assert!(s.phy.borrow()[phy::BMCR as usize] == 0, "an unknown PHY was written to");
    }

    #[test]
    fn a_phy_that_never_leaves_reset_is_an_error() {
        let s = Sim::new(Some(GIGABIT));
        s.phy_reset_stuck.set(true);
        assert_eq!(Nic::init(s, s, cfg(), mem()).err(), Some(Error::PhyResetTimeout));
    }

    /// **Discriminates.** A cable pulled turns transmit and receive off and
    /// refuses sends; plugged back, the MAC is re-enabled. The rate limit is
    /// on the clock: a poll inside the interval does not touch the PHY.
    #[test]
    fn link_loss_and_return() {
        let (mut nic, s) = bring_up(Some(GIGABIT));
        assert!(nic.link_poll().is_none(), "polled again straight away");
        s.link_ok.set(false);
        s.t.set(s.t.get() + 600_000);
        assert_eq!(nic.link_poll(), Some(Link::DOWN));
        assert_eq!(s.reg(reg::MAC_CONFIGURATION) & (mac::CFG_TE | mac::CFG_RE), 0);
        assert_eq!(nic.send(&frame(1, 60)), Err(NetError::NotReady));

        s.link_ok.set(true);
        s.t.set(s.t.get() + 600_000);
        assert_eq!(nic.link_poll().map(|l| l.up), Some(true));
        assert_eq!(s.reg(reg::MAC_CONFIGURATION) & (mac::CFG_TE | mac::CFG_RE), mac::CFG_TE | mac::CFG_RE);
        assert!(nic.send(&frame(2, 60)).is_ok());
    }
}

// ── Transmit ────────────────────────────────────────────────────────────

mod transmit {
    use super::*;

    /// **Discriminates.** The hand-over order a non-coherent master needs: the
    /// frame bytes cleaned, then the descriptor cleaned, then the doorbell. A
    /// tail write before the descriptor line is cleaned lets the device read a
    /// stale descriptor from RAM.
    #[test]
    fn a_frame_is_published_buffer_then_descriptor_then_doorbell() {
        let (mut nic, s) = bring_up(Some(GIGABIT));
        s.log.borrow_mut().clear();
        let f = frame(7, 100);
        assert_eq!(nic.send(&f), Ok(100));
        assert_eq!(s.wire.borrow().as_slice(), &[f]);

        let log = s.log.borrow();
        let buf = log.iter().position(|e| matches!(e, Ev::SyncDev(_, 100, Direction::ToDevice))).expect("buffer not cleaned");
        let desc = log.iter().position(|e| matches!(e, Ev::SyncDev(_, DESC_STRIDE, Direction::Bidirectional))).expect("descriptor not cleaned");
        let bell = log.iter().position(|e| matches!(e, Ev::Wr(o, _) if *o == reg::DMA_CH0_TXDESC_TAIL)).expect("no doorbell");
        assert!(buf < desc && desc < bell, "order was buf {buf}, desc {desc}, doorbell {bell}");
        // The doorbell is one past the descriptor just filled.
        let base = (s.reg(reg::DMA_CH0_TXDESC_HADDR) as u64) << 32 | s.reg(reg::DMA_CH0_TXDESC_LADDR) as u64;
        assert_eq!(s.reg(reg::DMA_CH0_TXDESC_TAIL), (base as u32).wrapping_add(DESC_STRIDE as u32));
        let seen = s.tx_seen.borrow()[0];
        assert_eq!(seen[3], desc::TDES3_OWN | desc::TDES3_FD | desc::TDES3_LD | 100);
    }

    #[test]
    fn bad_lengths_are_refused() {
        let (mut nic, s) = bring_up(Some(GIGABIT));
        assert_eq!(nic.send(&[]), Err(NetError::BadLength));
        assert_eq!(nic.send(&vec![0; 1515]), Err(NetError::BadLength));
        assert!(s.wire.borrow().is_empty());
        assert_eq!(nic.send(&vec![0; 1514]), Ok(1514));
    }

    /// **Discriminates.** With the device not consuming, exactly `TX_N - 1`
    /// frames fit (a full ring would put the producer index on the device's
    /// consumer index, which it reads as "nothing to do") and the next is
    /// `QueueFull`, a transient, not a failure; once the device catches up the
    /// slots are reclaimed and sending resumes, in order, through more than one
    /// lap of the ring.
    #[test]
    fn the_transmit_ring_fills_drains_and_wraps() {
        let (mut nic, s) = bring_up(Some(GIGABIT));
        s.tx_hold.set(true);
        for i in 0..TX_N - 1 {
            assert!(nic.send(&frame(i as u8, 64)).is_ok(), "frame {i}");
        }
        assert_eq!(nic.send(&frame(99, 64)), Err(NetError::QueueFull));
        assert!(s.wire.borrow().is_empty());

        s.tx_hold.set(false);
        s.wr_tail_kick();
        for lap in 0..3 {
            for i in 0..TX_N {
                let tag = (lap * TX_N + i) as u8 + 100;
                assert!(nic.send(&frame(tag, 64)).is_ok(), "lap {lap} frame {i}");
            }
        }
        let wire = s.wire.borrow();
        assert_eq!(wire.len(), TX_N - 1 + 3 * TX_N);
        for (n, f) in wire.iter().enumerate() {
            let want = if n < TX_N - 1 { n as u8 } else { (n - (TX_N - 1)) as u8 + 100 };
            assert_eq!(f[20], want, "frame {n} out of order or corrupted");
        }
    }

    /// **Discriminates.** A batch rings the doorbell once at the end, not once
    /// per frame, and still delivers every frame.
    #[test]
    fn a_batch_has_one_doorbell() {
        let (mut nic, s) = bring_up(Some(GIGABIT));
        s.log.borrow_mut().clear();
        nic.tx_batch_begin();
        for i in 0..5 {
            nic.send(&frame(i, 64)).unwrap();
        }
        assert!(s.writes(reg::DMA_CH0_TXDESC_TAIL).is_empty(), "doorbell inside the batch");
        assert!(s.wire.borrow().is_empty());
        nic.tx_batch_end();
        assert_eq!(s.writes(reg::DMA_CH0_TXDESC_TAIL).len(), 1);
        assert_eq!(s.wire.borrow().len(), 5);
        // An empty batch rings nothing.
        nic.tx_batch_begin();
        nic.tx_batch_end();
        assert_eq!(s.writes(reg::DMA_CH0_TXDESC_TAIL).len(), 1);
    }

    /// The device flags a failed transmit; the driver counts it and carries on.
    #[test]
    fn a_failed_transmit_is_counted_and_the_slot_reused() {
        let (mut nic, s) = bring_up(Some(GIGABIT));
        s.tx_hold.set(true);
        nic.send(&frame(1, 64)).unwrap();
        let base = (s.reg(reg::DMA_CH0_TXDESC_HADDR) as u64) << 32 | s.reg(reg::DMA_CH0_TXDESC_LADDR) as u64;
        // SAFETY: the test's ring; the device writes back with an error.
        unsafe { ((base as *mut u32).add(3)).write(desc::TDES3_ES | desc::TDES3_LD) };
        for _ in 0..TX_N {
            let _ = nic.send(&frame(2, 64));
        }
        assert_eq!(nic.stats().tx_errors, 1);
    }
}

impl Sim {
    /// Re-announce the TX tail so the engine runs again (a held device
    /// released).
    fn wr_tail_kick(&'static self) {
        let v = self.reg(reg::DMA_CH0_TXDESC_TAIL);
        self.wr(reg::DMA_CH0_TXDESC_TAIL, v);
    }
}

// ── Receive ─────────────────────────────────────────────────────────────

mod receive {
    use super::*;

    fn drain(nic: &mut Nic, got: &mut Vec<Vec<u8>>) -> usize {
        let mut out = [(0u16, 0u16); RX_BATCH];
        let first = nic.rx_first();
        let (frames, used) = nic.rx_harvest(&mut out);
        for &(d, l) in &out[..frames] {
            got.push(nic.rx_frame(d, l).to_vec());
        }
        nic.rx_release(first, used);
        frames
    }

    /// **Discriminates.** Frames come out in arrival order and intact through
    /// more than three laps of the 32-descriptor ring, with the device
    /// refilled in between. This is the test that catches a buffer returned to
    /// the descriptor it came out of instead of the next one in ring order
    /// (the device would stall at the first unposted descriptor).
    #[test]
    fn many_laps_in_order_without_loss() {
        let (mut nic, s) = bring_up(Some(GIGABIT));
        let mut got = Vec::new();
        let mut sent = Vec::new();
        for n in 0..(RX_N * 3 + 5) {
            let f = frame(n as u8, 60 + n % 40);
            assert!(s.inject(&f), "the device found no free descriptor at frame {n}");
            sent.push(f);
            if n % 5 == 4 {
                drain(&mut nic, &mut got);
            }
        }
        while drain(&mut nic, &mut got) > 0 {}
        assert_eq!(got, sent);
        assert_eq!(nic.stats().rx_frames as usize, sent.len());
    }

    /// **Discriminates.** A full burst fills every posted descriptor and no
    /// more: the next frame finds the ring dry (`RBU`), and after a drain the
    /// device continues. Tail pointer = the first unposted descriptor each time.
    #[test]
    fn a_dry_ring_resumes_after_release() {
        let (mut nic, s) = bring_up(Some(GIGABIT));
        let mut n = 0;
        while s.inject(&frame(n as u8, 64)) {
            n += 1;
        }
        assert_eq!(n, RX_BUFS, "one descriptor stays unposted");
        assert_ne!(s.reg(reg::DMA_CH0_STATUS) & dma::INT_RBU, 0);
        let mut got = Vec::new();
        while drain(&mut nic, &mut got) > 0 {}
        assert_eq!(got.len(), RX_BUFS);
        assert!(s.inject(&frame(200, 64)), "the device did not resume after the release");
        let base = (s.reg(reg::DMA_CH0_RXDESC_HADDR) as u64) << 32 | s.reg(reg::DMA_CH0_RXDESC_LADDR) as u64;
        let tail = s.reg(reg::DMA_CH0_RXDESC_TAIL).wrapping_sub(base as u32) as usize / DESC_STRIDE;
        assert!(tail < RX_N);
    }

    /// **Discriminates.** The descriptor is taken back from the device before
    /// its status word is read, the buffer before its bytes are, and on the
    /// way out buffer, then descriptor, then the tail doorbell.
    #[test]
    fn the_cache_discipline_around_a_received_frame() {
        let (mut nic, s) = bring_up(Some(GIGABIT));
        s.inject(&frame(5, 90));
        s.log.borrow_mut().clear();
        let mut got = Vec::new();
        drain(&mut nic, &mut got);
        let log = s.log.borrow();
        let d_cpu = log.iter().position(|e| matches!(e, Ev::SyncCpu(_, DESC_STRIDE, Direction::Bidirectional))).expect("descriptor read without sync_for_cpu");
        let b_cpu = log.iter().position(|e| matches!(e, Ev::SyncCpu(_, 90, Direction::FromDevice))).expect("frame read without sync_for_cpu");
        assert!(d_cpu < b_cpu);
        let b_dev = log.iter().position(|e| matches!(e, Ev::SyncDev(_, BUF_SIZE, Direction::FromDevice))).expect("buffer not given back");
        let d_dev = log.iter().position(|e| matches!(e, Ev::SyncDev(_, DESC_STRIDE, Direction::Bidirectional))).expect("descriptor not given back");
        let bell = log.iter().position(|e| matches!(e, Ev::Wr(o, _) if *o == reg::DMA_CH0_RXDESC_TAIL)).expect("no doorbell");
        assert!(b_cpu < b_dev && b_dev < d_dev && d_dev < bell);
    }

    /// **Discriminates.** The device's word is untrusted. A frame the device
    /// flags, a runt, one that spans buffers (and the pieces after it), and a
    /// length field claiming 32 KiB are each handled without delivering bytes
    /// the buffer does not hold; the good frame behind them arrives.
    #[test]
    fn a_lying_or_damaged_descriptor_cannot_make_the_driver_overread() {
        let (mut nic, s) = bring_up(Some(GIGABIT));
        s.inject_raw(&frame(1, 100), 100, desc::RDES3_FD | desc::RDES3_LD | desc::RDES3_ES); // flagged
        s.inject_raw(&[2; 8], 8, desc::RDES3_FD | desc::RDES3_LD); // runt
        s.inject_raw(&frame(3, 1536), 1536, desc::RDES3_FD); // spills over: first piece
        s.inject_raw(&frame(4, 100), 100, desc::RDES3_LD); // the rest of it
        s.inject_raw(&frame(5, 100), 0x7FFF, desc::RDES3_FD | desc::RDES3_LD); // length lies
        s.inject(&frame(6, 70));
        let mut got = Vec::new();
        while drain(&mut nic, &mut got) > 0 {}
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].len(), BUF_SIZE, "a 32 KiB claim is clamped to the buffer");
        assert_eq!(got[1], frame(6, 70));
        let st = nic.stats();
        assert_eq!((st.rx_errors, st.rx_dropped), (1, 3), "runt, first piece, rest of it");
    }

    /// A context descriptor in the ring is skipped, not delivered.
    #[test]
    fn a_context_descriptor_is_not_a_frame() {
        let (mut nic, s) = bring_up(Some(GIGABIT));
        s.inject_raw(&[0; 64], 0, desc::RDES3_CTXT);
        s.inject(&frame(9, 64));
        let mut got = Vec::new();
        while drain(&mut nic, &mut got) > 0 {}
        assert_eq!(got, vec![frame(9, 64)]);
    }

    #[test]
    fn an_idle_ring_looks_idle() {
        let (nic, s) = bring_up(Some(GIGABIT));
        assert!(!nic.rx_ready());
        s.inject(&frame(1, 64));
        assert!(nic.rx_ready());
    }
}

// ── Interrupts ──────────────────────────────────────────────────────────

mod interrupts {
    use super::*;

    /// **Discriminates.** The handler acknowledges what it handled and only
    /// that, tells the receive path to look (a frame, or the ring dry), and
    /// reports a bus fault. Writing back bits it did not enable would clear
    /// status the poll path still wants.
    #[test]
    fn the_interrupt_is_acknowledged_and_classified() {
        let (_nic, s) = bring_up(Some(GIGABIT));
        s.log.borrow_mut().clear();
        assert_eq!(irq_ack(&s), IrqCause { rx: false, fatal: false });
        assert!(s.writes(reg::DMA_CH0_STATUS).is_empty(), "acknowledged nothing");

        s.set(reg::DMA_CH0_STATUS, dma::INT_RI | dma::INT_NIS | (1 << 9));
        assert_eq!(irq_ack(&s), IrqCause { rx: true, fatal: false });
        assert_eq!(s.writes(reg::DMA_CH0_STATUS), vec![dma::INT_RI | dma::INT_NIS], "bit 9 is not ours");
        assert_eq!(s.reg(reg::DMA_CH0_STATUS), 1 << 9);

        s.set(reg::DMA_CH0_STATUS, dma::INT_RBU | dma::INT_AIS);
        assert_eq!(irq_ack(&s).rx, true);
        s.set(reg::DMA_CH0_STATUS, dma::INT_FBE | dma::INT_AIS);
        assert_eq!(irq_ack(&s), IrqCause { rx: false, fatal: true });
        assert_eq!(s.reg(reg::DMA_CH0_STATUS), 0);
    }
}
