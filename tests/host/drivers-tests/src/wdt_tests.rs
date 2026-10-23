// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The SBSA Generic Watchdog (`crates/drivers/sys/src/wdt_sbsa.rs`) and the
//! AMD FCH watchdog (`wdt_sp5100.rs`) against a model of each counter: a
//! feed keeps the machine up, and a feed that stops lets the reset come
//! within the armed timeout. QEMU's `virt` has no SBSA watchdog and no
//! machine of it has an FCH, so this is where both are run.

use std::cell::{Cell, RefCell};

use crate::wdt_sbsa as g;
use crate::wdt_sp5100 as t;

// ── SBSA ────────────────────────────────────────────────────────────────────

/// The SBSA Generic Watchdog's two-stage counter (SBSA "Generic Watchdog"):
/// an expiry raises WS0 and reloads `WCV` with `WOR` more ticks, a second one
/// raises WS1 (the reset); a refresh (`WRR`, or a `WOR` write) drops WS0 and
/// starts over.
struct Gwdt {
    version: u32,
    now: Cell<u64>,
    en: Cell<bool>,
    wor: Cell<u64>,
    wcv: Cell<u64>,
    ws0: Cell<bool>,
    reset_at: Cell<Option<u64>>,
    writes: RefCell<Vec<(char, usize, u32)>>,
}

impl Gwdt {
    fn new(version: u32) -> Self {
        Gwdt {
            version, now: Cell::new(0), en: Cell::new(false), wor: Cell::new(0), wcv: Cell::new(0),
            ws0: Cell::new(false), reset_at: Cell::new(None), writes: RefCell::new(Vec::new()),
        }
    }
    fn refresh(&self) {
        self.ws0.set(false);
        self.wcv.set(self.now.get() + self.wor.get());
    }
    /// Advance the system counter by `ticks`, one tick at a time.
    fn run(&self, ticks: u64) {
        for _ in 0..ticks {
            self.now.set(self.now.get() + 1);
            if !self.en.get() || self.reset_at.get().is_some() || self.now.get() < self.wcv.get() {
                continue;
            }
            if self.ws0.get() {
                self.reset_at.set(Some(self.now.get()));
            } else {
                self.ws0.set(true);
                self.wcv.set(self.now.get() + self.wor.get());
            }
        }
    }
}

impl g::Frames for Gwdt {
    fn ctrl_read32(&self, off: usize) -> u32 {
        match off {
            g::W_IIDR => self.version << 16 | 0x43B,
            g::WCS => self.en.get() as u32 | (self.ws0.get() as u32) << 1,
            _ => 0,
        }
    }
    fn ctrl_write32(&self, off: usize, val: u32) {
        self.writes.borrow_mut().push(('c', off, val));
        match off {
            g::WCS => {
                let was = self.en.get();
                self.en.set(val & g::WCS_EN != 0);
                if self.en.get() && !was {
                    self.refresh();
                }
            }
            g::WOR => {
                let hi = if self.version == 0 { 0 } else { self.wor.get() & !0xFFFF_FFFF };
                self.wor.set(hi | val as u64);
                self.refresh();
            }
            o if o == g::WOR + 4 && self.version != 0 => {
                self.wor.set((self.wor.get() & 0xFFFF_FFFF) | (val as u64 & 0xFFFF) << 32);
                self.refresh();
            }
            _ => {}
        }
    }
    fn refresh_write32(&self, off: usize, val: u32) {
        self.writes.borrow_mut().push(('r', off, val));
        if off == g::WRR {
            self.refresh();
        }
    }
}

/// `WOR` is half the timeout at the live counter rate; the armed timeout is
/// what that `WOR` gives, clamped to the version's register.
#[test]
fn sbsa_wor_is_half_the_timeout_at_the_counter_rate() {
    assert_eq!(g::wor_for_ms(10_000, 62_500_000, 0), (312_500_000, 10_000));
    assert_eq!(g::wor_for_ms(10_000, 1_000_000_000, 1), (5_000_000_000, 10_000));
    // Version 0 at 1 GHz: 32 bits of WOR are 4.29 s, so 8.58 s at most.
    let (wor, armed) = g::wor_for_ms(60_000, 1_000_000_000, 0);
    assert_eq!((wor, armed), (u32::MAX as u64, 8_589));
    assert_eq!(g::wor_for_ms(0, 1_000_000, 0).0, 1, "never a zero offset");
    assert_eq!(g::version(&Gwdt::new(1)), 1);
}

/// Arm writes the 48-bit offset low word first, refreshes, then enables;
/// disarm clears EN.
#[test]
fn sbsa_arm_and_disarm_writes() {
    let w = Gwdt::new(1);
    g::arm(&w, 0x1_2345_6789, 1);
    assert_eq!(*w.writes.borrow(), vec![
        ('c', g::WCS, 0), ('c', g::WOR, 0x2345_6789), ('c', g::WOR + 4, 1), ('r', g::WRR, 0), ('c', g::WCS, g::WCS_EN),
    ]);
    assert_eq!(w.wor.get(), 0x1_2345_6789);
    let w0 = Gwdt::new(0);
    g::arm(&w0, 0x1_2345_6789, 0);
    assert!(!w0.writes.borrow().iter().any(|&(f, o, _)| f == 'c' && o == g::WOR + 4), "version 0 has no high word");
    g::disarm(&w0);
    assert!(!w0.en.get());
}

/// Fed every 0.4 s, a 1 s watchdog never resets; once the feed stops the
/// reset comes within 1 s of the last refresh, not before half of it.
/// Canary: a `kick` that writes nothing resets the machine while it is fed.
#[test]
fn sbsa_a_fed_watchdog_holds_and_a_starved_one_resets() {
    const HZ: u64 = 10_000;
    let w = Gwdt::new(0);
    let (wor, armed) = g::wor_for_ms(1000, HZ, 0);
    assert_eq!(armed, 1000);
    g::arm(&w, wor, 0);
    for _ in 0..25 {
        w.run(HZ * 4 / 10);
        g::kick(&w);
    }
    assert_eq!(w.reset_at.get(), None, "a fed watchdog reset the machine");
    let last = w.now.get();
    w.run(HZ * 2);
    let at = w.reset_at.get().expect("a starved watchdog never reset the machine");
    assert!(at - last <= HZ && at - last > HZ / 2, "reset {} ticks after the last feed", at - last);
}

/// Disarmed, a starved watchdog does nothing.
#[test]
fn sbsa_a_disarmed_watchdog_never_resets() {
    let w = Gwdt::new(0);
    g::arm(&w, 100, 0);
    g::disarm(&w);
    w.run(10_000);
    assert_eq!(w.reset_at.get(), None);
}

// ── AMD FCH ─────────────────────────────────────────────────────────────────

/// The FCH PM bytes and the watchdog's two registers, with its counter: one
/// second per `second()`, a trigger reloads `COUNT`, zero resets.
struct Fch {
    pm: RefCell<[u8; 8]>,
    /// `DECODEEN.WDT_TMREN` cannot be set (a firmware that locks it).
    tmren_locked: bool,
    control: Cell<u32>,
    count: Cell<u32>,
    left: Cell<u32>,
    reset: Cell<bool>,
    writes: RefCell<Vec<(usize, u32)>>,
}

impl Fch {
    fn new(control: u32) -> Self {
        Fch {
            pm: RefCell::new([0, 0, 0, 0b1100, 0, 0, 0, 0]), tmren_locked: false, control: Cell::new(control),
            count: Cell::new(0), left: Cell::new(0), reset: Cell::new(false), writes: RefCell::new(Vec::new()),
        }
    }
    fn second(&self) {
        if self.control.get() & t::CTL_RUN == 0 || self.reset.get() {
            return;
        }
        self.left.set(self.left.get().saturating_sub(1));
        if self.left.get() == 0 {
            self.reset.set(true);
        }
    }
}

impl t::Pm for Fch {
    fn read8(&self, off: usize) -> u8 {
        self.pm.borrow()[off]
    }
    fn write8(&self, off: usize, val: u8) {
        let mut v = val;
        if off == t::PM_DECODEEN && self.tmren_locked {
            v &= !t::PM_DECODEEN_WDT_TMREN;
        }
        self.pm.borrow_mut()[off] = v;
    }
}

impl t::Regs for Fch {
    fn read32(&self, off: usize) -> u32 {
        match off {
            t::CONTROL => self.control.get(),
            t::COUNT => self.count.get(),
            _ => 0,
        }
    }
    fn write32(&self, off: usize, val: u32) {
        self.writes.borrow_mut().push((off, val));
        match off {
            t::CONTROL => {
                self.control.set(val & !t::CTL_TRIGGER);
                if val & t::CTL_TRIGGER != 0 {
                    self.left.set(self.count.get());
                }
            }
            t::COUNT => self.count.set(val),
            _ => {}
        }
    }
}

/// Only the Zen layout (the KERNCZ SMBus function at revision 0x51 or later,
/// AMD or Hygon) is driven.
#[test]
fn fch_only_the_zen_layout_is_driven() {
    assert!(t::is_efch_mmio(0x1022, 0x790b, 0x51));
    assert!(t::is_efch_mmio(0x1022, 0x790b, 0x71));
    assert!(t::is_efch_mmio(0x1d94, 0x790b, 0x51));
    assert!(!t::is_efch_mmio(0x1022, 0x790b, 0x50), "pre-Zen KERNCZ uses the index/data ports");
    assert!(!t::is_efch_mmio(0x1022, 0x780b, 0x51), "Hudson-2 is not this layout");
    assert!(!t::is_efch_mmio(0x8086, 0x790b, 0x51));
}

/// The decode is turned on when off, and a bit that does not stay set is a
/// refusal; the setup clears the disable bits, picks the 1 s resolution,
/// makes the action a reset and leaves the counter stopped.
#[test]
fn fch_decode_and_setup() {
    let f = Fch::new(t::CTL_ACTION_POWEROFF | t::CTL_RUN | t::CTL_FIRED);
    assert_eq!(t::enable_decode(&f), Ok(()));
    assert_ne!(f.pm.borrow()[t::PM_DECODEEN] & t::PM_DECODEEN_WDT_TMREN, 0);
    assert_eq!(t::setup(&f, &f), Ok(true), "the fired bit is reported");
    assert_eq!(f.pm.borrow()[t::PM_DECODEEN3], t::PM_DECODEEN3_SECOND_RES);
    assert_eq!(f.control.get() & (t::CTL_ACTION_POWEROFF | t::CTL_RUN), 0);

    let mut locked = Fch::new(0);
    locked.tmren_locked = true;
    assert_eq!(t::enable_decode(&locked), Err(t::Refused::NoDecode));
    assert_eq!(t::setup(&Fch::new(t::CTL_DISABLED), &Fch::new(t::CTL_DISABLED)), Err(t::Refused::Disabled));
}

/// Whole seconds, at least 1, at most 65535.
#[test]
fn fch_count_in_seconds() {
    assert_eq!(t::seconds_for_ms(10_000), (10, 10_000));
    assert_eq!(t::seconds_for_ms(1_500), (1, 1_000));
    assert_eq!(t::seconds_for_ms(0), (1, 1_000));
    assert_eq!(t::seconds_for_ms(u32::MAX), (0xFFFF, 0xFFFF * 1000));
}

/// Arm loads the count, runs, and triggers in a write of its own; fed every
/// second a 3 s watchdog holds, starved it resets within 3 s, disarmed it
/// never does. Canary: a `kick` without the trigger bit resets while fed.
#[test]
fn fch_a_fed_watchdog_holds_and_a_starved_one_resets() {
    let f = Fch::new(0);
    t::arm(&f, 3);
    assert_eq!(*f.writes.borrow(), vec![(t::COUNT, 3), (t::CONTROL, t::CTL_RUN), (t::CONTROL, t::CTL_RUN | t::CTL_TRIGGER)]);
    for _ in 0..20 {
        f.second();
        t::kick(&f);
    }
    assert!(!f.reset.get(), "a fed watchdog reset the machine");
    let mut n = 0;
    while !f.reset.get() && n < 10 {
        f.second();
        n += 1;
    }
    assert_eq!(n, 3, "the reset comes at the armed count");

    let d = Fch::new(0);
    t::arm(&d, 1);
    t::disarm(&d);
    for _ in 0..5 {
        d.second();
    }
    assert!(!d.reset.get());
}
