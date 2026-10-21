// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The real-time clock drivers (`crates/drivers/rtc`, Kconfig `DRV_RTC`) against
//! a model of each chip: a register file that behaves like the part, not like
//! the driver. The models are written from the data sheets and the QEMU
//! devices (goldfish: latch on the low read, commit on the low write; PL031:
//! PrimeCell ID registers, load register; MC146818: UIP, SET, BCD or binary,
//! 12 or 24 hour, an update that can land between two reads; PCF8563: VL, one
//! transfer for seven registers), and decode what a driver wrote with their own
//! arithmetic, so a driver that encodes wrongly is read back wrong.
//!
//! Wired by `#[cfg(test)] mod rtc;` in `lib.rs`.

use azos_rtc::civil::{bcd_to_bin, bin_to_bcd, year_start, DateTime};
use azos_rtc::goldfish::{Goldfish, TIME_HIGH, TIME_LOW};
use azos_rtc::mc146818::{Mc146818, PORT_DATA, PORT_INDEX};
use azos_rtc::pcf8563::{Pcf8563, ADDR};
use azos_rtc::pl031::{Pl031, RTCCR, RTCDR, RTCLR};
use azos_rtc::{Error, I2c, Mmio, Ports, Rtc};
use std::cell::RefCell;
use std::rc::Rc;

/// 2026-10-17T12:34:56Z (a Saturday).
const T2026: u64 = 1_792_240_496;
const NS: u64 = 1_000_000_000;

// ── The calendar ─────────────────────────────────────────────────────────────

/// Known instants: the epoch, a leap day that is a century (2000), one that is
/// not (2100 has none), the 32-bit rollover, and the first second of 2026.
#[test]
fn civil_known_instants() {
    let at = |s| DateTime::from_epoch(s).unwrap();
    assert_eq!((at(0).year, at(0).month, at(0).day, at(0).weekday()), (1970, 1, 1, 4), "a Thursday");
    assert_eq!((at(951_782_400).month, at(951_782_400).day), (2, 29), "2000 is a leap year");
    assert_eq!((at(1_709_164_800).month, at(1_709_164_800).day), (2, 29), "2024-02-29");
    let t = at(2_147_483_648);
    assert_eq!((t.year, t.month, t.day, t.hour, t.min, t.sec), (2038, 1, 19, 3, 14, 8));
    let t = at(4_102_444_800 - 1);
    assert_eq!((t.year, t.month, t.day, t.hour, t.min, t.sec), (2099, 12, 31, 23, 59, 59));
    assert_eq!(at(4_102_444_800).year, 2100);
    assert_eq!(year_start(2026), 1_767_225_600);
    assert_eq!(year_start(1969), 0, "before the epoch is the epoch");
    let t = at(T2026);
    assert_eq!((t.year, t.month, t.day, t.hour, t.min, t.sec, t.weekday()), (2026, 10, 17, 12, 34, 56, 6));
}

/// Every day of 1970..2110 round-trips, and so does the last second of it.
#[test]
fn civil_round_trips_every_day() {
    let mut s = 0u64;
    while s < 4_544_208_000 {
        let t = DateTime::from_epoch(s).unwrap();
        assert_eq!(t.to_epoch(), Some(s), "{t:?}");
        let last = DateTime::from_epoch(s + 86_399).unwrap();
        assert_eq!(last.to_epoch(), Some(s + 86_399), "{last:?}");
        s += 86_400;
    }
}

/// A field out of range is not a time (a chip in a power glitch reads such
/// registers), and a date before the epoch is not one the count holds.
#[test]
fn civil_refuses_what_is_not_a_date() {
    let t = |year, month, day, hour, min, sec| DateTime { year, month, day, hour, min, sec }.to_epoch();
    assert_eq!(t(2026, 2, 29, 0, 0, 0), None, "2026 is not a leap year");
    assert!(t(2028, 2, 29, 0, 0, 0).is_some());
    assert_eq!(t(2100, 2, 29, 0, 0, 0), None, "a century that is not divisible by 400");
    assert_eq!(t(2026, 13, 1, 0, 0, 0), None);
    assert_eq!(t(2026, 0, 1, 0, 0, 0), None);
    assert_eq!(t(2026, 4, 31, 0, 0, 0), None);
    assert_eq!(t(2026, 1, 1, 24, 0, 0), None);
    assert_eq!(t(2026, 1, 1, 0, 60, 0), None);
    assert_eq!(t(2026, 1, 1, 0, 0, 60), None);
    assert_eq!(t(1969, 12, 31, 23, 59, 59), None, "before the epoch");
    assert_eq!(bcd_to_bin(0x59), Some(59));
    assert_eq!(bcd_to_bin(0x5a), None);
    assert_eq!(bcd_to_bin(0xa0), None);
    assert_eq!(bin_to_bcd(59), 0x59);
}

// ── goldfish ────────────────────────────────────────────────────────────────

/// QEMU's goldfish RTC: a 64-bit nanosecond count. A read of the low word
/// latches the high word; a write of the high word is staged and the low word
/// commits both. Every access moves the count on by `drift` ns, so a driver
/// that reads the halves in the wrong order sees the carry.
struct GoldfishModel {
    ns: u64,
    latched_hi: u32,
    staged_hi: u32,
    drift: u64,
    /// The order of the writes, for the test that wants it.
    writes: Vec<u32>,
}

impl GoldfishModel {
    fn new(ns: u64) -> Self {
        GoldfishModel { ns, latched_hi: 0, staged_hi: 0, drift: 0, writes: Vec::new() }
    }
}

#[derive(Clone)]
struct Gf(Rc<RefCell<GoldfishModel>>);

impl Mmio for Gf {
    fn read32(&mut self, off: u32) -> u32 {
        let mut m = self.0.borrow_mut();
        let v = match off {
            TIME_LOW => {
                m.latched_hi = (m.ns >> 32) as u32;
                m.ns as u32
            }
            TIME_HIGH => m.latched_hi,
            _ => 0,
        };
        m.ns += m.drift;
        v
    }
    fn write32(&mut self, off: u32, v: u32) {
        let mut m = self.0.borrow_mut();
        m.writes.push(off);
        match off {
            TIME_HIGH => m.staged_hi = v,
            TIME_LOW => m.ns = (m.staged_hi as u64) << 32 | v as u64,
            _ => {}
        }
    }
}

fn goldfish(ns: u64) -> (Goldfish<Gf>, Rc<RefCell<GoldfishModel>>) {
    let m = Rc::new(RefCell::new(GoldfishModel::new(ns)));
    (Goldfish::new(Gf(m.clone())), m)
}

/// The count is nanoseconds: the seconds are the count divided, the sub-second
/// part is dropped.
#[test]
fn goldfish_reads_seconds() {
    let (mut g, _) = goldfish(T2026 * NS + 999_999_999);
    assert_eq!(g.read(), Ok(T2026));
    let (mut zero, _) = goldfish(0);
    assert_eq!(zero.read(), Err(Error::Lost), "a device with no host clock");
}

/// **Canary:** read `TIME_HIGH` first and the model's latch is stale (and,
/// with a carry between the two reads, a whole 4.29 s off): the exact-second
/// assertion fails.
#[test]
fn goldfish_reads_low_first_so_a_carry_between_the_words_is_latched() {
    // The count is a few ns short of a carry of the low word; every access
    // moves it on by 1 us, so the carry lands between the two reads.
    let base = (T2026 * NS) & !0xffff_ffff;
    let ns = base + 0xffff_ffff - 500;
    let (mut g, m) = goldfish(ns);
    m.borrow_mut().drift = 1_000;
    assert_eq!(g.read(), Ok(ns / NS));
}

/// A set writes the high word first and the low word commits: a model that
/// commits on the low write holds the time exactly, and a reader gets it back.
/// **Canary:** write the low word first: the commit takes the stale staged
/// high word and the read-back is off by billions of seconds.
#[test]
fn goldfish_set_commits_on_the_low_word() {
    let (mut g, m) = goldfish(5 * NS);
    m.borrow_mut().staged_hi = 0x1234;
    g.set(T2026).unwrap();
    assert_eq!(m.borrow().writes, [TIME_HIGH, TIME_LOW]);
    assert_eq!(m.borrow().ns, T2026 * NS);
    assert_eq!(g.read(), Ok(T2026));
    assert_eq!(g.set(u64::MAX / 2), Err(Error::Range), "past 584 years of nanoseconds");
}

// ── PL031 ───────────────────────────────────────────────────────────────────

struct Pl031Model {
    secs: u32,
    cr: u32,
    id: [u32; 8],
    writes: Vec<(u32, u32)>,
}

#[derive(Clone)]
struct Pl(Rc<RefCell<Pl031Model>>);

/// The IDs QEMU's PL031 returns: part 0x031, revision 1, PrimeCell 0xB105F00D.
const PL031_ID: [u32; 8] = [0x31, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1];

impl Mmio for Pl {
    fn read32(&mut self, off: u32) -> u32 {
        let m = self.0.borrow();
        match off {
            RTCDR => m.secs,
            RTCCR => m.cr,
            0xfe0..=0xffc if off % 4 == 0 => m.id[((off - 0xfe0) / 4) as usize],
            _ => 0,
        }
    }
    fn write32(&mut self, off: u32, v: u32) {
        let mut m = self.0.borrow_mut();
        m.writes.push((off, v));
        match off {
            RTCLR => m.secs = v,
            RTCCR => m.cr = v & 1,
            _ => {}
        }
    }
}

fn pl031(secs: u32) -> (Pl031<Pl>, Rc<RefCell<Pl031Model>>) {
    let m = Rc::new(RefCell::new(Pl031Model { secs, cr: 0, id: PL031_ID, writes: Vec::new() }));
    (Pl031::probe(Pl(m.clone())).unwrap(), m)
}

/// The PrimeCell ID registers say what is behind the window: the QEMU PL031 is
/// taken, another peripheral (or an unmapped bus: zeros, ones) is not.
#[test]
fn pl031_probe_checks_the_prime_cell_ids() {
    let m = Rc::new(RefCell::new(Pl031Model { secs: 1, cr: 0, id: PL031_ID, writes: Vec::new() }));
    assert!(Pl031::probe(Pl(m.clone())).is_ok());
    for bad in [[0u32; 8], [0xff; 8], [0x11, 0x10, 0x14, 0, 0x0d, 0xf0, 0x05, 0xb1], [0x31, 0x10, 0x14, 0, 0x0d, 0xf0, 0x05, 0xb0]] {
        m.borrow_mut().id = bad;
        assert_eq!(Pl031::probe(Pl(m.clone())).err(), Some(Error::NoDevice), "{bad:x?}");
    }
}

#[test]
fn pl031_reads_and_loads_seconds() {
    let (mut p, m) = pl031(T2026 as u32);
    assert_eq!(p.read(), Ok(T2026));
    p.set(T2026 + 3600).unwrap();
    assert_eq!(m.borrow().secs as u64, T2026 + 3600);
    assert_eq!(p.read(), Ok(T2026 + 3600));
    assert_eq!(m.borrow().cr, 1, "a set starts a stopped counter");
    assert_eq!(p.set(1 << 32), Err(Error::Range), "past 2106");
    assert_eq!(p.set(u32::MAX as u64), Ok(()));
}

/// A counter that runs is not written to start again; only the load register
/// and (once) the control register are touched, never the match or the
/// interrupt registers.
#[test]
fn pl031_touches_only_the_load_and_control_registers() {
    let (mut p, m) = pl031(0);
    p.set(T2026).unwrap();
    p.set(T2026 + 1).unwrap();
    let w = m.borrow().writes.clone();
    assert_eq!(w, [(RTCLR, T2026 as u32), (RTCCR, 1), (RTCLR, T2026 as u32 + 1)]);
}

// ── MC146818 ────────────────────────────────────────────────────────────────

const CENTURY: u8 = 0x32;

struct CmosModel {
    /// The true time, advanced by the test or by a scheduled update.
    secs: u64,
    binary: bool,
    h24: bool,
    vrt: bool,
    /// Status A reads that still say "update in progress".
    uip_reads: u32,
    /// After this many reads of a time register, the update lands (+1 s), once.
    tear_after: Option<u32>,
    time_reads: u32,
    /// Writes with SET held go here; clearing SET commits them.
    set: bool,
    staged: [u8; 128],
    a: u8,
    index: u8,
    log: Vec<(u8, u8)>,
}

impl CmosModel {
    fn new(secs: u64, binary: bool, h24: bool) -> Self {
        CmosModel {
            secs, binary, h24, vrt: true, uip_reads: 0, tear_after: None, time_reads: 0,
            set: false, staged: [0; 128], a: 0x26, index: 0, log: Vec::new(),
        }
    }

    fn enc(&self, v: u8) -> u8 {
        if self.binary { v } else { bin_to_bcd(v) }
    }

    fn reg(&mut self, r: u8) -> u8 {
        let t = DateTime::from_epoch(self.secs).unwrap();
        match r {
            0x00 => self.enc(t.sec),
            0x02 => self.enc(t.min),
            0x04 if self.h24 => self.enc(t.hour),
            0x04 => {
                let h12 = if t.hour % 12 == 0 { 12 } else { t.hour % 12 };
                self.enc(h12) | if t.hour >= 12 { 0x80 } else { 0 }
            }
            0x06 => t.weekday() + 1,
            0x07 => self.enc(t.day),
            0x08 => self.enc(t.month),
            0x09 => self.enc((t.year % 100) as u8),
            0x32 => self.enc((t.year / 100) as u8),
            0x0a => self.a & 0x7f | if self.uip_reads > 0 { 0x80 } else { 0 },
            0x0b => (if self.binary { 4 } else { 0 }) | (if self.h24 { 2 } else { 0 }) | if self.set { 0x80 } else { 0 },
            0x0d => if self.vrt { 0x80 } else { 0 },
            _ => 0,
        }
    }

    /// Decode the staged registers, the way the chip would count from them.
    fn commit(&mut self) {
        let dec = |m: &CmosModel, v: u8| if m.binary { v } else { bcd_to_bin(v).unwrap() };
        let s = &self.staged;
        let hour = if self.h24 { dec(self, s[4]) } else {
            let h = dec(self, s[4] & 0x7f);
            h % 12 + if s[4] & 0x80 != 0 { 12 } else { 0 }
        };
        let t = DateTime {
            year: dec(self, s[0x32]) as u16 * 100 + dec(self, s[9]) as u16,
            month: dec(self, s[8]),
            day: dec(self, s[7]),
            hour,
            min: dec(self, s[2]),
            sec: dec(self, s[0]),
        };
        // The weekday the driver wrote must be the date's.
        assert_eq!(s[6], t.weekday() + 1, "weekday register");
        self.secs = t.to_epoch().expect("the driver wrote a date");
    }
}

#[derive(Clone)]
struct Cmos(Rc<RefCell<CmosModel>>);

impl Ports for Cmos {
    fn inb(&mut self, port: u16) -> u8 {
        assert_eq!(port, PORT_DATA);
        let mut m = self.0.borrow_mut();
        let r = m.index;
        if r == 0x0a && m.uip_reads > 0 {
            let v = m.reg(r);
            m.uip_reads -= 1;
            return v;
        }
        if matches!(r, 0x00 | 0x02 | 0x04 | 0x07 | 0x08 | 0x09 | 0x32) {
            let v = m.reg(r);
            m.time_reads += 1;
            if m.tear_after == Some(m.time_reads) {
                m.secs += 1;
                m.tear_after = None;
            }
            return v;
        }
        m.reg(r)
    }
    fn outb(&mut self, port: u16, v: u8) {
        let mut m = self.0.borrow_mut();
        if port == PORT_INDEX {
            assert_eq!(v & 0x80, 0, "the driver never disables NMI");
            m.index = v;
            return;
        }
        assert_eq!(port, PORT_DATA);
        let r = m.index;
        m.log.push((r, v));
        match r {
            0x0a => m.a = v,
            0x0b => {
                let was = m.set;
                m.set = v & 0x80 != 0;
                m.binary = v & 4 != 0;
                m.h24 = v & 2 != 0;
                if was && !m.set {
                    m.commit();
                }
            }
            _ if m.set => m.staged[r as usize] = v,
            _ => panic!("a time register written without SET held: {r:#x}"),
        }
    }
}

fn cmos(secs: u64, binary: bool, h24: bool) -> (Mc146818<Cmos>, Rc<RefCell<CmosModel>>) {
    let m = Rc::new(RefCell::new(CmosModel::new(secs, binary, h24)));
    (Mc146818::new(Cmos(m.clone()), Some(CENTURY), 1000), m)
}

/// Binary and BCD, 24 and 12 hour: the same instant reads back four ways.
#[test]
fn cmos_reads_every_format() {
    for (binary, h24) in [(false, true), (true, true), (false, false), (true, false)] {
        for t in [T2026, 951_782_400 + 86_399, 4_102_444_799, 1_767_225_600, 1_767_225_600 + 12 * 3600] {
            let (mut c, _) = cmos(t, binary, h24);
            assert_eq!(c.read(), Ok(t), "binary={binary} 24h={h24} t={t}");
        }
    }
}

/// 12-hour mode around noon and midnight: 12 AM is hour 0, 12 PM hour 12.
/// **Canary:** `hour % 12` dropped: 12 AM reads as noon.
#[test]
fn cmos_twelve_hour_mode_noon_and_midnight() {
    let day = 1_767_225_600u64;
    for h in 0..24u64 {
        let (mut c, _) = cmos(day + h * 3600 + 61, false, false);
        assert_eq!(c.read(), Ok(day + h * 3600 + 61), "hour {h}");
    }
}

/// A battery that died: the chip says so (status D, bit 7), and the read is
/// `Lost`, however plausible the registers look.
/// **Canary:** skip the `VRT` check: the read returns the registers.
#[test]
fn cmos_dead_battery_is_lost() {
    let (mut c, m) = cmos(T2026, false, true);
    m.borrow_mut().vrt = false;
    assert_eq!(c.read(), Err(Error::Lost));
}

/// A bus that floats high (no CMOS on this machine) answers 0xff everywhere,
/// status D included: not a chip.
#[test]
fn cmos_floating_bus_is_no_device() {
    struct Floating;
    impl Ports for Floating {
        fn inb(&mut self, _: u16) -> u8 { 0xff }
        fn outb(&mut self, _: u16, _: u8) {}
    }
    assert_eq!(Mc146818::new(Floating, Some(CENTURY), 1000).read(), Err(Error::NoDevice));
}

/// Registers that are not a date (a glitch: month 0) are `Lost`, not a wrong
/// time.
#[test]
fn cmos_garbage_is_lost() {
    struct ZeroMonth(Cmos);
    impl Ports for ZeroMonth {
        fn inb(&mut self, p: u16) -> u8 {
            let v = self.0.inb(p);
            if self.0 .0.borrow().index == 0x08 { 0 } else { v }
        }
        fn outb(&mut self, p: u16, v: u8) {
            self.0.outb(p, v)
        }
    }
    let m = Rc::new(RefCell::new(CmosModel::new(T2026, true, true)));
    assert_eq!(Mc146818::new(Cmos(m.clone()), Some(CENTURY), 1000).read(), Ok(T2026));
    assert_eq!(Mc146818::new(ZeroMonth(Cmos(m)), Some(CENTURY), 1000).read(), Err(Error::Lost), "month 0");
}

/// **A read is a snapshot between two updates.** The update lands between the
/// seconds and the rest of the registers at 23:59:59 on New Year's Eve: a
/// single pass would return 2027-01-01 00:00:59 (a time that was never true).
/// The read takes the registers twice and believes two that agree.
/// **Canary:** read the registers once: the torn value is returned.
#[test]
fn cmos_read_does_not_return_a_torn_time() {
    let nye = DateTime { year: 2026, month: 12, day: 31, hour: 23, min: 59, sec: 59 }.to_epoch().unwrap();
    let (mut c, m) = cmos(nye, false, true);
    m.borrow_mut().tear_after = Some(1);
    assert_eq!(c.read(), Ok(nye + 1), "the new second, whole");
}

/// The wait for the update to end is bounded: a stuck `UIP` is a bus fault,
/// not a hung boot; a short one is waited out.
#[test]
fn cmos_uip_wait_is_bounded() {
    let (mut c, m) = cmos(T2026, false, true);
    m.borrow_mut().uip_reads = 10;
    assert_eq!(c.read(), Ok(T2026), "waited out");
    m.borrow_mut().uip_reads = u32::MAX;
    assert_eq!(c.read(), Err(Error::Bus), "stuck");
    assert!(m.borrow().uip_reads > u32::MAX - 2000, "and it did not spin forever");
}

/// A set round-trips in every format, writes the weekday (Sunday = 1), turns
/// the oscillator on, always leaves 24-hour mode, and holds `SET` only while
/// the registers change.
/// **Canary:** write `weekday()` without the +1: the model's weekday assert fires.
#[test]
fn cmos_set_round_trips() {
    for (binary, h24) in [(false, true), (true, true), (false, false), (true, false)] {
        for t in [T2026, 951_782_400, 4_102_444_799, 1_767_225_600 + 12 * 3600 + 5] {
            let (mut c, m) = cmos(1_000_000_000, binary, h24);
            m.borrow_mut().a = 0x06; // divider off
            c.set(t).unwrap();
            assert_eq!(m.borrow().secs, t, "binary={binary} 24h={h24}");
            assert_eq!(m.borrow().a & 0x70, 0x20, "oscillator on");
            assert!(m.borrow().h24, "24-hour afterwards");
            assert_eq!(m.borrow().binary, binary, "the number format is the chip's");
            assert!(!m.borrow().set, "SET released");
            assert_eq!(c.read(), Ok(t));
        }
    }
    let (mut c, _) = cmos(0, false, true);
    assert_eq!(c.set(4_102_444_800), Err(Error::Range), "2100");
    assert_eq!(c.set(946_684_799), Err(Error::Range), "1999");
}

// ── PCF8563 ─────────────────────────────────────────────────────────────────

struct PcfModel {
    regs: [u8; 16],
    /// Transfers, to see that the seven time registers go in one.
    reads: Vec<(u8, usize)>,
    writes: Vec<Vec<u8>>,
    nack: bool,
}

#[derive(Clone)]
struct Bus(Rc<RefCell<PcfModel>>);

impl I2c for Bus {
    fn read_regs(&mut self, addr: u8, reg: u8, buf: &mut [u8]) -> Result<(), Error> {
        let mut m = self.0.borrow_mut();
        if addr != ADDR || m.nack {
            return Err(Error::Bus);
        }
        m.reads.push((reg, buf.len()));
        for (i, b) in buf.iter_mut().enumerate() {
            *b = m.regs[(reg as usize + i) & 15];
        }
        Ok(())
    }
    fn write_regs(&mut self, addr: u8, data: &[u8]) -> Result<(), Error> {
        let mut m = self.0.borrow_mut();
        if addr != ADDR || m.nack {
            return Err(Error::Bus);
        }
        m.writes.push(data.to_vec());
        for (i, b) in data[1..].iter().enumerate() {
            let r = (data[0] as usize + i) & 15;
            m.regs[r] = *b;
        }
        Ok(())
    }
}

/// A chip just powered on: `VL` set, stopped (`STOP`).
fn pcf() -> (Pcf8563<Bus>, Rc<RefCell<PcfModel>>) {
    let mut regs = [0u8; 16];
    regs[0] = 0x20; // STOP
    regs[2] = 0x80; // VL
    regs[3] = 0x01;
    regs[4] = 0x00;
    regs[5] = 0x01;
    regs[7] = 0x01;
    let m = Rc::new(RefCell::new(PcfModel { regs, reads: Vec::new(), writes: Vec::new(), nack: false }));
    (Pcf8563::new(Bus(m.clone())), m)
}

/// **A chip whose clock integrity is not guaranteed has no time**: `VL` is
/// `Lost`, and a set clears it.
/// **Canary:** ignore `VL`: the read returns 2000-01-01.
#[test]
fn pcf8563_vl_is_lost_until_set() {
    let (mut p, m) = pcf();
    assert_eq!(p.read(), Err(Error::Lost));
    p.set(T2026).unwrap();
    assert_eq!(m.borrow().regs[2] & 0x80, 0, "VL cleared by the seconds write");
    assert_eq!(m.borrow().regs[0] & 0xa8, 0, "STOP and the test bits cleared");
    assert_eq!(p.read(), Ok(T2026));
}

/// The time registers go in one transfer each way (the chip freezes its
/// counters into the read buffer for one transfer), the weekday is Sunday = 0,
/// and the century bit is written 0.
#[test]
fn pcf8563_uses_one_transfer_and_writes_the_calendar_in_bcd() {
    let (mut p, m) = pcf();
    p.set(T2026).unwrap();
    let w = m.borrow().writes.last().unwrap().clone();
    assert_eq!(w, [0x02, 0x56, 0x34, 0x12, 0x17, 6, 0x10, 0x26], "2026-10-17 12:34:56, Saturday");
    p.read().unwrap();
    assert_eq!(*m.borrow().reads.last().unwrap(), (0x02, 7));
}

/// Clones disagree on the century bit's level; a read ignores it.
#[test]
fn pcf8563_ignores_the_century_bit() {
    let (mut p, m) = pcf();
    p.set(T2026).unwrap();
    m.borrow_mut().regs[7] |= 0x80;
    assert_eq!(p.read(), Ok(T2026));
}

/// Registers that are not BCD, or not a date, are `Lost`; the reserved bits
/// of each register are masked.
#[test]
fn pcf8563_garbage_is_lost_and_reserved_bits_are_masked() {
    let (mut p, m) = pcf();
    p.set(T2026).unwrap();
    m.borrow_mut().regs[3] = 0x6a;
    assert_eq!(p.read(), Err(Error::Lost));
    m.borrow_mut().regs[3] = 0x34 | 0x80;
    m.borrow_mut().regs[4] = 0x12 | 0xc0;
    m.borrow_mut().regs[5] = 0x17 | 0xc0;
    m.borrow_mut().regs[7] = 0x10 | 0x60;
    assert_eq!(p.read(), Ok(T2026), "bits that are not the field's are not read");
    m.borrow_mut().regs[7] = 0x13;
    assert_eq!(p.read(), Err(Error::Lost), "month 13");
}

/// Leap days and the last second of the range survive a round trip; a time the
/// two-digit year cannot hold is `Range`.
#[test]
fn pcf8563_round_trips_and_refuses_what_it_cannot_hold() {
    let (mut p, _) = pcf();
    for t in [951_782_400u64, 1_709_164_800 + 86_399, 4_102_444_799, 946_684_800] {
        p.set(t).unwrap();
        assert_eq!(p.read(), Ok(t));
    }
    assert_eq!(p.set(4_102_444_800), Err(Error::Range), "2100");
    assert_eq!(p.set(946_684_799), Err(Error::Range), "1999");
}

/// A bus that does not answer is `Bus`, and a failed set writes nothing.
#[test]
fn pcf8563_bus_failure_is_bus() {
    let (mut p, m) = pcf();
    m.borrow_mut().nack = true;
    assert_eq!(p.read(), Err(Error::Bus));
    assert_eq!(p.set(T2026), Err(Error::Bus));
    assert!(m.borrow().writes.is_empty());
}
