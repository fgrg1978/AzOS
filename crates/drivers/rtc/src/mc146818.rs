// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The MC146818 CMOS clock, in every PC (x86_64): an index port (0x70) and a
//! data port (0x71) in front of 128 bytes of battery-backed registers.
//!
//! **A read is a snapshot taken between two updates.** The chip rewrites its
//! time registers once a second and raises `UIP` (status A, bit 7) 244 us
//! before it does; a read that straddles the update returns a time that was
//! never true (23:59:59 with the date of the next day). So the read waits for
//! `UIP` to clear, takes the registers twice and believes them when the two
//! agree. Both waits are bounded (a stuck bit is [`Error::Bus`], not a hung
//! boot).
//!
//! **The format is the chip's.** Status B says binary or BCD (`DM`) and 24-hour
//! or 12-hour (`24H`); firmware chooses and a read follows. A set writes in the
//! chip's number format and in 24-hour time, and turns the oscillator on
//! (status A, divider 010) in case a board left it off. The century is the
//! register the FADT names, 0x32 where it does not; a value that is not 19, 20
//! or 21 is read as 20.
//!
//! `VRT` (status D, bit 7) is 0 when the battery died: [`Error::Lost`].
//! The chip also keeps two-digit years, so a set outside 2000..=2099 is
//! [`Error::Range`].

use crate::civil::{bcd_to_bin, bin_to_bcd, DateTime};
use crate::{Error, Ports, Rtc};

/// Index port. Bit 7 of the index disables NMI on a PC; this driver never sets it.
pub const PORT_INDEX: u16 = 0x70;
/// Data port.
pub const PORT_DATA: u16 = 0x71;
/// The century register where the FADT does not name one.
pub const CENTURY_DEFAULT: u8 = 0x32;

const SEC: u8 = 0x00;
const MIN: u8 = 0x02;
const HOUR: u8 = 0x04;
const WDAY: u8 = 0x06;
const DAY: u8 = 0x07;
const MON: u8 = 0x08;
const YEAR: u8 = 0x09;
const STATUS_A: u8 = 0x0a;
const STATUS_B: u8 = 0x0b;
const STATUS_D: u8 = 0x0d;

/// Status A: an update is under way.
const A_UIP: u8 = 0x80;
/// Status A: divider 010 (32.768 kHz time base), the running oscillator.
const A_DIVIDER_RUN: u8 = 0x20;
/// Status B: `SET` stops updates so the time can be written.
const B_SET: u8 = 0x80;
/// Status B: 24-hour mode.
const B_24H: u8 = 0x02;
/// Status B: binary numbers, not BCD.
const B_BINARY: u8 = 0x04;
/// Status D: the battery is good.
const D_VRT: u8 = 0x80;

/// Snapshots tried before giving up on two that agree.
const SNAPSHOTS: u32 = 4;

pub struct Mc146818<P: Ports> {
    p: P,
    century: Option<u8>,
    /// Reads of status A spent waiting for `UIP` (Kconfig `RTC_UIP_POLLS`).
    uip_polls: u32,
}

/// One reading of the time registers, raw.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Snapshot {
    sec: u8,
    min: u8,
    hour: u8,
    day: u8,
    mon: u8,
    year: u8,
    century: u8,
}

impl<P: Ports> Mc146818<P> {
    /// The CMOS clock on the standard ports. `century` is the register the
    /// FADT names (`None`: 20xx assumed, and a set writes no century);
    /// `uip_polls` the reads of status A a wait for `UIP` to clear spends
    /// before giving up (`UIP` lasts 244 us, a read is a microsecond or two).
    pub fn new(p: P, century: Option<u8>, uip_polls: u32) -> Self {
        Mc146818 { p, century, uip_polls }
    }

    fn rd(&mut self, reg: u8) -> u8 {
        self.p.outb(PORT_INDEX, reg);
        self.p.inb(PORT_DATA)
    }

    fn wr(&mut self, reg: u8, v: u8) {
        self.p.outb(PORT_INDEX, reg);
        self.p.outb(PORT_DATA, v);
    }

    fn wait_not_updating(&mut self) -> Result<(), Error> {
        for _ in 0..self.uip_polls {
            if self.rd(STATUS_A) & A_UIP == 0 {
                return Ok(());
            }
        }
        Err(Error::Bus)
    }

    fn snapshot(&mut self) -> Snapshot {
        Snapshot {
            sec: self.rd(SEC),
            min: self.rd(MIN),
            hour: self.rd(HOUR),
            day: self.rd(DAY),
            mon: self.rd(MON),
            year: self.rd(YEAR),
            century: self.century.map_or(0, |r| self.rd(r)),
        }
    }
}

impl<P: Ports> Rtc for Mc146818<P> {
    fn name(&self) -> &'static str {
        "mc146818"
    }

    fn read(&mut self) -> Result<u64, Error> {
        let d = self.rd(STATUS_D);
        // Bits 6..0 of status D read 0 on a chip: a bus that floats high
        // (no CMOS) answers 0xff.
        if d & 0x7f != 0 {
            return Err(Error::NoDevice);
        }
        if d & D_VRT == 0 {
            return Err(Error::Lost);
        }
        let b = self.rd(STATUS_B);
        let mut raw = None;
        for _ in 0..SNAPSHOTS {
            self.wait_not_updating()?;
            let first = self.snapshot();
            let second = self.snapshot();
            if first == second {
                raw = Some(first);
                break;
            }
        }
        let s = raw.ok_or(Error::Bus)?;

        let num = |v: u8| -> Result<u8, Error> {
            if b & B_BINARY != 0 { Ok(v) } else { bcd_to_bin(v).ok_or(Error::Lost) }
        };
        let hour = if b & B_24H != 0 {
            num(s.hour)?
        } else {
            // 12-hour: 1..=12 in the low bits, PM in bit 7.
            let h = num(s.hour & 0x7f)?;
            (h % 12) + if s.hour & 0x80 != 0 { 12 } else { 0 }
        };
        let century = match self.century {
            Some(_) => match num(s.century) {
                Ok(c @ 19..=21) => c,
                _ => 20,
            },
            None => 20,
        };
        let t = DateTime {
            year: century as u16 * 100 + num(s.year)? as u16,
            month: num(s.mon)?,
            day: num(s.day)?,
            hour,
            min: num(s.min)?,
            sec: num(s.sec)?,
        };
        t.to_epoch().ok_or(Error::Lost)
    }

    fn set(&mut self, unix_secs: u64) -> Result<(), Error> {
        let t = DateTime::from_epoch(unix_secs).ok_or(Error::Range)?;
        if !(2000..=2099).contains(&t.year) {
            return Err(Error::Range);
        }
        let b = self.rd(STATUS_B);
        let enc = |v: u8| if b & B_BINARY != 0 { v } else { bin_to_bcd(v) };
        let a = self.rd(STATUS_A);
        self.wr(STATUS_A, (a & 0x0f) | A_DIVIDER_RUN);
        self.wr(STATUS_B, b | B_SET | B_24H);
        self.wr(SEC, enc(t.sec));
        self.wr(MIN, enc(t.min));
        self.wr(HOUR, enc(t.hour));
        // Sunday is 1 in this chip.
        self.wr(WDAY, t.weekday() + 1);
        self.wr(DAY, enc(t.day));
        self.wr(MON, enc(t.month));
        self.wr(YEAR, enc((t.year % 100) as u8));
        if let Some(r) = self.century {
            self.wr(r, enc((t.year / 100) as u8));
        }
        // Clearing `SET` restarts the divider chain: the new second starts
        // within half a second.
        self.wr(STATUS_B, (b | B_24H) & !B_SET);
        Ok(())
    }
}
