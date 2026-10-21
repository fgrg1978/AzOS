// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The NXP PCF8563 real-time clock, over I2C at address 0x51 (boards).
//!
//! Registers 0x02..=0x08 hold seconds, minutes, hours, days, weekdays, months
//! and years in BCD; the seconds register's bit 7 is `VL`, "clock integrity is
//! not guaranteed" (the oscillator stopped or the supply dropped), which is
//! [`Error::Lost`]. The chip counts two-digit years, so it holds 2000..=2099;
//! the century bit (months, bit 7) is ignored on a read (clones differ on which
//! level means 20xx) and written 0 on a set.
//!
//! The seven time registers are read in one transfer: the chip freezes its
//! counters into the read buffer for the transfer, so the seconds and the
//! minutes cannot belong to different seconds. A set writes them in one
//! transfer too, and writing the seconds register with bit 7 clear clears
//! `VL`. `STOP` and the test bits of control 1 are cleared on a set, in case a
//! board's first power-up left the chip stopped.

use crate::civil::{bcd_to_bin, bin_to_bcd, DateTime};
use crate::{Error, I2c, Rtc};

/// The chip's 7-bit address.
pub const ADDR: u8 = 0x51;

const CONTROL1: u8 = 0x00;
const SECONDS: u8 = 0x02;
/// Seconds: clock integrity not guaranteed.
const VL: u8 = 0x80;
/// Control 1: `TEST1` (7), `STOP` (5) and `TESTC` (3) must all be 0 in normal operation.
const CONTROL1_ABNORMAL: u8 = 0xa8;

pub struct Pcf8563<B: I2c> {
    bus: B,
}

impl<B: I2c> Pcf8563<B> {
    pub fn new(bus: B) -> Self {
        Pcf8563 { bus }
    }
}

impl<B: I2c> Rtc for Pcf8563<B> {
    fn name(&self) -> &'static str {
        "pcf8563"
    }

    fn read(&mut self) -> Result<u64, Error> {
        let mut r = [0u8; 7];
        self.bus.read_regs(ADDR, SECONDS, &mut r)?;
        if r[0] & VL != 0 {
            return Err(Error::Lost);
        }
        let bcd = |v: u8| bcd_to_bin(v).ok_or(Error::Lost);
        let t = DateTime {
            year: 2000 + bcd(r[6])? as u16,
            month: bcd(r[5] & 0x1f)?,
            day: bcd(r[3] & 0x3f)?,
            hour: bcd(r[2] & 0x3f)?,
            min: bcd(r[1] & 0x7f)?,
            sec: bcd(r[0] & 0x7f)?,
        };
        t.to_epoch().ok_or(Error::Lost)
    }

    fn set(&mut self, unix_secs: u64) -> Result<(), Error> {
        let t = DateTime::from_epoch(unix_secs).ok_or(Error::Range)?;
        if !(2000..=2099).contains(&t.year) {
            return Err(Error::Range);
        }
        let mut c1 = [0u8; 1];
        self.bus.read_regs(ADDR, CONTROL1, &mut c1)?;
        if c1[0] & CONTROL1_ABNORMAL != 0 {
            self.bus.write_regs(ADDR, &[CONTROL1, c1[0] & !CONTROL1_ABNORMAL])?;
        }
        self.bus.write_regs(
            ADDR,
            &[
                SECONDS,
                bin_to_bcd(t.sec),
                bin_to_bcd(t.min),
                bin_to_bcd(t.hour),
                bin_to_bcd(t.day),
                t.weekday(),
                bin_to_bcd(t.month),
                bin_to_bcd((t.year % 100) as u8),
            ],
        )
    }
}
