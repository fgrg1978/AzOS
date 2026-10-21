// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Calendar arithmetic for the chips that keep a date, not a count: days from
//! 1970-01-01 and back (Howard Hinnant's `days_from_civil` /
//! `civil_from_days`), proleptic Gregorian, UTC, no leap seconds (the RTC
//! counts calendar seconds; the TAI-UTC table is the wall clock's, not the
//! chip's).

/// A broken-down UTC time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateTime {
    pub year: u16,
    /// 1..=12.
    pub month: u8,
    /// 1..=31.
    pub day: u8,
    /// 0..=23.
    pub hour: u8,
    pub min: u8,
    pub sec: u8,
}

const SECS_PER_DAY: u64 = 86_400;

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u8) -> u8 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(y) => 29,
        _ => 28,
    }
}

/// Days from 1970-01-01 to the civil date (negative before it).
fn days_from_civil(y: i64, m: u8, d: u8) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date of the day `z` days from 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u8, u8) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

impl DateTime {
    /// The time `secs` seconds after 1970-01-01T00:00:00Z. `None` past year
    /// 65535 (no chip goes near it).
    pub fn from_epoch(secs: u64) -> Option<DateTime> {
        let (y, month, day) = civil_from_days((secs / SECS_PER_DAY) as i64);
        let rem = secs % SECS_PER_DAY;
        Some(DateTime {
            year: u16::try_from(y).ok()?,
            month,
            day,
            hour: (rem / 3_600) as u8,
            min: (rem % 3_600 / 60) as u8,
            sec: (rem % 60) as u8,
        })
    }

    /// Seconds after 1970-01-01T00:00:00Z. `None` for a field out of range
    /// (month 13, 30 February, hour 24) or a date before 1970.
    pub fn to_epoch(&self) -> Option<u64> {
        let y = self.year as i64;
        if !(1..=12).contains(&self.month)
            || self.day == 0
            || self.day > days_in_month(y, self.month)
            || self.hour > 23
            || self.min > 59
            || self.sec > 59
        {
            return None;
        }
        let days = u64::try_from(days_from_civil(y, self.month, self.day)).ok()?;
        Some(days * SECS_PER_DAY + self.hour as u64 * 3_600 + self.min as u64 * 60 + self.sec as u64)
    }

    /// Day of the week, 0 = Sunday (the PCF8563's convention; the MC146818's
    /// register counts from 1).
    pub fn weekday(&self) -> u8 {
        // 1970-01-01 was a Thursday.
        (days_from_civil(self.year as i64, self.month, self.day) + 4).rem_euclid(7) as u8
    }
}

/// The first second of `year` (UTC), for a plausibility floor. `year` below
/// 1970 gives 0.
pub fn year_start(year: u16) -> u64 {
    u64::try_from(days_from_civil(year as i64, 1, 1)).unwrap_or(0) * SECS_PER_DAY
}

/// Two packed-BCD digits to a number; `None` if either nibble is not a digit
/// (a chip in the middle of a power glitch reads such bytes).
pub fn bcd_to_bin(v: u8) -> Option<u8> {
    let (hi, lo) = (v >> 4, v & 0xf);
    (hi <= 9 && lo <= 9).then_some(hi * 10 + lo)
}

/// A number below 100 to two packed-BCD digits.
pub fn bin_to_bcd(v: u8) -> u8 {
    debug_assert!(v < 100);
    (v / 10) << 4 | (v % 10)
}
