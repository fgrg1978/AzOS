// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Seconds since the epoch as a calendar date (UTC, proleptic Gregorian).

use crate::host::{Error, Host};
use crate::util::{put, put_padded, put_u64};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    pub year: u64,
    pub month: u64,
    pub day: u64,
    pub hour: u64,
    pub min: u64,
    pub sec: u64,
    /// 0 is Sunday.
    pub wday: u64,
    /// Day of the year, 1 for January 1.
    pub yday: u64,
}

pub fn civil(secs: u64) -> Civil {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    // Days since 0000-03-01 (Hinnant's civil_from_days).
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + (month <= 2) as u64;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    const CUM: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let yday = CUM[month as usize - 1] + day + (leap && month > 2) as u64;
    Civil { year, month, day, hour: rem / 3_600, min: rem % 3_600 / 60, sec: rem % 60, wday: (days + 4) % 7, yday }
}

const DAYS: [&[u8]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const MONTHS: [&[u8]; 12] =
    [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

/// `YYYY-MM-DD HH:MM:SS`.
pub fn put_datetime<H: Host>(h: &mut H, secs: u64) -> Result<(), Error> {
    format(h, b"%F %T", secs)
}

/// `secs` through a `date` format: `%Y %m %d %H %M %S %s %F %T %a %b %j %Z %%`.
/// Another conversion is written as it stands.
pub fn format<H: Host>(h: &mut H, fmt: &[u8], secs: u64) -> Result<(), Error> {
    let c = civil(secs);
    let mut i = 0;
    while i < fmt.len() {
        if fmt[i] != b'%' || i + 1 == fmt.len() {
            let end = fmt[i + 1..].iter().position(|&b| b == b'%').map_or(fmt.len(), |p| i + 1 + p);
            put(h, &fmt[i..end])?;
            i = end;
            continue;
        }
        match fmt[i + 1] {
            b'Y' => put_padded(h, c.year, 4)?,
            b'm' => put_padded(h, c.month, 2)?,
            b'd' => put_padded(h, c.day, 2)?,
            b'H' => put_padded(h, c.hour, 2)?,
            b'M' => put_padded(h, c.min, 2)?,
            b'S' => put_padded(h, c.sec, 2)?,
            b's' => put_u64(h, secs)?,
            b'j' => put_padded(h, c.yday, 3)?,
            b'a' => put(h, DAYS[c.wday as usize])?,
            b'b' => put(h, MONTHS[c.month as usize - 1])?,
            b'F' => {
                put_padded(h, c.year, 4)?;
                put(h, b"-")?;
                put_padded(h, c.month, 2)?;
                put(h, b"-")?;
                put_padded(h, c.day, 2)?;
            }
            b'T' => {
                put_padded(h, c.hour, 2)?;
                put(h, b":")?;
                put_padded(h, c.min, 2)?;
                put(h, b":")?;
                put_padded(h, c.sec, 2)?;
            }
            b'Z' => put(h, b"UTC")?,
            b'%' => put(h, b"%")?,
            _ => put(h, &fmt[i..i + 2])?,
        }
        i += 2;
    }
    Ok(())
}
