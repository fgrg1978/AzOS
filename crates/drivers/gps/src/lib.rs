// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! GPS driver — NMEA parser over UART (Phase I2).
//!
//! Provides a GPS position type and NMEA sentence parser ($GPGGA, $GPRMC).
//! In QEMU, returns simulated position data (no real UART1).
//! On real hardware (VF2/K1), reads from a secondary UART.
//!
//! All parsing is integer-only (no `f32`, no `libm`).
//!
//! # Channels
//!
//! - `CH_GPS` — latest GPS fix (published by sensor task)

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use azos_channel::Channel;

// ── Channel ─────────────────────────────────────────────────────────────────

/// Channel for GPS position fixes.
pub static CH_GPS: Channel<GpsPosition> = Channel::new(GpsPosition::new());

// ── GPS position type ───────────────────────────────────────────────────────

/// GPS position fix.
#[derive(Clone, Copy)]
pub struct GpsPosition {
    /// Latitude in degrees × 10^7 (e.g. 48_1173000 = 48.1173000°).
    pub lat_deg7: i32,
    /// Longitude in degrees × 10^7 (e.g. 11_6324000 = 11.6324000°).
    pub lon_deg7: i32,
    /// Altitude above MSL in millimetres.
    pub alt_mm: i32,
    /// Horizontal dilution of precision × 100 (e.g. 120 = HDOP 1.20).
    pub hdop: u16,
    /// Fix quality: 0=none, 1=GPS, 2=DGPS, 4=RTK fixed, 5=RTK float.
    pub fix: u8,
    /// Number of satellites in use.
    pub sats: u8,
    /// Speed over ground in cm/s.
    pub speed_cms: u16,
    /// Course over ground in centi-degrees (0..36000).
    pub course_cdeg: u16,
}

impl GpsPosition {
    pub const fn new() -> Self {
        GpsPosition {
            lat_deg7: 0,
            lon_deg7: 0,
            alt_mm: 0,
            hdop: 9999,
            fix: 0,
            sats: 0,
            speed_cms: 0,
            course_cdeg: 0,
        }
    }

    /// Returns true if there is a valid fix (fix > 0).
    pub const fn has_fix(&self) -> bool {
        self.fix > 0
    }
}

// ── GPS state ───────────────────────────────────────────────────────────────

static GPS_UART_BUS: AtomicU8 = AtomicU8::new(0);
static GPS_READY: AtomicBool = AtomicBool::new(false);

/// NMEA sentence accumulator (single static buffer).
const NMEA_BUF_CAP: usize = 128;
static mut NMEA_BUF: [u8; NMEA_BUF_CAP] = [0u8; NMEA_BUF_CAP];
static mut NMEA_POS: usize = 0;

/// Last parsed position (updated by gps_poll).
static mut LAST_POS: GpsPosition = GpsPosition::new();

/// Timebase counter (ticks) when the sentence behind `LAST_POS` completed:
/// read at the line end that made [`gps_feed_byte`] parse it, and stored
/// after the position, so a reader that loads it first never ages a fix
/// younger than the fields it then reads. 0 = no sentence parsed yet.
static LAST_ACQ: AtomicU64 = AtomicU64::new(0);

// ── Public API ──────────────────────────────────────────────────────────────

/// Initialize GPS receiver on the given UART bus.
///
/// With `simulated-fix` (the kernel's `qemu` feature) a fixed position is
/// loaded and reported as a fix at once. Without it nothing is loaded:
/// [`gps_read`] returns `None` until a sentence parses. The geofence reads
/// this fix, so a board must never judge its fence against a position nobody
/// measured.
pub fn gps_init(uart_bus: u8, _baud: u32) -> bool {
    GPS_UART_BUS.store(uart_bus, Ordering::Relaxed);

    #[cfg(feature = "simulated-fix")]
    {
        // Simulated: Munich, Germany — lat 48.1351, lon 11.5820, alt 519m.
        unsafe {
            LAST_POS = GpsPosition {
                lat_deg7:    481_351_000,
                lon_deg7:    115_820_000,
                alt_mm:      519_000,
                hdop:        110,          // 1.10
                fix:         1,            // GPS fix
                sats:        9,
                speed_cms:   0,
                course_cdeg: 0,
            };
        }
        GPS_READY.store(true, Ordering::Release);
        azos_drv_sys::kprintln!("[GPS] Initialized on UART bus {} (simulated)", uart_bus);
    }
    #[cfg(not(feature = "simulated-fix"))]
    azos_drv_sys::kprintln!("[GPS] Initialized on UART bus {} (no position until a sentence parses)", uart_bus);
    true
}

/// Poll for new NMEA data and update position.
///
/// In QEMU: returns the simulated position (no real UART to poll).
/// On real hardware: would read bytes from UART, accumulate NMEA sentences,
/// parse complete sentences, and update the position.
pub fn gps_read() -> Option<GpsPosition> {
    gps_read_stamped().map(|s| s.pos)
}

/// One fix and when it was acquired.
#[derive(Clone, Copy)]
pub struct StampedFix {
    pub pos: GpsPosition,
    /// Timebase ticks when the receiver's sentence carrying it completed; 0 =
    /// no sentence has been parsed (a fix nobody measured).
    pub acq: u64,
    /// The fix comes from `simulated-fix`, not from a receiver.
    pub synthetic: bool,
}

/// [`gps_read`] with the fix's acquisition time.
///
/// **A receiver that goes silent leaves its last fix here forever**, and
/// [`gps_read`] keeps returning it. Before this stamp the kernel's AHRS task
/// re-published that fix every 100 ms with the time of the re-publication, so
/// the geofence's two-second staleness bound never saw it age. The stamp is
/// the parse, so it ages from the receiver's last sentence.
///
/// With `simulated-fix` (QEMU) the simulated receiver stands in for a live
/// one: every read is a fresh emission, stamped now and marked synthetic.
pub fn gps_read_stamped() -> Option<StampedFix> {
    if !GPS_READY.load(Ordering::Acquire) {
        return None;
    }
    #[cfg(feature = "simulated-fix")]
    let (acq, synthetic) = (azos_drv_sys::timebase::now(), true);
    #[cfg(not(feature = "simulated-fix"))]
    let (acq, synthetic) = (LAST_ACQ.load(Ordering::Acquire), false);
    Some(StampedFix { pos: unsafe { LAST_POS }, acq, synthetic })
}

/// Print GPS status info.
pub fn gps_info() {
    if !GPS_READY.load(Ordering::Acquire) {
        azos_drv_sys::kconsoleln!("[GPS] Not initialized");
        return;
    }
    let pos = unsafe { LAST_POS };
    let fix_str = match pos.fix {
        0 => "No fix",
        1 => "GPS",
        2 => "DGPS",
        4 => "RTK fixed",
        5 => "RTK float",
        _ => "Unknown",
    };
    azos_drv_sys::kconsoleln!("[GPS] Fix: {} ({} sats, HDOP {}.{:02})",
        fix_str, pos.sats, pos.hdop / 100, pos.hdop % 100);

    // Print lat/lon as degrees with 7 decimal places.
    let (lat_sign, lat_abs) = if pos.lat_deg7 < 0 { ("S", (-pos.lat_deg7) as u32) } else { ("N", pos.lat_deg7 as u32) };
    let (lon_sign, lon_abs) = if pos.lon_deg7 < 0 { ("W", (-pos.lon_deg7) as u32) } else { ("E", pos.lon_deg7 as u32) };
    azos_drv_sys::kconsoleln!("[GPS] Lat: {}{}.{:07}  Lon: {}{}.{:07}",
        lat_sign, lat_abs / 10_000_000, lat_abs % 10_000_000,
        lon_sign, lon_abs / 10_000_000, lon_abs % 10_000_000);

    let alt_sign = if pos.alt_mm < 0 { "-" } else { "" };
    let alt_abs = pos.alt_mm.unsigned_abs();
    azos_drv_sys::kconsoleln!("[GPS] Alt: {}{}.{:03} m  Speed: {}.{:02} m/s  Course: {}.{:02} deg",
        alt_sign, alt_abs / 1000, alt_abs % 1000,
        pos.speed_cms / 100, pos.speed_cms % 100,
        pos.course_cdeg / 100, pos.course_cdeg % 100);
}

// ── NMEA parser ─────────────────────────────────────────────────────────────

/// Feed a byte into the NMEA accumulator.  When a complete sentence is
/// received (terminated by '\n'), it is parsed and the position updated.
///
/// Call this for each byte received from the GPS UART.
/// Returns `true` if a sentence was successfully parsed this call.
pub fn gps_feed_byte(b: u8) -> bool {
    unsafe {
        match b {
            b'$' => {
                // Start of a new sentence.
                NMEA_POS = 0;
                NMEA_BUF[0] = b;
                NMEA_POS = 1;
                false
            }
            b'\n' | b'\r' => {
                if NMEA_POS > 6 {
                    let len = NMEA_POS;
                    NMEA_POS = 0;
                    parse_sentence(&NMEA_BUF[..len])
                } else {
                    NMEA_POS = 0;
                    false
                }
            }
            _ => {
                if NMEA_POS < NMEA_BUF_CAP {
                    NMEA_BUF[NMEA_POS] = b;
                    NMEA_POS += 1;
                }
                false
            }
        }
    }
}

/// Parse a complete NMEA sentence (without trailing CR/LF).
/// Dispatches to GGA or RMC parser.
fn parse_sentence(sentence: &[u8]) -> bool {
    // Validate checksum: everything between '$' and '*' XOR'd.
    if !validate_checksum(sentence) {
        return false;
    }

    // Strip checksum (*XX) for field parsing.
    let data = strip_checksum(sentence);

    // Check sentence type (bytes 3..6 after '$GP' or '$GN').
    if data.len() < 7 { return false; }

    let parsed = if field_match(&data[3..], b"GGA,") {
        parse_gga(data)
    } else if field_match(&data[3..], b"RMC,") {
        parse_rmc(data)
    } else {
        false
    };
    // A receiver that has produced a sentence makes `gps_read` answer; without
    // `simulated-fix` nothing else does.
    if parsed {
        // `max(1)`: 0 is "never parsed".
        LAST_ACQ.store(azos_drv_sys::timebase::now().max(1), Ordering::Release);
        GPS_READY.store(true, Ordering::Release);
    }
    parsed
}

/// Parse $GPGGA (or $GNGGA) sentence.
///
/// Format: $GPGGA,hhmmss.ss,lat,N/S,lon,E/W,fix,sats,hdop,alt,M,geoid,M,age,ref*cs
fn parse_gga(data: &[u8]) -> bool {
    let fields = split_fields(data);
    if fields.len() < 10 { return false; }

    // Field 6: fix quality
    let fix = parse_u32_field(fields[6]).unwrap_or(0) as u8;

    // Field 7: number of satellites
    let sats = parse_u32_field(fields[7]).unwrap_or(0) as u8;

    // Field 8: HDOP (e.g. "1.10" → 110)
    let hdop = parse_decimal_field(fields[8], 2).unwrap_or(9999) as u16;

    // Field 9: altitude (e.g. "519.0" → 519000 mm)
    let alt_mm = parse_decimal_field(fields[9], 3).unwrap_or(0) as i32;

    // Field 2,3: latitude (e.g. "4808.1062,N" → deg7)
    let lat_deg7 = parse_nmea_coord(fields[2], fields[3]);

    // Field 4,5: longitude (e.g. "01134.9200,E" → deg7)
    let lon_deg7 = parse_nmea_coord(fields[4], fields[5]);

    unsafe {
        LAST_POS.fix = fix;
        LAST_POS.sats = sats;
        LAST_POS.hdop = hdop;
        LAST_POS.alt_mm = alt_mm;
        if fix > 0 {
            LAST_POS.lat_deg7 = lat_deg7;
            LAST_POS.lon_deg7 = lon_deg7;
        }
    }
    true
}

/// Parse $GPRMC (or $GNRMC) sentence.
///
/// Format: $GPRMC,hhmmss.ss,status,lat,N/S,lon,E/W,speed_knots,course,ddmmyy,...*cs
fn parse_rmc(data: &[u8]) -> bool {
    let fields = split_fields(data);
    if fields.len() < 8 { return false; }

    // Field 2: status (A=active, V=void)
    if fields[2].is_empty() || fields[2][0] != b'A' {
        return false;
    }

    // Field 3,4: latitude
    let lat_deg7 = parse_nmea_coord(fields[3], fields[4]);

    // Field 5,6: longitude
    let lon_deg7 = parse_nmea_coord(fields[5], fields[6]);

    // Field 7: speed over ground in knots (e.g. "0.05")
    // Convert knots → cm/s: 1 knot = 51.444 cm/s ≈ 51444/1000
    // Parse as milli-knots first, then convert.
    let speed_mknots = parse_decimal_field(fields[7], 3).unwrap_or(0) as u32;
    let speed_cms = ((speed_mknots as u64 * 51444) / 1_000_000) as u16;

    // Field 8: course over ground in degrees (e.g. "054.7")
    let course_cdeg = parse_decimal_field(if fields.len() > 8 { fields[8] } else { b"" }, 2)
        .unwrap_or(0) as u16;

    unsafe {
        LAST_POS.lat_deg7 = lat_deg7;
        LAST_POS.lon_deg7 = lon_deg7;
        LAST_POS.speed_cms = speed_cms;
        LAST_POS.course_cdeg = course_cdeg;
    }
    true
}

// ── NMEA helpers ────────────────────────────────────────────────────────────

/// Validate NMEA checksum: XOR of all bytes between '$' and '*'.
fn validate_checksum(sentence: &[u8]) -> bool {
    if sentence.is_empty() || sentence[0] != b'$' { return false; }

    // Find '*' marker.
    let mut star_pos = 0;
    for i in 1..sentence.len() {
        if sentence[i] == b'*' {
            star_pos = i;
            break;
        }
    }
    if star_pos == 0 || star_pos + 2 >= sentence.len() {
        // Safety-critical: an NMEA sentence without a valid checksum is not
        // trusted (spoofed/garbage frames must not reach the RTL/failsafe).
        return false;
    }

    // Compute XOR checksum.
    let mut cksum: u8 = 0;
    for &b in &sentence[1..star_pos] {
        cksum ^= b;
    }

    // Parse hex checksum after '*'.
    let expected = hex_byte(sentence[star_pos + 1], sentence[star_pos + 2]);
    cksum == expected
}

/// Strip checksum (*XX) from sentence end, returning the data portion.
fn strip_checksum(sentence: &[u8]) -> &[u8] {
    for i in (0..sentence.len()).rev() {
        if sentence[i] == b'*' {
            return &sentence[..i];
        }
    }
    sentence
}

/// Split NMEA sentence into comma-separated fields.
/// Returns up to 20 fields.
const MAX_FIELDS: usize = 20;
fn split_fields(data: &[u8]) -> [&[u8]; MAX_FIELDS] {
    let mut fields: [&[u8]; MAX_FIELDS] = [b""; MAX_FIELDS];
    let mut count = 0;
    let mut start = 0;

    for i in 0..data.len() {
        if data[i] == b',' {
            if count < MAX_FIELDS {
                fields[count] = &data[start..i];
                count += 1;
            }
            start = i + 1;
        }
    }
    // Last field.
    if count < MAX_FIELDS && start <= data.len() {
        fields[count] = &data[start..];
    }
    fields
}

/// Parse NMEA coordinate "DDMM.MMMM" with hemisphere "N"/"S"/"E"/"W"
/// into degrees × 10^7.
///
/// Example: "4808.1062", "N" → 48_135_103 (48.1351033°)
/// Formula: degrees + minutes/60, all in deg7.
fn parse_nmea_coord(coord: &[u8], hemi: &[u8]) -> i32 {
    if coord.is_empty() { return 0; }

    // Find the decimal point.
    let mut dot_pos = 0;
    for i in 0..coord.len() {
        if coord[i] == b'.' {
            dot_pos = i;
            break;
        }
    }
    if dot_pos < 2 { return 0; }

    // Degrees: everything before the last 2 digits before dot.
    let deg_end = dot_pos - 2;
    let degrees = parse_u32_slice(&coord[..deg_end]).unwrap_or(0);

    // Minutes: DD.DDDD (the 2 digits before dot + fraction).
    // Parse as integer with 7 decimal places for precision.
    let min_int = parse_u32_slice(&coord[deg_end..dot_pos]).unwrap_or(0);
    let min_frac_str = if dot_pos + 1 < coord.len() { &coord[dot_pos + 1..] } else { b"" };

    // Build minutes as fixed-point with 7 fractional digits.
    // min_int.min_frac → multiply to get 7-digit fraction.
    let mut min_frac: u32 = 0;
    let mut mul = 1_000_000; // 7 digits for degree fraction
    for &b in min_frac_str {
        if b < b'0' || b > b'9' { break; }
        if mul > 0 {
            min_frac += (b - b'0') as u32 * mul;
            mul /= 10;
        }
    }
    // Total minutes in deg7: min_int * 10^7 + min_frac
    // (min_frac is already scaled to 7 decimal digits by the loop above,
    // matching min_int's 10^7 scale — no extra factor needed.)
    let min_total = min_int as u64 * 10_000_000 + min_frac as u64;
    let min_deg7 = (min_total / 60) as i32;

    let deg7 = degrees as i32 * 10_000_000 + min_deg7;

    // Apply hemisphere.
    if !hemi.is_empty() && (hemi[0] == b'S' || hemi[0] == b'W') {
        -deg7
    } else {
        deg7
    }
}

/// Parse unsigned integer from byte slice.
fn parse_u32_slice(s: &[u8]) -> Option<u32> {
    if s.is_empty() { return None; }
    let mut val: u32 = 0;
    for &b in s {
        if b < b'0' || b > b'9' { return None; }
        val = val * 10 + (b - b'0') as u32;
    }
    Some(val)
}

/// Parse unsigned integer from a comma-separated field.
fn parse_u32_field(field: &[u8]) -> Option<u32> {
    if field.is_empty() { return None; }
    parse_u32_slice(field)
}

/// Parse a decimal number with `frac_digits` fractional digits.
///
/// E.g. "1.10" with frac_digits=2 → 110; "519.0" with frac_digits=3 → 519000.
fn parse_decimal_field(field: &[u8], frac_digits: u32) -> Option<i32> {
    if field.is_empty() { return None; }

    let negative = field[0] == b'-';
    let start = if negative { 1 } else { 0 };

    // Find dot.
    let mut dot_pos = field.len();
    for i in start..field.len() {
        if field[i] == b'.' {
            dot_pos = i;
            break;
        }
    }

    // Integer part.
    let int_part = parse_u32_slice(&field[start..dot_pos]).unwrap_or(0) as i32;

    // Fractional part — pad/truncate to frac_digits.
    let frac_start = if dot_pos + 1 < field.len() { dot_pos + 1 } else { field.len() };
    let frac_bytes = &field[frac_start..];
    let mut frac_val: i32 = 0;
    let mut remaining = frac_digits;
    for &b in frac_bytes {
        if remaining == 0 { break; }
        if b < b'0' || b > b'9' { break; }
        frac_val = frac_val * 10 + (b - b'0') as i32;
        remaining -= 1;
    }
    // Pad remaining digits with zeros.
    for _ in 0..remaining {
        frac_val *= 10;
    }

    let mut multiplier: i32 = 1;
    for _ in 0..frac_digits {
        multiplier *= 10;
    }

    let result = int_part * multiplier + frac_val;
    Some(if negative { -result } else { result })
}

/// Check if slice starts with pattern.
fn field_match(data: &[u8], pattern: &[u8]) -> bool {
    if data.len() < pattern.len() { return false; }
    data[..pattern.len()] == *pattern
}

/// Parse two hex ASCII chars into a byte.
fn hex_byte(hi: u8, lo: u8) -> u8 {
    (hex_digit(hi) << 4) | hex_digit(lo)
}

fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'A'..=b'F' => c - b'A' + 10,
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    }
}
