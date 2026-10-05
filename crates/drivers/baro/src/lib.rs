// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! Barometer driver — BMP280 over I2C.
//!
//! Provides high-level access to a simulated (QEMU) or real BMP280
//! pressure/temperature sensor.  Uses the I2C driver from `azos_drv_bus`.
//!
//! Phase G1.

use core::sync::atomic::{AtomicU8, AtomicBool, Ordering};
use azos_drv_bus::i2c;
use azos_sync::SpinLock;

pub const BMP280_ADDR: u8 = 0x76;

// BMP280 register map
const REG_CHIP_ID:    u8 = 0xD0;
const REG_CTRL_MEAS:  u8 = 0xF4;
const REG_CONFIG:     u8 = 0xF5;
const REG_PRESS_MSB:  u8 = 0xF7; // 6 bytes: pressure(3) + temperature(3)
const REG_CALIB_00:   u8 = 0x88; // 26 bytes of calibration data
const REG_STATUS:     u8 = 0xF3; // bit 3 = "measuring", bit 0 = "im_update"

/// Bounded upper bound on STATUS-register polls while waiting for a
/// forced-mode conversion to finish (worst case ~40ms at osrs_t=x2 +
/// osrs_p=x16). This is a generous ceiling, not a timed guarantee — if
/// the sensor never clears the "measuring" bit (disconnected, wedged),
/// we give up and let the caller's existing bad-sample handling deal
/// with the stale/garbage read that follows.
const BARO_MEASURING_POLL_MAX_ITERS: u32 = 1000;

/// Barometer reading with calibrated values.
#[derive(Clone, Copy)]
pub struct BaroData {
    /// Pressure in Pascals (e.g. 101325 = 1013.25 hPa = standard atmosphere).
    pub pressure_pa: u32,
    /// Temperature in centi-degrees Celsius (e.g. 2530 = 25.30 C).
    pub temp_cdeg:   i32,
}

/// Calibration coefficients from BMP280 NVM (trimming parameters).
#[derive(Clone, Copy)]
struct CalibData {
    dig_t1: u16,
    dig_t2: i16,
    dig_t3: i16,
    dig_p1: u16,
    dig_p2: i16,
    dig_p3: i16,
    dig_p4: i16,
    dig_p5: i16,
    dig_p6: i16,
    dig_p7: i16,
    dig_p8: i16,
    dig_p9: i16,
}

static BARO_BUS:   AtomicU8   = AtomicU8::new(0);
static BARO_ADDR:  AtomicU8   = AtomicU8::new(BMP280_ADDR);
static BARO_READY: AtomicBool = AtomicBool::new(false);
static BARO_CALIB: SpinLock<CalibData> = SpinLock::new(CalibData {
    dig_t1: 0, dig_t2: 0, dig_t3: 0,
    dig_p1: 0, dig_p2: 0, dig_p3: 0, dig_p4: 0, dig_p5: 0,
    dig_p6: 0, dig_p7: 0, dig_p8: 0, dig_p9: 0,
});

/// Initialize the BMP280 on the given I2C bus/address.
///
/// Verifies chip_id (0x58), reads calibration data, configures forced mode.
/// Returns `true` if initialization succeeded.
pub fn baro_init(bus: u8, addr: u8) -> bool {
    // Check chip ID
    let mut id = [0u8; 1];
    if i2c::i2c_read(bus, addr, REG_CHIP_ID, &mut id) < 1 {
        azos_drv_sys::kwarn!("[BARO] BMP280 @ bus={} addr=0x{:02x} — not found", bus, addr);
        return false;
    }
    // BMP280 chip_id = 0x58, BME280 = 0x60. Accept both.
    if id[0] != 0x58 && id[0] != 0x60 {
        azos_drv_sys::kwarn!("[BARO] chip_id mismatch: expected 0x58, got 0x{:02x}", id[0]);
        return false;
    }

    // Read calibration data (26 bytes from 0x88)
    let mut cal = [0u8; 26];
    if i2c::i2c_read(bus, addr, REG_CALIB_00, &mut cal) < 26 {
        azos_drv_sys::kerr!("[BARO] Failed to read calibration data");
        return false;
    }

    let u16le = |i: usize| -> u16 { cal[i] as u16 | (cal[i + 1] as u16) << 8 };
    let i16le = |i: usize| -> i16 { u16le(i) as i16 };

    {
        let mut c = BARO_CALIB.lock();
        c.dig_t1 = u16le(0);
        c.dig_t2 = i16le(2);
        c.dig_t3 = i16le(4);
        c.dig_p1 = u16le(6);
        c.dig_p2 = i16le(8);
        c.dig_p3 = i16le(10);
        c.dig_p4 = i16le(12);
        c.dig_p5 = i16le(14);
        c.dig_p6 = i16le(16);
        c.dig_p7 = i16le(18);
        c.dig_p8 = i16le(20);
        c.dig_p9 = i16le(22);
    }

    // Configure: osrs_t=x2 (010), osrs_p=x16 (101), mode=forced (01)
    // ctrl_meas = 0b010_101_01 = 0x55 (forced mode, triggers one measurement)
    if i2c::i2c_write(bus, addr, &[REG_CONFIG, 0x00]) < 0 {   // no filter, no standby
        azos_drv_sys::kerr!("[BARO] Failed to write CONFIG register");
        return false;
    }
    if i2c::i2c_write(bus, addr, &[REG_CTRL_MEAS, 0x55]) < 0 {
        azos_drv_sys::kerr!("[BARO] Failed to write CTRL_MEAS register");
        return false;
    }

    BARO_BUS.store(bus, Ordering::Relaxed);
    BARO_ADDR.store(addr, Ordering::Relaxed);
    BARO_READY.store(true, Ordering::Release);

    azos_drv_sys::kprintln!("[BARO] BMP280 @ bus={} addr=0x{:02x} — initialized (id=0x{:02x})",
        bus, addr, id[0]);
    true
}

/// Read pressure and temperature with BMP280 compensation formulas.
///
/// Returns calibrated pressure (Pa) and temperature (centi-degrees C).
/// Uses the integer compensation algorithm from the BMP280 datasheet.
pub fn baro_read() -> Option<BaroData> {
    baro_read_stamped().map(|(d, _)| d)
}

/// [`baro_read`] and its acquisition time: the timebase counter
/// (`timebase::now()`, ticks) read right after the data-register burst
/// returned, in the driver, so a consumer ages the value from the read and
/// not from its own delivery.
pub fn baro_read_stamped() -> Option<(BaroData, u64)> {
    let bus   = BARO_BUS.load(Ordering::Relaxed);
    let addr  = BARO_ADDR.load(Ordering::Relaxed);
    let ready = BARO_READY.load(Ordering::Acquire);
    if !ready { return None; }

    // Trigger a forced-mode measurement
    i2c::i2c_write(bus, addr, &[REG_CTRL_MEAS, 0x55]);

    // Wait for the conversion to finish (STATUS bit 3 = "measuring").
    // Bounded poll — if the sensor never clears the bit (disconnected,
    // wedged), give up rather than spinning forever; the stale/garbage
    // read that follows is caught by the caller same as any other bad
    // sample.
    let mut status = [0u8; 1];
    for _ in 0..BARO_MEASURING_POLL_MAX_ITERS {
        if i2c::i2c_read(bus, addr, REG_STATUS, &mut status) < 1 { break; }
        if status[0] & 0x08 == 0 { break; } // bit 3 clear = conversion done
    }

    // Read 6 bytes: pressure MSB/LSB/XLSB + temperature MSB/LSB/XLSB
    let mut raw = [0u8; 6];
    if i2c::i2c_read(bus, addr, REG_PRESS_MSB, &mut raw) < 6 {
        return None;
    }
    let acq = azos_drv_sys::timebase::now();

    let adc_p = ((raw[0] as i32) << 12) | ((raw[1] as i32) << 4) | ((raw[2] as i32) >> 4);
    let adc_t = ((raw[3] as i32) << 12) | ((raw[4] as i32) << 4) | ((raw[5] as i32) >> 4);

    let cal = *BARO_CALIB.lock();

    // Temperature compensation (BMP280 datasheet Section 4.2.3).
    // Computed in i64: with a marginal/corrupt calibration block the i32
    // products (diff*dig_t2, diff*diff) can overflow and abort the kernel.
    let var1 = ((((adc_t >> 3) as i64 - ((cal.dig_t1 as i64) << 1))
                 * (cal.dig_t2 as i64)) >> 11) as i32;
    let dt = (adc_t >> 4) as i64 - (cal.dig_t1 as i64);
    let var2 = ((((dt * dt) >> 12) * (cal.dig_t3 as i64)) >> 14) as i32;
    let t_fine = var1 + var2;
    let temp_cdeg = ((t_fine * 5 + 128) >> 8) as i32; // in 0.01 C

    // Pressure compensation (BMP280 datasheet Section 4.2.3)
    let mut var1_p = (t_fine as i64) - 128000;
    let mut var2_p = var1_p * var1_p * (cal.dig_p6 as i64);
    var2_p = var2_p + ((var1_p * (cal.dig_p5 as i64)) << 17);
    var2_p = var2_p + ((cal.dig_p4 as i64) << 35);
    var1_p = ((var1_p * var1_p * (cal.dig_p3 as i64)) >> 8) +
             ((var1_p * (cal.dig_p2 as i64)) << 12);
    var1_p = ((1i64 << 47) + var1_p) * (cal.dig_p1 as i64) >> 33;

    let pressure_pa = if var1_p == 0 {
        0u32
    } else {
        let mut p: i64 = 1048576 - adc_p as i64;
        p = (((p << 31) - var2_p) * 3125) / var1_p;
        let v1 = ((cal.dig_p9 as i64) * (p >> 13) * (p >> 13)) >> 25;
        let v2 = ((cal.dig_p8 as i64) * p) >> 19;
        let p_with_p7 = ((p + v1 + v2) >> 8) + ((cal.dig_p7 as i64) << 4);
        // Clamp before the u32 cast: a negative compensated pressure would
        // wrap to a ~16.7 MPa reading and publish a grotesque altitude.
        let p_clamped = if p_with_p7 < 0 { 0 } else { p_with_p7 };
        (p_clamped as u32) / 256 // Pa with Q24.8 → integer Pa
    };

    Some((BaroData { pressure_pa, temp_cdeg }, acq))
}

/// Print barometer status info.
pub fn baro_info() {
    let bus   = BARO_BUS.load(Ordering::Relaxed);
    let addr  = BARO_ADDR.load(Ordering::Relaxed);
    let ready = BARO_READY.load(Ordering::Acquire);
    if ready {
        azos_drv_sys::kconsoleln!("[BARO] BMP280 @ bus={} addr=0x{:02x} — ready", bus, addr);
    } else {
        azos_drv_sys::kconsoleln!("[BARO] Not initialized");
    }
}
