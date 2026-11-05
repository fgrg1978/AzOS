// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The BMP280 pressure and temperature sensor: the chip logic over an
//! [`I2cCall`] bound to the device. No statics, no clock, no kernel function;
//! the host owns the bus, the acquisition stamp and the calibration it keeps
//! between reads.

use azos_devif::i2c::{read_regs, write_bytes};
use azos_devif::I2cCall;

/// The chip's default 7-bit address (SDO low).
pub const BMP280_ADDR: u8 = 0x76;

const REG_CHIP_ID: u8 = 0xD0;
const REG_CTRL_MEAS: u8 = 0xF4;
const REG_CONFIG: u8 = 0xF5;
const REG_PRESS_MSB: u8 = 0xF7; // 6 bytes: pressure(3) + temperature(3)
const REG_CALIB_00: u8 = 0x88; // 26 bytes of calibration data
const REG_STATUS: u8 = 0xF3; // bit 3 = "measuring", bit 0 = "im_update"

/// osrs_t x2, osrs_p x16, forced mode: triggers one measurement.
const CTRL_MEAS_FORCED: u8 = 0x55;

/// Bounded upper bound on STATUS-register polls while waiting for a
/// forced-mode conversion to finish (worst case ~40ms at osrs_t=x2 +
/// osrs_p=x16). This is a generous ceiling, not a timed guarantee — if
/// the sensor never clears the "measuring" bit (disconnected, wedged),
/// we give up and let the caller's existing bad-sample handling deal
/// with the stale/garbage read that follows.
pub const MEASURING_POLL_MAX_ITERS: u32 = 1000;

/// Bytes of the data burst.
pub const BURST_LEN: usize = 6;

/// Barometer reading with calibrated values.
#[derive(Clone, Copy)]
pub struct BaroData {
    /// Pressure in Pascals (e.g. 101325 = 1013.25 hPa = standard atmosphere).
    pub pressure_pa: u32,
    /// Temperature in centi-degrees Celsius (e.g. 2530 = 25.30 C).
    pub temp_cdeg: i32,
}

/// Calibration coefficients from the chip's NVM (trimming parameters).
#[derive(Clone, Copy)]
pub struct Calib {
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

impl Calib {
    /// Before the chip's own: every coefficient zero.
    pub const ZERO: Calib = Calib {
        dig_t1: 0, dig_t2: 0, dig_t3: 0,
        dig_p1: 0, dig_p2: 0, dig_p3: 0, dig_p4: 0, dig_p5: 0,
        dig_p6: 0, dig_p7: 0, dig_p8: 0, dig_p9: 0,
    };

    fn from_nvm(cal: &[u8; 26]) -> Calib {
        let u16le = |i: usize| -> u16 { cal[i] as u16 | (cal[i + 1] as u16) << 8 };
        let i16le = |i: usize| -> i16 { u16le(i) as i16 };
        Calib {
            dig_t1: u16le(0),
            dig_t2: i16le(2),
            dig_t3: i16le(4),
            dig_p1: u16le(6),
            dig_p2: i16le(8),
            dig_p3: i16le(10),
            dig_p4: i16le(12),
            dig_p5: i16le(14),
            dig_p6: i16le(16),
            dig_p7: i16le(18),
            dig_p8: i16le(20),
            dig_p9: i16le(22),
        }
    }
}

/// Why [`Bmp280::probe`] did not leave the chip configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    /// The chip id could not be read.
    NotFound,
    /// The chip id names another part.
    WrongId(u8),
    /// The calibration block could not be read.
    Calibration,
    /// A configuration register refused its write.
    Write(&'static str),
}

pub struct Bmp280<B: I2cCall> {
    bus: B,
    cal: Calib,
}

impl<B: I2cCall> Bmp280<B> {
    /// A chip whose calibration the host already holds.
    pub fn with_calibration(bus: B, cal: Calib) -> Self {
        Bmp280 { bus, cal }
    }

    /// Verify the chip id (BMP280 0x58 or BME280 0x60), read the calibration,
    /// configure no filter and forced mode. The chip id comes back with the
    /// chip.
    pub fn probe(mut bus: B) -> Result<(Self, u8), InitError> {
        let mut id = [0u8; 1];
        read_regs(&mut bus, REG_CHIP_ID, &mut id).map_err(|_| InitError::NotFound)?;
        if id[0] != 0x58 && id[0] != 0x60 {
            return Err(InitError::WrongId(id[0]));
        }
        let mut nvm = [0u8; 26];
        read_regs(&mut bus, REG_CALIB_00, &mut nvm).map_err(|_| InitError::Calibration)?;
        write_bytes(&mut bus, &[REG_CONFIG, 0x00]).map_err(|_| InitError::Write("CONFIG"))?;
        write_bytes(&mut bus, &[REG_CTRL_MEAS, CTRL_MEAS_FORCED]).map_err(|_| InitError::Write("CTRL_MEAS"))?;
        Ok((Bmp280 { bus, cal: Calib::from_nvm(&nvm) }, id[0]))
    }

    /// The calibration the chip gave, for the host to keep.
    pub fn calibration(&self) -> Calib {
        self.cal
    }

    /// Trigger a forced-mode measurement, wait (bounded) for it, and read the
    /// data burst. The outcome code of the failed transfer, never a burst the
    /// chip did not deliver: a trigger that did not land would leave the
    /// previous conversion in the data registers.
    pub fn read_raw(&mut self) -> Result<[u8; BURST_LEN], u32> {
        write_bytes(&mut self.bus, &[REG_CTRL_MEAS, CTRL_MEAS_FORCED])?;
        let mut status = [0u8; 1];
        for _ in 0..MEASURING_POLL_MAX_ITERS {
            read_regs(&mut self.bus, REG_STATUS, &mut status)?;
            if status[0] & 0x08 == 0 {
                break; // bit 3 clear = conversion done
            }
        }
        let mut raw = [0u8; BURST_LEN];
        read_regs(&mut self.bus, REG_PRESS_MSB, &mut raw)?;
        Ok(raw)
    }
}

/// The burst through the chip's compensation formulas, the integer arithmetic
/// of the BMP280 datasheet (section 4.2.3).
pub fn compensate(cal: &Calib, raw: &[u8; BURST_LEN]) -> BaroData {
    let adc_p = ((raw[0] as i32) << 12) | ((raw[1] as i32) << 4) | ((raw[2] as i32) >> 4);
    let adc_t = ((raw[3] as i32) << 12) | ((raw[4] as i32) << 4) | ((raw[5] as i32) >> 4);

    // Computed in i64: with a marginal/corrupt calibration block the i32
    // products (diff*dig_t2, diff*diff) can overflow and abort the kernel.
    let var1 = ((((adc_t >> 3) as i64 - ((cal.dig_t1 as i64) << 1))
                 * (cal.dig_t2 as i64)) >> 11) as i32;
    let dt = (adc_t >> 4) as i64 - (cal.dig_t1 as i64);
    let var2 = ((((dt * dt) >> 12) * (cal.dig_t3 as i64)) >> 14) as i32;
    let t_fine = var1 + var2;
    let temp_cdeg = ((t_fine * 5 + 128) >> 8) as i32; // in 0.01 C

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

    BaroData { pressure_pa, temp_cdeg }
}
