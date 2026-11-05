// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The MPU-6050 6-axis IMU: the chip logic over an [`I2cCall`] bound to the
//! device. No statics, no clock, no kernel function; the host owns the bus,
//! the acquisition stamp and the calibration offsets.

use azos_devif::i2c::{read_regs, write_bytes};
use azos_devif::I2cCall;

/// The chip's default 7-bit address (AD0 low).
pub const MPU6050_ADDR: u8 = 0x68;

const REG_SMPLRT_DIV: u8 = 0x19;
const REG_CONFIG: u8 = 0x1A;
const REG_GYRO_CONFIG: u8 = 0x1B;
const REG_ACCEL_CONFIG: u8 = 0x1C;
/// First of the 14 burst registers: accel (6), temp (2), gyro (6).
pub const REG_ACCEL_XOUT_H: u8 = 0x3B;
const REG_PWR_MGMT_1: u8 = 0x6B;
const REG_WHO_AM_I: u8 = 0x75;

const WHO_AM_I: u8 = 0x68;

/// Bytes of one sample burst.
pub const BURST_LEN: usize = 14;

/// Scaled IMU reading.
#[derive(Clone, Copy)]
pub struct ImuData {
    /// Accelerometer in milli-g (1 g = 1000).  [X, Y, Z].
    pub accel_mg: [i32; 3],
    /// Gyroscope in milli-degrees/sec.  [X, Y, Z].
    pub gyro_mdps: [i32; 3],
    /// Temperature in centi-degrees Celsius (e.g. 3653 = 36.53 °C).
    pub temp_cdeg: i32,
}

/// Why [`Mpu6050::init`] did not leave the chip configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    /// WHO_AM_I could not be read.
    NotFound,
    /// WHO_AM_I names another part.
    WrongId(u8),
    /// A configuration register refused its write.
    Write(&'static str),
}

pub struct Mpu6050<B: I2cCall> {
    bus: B,
}

impl<B: I2cCall> Mpu6050<B> {
    pub fn new(bus: B) -> Self {
        Mpu6050 { bus }
    }

    /// Verify WHO_AM_I, wake the chip (clear SLEEP), 1 kHz sample rate, DLPF
    /// at ~44 Hz, +-250 deg/s and +-2 g.
    pub fn init(&mut self) -> Result<(), InitError> {
        let mut wai = [0u8; 1];
        read_regs(&mut self.bus, REG_WHO_AM_I, &mut wai).map_err(|_| InitError::NotFound)?;
        if wai[0] != WHO_AM_I {
            return Err(InitError::WrongId(wai[0]));
        }
        for (reg, val, name) in [
            (REG_PWR_MGMT_1, 0x00, "PWR_MGMT_1"),
            (REG_SMPLRT_DIV, 0x00, "SMPLRT_DIV"),
            (REG_CONFIG, 0x03, "CONFIG"),
            (REG_GYRO_CONFIG, 0x00, "GYRO_CONFIG"),
            (REG_ACCEL_CONFIG, 0x00, "ACCEL_CONFIG"),
        ] {
            write_bytes(&mut self.bus, &[reg, val]).map_err(|_| InitError::Write(name))?;
        }
        Ok(())
    }

    /// One burst of the 14 sample registers. The outcome code of the failed
    /// transfer, never a partial burst.
    pub fn read_raw(&mut self) -> Result<[u8; BURST_LEN], u32> {
        let mut raw = [0u8; BURST_LEN];
        read_regs(&mut self.bus, REG_ACCEL_XOUT_H, &mut raw)?;
        Ok(raw)
    }
}

/// The burst (accel, temp, gyro, big-endian) in physical units, with
/// `accel_offset_mg` (calibration, milli-g) taken off the accelerometer.
pub fn scale(raw: &[u8; BURST_LEN], accel_offset_mg: [i32; 3]) -> ImuData {
    let i16be = |hi: u8, lo: u8| -> i16 { ((hi as u16) << 8 | lo as u16) as i16 };

    let ax = i16be(raw[0], raw[1]) as i32;
    let ay = i16be(raw[2], raw[3]) as i32;
    let az = i16be(raw[4], raw[5]) as i32;
    let tr = i16be(raw[6], raw[7]) as i32;
    let gx = i16be(raw[8], raw[9]) as i32;
    let gy = i16be(raw[10], raw[11]) as i32;
    let gz = i16be(raw[12], raw[13]) as i32;

    ImuData {
        // +-2 g range: 16384 LSB/g.
        accel_mg: [
            ax * 1000 / 16384 - accel_offset_mg[0],
            ay * 1000 / 16384 - accel_offset_mg[1],
            az * 1000 / 16384 - accel_offset_mg[2],
        ],
        // +-250 deg/s range: 131 LSB/(deg/s).
        gyro_mdps: [gx * 1000 / 131, gy * 1000 / 131, gz * 1000 / 131],
        temp_cdeg: tr * 100 / 340 + 3653,
    }
}
