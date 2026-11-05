// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `crates/drivers/imu/src/chip.rs`, the MPU-6050 over an `I2cCall`, against a
//! register file served as the `I2c` interface.

#[path = "../../../../crates/drivers/imu/src/chip.rs"]
mod chip;

use crate::i2c_fake::{Dev, Op};
use chip::*;

/// The chip as it answers at power-up: WHO_AM_I right.
fn mpu() -> Dev {
    let d = Dev::new();
    d.set(0x75, &[0x68]);
    d
}

/// Init reads WHO_AM_I, then writes the five configuration registers in the
/// order that wakes the chip first.
#[test]
fn init_checks_the_id_then_configures() {
    let d = mpu();
    Mpu6050::new(d.call()).init().unwrap();
    assert_eq!(MPU6050_ADDR, 0x68, "the address the host binds the bus to");
    assert_eq!(REG_ACCEL_XOUT_H, 0x3B);
    assert_eq!(
        d.log(),
        [
            Op::Read(0x75, 1),
            Op::Write(vec![0x6B, 0x00]),
            Op::Write(vec![0x19, 0x00]),
            Op::Write(vec![0x1A, 0x03]),
            Op::Write(vec![0x1B, 0x00]),
            Op::Write(vec![0x1C, 0x00]),
        ]
    );
}

/// Another part at the address is refused before anything is written.
#[test]
fn init_refuses_another_part_and_writes_nothing() {
    let d = Dev::new();
    d.set(0x75, &[0x70]);
    assert_eq!(Mpu6050::new(d.call()).init(), Err(InitError::WrongId(0x70)));
    assert_eq!(d.log(), [Op::Read(0x75, 1)]);
}

/// **A NAK is an error, never a value.** WHO_AM_I not acknowledged is
/// `NotFound`; a NAK on each configuration write names that register.
/// **Canary:** the NAK check in `azos_devif::i2c::{read_regs, write_bytes}`
/// returns `Ok` whatever the code: these go red.
#[test]
fn a_nak_is_reported_at_every_step_of_init() {
    let names = ["PWR_MGMT_1", "SMPLRT_DIV", "CONFIG", "GYRO_CONFIG", "ACCEL_CONFIG"];
    let d = mpu();
    d.0.borrow_mut().nak_from = Some(0);
    assert_eq!(Mpu6050::new(d.call()).init(), Err(InitError::NotFound));
    for (i, name) in names.iter().enumerate() {
        let d = mpu();
        d.0.borrow_mut().nak_from = Some(1 + i);
        assert_eq!(Mpu6050::new(d.call()).init(), Err(InitError::Write(name)), "write {i}");
    }
}

/// The 14 sample registers are one burst from 0x3B, and a burst the bus
/// refuses is the outcome code, not bytes.
#[test]
fn a_burst_is_one_transfer_and_a_nak_is_not_data() {
    let d = mpu();
    let sample: Vec<u8> = (1..=14).collect();
    d.set(0x3B, &sample);
    let mut imu = Mpu6050::new(d.call());
    assert_eq!(imu.read_raw().unwrap().to_vec(), sample);
    assert_eq!(*d.log().last().unwrap(), Op::Read(0x3B, 14));
    d.0.borrow_mut().nak_from = Some(d.log().len());
    assert_eq!(imu.read_raw(), Err(azos_devif::outcome::FAULT));
}

/// +-2 g is 16384 LSB/g, +-250 deg/s is 131 LSB per deg/s, the temperature
/// is raw/340 + 36.53 C, and the calibration offset comes off the
/// accelerometer only.
#[test]
fn scale_decodes_big_endian_signed_values() {
    let mut raw = [0u8; BURST_LEN];
    raw[0..2].copy_from_slice(&16384i16.to_be_bytes());
    raw[2..4].copy_from_slice(&(-8192i16).to_be_bytes());
    raw[4..6].copy_from_slice(&0i16.to_be_bytes());
    raw[6..8].copy_from_slice(&340i16.to_be_bytes());
    raw[8..10].copy_from_slice(&131i16.to_be_bytes());
    raw[10..12].copy_from_slice(&(-131i16).to_be_bytes());
    raw[12..14].copy_from_slice(&(-32768i16).to_be_bytes());
    let d = scale(&raw, [0, 0, 0]);
    assert_eq!(d.accel_mg, [1000, -500, 0]);
    assert_eq!(d.gyro_mdps, [1000, -1000, -32768 * 1000 / 131]);
    assert_eq!(d.temp_cdeg, 100 + 3653);
    let d = scale(&raw, [10, -20, 30]);
    assert_eq!(d.accel_mg, [990, -480, -30]);
    assert_eq!(d.gyro_mdps[0], 1000, "offsets are the accelerometer's");
}
