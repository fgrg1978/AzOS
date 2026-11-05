// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `crates/drivers/baro/src/chip.rs`, the BMP280 over an `I2cCall`, against a
//! register file served as the `I2c` interface, with the calibration and the
//! worked example of the Bosch datasheet (section 3.12).

#[path = "../../../../crates/drivers/baro/src/chip.rs"]
mod chip;

use crate::i2c_fake::{Dev, Op};
use chip::*;

/// The datasheet's trimming values, in the NVM's little-endian order.
fn calibration_block() -> [u8; 26] {
    let mut b = [0u8; 26];
    let words: [i32; 12] = [27504, 26435, -1000, 36477, -10685, 3024, 2855, 140, -7, 15500, -14600, 6000];
    for (i, w) in words.iter().enumerate() {
        b[2 * i..2 * i + 2].copy_from_slice(&(*w as i16).to_le_bytes());
    }
    b
}

/// A BMP280 holding the datasheet's calibration and conversion
/// (adc_T 519888, adc_P 415148).
fn bmp() -> Dev {
    let d = Dev::new();
    d.set(0xD0, &[0x58]);
    d.set(0x88, &calibration_block());
    d.set(0xF7, &[0x65, 0x5A, 0xC0, 0x7E, 0xED, 0x00]);
    d
}

/// Init reads the id and the 26-byte calibration block, then writes the
/// configuration, forced mode last.
#[test]
fn probe_reads_the_calibration_then_configures() {
    let d = bmp();
    let (_, id) = Bmp280::probe(d.call()).ok().unwrap();
    assert_eq!(id, 0x58);
    assert_eq!(
        d.log(),
        [Op::Read(0xD0, 1), Op::Read(0x88, 26), Op::Write(vec![0xF5, 0x00]), Op::Write(vec![0xF4, 0x55])]
    );
}

/// A BME280 (0x60) is accepted, anything else refused before the calibration.
#[test]
fn probe_accepts_the_bme280_and_refuses_other_parts() {
    let d = bmp();
    d.set(0xD0, &[0x60]);
    assert!(Bmp280::probe(d.call()).is_ok());
    let d = bmp();
    d.set(0xD0, &[0x61]);
    assert!(matches!(Bmp280::probe(d.call()), Err(InitError::WrongId(0x61))));
    assert_eq!(d.log(), [Op::Read(0xD0, 1)]);
}

/// **A NAK is an error, never a value**, at every step of the probe.
/// **Canary:** the NAK check in `azos_devif::i2c::{read_regs, write_bytes}`
/// returns `Ok` whatever the code: these go red.
#[test]
fn a_nak_is_reported_at_every_step_of_probe() {
    let want = [
        InitError::NotFound,
        InitError::Calibration,
        InitError::Write("CONFIG"),
        InitError::Write("CTRL_MEAS"),
    ];
    for (i, w) in want.iter().enumerate() {
        let d = bmp();
        d.0.borrow_mut().nak_from = Some(i);
        assert_eq!(Bmp280::probe(d.call()).err(), Some(*w), "step {i}");
    }
}

/// The datasheet's example: 25.08 C and 100653 Pa.
#[test]
fn compensation_reproduces_the_datasheet_example() {
    let d = bmp();
    let (mut chip, _) = Bmp280::probe(d.call()).ok().unwrap();
    let raw = chip.read_raw().unwrap();
    let r = compensate(&chip.calibration(), &raw);
    assert_eq!(r.temp_cdeg, 2508);
    assert_eq!(r.pressure_pa, 100653);
}

/// A read triggers a forced measurement, polls STATUS while it is measuring
/// (bit 3), then reads the six data registers in one burst.
#[test]
fn a_read_triggers_polls_and_reads_one_burst() {
    let d = bmp();
    let (mut chip, _) = Bmp280::probe(d.call()).ok().unwrap();
    let before = d.log().len();
    d.0.borrow_mut().busy = Some((0xF3, 0x08, 3));
    chip.read_raw().unwrap();
    assert_eq!(
        d.log()[before..],
        [
            Op::Write(vec![0xF4, 0x55]),
            Op::Read(0xF3, 1),
            Op::Read(0xF3, 1),
            Op::Read(0xF3, 1),
            Op::Read(0xF3, 1),
            Op::Read(0xF7, 6),
        ],
        "three measuring polls, one that sees it done, then the burst"
    );
}

/// A sensor that never finishes is given up on after the bound, and the
/// burst that follows is read as it is.
#[test]
fn a_wedged_measuring_bit_is_bounded() {
    let d = bmp();
    let (mut chip, _) = Bmp280::probe(d.call()).ok().unwrap();
    let before = d.log().len();
    d.0.borrow_mut().busy = Some((0xF3, 0x08, u32::MAX));
    chip.read_raw().unwrap();
    let polls = d.log()[before..].iter().filter(|o| matches!(o, Op::Read(0xF3, 1))).count();
    assert_eq!(polls as u32, MEASURING_POLL_MAX_ITERS);
}

/// A read whose trigger, status poll or burst is not acknowledged is the
/// outcome code, not the previous conversion's bytes.
#[test]
fn a_nak_during_a_read_is_not_data() {
    for step in 0..3 {
        let d = bmp();
        let (mut chip, _) = Bmp280::probe(d.call()).ok().unwrap();
        let from = d.log().len() + step;
        d.0.borrow_mut().nak_from = Some(from);
        assert_eq!(chip.read_raw(), Err(azos_devif::outcome::FAULT), "step {step}");
    }
}

/// The host keeps the calibration between reads and hands it back: a chip
/// built from it reads what the probed one does, and an unprobed (zero)
/// calibration publishes no pressure rather than dividing by zero.
#[test]
fn a_host_that_keeps_the_calibration_reads_the_same() {
    let d = bmp();
    let (probed, _) = Bmp280::probe(d.call()).ok().unwrap();
    let mut again = Bmp280::with_calibration(d.call(), probed.calibration());
    let raw = again.read_raw().unwrap();
    assert_eq!(compensate(&probed.calibration(), &raw).pressure_pa, 100653);
    assert_eq!(compensate(&Calib::ZERO, &raw).pressure_pa, 0);
    assert_eq!(BMP280_ADDR, 0x76);
}
