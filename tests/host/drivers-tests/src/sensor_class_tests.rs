// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sensor class (`sensors.rs`), the real file.
//!
//! The registry is a process-wide static: only
//! `the_board_block_is_reserved_and_the_thermal_sensors_follow_it` touches it.

use super::sensors::{
    self, stream, value, Channel, Quantity, ReadError, Sample, Sensor, SensorChip, Source, Stream, Unit, POWER_CHANNELS,
    STREAM_DEPTH, TEMPERATURE_CHANNELS,
};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering::SeqCst};

/// Samples carrying their number in the first word, so a reader can see a gap
/// the log itself cannot (a sample that was never published).
fn numbered(n: u64) -> Sample {
    let mut s = Sample::new(&[0u8; 8], 0, n * 10_000_000);
    s.w[0] = n;
    s
}

fn number(s: &Sample) -> u64 {
    s.w[0]
}

/// Six signed 32-bit acceleration axes: the shape of an IMU's record.
static IMU_SHAPE: [Channel; 6] = [Channel::new(Quantity::Acceleration, Unit::MilliG, 4, true, -2000, 2000, 100); 6];

static VIRTUAL_LOG: Stream = stream();
static VIRTUAL: Sensor = Sensor::new(&IMU_SHAPE, Source::Stream(&VIRTUAL_LOG));

/// **A stream loses no sample at the rate it is read.** A virtual IMU is driven
/// for `TICKS` acquisitions at rate R while one reader drains it every
/// `STREAM_DEPTH / 2` ticks (a reader that keeps up at half the depth). Every
/// acquisition reaches the reader, in order, with no gap, and the reader's
/// overrun count is zero.
///
/// **Canary** (`sensor-drop-canary`): the producer drops every 10th sample.
/// The log's head stays contiguous, so only the comparison with the number of
/// acquisitions notices: `delivered` is 90 for 100 ticks and the numbers skip.
#[test]
fn a_stream_loses_no_sample_at_the_rate_it_is_read() {
    const TICKS: u64 = 100;
    let mut tx = VIRTUAL.producer().expect("the one producer");
    assert!(VIRTUAL.producer().is_none(), "a second producer cannot exist");
    let mut rx = VIRTUAL.cursor().expect("a stream");
    let mut seen = Vec::new();
    for t in 1..=TICKS {
        tx.publish(numbered(t));
        if t % (STREAM_DEPTH as u64 / 2).max(1) == 0 {
            while let Some(s) = rx.next() {
                seen.push(number(&s));
            }
        }
    }
    while let Some(s) = rx.next() {
        seen.push(number(&s));
    }
    assert_eq!(tx.acquired(), TICKS);
    assert_eq!(rx.overrun(), 0, "the reader kept up");
    assert_eq!(rx.delivered(), TICKS, "every acquisition was delivered");
    assert_eq!(seen, (1..=TICKS).collect::<Vec<_>>(), "in order, no gap");
}

static SLOW_LOG: Stream = stream();
static SLOW: Sensor = Sensor::new(&IMU_SHAPE, Source::Stream(&SLOW_LOG));

/// A reader that falls further behind than the stream's depth is told how many
/// samples it lost, and goes on from the oldest one kept.
///
/// **Canary:** `Reader::next` skips the loss without returning it (rings'
/// `canary-no-overrun` path): the count stays 0 and the row goes red.
#[test]
fn a_reader_that_falls_behind_counts_what_it_lost() {
    let mut tx = SLOW.producer().unwrap();
    let mut rx = SLOW.cursor().expect("a stream");
    let extra = 5u64;
    for t in 1..=(STREAM_DEPTH as u64 + extra) {
        tx.publish(numbered(t));
    }
    let first = rx.next().expect("a sample is kept");
    assert_eq!(rx.overrun(), extra);
    assert_eq!(number(&first), extra + 1, "it resumes at the oldest kept");
}

static LATEST_LOG: Stream = stream();
static LATEST: Sensor = Sensor::new(&IMU_SHAPE, Source::Stream(&LATEST_LOG));

/// A read of a stream is the newest sample with the time it was acquired;
/// before the first publish it is not ready.
#[test]
fn a_read_of_a_stream_is_the_newest_sample() {
    assert_eq!(LATEST.read(), Err(ReadError::NotReady));
    let mut tx = LATEST.producer().unwrap();
    tx.publish(numbered(1));
    tx.publish(numbered(2));
    let s = LATEST.read().unwrap();
    assert_eq!(number(&s), 2);
    assert_eq!(s.acq_ns, 20_000_000, "stamped when it was acquired");
}

/// The IMU's record: six little-endian i32, signed, decoded by its channels.
///
/// **Canary:** read a signed channel as unsigned: -1000 mg reads back as
/// 4294966296.
#[test]
fn a_channel_decodes_its_value_from_the_record() {
    let vals: [i32; 6] = [-1000, 20, 981, -1999, 7, 2000];
    let mut rec = [0u8; 24];
    for (i, v) in vals.iter().enumerate() {
        rec[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    let s = Sample::new(&rec, 0, 1);
    for (i, v) in vals.iter().enumerate() {
        assert_eq!(value(&IMU_SHAPE, &s, i), Some(*v as i64), "channel {i}");
    }
    assert_eq!(value(&IMU_SHAPE, &s, 6), None, "no seventh channel");
    let short = Sample::new(&rec[..10], 0, 1);
    assert_eq!(value(&IMU_SHAPE, &short, 2), None, "the record does not reach it");
    assert!(IMU_SHAPE[0].admits(-1000) && !IMU_SHAPE[0].admits(2001));
}

struct Chip(AtomicU32, bool);

impl SensorChip for Chip {
    fn read(&self) -> Result<Sample, ReadError> {
        Ok(numbered(self.0.fetch_add(1, SeqCst) as u64 + 1))
    }
    fn may_sleep(&self) -> bool {
        self.1
    }
}

static BUS_CHIP: Chip = Chip(AtomicU32::new(0), true);
static REG_CHIP: Chip = Chip(AtomicU32::new(0), false);
static BUS: Sensor = Sensor::new(&POWER_CHANNELS, Source::Chip(&BUS_CHIP));
static REGS: Sensor = Sensor::new(&POWER_CHANNELS, Source::Chip(&REG_CHIP));
static NONE: Sensor = Sensor::new(&IMU_SHAPE, Source::Unsupported);

/// A chip is read when asked and says whether the read may sleep; a stream
/// and an unsupported record never do.
///
/// **Canary:** answer `false` for a chip: the bus-attached chip is then served
/// from a ring pass.
#[test]
fn a_chip_is_read_when_asked_and_says_whether_it_may_sleep() {
    assert!(BUS.may_sleep() && !REGS.may_sleep());
    assert!(!LATEST.may_sleep() && !NONE.may_sleep());
    assert_eq!(number(&REGS.read().unwrap()), 1);
    assert_eq!(number(&REGS.read().unwrap()), 2);
    assert_eq!(NONE.read(), Err(ReadError::Unsupported));
}

static SCRIPTED: AtomicI32 = AtomicI32::new(0);

/// A thermal zone's sensor: whatever the test scripted, as the board's
/// temperature channel.
struct Thermometer;

impl SensorChip for Thermometer {
    fn read(&self) -> Result<Sample, ReadError> {
        Ok(sensors::temperature_sample(SCRIPTED.load(SeqCst), 7))
    }
    fn may_sleep(&self) -> bool {
        false
    }
}

static THERMOMETER: Sensor = Sensor::new(&TEMPERATURE_CHANNELS, Source::Chip(&Thermometer));

static ACCEL: Sensor = Sensor::new(&IMU_SHAPE, Source::Unsupported);
static CENTI_CHANNELS: [Channel; 1] = [Channel::new(Quantity::Temperature, Unit::CentiDegC, 4, true, -4000, 12_500, 0)];
static CENTI: Sensor = Sensor::new(&CENTI_CHANNELS, Source::Unsupported);

/// The numbers of the topology's sensor endpoints are reserved before anything
/// registers, whoever produces them: a vacant one reads nothing, an attached
/// one is the producer's, and a thermal zone's sensors take the numbers after
/// the block on every image. A zone reads the temperature of the instance it
/// names, and only a temperature.
///
/// **Canary:** skip the reservation (`reserve_board_block` does nothing): the
/// thermometer takes instance 0 and the assertion on the block's end fails.
/// Admit every value in `temperature_mdeg` (skip the range check): the fault
/// reads as a temperature.
#[test]
fn the_board_block_is_reserved_and_the_thermal_sensors_follow_it() {
    use azos_abi::sensor_sample::instance as slot;
    sensors::reserve_board_block().unwrap();
    assert_eq!(sensors::reserve_board_block(), Err(super::instances::RegisterError::Full), "reserved once");
    assert!((0..slot::COUNT as u32).all(|n| sensors::get(n).is_none()), "a number nobody produces reads nothing");
    sensors::attach_board(slot::IMU, &ACCEL).unwrap();
    sensors::attach_board(slot::IMU_TEMP, &CENTI).unwrap();
    assert_eq!(sensors::attach_board(slot::IMU, &ACCEL), Err(super::instances::RegisterError::Registered));
    assert_eq!(sensors::attach_board(slot::COUNT as u32, &ACCEL), Err(super::instances::RegisterError::Full), "past the block");
    let got = sensors::get(slot::IMU).expect("attached");
    assert!(core::ptr::eq(&*got as *const Sensor, &ACCEL as *const Sensor));
    drop(got);
    assert!(sensors::get(slot::POWER).is_none() && sensors::get(slot::ODOM).is_none());
    let first = slot::COUNT as u32;
    assert_eq!(sensors::register_boards(&[&THERMOMETER]), Ok(first), "after the block, with a producer or without");
    assert!(sensors::get(first + 1).is_none());

    SCRIPTED.store(61_250, SeqCst);
    assert_eq!(sensors::temperature_mdeg(first), Ok(61_250));
    SCRIPTED.store(-12_000, SeqCst);
    assert_eq!(sensors::temperature_mdeg(first), Ok(-12_000), "below zero is a temperature");
    SCRIPTED.store(150_000, SeqCst);
    assert_eq!(sensors::temperature_mdeg(first), Ok(150_000), "real heat above any junction limit is read");
    SCRIPTED.store(i32::MAX, SeqCst);
    assert_eq!(sensors::temperature_mdeg(first), Err(ReadError::Io), "a transport fault is not a temperature");
    assert_eq!(sensors::temperature_mdeg(first + 1), Err(ReadError::NotReady), "no such sensor");
    assert_eq!(sensors::temperature_mdeg(slot::IMU), Err(ReadError::Unsupported), "an accelerometer is not a thermometer");
    assert_eq!(sensors::temperature_mdeg(slot::IMU_TEMP), Err(ReadError::Unsupported), "centi-degrees are not milli-degrees");
}

static THERMOMETERS: [&Sensor; 3] = [&THERMOMETER, &THERMOMETER, &THERMOMETER];

/// **A board whose sensors do not all fit takes no instance.** Three
/// temperature channels asked of a table with two free slots: refused, and the
/// slots are still free for a board that fits (no number is left registered
/// with nobody to use it).
///
/// **Canary.** Drop the room check in `Instances::register_boards`: the first
/// two are taken before the third is refused, and the small board no longer fits.
#[test]
fn a_board_that_does_not_fit_takes_no_instance() {
    use super::instances::{Instances, RegisterError};
    let t: Instances<Sensor, 2> = Instances::empty();
    assert_eq!(t.register_boards(&THERMOMETERS), Err(RegisterError::Full));
    assert!(t.get(0).is_none(), "a refused board left a sensor registered");
    assert_eq!(t.register_boards(&THERMOMETERS[..2]), Ok(0));
    assert_eq!(t.register_boards(&THERMOMETERS[..1]), Err(RegisterError::Full), "the table is full");
}
