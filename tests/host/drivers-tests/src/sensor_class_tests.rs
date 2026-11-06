// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sensor class (`sensors.rs`, `sensors/board.rs`), the real files.
//!
//! The registry is a process-wide static: only
//! `the_board_registers_its_sensors_in_the_topologys_order` touches it.

use super::sensors::{
    self, board, value, Channel, Quantity, ReadError, Sample, Sensor, SensorChip, Source, Unit, STREAM_DEPTH,
};
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};

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

static VIRTUAL: Sensor = Sensor::new(&board::IMU_CHANNELS, Source::Stream);

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
    let mut rx = VIRTUAL.cursor();
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

static SLOW: Sensor = Sensor::new(&board::IMU_CHANNELS, Source::Stream);

/// A reader that falls further behind than the stream's depth is told how many
/// samples it lost, and goes on from the oldest one kept.
///
/// **Canary:** `Reader::next` skips the loss without returning it (rings'
/// `canary-no-overrun` path): the count stays 0 and the row goes red.
#[test]
fn a_reader_that_falls_behind_counts_what_it_lost() {
    let mut tx = SLOW.producer().unwrap();
    let mut rx = SLOW.cursor();
    let extra = 5u64;
    for t in 1..=(STREAM_DEPTH as u64 + extra) {
        tx.publish(numbered(t));
    }
    let first = rx.next().expect("a sample is kept");
    assert_eq!(rx.overrun(), extra);
    assert_eq!(number(&first), extra + 1, "it resumes at the oldest kept");
}

static LATEST: Sensor = Sensor::new(&board::IMU_CHANNELS, Source::Stream);

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
    let vals: [i32; 6] = [-1000, 20, 981, -250_000, 7, 250_000];
    let mut rec = [0u8; 24];
    for (i, v) in vals.iter().enumerate() {
        rec[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    let s = Sample::new(&rec, 0, 1);
    for (i, v) in vals.iter().enumerate() {
        assert_eq!(value(&board::IMU_CHANNELS, &s, i), Some(*v as i64), "channel {i}");
    }
    assert_eq!(value(&board::IMU_CHANNELS, &s, 6), None, "no seventh channel");
    let short = Sample::new(&rec[..10], 0, 1);
    assert_eq!(value(&board::IMU_CHANNELS, &short, 2), None, "the record does not reach it");
    assert!(board::IMU_CHANNELS[0].admits(-1000) && !board::IMU_CHANNELS[0].admits(2001));
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
static BUS: Sensor = Sensor::new(&board::POWER_CHANNELS, Source::Chip(&BUS_CHIP));
static REGS: Sensor = Sensor::new(&board::POWER_CHANNELS, Source::Chip(&REG_CHIP));
static NONE: Sensor = Sensor::new(&board::IMU_CHANNELS, Source::Unsupported);

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

static T_ZONE: Sensor = Sensor::new(&TEMP, Source::Stream);
static TEMP: [Channel; 1] = [Channel {
    quantity: Quantity::Temperature,
    unit: Unit::MilliDegC,
    width: 4,
    signed: true,
    min: -40_000,
    max: 125_000,
    rate_hz: 0,
}];

/// The board's sensors take the numbers the topology's endpoints name, then
/// the IMU's temperature, then a later sensor the next one; a temperature
/// sensor is found by what it measures, not by its number.
///
/// **Canary:** register the power monitor before the GPS: `sensor.9` is then
/// the GPS and the assertion on `POWER` fails.
#[test]
fn the_board_registers_its_sensors_in_the_topologys_order() {
    board::register(&board::NO_POWER_SENSOR).unwrap();
    for (n, expect) in [
        (board::IMU, &board::IMU_SENSOR),
        (board::ODOM, &board::ODOM_SENSOR),
        (board::GPS, &board::GPS_SENSOR),
        (board::POWER, &board::NO_POWER_SENSOR),
        (board::IMU_TEMP, &board::IMU_TEMP_SENSOR),
    ] {
        let got = sensors::get(n).unwrap_or_else(|| panic!("sensor {n} is registered"));
        assert!(core::ptr::eq(&*got as *const Sensor, expect as *const Sensor), "sensor {n}");
    }
    assert_eq!(sensors::count(), 11);
    assert_eq!(sensors::register_board(&T_ZONE), Ok(11));
    assert_eq!(sensors::find(Quantity::Temperature, Unit::MilliDegC, 0), Some(11));
    assert_eq!(sensors::find(Quantity::Temperature, Unit::CentiDegC, 0), Some(board::IMU_TEMP));
    assert!(sensors::get(12).is_none());
}
