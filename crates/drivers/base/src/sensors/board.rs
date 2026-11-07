// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sensors the board registers first. Their numbers are the topology's
//! `sensor.<n>` endpoints (`azos_topology`'s `sensor.0` .. `sensor.9`), so the
//! order of [`register`] is the ABI.
//!
//! A machine without the sensor's hardware or domain still has the instance:
//! nothing publishes into it and a read answers `NOT_READY`, which is what the
//! capability on it was granted for.

use super::{stream, Channel, Quantity as Q, RegisterError, Sample, Sensor, Source, Stream, Unit as U};
use azos_abi::sensor_sample::SENSOR_SAMPLE_FLAG_SYNTHETIC;

pub use azos_abi::sensor_sample::instance::{BATTERY, CAMERA, ENCODER, FLAGS, GPS, IMU, LIDAR, ODOM, POWER, RANGE};

/// The IMU's die temperature, registered after the topology's ten.
pub const IMU_TEMP: u32 = 10;

/// Instances the board registers by itself: the topology's ten and the IMU's
/// temperature.
pub const COUNT: usize = 11;

pub const IMU_HZ: u32 = azos_limits::SENSOR_IMU_HZ as u32;
pub const ODOM_HZ: u32 = azos_limits::SENSOR_ODOM_HZ as u32;
pub const SLOW_HZ: u32 = azos_limits::SENSOR_SLOW_HZ as u32;

const fn ch(quantity: Q, unit: U, width: u8, signed: bool, min: i64, max: i64, rate_hz: u32) -> Channel {
    Channel { quantity, unit, width, signed, min, max, rate_hz }
}

/// Accel x y z (mg), gyro x y z (mdps), as i32 little-endian: the MPU-6050 at
/// +-2 g and +-250 deg/s.
pub static IMU_CHANNELS: [Channel; 6] = [
    ch(Q::Acceleration, U::MilliG, 4, true, -2000, 2000, IMU_HZ),
    ch(Q::Acceleration, U::MilliG, 4, true, -2000, 2000, IMU_HZ),
    ch(Q::Acceleration, U::MilliG, 4, true, -2000, 2000, IMU_HZ),
    ch(Q::AngularRate, U::MilliDegPerSec, 4, true, -250_000, 250_000, IMU_HZ),
    ch(Q::AngularRate, U::MilliDegPerSec, 4, true, -250_000, 250_000, IMU_HZ),
    ch(Q::AngularRate, U::MilliDegPerSec, 4, true, -250_000, 250_000, IMU_HZ),
];
static ODOM_CHANNELS: [Channel; 2] = [
    ch(Q::Distance, U::Millimeter, 8, true, i64::MIN, i64::MAX, ODOM_HZ),
    ch(Q::Angle, U::CentiDegree, 8, true, i64::MIN, i64::MAX, ODOM_HZ),
];
static ENCODER_CHANNELS: [Channel; 2] = [
    ch(Q::Count, U::Ticks, 8, true, i64::MIN, i64::MAX, ODOM_HZ),
    ch(Q::Count, U::Ticks, 8, true, i64::MIN, i64::MAX, ODOM_HZ),
];
static RANGE_CHANNELS: [Channel; 2] = [
    ch(Q::Distance, U::Millimeter, 2, false, 0, u16::MAX as i64, SLOW_HZ),
    ch(Q::Distance, U::Millimeter, 2, false, 0, u16::MAX as i64, SLOW_HZ),
];
static BATTERY_CHANNELS: [Channel; 1] = [ch(Q::Voltage, U::MilliVolt, 2, false, 0, u16::MAX as i64, SLOW_HZ)];
/// Latitude, longitude (degrees x 1e7), altitude (mm), fix quality, satellites.
static GPS_CHANNELS: [Channel; 5] = [
    ch(Q::Coordinate, U::DegreeE7, 4, true, -900_000_000, 900_000_000, SLOW_HZ),
    ch(Q::Coordinate, U::DegreeE7, 4, true, -1_800_000_000, 1_800_000_000, SLOW_HZ),
    ch(Q::Distance, U::Millimeter, 4, true, i32::MIN as i64, i32::MAX as i64, SLOW_HZ),
    ch(Q::Count, U::None, 1, false, 0, u8::MAX as i64, SLOW_HZ),
    ch(Q::Count, U::None, 1, false, 0, u8::MAX as i64, SLOW_HZ),
];
/// One 4-byte point per entry: angle (cdeg) and distance (mm), a scan too big
/// for a sample.
static LIDAR_CHANNELS: [Channel; 1] = [ch(Q::Image, U::None, 4, false, 0, u32::MAX as i64, 0)];
/// PIR (bit 0), sound (bit 1), IR (bit 2).
static FLAGS_CHANNELS: [Channel; 1] = [ch(Q::Flags, U::Bits, 2, false, 0, 7, SLOW_HZ)];
/// A frame too big for a sample: `azos_cam_ring`'s ring carries it.
static CAMERA_CHANNELS: [Channel; 1] = [ch(Q::Image, U::None, 4, false, 0, u32::MAX as i64, 0)];
/// Voltage (mV), current (mA), charge used (mAh), percent, sag, failsafe.
pub static POWER_CHANNELS: [Channel; 6] = [
    ch(Q::Voltage, U::MilliVolt, 2, false, 0, u16::MAX as i64, 0),
    ch(Q::Current, U::MilliAmp, 2, false, 0, u16::MAX as i64, 0),
    ch(Q::Charge, U::MilliAmpHour, 4, false, 0, u32::MAX as i64, 0),
    ch(Q::Ratio, U::Percent, 1, false, 0, 100, 0),
    ch(Q::Flags, U::Bits, 1, false, 0, 1, 0),
    ch(Q::Flags, U::Bits, 1, false, 0, 1, 0),
];
/// A temperature sensor of a thermal zone: milli-degrees Celsius. The range is
/// what no part can exceed (a reading past it is a transport fault, never a
/// temperature to act on), wide above any junction limit so that real heat is
/// never mistaken for a fault.
pub static TEMPERATURE_CHANNELS: [Channel; 1] = [ch(Q::Temperature, U::MilliDegC, 4, true, -100_000, 300_000, 0)];
static IMU_TEMP_CHANNELS: [Channel; 1] = [ch(Q::Temperature, U::CentiDegC, 4, true, -4000, 12_500, IMU_HZ)];

/// A sensor, and its stream when it has one, as the two statics they are.
macro_rules! sensor {
    ($(#[$m:meta])* $name:ident, $chans:expr, stream $log:ident) => {
        static $log: Stream = stream();
        $(#[$m])* pub static $name: Sensor = Sensor::new(&$chans, Source::Stream(&$log));
    };
    ($(#[$m:meta])* $name:ident, $chans:expr, unsupported) => {
        $(#[$m])* pub static $name: Sensor = Sensor::new(&$chans, Source::Unsupported);
    };
}

sensor!(IMU_SENSOR, IMU_CHANNELS, stream IMU_LOG);
sensor!(ODOM_SENSOR, ODOM_CHANNELS, stream ODOM_LOG);
sensor!(ENCODER_SENSOR, ENCODER_CHANNELS, stream ENCODER_LOG);
sensor!(RANGE_SENSOR, RANGE_CHANNELS, stream RANGE_LOG);
sensor!(BATTERY_SENSOR, BATTERY_CHANNELS, stream BATTERY_LOG);
sensor!(GPS_SENSOR, GPS_CHANNELS, stream GPS_LOG);
sensor!(LIDAR_SENSOR, LIDAR_CHANNELS, unsupported);
sensor!(FLAGS_SENSOR, FLAGS_CHANNELS, stream FLAGS_LOG);
sensor!(CAMERA_SENSOR, CAMERA_CHANNELS, unsupported);
sensor!(
    /// The power monitor of a machine that has none.
    NO_POWER_SENSOR, POWER_CHANNELS, stream NO_POWER_LOG
);
sensor!(IMU_TEMP_SENSOR, IMU_TEMP_CHANNELS, stream IMU_TEMP_LOG);

/// Register the board's sensors in the order of the numbers above. `power` is
/// the power monitor's (a chip read, or [`NO_POWER_SENSOR`]).
pub fn register(power: &'static Sensor) -> Result<(), RegisterError> {
    let all: [&'static Sensor; COUNT] = [
        &IMU_SENSOR, &ODOM_SENSOR, &ENCODER_SENSOR, &RANGE_SENSOR, &BATTERY_SENSOR, &GPS_SENSOR,
        &LIDAR_SENSOR, &FLAGS_SENSOR, &CAMERA_SENSOR, power, &IMU_TEMP_SENSOR,
    ];
    super::register_boards(&all).map(|first| debug_assert_eq!(first, 0))
}

/// A temperature sample of a thermal sensor, milli-degrees Celsius.
pub fn temperature_sample(mdeg: i32, acq_ns: u64) -> Sample {
    super::pack(&TEMPERATURE_CHANNELS, &[mdeg as i64], 0, acq_ns)
}

/// The rangefinders' sample: `None` when the front one has no reading (a board
/// without one: not a zero that reads as "clear"), the right one's absence a
/// zero. The driver only simulates its sensors, so a distance is never
/// presented as a device's measurement.
pub fn range_sample(front: Option<u32>, right: Option<u32>, acq_ns: u64) -> Option<Sample> {
    let front = front?;
    Some(RANGE_SENSOR.pack(&[front as i64, right.unwrap_or(0) as i64], SENSOR_SAMPLE_FLAG_SYNTHETIC as u32, acq_ns))
}

/// The battery's sample: `None` when the converter gave no reading. A number
/// nothing measured is never invented: the safety layer reads "no battery" as
/// unknown, and a made-up voltage below its thresholds as a flat pack.
pub fn battery_sample(mv: Option<u32>, acq_ns: u64) -> Option<Sample> {
    Some(BATTERY_SENSOR.pack(&[mv? as i64], 0, acq_ns))
}

/// The digital lines' sample: PIR bit 0, sound bit 1, IR bit 2.
pub fn flags_sample(pir: bool, sound: bool, ir: bool, acq_ns: u64) -> Sample {
    FLAGS_SENSOR.pack(&[pir as i64 | (sound as i64) << 1 | (ir as i64) << 2], 0, acq_ns)
}
