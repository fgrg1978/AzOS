// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

use azos_abi::sensor_sample::{instance, SENSOR_SAMPLE_FLAG_SYNTHETIC};
use azos_drv_base::sensors::{
    self, stream, Channel, Quantity as Q, Sample, Sensor, Source, Stream, Unit as U,
};

pub use instance::{BATTERY, CAMERA, ENCODER, FLAGS, GPS, IMU, IMU_TEMP, LIDAR, ODOM, RANGE};

pub const IMU_HZ: u32 = azos_limits::SENSOR_IMU_HZ as u32;
pub const ODOM_HZ: u32 = azos_limits::SENSOR_ODOM_HZ as u32;
pub const SLOW_HZ: u32 = azos_limits::SENSOR_SLOW_HZ as u32;

const fn ch(quantity: Q, unit: U, width: u8, signed: bool, min: i64, max: i64, rate_hz: u32) -> Channel {
    Channel::new(quantity, unit, width, signed, min, max, rate_hz)
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
/// A frame too big for a sample: the `Frame` interface carries it.
static CAMERA_CHANNELS: [Channel; 1] = [ch(Q::Image, U::None, 4, false, 0, u32::MAX as i64, 0)];
static IMU_TEMP_CHANNELS: [Channel; 1] = [ch(Q::Temperature, U::CentiDegC, 4, true, -4000, 12_500, IMU_HZ)];

/// A sensor, and its stream when it has one, as the two statics they are.
macro_rules! sensor {
    ($name:ident, $chans:expr, stream $log:ident) => {
        static $log: Stream = stream();
        pub static $name: Sensor = Sensor::new(&$chans, Source::Stream(&$log));
    };
    ($name:ident, $chans:expr, unsupported) => {
        pub static $name: Sensor = Sensor::new(&$chans, Source::Unsupported);
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
sensor!(IMU_TEMP_SENSOR, IMU_TEMP_CHANNELS, stream IMU_TEMP_LOG);

/// Attach the robot's sensors to their reserved instances.
pub fn register() {
    let all: [(u32, &'static Sensor); 10] = [
        (if cfg!(feature = "robot-sensors-swap-canary") { ODOM } else { IMU }, &IMU_SENSOR),
        (if cfg!(feature = "robot-sensors-swap-canary") { IMU } else { ODOM }, &ODOM_SENSOR), (ENCODER, &ENCODER_SENSOR), (RANGE, &RANGE_SENSOR),
        (BATTERY, &BATTERY_SENSOR), (GPS, &GPS_SENSOR), (LIDAR, &LIDAR_SENSOR), (FLAGS, &FLAGS_SENSOR),
        (CAMERA, &CAMERA_SENSOR), (IMU_TEMP, &IMU_TEMP_SENSOR),
    ];
    for (n, s) in all {
        if let Err(e) = sensors::attach_board(n, s) {
            panic!("robot sensor {} was refused its instance: {:?}", n, e);
        }
    }
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
