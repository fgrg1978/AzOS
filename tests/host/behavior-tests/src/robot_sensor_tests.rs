// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The robot extension's sensors (`crates/domains/robot/sensors`, the real
//! file): where they sit in the topology's numbering, and what a missing
//! reading is.
//!
//! The sensor registry is a process-wide static: only
//! `the_robot_attaches_each_sensor_at_its_topology_number` touches it.

use azos_abi::sensor_sample::instance;
use azos_drv_base::sensors::{self, value, Sensor};
use azos_robot_sensors as robot;
use std::panic::catch_unwind;

/// The robot's sensors take the numbers the topology's endpoints name, and no
/// other: the power monitor (the board's I/O) and every number past the block
/// stay vacant, and attaching twice is refused rather than replacing a producer.
///
/// **Canary:** swap two entries of `register`'s table (the IMU's and the
/// odometry's): the sensor at `sensor.0` is the odometry and the first
/// assertion fails. Drop one entry: its number reads nothing.
#[test]
fn the_robot_attaches_each_sensor_at_its_topology_number() {
    sensors::reserve_board_block().unwrap();
    robot::register();
    for (n, expect) in [
        (instance::IMU, &robot::IMU_SENSOR),
        (instance::ODOM, &robot::ODOM_SENSOR),
        (instance::ENCODER, &robot::ENCODER_SENSOR),
        (instance::RANGE, &robot::RANGE_SENSOR),
        (instance::BATTERY, &robot::BATTERY_SENSOR),
        (instance::GPS, &robot::GPS_SENSOR),
        (instance::LIDAR, &robot::LIDAR_SENSOR),
        (instance::FLAGS, &robot::FLAGS_SENSOR),
        (instance::CAMERA, &robot::CAMERA_SENSOR),
        (instance::IMU_TEMP, &robot::IMU_TEMP_SENSOR),
    ] {
        let got = sensors::get(n).unwrap_or_else(|| panic!("sensor {n} is attached"));
        assert!(core::ptr::eq(&*got as *const Sensor, expect as *const Sensor), "sensor {n}");
    }
    assert!(sensors::get(instance::POWER).is_none(), "the power monitor is the board's, not the robot's");
    assert!(sensors::get(instance::COUNT as u32).is_none(), "nothing past the reserved block");
    assert!(catch_unwind(robot::register).is_err(), "a second registration must not replace a producer");
}

/// **A rangefinder with no reading is no sample, never a zero that reads as
/// "clear"; a reading is flagged synthetic, the driver only simulating.**
///
/// **Canary:** answer `front.unwrap_or(0)` for a missing front reading: the
/// first assertion sees a sample.
#[test]
fn a_missing_range_is_no_sample_and_a_simulated_one_is_flagged() {
    use azos_abi::sensor_sample::SENSOR_SAMPLE_FLAG_SYNTHETIC as SYN;
    assert_eq!(robot::range_sample(None, Some(800), 5), None);
    let s = robot::range_sample(Some(1500), None, 5).unwrap();
    assert_eq!(s.flags, SYN as u32);
    assert_eq!(value(robot::RANGE_SENSOR.channels(), &s, 0), Some(1500));
    assert_eq!(value(robot::RANGE_SENSOR.channels(), &s, 1), Some(0), "no right reading is 0");
    assert_eq!(s.acq_ns, 5);
}

/// A converter with no reading publishes nothing, and the lines pack to the
/// bits the companion's protocol names.
///
/// **Canary:** make `battery_sample` answer a fixed 3700 mV for `None`: the
/// first assertion sees a sample.
#[test]
fn an_unread_battery_is_no_sample_and_the_lines_pack_to_their_bits() {
    assert_eq!(robot::battery_sample(None, 1), None);
    let s = robot::battery_sample(Some(7400), 1).unwrap();
    assert_eq!(value(robot::BATTERY_SENSOR.channels(), &s, 0), Some(7400));
    for (p, so, ir, bits) in [(true, false, false, 1), (false, true, false, 2), (false, false, true, 4), (true, true, true, 7)] {
        let f = robot::flags_sample(p, so, ir, 1);
        assert_eq!(value(robot::FLAGS_SENSOR.channels(), &f, 0), Some(bits));
    }
}
