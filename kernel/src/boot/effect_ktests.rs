// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The effect interface in a booted image without the robot extension: no
//! provider owns the motor kind, so a motor op is refused as no device, with a
//! receipt, before the effect gate or the motor layer is reached.

use azos_actuation::kind::KIND_MOTOR;
use azos_syscall::motor_host::{wheel_speed, Unissued};

azos_ktest::ktest! {
    fn effect_a_motor_op_without_wheels_is_refused_as_no_device() {
        if azos_actuation::providers::serves(KIND_MOTOR) {
            return Err("a provider owns the motor kind in an image without the robot extension");
        }
        match wheel_speed(0, 0, 0) {
            Err(Unissued::NoDevice) => Ok(()),
            _ => Err("a motor op on an image without wheels was not refused as no device"),
        }
    }
}

azos_ktest::ktest! {
    fn effect_the_robot_sensor_numbers_are_reserved_and_vacant() {
        use azos_abi::sensor_sample::instance as n;
        use azos_drv_base::sensors;
        for i in [n::IMU, n::ODOM, n::ENCODER, n::RANGE, n::BATTERY, n::GPS, n::LIDAR, n::FLAGS, n::CAMERA, n::IMU_TEMP] {
            if sensors::get(i).is_some() {
                return Err("a robot sensor is attached in an image without the robot extension");
            }
        }
        if sensors::get(n::POWER).is_some() != cfg!(feature = "board-io") {
            return Err("the power monitor is attached only where the board's I/O is built");
        }
        if sensors::reserve_board_block().is_ok() {
            return Err("the topology's sensor numbers were not reserved at boot");
        }
        Ok(())
    }
}
