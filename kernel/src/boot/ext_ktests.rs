// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The extension contract in a booted image (Kconfig `EXT_ROBOT`): what the
//! robot extension's manifest, and the base providers beside it, declare is
//! what the actuation core holds.

use azos_actuation::{gate, providers};
use azos_safety_core::actuation::ROBOT;

azos_ktest::ktest! {
    fn ext_robot_providers_are_installed() {
        if providers::count() != ROBOT.providers.len() {
            return Err("the provider table does not hold the robot manifest's providers");
        }
        Ok(())
    }
}

azos_ktest::ktest! {
    fn ext_gate_follows_the_providers_readiness() {
        let ready = ROBOT.providers.iter().all(|p| p.ready.is_none_or(|r| r()));
        if gate::gate_installed() != ready {
            return Err("the actuation gate does not follow the robot provider's readiness");
        }
        if !ready {
            return Err("the robot provider is not ready after boot");
        }
        Ok(())
    }
}

azos_ktest::ktest! {
    fn ext_robot_owns_the_motor_kind() {
        use azos_actuation::kind::KIND_MOTOR;
        if !providers::serves(KIND_MOTOR) {
            return Err("no installed provider owns the motor kind");
        }
        // The robot provider's effects hook, not the core, registers the
        // wheel's safe-state drive (Kconfig EFFECT_WRITE_AHEAD).
        #[cfg(feature = "effect-gate")]
        if !azos_actuation::safe_state::can_drive(KIND_MOTOR) {
            return Err("the robot provider's effects hook did not register the wheel's safe-state drive");
        }
        Ok(())
    }
}

azos_ktest::ktest! {
    fn ext_the_kill_switch_is_installed_beside_the_robot() {
        // The robot's kernel feature turns on the board's I/O, whose GPIO kill
        // switch is a base provider: its report and its task run from the
        // table's boot phases, so a robot image without it has no kill switch.
        let want = 1 + cfg!(feature = "board-io") as usize;
        if providers::manifests() != want {
            return Err("the provider table does not hold the robot's and the kill switch's manifests");
        }
        Ok(())
    }
}

azos_ktest::ktest! {
    fn ext_a_wheel_stop_reaches_the_motor_layer() {
        // The provider check fails closed when unset: a robot image whose
        // boot did not install it would refuse even this stop.
        match azos_syscall::motor_host::wheel_speed(0, 0, 0) {
            Ok(_) => Ok(()),
            Err(_) => Err("a stop of wheel 0 was refused on the robot: the provider check is not installed or not served"),
        }
    }
}

azos_ktest::ktest! {
    fn ext_robot_sensors_are_attached_at_their_topology_numbers() {
        use azos_abi::sensor_sample::instance as n;
        use azos_drv_base::sensors::{self, Sensor};
        use azos_robot_sensors as r;
        let is = |i: u32, want: &'static Sensor| sensors::get(i).is_some_and(|got| core::ptr::eq(&*got, want));
        let robot = [
            (n::IMU, &r::IMU_SENSOR), (n::ODOM, &r::ODOM_SENSOR), (n::ENCODER, &r::ENCODER_SENSOR),
            (n::RANGE, &r::RANGE_SENSOR), (n::BATTERY, &r::BATTERY_SENSOR), (n::GPS, &r::GPS_SENSOR),
            (n::LIDAR, &r::LIDAR_SENSOR), (n::FLAGS, &r::FLAGS_SENSOR), (n::CAMERA, &r::CAMERA_SENSOR),
            (n::IMU_TEMP, &r::IMU_TEMP_SENSOR),
        ];
        for (i, want) in robot {
            if !is(i, want) {
                return Err("a robot sensor is not the one attached to its reserved number");
            }
        }
        // The power monitor is the board's I/O, which the robot's feature turns on.
        if !is(n::POWER, &azos_drv_sensor::ina219::POWER_SENSOR) {
            return Err("the board's power monitor is not the one attached to its number");
        }
        Ok(())
    }
}
