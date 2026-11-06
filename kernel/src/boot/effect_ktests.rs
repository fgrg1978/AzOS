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
