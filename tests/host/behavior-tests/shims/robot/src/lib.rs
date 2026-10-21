// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_robot`, used only by `tests/host/behavior-tests`'
//! motor-gate/record suite (Q1.3/Q1.4, 2026-09-25).
//!
//! **The motor layer is the real one.** `motor.rs` and `pid.rs` are the files
//! from `domains/robot/robot/src`, pulled in with `#[path]` — the same technique
//! `tests/host/syscall-tests/shims/robot` already uses for the same file, for the
//! same reason: the code under test is the code that ships, not a
//! reimplementation. `motor.rs` also needs `SpinLock::get_mut_unchecked`,
//! which `cap_test_sync` (the alias `tests/host/behavior-tests` uses for
//! everything else) deliberately omits — see `shims/robot_sync`, a copy of
//! `tests/host/syscall-tests/shims/robot_sync` scoped here the same way.

// The driver class crates the compiled sources name, all served by the
// one host stand-in `beh_test_drivers`.
extern crate beh_test_drivers as azos_drv_actuator;
extern crate beh_test_drivers as azos_drv_gpio;
extern crate beh_test_drivers as azos_drv_sys;

#[path = "../../../../../../domains/robot/robot/src/pid.rs"]
pub mod pid;

#[path = "../../../../../../domains/robot/robot/src/motor.rs"]
pub mod motor_real;

pub use motor_real::{
    motor_init, motor_set, motor_set_reporting, motor_state, motor_stop, motor_stop_reporting,
    motor_gate_installed, set_motor_gate, set_motor_halt, set_motor_recorder,
    MotorDir, MAX_MOTORS, MOTOR_REFUSED_HALTED,
};

#[cfg(any(test, feature = "test-util"))]
pub use motor_real::{clear_motor_gate_for_test, clear_motor_recorder_for_test};
