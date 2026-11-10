// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The machine without the Robot domain, as the syscall layer sees it.
//!
//! Built only without the `use-robot` feature (DOMAIN), when the
//! robot crate (`azos_robot`) is not linked. The files that call it import
//! this module under the crate's name instead
//! (`use crate::no_robot::robot as azos_robot;`), so the motor syscalls and
//! the vDSO publisher keep one body for both images.
//!
//! The answers are the robot crate's own answers for a machine on which no
//! motor was ever initialised: every motor id is refused as uninitialised
//! (-1, nothing applied), no PWM channel or GPIO pin is bound to a motor, and
//! the encoder and odometry read zero with a zero ("never acquired") stamp,
//! exactly what a robot image returns before `robot_init()`. A bind of those
//! sensors to the vDSO page is refused in this build, so the interrupt never
//! publishes those zeros.

/// Stand-in for `azos_robot`: no motor exists.
pub mod robot {
    /// Same discriminants as `azos_robot::MotorDir`.
    #[derive(Clone, Copy, PartialEq, Debug)]
    pub enum MotorDir {
        Forward  = 0,
        Backward = 1,
        Brake    = 2,
        Coast    = 3,
    }

    /// `azos_robot::MOTOR_REFUSED_HALTED`; never returned here.
    pub const MOTOR_REFUSED_HALTED: i32 = -2;
    /// No motors without the Robot domain: the commander table is empty.
    pub const MAX_MOTORS: usize = 0;

    /// No drivetrain loop: a command has nobody to apply it.
    pub fn motor_cmd_publish(_speed_l: i32, _speed_r: i32) {}
    pub fn motor_cmd_zero() {}

    /// No motors, nothing to halt.
    pub fn motor_halted() -> bool { false }

    /// No motor driver: every id is refused as `motor_init` refuses a bad one.
    pub fn motor_init(_id: u32, _pwm_ch: u32, _dir_a: u32, _dir_b: u32) -> i32 { -1 }

    /// An uninitialised id: refused, nothing applied.
    pub fn motor_set_reporting(_id: u32, _dir: MotorDir, _speed_pct: u32) -> (i32, Option<u32>) { (-1, None) }

    /// An uninitialised id: refused, nothing applied.
    pub fn motor_stop_reporting(_id: u32) -> (i32, Option<u32>) { (-1, None) }

    /// No motor to stop.
    pub fn motor_stop_panic(_id: u32) {}

    /// No motor to drive to a safe state.
    pub fn motor_safe_state(_id: u32) -> bool { false }

    /// No motor whose hold to lift.
    pub fn motor_release(_id: u32) -> bool { false }

    /// No encoder: zero ticks.
    pub fn encoder_read() -> (i64, i64) { (0, 0) }

    /// No encoder: zero ticks, stamped 0 ("never acquired"), as
    /// `azos_robot::encoder_read_stamped` answers where it has no encoder.
    pub fn encoder_read_stamped() -> ((i64, i64), u64) { ((0, 0), 0) }

    /// No odometry: zero distance, zero heading, stamped 0 (never integrated).
    pub fn odom_get_stamped() -> ((i64, i64), u64) { ((0, 0), 0) }

    pub mod motor {
        /// No PWM channel is bound to a motor.
        pub fn pwm_channel_motor_id(_ch: u32) -> Option<u32> { None }
        /// No GPIO pin is bound to a motor.
        pub fn gpio_pin_motor_id(_pin: u32) -> Option<u32> { None }
    }
}
