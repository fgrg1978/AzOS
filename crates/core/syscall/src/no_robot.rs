// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The machine without the Robot domain, as the syscall layer sees it.
//!
//! Built only without the `domain-robot` feature (wave 11, DOMAIN), when the
//! robot crates (`azos_robot`, `azos_imu`, `azos_gps`) are not
//! linked. The four files that call them import these modules under the
//! crates' names instead (`use crate::no_robot::robot as azos_robot;`),
//! so the motor and sensor syscalls keep one body for both images.
//!
//! The answers are the robot crates' own answers for a machine on which no
//! motor was ever initialised and no IMU/GPS ever came up: every motor id is
//! refused as uninitialised (-1, nothing applied), no PWM channel or GPIO pin
//! is bound to a motor, the IMU and GPS are not ready, and the encoder and
//! odometry read zero with a zero ("never acquired") stamp — exactly what a
//! robot image returns before `robot_init()`. `sensor_read_into` refuses the four robot sensor types
//! outright in this build, so ring 3 gets an error, not those zeros.

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

    /// No motor driver: every id is refused as `motor_init` refuses a bad one.
    pub fn motor_init(_id: u32, _pwm_ch: u32, _dir_a: u32, _dir_b: u32) -> i32 { -1 }

    /// Prints what `azos_robot::motor_info` prints for zero motors.
    pub fn motor_info() {
        azos_drv_sys::kconsoleln!("[MOTOR] no motors (image built without the Robot domain)");
    }

    /// An uninitialised id: refused, nothing applied.
    pub fn motor_set_reporting(_id: u32, _dir: MotorDir, _speed_pct: u32) -> (i32, Option<u32>) { (-1, None) }

    /// An uninitialised id: refused, nothing applied.
    pub fn motor_stop_reporting(_id: u32) -> (i32, Option<u32>) { (-1, None) }

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

/// Stand-in for `azos_imu`: the IMU never comes up.
pub mod imu {
    /// Field layout of `azos_imu::ImuData`.
    pub struct ImuData {
        pub accel_mg:  [i32; 3],
        pub gyro_mdps: [i32; 3],
        pub temp_cdeg: i32,
    }
    /// `azos_imu::imu_read_scaled_stamped`: no reading, so no stamp.
    pub fn imu_read_scaled_stamped() -> Option<(ImuData, u64)> { None }
}

/// Stand-in for `azos_gps`: no fix, ever.
pub mod gps {
    /// Field layout of `azos_gps::GpsPosition`.
    pub struct GpsPosition {
        pub lat_deg7: i32,
        pub lon_deg7: i32,
        pub alt_mm: i32,
        pub hdop: u16,
        pub fix: u8,
        pub sats: u8,
        pub speed_cms: u16,
        pub course_cdeg: u16,
    }
    /// Field layout of `azos_gps::StampedFix`.
    pub struct StampedFix {
        pub pos: GpsPosition,
        pub acq: u64,
        pub synthetic: bool,
    }
    /// `azos_gps::gps_read_stamped`: no fix.
    pub fn gps_read_stamped() -> Option<StampedFix> { None }
}
