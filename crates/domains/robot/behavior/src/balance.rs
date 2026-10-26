// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Balance Bot — self-balancing inverted pendulum controller (Phase AO).
//!
//! PID controller reads IMU pitch angle and drives motors to maintain
//! upright balance. Runs at high frequency (~400Hz) for stability.
//!
//! Control law:
//!   error = target_angle - current_angle
//!   output = Kp*error + Ki*∫error + Kd*(d_error/dt)
//!   motor_speed = clamp(output, -MAX_SPEED, +MAX_SPEED)
//!
//! Both wheels get the same speed (differential for turning is added
//! on top by the brain's steering commands).

use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use crate::types::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Target pitch angle (centidegrees). 0 = perfectly upright.
pub const BALANCE_TARGET_CDEG: i32 = 0;

/// PID gains (×1000 for fixed-point). Tuned for typical 2-wheel balance bot.
pub const BALANCE_KP: i32 = 500;       // proportional
pub const BALANCE_KI: i32 = 5;         // integral
pub const BALANCE_KD: i32 = 200;       // derivative

/// Maximum motor output from balance PID (before steering overlay).
pub const BALANCE_MAX_OUTPUT: i32 = 80;

/// Maximum tilt before giving up (centidegrees). Beyond this, robot has fallen.
pub const BALANCE_FALLEN_CDEG: i32 = 6000;  // 60°

/// Integral windup limit.
const INTEGRAL_LIMIT: i32 = 50_000;

/// PID gain divisor (gains are ×1000).
const GAIN_SCALE: i32 = 1000;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

static BALANCE_ENABLED: AtomicBool = AtomicBool::new(false);
static PREV_ERROR: AtomicI32 = AtomicI32::new(0);
static INTEGRAL: AtomicI32 = AtomicI32::new(0);
static STEERING_OFFSET: AtomicI32 = AtomicI32::new(0);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Enable balance mode.
pub fn balance_enable() {
    PREV_ERROR.store(0, Ordering::Relaxed);
    INTEGRAL.store(0, Ordering::Relaxed);
    STEERING_OFFSET.store(0, Ordering::Relaxed);
    BALANCE_ENABLED.store(true, Ordering::Release);
}

/// Disable balance mode.
pub fn balance_disable() {
    BALANCE_ENABLED.store(false, Ordering::Release);
}

/// Check if balance mode is active.
pub fn balance_is_enabled() -> bool {
    BALANCE_ENABLED.load(Ordering::Acquire)
}

/// Set steering offset (for turning while balancing).
/// Positive = turn right, negative = turn left.
pub fn balance_set_steering(offset: i32) {
    STEERING_OFFSET.store(offset.clamp(-50, 50), Ordering::Relaxed);
}

/// Balance behavior layer — call from arbiter at high frequency.
///
/// Uses IMU pitch angle to compute PID output for motor speeds.
/// Returns valid MotorOutput when balance is enabled and robot is upright.
pub fn layer_balance(state: &SensorState) -> BehaviorOutput {
    if !BALANCE_ENABLED.load(Ordering::Acquire) || !state.imu_valid {
        return BehaviorOutput { cmd: MotorOutput::none(), layer: 3 };
    }

    // Compute pitch angle from accelerometer (centidegrees)
    let pitch_cdeg = pitch_from_accel(state.accel_mg);

    // Check if fallen (irrecoverable)
    if pitch_cdeg.unsigned_abs() > BALANCE_FALLEN_CDEG as u32 {
        // Robot has fallen — stop motors
        return BehaviorOutput { cmd: MotorOutput::some(0, 0), layer: 3 };
    }

    // PID error
    let error = BALANCE_TARGET_CDEG - pitch_cdeg;

    // Integral (with anti-windup)
    let prev_integral = INTEGRAL.load(Ordering::Relaxed);
    let new_integral = (prev_integral + error).clamp(-INTEGRAL_LIMIT, INTEGRAL_LIMIT);
    INTEGRAL.store(new_integral, Ordering::Relaxed);

    // Derivative
    let prev_error = PREV_ERROR.load(Ordering::Relaxed);
    let derivative = error - prev_error;
    PREV_ERROR.store(error, Ordering::Relaxed);

    // PID output (gains are ×1000, divide at end)
    let output = (BALANCE_KP * error
                + BALANCE_KI * new_integral
                + BALANCE_KD * derivative) / GAIN_SCALE;

    let output = output.clamp(-BALANCE_MAX_OUTPUT, BALANCE_MAX_OUTPUT);

    // Apply steering offset
    let steer = STEERING_OFFSET.load(Ordering::Relaxed);
    let speed_l = (output + steer).clamp(-BALANCE_MAX_OUTPUT, BALANCE_MAX_OUTPUT);
    let speed_r = (output - steer).clamp(-BALANCE_MAX_OUTPUT, BALANCE_MAX_OUTPUT);

    BehaviorOutput {
        cmd: MotorOutput::some(speed_l, speed_r),
        layer: 3,
    }
}

// ---------------------------------------------------------------------------
// Math helpers
// ---------------------------------------------------------------------------

/// Compute pitch angle from accelerometer in centidegrees.
/// Pitch = atan2(ax, az) — forward/backward tilt.
fn pitch_from_accel(accel_mg: [i32; 3]) -> i32 {
    let ax = accel_mg[0] as i64;
    let az = accel_mg[2] as i64;

    if az == 0 && ax == 0 {
        return 0;
    }

    // atan2 approximation in centidegrees
    // Using the same approach as offline.rs
    let abs_ax = if ax < 0 { -ax } else { ax };
    let abs_az = if az < 0 { -az } else { az };

    let angle_cdeg = if abs_az >= abs_ax {
        if abs_az == 0 { 0 } else {
            ((45 * abs_ax / (abs_az + abs_ax / 4)).min(45) * 100) as i32
        }
    } else {
        (90 - if abs_ax == 0 { 0 } else {
            (45 * abs_az / (abs_ax + abs_az / 4)).min(45)
        }) as i32 * 100
    };

    // Sign: positive ax = tilting forward
    if ax >= 0 { angle_cdeg } else { -angle_cdeg }
}
