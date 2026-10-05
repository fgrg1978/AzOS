// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Horizontal position controller for multirotors (D04 enabler).
//!
//! `FlightMode::PosHold` / `Auto` need an outer loop that turns a *position*
//! setpoint into the roll/pitch angles the attitude controller already tracks.
//! That loop does not exist in the kernel `flight` crate today (PosHold just
//! forwards server-supplied attitude targets). This module is that missing
//! piece, kept here in `flight-math` so it is pure and host-testable.
//!
//! ## Cascade (all NED, integer fixed-point)
//! ```text
//!   position error ──P──► velocity setpoint ──PI──► accel setpoint
//!                                                      │
//!                          tilt = asin(accel / g) ◄────┘   (+ wind feed-fwd)
//! ```
//! 1. **Position → velocity** (P): `vel_sp = Kp · pos_err`, clamped to a max
//!    cruise speed so a far setpoint doesn't command an unflyable velocity.
//! 2. **Velocity → acceleration** (PI): the integral term cancels steady
//!    disturbances (e.g. wind) without a separate estimator; the optional
//!    wind feed-forward (see [`crate::wind`]) just makes that faster.
//! 3. **Acceleration → tilt**: small-angle `a = g·sin(θ)`, then the NED accel
//!    is rotated into body forward/right → pitch/roll.
//!
//! ## Frames & sign convention
//! Matches [`crate::wind`]: NED `(north, east)`; positive `pitch_cdeg`
//! accelerates forward, positive `roll_cdeg` accelerates right.
//!
//! ## Statelessness
//! The only retained state is the two velocity-loop integrators. Every input
//! is passed explicitly to [`PositionController::update`]; no global reads.

use crate::wind::{accel_to_tilt_cdeg, ned_horizontal_to_body, GRAVITY_MMSS};

// ── Gains (NUM/DEN keep everything integer) ──────────────────────────────────

/// Position→velocity P gain numerator/denominator: `vel_sp = pos_err · 1/2`
/// (mm → mm/s). A ~2 s approach time constant — gentle, no overshoot.
pub const POS_VEL_P_NUM: i32 = 1;
pub const POS_VEL_P_DEN: i32 = 2;

/// Velocity→acceleration P gain: `accel = vel_err · 2` (mm/s → mm/s²).
pub const VEL_ACC_P_NUM: i32 = 2;
pub const VEL_ACC_P_DEN: i32 = 1;

/// Velocity→acceleration I gain: `accel_i = integral · 1/4`, where the
/// integral accumulates `vel_err · dt` (mm/s · s = mm). Small, to reject
/// steady disturbance without inducing oscillation.
pub const VEL_ACC_I_NUM: i32 = 1;
pub const VEL_ACC_I_DEN: i32 = 4;

// ── Limits (named, no magic numbers) ─────────────────────────────────────────

/// Max commanded horizontal velocity (mm/s) — ~5 m/s cruise.
pub const MAX_VEL_MMS: i32 = 5_000;

/// Max commanded horizontal acceleration (mm/s²) — ~0.5 g.
pub const MAX_ACC_MMSS: i32 = GRAVITY_MMSS / 2;

/// Max tilt the position loop may command per axis (cdeg) — 25°.
pub const POS_TILT_MAX_CDEG: i32 = 2_500;

/// Integrator clamp (mm) — bounds the velocity-loop I term's authority.
pub const VEL_I_MAX: i32 = MAX_ACC_MMSS * VEL_ACC_I_DEN / VEL_ACC_I_NUM;

// ── Controller ───────────────────────────────────────────────────────────────

/// Cascaded horizontal position controller. Output is a tilt target in cdeg.
#[derive(Clone, Copy, Default)]
pub struct PositionController {
    /// Velocity-loop integrator, north axis (mm/s · s = mm).
    vel_i_n: i32,
    /// Velocity-loop integrator, east axis.
    vel_i_e: i32,
}

/// Clamp helper (const-friendly, avoids pulling in std::cmp on no_std paths).
fn clamp_i32(v: i32, lo: i32, hi: i32) -> i32 {
    if v < lo {
        lo
    } else if v > hi {
        hi
    } else {
        v
    }
}

impl PositionController {
    pub const fn new() -> Self {
        PositionController { vel_i_n: 0, vel_i_e: 0 }
    }

    /// Compute the roll/pitch tilt target (cdeg) to drive the craft toward
    /// `target_pos_ne` from `current_pos_ne` / `current_vel_ne` (all NED).
    ///
    /// - `*_pos_ne`: position north/east (mm). - `current_vel_ne`: velocity (mm/s).
    /// - `yaw_cdeg`: current heading, for the NED→body rotation.
    /// - `wind_ff_cdeg`: optional `(roll, pitch)` wind feed-forward bias (cdeg),
    ///   e.g. from [`crate::wind::WindEstimator::tilt_bias_cdeg`]; pass `(0, 0)`
    ///   to disable. Added on top of the feedback tilt, then clamped.
    /// - `dt_ms`: time step (ms).
    ///
    /// Returns `(roll_cdeg, pitch_cdeg)`.
    pub fn update(
        &mut self,
        target_pos_ne: (i32, i32),
        current_pos_ne: (i32, i32),
        current_vel_ne: (i32, i32),
        yaw_cdeg: i32,
        wind_ff_cdeg: (i32, i32),
        dt_ms: u32,
    ) -> (i32, i32) {
        if dt_ms == 0 {
            return (0, 0);
        }
        let accel_n = self.axis_accel(
            target_pos_ne.0 - current_pos_ne.0,
            current_vel_ne.0,
            dt_ms,
            Axis::North,
        );
        let accel_e = self.axis_accel(
            target_pos_ne.1 - current_pos_ne.1,
            current_vel_ne.1,
            dt_ms,
            Axis::East,
        );

        // NED accel → body forward/right → pitch/roll.
        let (fwd, right) = ned_horizontal_to_body(accel_n, accel_e, yaw_cdeg);
        let pitch = clamp_i32(
            accel_to_tilt_cdeg(fwd) + wind_ff_cdeg.1,
            -POS_TILT_MAX_CDEG,
            POS_TILT_MAX_CDEG,
        );
        let roll = clamp_i32(
            accel_to_tilt_cdeg(right) + wind_ff_cdeg.0,
            -POS_TILT_MAX_CDEG,
            POS_TILT_MAX_CDEG,
        );
        (roll, pitch)
    }

    /// One axis of the cascade: position error + measured velocity → accel.
    fn axis_accel(&mut self, pos_err: i32, vel: i32, dt_ms: u32, axis: Axis) -> i32 {
        // P: position error → velocity setpoint, clamped to cruise speed.
        let vel_sp = clamp_i32(
            (pos_err as i64 * POS_VEL_P_NUM as i64 / POS_VEL_P_DEN as i64) as i32,
            -MAX_VEL_MMS,
            MAX_VEL_MMS,
        );
        let vel_err = vel_sp - vel;

        // I: accumulate vel_err·dt (mm/s · s), clamped (anti-windup).
        let integ = match axis {
            Axis::North => &mut self.vel_i_n,
            Axis::East => &mut self.vel_i_e,
        };
        *integ = clamp_i32(
            *integ + (vel_err as i64 * dt_ms as i64 / 1_000) as i32,
            -VEL_I_MAX,
            VEL_I_MAX,
        );

        // PI → acceleration, clamped.
        let acc_p = (vel_err as i64 * VEL_ACC_P_NUM as i64 / VEL_ACC_P_DEN as i64) as i32;
        let acc_i = (*integ as i64 * VEL_ACC_I_NUM as i64 / VEL_ACC_I_DEN as i64) as i32;
        clamp_i32(acc_p + acc_i, -MAX_ACC_MMSS, MAX_ACC_MMSS)
    }

    /// Reset integrators (on disarm or mode change).
    pub fn reset(&mut self) {
        *self = PositionController::new();
    }
}

#[derive(Clone, Copy)]
enum Axis {
    North,
    East,
}
