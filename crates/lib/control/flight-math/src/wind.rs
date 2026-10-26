// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wind / disturbance estimation for multirotors (D04).
//!
//! Estimates the steady horizontal acceleration acting on the craft that is
//! **not** explained by the commanded tilt — i.e. aerodynamic wind drag plus
//! any other slow disturbance — and converts it into a feed-forward tilt bias
//! that would counteract it.
//!
//! ## Why acceleration-residual (not velocity- or position-error)
//! A working position controller drives ground velocity *and* position error to
//! zero in steady state even under constant wind, so neither encodes wind once
//! converged. What always encodes wind is the **acceleration residual**:
//! ```text
//!   a_residual = a_measured − a_commanded
//! ```
//! In steady flight the craft's true horizontal acceleration equals the sum of
//! the commanded thrust-tilt acceleration and the wind drag acceleration, so the
//! residual converges to the wind contribution (this is the PX4/ArduPilot
//! approach). The estimator is a first-order low-pass (IIR) over that residual.
//!
//! ## Frames & units (consistent with `ekf.rs`)
//! - NED: N=north, E=east, D=down. Horizontal pair is `(north, east)`.
//! - Body: X=forward (nose), Y=right, Z=down.
//! - Accelerations in **mm/s²**. Angles in **centi-degrees** (cdeg).
//! - Attitude sign convention matches `rc_to_target`: positive `pitch_cdeg`
//!   leans the craft so it accelerates **forward**; positive `roll_cdeg`
//!   accelerates **right**.
//!
//! ## Statelessness / testability
//! [`WindEstimator`] holds only its own filtered estimate. Every input is passed
//! explicitly to [`WindEstimator::update`]; it never reads global state (EKF,
//! attitude channel), so it is unit-testable as a pure struct.

use crate::trig::{cos1000, sin1000, TRIG_SCALE};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Gravity in mm/s² (9.81 m/s²), matching `ekf::GRAVITY_MMSQ`.
pub const GRAVITY_MMSS: i32 = 9_810;

/// Low-pass time constant for the residual filter, in milliseconds.
///
/// Wind is a slow disturbance relative to attitude dynamics; a ~2 s constant
/// rejects gust transients and IMU noise while still tracking sustained wind.
pub const WIND_FILTER_TAU_MS: i32 = 2_000;

/// Clamp on the estimated wind acceleration per axis (mm/s²).
///
/// 0.5 g — beyond this the "residual" is almost certainly a manoeuvre or a
/// sensor fault, not wind, so we refuse to attribute it to wind.
pub const WIND_ACC_MAX_MMSS: i32 = GRAVITY_MMSS / 2;

/// Centi-degrees per radian (≈ 18000/π), for the small-angle accel→tilt map.
pub const RAD_TO_CDEG: i32 = 5_730;

/// Clamp on the feed-forward tilt bias per axis (cdeg).
///
/// 15° — a generous ceiling; a healthy compensation against strong wind rarely
/// needs more, and capping here bounds the authority handed to the feed-forward.
pub const TILT_BIAS_MAX_CDEG: i32 = 1_500;

// ── Geometry helpers ────────────────────────────────────────────────────────

/// Horizontal acceleration (mm/s², NED) produced by a commanded tilt.
///
/// Small-angle thrust model: a craft tilted by angle θ accelerates by
/// `g·sin(θ)` in the lean direction. Body forward/right accelerations are then
/// rotated into NED by the yaw angle.
///
/// Returns `(a_north, a_east)` in mm/s².
pub fn commanded_accel_ned(roll_cdeg: i32, pitch_cdeg: i32, yaw_cdeg: i32) -> (i32, i32) {
    // Body-frame horizontal accelerations from tilt (g·sin(angle)).
    let a_fwd = GRAVITY_MMSS * sin1000(pitch_cdeg) / TRIG_SCALE; // +X (forward)
    let a_right = GRAVITY_MMSS * sin1000(roll_cdeg) / TRIG_SCALE; // +Y (right)
    body_horizontal_to_ned(a_fwd, a_right, yaw_cdeg)
}

/// Rotate a body-frame horizontal vector `(forward, right)` into NED `(n, e)`
/// by the yaw angle. Pure 2-D rotation:
/// ```text
///   n = fwd·cos(ψ) − right·sin(ψ)
///   e = fwd·sin(ψ) + right·cos(ψ)
/// ```
pub fn body_horizontal_to_ned(fwd: i32, right: i32, yaw_cdeg: i32) -> (i32, i32) {
    let c = cos1000(yaw_cdeg);
    let s = sin1000(yaw_cdeg);
    let n = (fwd * c - right * s) / TRIG_SCALE;
    let e = (fwd * s + right * c) / TRIG_SCALE;
    (n, e)
}

/// Rotate an NED horizontal vector `(n, e)` into body-frame `(forward, right)`
/// by the yaw angle. Inverse of [`body_horizontal_to_ned`]:
/// ```text
///   fwd   =  n·cos(ψ) + e·sin(ψ)
///   right = −n·sin(ψ) + e·cos(ψ)
/// ```
pub fn ned_horizontal_to_body(n: i32, e: i32, yaw_cdeg: i32) -> (i32, i32) {
    let c = cos1000(yaw_cdeg);
    let s = sin1000(yaw_cdeg);
    let fwd = (n * c + e * s) / TRIG_SCALE;
    let right = (-n * s + e * c) / TRIG_SCALE;
    (fwd, right)
}

/// Convert a horizontal acceleration (mm/s²) into the tilt angle (cdeg) that
/// would produce it, using the small-angle inverse of `a = g·sin(θ)`:
/// `θ ≈ (a/g) rad`. Result clamped to [`TILT_BIAS_MAX_CDEG`].
pub fn accel_to_tilt_cdeg(accel_mmss: i32) -> i32 {
    let cdeg = accel_mmss * RAD_TO_CDEG / GRAVITY_MMSS;
    cdeg.clamp(-TILT_BIAS_MAX_CDEG, TILT_BIAS_MAX_CDEG)
}

// ── Estimator ─────────────────────────────────────────────────────────────────

/// First-order low-pass estimator of the horizontal wind acceleration (NED).
#[derive(Clone, Copy, Default)]
pub struct WindEstimator {
    /// Filtered wind acceleration, north axis (mm/s²).
    wind_acc_n: i32,
    /// Filtered wind acceleration, east axis (mm/s²).
    wind_acc_e: i32,
    /// Set once the first sample has been folded in.
    initialized: bool,
}

impl WindEstimator {
    pub const fn new() -> Self {
        WindEstimator { wind_acc_n: 0, wind_acc_e: 0, initialized: false }
    }

    /// Fold one sample into the estimate.
    ///
    /// - `meas_acc_n/e`: measured horizontal acceleration in NED (mm/s²),
    ///   e.g. from differentiated EKF velocity or rotated IMU specific force.
    /// - `cmd_acc_n/e`: acceleration the commanded tilt *should* produce, from
    ///   [`commanded_accel_ned`].
    /// - `dt_ms`: time since the previous update (ms).
    ///
    /// Residual `meas − cmd` is the unmodelled (wind) acceleration; it is
    /// low-pass filtered with time constant [`WIND_FILTER_TAU_MS`].
    pub fn update(
        &mut self,
        meas_acc_n: i32,
        meas_acc_e: i32,
        cmd_acc_n: i32,
        cmd_acc_e: i32,
        dt_ms: u32,
    ) {
        if dt_ms == 0 {
            return;
        }
        let residual_n = meas_acc_n - cmd_acc_n;
        let residual_e = meas_acc_e - cmd_acc_e;

        if !self.initialized {
            // Seed directly so we don't spend several τ ramping from zero.
            self.wind_acc_n = residual_n;
            self.wind_acc_e = residual_e;
            self.initialized = true;
        } else {
            // IIR: estimate += (residual − estimate) · α, with α = dt/τ ≤ 1.
            // Integer form keeps the (residual−estimate)·dt product before the
            // divide to preserve resolution.
            let alpha_num = (dt_ms as i32).min(WIND_FILTER_TAU_MS);
            self.wind_acc_n += (residual_n - self.wind_acc_n) * alpha_num / WIND_FILTER_TAU_MS;
            self.wind_acc_e += (residual_e - self.wind_acc_e) * alpha_num / WIND_FILTER_TAU_MS;
        }

        self.wind_acc_n = self.wind_acc_n.clamp(-WIND_ACC_MAX_MMSS, WIND_ACC_MAX_MMSS);
        self.wind_acc_e = self.wind_acc_e.clamp(-WIND_ACC_MAX_MMSS, WIND_ACC_MAX_MMSS);
    }

    /// Current wind acceleration estimate `(north, east)` in mm/s².
    pub fn wind_accel_ne(&self) -> (i32, i32) {
        (self.wind_acc_n, self.wind_acc_e)
    }

    /// Feed-forward tilt bias `(roll_cdeg, pitch_cdeg)` that counteracts the
    /// estimated wind for the given heading.
    ///
    /// To cancel a wind acceleration the craft must produce the opposite
    /// acceleration, which means tilting *into* the wind — hence the negation.
    /// The counter-acceleration is rotated NED→body, then each body axis is
    /// mapped to a tilt angle: forward→pitch, right→roll.
    pub fn tilt_bias_cdeg(&self, yaw_cdeg: i32) -> (i32, i32) {
        let (fwd, right) = ned_horizontal_to_body(-self.wind_acc_n, -self.wind_acc_e, yaw_cdeg);
        let pitch = accel_to_tilt_cdeg(fwd);
        let roll = accel_to_tilt_cdeg(right);
        (roll, pitch)
    }

    /// Reset the estimate (e.g. on disarm or mode change).
    pub fn reset(&mut self) {
        *self = WindEstimator::new();
    }
}

// Unit tests live in `tests/host/flight-math-tests` (host target).
