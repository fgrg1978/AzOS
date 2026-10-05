// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! EKF scalar Kalman update — testable mirror of flight/src/ekf.rs (D01).
//!
//! Extracts the core filter mathematics as pure functions so they can be
//! exercised on the host without the no_std / SpinLock dependency chain.

// ── Constants ─────────────────────────────────────────────────────────────────

/// Fixed-point scale factor.
pub const EKF_SCALE: i64 = 1_000;
/// Minimum covariance enforced after each update.
pub const EKF_P_MIN: i64 = EKF_SCALE;

/// Process noise — position states.
pub const Q_POS: i64 = 100 * EKF_SCALE;
/// Process noise — velocity states.
pub const Q_VEL: i64 = 500 * EKF_SCALE;
/// Process noise — attitude states.
pub const Q_ATT: i64 = 10  * EKF_SCALE;

/// Measurement noise — GPS position.
pub const R_GPS_POS: i64 = 1_000_000 * EKF_SCALE;
/// Measurement noise — barometer.
pub const R_BARO: i64 = 10_000 * EKF_SCALE;
/// Measurement noise — optical flow.
pub const R_FLOW: i64 = 5_000 * EKF_SCALE;

/// Gravity (mm/s²).
pub const GRAVITY_MMSQ: i64 = 9_810;

// ── Pure math ─────────────────────────────────────────────────────────────────

/// Scalar Kalman update: `H = I` (direct measurement of the state).
///
/// - `x`: current state estimate
/// - `p`: current state covariance (> 0)
/// - `z`: measurement
/// - `r`: measurement noise covariance (> 0)
///
/// Returns `(x_new, p_new)`.
pub fn scalar_update(x: i64, p: i64, z: i64, r: i64) -> (i64, i64) {
    let y = z - x;
    let s = p + r;
    if s == 0 { return (x, p); }
    let k_scaled = p * 1_000 / s;       // Kalman gain × 1000
    let x_new = x + k_scaled * y / 1_000;
    let p_new = p - k_scaled * p / 1_000;
    (x_new, p_new.max(EKF_P_MIN))
}

/// Predict (propagate) a single state + covariance by adding process noise.
pub fn predict_state(x: i64, p: i64, accel_contribution: i64, dt_ms: i64, q: i64) -> (i64, i64) {
    let x_new = x + accel_contribution * dt_ms / 1_000;
    let p_new = p + q;
    (x_new, p_new)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// State matches measurement exactly → no update needed → covariance shrinks.
    #[test]
    fn exact_measurement_no_state_change() {
        let x = 1_000_i64;
        let p = R_GPS_POS;
        let (x_new, _) = scalar_update(x, p, x, R_GPS_POS); // z == x
        assert_eq!(x_new, x, "State should not change when z == x");
    }

    /// Measurement pulls state toward z.
    #[test]
    fn measurement_moves_state_toward_z() {
        let x = 0_i64;
        let p = R_GPS_POS;
        let z = 1_000_i64;
        let (x_new, _) = scalar_update(x, p, z, R_GPS_POS);
        assert!(x_new > x && x_new < z,
            "State should move toward measurement: x={} x_new={} z={}", x, x_new, z);
    }

    /// High confidence (low P) → measurement has less effect.
    #[test]
    fn high_confidence_resists_measurement() {
        let x = 0_i64;
        let z = 10_000_i64;
        let (x_high_conf, _) = scalar_update(x, EKF_P_MIN, z, R_GPS_POS);
        let (x_low_conf,  _) = scalar_update(x, R_GPS_POS,  z, R_GPS_POS);
        // Lower P → smaller K → less state movement.
        assert!(x_high_conf < x_low_conf,
            "High confidence state should move less: {} vs {}", x_high_conf, x_low_conf);
    }

    /// High measurement noise (large R) → measurement has less effect.
    #[test]
    fn high_noise_resists_measurement() {
        let x = 0_i64;
        let z = 10_000_i64;
        let p = R_GPS_POS;
        let (x_high_r, _) = scalar_update(x, p, z, R_GPS_POS * 100);
        let (x_low_r,  _) = scalar_update(x, p, z, R_GPS_POS);
        assert!(x_high_r < x_low_r,
            "High noise should move state less: {} vs {}", x_high_r, x_low_r);
    }

    /// Covariance always decreases after a valid measurement update.
    #[test]
    fn covariance_decreases_after_update() {
        let x = 0_i64;
        let p = R_GPS_POS;
        let z = 5_000_i64;
        let (_, p_new) = scalar_update(x, p, z, R_GPS_POS);
        assert!(p_new < p, "P should decrease after update: {} vs {}", p_new, p);
    }

    /// Covariance is clamped to at least EKF_P_MIN.
    #[test]
    fn covariance_floor_enforced() {
        // With very small P and large R, K ≈ 0 → P_new ≈ P. But let's force floor.
        let (_, p_new) = scalar_update(0, EKF_P_MIN, 1_000, R_GPS_POS);
        assert!(p_new >= EKF_P_MIN,
            "P should never fall below EKF_P_MIN: got {}", p_new);
    }

    /// Repeated updates converge state toward true value.
    #[test]
    fn repeated_updates_converge() {
        let true_value: i64 = 5_000; // mm
        let mut x: i64 = 0;
        let mut p: i64 = R_GPS_POS;
        for _ in 0..20 {
            let (xn, pn) = scalar_update(x, p, true_value, R_GPS_POS);
            x = xn; p = pn;
        }
        // After 20 GPS updates, state should be within 10% of true value.
        let error = (x - true_value).abs();
        assert!(error < true_value / 10,
            "Should converge near true value {}: got {} (error {})", true_value, x, error);
    }

    /// S=0 guard: does not panic.
    #[test]
    fn zero_denominator_safe() {
        // S = P + R = 0 only when both are 0, which should just return (x, p).
        let (x_out, p_out) = scalar_update(42, 0, 100, 0);
        assert_eq!(x_out, 42);
        assert_eq!(p_out, 0);
    }

    /// Predict: covariance grows by Q.
    #[test]
    fn predict_covariance_grows() {
        let (_, p_new) = predict_state(0, EKF_P_MIN, 0, 10, Q_POS);
        assert_eq!(p_new, EKF_P_MIN + Q_POS);
    }

    /// Predict: state advances by velocity × dt.
    #[test]
    fn predict_state_integrates_velocity() {
        // Treat x as position, accel_contribution as velocity (mm/s).
        let vel: i64 = 1_000; // 1000 mm/s
        let dt_ms: i64 = 100; // 100 ms
        let (x_new, _) = predict_state(0, Q_POS, vel, dt_ms, Q_POS);
        assert_eq!(x_new, 100); // 1000 mm/s × 0.1 s = 100 mm
    }

    /// Process noise constants are positive and ordered reasonably.
    #[test]
    fn noise_constants_sane() {
        assert!(Q_POS > 0);
        assert!(Q_VEL > 0);
        assert!(Q_ATT > 0);
        assert!(R_GPS_POS > R_BARO, "GPS noisier than baro for position");
        assert!(R_BARO > R_FLOW,   "Baro noisier than flow for velocity proxy");
    }
}
