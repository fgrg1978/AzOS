// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Terrain-following PD controller — pure-logic mirror of terrain.rs (D05).
//!
//! Stateless version that takes all inputs as parameters, making it directly
//! unit-testable without global atomics.

// ── Constants ─────────────────────────────────────────────────────────────────

/// Proportional gain (throttle units per metre error, gains are × 1000).
pub const TERRAIN_KP: i32 = 100;
/// Derivative gain (throttle units per metre/s, gains are × 1000).
pub const TERRAIN_KD: i32 = 50;
/// Maximum throttle trim authority (prevents runaway).
pub const TERRAIN_MAX_TRIM: i32 = 200;
/// Minimum valid rangefinder reading (mm).
pub const TERRAIN_RANGE_MIN_MM: i32 = 100;
/// Maximum valid rangefinder reading (mm).
pub const TERRAIN_RANGE_MAX_MM: i32 = 10_000;

// ── Pure PD function ─────────────────────────────────────────────────────────

/// Compute terrain-following throttle trim.
///
/// - `target_agl_mm`: desired height above ground (mm)
/// - `range_mm`: current rangefinder reading (mm)
/// - `prev_error`: error from previous call (mm)
/// - `dt_ms`: time step (ms)
///
/// Returns `(trim, new_error)`.  `trim` is 0 if the range is invalid.
pub fn terrain_pd(
    target_agl_mm: i32,
    range_mm: i32,
    prev_error: i32,
    dt_ms: u32,
) -> (i32, i32) {
    if range_mm < TERRAIN_RANGE_MIN_MM || range_mm > TERRAIN_RANGE_MAX_MM {
        return (0, prev_error); // hold previous error, no update
    }
    let error  = target_agl_mm - range_mm;
    let p_term = TERRAIN_KP * error / 1_000;
    let d_term = if dt_ms > 0 {
        TERRAIN_KD * (error - prev_error) * 1_000 / dt_ms as i32 / 1_000
    } else {
        0
    };
    let trim = (p_term + d_term).clamp(-TERRAIN_MAX_TRIM, TERRAIN_MAX_TRIM);
    (trim, error)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// At target height, error=0 → trim=0.
    #[test]
    fn at_target_trim_zero() {
        let target = 3_000;
        let (trim, err) = terrain_pd(target, target, 0, 100);
        assert_eq!(err, 0);
        assert_eq!(trim, 0);
    }

    /// Below target (too close to ground) → positive trim (climb).
    #[test]
    fn below_target_positive_trim() {
        let (trim, _) = terrain_pd(3_000, 2_000, 0, 100);
        assert!(trim > 0, "Below target: trim should be positive, got {}", trim);
    }

    /// Above target (too high) → negative trim (descend).
    #[test]
    fn above_target_negative_trim() {
        let (trim, _) = terrain_pd(3_000, 4_000, 0, 100);
        assert!(trim < 0, "Above target: trim should be negative, got {}", trim);
    }

    /// Trim clamped at TERRAIN_MAX_TRIM for large errors.
    #[test]
    fn large_error_clamped() {
        let (trim, _) = terrain_pd(3_000, 100, 0, 100);
        assert_eq!(trim, TERRAIN_MAX_TRIM,
            "Large positive error should clamp to {}", TERRAIN_MAX_TRIM);
    }

    #[test]
    fn large_negative_error_clamped() {
        let (trim, _) = terrain_pd(100, 9_000, 0, 100);
        assert_eq!(trim, -TERRAIN_MAX_TRIM,
            "Large negative error should clamp to -{}", TERRAIN_MAX_TRIM);
    }

    /// Invalid (too low) range → trim 0, error unchanged.
    #[test]
    fn invalid_range_too_low() {
        let (trim, err) = terrain_pd(3_000, 50, 100, 100); // 50 mm < RANGE_MIN
        assert_eq!(trim, 0);
        assert_eq!(err, 100); // prev_error preserved
    }

    /// Invalid (too high) range → trim 0, error unchanged.
    #[test]
    fn invalid_range_too_high() {
        let (trim, err) = terrain_pd(3_000, 15_000, -50, 100);
        assert_eq!(trim, 0);
        assert_eq!(err, -50);
    }

    /// Derivative term adds damping: approaching from below dampens climb.
    #[test]
    fn derivative_dampens_approach() {
        // Error shrinking: prev_error=1000, current error=500 → negative Δerror
        let (trim_no_d, _) = terrain_pd(3_500, 3_000, 0,     100); // prev=0
        let (trim_w_d,  _) = terrain_pd(3_500, 3_000, 1_000, 100); // prev=1000 (was higher)
        // With prev_error > current_error, D term is negative → lower trim
        assert!(trim_w_d < trim_no_d,
            "Derivative damping: trim_w_d={} should be < trim_no_d={}", trim_w_d, trim_no_d);
    }

    /// dt_ms=0 → no D term, only P.
    #[test]
    fn zero_dt_uses_only_p_term() {
        let target = 3_000;
        let range  = 2_000;
        let error  = target - range; // 1000 mm
        let p_only = (TERRAIN_KP * error / 1_000).clamp(-TERRAIN_MAX_TRIM, TERRAIN_MAX_TRIM);
        let (trim, _) = terrain_pd(target, range, 500, 0); // dt=0
        assert_eq!(trim, p_only);
    }

    /// Error value returned matches expected.
    #[test]
    fn error_return_value() {
        let target = 3_000;
        let range  = 2_500;
        let (_, err) = terrain_pd(target, range, 0, 100);
        assert_eq!(err, target - range);
    }
}
