// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Integer sine/cosine — exact mirror of slam.rs sin1000/cos1000 (D06).
//!
//! Values are scaled × 1000 so 1.000 == 1000 (avoids floating point).
//! Angle unit: centi-degrees (cdeg); 36000 cdeg = 360°.

/// Look-up table: sin(0°..89°) in 1° steps, scaled × 1000.
const SIN_LUT: [i32; 90] = [
    0,17,35,52,70,87,105,122,139,156,174,191,208,225,242,259,276,292,309,
    326,342,358,375,391,407,423,438,454,469,485,500,515,530,545,559,574,
    588,602,616,629,643,656,669,682,695,707,719,731,743,755,766,777,788,
    799,809,819,829,839,848,857,866,875,883,891,899,906,914,921,927,934,
    940,946,951,956,961,966,970,974,978,982,985,988,990,993,995,996,998,
    999,999,1000,
];

/// Evaluate the LUT for a first-quadrant angle (0 ≤ r < 9000 cdeg).
/// Returns sin(r) × 1000 with linear interpolation between degree steps.
fn sin_q0(r: i32) -> i32 {
    let deg  = (r / 100).clamp(0, 89) as usize;
    let frac = r % 100;
    let s0 = SIN_LUT[deg];
    let s1 = SIN_LUT[(deg + 1).min(89)];
    s0 + (s1 - s0) * frac / 100
}

/// sin(angle_cdeg) × 1000.  Full 360° range.
///
/// Uses the identity sin(90°+α) = cos(α) = sin(90°−α) for Q1 and Q3,
/// so the same 90-entry table covers all quadrants correctly.
pub fn sin1000(cdeg: i32) -> i32 {
    let cdeg = ((cdeg % 36_000) + 36_000) % 36_000;
    let q = cdeg / 9_000;
    let r = cdeg % 9_000;
    match q {
        0 =>  sin_q0(r),            // sin(r)
        1 =>  sin_q0(9_000 - r),    // sin(90°+r) = cos(r) = sin(90°−r)
        2 => -sin_q0(r),            // sin(180°+r) = −sin(r)
        _ => -sin_q0(9_000 - r),    // sin(270°+r) = −cos(r)
    }
}

/// cos(angle_cdeg) × 1000.  Derived from sin by 90° phase shift.
pub fn cos1000(cdeg: i32) -> i32 { sin1000(cdeg + 9_000) }

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Allowed error tolerance (scaled × 1000, i.e. ±2 counts = ±0.002).
    const TOL: i32 = 2;

    fn near(got: i32, want: i32) -> bool { (got - want).abs() <= TOL }

    #[test]
    fn sin_cardinal_angles() {
        assert!(near(sin1000(0),       0),    "sin(0°)   got {}", sin1000(0));
        assert!(near(sin1000(9_000),   1000), "sin(90°)  got {}", sin1000(9_000));
        assert!(near(sin1000(18_000),  0),    "sin(180°) got {}", sin1000(18_000));
        assert!(near(sin1000(27_000), -1000), "sin(270°) got {}", sin1000(27_000));
        assert!(near(sin1000(36_000),  0),    "sin(360°) got {}", sin1000(36_000));
    }

    #[test]
    fn cos_cardinal_angles() {
        assert!(near(cos1000(0),       1000), "cos(0°)   got {}", cos1000(0));
        assert!(near(cos1000(9_000),   0),    "cos(90°)  got {}", cos1000(9_000));
        assert!(near(cos1000(18_000), -1000), "cos(180°) got {}", cos1000(18_000));
        assert!(near(cos1000(27_000),  0),    "cos(270°) got {}", cos1000(27_000));
    }

    #[test]
    fn sin_45_approx() {
        // sin(45°) = 0.7071 → scaled 707
        let v = sin1000(4_500);
        assert!((v - 707).abs() <= 2, "sin(45°) got {}", v);
    }

    #[test]
    fn sin_30_approx() {
        // sin(30°) = 0.5 → 500
        let v = sin1000(3_000);
        assert!((v - 500).abs() <= 2, "sin(30°) got {}", v);
    }

    #[test]
    fn sin_120_approx() {
        // sin(120°) = sin(60°) = 0.866 → 866
        let v = sin1000(12_000);
        assert!((v - 866).abs() <= 2, "sin(120°) got {}", v);
    }

    #[test]
    fn pythagorean_identity() {
        // sin²θ + cos²θ ≈ 1 (scaled: (sin1000)² + (cos1000)² ≈ 1_000_000)
        for cdeg_steps in 0..36 {
            let cdeg = cdeg_steps * 1_000;
            let s = sin1000(cdeg);
            let c = cos1000(cdeg);
            let sum_sq = s * s / 1000 + c * c / 1000;
            // Expect ~1000 (i.e. 1.000 × 1000), allow ±5 for rounding
            assert!((sum_sq - 1000).abs() <= 5,
                "cdeg={} sin²+cos²={} (expected ~1000)", cdeg, sum_sq);
        }
    }

    #[test]
    fn negative_angles_wrap_correctly() {
        assert!(near(sin1000(-9_000), sin1000(27_000)), "sin(-90°) ≠ sin(270°)");
        assert!(near(cos1000(-9_000), cos1000(27_000)), "cos(-90°) ≠ cos(270°)");
    }

    #[test]
    fn angles_beyond_360_wrap_correctly() {
        assert!(near(sin1000(40_000), sin1000(4_000)), "sin(400°) wrap");
        assert!(near(cos1000(40_000), cos1000(4_000)), "cos(400°) wrap");
    }
}
