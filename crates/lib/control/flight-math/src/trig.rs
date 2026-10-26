// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Integer trigonometry (lookup-table based), shared across the flight crate.
//!
//! All angles are in centi-degrees (cdeg); results are scaled ×1000 so that
//! `sin1000(9_000) == 1000` represents `sin(90°) = 1.0`. Integer-only — no
//! floating point, so it is usable from any kernel context.
//!
//! Extracted from `slam.rs` so that `slam` and `wind` share one table
//! (previously each module carried its own copy).

/// Output scale factor: `sin1000`/`cos1000` return values in `[-SCALE, SCALE]`.
pub const TRIG_SCALE: i32 = 1_000;

/// Centi-degrees in a full circle.
pub const FULL_CIRCLE_CDEG: i32 = 36_000;

/// Centi-degrees in a quarter circle (90°).
pub const QUARTER_CIRCLE_CDEG: i32 = 9_000;

/// Sine of an angle in centi-degrees, scaled ×[`TRIG_SCALE`].
///
/// Uses a 90-entry first-quadrant table (sin 0°..89° in 1° steps) plus the
/// quadrant identities to cover the full circle. Linearly interpolates
/// between table entries for sub-degree resolution.
pub fn sin1000(cdeg: i32) -> i32 {
    // Reduce to [0, FULL_CIRCLE_CDEG) and map to quadrant.
    let cdeg = ((cdeg % FULL_CIRCLE_CDEG) + FULL_CIRCLE_CDEG) % FULL_CIRCLE_CDEG;
    let q = cdeg / QUARTER_CIRCLE_CDEG;
    let r = cdeg % QUARTER_CIRCLE_CDEG;

    // Lookup table: sin(0°..89°) in 1° steps, scaled × TRIG_SCALE.
    // Entry 89 = sin(89°) ≈ 1000 serves as the sin(90°) boundary value.
    const SIN_LUT: [i32; 90] = [
        0, 17, 35, 52, 70, 87, 105, 122, 139, 156, 174, 191, 208, 225, 242, 259, 276, 292, 309,
        326, 342, 358, 375, 391, 407, 423, 438, 454, 469, 485, 500, 515, 530, 545, 559, 574,
        588, 602, 616, 629, 643, 656, 669, 682, 695, 707, 719, 731, 743, 755, 766, 777, 788,
        799, 809, 819, 829, 839, 848, 857, 866, 875, 883, 891, 899, 906, 914, 921, 927, 934,
        940, 946, 951, 956, 961, 966, 970, 974, 978, 982, 985, 988, 990, 993, 995, 996, 998,
        999, 999, 1000,
    ];

    /// Degrees per table entry, in centi-degrees.
    const CDEG_PER_ENTRY: i32 = 100;
    /// Highest valid table index (table covers 0°..89°).
    const LAST_ENTRY: i32 = 89;

    // Evaluate sin(r) for a first-quadrant angle r (0 ≤ r < QUARTER_CIRCLE_CDEG).
    let sin_q0 = |r: i32| -> i32 {
        let deg = (r / CDEG_PER_ENTRY).clamp(0, LAST_ENTRY) as usize;
        let frac = r % CDEG_PER_ENTRY;
        let s0 = SIN_LUT[deg];
        let s1 = SIN_LUT[(deg + 1).min(LAST_ENTRY as usize)];
        s0 + (s1 - s0) * frac / CDEG_PER_ENTRY
    };

    match q {
        0 => sin_q0(r),                          // sin(r)
        1 => sin_q0(QUARTER_CIRCLE_CDEG - r),    // sin(90°+r) = cos(r) = sin(90°−r)
        2 => -sin_q0(r),                         // sin(180°+r) = −sin(r)
        _ => -sin_q0(QUARTER_CIRCLE_CDEG - r),   // sin(270°+r) = −cos(r)
    }
}

/// Cosine of an angle in centi-degrees, scaled ×[`TRIG_SCALE`].
pub fn cos1000(cdeg: i32) -> i32 {
    sin1000(cdeg + QUARTER_CIRCLE_CDEG)
}

// Unit tests live in `tests/host/flight-math-tests` (host target).
