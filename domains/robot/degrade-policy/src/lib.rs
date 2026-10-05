// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RFC-0037 degrade taxonomy and actuation policy — dep-free leaf crate.
//!
//! Owns the graded degrade LEVEL constants and the level→speed-ceiling
//! mapping. Having these in a dep-free leaf lets both `crates/core/ipc` (TCB)
//! and `domains/robot/behavior` (safety domain) depend on them without polluting
//! the TCB with motor-actuation policy.
//!
//! ## Design
//!
//! The crate has ZERO dependencies (no `azos_*`, no proc-macros).
//! It is `no_std` in production builds and enables `std` only for the
//! in-crate test suite (the `#[cfg(test)]` block needs `libtest`).
//!
//! The level taxonomy is an ordered enum encoded as `u8`:
//!
//! ```text
//! FULL (0) < CAUTIOUS (1) < SLOW (2) < CONTAINED (3)
//! ```
//!
//! Higher level = more restrictive. Fail-closed: any unknown/out-of-range
//! level is treated as CONTAINED (level 3, 0 % speed).

#![cfg_attr(not(test), no_std)]

// ──────────────────────────────────────────────────────────────────────────
// Graded degrade levels — single source of truth (RFC-0037)
// ──────────────────────────────────────────────────────────────────────────

/// No extra restriction — normal operation. Speed cap: per-type maximum.
pub const DEGRADE_LEVEL_FULL: u8 = 0;

/// Cautious operation — brain perceived a mild situational risk.
/// Speed ceiling: 70 % of per-type maximum.
pub const DEGRADE_LEVEL_CAUTIOUS: u8 = 1;

/// Slow operation — brain perceived a significant situational risk.
/// Speed ceiling: 30 % of per-type maximum.
pub const DEGRADE_LEVEL_SLOW: u8 = 2;

/// Full containment — brain perceived a critical hazard or went blind.
/// Speed ceiling: 0 % (stop). Additionally, every user-task write/actuation
/// capability is denied at the `CapTable::get` chokepoint (RFC-0036 semantics).
pub const DEGRADE_LEVEL_CONTAINED: u8 = 3;

/// Maximum valid level index (= `DEGRADE_LEVEL_CONTAINED`). Any out-of-range
/// index received over the wire is clamped to this value (fail-closed).
pub const DEGRADE_LEVEL_MAX: u8 = DEGRADE_LEVEL_CONTAINED;

// ──────────────────────────────────────────────────────────────────────────
// Per-level speed ceilings (RFC-0037) — single source of truth
// ──────────────────────────────────────────────────────────────────────────
//
// PLACEHOLDER VALUES — owner decision recorded 2026-09-06.
//
// `DEGRADE_SPEED_CAP_CAUTIOUS_PCT` (70) and `DEGRADE_SPEED_CAP_SLOW_PCT` (30)
// were CHOSEN, not derived. No stopping-distance model and no measurement of
// any kind supports either number, and none was ever attempted. They are
// plausible-looking and consistent between this kernel and the brain
// (`../AzOSRobotBrain/protocol.py`), which is not the same thing as being safe.
//
// A robot's real safe speed under degradation is a function of its mass,
// its brake authority, and its sensor range at the perceived hazard — none
// of which this kernel knows anything about. A wheelchair-class robot and a
// warehouse forklift-class robot do not share a safe "70 %", and this crate
// has no way to tell them apart.
//
// Given the owner's decision, these stay placeholders on record — a
// deliberate choice to ship the fail-closed *shape* (four ordered levels,
// each strictly more restrictive, unknown input clamps to the tightest) now,
// without pretending the two interior numbers are engineering. Replacing
// them requires either (a) a per-robot-type stopping-distance model driven
// by real mass/brake/sensor parameters, or (b) a measured stopping distance
// per robot type at each level, validated against that model. Until one of
// those exists, no deployment may treat `70` or `30` as a validated safe
// ceiling — they are a known-arbitrary interim value, not a safety
// engineering result.

/// Speed ceiling (% of per-type max) at `DEGRADE_LEVEL_FULL`: no extra cap.
pub const DEGRADE_SPEED_CAP_FULL_PCT: i32 = 100;

/// Speed ceiling at `DEGRADE_LEVEL_CAUTIOUS`: 70 % of per-type maximum.
/// Matches the value documented in RFC-0037 and enforced in `motor_envelope`.
///
/// **Placeholder, not derived.** See the module-level note above this block:
/// no stopping-distance model, no measurement — chosen, on record as such
/// since 2026-09-06.
pub const DEGRADE_SPEED_CAP_CAUTIOUS_PCT: i32 = 70;

/// Speed ceiling at `DEGRADE_LEVEL_SLOW`: 30 % of per-type maximum.
///
/// **Placeholder, not derived.** See the module-level note above this block:
/// no stopping-distance model, no measurement — chosen, on record as such
/// since 2026-09-06.
pub const DEGRADE_SPEED_CAP_SLOW_PCT: i32 = 30;

/// Speed ceiling at `DEGRADE_LEVEL_CONTAINED`: 0 % (full stop).
/// Complements cap-denial in `CapTable::get`; both layers are required.
pub const DEGRADE_SPEED_CAP_CONTAINED_PCT: i32 = 0;

// ──────────────────────────────────────────────────────────────────────────
// Mapping function
// ──────────────────────────────────────────────────────────────────────────

/// Map a degrade level to the corresponding motor speed ceiling (% of max).
///
/// Pure function — no I/O, no allocation, O(1). Intended for use in
/// `motor_envelope` (behavior/safety.rs) at the per-command chokepoint.
///
/// The catch-all arm maps any unknown/future level to
/// `DEGRADE_SPEED_CAP_CONTAINED_PCT` (0) — fail-closed: an unrecognised
/// level stops the robot rather than silently passing through at full speed.
#[inline]
pub const fn level_cap_pct(level: u8) -> i32 {
    match level {
        DEGRADE_LEVEL_FULL      => DEGRADE_SPEED_CAP_FULL_PCT,
        DEGRADE_LEVEL_CAUTIOUS  => DEGRADE_SPEED_CAP_CAUTIOUS_PCT,
        DEGRADE_LEVEL_SLOW      => DEGRADE_SPEED_CAP_SLOW_PCT,
        _                       => DEGRADE_SPEED_CAP_CONTAINED_PCT,
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────
//
// These assert the *literal* RFC-specified speed-ceiling percentages, NOT
// the named DEGRADE_SPEED_CAP_* constants — that way a wrong constant value
// causes a test failure rather than a silent tautology.
//
// Inputs: named DEGRADE_LEVEL_* constants (tests the level routing).
// Outputs: literal integers (tests the RFC contract for those values).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_cap_pct_full_is_100() {
        // FULL → no extra restriction; 100 means the per-type cap applies unchanged.
        assert_eq!(level_cap_pct(DEGRADE_LEVEL_FULL), 100);
    }

    #[test]
    fn level_cap_pct_cautious_is_70() {
        // RFC-0037 §CAUTIOUS: mild situational risk → 70 % of per-type maximum.
        assert_eq!(level_cap_pct(DEGRADE_LEVEL_CAUTIOUS), 70);
    }

    #[test]
    fn level_cap_pct_slow_is_30() {
        // RFC-0037 §SLOW: significant situational risk → 30 % of per-type maximum.
        assert_eq!(level_cap_pct(DEGRADE_LEVEL_SLOW), 30);
    }

    #[test]
    fn level_cap_pct_contained_is_0() {
        // RFC-0037 §CONTAINED: critical hazard → full stop (0 %).
        assert_eq!(level_cap_pct(DEGRADE_LEVEL_CONTAINED), 0);
    }

    #[test]
    fn level_cap_pct_unknown_clamps_to_0() {
        // Out-of-range level → fail-closed (0 %), never silently passes at 100.
        assert_eq!(level_cap_pct(99), 0);
        assert_eq!(level_cap_pct(4), 0);
        assert_eq!(level_cap_pct(255), 0);
    }

    #[test]
    fn level_cap_pct_order_is_monotone_decreasing() {
        // Higher levels must be progressively more restrictive — a structural
        // invariant of the RFC. Any reordering of the match arms that breaks
        // the monotone property is caught here.
        assert!(level_cap_pct(DEGRADE_LEVEL_FULL) > level_cap_pct(DEGRADE_LEVEL_CAUTIOUS));
        assert!(level_cap_pct(DEGRADE_LEVEL_CAUTIOUS) > level_cap_pct(DEGRADE_LEVEL_SLOW));
        assert!(level_cap_pct(DEGRADE_LEVEL_SLOW) > level_cap_pct(DEGRADE_LEVEL_CONTAINED));
        assert_eq!(level_cap_pct(DEGRADE_LEVEL_CONTAINED), 0);
    }
}
