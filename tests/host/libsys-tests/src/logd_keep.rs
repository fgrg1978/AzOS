// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Which decision records `logd` writes (`userspace/services/logd/src/keep.rs`).

use crate::keep::{Keep, VERDICT_DENY, VERDICT_REFUSE};

const ADMIT: u8 = 0;
const PLACE: u8 = 2;

/// By default a migrating wake's placement (and any admission) stays out of
/// the files; refusals and denials go in. **Canary.** Make `admit` return true
/// for every verdict when `all` is off: the first assertion goes red.
#[test]
fn by_default_only_refusals_and_denials_reach_the_files() {
    let mut k = Keep::new(false, 1000, 5, 1000);
    assert!(!k.admit(PLACE) && !k.admit(ADMIT), "placements and admissions are not written");
    assert!(k.admit(VERDICT_REFUSE) && k.admit(VERDICT_DENY));
    assert_eq!(k.period(), 0, "what the policy leaves out is not counted as held back");
    let mut all = Keep::new(true, 1000, 5, 1000);
    assert!(all.admit(PLACE) && all.admit(ADMIT), "LOGD_DECISIONS_ALL writes every rule");
}

/// The rate limit holds back what passes it in a period and counts it, and
/// the next period starts afresh. **Canary.** Drop the `used >= per_period`
/// test: nothing is held back (red).
#[test]
fn a_refusal_storm_is_cut_at_the_rate_and_counted() {
    // 20 a second over 500 ms periods: 10 a period.
    let mut k = Keep::new(false, 20, 5, 500);
    let kept = (0..100).filter(|_| k.admit(VERDICT_REFUSE)).count();
    assert_eq!(kept, 10);
    assert_eq!(k.period(), 90, "the 90 held back are counted");
    assert!(k.admit(VERDICT_DENY), "a new period has its budget again");
    assert_eq!(k.period(), 0);
    // A rate below one a period still lets one through.
    let mut slow = Keep::new(false, 1, 5, 100);
    assert!(slow.admit(VERDICT_REFUSE) && !slow.admit(VERDICT_REFUSE));
}

const MOTOR: u16 = 2;
const MODE: u16 = 4;
const ERROR: u16 = 8;

/// Telemetry is cut at the rate per kind: a chatty motor uses up its own
/// budget and not a mode change's or an error's, and what the limit held back
/// is counted. **Canary** `canary-logd-telemetry-one-bucket`: one budget for
/// every kind, so the motor storm holds the mode change back (red).
#[test]
fn a_chatty_telemetry_kind_is_cut_at_the_rate_and_does_not_hold_back_the_others() {
    // 4 a second of each kind over 500 ms periods: 2 a period.
    let mut k = Keep::new(false, 20, 4, 500);
    let kept = (0..50).filter(|_| k.admit_telemetry(MOTOR)).count();
    assert_eq!(kept, 2);
    assert!(k.admit_telemetry(MODE) && k.admit_telemetry(ERROR), "another kind has its own budget");
    assert_eq!(k.telemetry_period(), 48, "the 48 held back are counted");
    assert!(k.admit_telemetry(MOTOR), "a new period has its budget again");
    assert_eq!(k.period(), 0, "the decisions' count is not the telemetry's");
}

/// 0 writes no telemetry; a rate below one a period still lets one through.
#[test]
fn telemetry_off_writes_none_and_a_slow_rate_writes_one_a_period() {
    let mut off = Keep::new(false, 20, 0, 500);
    assert!(!off.admit_telemetry(MOTOR));
    assert_eq!(off.telemetry_period(), 0, "what the policy leaves out is not counted as held back");
    let mut slow = Keep::new(false, 20, 1, 100);
    assert!(slow.admit_telemetry(MOTOR) && !slow.admit_telemetry(MOTOR));
}
