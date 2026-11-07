// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Which decision records `logd` writes (`userspace/services/logd/src/keep.rs`).

use crate::keep::{Keep, Sample, VERDICT_DENY, VERDICT_REFUSE};

const ADMIT: u8 = 0;
const PLACE: u8 = 2;

/// By default a migrating wake's placement (and any admission) stays out of
/// the files; refusals and denials go in. **Canary.** Make `admit` return true
/// for every verdict when `all` is off: the first assertion goes red.
#[test]
fn by_default_only_refusals_and_denials_reach_the_files() {
    let mut k = Keep::<4>::new(false, 1000, 5, 1000);
    assert!(!k.admit(PLACE) && !k.admit(ADMIT), "placements and admissions are not written");
    assert!(k.admit(VERDICT_REFUSE) && k.admit(VERDICT_DENY));
    assert_eq!(k.period(), 0, "what the policy leaves out is not counted as held back");
    let mut all = Keep::<4>::new(true, 1000, 5, 1000);
    assert!(all.admit(PLACE) && all.admit(ADMIT), "LOGD_DECISIONS_ALL writes every rule");
}

/// The rate limit holds back what passes it in a period and counts it, and
/// the next period starts afresh. **Canary.** Drop the `used >= per_period`
/// test: nothing is held back (red).
#[test]
fn a_refusal_storm_is_cut_at_the_rate_and_counted() {
    // 20 a second over 500 ms periods: 10 a period.
    let mut k = Keep::<4>::new(false, 20, 5, 500);
    let kept = (0..100).filter(|_| k.admit(VERDICT_REFUSE)).count();
    assert_eq!(kept, 10);
    assert_eq!(k.period(), 90, "the 90 held back are counted");
    assert!(k.admit(VERDICT_DENY), "a new period has its budget again");
    assert_eq!(k.period(), 0);
    // A rate below one a period still lets one through.
    let mut slow = Keep::<4>::new(false, 1, 5, 100);
    assert!(slow.admit(VERDICT_REFUSE) && !slow.admit(VERDICT_REFUSE));
}

const MOTOR: u16 = 2;
const MODE: u16 = 4;
const ERROR: u16 = 8;

fn sample(kind: u16, source: u8, value: u8, seq: u64) -> Sample {
    let mut s = Sample::empty();
    s.kind = kind;
    s.seq = seq;
    s.len = 20;
    s.payload[0] = source;
    s.payload[1] = value;
    s
}

/// Telemetry is cut at the rate per kind and source: a chatty motor uses up
/// its own budget and not another motor's, a mode change's or an error's, and
/// what the limit held back is counted. **Canary**
/// `canary-logd-telemetry-one-bucket`: one budget for all (red).
#[test]
fn a_chatty_motor_does_not_hold_back_another_motor_or_another_kind() {
    // 4 a second of each over 500 ms periods: 2 a period.
    let mut k = Keep::<4>::new(false, 20, 4, 500);
    let kept = (0..50).filter(|&i| k.admit_telemetry(&sample(MOTOR, 0, 0, i))).count();
    assert_eq!(kept, 2);
    assert!(k.admit_telemetry(&sample(MOTOR, 1, 0, 60)), "another motor has its own budget");
    assert!(k.admit_telemetry(&sample(MODE, 0, 0, 61)) && k.admit_telemetry(&sample(ERROR, 7, 0, 62)));
    let (_, held) = k.telemetry_held().expect("motor 0 held records back");
    assert_eq!(held, 48);
    assert!(k.telemetry_held().is_none());
    assert_eq!(k.telemetry_period(), 0);
    assert!(k.admit_telemetry(&sample(MOTOR, 0, 0, 70)), "a new period has its budget again");
    assert_eq!(k.period(), 0, "the decisions' count is not the telemetry's");
}

/// What the budget holds back leaves its newest record, written at the end of
/// the period: the settled value of a ramp survives. **Canary**
/// `canary-logd-telemetry-first-wins`: the first held one stays (red).
#[test]
fn the_newest_held_value_of_a_budget_survives_the_period() {
    let mut k = Keep::<4>::new(false, 20, 4, 500);
    for i in 0..10u8 {
        k.admit_telemetry(&sample(MOTOR, 0, i, i as u64));
    }
    let (newest, held) = k.telemetry_held().unwrap();
    assert_eq!((newest.payload[1], newest.seq, held), (9, 9, 8), "the last value, and how many were held");
}

/// A record with no budget to take is dropped and counted, not written
/// unbounded; budgets are freed with the period.
#[test]
fn records_for_want_of_a_budget_are_counted() {
    let mut k = Keep::<2>::new(false, 20, 4, 500);
    assert!(k.admit_telemetry(&sample(MOTOR, 0, 0, 0)) && k.admit_telemetry(&sample(MOTOR, 1, 0, 1)));
    assert!(!k.admit_telemetry(&sample(MOTOR, 2, 0, 2)) && !k.admit_telemetry(&sample(MODE, 0, 0, 3)));
    assert_eq!(k.telemetry_period(), 2);
    assert!(k.admit_telemetry(&sample(MODE, 0, 0, 4)), "freed with the period");
}

/// 0 writes no telemetry; a rate below one a period still lets one through.
#[test]
fn telemetry_off_writes_none_and_a_slow_rate_writes_one_a_period() {
    let mut off = Keep::<4>::new(false, 20, 0, 500);
    assert!(!off.admit_telemetry(&sample(MOTOR, 0, 0, 0)));
    assert!(off.telemetry_held().is_none(), "what the policy leaves out is not counted as held back");
    let mut slow = Keep::<4>::new(false, 20, 1, 100);
    assert!(slow.admit_telemetry(&sample(MOTOR, 0, 0, 0)) && !slow.admit_telemetry(&sample(MOTOR, 0, 0, 1)));
}
