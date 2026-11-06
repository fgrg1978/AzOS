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
    let mut k = Keep::new(false, 1000, 1000);
    assert!(!k.admit(PLACE) && !k.admit(ADMIT), "placements and admissions are not written");
    assert!(k.admit(VERDICT_REFUSE) && k.admit(VERDICT_DENY));
    assert_eq!(k.period(), 0, "what the policy leaves out is not counted as held back");
    let mut all = Keep::new(true, 1000, 1000);
    assert!(all.admit(PLACE) && all.admit(ADMIT), "LOGD_DECISIONS_ALL writes every rule");
}

/// The rate limit holds back what passes it in a period and counts it, and
/// the next period starts afresh. **Canary.** Drop the `used >= per_period`
/// test: nothing is held back (red).
#[test]
fn a_refusal_storm_is_cut_at_the_rate_and_counted() {
    // 20 a second over 500 ms periods: 10 a period.
    let mut k = Keep::new(false, 20, 500);
    let kept = (0..100).filter(|_| k.admit(VERDICT_REFUSE)).count();
    assert_eq!(kept, 10);
    assert_eq!(k.period(), 90, "the 90 held back are counted");
    assert!(k.admit(VERDICT_DENY), "a new period has its budget again");
    assert_eq!(k.period(), 0);
    // A rate below one a period still lets one through.
    let mut slow = Keep::new(false, 1, 100);
    assert!(slow.admit(VERDICT_REFUSE) && !slow.admit(VERDICT_REFUSE));
}
