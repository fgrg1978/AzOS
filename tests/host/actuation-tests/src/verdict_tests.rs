// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `crates/core/actuation/src/verdict.rs`: a verdict counts only while fresh.

use crate::verdict::Stamped;

/// **Never published, too old, or withdrawn: no verdict.** A reader then takes
/// the safe value, which is how a stalled enforcer stops the drivetrain.
///
/// **Canary.** Drop the age check in `fresh`: the old verdict still counts.
#[test]
fn a_verdict_counts_only_while_fresh() {
    let v = Stamped::new();
    assert_eq!(v.fresh(1_000, 300), None, "a verdict never published counted");
    v.publish(42, 1_000);
    assert_eq!(v.fresh(1_000, 300), Some(42));
    assert_eq!(v.fresh(1_300, 300), Some(42), "a verdict exactly max_age old is fresh");
    assert_eq!(v.fresh(1_301, 300), None, "a stale verdict counted");
    v.publish(7, 1_400);
    assert_eq!(v.fresh(1_500, 300), Some(7));
    v.withdraw();
    assert_eq!(v.fresh(1_500, 300), None, "a withdrawn verdict counted");
    let at_zero = Stamped::new();
    at_zero.publish(5, 0);
    assert_eq!(at_zero.fresh(0, 300), Some(5), "a verdict published at tick 0 read as never published");
}
