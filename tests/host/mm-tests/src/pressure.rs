// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A Domain's level of memory pressure (`Rule::MemPressure`,
//! `budget::Pressure`): the shipping arithmetic of `PageBudget::pressure_change`,
//! which the reclaim task asks before it opens a storm and tells the Domain's
//! Port about. The delivery to the Port is kernel glue (`reclaim.rs`) and is
//! booted in the testing week; what is decided here is WHEN a level changes.

use super::budget::{pressure_after, PageBudget, Pressure, Pressure::*};

/// A budget of 1000 pages with the kernel's default marks 65/85 percent.
fn row() -> PageBudget {
    let b = PageBudget::new();
    b.set_limit_marked(1000, 85, 65);
    b
}

fn set_used(b: &PageBudget, used: u32) {
    let now = b.used();
    if used > now {
        assert!(b.charge(used - now));
    } else {
        b.discharge(now - used);
    }
}

#[test]
fn the_level_follows_the_charge_up_at_once() {
    let b = row();
    assert_eq!(b.pressure_change(), None, "an empty Domain is where it was reported: normal");
    set_used(&b, 849);
    assert_eq!(b.pressure_change(), None, "one page under the high watermark is normal");
    set_used(&b, 850);
    assert_eq!(b.pressure_change(), Some((Normal, Warning)), "the high watermark is warning");
    assert_eq!(b.pressure_change(), None, "told once");
    set_used(&b, 999);
    assert_eq!(b.pressure_change(), None, "still warning one page below the limit");
    set_used(&b, 1000);
    assert_eq!(b.pressure_change(), Some((Warning, Critical)), "the limit is critical");
    assert_eq!(b.pressure_change(), None);
}

#[test]
fn a_jump_over_warning_is_one_change() {
    let b = row();
    set_used(&b, 1000);
    assert_eq!(b.pressure_change(), Some((Normal, Critical)), "no warning is invented for a poll that missed it");
}

#[test]
fn the_way_down_has_hysteresis() {
    let b = row();
    set_used(&b, 1000);
    b.pressure_change();
    // Critical is left below the high watermark, not at the limit: a task that
    // frees and charges one page at the limit does not flap.
    set_used(&b, 999);
    assert_eq!(b.pressure_change(), None);
    set_used(&b, 850);
    assert_eq!(b.pressure_change(), None, "the high watermark itself is still critical on the way down");
    set_used(&b, 849);
    assert_eq!(b.pressure_change(), Some((Critical, Warning)));
    // Warning is left where a storm stops (the low watermark), not at the high one.
    set_used(&b, 700);
    assert_eq!(b.pressure_change(), None);
    set_used(&b, 651);
    assert_eq!(b.pressure_change(), None, "just above the low watermark: warning");
    set_used(&b, 650);
    assert_eq!(b.pressure_change(), Some((Warning, Normal)));
    // And up again from there is warning only at the high watermark.
    set_used(&b, 700);
    assert_eq!(b.pressure_change(), None);
}

#[test]
fn a_storm_that_ends_at_the_low_watermark_returns_to_normal_in_one_change() {
    let b = row();
    set_used(&b, 900);
    assert_eq!(b.pressure_change(), Some((Normal, Warning)));
    b.storm_begin(false, false).unwrap();
    while b.reclaim_target() != 0 {
        b.storm_note_stored(100);
    }
    b.storm_end(4096).unwrap();
    assert_eq!(b.used(), b.low());
    assert_eq!(b.pressure_change(), Some((Warning, Normal)));
}

#[test]
fn a_domain_with_no_marks_is_never_under_pressure() {
    let none = PageBudget::new();
    none.set_limit(0);
    set_used(&none, 5_000_000);
    assert_eq!(none.pressure_change(), None, "no limit");
    let unmarked = PageBudget::new();
    unmarked.set_limit(1000);
    set_used(&unmarked, 1000);
    assert_eq!(unmarked.pressure_change(), None, "a limit without watermarks (reclaim off) has no levels");
    assert_eq!(unmarked.pressure(), Normal);
}

#[test]
fn a_reused_slot_starts_normal() {
    let b = row();
    set_used(&b, 1000);
    assert_eq!(b.pressure_change(), Some((Normal, Critical)));
    // The slot is given to a new Domain: `set_limit` is what `create_child` does.
    b.reset();
    b.set_limit(0);
    assert_eq!(b.reported(), Normal, "the new occupant has been told nothing");
    b.set_limit_marked(1000, 85, 65);
    assert_eq!(b.pressure_change(), None);
}

#[test]
fn exec_does_not_leave_the_domain_believing_it_is_short() {
    let b = row();
    set_used(&b, 900);
    assert_eq!(b.pressure_change(), Some((Normal, Warning)));
    // `reset_budget` at exec: the address space is gone, the Domain stays.
    b.reset();
    assert_eq!(b.reported(), Warning, "reset does not erase what was told");
    assert_eq!(b.pressure_change(), Some((Warning, Normal)), "the next poll tells the Domain it is over");
}

#[test]
fn only_one_caller_is_told_of_a_change() {
    let b = row();
    set_used(&b, 900);
    let told: Vec<_> = (0..4).filter_map(|_| b.pressure_change()).collect();
    assert_eq!(told, vec![(Normal, Warning)]);
}

#[test]
fn the_arithmetic_is_total() {
    // Every level, a spread of charges and marks, including the degenerate
    // ones (`low == 0`, `high == limit`): `Critical` only at the limit, `Normal`
    // only when there is no pressure to speak of, and the answer never panics.
    for cur in [Normal, Warning, Critical] {
        for &(low, high, limit) in &[(0, 1, 2), (0, 1, 1), (3, 4, 5), (650, 850, 1000), (1, 99, 100)] {
            for used in [0, 1, low, low + 1, high - 1, high, limit - 1, limit, limit + 1, u32::MAX] {
                let l = pressure_after(cur, used, low, high, limit);
                if used >= limit {
                    assert_eq!(l, Critical);
                }
                if used < low || (cur == Normal && used < high) {
                    assert_eq!(l, Normal, "cur {cur:?} used {used} marks {low}/{high}/{limit}");
                }
                assert_eq!(pressure_after(cur, used, 0, 0, limit), Normal, "no marks, no pressure");
                assert_eq!(pressure_after(cur, used, low, high, 0), Normal, "no limit, no pressure");
            }
        }
    }
    assert_eq!(Pressure::from_u8(2), Some(Critical));
    assert_eq!(Pressure::from_u8(3), None);
}
