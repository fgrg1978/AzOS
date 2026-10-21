// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Domain's reclaim watermarks (Kconfig `MM_RECLAIM_COMPRESS`), on the real
//! `domain.rs` and the real `PageBudget`: the frame limit a topology row
//! declares (`domain::set_limit`, the call `exec` and `set_current_user_page_limit`
//! make) is also where the Domain's reclaim starts and stops, so a Domain with
//! a limit asks for a storm when its charge crosses the high watermark, one
//! without a limit never does, and a reused slot keeps nothing of the Domain
//! that had it.
//!
//! Both branches of the Kconfig run: `KCONFIG_CONFIG` with `MM_RECLAIM_COMPRESS=y`
//! (watermarks follow `MM_RECLAIM_HIGH_PCT` / `MM_RECLAIM_LOW_PCT` of the
//! limit) and the default `MM_RECLAIM_OFF` (none).
//!
//! Canaries (by hand, 2026-10-17; discriminates / does not / did not compile):
//! * `domain::set_limit` calling `PageBudget::set_limit` (no marks):
//!   `a_rows_limit_gives_the_domain_its_watermarks` red (with reclaim on).
//! * `domain::set_limit` passing the percentages the wrong way round: the same row red.
//! * `PageBudget::set_limit` not clearing the marks:
//!   `a_reused_slot_keeps_no_watermarks` red.

use crate::domain::{self, NONE};
use crate::domain_tests::serial;

const HIGH: u32 = azos_limits::MM_RECLAIM_HIGH_PCT as u32;
const LOW: u32 = azos_limits::MM_RECLAIM_LOW_PCT as u32;

#[test]
fn a_rows_limit_gives_the_domain_its_watermarks() {
    let _s = serial();
    let k = domain::create().unwrap();
    let b = domain::budget(k).expect("a live domain has a budget");
    assert_eq!((b.low(), b.high()), (0, 0), "no limit, no watermarks");

    domain::set_limit(k, 1000);
    if azos_limits::MM_RECLAIM_COMPRESS {
        assert_eq!((b.low(), b.high()), (LOW * 10, HIGH * 10));
        // The charge crossing the high watermark is the storm's trigger.
        assert!(domain::charge(k, HIGH * 10 - 1).is_some());
        assert!(!b.over_high());
        assert!(domain::charge(k, 1).is_some());
        assert!(b.over_high(), "{} of 1000 pages is the high watermark", HIGH * 10);
    } else {
        assert_eq!((b.low(), b.high()), (0, 0), "reclaim off: no watermark to cross");
        assert!(domain::charge(k, 999).is_some());
        assert!(!b.over_high());
    }

    // Taking the limit away takes the marks with it.
    domain::set_limit(k, 0);
    assert_eq!((b.low(), b.high()), (0, 0));
    assert!(!b.over_high(), "a Domain without a limit never reclaims");
    while domain::live(k) != 0 {
        domain::leave(k);
    }
}

#[test]
fn a_reused_slot_keeps_no_watermarks() {
    let _s = serial();
    let a = domain::create().unwrap();
    domain::set_limit(a, 500);
    assert!(domain::leave(a));

    let b = domain::create().unwrap();
    assert_eq!(domain::index(a), domain::index(b), "the freed slot is the first free one");
    let bud = domain::budget(b).unwrap();
    assert_eq!((bud.limit(), bud.low(), bud.high()), (0, 0, 0), "nothing of the old limit's marks");
    // A child Domain starts without a limit either.
    let c = domain::create_child(b).unwrap();
    assert_eq!(domain::budget(c).map(|x| (x.low(), x.high())), Some((0, 0)));
    for k in [c, b] {
        while domain::live(k) != 0 {
            domain::leave(k);
        }
    }
}

#[test]
fn a_dead_key_has_no_budget_to_open_a_storm_on() {
    let _s = serial();
    let a = domain::create().unwrap();
    assert!(domain::leave(a));
    assert!(domain::budget(a).is_none());
    assert!(domain::budget(NONE).is_none());
}
