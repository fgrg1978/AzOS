// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! System power assertions (`azos_energy::assertion`): the ledger the kernel
//! keeps for the `powerassert` endpoint and that the suspend sequence reads.
//! Owner, reason and timeout; the quota per owner and the longest timeout;
//! release only by the owner; a lapse handed back for its record.
//!
//! Canaries (by hand, 2026-10-23, each restored with git):
//!
//! * never reap in `Ledger::reap`:
//!   `an_assertion_past_its_timeout_is_released_and_handed_back` and
//!   `one_owner_cannot_take_more_than_its_quota` fail;
//! * drop the per-owner check in `Ledger::hold`:
//!   `one_owner_cannot_take_more_than_its_quota` fails;
//! * drop `a.owner == owner` in `Ledger::release`:
//!   `only_the_owner_releases` fails.

use azos_energy::assertion::{AssertError, Assertion, Ledger, Quota, MAX_ASSERTIONS};

const TTL_MAX: u32 = 60_000;

fn ledger(per_owner: u32) -> Ledger {
    Ledger::new(Quota::new(per_owner, TTL_MAX))
}

/// Reap at `now` and return what lapsed.
fn reap(l: &mut Ledger, now: u64) -> Vec<Assertion> {
    let mut out = vec![];
    l.reap(now, |a| out.push(*a));
    out
}

#[test]
fn a_held_assertion_is_live_until_released() {
    let mut l = ledger(2);
    let id = l.hold(7, 1, 5_000, 1_000).unwrap();
    assert_ne!(id, 0);
    assert_eq!(l.live(1_000), 1);
    assert_eq!(l.held_by(7, 1_000), 1);
    let a = l.release(7, id).unwrap();
    assert_eq!((a.owner, a.reason, a.ttl_ms, a.expiry_ms), (7, 1, 5_000, 6_000));
    assert_eq!(l.live(1_000), 0);
    assert_eq!(l.counters.granted, 1);
    assert_eq!(l.counters.released, 1);
    // Released once: a second release finds nothing.
    assert_eq!(l.release(7, id), Err(AssertError::NoAssertion));
}

#[test]
fn an_assertion_past_its_timeout_is_released_and_handed_back() {
    let mut l = ledger(2);
    let a = l.hold(7, 3, 5_000, 1_000).unwrap();
    let b = l.hold(8, 4, 20_000, 1_000).unwrap();
    assert!(reap(&mut l, 5_999).is_empty(), "not yet");
    let lapsed = reap(&mut l, 6_000);
    assert_eq!(lapsed.len(), 1);
    assert_eq!((lapsed[0].id, lapsed[0].owner, lapsed[0].reason, lapsed[0].ttl_ms), (a, 7, 3, 5_000));
    assert_eq!(l.counters.expired, 1);
    assert_eq!(l.live(6_000), 1, "the other owner's is still live");
    // A lapsed one cannot be released any more: it is gone, recorded once.
    assert_eq!(l.release(7, a), Err(AssertError::NoAssertion));
    assert!(reap(&mut l, 6_001).is_empty(), "handed back once");
    assert_eq!(l.release(8, b).map(|x| x.id), Ok(b));
}

#[test]
fn live_does_not_count_a_lapsed_one_before_the_reap() {
    let mut l = ledger(1);
    l.hold(7, 1, 1_000, 0).unwrap();
    assert_eq!(l.live(999), 1);
    assert_eq!(l.live(1_000), 0, "a suspend gate reading at the timeout is not held by it");
}

#[test]
fn one_owner_cannot_take_more_than_its_quota() {
    let mut l = ledger(2);
    l.hold(7, 1, 1_000, 0).unwrap();
    l.hold(7, 1, 1_000, 0).unwrap();
    assert_eq!(l.hold(7, 1, 1_000, 0), Err(AssertError::Quota));
    // Another owner is not held back by it.
    assert!(l.hold(8, 1, 1_000, 0).is_ok());
    assert_eq!(l.counters.refused, 1);
    // Once the first two lapse and are reaped, the owner may hold again.
    assert_eq!(reap(&mut l, 1_000).len(), 3);
    assert!(l.hold(7, 1, 1_000, 1_000).is_ok());
}

#[test]
fn the_ledger_is_bounded_for_every_owner_together() {
    let mut l = ledger(1);
    for owner in 0..MAX_ASSERTIONS as u32 {
        l.hold(100 + owner, 1, 1_000, 0).unwrap();
    }
    assert_eq!(l.hold(999, 1, 1_000, 0), Err(AssertError::Full));
}

#[test]
fn a_reason_and_a_timeout_within_the_longest_are_required() {
    let mut l = ledger(4);
    assert_eq!(l.hold(7, 0, 1_000, 0), Err(AssertError::Reason));
    assert_eq!(l.hold(7, 1, 0, 0), Err(AssertError::Ttl));
    assert_eq!(l.hold(7, 1, TTL_MAX + 1, 0), Err(AssertError::Ttl));
    assert!(l.hold(7, 1, TTL_MAX, 0).is_ok());
    assert_eq!(l.counters.refused, 3);
}

#[test]
fn only_the_owner_releases() {
    let mut l = ledger(2);
    let id = l.hold(7, 1, 1_000, 0).unwrap();
    assert_eq!(l.release(8, id), Err(AssertError::NoAssertion), "an id is not a capability");
    assert_eq!(l.live(0), 1);
    assert!(l.release(7, id).is_ok());
}

#[test]
fn ids_are_unique_among_live_assertions() {
    let mut l = ledger(MAX_ASSERTIONS as u32);
    let mut ids = vec![];
    for _ in 0..MAX_ASSERTIONS {
        ids.push(l.hold(7, 1, 1_000, 0).unwrap());
    }
    let n = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), n);
    assert!(!ids.contains(&0));
}

#[test]
fn the_quota_is_clamped() {
    assert_eq!(Quota::new(0, 0), Quota { per_owner: 1, max_ttl_ms: 1 });
    assert_eq!(Quota::new(99, 5).per_owner as usize, MAX_ASSERTIONS);
}
