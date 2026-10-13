// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `crates/core/sched/src/domain.rs` (owner decision D2), the
//! real file: the domain lifecycle (create, join, last exit frees), charge
//! accounting against the budget, and generation reuse.
//!
//! The domain table is one process-wide static, so every test takes `serial`
//! and leaves the table as it found it.

use crate::domain::{self, Key, DOMAINS_MAX, NONE};
use std::sync::{Mutex, MutexGuard};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Free every member of `key` (best effort, for cleanup).
fn free_all(key: Key) {
    while domain::live(key) != 0 {
        domain::leave(key);
    }
}

#[test]
fn a_domain_is_created_joined_and_freed_by_its_last_member() {
    let _s = serial();
    let base = domain::count();
    let k = domain::create().expect("a free domain");
    assert_ne!(k, NONE, "a domain's key is never the null key");
    assert_eq!(domain::live(k), 1, "the creator's task is the first member");
    assert!(!domain::shared(k), "one member shares nothing");
    assert_eq!(domain::count(), base + 1);

    assert!(domain::join(k), "a thread joins a live domain");
    assert_eq!(domain::live(k), 2);
    assert!(domain::shared(k), "two members share the table: a thread's exit must not wipe it");

    assert!(!domain::leave(k), "the first to go is not the last");
    assert_eq!(domain::live(k), 1);
    assert!(!domain::shared(k), "the survivor owns the table alone");
    assert_eq!(domain::count(), base + 1, "the domain stays while a member lives");

    assert!(domain::leave(k), "the last member frees the domain");
    assert_eq!(domain::live(k), 0);
    assert_eq!(domain::count(), base, "the slot is free again");
    assert!(domain::info(k).is_none(), "a freed domain has no state to read");
}

#[test]
fn a_key_that_names_no_domain_changes_nothing() {
    let _s = serial();
    let k = domain::create().unwrap();
    assert!(domain::leave(k));
    let base = domain::count();
    assert!(!domain::join(k), "nobody joins an ended domain");
    assert!(!domain::leave(k), "an ended domain has no last member");
    assert!(!domain::join(NONE) && !domain::leave(NONE), "the null key names none");
    assert_eq!(domain::count(), base);
}

#[test]
fn a_reused_slot_gets_a_new_generation_and_the_old_key_stays_dead() {
    let _s = serial();
    let a = domain::create().unwrap();
    domain::set_limit(a, 100);
    assert_eq!(domain::charge(a, 7), Some(7));
    assert!(domain::leave(a));

    let b = domain::create().unwrap();
    assert_eq!(domain::index(a), domain::index(b), "the freed slot is the first free one");
    assert_ne!(a, b, "same slot, new generation");
    assert_eq!(domain::live(b), 1);

    // The old key must not reach the successor, whatever it asks.
    assert_eq!(domain::live(a), 0);
    assert_eq!(domain::charge(a, 1), None, "a charge through a dead key is refused");
    domain::discharge(a, 1);
    domain::discharge(a, 5);
    domain::set_limit(a, 3);
    assert!(!domain::join(a), "a dead key cannot join the successor");
    assert!(!domain::leave(a), "a dead key cannot free the successor");
    assert_eq!(domain::live(b), 1, "the successor kept its member");
    assert_eq!(domain::used_limit(b), (0, 0), "and its budget: nothing leaked across the generations");
    assert_eq!(domain::charge(b, 2), Some(2), "the successor's own charge is not disturbed by a discharge through the dead key");
    free_all(b);
}

#[test]
fn a_new_domain_starts_from_nothing() {
    let _s = serial();
    let a = domain::create().unwrap();
    domain::set_limit(a, 50);
    domain::set_mem_locked(a, true);
    domain::set_identity(a, 7, 2, 3);
    domain::set_measurement(a, [0xAB; 32]);
    assert_eq!(domain::charge(a, 10), Some(10));
    domain::discharge(a, 4);
    assert!(domain::leave(a));

    let b = domain::create().unwrap();
    assert_eq!(domain::used_limit(b), (0, 0), "no budget inherited");
    assert_eq!(domain::peak(b), 0);
    assert!(!domain::mem_locked(b), "no memory policy inherited");
    let i = domain::info(b).unwrap();
    assert_eq!(
        (i.live, i.owner_root, i.security_boundary, i.partition_id, i.vm, i.measurement),
        (1, 0, 0, 0, None, [0; 32]),
        "no identity inherited"
    );
    assert_eq!(domain::charge(b, 1), Some(1), "nothing of the old domain is carried into the new one");
    free_all(b);
}

#[test]
fn the_hook_fields_are_kept() {
    let _s = serial();
    let k = domain::create().unwrap();
    domain::set_identity(k, 0xD10, 3, 9);
    domain::set_measurement(k, [7; 32]);
    let i = domain::info(k).unwrap();
    assert_eq!((i.owner_root, i.security_boundary, i.partition_id), (0xD10, 3, 9));
    assert_eq!(i.measurement, [7; 32]);
    assert_eq!(i.vm, None);
    free_all(k);
}

#[test]
fn charges_are_all_or_nothing_and_shared_by_every_member() {
    let _s = serial();
    let k = domain::create().unwrap();
    assert!(domain::join(k), "a second thread");
    domain::set_limit(k, 10);

    // Either member charges the one budget: the key is the whole identity.
    assert_eq!(domain::charge(k, 4), Some(4));
    assert_eq!(domain::charge(k, 3), Some(7));
    assert_eq!(domain::charge(k, 4), None, "7 + 4 would pass the limit of 10");
    assert_eq!(domain::used_limit(k), (7, 10), "a refused charge takes nothing");
    assert_eq!(domain::charge(k, 3), Some(10), "exactly the limit fits");
    assert_eq!(domain::peak(k), 10);

    domain::discharge(k, 6);
    assert_eq!(domain::used_limit(k), (4, 10));
    assert_eq!(domain::peak(k), 10, "the high-water mark survives a discharge");
    domain::discharge(k, 99);
    assert_eq!(domain::used_limit(k), (0, 10), "an over-discharge floors at zero");

    assert_eq!(domain::charge(k, 8), Some(8));
    domain::reset_budget(k);
    assert_eq!(domain::used_limit(k), (0, 10), "a new address space starts empty, keeps the limit");
    assert_eq!(domain::peak(k), 0);

    // 0 = unlimited.
    domain::set_limit(k, 0);
    assert_eq!(domain::charge(k, 100_000), Some(100_000));

    // A thread's exit leaves the budget with the domain.
    assert!(!domain::leave(k));
    assert_eq!(domain::used_limit(k).0, 100_000);
    free_all(k);
}

#[test]
fn frames_freed_by_another_task_come_off_at_once() {
    let _s = serial();
    let k = domain::create().unwrap();
    domain::set_limit(k, 10);
    assert_eq!(domain::charge(k, 10), Some(10));
    assert_eq!(domain::charge(k, 1), None, "full");
    domain::discharge(k, 4);
    assert_eq!(domain::used_limit(k).0, 6, "applied at once, from any context");
    assert_eq!(domain::charge(k, 3), Some(9), "10 - 4 + 3");
    assert_eq!(domain::charge(k, 2), None, "refused on what the domain holds now (9 + 2 > 10)");
    free_all(k);
}

/// **Charges from several harts, and across Domains, are race-free.** Eight
/// threads charge one Domain one page at a time against a limit of 1000: the
/// grants are exactly the limit and `used` equals them. Then four threads each
/// charge and give back across two Domains, as a MOVE does from one Domain's
/// thread to the other's: neither count is ever lost or doubled and both end
/// where they began.
///
/// **Canary** `budget-racy-charge-canary` (the pulled `budget.rs` the mm shim
/// declares, run through `tests/host/mm-tests`' twin of the first half): the
/// limit test and the store are two steps and the totals disagree.
#[test]
fn charges_from_many_harts_and_across_domains_never_race() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let _s = serial();
    const LIMIT: u32 = 1000;
    let k = domain::create().unwrap();
    domain::set_limit(k, LIMIT);
    let granted = AtomicU32::new(0);
    std::thread::scope(|sc| {
        for _ in 0..8 {
            sc.spawn(|| {
                for _ in 0..50_000 {
                    if domain::charge(k, 1).is_some() {
                        granted.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    assert_eq!(granted.load(Ordering::Relaxed), LIMIT, "the grants passed the limit or fell short");
    assert_eq!(domain::used_limit(k).0, LIMIT, "a charge was lost");
    assert!(domain::peak(k) <= LIMIT);
    free_all(k);

    let (a, b) = (domain::create().unwrap(), domain::create().unwrap());
    assert_eq!(domain::charge(a, 400), Some(400));
    std::thread::scope(|sc| {
        for t in 0..4 {
            sc.spawn(move || {
                // What a MOVE does from one Domain's thread to the other's:
                // charge the receiver, give the sender's back. Every give-back
                // matches a charge of its own, so no discharge saturates.
                let (x, y) = if t % 2 == 0 { (a, b) } else { (b, a) };
                for _ in 0..20_000 {
                    assert!(domain::charge(y, 10).is_some());
                    assert!(domain::charge(x, 10).is_some());
                    domain::discharge(y, 10);
                    domain::discharge(x, 10);
                }
            });
        }
    });
    let (ua, ub) = (domain::used_limit(a).0, domain::used_limit(b).0);
    assert_eq!((ua, ub), (400, 0), "a charge was lost or doubled across the Domains");
    free_all(a);
    free_all(b);
}

#[test]
fn the_memory_policy_is_the_domains() {
    let _s = serial();
    let k = domain::create().unwrap();
    assert!(!domain::mem_locked(k));
    domain::set_mem_locked(k, true);
    assert!(domain::mem_locked(k));
    domain::set_mem_locked(k, false);
    assert!(!domain::mem_locked(k));
    domain::set_mem_locked(k, true);
    assert!(domain::leave(k));
    assert!(!domain::mem_locked(k), "an ended domain is locked against nothing");
}

#[test]
fn there_is_a_domain_for_every_task_slot_and_no_more() {
    let _s = serial();
    let base = domain::count();
    let mut keys = Vec::new();
    while let Some(k) = domain::create() {
        keys.push(k);
        assert!(keys.len() <= DOMAINS_MAX, "created more domains than slots");
    }
    assert_eq!(base + keys.len(), DOMAINS_MAX, "the table filled exactly");
    assert!(domain::create().is_none(), "full is refused, not overwritten");

    let gone = keys.pop().unwrap();
    assert!(domain::leave(gone));
    let again = domain::create().expect("a freed slot is usable");
    assert_eq!(domain::index(again), domain::index(gone));
    keys.push(again);
    for k in keys {
        free_all(k);
    }
    assert_eq!(domain::count(), base);
}
