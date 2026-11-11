// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `crates/core/sched/src/domain.rs`, the
//! real file: the domain lifecycle (create, join, last exit frees), charge
//! accounting against the budget, and generation reuse.
//!
//! The domain table is one process-wide static, so every test takes `serial`
//! and leaves the table as it found it.

use crate::domain::{self, Key, DOMAINS_MAX, NONE};
use std::sync::{Mutex, MutexGuard};

static SERIAL: Mutex<()> = Mutex::new(());

pub(crate) fn serial() -> MutexGuard<'static, ()> {
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
    domain::set_owner_root(a, 7);
    domain::set_partition(a, 3);
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
        (i.live, i.owner_root, i.partition_id, i.vm, i.measurement),
        (1, 0, 0, None, [0; 32]),
        "no identity inherited"
    );
    assert_eq!(domain::charge(b, 1), Some(1), "nothing of the old domain is carried into the new one");
    free_all(b);
}

#[test]
fn the_hook_fields_are_kept() {
    let _s = serial();
    let k = domain::create().unwrap();
    domain::set_owner_root(k, 0xD10);
    domain::set_partition(k, 9);
    domain::set_measurement(k, [7; 32]);
    let i = domain::info(k).unwrap();
    assert_eq!((i.owner_root, i.partition_id), (0xD10, 9));
    assert_eq!(i.measurement, [7; 32]);
    assert_eq!(i.vm, None);
    free_all(k);
}

/// Console login: the session of a user is a subtree. A Domain created beneath
/// one is the same user's, a root is the system's, and a slot that is reused
/// by a Domain of another lineage starts from 0 again.
///
/// The root of a subtree is what its spawned children (and theirs) name as
/// their root: one key per application, however many it spawns; a key that
/// names no live Domain has none.
#[test]
fn a_subtree_names_its_root() {
    let _s = serial();
    let app = domain::create().unwrap();
    let child = domain::create_child(app).unwrap();
    let grandchild = domain::create_child(child).unwrap();
    let other = domain::create().unwrap();
    assert_eq!((domain::root_of(app), domain::root_of(child), domain::root_of(grandchild)), (app, app, app));
    assert_eq!(domain::root_of(other), other);
    assert_eq!(domain::root_of(NONE), NONE);
}

/// **Canary.** Delete the inheritance in `create_child`: the child reads 0 and
/// the first assertion fails.
#[test]
fn the_user_root_is_inherited_down_a_subtree_and_nowhere_else() {
    let _s = serial();
    let session = domain::create().unwrap();
    assert!(domain::set_owner_root(session, 4242));
    let job = domain::create_child(session).unwrap();
    let grandjob = domain::create_child(job).unwrap();
    assert_eq!(domain::info(job).unwrap().owner_root, 4242, "a job of the session is the user's");
    assert_eq!(domain::info(grandjob).unwrap().owner_root, 4242, "so is what the job starts");
    let other = domain::create().unwrap();
    assert_eq!(domain::info(other).unwrap().owner_root, 0, "a root Domain is the system's");
    assert_eq!(domain::info(session).unwrap().owner_root, 4242);
    // Narrowing the root of a Domain does not reach back to its parent.
    assert!(domain::set_owner_root(grandjob, 7));
    assert_eq!(domain::info(job).unwrap().owner_root, 4242);
    free_all(grandjob);
    free_all(job);
    free_all(session);
    assert!(!domain::set_owner_root(session, 1), "a dead key names no domain");
    let reused = domain::create().unwrap();
    assert_eq!(domain::info(reused).unwrap().owner_root, 0, "a reused slot is not the old user's");
    free_all(reused);
    free_all(other);
}

/// Console login: the grant `login` arms is spent by one spawn and by nobody
/// else, lapses with time, is replaced and not stacked, and a reused slot does
/// not inherit the old Domain's.
///
/// **Canary.** Delete the expiry filter in `take_login_grant`: the lapsed
/// grant is honoured and the third assertion fails. Delete the `take()`: the
/// grant is spent twice and the second assertion fails.
#[test]
fn a_login_grant_is_spent_once_lapses_and_is_not_inherited() {
    let _s = serial();
    let d = domain::create().unwrap();
    assert_eq!(domain::take_login_grant(d, 0), None, "nothing armed, nothing to spend");
    assert!(domain::arm_login_grant(d, 7, 100));
    assert_eq!(domain::take_login_grant(d, 50), Some(7));
    assert_eq!(domain::take_login_grant(d, 50), None, "one credential, one session");
    assert!(domain::arm_login_grant(d, 7, 100));
    assert_eq!(domain::take_login_grant(d, 101), None, "a lapsed grant admits nobody");
    assert_eq!(domain::take_login_grant(d, 50), None, "and is not kept for a later look");
    assert!(domain::arm_login_grant(d, 1, 100));
    assert!(domain::arm_login_grant(d, 2, 100));
    assert_eq!(domain::take_login_grant(d, 0), Some(2), "the last credential replaces the first");
    assert_eq!(domain::take_login_grant(d, 0), None);
    // The system's own session is root 0 and is a grant like any other.
    assert!(domain::arm_login_grant(d, 0, 10));
    assert_eq!(domain::take_login_grant(d, 0), Some(0));
    // A child Domain starts without the parent's grant.
    assert!(domain::arm_login_grant(d, 9, 100));
    let child = domain::create_child(d).unwrap();
    assert_eq!(domain::take_login_grant(child, 0), None);
    free_all(child);
    free_all(d);
    assert!(!domain::arm_login_grant(d, 1, 1), "a dead key names no domain");
    let reused = domain::create().unwrap();
    assert_eq!(domain::take_login_grant(reused, 0), None, "a reused slot is not the old Domain's");
    free_all(reused);
}

/// The resource partition (Ssqosid RCID and peers): the switch path reads it
/// by key, a child Domain starts in its creator's, a root and a reused slot in
/// partition 0, and the null key is partition 0.
#[test]
fn the_partition_is_read_by_key_and_inherited_by_a_child() {
    let _s = serial();
    assert_eq!(domain::partition_of(NONE), 0, "the null key is the default partition");
    let root = domain::create().unwrap();
    assert_eq!(domain::partition_of(root), 0, "a root starts in the default partition");
    domain::set_partition(root, 7);
    assert_eq!(domain::partition_of(root), 7);
    assert_eq!(domain::info(root).unwrap().partition_id, 7, "introspection reports the same value");

    let child = domain::create_child(root).unwrap();
    assert_eq!(domain::partition_of(child), 7, "a child runs where its creator does");
    domain::set_partition(child, 9);
    assert_eq!((domain::partition_of(root), domain::partition_of(child)), (7, 9), "the row moves the child only");
    let grandchild = domain::create_child(child).unwrap();
    assert_eq!(domain::partition_of(grandchild), 9);

    // A key that names no live Domain changes nothing.
    free_all(grandchild);
    domain::set_partition(grandchild, 5);
    free_all(child);
    free_all(root);
    // The freed slots come back clean, whoever held them.
    let again = domain::create().unwrap();
    assert_eq!(domain::partition_of(again), 0, "a reused slot is not in the old occupant's partition");
    free_all(again);
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

// ── KMEM-CHARGE: the kernel-memory ledger of a domain ──────────────────────

use crate::domain::{KmemClass, kmem_charge, kmem_charge_atomic, kmem_discharge, kmem_limit_kib, kmem_used_limit, set_kmem_limit_kib};

/// The `kmem-charge` records written for `key` since `after` (a
/// `azos_decision::total()`): `(verdict, [bytes, used, limit])`.
fn kmem_records(key: Key, after: u64) -> Vec<(u8, [u64; 3])> {
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.seq > after && r.rule == azos_decision::Rule::KmemCharge as u8 && r.subject == key {
            v.push((r.verdict, r.n));
        }
    });
    v
}

#[test]
fn a_kmem_charge_past_the_limit_is_refused_and_leaves_a_record() {
    let _s = serial();
    let k = domain::create().expect("a free domain");
    set_kmem_limit_kib(k, 1);
    let before = azos_decision::total();
    assert!(kmem_charge(k, KmemClass::EpQueue, 600));
    assert!(kmem_records(k, before).is_empty(), "a granted charge writes no record");
    assert!(!kmem_charge(k, KmemClass::MemObjMeta, 600), "600 + 600 passes 1 KiB");
    assert_eq!(kmem_used_limit(k, KmemClass::MemObjMeta), (600, 1024, 0), "a refusal charges nothing");
    assert_eq!(
        kmem_records(k, before),
        vec![(azos_decision::Verdict::Refuse as u8, [600, 600, 1024])],
        "one Refuse record: bytes asked, bytes held, the ceiling",
    );
    free_all(k);
}

/// A context that may hold a spinlock records its refusal as `Deny`: the ring
/// only, never the durable sink (which flushes to the medium).
#[test]
fn a_kmem_charge_from_an_atomic_context_is_recorded_as_a_deny() {
    let _s = serial();
    let k = domain::create().expect("a free domain");
    set_kmem_limit_kib(k, 1);
    let before = azos_decision::total();
    assert!(!kmem_charge_atomic(k, KmemClass::PageTable, 4096));
    assert_eq!(
        kmem_records(k, before),
        vec![(azos_decision::Verdict::Deny as u8, [4096, 0, 1024])],
    );
    free_all(k);
}

#[test]
fn freeing_returns_the_kmem_charge_and_the_refused_allocation_then_fits() {
    let _s = serial();
    let k = domain::create().expect("a free domain");
    set_kmem_limit_kib(k, 1);
    assert!(kmem_charge(k, KmemClass::CapTable, 700));
    assert!(!kmem_charge(k, KmemClass::CapTable, 700));
    kmem_discharge(k, KmemClass::CapTable, 700);
    assert_eq!(kmem_used_limit(k, KmemClass::CapTable), (0, 1024, 0));
    assert!(kmem_charge(k, KmemClass::CapTable, 700), "the freed bytes can be taken again");
    free_all(k);
}

#[test]
fn a_domain_without_kmem_kib_has_no_kmem_ceiling() {
    let _s = serial();
    let k = domain::create().expect("a free domain");
    assert_eq!(kmem_limit_kib(k), 0);
    assert!(kmem_charge(k, KmemClass::CapTable, 1 << 30));
    set_kmem_limit_kib(k, 7);
    assert_eq!(kmem_limit_kib(k), 7, "the limit a fork inherits");
    free_all(k);
}

/// A key that names no domain has nothing to bill: the kernel's own objects
/// charge key 0, and a domain whose last member just went is not charged for
/// what is still being torn down.
#[test]
fn a_key_that_names_no_domain_is_not_billed_and_its_discharge_is_a_no_op() {
    let _s = serial();
    assert!(kmem_charge(NONE, KmemClass::EpQueue, 1 << 20));
    kmem_discharge(NONE, KmemClass::EpQueue, 1 << 20);
    let k = domain::create().expect("a free domain");
    assert!(domain::leave(k));
    assert!(kmem_charge(k, KmemClass::EpQueue, 1 << 20), "an ended domain is not billed");
    kmem_discharge(k, KmemClass::EpQueue, 1 << 20);
}

/// A slot reused by a new domain starts with an empty ledger and no limit,
/// and a discharge aimed at the old occupant cannot reach the new one.
#[test]
fn a_reused_slot_starts_with_an_empty_kmem_ledger() {
    let _s = serial();
    let old = domain::create().expect("a free domain");
    set_kmem_limit_kib(old, 4);
    assert!(kmem_charge(old, KmemClass::CapTable, 2048));
    assert!(domain::leave(old));
    let mut held = Vec::new();
    let new = loop {
        let k = domain::create().expect("a free domain");
        if domain::index(k) == domain::index(old) {
            break k;
        }
        held.push(k);
    };
    assert_eq!(kmem_used_limit(new, KmemClass::CapTable), (0, 0, 0), "nothing inherited");
    assert!(kmem_charge(new, KmemClass::CapTable, 100));
    kmem_discharge(old, KmemClass::CapTable, 100);
    assert_eq!(kmem_used_limit(new, KmemClass::CapTable), (100, 0, 100), "a stale key reaches nobody");
    for k in held.into_iter().chain([new]) {
        free_all(k);
    }
}

/// An exec or a spawn installs a new address space: the page tables the old one
/// grew go with it, and what the kernel keeps for the Domain itself does not.
#[test]
fn a_new_address_space_drops_the_page_table_charge_and_keeps_the_rest() {
    let _s = serial();
    let k = domain::create().expect("a free domain");
    assert!(kmem_charge(k, KmemClass::PageTable, 3 * 4096));
    assert!(kmem_charge(k, KmemClass::CapTable, 2048));
    domain::reset_budget(k);
    assert_eq!(kmem_used_limit(k, KmemClass::PageTable), (2048, 0, 0));
    assert_eq!(kmem_used_limit(k, KmemClass::CapTable), (2048, 0, 2048));
    free_all(k);
}

/// **The bytes of block writes belong to the Domain they were made for, stay in
/// the device total when it ends, and a late completion is never charged to
/// the Domain that took its slot.** The kernel's own writes (`OWNER_KERNEL`, a
/// key that names no Domain) are unowned from the start.
#[test]
fn written_bytes_follow_their_domain_and_stay_in_the_total() {
    let _s = serial();
    let (t0, u0) = domain::written_totals();
    let delta = |(t, u): (u64, u64)| (t - t0, u - u0);
    let k = domain::create().expect("a free domain");
    domain::add_written(k, 4096);
    domain::add_written(k, 512);
    domain::add_written(u32::MAX, 1024);
    domain::add_written(NONE, 2048);
    assert_eq!(domain::slot_written(domain::index(k)), Some((k, [4608])));
    assert_eq!(delta(domain::written_totals()), (4608 + 3072, 3072), "the live Domain's bytes are not unowned");

    // It ends: its bytes are unowned now, and the total did not move.
    free_all(k);
    assert_eq!(domain::slot_written(domain::index(k)), None, "an ended Domain is not listed");
    assert_eq!(delta(domain::written_totals()), (4608 + 3072, 4608 + 3072));

    // The slot is taken again: the successor starts from zero, the old bytes
    // are still counted once, and the old key charges nobody but the unowned.
    let k2 = domain::create().expect("a free domain");
    domain::add_written(k, 100);
    domain::add_written(k2, 7);
    assert_eq!(domain::slot_written(domain::index(k2)), Some((k2, [7])));
    assert_eq!(delta(domain::written_totals()), (4608 + 3072 + 100 + 7, 4608 + 3072 + 100));
    free_all(k2);
}

/// **A wake counts in the Domain of the task it woke, a Domain that took the
/// slot starts from zero, and a key that names no Domain (a kernel task's)
/// counts nothing** (`WAKE_RING_ENTRIES`; the introspection tree's
/// `metrics/wake/dN`).
#[test]
fn wakes_follow_their_domain_and_a_new_occupant_starts_from_zero() {
    let _s = serial();
    let t0 = domain::wakes_total();
    let k = domain::create().expect("a free domain");
    // The answer is the wakes counted before this one.
    assert_eq!((domain::count_wake(k), domain::count_wake(k), domain::count_wake(k)), (0, 1, 2));
    // A kernel task's wake belongs to no Domain: counted apart, and it counts on.
    let n0 = domain::count_wake(NONE);
    assert_eq!((domain::count_wake(NONE), domain::count_wake(NONE)), (n0 + 1, n0 + 2));
    assert_eq!(domain::slot_wakes(domain::index(k)), Some((k, [3])));
    assert_eq!(domain::wakes_total() - t0, 3 + 3, "the Domain's three and the kernel tasks' three");
    // The other Domains' counts are theirs: a second Domain counts apart.
    let other = domain::create().expect("a free domain");
    assert_eq!(domain::count_wake(other), 0);
    assert_eq!(domain::slot_wakes(domain::index(other)), Some((other, [1])));
    assert_eq!(domain::slot_wakes(domain::index(k)), Some((k, [3])));
    free_all(other);

    free_all(k);
    assert_eq!(domain::slot_wakes(domain::index(k)), None, "an ended Domain is not listed");
    assert_eq!(domain::wakes_total() - t0, 3 + 3 + 1, "an ended Domain's wakes stay in the total");
    let k2 = domain::create().expect("a free domain");
    assert_eq!(domain::slot_wakes(domain::index(k2)), Some((k2, [0])), "the new occupant inherits no wakes");
    assert_eq!(domain::wakes_total() - t0, 3 + 3 + 1, "and are counted once when the slot is taken again");
    free_all(k2);
}

/// The login grant is one-shot even when several members of the Domain spend
/// it at once: every grant armed admits exactly one session. Three members
/// poll `take_login_grant` in a tight loop while the armer arms a grant and
/// waits for its session. **Canary.** Keep the grant in the unlocked `State`
/// again (`Option::take` on the shared cell): two takers read it before
/// either clears it, and more sessions start than grants were armed.
#[test]
fn a_login_grant_is_spent_once_under_concurrent_takers() {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    let _s = serial();
    let k = domain::create().expect("a free domain");
    const ARMS: u32 = 20_000;
    let sessions = AtomicU32::new(0);
    let done = AtomicBool::new(false);
    std::thread::scope(|sc| {
        for _ in 0..3 {
            sc.spawn(|| {
                while !done.load(Ordering::Relaxed) {
                    if domain::take_login_grant(k, 50) == Some(7) {
                        sessions.fetch_add(1, Ordering::SeqCst);
                    }
                    std::thread::yield_now();
                }
            });
        }
        let t0 = std::time::Instant::now();
        for n in 1..=ARMS {
            assert!(domain::arm_login_grant(k, 7, 100));
            while sessions.load(Ordering::SeqCst) < n && t0.elapsed().as_secs() < 20 {
                std::thread::yield_now();
            }
        }
        done.store(true, Ordering::Relaxed);
    });
    assert_eq!(sessions.load(Ordering::SeqCst), ARMS, "every grant admits one session, no more");
    assert_eq!(domain::take_login_grant(k, 50), None, "spent");
    assert!(domain::arm_login_grant(k, 7, 10));
    assert_eq!(domain::take_login_grant(k, 11), None, "a lapsed grant admits nobody");
    assert_eq!(domain::take_login_grant(k, 5), None, "and is gone either way");
    free_all(k);
}

// ── Budget growth: the ceiling's receipts ─────────────────────────────────

/// The `budget-grow` records written for `key` since `after`.
fn grow_records(key: Key, after: u64) -> Vec<(u8, [u64; 3])> {
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.seq > after && r.rule == azos_decision::Rule::BudgetGrow as u8 && r.subject == key {
            v.push((r.verdict, r.n));
        }
    });
    v
}

/// A request that grows the budget past its base leaves an admitted
/// `budget-grow` record, and one refused at the ceiling or for want of growth
/// pool a refused one: pages asked for, the limit after, the ceiling. A
/// request within the limit writes none.
/// **Canary** (by hand): drop the record in `domain::charge_request`: red.
#[test]
fn a_growth_and_a_refusal_at_the_ceiling_leave_a_record() {
    let _s = serial();
    let k = domain::create().expect("a free domain");
    domain::set_limit(k, 8);
    domain::set_ceiling(k, 12);
    azos_mm::budget::set_growth_pool(2);
    let before = azos_decision::total();
    assert!(matches!(domain::charge_request(k, 8, true), Some(Ok(_))));
    assert!(grow_records(k, before).is_empty(), "within the limit: no record");
    assert!(matches!(domain::charge_request(k, 2, true), Some(Ok((azos_mm::budget::Granted::Grew(2), 10)))));
    assert!(matches!(domain::charge_request(k, 1, true), Some(Err(azos_mm::budget::RequestRefused::Pool))));
    assert!(matches!(domain::charge_request(k, 4, true), Some(Err(azos_mm::budget::RequestRefused::Ceiling))));
    let (a, r) = (azos_decision::Verdict::Admit as u8, azos_decision::Verdict::Refuse as u8);
    assert_eq!(grow_records(k, before), vec![(a, [2, 10, 12]), (r, [1, 10, 12]), (r, [4, 10, 12])]);
    free_all(k);
}

/// **A Domain's death gives its growth back to the pool.** The pool is what
/// admission left free after the admitted bases; a Domain that grew past its
/// base and then died must not keep the frames out of it until its slot is
/// declared again by another Domain (`create_child` does that, much later).
/// A member leaving that is not the last gives nothing back.
/// **Canary** `budget-death-keeps-growth-canary`: the growth stays out of the
/// pool until the slot is reused.
#[test]
fn a_domains_death_gives_its_growth_back_to_the_pool() {
    let _s = serial();
    azos_mm::budget::set_growth_pool(10);
    let k = domain::create().expect("a free domain");
    domain::set_limit(k, 8);
    domain::set_ceiling(k, 16);
    assert!(matches!(domain::charge_request(k, 8, true), Some(Ok((azos_mm::budget::Granted::Within, 8)))));
    assert!(matches!(domain::charge_request(k, 6, true), Some(Ok((azos_mm::budget::Granted::Grew(6), 14)))));
    assert_eq!(azos_mm::budget::growth_pool(), 4);
    assert!(domain::join(k));
    assert!(!domain::leave(k), "a member that is not the last");
    assert_eq!(azos_mm::budget::growth_pool(), 4, "the Domain still lives, and so does its growth");
    assert!(domain::leave(k), "the last member");
    assert_eq!(azos_mm::budget::growth_pool(), 10, "a dead Domain holds no growth");
    assert!(domain::charge_request(k, 1, true).is_none(), "and its key names nothing");
}

/// **An exec keeps what the Domain's objects hold.** The exec's budget reset
/// forgets the old address space and keeps the frames of the objects whose
/// references outlive the image (the retained hook answers them), so the
/// release that comes later lands on the objects' share and not on the new
/// image's: the Domain never holds more than its limit. 8 pages of an object
/// and 2 of image, an exec to a 4-page image, then the object's release: 4
/// pages (the new image), not 0 and a room of 8 past the limit.
/// **Canary** `budget-exec-zeroes-canary`: the reset keeps nothing.
#[test]
fn an_exec_keeps_the_object_pages_and_the_release_then_leaves_the_new_image() {
    use std::sync::atomic::{AtomicU32, Ordering};
    static OBJECTS: AtomicU32 = AtomicU32::new(0);
    fn retained(_: Key) -> u32 { OBJECTS.load(Ordering::SeqCst) }
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| domain::set_retained_hook(retained));
    let _s = serial();
    let k = domain::create().expect("a free domain");
    domain::set_limit(k, 12);
    assert!(domain::charge(k, 2).is_some(), "the old image");
    assert!(domain::charge(k, 8).is_some(), "an object of 8 pages");
    OBJECTS.store(8, Ordering::SeqCst);
    domain::reset_budget(k);
    assert_eq!(domain::used_limit(k).0, 8, "the exec forgot the image and kept the object");
    assert!(domain::charge(k, 4).is_some(), "the new image");
    assert_eq!(domain::used_limit(k).0, 12);
    assert!(domain::charge(k, 1).is_none(), "the Domain is at its limit, not 8 under it");
    OBJECTS.store(0, Ordering::SeqCst);
    domain::discharge(k, 8);
    assert_eq!(domain::used_limit(k).0, 4, "the release leaves the new image's pages");
    domain::reset_budget(k);
    assert_eq!(domain::used_limit(k).0, 0, "with nothing held, a reset is the old one");
    free_all(k);
}

/// **A promised page table is never refused by the kernel-memory ledger.** The
/// first touch of a reserved page builds a table the reservation did not count
/// and has nowhere to report a refusal (`pager.rs`): the frame goes through
/// `charge_unrefused`, and so must the ledger's page-table bytes. At the limit
/// a plain page-table charge is refused; the promised one lands, passing the
/// limit, a plain charge stays refused until it is given back, and the table
/// going back returns the bytes (the mapping paths discharge them as they do
/// for any table).
/// **Canary** `kmem-promised-refused-canary`: past the limit it is dropped.
#[test]
fn a_promised_page_table_is_charged_to_the_kmem_ledger_past_its_limit() {
    let _s = serial();
    let k = domain::create().expect("a free domain");
    set_kmem_limit_kib(k, 8);
    assert!(kmem_charge_atomic(k, KmemClass::PageTable, 4096));
    assert!(kmem_charge_atomic(k, KmemClass::PageTable, 4096));
    assert!(!kmem_charge_atomic(k, KmemClass::PageTable, 4096), "a plain table is refused at the limit");
    domain::kmem_charge_unrefused(k, KmemClass::PageTable, 4096);
    assert_eq!(kmem_used_limit(k, KmemClass::PageTable).0, 3 * 4096, "the promised table was charged past the limit");
    assert!(!kmem_charge_atomic(k, KmemClass::PageTable, 1), "and a plain charge stays refused");
    kmem_discharge(k, KmemClass::PageTable, 4096);
    assert!(!kmem_charge_atomic(k, KmemClass::PageTable, 4096), "still over the limit by one table");
    kmem_discharge(k, KmemClass::PageTable, 4096);
    assert!(kmem_charge_atomic(k, KmemClass::PageTable, 4096), "back under it, a table fits");
    free_all(k);
}
