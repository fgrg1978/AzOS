// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for the subtree policy of `crates/core/sched/src/domain.rs`
//! (SUBTREE-POLICY), the real file: a `[policy.NAME]` row with `scope =
//! "subtree"` binds a Domain and every Domain beneath it, the walk is bounded
//! at `WALK_MAX` = 8 ancestors without leaving a hole, and a refusal leaves a
//! `subtree-policy` record.
//!
//! The domain table is one process-wide static: every test takes the lock of
//! `domain_tests` (which counts the table) and frees what it made.

use crate::domain::{self, Create, Key, Limits, Refusal, NONE, WALK_MAX};
use crate::domain_tests::serial;
use azos_decision::{Rule, Verdict};

fn free(k: Key) {
    while domain::live(k) != 0 {
        domain::leave(k);
    }
}

const NO_PORTS: Limits = Limits { create_ports: false, ..Limits::NONE };
const NO_ENDPOINTS: Limits = Limits { create_endpoints: false, ..Limits::NONE };
const fn ceiling(pages: u32) -> Limits {
    Limits { memobj_max_pages: pages, ..Limits::NONE }
}

/// A chain `root`, then `n` Domains each created by the previous one.
fn chain(root: Key, n: usize) -> Vec<Key> {
    let mut v = vec![root];
    for _ in 0..n {
        v.push(domain::create_child(*v.last().unwrap()).expect("a free domain"));
    }
    v
}

fn free_all(v: &[Key]) {
    for &k in v.iter().rev() {
        free(k);
    }
}

fn refused(k: Key, what: Create) -> Option<(Key, u8)> {
    domain::refusal(k, what).map(|r| (r.policy, r.depth))
}

#[test]
fn limits_narrow_and_have_an_identity() {
    let both = NO_PORTS.narrow(NO_ENDPOINTS);
    assert!(!both.create_ports && !both.create_endpoints);
    assert_eq!(Limits::NONE.narrow(NO_PORTS), NO_PORTS, "NONE is the identity");
    assert_eq!(ceiling(0).narrow(ceiling(8)), ceiling(8), "0 is no ceiling");
    assert_eq!(ceiling(64).narrow(ceiling(8)), ceiling(8), "the smaller ceiling holds");
    assert_eq!(ceiling(8).narrow(ceiling(64)), ceiling(8));
    // The Domain words round-trip: a fresh Domain's zero words are NONE.
    let k = domain::create().unwrap();
    assert_eq!(domain::refusal(k, Create::Port), None);
    domain::set_policy(k, NO_PORTS.narrow(ceiling(7)), Limits::NONE);
    assert_eq!(refused(k, Create::Port), Some((k, 0)));
    assert_eq!(refused(k, Create::MemObj(8)), Some((k, 0)));
    assert_eq!(refused(k, Create::MemObj(7)), None, "the ceiling itself is allowed");
    assert_eq!(refused(k, Create::Endpoint), None);
    free(k);
}

#[test]
fn a_subtree_limit_is_inherited_three_levels_down() {
    let _s = serial();
    let root = domain::create().unwrap();
    domain::set_policy(root, Limits::NONE, NO_PORTS.narrow(ceiling(64)));
    let v = chain(root, 3);
    for (level, &k) in v.iter().enumerate() {
        assert_eq!(refused(k, Create::Port), Some((root, level as u8)), "level {level}: the row of the root, {level} up");
        assert_eq!(refused(k, Create::MemObj(65)), Some((root, level as u8)), "level {level}");
        assert_eq!(refused(k, Create::MemObj(64)), None, "the ceiling itself");
        assert_eq!(refused(k, Create::Endpoint), None, "what the row does not forbid");
    }
    assert_eq!(domain::info(v[3]).unwrap().depth, 3);
    assert_eq!(domain::info(v[3]).unwrap().parent, v[2]);
    free_all(&v);
}

#[test]
fn a_self_row_binds_the_domain_and_not_its_children() {
    let _s = serial();
    let root = domain::create().unwrap();
    domain::set_policy(root, NO_PORTS, Limits::NONE);
    let kid = domain::create_child(root).unwrap();
    assert_eq!(refused(root, Create::Port), Some((root, 0)));
    assert_eq!(refused(kid, Create::Port), None);
    free_all(&[root, kid]);
}

#[test]
fn a_descendant_cannot_exceed_its_ancestors_limit() {
    let _s = serial();
    let root = domain::create().unwrap();
    domain::set_policy(root, Limits::NONE, ceiling(64).narrow(NO_ENDPOINTS));
    let v = chain(root, 2);
    let leaf = v[2];
    // Granted everything by its own row: the ancestor still holds.
    domain::set_policy(leaf, Limits::NONE, Limits::NONE);
    assert_eq!(refused(leaf, Create::Endpoint), Some((root, 2)));
    assert_eq!(refused(leaf, Create::MemObj(100)), Some((root, 2)));
    // A stricter row of its own narrows further; the nearest refusal is named.
    domain::set_policy(leaf, ceiling(16), Limits::NONE);
    assert_eq!(refused(leaf, Create::MemObj(20)), Some((leaf, 0)));
    assert_eq!(refused(leaf, Create::MemObj(16)), None);
    assert_eq!(refused(leaf, Create::Endpoint), Some((root, 2)), "the ancestor's still stands");
    // The limit of one branch is not its sibling's.
    let side = domain::create_child(domain::create().unwrap()).unwrap();
    assert_eq!(refused(side, Create::Endpoint), None);
    free_all(&v);
    free(domain::info(side).unwrap().parent);
    free(side);
}

#[test]
fn a_refusal_leaves_a_subtree_policy_record() {
    let _s = serial();
    let root = domain::create().unwrap();
    domain::set_policy(root, Limits::NONE, ceiling(64));
    let v = chain(root, 2);
    let before = azos_decision::total();
    assert_eq!(domain::check_create(v[2], Create::MemObj(64)), Ok(()));
    assert_eq!(
        domain::check_create(v[2], Create::MemObj(65)),
        Err(Refusal { policy: root, depth: 2, action: Create::MemObj(65).action() })
    );
    let mut got = Vec::new();
    azos_decision::for_each(|r| {
        if r.seq > before && r.rule == Rule::SubtreePolicy as u8 {
            got.push((r.verdict, r.subject, r.n));
        }
    });
    assert_eq!(
        got,
        vec![(Verdict::Refuse as u8, v[2], [u64::from(root), 2, 3 | 65 << 8])],
        "one record for the refusal, none for the grant: the actor, whose limit, how far up, what"
    );
    assert_eq!(Create::Endpoint.action(), 1);
    assert_eq!(Create::Port.action(), 2);
    free_all(&v);
}

#[test]
fn a_key_that_names_no_domain_is_not_limited() {
    let _s = serial();
    assert_eq!(domain::check_create(NONE, Create::Port), Ok(()), "the kernel's own objects");
    let k = domain::create().unwrap();
    domain::set_policy(k, NO_PORTS, NO_PORTS);
    free(k);
    assert_eq!(domain::check_create(k, Create::Port), Ok(()), "an ended domain");
}

#[test]
fn the_walk_bound_is_eight_and_the_chain_stays_within_it() {
    assert_eq!(WALK_MAX, 8);
    let _s = serial();
    let root = domain::create().unwrap();
    domain::set_policy(root, Limits::NONE, NO_PORTS);
    // Twelve levels: past the bound.
    let v = chain(root, WALK_MAX + 4);
    for (level, &k) in v.iter().enumerate() {
        let i = domain::info(k).unwrap();
        assert!(usize::from(i.depth) <= WALK_MAX, "level {level} sits at depth {}", i.depth);
        let r = refused(k, Create::Port).unwrap_or_else(|| panic!("level {level} escaped the root's row"));
        assert_eq!(r.0, root, "level {level}");
        assert!(usize::from(r.1) <= WALK_MAX, "level {level}: the root is {} up", r.1);
    }
    // The ninth level and beyond are attached higher up, not dropped.
    assert_eq!(domain::info(v[WALK_MAX]).unwrap().parent, v[WALK_MAX - 1]);
    assert_eq!(domain::info(v[WALK_MAX + 1]).unwrap().parent, v[WALK_MAX - 1], "left out of the chain");
    assert_eq!(domain::info(v[WALK_MAX + 4]).unwrap().parent, v[WALK_MAX - 1]);
    free_all(&v);
}

#[test]
fn a_limit_bound_on_a_domain_left_out_of_the_chain_still_holds() {
    let _s = serial();
    let root = domain::create().unwrap();
    let mut v = chain(root, WALK_MAX);
    // The Domain at depth 8 binds a ceiling, then a Domain is made beneath it:
    // the new one is attached to its parent and takes the ceiling as its own.
    domain::set_policy(v[WALK_MAX], Limits::NONE, ceiling(16));
    let deep = domain::create_child(v[WALK_MAX]).unwrap();
    v.push(deep);
    let grandchild = domain::create_child(deep).unwrap();
    v.push(grandchild);
    assert_eq!(refused(deep, Create::MemObj(17)), Some((deep, 0)), "the bound is part of the Domain");
    // `deep` is at the bound too, so the Domain beneath it is attached higher
    // and takes the ceiling the same way.
    assert_eq!(refused(grandchild, Create::MemObj(17)), Some((grandchild, 0)), "and of what is beneath it");
    assert_eq!(refused(grandchild, Create::MemObj(16)), None);
    // A new image in the Domain keeps what its ancestors imposed.
    domain::set_policy(deep, Limits::NONE, Limits::NONE);
    assert_eq!(refused(deep, Create::MemObj(17)), Some((deep, 0)));
    free_all(&v);
}

#[test]
fn a_limit_outlives_the_domain_that_carried_it() {
    let _s = serial();
    let base = domain::count();
    let a = domain::create().unwrap();
    domain::set_policy(a, Limits::NONE, NO_ENDPOINTS);
    let b = domain::create_child(a).unwrap();
    domain::set_policy(b, Limits::NONE, ceiling(32));
    let c = domain::create_child(b).unwrap();
    assert_eq!(refused(c, Create::Endpoint), Some((a, 2)));
    assert_eq!(refused(c, Create::MemObj(33)), Some((b, 1)));

    // The middle Domain ends: its child is re-attached to the root and takes
    // the ceiling along.
    free(b);
    assert_eq!(domain::info(c).unwrap().parent, a);
    assert_eq!(refused(c, Create::Endpoint), Some((a, 1)));
    assert_eq!(refused(c, Create::MemObj(33)), Some((c, 0)), "carried by the orphan now");

    // The root ends too: nothing is left to walk, and both limits still hold.
    free(a);
    assert_eq!(domain::info(c).unwrap().parent, NONE);
    assert_eq!(refused(c, Create::Endpoint), Some((c, 0)));
    assert_eq!(refused(c, Create::MemObj(33)), Some((c, 0)));
    // And so does the next generation made beneath it.
    let d = domain::create_child(c).unwrap();
    assert_eq!(refused(d, Create::MemObj(33)), Some((c, 1)));
    assert_eq!(refused(d, Create::Endpoint), Some((c, 1)));
    free_all(&[c, d]);
    assert_eq!(domain::count(), base);
}

#[test]
fn child_counts_follow_domains_that_come_and_go() {
    let _s = serial();
    let a = domain::create().unwrap();
    let b = domain::create_child(a).unwrap();
    let c = domain::create_child(a).unwrap();
    let d = domain::create_child(b).unwrap();
    free(b); // d is a's now
    assert_eq!(domain::info(d).unwrap().parent, a);
    // `a` has c and d; ending it must still find both (the scan runs while a
    // child count says there are some).
    domain::set_policy(a, Limits::NONE, NO_PORTS);
    free(a);
    for k in [c, d] {
        assert_eq!(domain::info(k).unwrap().parent, NONE);
        assert_eq!(refused(k, Create::Port), Some((k, 0)));
    }
    free_all(&[c, d]);
}

#[test]
fn a_reused_slot_carries_nothing_over() {
    let _s = serial();
    let a = domain::create().unwrap();
    domain::set_policy(a, NO_PORTS, NO_PORTS);
    let kid = domain::create_child(a).unwrap();
    free(kid);
    free(a);
    // A creator that is gone makes a root; a slot reused starts clean.
    let r = domain::create_child(a).unwrap();
    assert_eq!(domain::info(r).unwrap().parent, NONE);
    assert_eq!(domain::refusal(r, Create::Port), None);
    free(r);
}
