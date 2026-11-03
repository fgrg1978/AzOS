// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// A slot's generation running out, through the store and its sweep.

use super::*;
use azos_decision::{Record, Rule};

const CYCLE: u32 = CapHandle::MAX_GENERATION as u32;

fn records(rule: Rule, since: u64) -> Vec<Record> {
    let mut v = Vec::new();
    azos_decision::for_each(|x| {
        if x.seq > since && x.rule == rule as u8 {
            v.push(*x);
        }
    });
    v
}

fn last_seq() -> u64 {
    let mut s = 0;
    azos_decision::for_each(|x| s = s.max(x.seq));
    s
}

/// A task whose table has one free slot left, so every grant is that slot's.
fn one_free_slot(t: &Task) {
    let free = cap_store::with_table(t.tid, |tb| tb.free_slots()).unwrap();
    for i in 0..free - 1 {
        let _: Cap<Port> = cap_store::grant(t.tid, CapPerms::RW, 1000 + i as u32).unwrap();
    }
}

fn open(t: &Task, res: u32) -> Cap<Port> {
    cap_store::grant(t.tid, CapPerms::RW_DELEGATE, res).expect("a slot, far past where one used to retire")
}

fn close(t: &Task, c: Cap<Port>) {
    assert!(cap_store::with_table(t.tid, |tb| tb.delete_raw(c.raw())).unwrap());
}

/// The bug: 2,047 grants of a slot and it was lost for the domain's life. Three
/// whole cycles through the only free slot, and the record says when each
/// restart happened. **Canary** `canary_gen_retire`: the next test.
#[test]
fn a_domain_opens_and_closes_past_every_cycle_with_one_slot() {
    let _g = wguard();
    let t = wtask(WARRANT_SLOT0);
    one_free_slot(&t);
    let since = last_seq();
    let mut slot = None;
    for i in 0..3 * CYCLE + 5 {
        let c = open(&t, i);
        assert_eq!(*slot.get_or_insert(c.raw().slot()), c.raw().slot());
        assert_eq!(cap_store::get(t.tid, c, CapPerms::READ), Ok(i));
        close(&t, c);
    }
    // A sweep restarts every parked slot of every domain, so a slot another test left
    // parked can restart during this loop: only this domain's records count.
    let mut restarts = records(Rule::CapSlotRestart, since);
    restarts.retain(|r| r.subject == key(&t));
    assert_eq!(restarts.len(), 3);
    assert_eq!(restarts[2].n[0], slot.unwrap() as u64, "the record names the slot");
    assert_eq!(restarts[2].n[1], 3);
}

/// Without the restart the same loop ends in a refusal at the end of the first
/// cycle, the bug's shape with a wider field.
#[test]
fn canary_gen_retire_loses_the_slot() {
    let _g = wguard();
    let t = wtask(WARRANT_SLOT0);
    one_free_slot(&t);
    crate::cap::canary_gen_retire(true);
    let mut refused_at = None;
    for i in 0..CYCLE + 5 {
        match cap_store::grant::<Port>(t.tid, CapPerms::RW, i) {
            Some(c) => close(&t, c),
            None => {
                refused_at = Some(i);
                break;
            }
        }
    }
    crate::cap::canary_gen_retire(false);
    assert_eq!(refused_at, Some(CYCLE));
    cap_store::with_table(t.tid, |tb| tb.unpark());
}

/// A stale handle is refused at every grant across the point the generation
/// used to retire, and across the top of the cycle; at the restart only the
/// recurrence the design names comes back, and nothing else does.
#[test]
fn a_stale_handle_is_refused_across_the_old_limit_and_the_restart() {
    let _g = wguard();
    let t = wtask(WARRANT_SLOT0);
    one_free_slot(&t);
    let first = open(&t, 1);
    let first_raw = first.raw();
    close(&t, first);
    let mut at_old_limit = None;
    let mut at_top = None;
    for i in 2..=CYCLE {
        let c = open(&t, i);
        assert_eq!(c.raw().generation() as u32, i);
        assert_eq!(cap_store::get(t.tid, ch(first_raw), CapPerms::READ), Err(CapError::Stale));
        if let Some(old) = at_old_limit {
            assert_eq!(cap_store::get(t.tid, old, CapPerms::READ), Err(CapError::Stale), "at generation {i}");
        }
        if i == 2047 {
            at_old_limit = Some(c);
        }
        if i == CYCLE {
            at_top = Some(c);
        }
        close(&t, c);
    }
    let (at_old_limit, at_top) = (at_old_limit.unwrap(), at_top.unwrap());
    let restarted = open(&t, 9);
    assert_eq!(restarted.raw().generation(), 1);
    assert_eq!(cap_store::get(t.tid, at_top, CapPerms::READ), Err(CapError::Stale));
    assert_eq!(cap_store::get(t.tid, at_old_limit, CapPerms::READ), Err(CapError::Stale));
    assert_eq!(cap_store::get(t.tid, ch(first_raw), CapPerms::READ), Ok(9), "the documented recurrence");
}

// REQ-001
/// A reference between domains does not revive: a copy whose parent was revoked
/// went with it, and a copy whose parent was deleted was hung elsewhere, so a
/// later occupant at the very generation the parent had is nobody's parent.
#[test]
fn a_warrant_does_not_revive_across_a_restart() {
    let _g = wguard();
    let (a, b) = (wtask(WARRANT_SLOT0), wtask(WARRANT_SLOT0 + 1));
    one_free_slot(&a);
    let parent = open(&a, 5);
    let (slot, gen) = (parent.raw().slot(), parent.raw().generation());
    let copy = dup(&a, &b, parent.raw()).unwrap();
    close(&a, parent);
    assert!(live(&b, copy), "a delete keeps what was derived");
    assert_ne!(warrant(&b, copy).parent, azos_decision::warrant_ref(key(&a), slot, gen));
    let mut again = None;
    for i in 0..CYCLE + 1 {
        let c = open(&a, 100 + i);
        if c.raw().slot() == slot && c.raw().generation() == gen {
            again = Some(c);
            break;
        }
        close(&a, c);
    }
    let again = again.expect("the slot came round to the parent's generation");
    cap_store::revoke(a.tid, again);
    assert!(live(&b, copy), "revoking the later occupant does not reach the old parent's copy");
}

/// A grant that finds no slot leaves a record of why: live slots, parked ones,
/// and how many refusals, at powers of two so a loop does not flood the ring.
#[test]
fn a_full_table_refuses_with_a_record() {
    let _g = wguard();
    let t = wtask(WARRANT_SLOT0);
    one_free_slot(&t);
    let last: Cap<Port> = open(&t, 2);
    let since = last_seq();
    for _ in 0..3 {
        assert!(cap_store::grant::<Port>(t.tid, CapPerms::RW, 3).is_none());
    }
    let refused = records(Rule::CapTableFull, since);
    assert_eq!(refused.len(), 2, "refusals 1 and 2; the third is not a power of two");
    let live = cap_store::with_table(t.tid, |tb| tb.occupied()).unwrap() as u64;
    assert_eq!(refused[0].n, [live, 0, 1]);
    assert_eq!(refused[1].n, [live, 0, 2]);
    assert_eq!(refused[0].subject, key(&t));
    close(&t, last);
    assert!(cap_store::grant::<Port>(t.tid, CapPerms::RW, 4).is_some(), "a slot freed is a slot granted");
}

/// A sender that names more capabilities than the receiver has slots is
/// refused with the same record, before anything moves.
#[test]
fn a_transfer_into_a_full_table_refuses_with_a_record() {
    let _g = wguard();
    let (a, b) = (wtask(WARRANT_SLOT0), wtask(WARRANT_SLOT0 + 1));
    one_free_slot(&b);
    let _: Cap<Port> = cap_store::grant(b.tid, CapPerms::RW, 1).unwrap();
    let c: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 7).unwrap();
    let since = last_seq();
    assert_eq!(dup(&a, &b, c.raw()), Err(CapError::NoSpace));
    assert_eq!(records(Rule::CapTableFull, since).len(), 1);
}
