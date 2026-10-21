// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The foundational case of each syscall number (`azos_abi::syscall_nr`) and the
//! per-Domain entry counters (`domain.rs`) the prologue calls.

use crate::domain::{self, ENTRY_SLOTS, NONE};
use azos_abi::syscall_nr::*;

#[test]
fn every_assigned_number_has_a_case_and_the_holes_have_none() {
    assert_eq!(syscall_case(0), 0, "number 0 is no call");
    for nr in 1..SYS_NR_RESERVED_UPPER {
        let c = syscall_case(nr);
        assert!((1..=CASES as u8).contains(&c), "syscall {nr} has no foundational case ({c})");
    }
    assert_eq!(syscall_case(SYS_NR_RESERVED_UPPER), 0, "the first unassigned number has no case");
    assert_eq!(syscall_case(u64::MAX), 0);
    assert_eq!(SYSCALL_CASE.len() as u64, SYS_NR_RESERVED_UPPER);
}

/// The cases are the ones each call's doc names ("Foundational case N").
#[test]
fn the_cases_are_the_ones_the_docs_name() {
    for nr in [SYS_CAP_INFO, SYS_CAP_DERIVE, SYS_SPAWN_EX, SYS_EXIT, SYS_GETPID, SYS_MO_MAP, SYS_RING_SETUP, SYS_INVOKE] {
        assert_eq!(syscall_case(nr), CASE_AUTHORITY, "syscall {nr}");
    }
    for nr in [
        SYS_YIELD, SYS_SLEEP_UNTIL, SYS_IPC_FAST_CALL_EP, SYS_IPC_FAST_REPLY, SYS_IPC_FAST_ACCEPT,
        SYS_IPC_FAST_REPLY_ACCEPT, SYS_IPC_CALL_V2, SYS_RING_ENTER, SYS_PORT_WAIT, SYS_FUTEX_WAIT, SYS_FUTEX_WAKE,
    ] {
        assert_eq!(syscall_case(nr), CASE_BLOCK_WAKE, "syscall {nr}");
    }
}

/// The lean entries' range test treats the two IPC fast calls it admits as one
/// pair; a case table must not split them.
#[test]
fn the_two_lean_ipc_calls_share_a_case() {
    assert_eq!(syscall_case(SYS_IPC_FAST_CALL_EP), syscall_case(SYS_IPC_FAST_REPLY_ACCEPT));
}

#[test]
fn a_fresh_domain_has_counted_nothing() {
    let k = domain::create().unwrap();
    assert_eq!(domain::entries(k), [0; ENTRY_SLOTS]);
    domain::leave(k);
}

#[test]
fn entries_are_counted_by_case_and_a_number_with_no_case_goes_to_slot_0() {
    let k = domain::create().unwrap();
    domain::count_entry(k, CASE_AUTHORITY);
    domain::count_entry(k, CASE_BLOCK_WAKE);
    domain::count_entry(k, CASE_BLOCK_WAKE);
    domain::count_entry(k, 0);
    let want = if azos_limits::DOMAIN_ENTRY_COUNTERS { [1, 1, 2] } else { [0; ENTRY_SLOTS] };
    assert_eq!(domain::entries(k), want);
    domain::leave(k);
}

#[test]
fn a_key_that_names_no_domain_counts_nothing() {
    domain::count_entry(NONE, CASE_AUTHORITY);
    assert_eq!(domain::entries(NONE), [0; ENTRY_SLOTS], "a kernel task has no Domain");
    let k = domain::create().unwrap();
    domain::leave(k);
    assert_eq!(domain::entries(k), [0; ENTRY_SLOTS], "a dead key names nothing");
}

/// A slot freed and taken again carries none of the old counts.
#[test]
fn a_reused_slot_starts_clean() {
    let k = domain::create().unwrap();
    domain::count_entry(k, CASE_AUTHORITY);
    domain::leave(k);
    // The table hands out the lowest free slot; take domains until the slot
    // returns under a new generation.
    let mut held = Vec::new();
    let again = loop {
        let n = domain::create().unwrap();
        if domain::index(n) == domain::index(k) {
            break n;
        }
        held.push(n);
    };
    assert_ne!(again, k, "a new generation");
    assert_eq!(domain::entries(again), [0; ENTRY_SLOTS]);
    held.push(again);
    for n in held {
        domain::leave(n);
    }
}
