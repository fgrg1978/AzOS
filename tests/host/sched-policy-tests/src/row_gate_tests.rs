// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `crates/core/sched/src/row_gate.rs`: the live-instance count of a topology
//! row, which a spawn, a row-changing exec and a fork child all draw on.
//!
//! * `a_fork_child_is_refused_past_its_rows_instances`: a row with
//!   `instances = 2` holds a parent, takes one fork child, and refuses the
//!   next; the exit of one gives the place back. Canary
//!   `fork-row-instance-canary` (a fork child is never refused): red.
//! * `a_row_with_one_instance_takes_no_fork_child`: the default row (1).
//!   Same canary.
//! * `a_row_that_never_counted_refuses_closed`: no recorded cap is no room.
//!
//! The wiring in `process.rs` (claim before the child exists, the child's row
//! recorded, the release on each failure exit) is read from its source by
//! `tests/host/syscall-tests` (`the_fork_claims_its_row_and_gives_it_back`).

use crate::row_gate::*;

// The statics are process-wide: each test owns a row of its own.

#[test]
fn a_fork_child_is_refused_past_its_rows_instances() {
    const ROW: u16 = 5;
    assert!(row_claim(ROW, 2), "the parent's own count");
    assert!(row_claim_for_fork(ROW), "the first child fits");
    assert_eq!(row_live(ROW), 2);
    assert!(!row_claim_for_fork(ROW), "the row is full: the child is refused");
    assert_eq!(row_live(ROW), 2, "a refusal takes nothing");
    row_release(ROW);
    assert!(row_claim_for_fork(ROW), "an exit gives its place back");
    row_release(ROW);
    row_release(ROW);
    assert_eq!(row_live(ROW), 0);
}

#[test]
fn a_row_with_one_instance_takes_no_fork_child() {
    const ROW: u16 = 6;
    assert!(row_claim(ROW, 1));
    assert!(!row_claim_for_fork(ROW));
    assert_eq!(row_live(ROW), 1);
    row_release(ROW);
}

#[test]
fn a_row_that_never_counted_refuses_closed() {
    const ROW: u16 = 7;
    assert_eq!(row_cap(ROW), 0);
    assert!(!row_claim_for_fork(ROW) || cfg!(feature = "fork-row-instance-canary"));
    assert_eq!(row_live(ROW), 0);
}

#[test]
fn no_row_counts_nothing() {
    assert!(row_claim_for_fork(0));
    assert!(row_claim(0, 1));
    assert_eq!(row_live(0), 0);
}

/// An exec re-pins: the reservation's single hart, else none.
///
/// **Canary.** `exec-pin-kept-canary`: hart 0 always.
#[test]
fn an_exec_pins_to_the_rows_hart_or_to_none() {
    assert_eq!(exec_pin(None), -1);
    assert_eq!(exec_pin(Some(0)), -1);
    assert_eq!(exec_pin(Some(0b1000)), 3);
    assert_eq!(exec_pin(Some(0b1100)), -1, "a mask of several harts pins none");
}
