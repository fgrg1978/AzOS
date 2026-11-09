// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A kernel call task (`kernel/src/call_task.rs`) that finds nothing posted
//! parks on `Timer(park_reason(now))`, and the client that posts wakes it by
//! that value. The wake is the scheduler's real transition (`wake_transition`),
//! so these are the interleavings of the task's look at the slot, the client's
//! post and wake, and the task's commit to sleep, with the reason each side
//! computed at its own time.

use crate::task::sched_word::{self, commit_blocked_or_consume_wake, wake_transition, WakeTransition};
use crate::task::TaskState;
use azos_devif::call_slot::park_reason;
use core::sync::atomic::{AtomicU32, Ordering};

fn running() -> AtomicU32 {
    AtomicU32::new(sched_word::pack(TaskState::Running))
}

/// The client's wake against the word, naming `named` while the task sleeps on
/// `parked`.
fn wake(w: &AtomicU32, named: u64, parked: u64) -> WakeTransition {
    wake_transition(w, || true, || named == parked, true, || true)
}

#[test]
fn a_wake_before_the_commit_is_kept_and_the_task_does_not_sleep() {
    let (t_client, t_task) = (5, 9);
    let w = running();
    assert_eq!(wake(&w, park_reason(t_client), park_reason(t_task)), WakeTransition::Stamped);
    assert!(!commit_blocked_or_consume_wake(&w), "the stamp ends the park before it starts");
}

#[test]
fn a_wake_after_the_commit_finds_the_task_parked_on_the_reason_it_names() {
    let (t_client, t_task) = (5, 9);
    let w = running();
    assert!(commit_blocked_or_consume_wake(&w));
    assert_eq!(
        wake(&w, park_reason(t_client), park_reason(t_task)),
        WakeTransition::Dispatched,
        "a wake that names another value than the park's is dropped and the task sleeps on"
    );
    assert_eq!(sched_word::state_of(w.load(Ordering::Acquire)), TaskState::Ready);
}
