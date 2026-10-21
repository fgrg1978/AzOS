// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cross-class wake-up preemption: the decision for every class pair, inside
//! RT by priority, inside DL by deadline, and when the waking CPU is asked to
//! reschedule.

use crate::sc::Class;
use crate::wake_preempt::{local_resched, must_preempt, Running};

fn t(class: Class) -> Running {
    Running { class, prio: 20, deadline: None }
}
fn rt(prio: u32) -> Running {
    Running { class: Class::Rt, prio, deadline: None }
}
fn dl(deadline: Option<u64>) -> Running {
    Running { class: Class::Dl, prio: 0, deadline }
}

#[test]
fn every_class_pair_follows_the_precedence() {
    // Different classes: the better class preempts, whatever the levels.
    for cand in Class::PRECEDENCE {
        for cur in Class::PRECEDENCE {
            if cand == cur {
                continue;
            }
            let (c, r) = (t(cand), Some(t(cur)));
            assert_eq!(
                must_preempt(r, c),
                cand.rank() < cur.rank(),
                "{} woken onto {}",
                cand.name(),
                cur.name()
            );
        }
    }
    // A worse level does not matter across classes: a DL or RT task at a
    // numerically worse level still beats a fair task, and a stop task beats
    // all.
    assert!(must_preempt(Some(rt(1)), Running { class: Class::Stop, prio: 31, deadline: None }));
    assert!(must_preempt(Some(t(Class::Fair)), rt(11)));
    assert!(must_preempt(Some(rt(0)), dl(Some(u64::MAX))));
}

#[test]
fn same_class_stop_fair_and_idle_do_not_preempt() {
    for c in [Class::Stop, Class::Fair, Class::Idle] {
        assert!(!must_preempt(Some(t(c)), t(c)), "{}", c.name());
    }
}

#[test]
fn inside_rt_the_smaller_priority_number_preempts() {
    assert!(must_preempt(Some(rt(8)), rt(3)));
    assert!(!must_preempt(Some(rt(3)), rt(8)));
    // Equal level: the incumbent keeps the CPU (FIFO inside a level).
    assert!(!must_preempt(Some(rt(8)), rt(8)));
    assert!(must_preempt(Some(rt(11)), rt(0)));
    assert!(!must_preempt(Some(rt(0)), rt(11)));
}

#[test]
fn inside_dl_the_earlier_deadline_preempts() {
    assert!(must_preempt(Some(dl(Some(200))), dl(Some(100))));
    assert!(!must_preempt(Some(dl(Some(100))), dl(Some(200))));
    // A tie keeps the incumbent, as `edf_before` does.
    assert!(!must_preempt(Some(dl(Some(100))), dl(Some(100))));
}

#[test]
fn an_unreadable_deadline_defers_to_the_targets_own_tick() {
    // A remote wake cannot read the owner hart's deadlines: the answer is
    // "preempt", so that CPU compares them where they live.
    assert!(must_preempt(Some(dl(None)), dl(Some(100))));
    assert!(must_preempt(Some(dl(Some(100))), dl(None)));
    assert!(must_preempt(Some(dl(None)), dl(None)));
}

#[test]
fn a_cpu_running_nothing_real_is_preempted_by_everything_but_idle() {
    for c in [Class::Stop, Class::Dl, Class::Rt, Class::Fair] {
        assert!(must_preempt(None, t(c)), "{}", c.name());
    }
    assert!(!must_preempt(None, t(Class::Idle)));
}

#[test]
fn a_preempting_wake_on_the_same_cpu_sets_need_resched() {
    assert!(local_resched(Some(t(Class::Fair)), rt(5)));
    assert!(local_resched(Some(rt(8)), dl(Some(1))));
    assert!(local_resched(Some(rt(8)), rt(2)));
    assert!(local_resched(Some(dl(Some(9))), dl(Some(3))));
    assert!(local_resched(None, t(Class::Fair)));
}

#[test]
fn a_wake_that_does_not_preempt_asks_for_nothing() {
    assert!(!local_resched(Some(rt(3)), rt(8)));
    assert!(!local_resched(Some(t(Class::Fair)), t(Class::Fair)));
    assert!(!local_resched(Some(t(Class::Idle)), t(Class::Idle)));
    assert!(!local_resched(Some(t(Class::Fair)), t(Class::Idle)));
    assert!(!local_resched(Some(dl(Some(3))), dl(Some(9))));
}

/// The wake paths of `wake.rs` all enqueue through the checking wrapper: one
/// that called `wake_enqueue_locked` directly would skip the comparison.
#[test]
fn every_wake_path_in_wake_rs_goes_through_the_check() {
    const WAKE: &str = include_str!("../../../../crates/core/sched/src/scheduler/wake.rs");
    let direct: Vec<&str> = WAKE
        .lines()
        .filter(|l| {
            let l = l.trim_start();
            !l.starts_with("//") && l.contains("wake_enqueue_locked(")
        })
        .collect();
    assert_eq!(direct.len(), 1, "only the wrapper may call it: {direct:?}");
    let checked = WAKE
        .lines()
        .filter(|l| {
            let l = l.trim_start();
            !l.starts_with("//") && l.contains("wake_enqueue_preempting(") && !l.contains("unsafe fn")
        })
        .count();
    assert_eq!(checked, 4, "try_wake_task, wq_wake_by_tid, the K-C25 reaper, wake_task_by_tid");
    // The IPC hand-off's waker blocks right after: its wake does not leave
    // `need_resched` behind for the woken task to pay.
    assert!(WAKE.contains("wake_enqueue_preempting(target_cpu, i, !ipc)"));
}

/// The IPC fast path's enqueue of a claimed task whose waker did not block
/// (`direct_claim_enqueue`, outcome 3) is a wake like any other: it goes
/// through the checking wrapper with the check on, never to the raw enqueue.
/// The direct switch (outcome 4) queues nothing and so calls neither.
///
/// **Canary**: put `wake_enqueue_locked(target_cpu, ti)` back in
/// `direct_claim_enqueue` (or pass `false`): both asserts go red.
#[test]
fn the_fast_ipc_hand_off_whose_waker_kept_running_goes_through_the_check() {
    const FAST: &str = include_str!("../../../../crates/core/sched/src/scheduler/ipc_fast.rs");
    let code = |l: &&str| !l.trim_start().starts_with("//");
    let raw = FAST.lines().filter(code).filter(|l| l.contains("wake_enqueue_locked(")).count();
    assert_eq!(raw, 0, "a claimed task is enqueued through wake_enqueue_preempting");
    let checked: Vec<&str> = FAST
        .lines()
        .filter(code)
        .filter(|l| l.contains("wake_enqueue_preempting("))
        .collect();
    assert_eq!(checked.len(), 1, "{checked:?}");
    assert!(checked[0].contains("(target_cpu, ti, true)"), "the waker keeps running: check on");
    // And the one place that calls it is the hand-off's cold exit, not the
    // direct switch itself.
    assert!(FAST.contains("#[inline(never)]\nunsafe fn direct_claim_enqueue("));
}
