// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! I-13 (`domains/robot/safety-core/src/txn_rule.rs`, pulled in by `#[path]`):
//! only a whitelisted kernel-mode fault of the task that armed the checkpoint
//! is rolled back into its restart, and only while the budget lasts.

#[path = "../../../../domains/robot/safety-core/src/txn_rule.rs"]
mod txn_rule;

use txn_rule::{may_roll_back, Fault, MAX_TXN_RESTARTS};

const CONTROL: u32 = 7;
const ARMED: Fault = Fault { recoverable: true, armed_tid: CONTROL, current_tid: CONTROL, streak: 0 };

#[test]
fn the_armed_task_s_recoverable_fault_rolls_back() {
    assert!(may_roll_back(ARMED));
    assert!(may_roll_back(Fault { streak: MAX_TXN_RESTARTS - 1, ..ARMED }));
}

#[test]
fn another_task_on_the_same_cpu_is_never_restarted_as_the_control_task() {
    // A kernel task, or a user task the control task was preempted for (the
    // checkpoint used to be per CPU: their frame was sent to the control
    // task's entry, on its stack).
    assert!(!may_roll_back(Fault { current_tid: CONTROL + 1, ..ARMED }));
    assert!(!may_roll_back(Fault { armed_tid: 0, current_tid: 0, ..ARMED }), "nothing armed");
}

#[test]
fn a_fault_outside_the_whitelist_or_past_the_budget_stays_fatal() {
    assert!(!may_roll_back(Fault { recoverable: false, ..ARMED }));
    assert!(!may_roll_back(Fault { streak: MAX_TXN_RESTARTS, ..ARMED }), "a deterministic fault escalates");
}
