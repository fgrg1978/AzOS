// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The interrupt bracket, the tick's shared work and the reschedule gate
//! (`kernel/src/trap/irq.rs`).

use crate::fakes::*;
use crate::trap::fault::fatal_note;
use crate::trap::irq::{arm, resched_exit, tick_work, Resched};

fn user_frame() -> RvFrame {
    RvFrame::default()
}

fn kernel_frame() -> RvFrame {
    RvFrame { s_mode: true, ..Default::default() }
}

/// **The QSBR boundary opens before the ISR depth, the body runs inside both,
/// and they close in the reverse order.**
#[test]
fn the_bracket_nests() {
    reset();
    let mut f = user_frame();
    arm::<Fake, _>(&mut f, |_| log("body"));
    assert_eq!(
        logged(),
        ["arm_guard user=true", "isr_enter 3", "body", "isr_exit 3", "drop arm_guard"],
        "the guard outlives the depth mark"
    );
}

#[test]
fn the_bracket_reports_a_kernel_interrupt_as_not_from_user() {
    reset();
    let mut f = kernel_frame();
    arm::<Fake, _>(&mut f, |_| {});
    assert!(saw("arm_guard user=false"));
}

/// The tick's shared work, in the order every ISA's tick had it.
#[test]
fn the_tick_does_the_shared_work_in_order() {
    reset();
    tick_work::<Fake, RvFrame>(5000, Some(77), Some(12));
    assert_eq!(logged(), ["watchdog_tick", "vdso_tick 77 Some(12) 5000", "wake_expired 5000", "reap_stamped"]);
}

#[test]
fn the_vdso_ticks_with_the_watchdogs_counter_when_the_isa_has_none() {
    reset();
    tick_work::<Fake, RvFrame>(5000, None, Some(12));
    assert!(saw("vdso_tick 100 Some(12)"), "{:?}", logged());
}

/// Before the timer is armed (`now == 0`) nothing can have expired; recovering
/// a stamped sleeper needs no clock, so it still runs.
#[test]
fn an_unarmed_clock_sweeps_no_timers_but_still_reaps() {
    reset();
    tick_work::<Fake, RvFrame>(0, Some(1), None);
    assert_eq!(logged(), ["watchdog_tick", "vdso_tick 1 None 0", "reap_stamped"]);
}

/// **A reschedule raised before the scheduler runs is left raised, not dropped:
/// the first exit after the gate opens spends it.**
#[test]
fn the_gate_leaves_a_raised_flag_raised() {
    reset();
    let r = Resched::<4>::new();
    r.request(3);
    let mut f = kernel_frame();
    resched_exit::<Fake, _, 4>(&r, &mut f);
    assert_eq!(with(|s| s.schedules), 0, "the scheduler is not running yet");
    assert!(!saw("exit_guard"), "not even the guards before the gate: {:?}", logged());
    r.set_live();
    resched_exit::<Fake, _, 4>(&r, &mut f);
    assert_eq!(with(|s| s.schedules), 1, "the flag survived the closed gate");
    resched_exit::<Fake, _, 4>(&r, &mut f);
    assert_eq!(with(|s| s.schedules), 1, "and was spent once");
    assert_eq!(r.preempts(), 1);
}

#[test]
fn an_exit_without_a_request_does_not_schedule() {
    reset();
    let r = Resched::<4>::new();
    r.set_live();
    let mut f = user_frame();
    resched_exit::<Fake, _, 4>(&r, &mut f);
    assert_eq!(with(|s| s.schedules), 0);
    assert_eq!(r.preempts(), 0);
}

/// A request lands on the CPU it names; the exit spends its own CPU's flag only
/// (the fake kernel runs on CPU 3). An out-of-range CPU is ignored.
#[test]
fn a_request_is_per_cpu() {
    reset();
    let r = Resched::<4>::new();
    r.set_live();
    r.request(1);
    r.request(99);
    let mut f = kernel_frame();
    resched_exit::<Fake, _, 4>(&r, &mut f);
    assert_eq!(with(|s| s.schedules), 0, "CPU 1's request is CPU 1's");
    r.request(3);
    resched_exit::<Fake, _, 4>(&r, &mut f);
    assert_eq!(with(|s| s.schedules), 1);
}

/// **The task work that may park the task (a forced stop, a signal) runs at the
/// return to user mode only, on the task's own stack, before the reschedule.**
#[test]
fn user_return_work_runs_only_for_an_interrupt_taken_from_user_mode() {
    reset();
    let r = Resched::<4>::new();
    r.set_live();
    r.request(3);
    let mut f = user_frame();
    resched_exit::<Fake, _, 4>(&r, &mut f);
    assert!(at("user_return_work").unwrap() < at("schedule").unwrap(), "{:?}", logged());
    assert!(saw("exit_guard user=true"));

    reset();
    r.request(3);
    let mut k = kernel_frame();
    resched_exit::<Fake, _, 4>(&r, &mut k);
    assert!(!saw("user_return_work"), "a nested kernel interrupt does no task work: {:?}", logged());
}

/// **A hart whose interrupt stack lost its magic word is fatal before anything
/// else: a corrupted stack is not a state to keep driving in.**
#[test]
fn an_overflowed_interrupt_stack_is_fatal() {
    reset();
    with(|s| s.stack_ok = false);
    let r = Resched::<4>::new();
    r.set_live();
    r.request(3);
    let mut f = user_frame();
    assert!(matches!(ends(|| resched_exit::<Fake, _, 4>(&r, &mut f)), Ended::Halted));
    assert!(saw("Interrupt stack of cpu 3 overflowed its slot"), "{:?}", logged());
    assert_eq!(with(|s| s.schedules), 0);
}

#[test]
fn the_fatal_note_takes_the_same_tail_as_a_fault() {
    reset();
    assert!(matches!(ends(|| fatal_note::<Fake, RvFrame>(format_args!("boom"))), Ended::Halted));
    assert_eq!(logged(), ["stop_actuators", "halt_begin", "error: boom", "halt_report", "fatal_halt"]);
}
