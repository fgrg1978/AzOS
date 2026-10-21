// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cross-class wake-up preemption: when a task becomes ready on a CPU, must
//! the task that CPU runs give way to it, and how is the CPU told?
//!
//! Pure: no kernel state, so `tests/host/sched-wake-tests` compiles this file
//! as is (with `sc.rs` and `rt_core.rs`). `wake.rs` reads the facts (the
//! class, level and deadline of both tasks) and applies the answer.
//!
//! # Why a wake needs its own check
//!
//! The dispatch order is `stop > DL > RT > fair > idle` (`sc::Class`), but the
//! tick is where it was enforced: a task woken onto a CPU running a worse
//! class waited for that CPU's next tick or `schedule()`. For a reservation
//! or a band task woken by a fair task on the same hart that is up to a tick
//! of latency on a path that has a deadline.
//!
//! # The rule
//!
//! * Different classes: the better class preempts ([`Class::preempts`]).
//! * Stop: never preempts another stop task (stop work runs to completion).
//! * RT: the strictly smaller priority number.
//! * DL: the strictly earlier absolute deadline. A deadline the caller could
//!   not read (it lives in the owner hart's state, so a remote wake has none)
//!   is not an answer "no": the target's own tick compares it exactly, so the
//!   verdict is "preempt, let the target decide".
//! * Fair: never. Two fair tasks are ordered by EEVDF and the target's tick
//!   charges and compares them (`fairq::tick`); a wake-up check here would
//!   only add reschedules to the commonest wake there is.
//! * Idle never preempts. A CPU that runs nothing real (`cur` is `None` or
//!   idle) is preempted by everything else.
//!
//! # What is done about it
//!
//! * The target is the waking CPU: `need_resched` is set on it
//!   ([`local_resched`]) and the outermost preempt-guard drop (or the next
//!   tick) takes the switch, as the tick's own deferred debt is. Nothing else
//!   told that CPU: the waker is on it and enqueues for itself without a
//!   doorbell (`ring_doorbell` skips a self-enqueue), so before this a woken
//!   task of a better class waited for the tick.
//! * The target is another CPU: nothing more. The enqueue rings its doorbell
//!   whenever it appends (K-C15, `ring_doorbell`), on every ISA that arm
//!   raises the target's own `need_resched` and runs `schedule()`, whose tick
//!   logic (`rt::tick`, `cpu_peek_highest_prio`, `fairq::tick`) makes the
//!   exact choice on the state it owns (a DL deadline is that hart's). A
//!   second ring from here would be a second IPI to a hart already rung.
//!
//! # The waker that is about to block
//!
//! A synchronous IPC hand-off wakes a task and blocks right after: its block
//! takes the best ready task anyway, and a `need_resched` left behind would
//! be paid by the woken task's first guard drop as a spurious `Preempted`
//! switch. `wake.rs` does not check for that path (`ipc` in
//! `wake_task_by_tid_placed`). The exception is the hand-off whose block did
//! not happen (the waker consumed a wake that was already pending and keeps
//! running): `ipc_fast.rs`'s `direct_claim_enqueue` checks, since that waker
//! stays on the CPU. The hand-off that switches to the server at once has no
//! queued task to compare.

use crate::rt_core::{dl_rank, edf_before};
use crate::sc::Class;

/// What `wake.rs` knows about one task for the comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Running {
    /// Its dispatch class.
    pub class: Class,
    /// Its priority bucket (an RT task's level; ignored by the other classes).
    pub prio: u32,
    /// Its absolute deadline, if it holds a reservation and the caller could
    /// read it (the owner hart's state).
    pub deadline: Option<u64>,
}

/// Must `cand`, just made ready, take the CPU from `cur` (`None`: nothing
/// real runs)? See the module docs for the rule per class pair.
#[inline]
pub fn must_preempt(cur: Option<Running>, cand: Running) -> bool {
    let Some(cur) = cur else {
        return cand.class != Class::Idle;
    };
    if cand.class != cur.class {
        return cand.class.preempts(cur.class);
    }
    match cand.class {
        Class::Rt => cand.prio < cur.prio,
        Class::Dl => match (cand.deadline, cur.deadline) {
            (Some(dn), Some(dc)) => edf_before(dl_rank(true, 0), dn, dl_rank(true, 0), dc),
            _ => true,
        },
        Class::Stop | Class::Fair | Class::Idle => false,
    }
}

/// Must the CPU the calling hart wakes `cand` onto, which runs `cur`, be
/// told to reschedule (`need_resched`)? Only meaningful for a wake onto the
/// calling hart: see the module docs for the other CPUs.
///
/// Gate canary `wake-preempt-canary` (Kconfig `SCHED_WAKE_PREEMPT_CANARY`):
/// never asks, so a preempting wake waits for the tick as it did before (the
/// host row `a_preempting_wake_on_the_same_cpu_sets_need_resched` must fail).
#[inline]
pub fn local_resched(cur: Option<Running>, cand: Running) -> bool {
    !cfg!(feature = "wake-preempt-canary") && must_preempt(cur, cand)
}
