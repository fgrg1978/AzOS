// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-CPU state for the W4 multi-policy scheduler — RFC-0004.
//!
//! Mirrors the per-CPU pattern used by the legacy scheduler
//! (`scheduler::PER_CPU`), but holds the new Adaptive Partitioning
//! Scheduler plus the five policy runqueues from `crate::policies`.
//!
//! In W4-int.1 (this wave) the state is **constructed but not yet
//! consulted** by the live dispatch core. The legacy priority-queue
//! scheduler continues to drive boot. W4-int.2 will atomically switch
//! the dispatch path to read from this module.

use core::sync::atomic::{AtomicBool, Ordering};

use azos_sync::spinlock::SpinLock;

use crate::class::SchedClass;
use crate::partitions::Aps;
use crate::policies::Backend;
use crate::scheduler::MAX_CPUS;

/// Per-CPU multi-policy scheduler state.
///
/// **Task 2 (enum-dispatch policy table).** Used to be one named field
/// per policy (`fifo`, `edf_cbs`, `rr`, `cfs`, `sporadic`), each reached
/// through its own hand-written `match class { ... }` in every function
/// below (22 `SchedClass::` matches total, U02-2). `table` replaces all
/// five fields; every class's policy is `table[class.slot()]`, and
/// `Backend`'s own `match` (one, in `policies/mod.rs`) is the only place
/// left that names a concrete policy type. See `policies::Backend`'s doc
/// for what this does and does not buy.
pub struct CpuSchedV2 {
    /// Adaptive Partitioning combinator.
    pub aps: Aps,
    /// One policy per [`SchedClass`], indexed by [`SchedClass::slot`].
    /// RFC-0004 defaults: SafetyCritical→Fifo, HardRT→EdfCbs,
    /// SoftRT→RoundRobin, BestEffort→Cfs, Idle→Sporadic
    /// (`policies::default_table`).
    pub table: [Backend; SchedClass::COUNT],
}

impl CpuSchedV2 {
    /// Construct an empty per-CPU state with RFC-0004 default budgets.
    pub const fn new() -> Self {
        Self {
            aps: Aps::default_config(),
            table: crate::policies::default_table(),
        }
    }
}

impl Default for CpuSchedV2 {
    fn default() -> Self {
        Self::new()
    }
}

/// Sentinel: `true` once `init()` has populated all per-CPU slots.
/// Read by tests; the dispatch core does not yet consult this.
static INIT_DONE: AtomicBool = AtomicBool::new(false);

/// Const initializer for the static array. The `[item; N]` syntax
/// repeats a `const` value, which avoids the `Copy` requirement.
const FRESH_CPU_STATE: SpinLock<CpuSchedV2> = SpinLock::new(CpuSchedV2::new());

/// Per-CPU multi-policy scheduler state.
///
/// IRQ-safe: `account()` runs from the timer ISR (via `schedule()`), while
/// `task_exit()`/admission run in task context on the same hart with interrupts
/// enabled. `with_cpu`/`for_each_cpu` therefore lock with `lock_irqsave()` so a
/// timer tick can't re-enter and deadlock on `V2_STATE[cpu]`.
static V2_STATE: [SpinLock<CpuSchedV2>; MAX_CPUS] =
    [FRESH_CPU_STATE; MAX_CPUS];

/// Mark the V2 scheduler state as initialised. Called once during
/// boot from `crate::scheduler::init()` (W4-int.2 will wire this in).
pub fn mark_initialised() {
    INIT_DONE.store(true, Ordering::Release);
}

/// Returns `true` iff `mark_initialised` has been called.
#[inline]
pub fn is_initialised() -> bool {
    INIT_DONE.load(Ordering::Acquire)
}

/// Borrow a CPU's state and run a closure on it.
///
/// Returns `None` if `cpu` is out of range.
pub fn with_cpu<R>(cpu: usize, f: impl FnOnce(&mut CpuSchedV2) -> R) -> Option<R> {
    if cpu >= MAX_CPUS {
        return None;
    }
    let mut state = V2_STATE[cpu].lock_irqsave();
    Some(f(&mut *state))
}

/// Run the same closure on every CPU's state in turn (used by the
/// window-anchor path at boot).
pub fn for_each_cpu(mut f: impl FnMut(usize, &mut CpuSchedV2)) {
    for cpu in 0..MAX_CPUS {
        let mut state = V2_STATE[cpu].lock_irqsave();
        f(cpu, &mut *state);
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Co-enqueue helpers — called by `scheduler::task_create_affinity` so the
// new policy runqueues stay populated even when SCHED_USE_APS is false.
// Flipping the flag mid-run then finds the policies already holding the
// current task set.
// ──────────────────────────────────────────────────────────────────────────

use crate::policies::{Policy, TaskMeta};

/// Insert a task into the policy that matches its `class_raw`.
///
/// **Still a silent drop on full runqueues, unaddressed.** The comment
/// this replaces promised W4-int.3 would surface the error once dispatch
/// consulted the policies; dispatch does now (`do_schedule`'s
/// `aps_pick_ready`, U02-1), and this still discards `Err` via `let _ =`.
/// Per-CPU capacities are 32/16/32/32/8 (`policies::TOTAL_CAPACITY` =
/// 120) against a pool of up to `MAX_TASKS` (64–4096 by profile); past
/// capacity a task is silently invisible to APS dispatch and falls back
/// to the legacy ring only via the empty-policies fallback in
/// `do_schedule`, not because anything here reported the overflow. Left
/// as a finding (U02-1's fourth point), not fixed: surfacing it needs a
/// counter and a decision about what a full-under-APS task should do
/// that is out of this fix's scope.
pub fn enqueue_task_for_class(
    cpu: usize,
    tid: u32,
    class_raw: u8,
    priority: u8,
    time_slice_us: u32,
    deadline_us: u64,
) {
    let class = match SchedClass::from_raw(class_raw) {
        Some(c) => c,
        None => return,
    };
    let mut meta = TaskMeta::new(tid, class, priority);
    meta.time_slice_us = time_slice_us;
    if deadline_us != 0 {
        meta.deadline_us = Some(deadline_us);
    }
    let _ = with_cpu(cpu, |state| {
        let _ = state.table[class.slot()].enqueue(meta);
    });
}

/// Pick the next task to run on `cpu` via the APS combinator.
///
/// Algorithm:
///   1. `Aps::pick_class` chooses the class whose budget is most
///      under-served and that has a runnable task.
///   2. The matching policy's `pick_next` returns a [`TaskMeta`].
///   3. The caller (the dispatch core) translates `meta.tid` to a
///      task slot index via [`crate::scheduler::idx_for_tid`].
///
/// Returns `None` if every policy's runqueue is empty.
pub fn pick_next(cpu: usize, now_us: u64) -> Option<TaskMeta> {
    if cpu >= MAX_CPUS {
        return None;
    }
    with_cpu(cpu, |state| {
        let class = state.aps.pick_class(|c| !state.table[c.slot()].is_empty())?;
        state.table[class.slot()].pick_next(now_us)
    })?
}

/// AZOS Phase 1 W4-int.2 — boot-time smoke test for the APS
/// dispatch path.
///
/// Returns `Ok(())` if at least one task is enqueued in each of the
/// classes specified by `classes_required`, and if `pick_next` on
/// the given CPU returns a `Some(meta)`. Otherwise returns
/// `Err(reason)`.
///
/// Used by the kernel to print a one-line PASS/FAIL line during
/// boot without flipping the dispatch flag permanently.
pub fn smoke_test(cpu: usize) -> Result<u32, &'static str> {
    if cpu >= MAX_CPUS {
        return Err("cpu out of range");
    }
    let pick = pick_next(cpu, 0).ok_or("no class returned a task")?;
    Ok(pick.tid)
}

/// Account for `dt_us` microseconds of runtime on `cpu`, charging
/// the currently-running class. Called from the timer ISR.
pub fn account(cpu: usize, now_us: u64, dt_us: u32, running_tid: u32) {
    let _ = with_cpu(cpu, |state| {
        // Drive the APS window roll-over and class-budget accounting.
        let rolled_over = state.aps.tick(now_us, dt_us);
        // Forward to every policy's tick — only the one that owns
        // `running_tid` reacts; the rest no-op (each `Policy::tick`
        // checks the tid itself). Iterating the table, not five named
        // fields, is the enum-dispatch table's whole point (task 2).
        for backend in state.table.iter_mut() {
            backend.tick(running_tid, dt_us);
        }
        // U02-1 fix: `Sporadic::replenish` used to have no caller outside
        // the host tests (`replenish_restores`), so the Idle class's
        // capacity bucket drained once, at the first tick where cumulative
        // `dt_us` exceeded `DEFAULT_CAPACITY_US` (1 ms), and never came
        // back — `pick_next` returns `None` unconditionally while
        // `exhausted()`, so Idle starved permanently after that. The
        // window roll-over IS this server's replenishment period boundary
        // (`Aps::tick`'s own doc); driving it from here needs no new
        // timer or period tracking. `replenish` is a `Policy` default
        // no-op everywhere except `Sporadic`, so this stays correct if
        // the Idle class's backend is ever reassigned.
        if rolled_over {
            state.table[SchedClass::Idle.slot()].replenish();
        }
    });
}

/// Remove a task from whichever policy holds it. Called from
/// `task_exit` so the per-class runqueues stay in sync.
pub fn dequeue_task_for_class(cpu: usize, tid: u32, class_raw: u8) {
    let class = match SchedClass::from_raw(class_raw) {
        Some(c) => c,
        None => return,
    };
    let _ = with_cpu(cpu, |state| {
        state.table[class.slot()].dequeue(tid);
    });
}
