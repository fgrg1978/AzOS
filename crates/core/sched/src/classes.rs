// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The five dispatch classes over today's Legacy queues (N6 part a).
//!
//! A child module of `scheduler.rs` (pulled in with `#[path]`, like `rt.rs`),
//! so it reaches the ready queues and the reservation sets without widening
//! their visibility. The model (`Class`, `SchedContext`, `SchedClassOps`, the
//! precedence walk) is the pure `sc.rs`.
//!
//! # The mapping
//!
//! | Class | Today's tasks | Queue |
//! |---|---|---|
//! | stop | none yet (a per-CPU slot, `SCHED_CLASS_STOP`) | [`STOP_TASK`] |
//! | DL | tasks with an admitted EDF + CBS reservation (`rt::reserve`) | the hart's reservation set, EDF |
//! | RT | the fixed-priority band, `priority < RT_PRIORITY_THRESHOLD` | band levels of the ready bitmap |
//! | fair | every other task (the Legacy round robin; EEVDF in part b) | the other levels |
//! | idle | the per-CPU idle task | the idle level |
//!
//! # What dispatches today
//!
//! `do_schedule` still takes its pick from the fused Legacy path (`rt::pick`
//! or the bitmap dequeue). Across RT, fair and idle that pick already *is*
//! this precedence: the classes own disjoint level ranges in that order. It
//! differs for DL: a reservation runs first **inside its level**, not above
//! every RT level, and the deadline-met rows encode that. The strict
//! `DL > RT` walk ([`pick`]) becomes the dispatch order with `sched=classes`
//! (part b), once those rows are re-judged. Until then [`pick`] is the
//! class view of the same queues (ktest `sched_class_precedence`), and the
//! switch path is unchanged.
//!
//! # SC per task
//!
//! A task's SC is [`SC`]`[slot]` (its own; IPC donation in N9 lends another
//! one). The class is written where the facts are: slot creation, base
//! priority changes, reservation admission and release — never on the switch
//! path. `on_cpu` and `blocked_on` have no writer yet: [`on_cpu`] computes
//! the former from the per-CPU current task (cold), the wait graph (N7)
//! writes the latter.

use core::sync::atomic::{AtomicUsize, Ordering};

use azos_arch::Interrupts;

use crate::sc::{classify, Class, ClassTable, SchedClassOps, SchedContext, NO_CPU};
use crate::task::{TaskState, IDLE_PRIORITY, RT_PRIORITY_THRESHOLD};

use super::{
    cpu_enqueue_locked, cpu_remove, ncpu, prio_bucket, rt, task_ref, CpuLockGuard, MAX_CPUS,
    MAX_TASKS, PER_CPU,
};

/// The classes this build has (Kconfig `SCHED_CLASS_*`). Fair and idle are
/// not optional: every task outside the band is fair, every CPU has an idle
/// task.
const STOP_ON: bool = azos_limits::SCHED_CLASS_STOP;
const DL_ON: bool = azos_limits::SCHED_CLASS_DL;
const RT_ON: bool = azos_limits::SCHED_CLASS_RT;
const _: () = assert!(azos_limits::SCHED_CLASS_FAIR && azos_limits::SCHED_CLASS_IDLE);

/// The band threshold the classifier uses: none without the RT class.
const RT_THRESHOLD: u32 = if RT_ON { RT_PRIORITY_THRESHOLD } else { 0 };

/// The class a task created without a class request starts in
/// (`SCHED_DEFAULT`): `None` = by its priority (Legacy).
pub const DEFAULT_CLASS: Option<Class> = if azos_limits::SCHED_DEFAULT_RT && RT_ON {
    Some(Class::Rt)
} else if azos_limits::SCHED_DEFAULT_FAIR {
    Some(Class::Fair)
} else {
    None
};

/// One SC per task slot: 64 bytes each (`sc::SC_SIZE`), `MAX_TASKS` of them.
pub static SC: [SchedContext; MAX_TASKS] = [const { SchedContext::new(Class::Fair) }; MAX_TASKS];

/// Per-CPU stop task (`usize::MAX` = none). Only read with `SCHED_CLASS_STOP`.
static STOP_TASK: [AtomicUsize; MAX_CPUS] = [const { AtomicUsize::new(usize::MAX) }; MAX_CPUS];

/// Task `idx`'s SC.
#[inline]
pub fn sc_of(idx: usize) -> Option<&'static SchedContext> {
    SC.get(idx)
}

/// The class of task `idx` (`None`: no such slot).
pub fn class_of(idx: usize) -> Option<Class> {
    sc_of(idx).map(SchedContext::class)
}

/// The CPU task `idx` runs on, [`NO_CPU`] if none. A scan of the per-CPU
/// current task: cold, for the wait graph and `schedctl`, not the switch.
pub fn on_cpu(idx: usize) -> u16 {
    (0..ncpu())
        .find(|&c| unsafe { PER_CPU[c].current_idx.load(Ordering::Relaxed) } == idx)
        .map_or(NO_CPU, |c| c as u16)
}

/// Install `idx` as `cpu`'s stop task (`usize::MAX` clears it). Refused
/// without `SCHED_CLASS_STOP`.
pub fn set_stop_task(cpu: usize, idx: usize) -> bool {
    if !STOP_ON || cpu >= MAX_CPUS || (idx != usize::MAX && idx >= MAX_TASKS) {
        return false;
    }
    STOP_TASK[cpu].store(idx, Ordering::Release);
    if let Some(sc) = sc_of(idx) {
        sc.set_class(Class::Stop, 0);
    }
    true
}

fn is_stop(idx: usize) -> bool {
    STOP_ON && (0..ncpu()).any(|c| STOP_TASK[c].load(Ordering::Relaxed) == idx)
}

/// The class task `idx` belongs in at base priority `prio`: DL while it
/// holds a reservation, stop if it is a stop task, else by its priority and
/// `SCHED_DEFAULT`. What the hooks below write; the ktest checks it against
/// what the SC holds.
pub fn class_for(idx: usize, prio: u32) -> Class {
    let reserved = DL_ON && class_of(idx) == Some(Class::Dl);
    match DEFAULT_CLASS {
        // Legacy keeps the idle task, the band and the reservations where
        // their priority and admission put them.
        Some(c) if !reserved && prio < IDLE_PRIORITY && prio >= RT_THRESHOLD => c,
        _ => classify(prio, reserved, is_stop(idx), RT_THRESHOLD, IDLE_PRIORITY),
    }
}

/// Slot creation and base-priority changes: the class follows the priority,
/// unless the task holds a reservation (DL) or is a stop task.
pub(super) fn on_base_priority(idx: usize, prio: u32) {
    let class = class_for(idx, prio);
    if let Some(sc) = sc_of(idx) {
        sc.set_class(class, prio);
    }
}

/// The task current on this CPU (`None`: nothing real runs).
pub fn current() -> Option<usize> {
    let cpu = crate::smp::current_cpu_id();
    let idx = unsafe { PER_CPU[cpu].current_idx.load(Ordering::Relaxed) };
    (idx < MAX_TASKS).then_some(idx)
}

/// A slot is (re)used: whatever its previous occupant held is gone.
pub(super) fn on_slot_reset(idx: usize, prio: u32) {
    if let Some(sc) = sc_of(idx) {
        sc.set_times(0, 0, 0);
        sc.class.store(Class::Fair as u8, Ordering::Relaxed);
    }
    on_base_priority(idx, prio);
}

/// Admission placed `idx`'s reservation: its SC is DL with those times.
pub(super) fn on_reserved(idx: usize, r: &rt::Reservation) {
    if let Some(sc) = sc_of(idx) {
        let d = if r.deadline_us == 0 { r.period_us } else { r.deadline_us };
        sc.set_times(r.runtime_us, r.period_us, d);
        sc.set_class(Class::Dl, r.level);
    }
}

/// `idx`'s reservation was dropped: back to the class of its base priority.
pub(super) fn on_released(idx: usize) {
    if let Some(sc) = sc_of(idx) {
        sc.set_times(0, 0, 0);
        sc.class.store(Class::Fair as u8, Ordering::Relaxed);
        let base = unsafe { task_ref(idx) }.base_priority.load(Ordering::Relaxed);
        on_base_priority(idx, base);
    }
}

fn prio(idx: usize) -> u32 {
    prio_bucket(unsafe { task_ref(idx) }.priority.load(Ordering::Relaxed)) as u32
}

fn ready(idx: usize) -> bool {
    let t = unsafe { task_ref(idx) };
    t.queued.load(Ordering::Relaxed) && t.state() == TaskState::Ready
}

fn enqueue_any(cpu: usize, idx: usize) -> bool {
    idx < MAX_TASKS && unsafe { cpu_enqueue_locked(cpu, idx) }
}

fn dequeue_any(cpu: usize, idx: usize) -> bool {
    if idx >= MAX_TASKS {
        return false;
    }
    let _g = CpuLockGuard::acquire(cpu);
    unsafe { cpu_remove(cpu, idx) }
}

/// Stop: one per-CPU slot, runs whenever it is ready.
pub struct StopClass;
/// DL: the hart's reservation set, EDF (level, then absolute deadline).
pub struct DlClass;
/// RT: the band levels, fixed priority, FIFO inside a level, band budget.
pub struct RtClass;
/// Fair: the levels between the band and idle (Legacy round robin).
pub struct FairClass;
/// Idle: the idle level.
pub struct IdleClass;

impl SchedClassOps for StopClass {
    fn class(&self) -> Class { Class::Stop }
    fn enqueue(&self, cpu: usize, idx: usize) -> bool { enqueue_any(cpu, idx) }
    fn dequeue(&self, cpu: usize, idx: usize) -> bool { dequeue_any(cpu, idx) }
    fn pick(&self, cpu: usize) -> Option<usize> {
        if !STOP_ON || cpu >= MAX_CPUS {
            return None;
        }
        let idx = STOP_TASK[cpu].load(Ordering::Acquire);
        (idx < MAX_TASKS && ready(idx)).then_some(idx)
    }
    /// Stop work runs to completion.
    fn tick(&self, _cpu: usize, _cur: usize) -> bool { false }
    fn preempt_check(&self, _cpu: usize, _cur: usize, _cand: usize) -> bool { false }
}

impl SchedClassOps for DlClass {
    fn class(&self) -> Class { Class::Dl }
    fn enqueue(&self, cpu: usize, idx: usize) -> bool { enqueue_any(cpu, idx) }
    fn dequeue(&self, cpu: usize, idx: usize) -> bool { dequeue_any(cpu, idx) }
    fn pick(&self, cpu: usize) -> Option<usize> {
        if !DL_ON { None } else { unsafe { rt::peek_dl(cpu) } }
    }
    /// The CBS charge and the band window, as the Legacy tick does.
    fn tick(&self, cpu: usize, cur: usize) -> bool {
        DL_ON && rt::active(cpu) && unsafe { rt::tick(cpu, cur) }
    }
    fn preempt_check(&self, cpu: usize, cur: usize, cand: usize) -> bool {
        let (pc, pn) = (prio(cur), prio(cand));
        match unsafe { (rt::dl_deadline(cpu, cur), rt::dl_deadline(cpu, cand)) } {
            (Some(dc), Some(dn)) => crate::rt_core::edf_before(pn, dn, pc, dc),
            _ => pn < pc,
        }
    }
}

impl SchedClassOps for RtClass {
    fn class(&self) -> Class { Class::Rt }
    fn enqueue(&self, cpu: usize, idx: usize) -> bool { enqueue_any(cpu, idx) }
    fn dequeue(&self, cpu: usize, idx: usize) -> bool { dequeue_any(cpu, idx) }
    /// The band's most urgent level, unless the band budget skips it (the
    /// exempt safety loops are found by `rt::pick`, which still dispatches).
    fn pick(&self, cpu: usize) -> Option<usize> {
        if !RT_ON || unsafe { rt::band_skipped(cpu) } {
            return None;
        }
        unsafe { rt::peek_levels(cpu, rt::LEVELS_BAND) }
    }
    fn tick(&self, cpu: usize, cur: usize) -> bool {
        RT_ON && rt::active(cpu) && unsafe { rt::tick(cpu, cur) }
    }
    fn preempt_check(&self, _cpu: usize, cur: usize, cand: usize) -> bool {
        prio(cand) < prio(cur)
    }
}

impl SchedClassOps for FairClass {
    fn class(&self) -> Class { Class::Fair }
    fn enqueue(&self, cpu: usize, idx: usize) -> bool { enqueue_any(cpu, idx) }
    fn dequeue(&self, cpu: usize, idx: usize) -> bool { dequeue_any(cpu, idx) }
    fn pick(&self, cpu: usize) -> Option<usize> {
        // Without the RT class the band levels are fair levels.
        let mask = if RT_ON { rt::LEVELS_NONBAND } else { rt::LEVELS_NONBAND | rt::LEVELS_BAND };
        unsafe { rt::peek_levels(cpu, mask) }
    }
    /// The round-robin slice is still charged by `schedule()`'s tick; EEVDF
    /// (part b) moves the charge here.
    fn tick(&self, _cpu: usize, _cur: usize) -> bool { false }
    fn preempt_check(&self, _cpu: usize, cur: usize, cand: usize) -> bool {
        prio(cand) < prio(cur)
    }
}

impl SchedClassOps for IdleClass {
    fn class(&self) -> Class { Class::Idle }
    fn enqueue(&self, cpu: usize, idx: usize) -> bool { enqueue_any(cpu, idx) }
    fn dequeue(&self, cpu: usize, idx: usize) -> bool { dequeue_any(cpu, idx) }
    fn pick(&self, cpu: usize) -> Option<usize> {
        unsafe { rt::peek_levels(cpu, rt::LEVELS_IDLE) }
    }
    fn tick(&self, _cpu: usize, _cur: usize) -> bool { false }
    fn preempt_check(&self, _cpu: usize, _cur: usize, _cand: usize) -> bool { false }
}

/// This build's class table, compiled-out classes `None`.
pub static TABLE: ClassTable<'static> = [
    if STOP_ON { Some(&StopClass) } else { None },
    if DL_ON { Some(&DlClass) } else { None },
    if RT_ON { Some(&RtClass) } else { None },
    Some(&FairClass),
    Some(&IdleClass),
];

/// The class walk on this CPU: the first class in precedence with a
/// runnable task, and that task (a peek: nothing leaves its queue).
/// Interrupts are off for the walk, so the caller cannot migrate between
/// reading its CPU and reading that CPU's owner-hart RT state.
pub fn pick_here() -> Option<(Class, usize)> {
    let s = azos_arch::ARCH.disable_all();
    let cpu = crate::smp::current_cpu_id();
    let r = if cpu < ncpu() { crate::sc::pick_in_precedence(&TABLE, cpu) } else { None };
    azos_arch::ARCH.restore(s);
    r
}
