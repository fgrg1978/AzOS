// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The five dispatch classes over the per-CPU ready queues.
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
//! | fair | every other task (EEVDF, `fairq.rs`) | the other levels, one EEVDF queue |
//! | idle | the per-CPU idle task | the idle level |
//!
//! # What dispatches today
//!
//! `do_schedule` takes its pick from the fused path (`rt::pick` or the
//! bitmap dequeue). Across RT, fair and idle that pick *is* this precedence:
//! the classes own disjoint level ranges in that order. For DL, `rt::pick`
//! and `rt::tick` rank every eligible reservation above the rest of the band
//! (`rt_core::dl_rank`; deadline order among reservations) and force the
//! switch past a better-priority band task, while the band's exempt safety
//! loops are the stop class and run above DL (`rt_core::stop_pick`, owner
//! decision 10-10), so the dispatch order is the strict precedence. The
//! walk ([`pick_here`]) is the class view of the same queues (ktest `sched_class_precedence`): the switch path keeps the
//! fused pick, its charging and its re-enqueue invariants. A wake-up does
//! not yet compare classes: a reservation woken onto a CPU running a
//! better-level band task waits for that CPU's next tick or schedule.
//!
//! # SC per task
//!
//! A task's SC is [`SC`]`[slot]` (its own; IPC donation in N9 lends another
//! one). The class is written where the facts are: slot creation, base
//! priority changes, reservation admission and release — never on the switch
//! path. `on_cpu` has no writer yet: [`on_cpu`] computes it from the
//! per-CPU current task (cold). `blocked_on` is written by the wait graph
//! (N7) through [`ClassPi`].
//!
//! # The wait graph's scheduler side (N7)
//!
//! [`ClassPi`] is `azos_sync::waitgraph::SchedPi` over these classes,
//! registered at boot with `WAIT_GRAPH`. The graph computes the effective
//! attribute; here it becomes a Legacy priority number ([`pi_prio`]) kept per
//! slot in `PI_PRIO`, and the live `priority` is re-bucketed under the
//! slot's donation lock. `TaskDonation::base` reads the same floor, so a
//! counted donor (PIFAST, lease, driver proxy, until N7's migrations move
//! them onto the graph) returning lands on the graph's boost, not under it.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use azos_arch::Interrupts;
use azos_sync::waitgraph::{self, PiAttr, SchedPi, TaskId, WaitObj};

use crate::sc::{classify, Class, ClassTable, SchedClassOps, SchedContext, NO_CPU};
use crate::task::{TaskState, IDLE_PRIORITY, RT_PRIORITY_THRESHOLD};

use super::{
    cpu_enqueue_locked, cpu_remove, fairq, ncpu, prio_bucket, rt, task_ref, CpuLockGuard,
    MAX_CPUS, MAX_TASKS, PER_CPU,
};

/// The classes this build has (Kconfig `SCHED_CLASS_*`). Fair and idle are
/// not optional: every task outside the band is fair, every CPU has an idle
/// task.
const DL_ON: bool = azos_limits::SCHED_CLASS_DL;
const RT_ON: bool = azos_limits::SCHED_CLASS_RT;
const _: () = assert!(
    azos_limits::SCHED_CLASS_FAIR && azos_limits::SCHED_CLASS_IDLE && azos_limits::SCHED_CLASS_STOP
);

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

// ───────────────── the dispatch order ─────────────────

/// Runtime canary `sched-dl-in-level`: ranks a reservation by its level
/// again (the pre-class order), so DL no longer runs above the band
/// (ktest `sched_dl_above_rt`).
static CANARY_DL_IN_LEVEL: AtomicBool = AtomicBool::new(false);

/// The rank switch the RT pick and tick read (`rt_core::dl_rank`): a
/// reservation outranks every band level, unless the canary puts it back
/// inside its level.
#[inline(always)]
pub fn dl_above_band() -> bool {
    !CANARY_DL_IN_LEVEL.load(Ordering::Relaxed)
}

/// Arm runtime canary `sched-dl-in-level` (boot only).
pub fn canary_dl_in_level() {
    CANARY_DL_IN_LEVEL.store(true, Ordering::Relaxed);
}

/// One SC per task slot: `sc::SC_SIZE` bytes each (64 on a 64-bit target), `MAX_TASKS` of them.
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

/// The CPU task `idx` runs on, [`NO_CPU`] if none. With `WAIT_GRAPH` one
/// load of the SC's `on_cpu`, written at every switch ([`on_switch`]);
/// without, a scan of the per-CPU current task (cold, nothing on the
/// switch). A hint for the kmutex spin and the graph: a racing switch may
/// make it stale for one switch, never wrong for longer.
pub fn on_cpu(idx: usize) -> u16 {
    if waitgraph::ENABLED {
        return sc_of(idx).map_or(NO_CPU, |sc| sc.on_cpu.load(Ordering::Relaxed));
    }
    (0..ncpu())
        .find(|&c| unsafe { PER_CPU[c].current_idx.load(Ordering::Relaxed) } == idx)
        .map_or(NO_CPU, |c| c as u16)
}

/// N7b: `cpu` switches from `prev` to `next` (`set_current_task`, the one
/// switch setter): `prev`'s SC leaves the CPU unless another CPU already
/// claimed it, `next`'s SC names `cpu`. Only with `WAIT_GRAPH`. Two
/// bounds checks, one load, two stores; Relaxed (a hint, see [`on_cpu`]).
#[inline(always)]
pub(super) fn on_switch(cpu: usize, prev: usize, next: usize) {
    if let Some(sc) = SC.get(prev) {
        if sc.on_cpu.load(Ordering::Relaxed) == cpu as u16 {
            sc.on_cpu.store(NO_CPU, Ordering::Relaxed);
        }
    }
    if let Some(sc) = SC.get(next) {
        sc.on_cpu.store(cpu as u16, Ordering::Relaxed);
    }
}

/// Install `idx` as `cpu`'s stop task (`usize::MAX` clears it).
pub fn set_stop_task(cpu: usize, idx: usize) -> bool {
    if cpu >= MAX_CPUS || (idx != usize::MAX && idx >= MAX_TASKS) {
        return false;
    }
    STOP_TASK[cpu].store(idx, Ordering::Release);
    if let Some(sc) = sc_of(idx) {
        store_class(sc, idx, Class::Stop, Some(0), 0);
    }
    true
}

fn is_stop(idx: usize) -> bool {
    rt::is_exempt_from_band_cap(idx)
        || (0..ncpu()).any(|c| STOP_TASK[c].load(Ordering::Relaxed) == idx)
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
        store_class(sc, idx, class, Some(prio), prio);
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
        store_class(sc, idx, Class::Fair, None, prio);
        sc.blocked_on.store(0, Ordering::Relaxed);
        // The new occupant serves no interrupt line (L5).
        sc.irq.store(0, Ordering::Relaxed);
        sc.qos_id.store(crate::sc::QOS_DEFAULT, Ordering::Relaxed);
        sc.set_timer_slack_row(false);
    }
    // And its EEVDF numbers: the new task joins the fair queue at the mean.
    fairq::reset(idx);
    // N7: nothing of the previous occupant's graph state survives (its
    // effective attribute, its boost floor). Under POOL_LOCK; the graph
    // lock is a leaf below it.
    if waitgraph::ENABLED && idx < MAX_TASKS {
        PI_PRIO[idx].store(u32::MAX, Ordering::Relaxed);
        // Detach only: no OwnerDiedHook under POOL_LOCK (N7c).
        waitgraph::task_reset(idx as TaskId);
    }
    on_base_priority(idx, prio);
}

/// N7b: `idx` is exiting (both exit paths, before the slot turns Zombie
/// and before interrupts go off for the last switch): its wait-graph state
/// goes now, not at the slot's reuse. The graph detaches any object it
/// still owns and takes it off any object it waits on; its boost floor is
/// dropped. Task context, no scheduler lock held. Compiled out without
/// `WAIT_GRAPH`. Runtime canary `exit-keeps-graph` skips it (ktest
/// `waitgraph_exit_clears_state`).
pub fn on_task_exit(idx: usize) {
    if !waitgraph::ENABLED || idx >= MAX_TASKS || CANARY_EXIT_KEEPS_GRAPH.load(Ordering::Relaxed) {
        return;
    }
    waitgraph::task_exit(idx as TaskId);
    PI_PRIO[idx].store(u32::MAX, Ordering::Relaxed);
}

static CANARY_EXIT_KEEPS_GRAPH: AtomicBool = AtomicBool::new(false);

/// Runtime canary `exit-keeps-graph`: the exit path leaves the task's
/// graph state to the slot's reuse (pre-N7b behaviour).
pub fn canary_exit_keeps_graph() {
    CANARY_EXIT_KEEPS_GRAPH.store(true, Ordering::Relaxed);
}

/// Admission placed `idx`'s reservation: its SC is DL with those times.
pub(super) fn on_reserved(idx: usize, r: &rt::Reservation) {
    if let Some(sc) = sc_of(idx) {
        let d = if r.deadline_us == 0 { r.period_us } else { r.deadline_us };
        sc.set_times(r.runtime_us, r.period_us, d);
        store_class(sc, idx, Class::Dl, Some(r.level), 0);
    }
}

/// `idx`'s reservation was dropped: back to the class of its base priority.
pub(super) fn on_released(idx: usize) {
    if let Some(sc) = sc_of(idx) {
        sc.set_times(0, 0, 0);
        let base = unsafe { task_ref(idx) }.base_priority.load(Ordering::Relaxed);
        store_class(sc, idx, Class::Fair, None, base);
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
/// Fair: the levels between the band and idle, EEVDF (`fairq.rs`).
pub struct FairClass;
/// Idle: the idle level.
pub struct IdleClass;

impl SchedClassOps for StopClass {
    fn class(&self) -> Class { Class::Stop }
    fn enqueue(&self, cpu: usize, idx: usize) -> bool { enqueue_any(cpu, idx) }
    fn dequeue(&self, cpu: usize, idx: usize) -> bool { dequeue_any(cpu, idx) }
    fn pick(&self, cpu: usize) -> Option<usize> {
        if cpu >= MAX_CPUS {
            return None;
        }
        let idx = STOP_TASK[cpu].load(Ordering::Acquire);
        if idx < MAX_TASKS && ready(idx) {
            return Some(idx);
        }
        // The exempt band loops are stop work.
        if rt::active(cpu) { unsafe { rt::peek_exempt(cpu) } } else { None }
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
        let classes = dl_above_band();
        let (pc, pn) = (crate::rt_core::dl_rank(classes, prio(cur)), crate::rt_core::dl_rank(classes, prio(cand)));
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
        // Without the RT class the band levels are fair levels, strict
        // priority as the band is (they are not EEVDF tasks: `fairq::is_fair`).
        if !RT_ON {
            if let Some(idx) = unsafe { rt::peek_levels(cpu, rt::LEVELS_BAND) } {
                return Some(idx);
            }
        }
        unsafe { fairq::peek(cpu) }
    }
    /// Charge the running fair task; `true`: a queued one now beats it.
    /// `schedule()`'s tick is this call.
    fn tick(&self, cpu: usize, cur: usize) -> bool { unsafe { fairq::tick(cpu, cur) } }
    /// Earlier virtual deadline.
    fn preempt_check(&self, _cpu: usize, cur: usize, cand: usize) -> bool {
        fairq::before(cand, cur)
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
    Some(&StopClass),
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

/// Per-slot wait-graph boost as a Legacy priority number, `u32::MAX` = none.
/// Sized 0 without `WAIT_GRAPH` (nothing writes it then).
const PI_SLOTS: usize = if waitgraph::ENABLED { MAX_TASKS } else { 0 };
static PI_PRIO: [AtomicU32; PI_SLOTS] = [const { AtomicU32::new(u32::MAX) }; PI_SLOTS];

/// The priority floor the wait graph holds `idx` at (`u32::MAX`: none). The
/// donation protocol's base is `min(base_priority, this)`.
#[inline]
pub(super) fn pi_floor(idx: usize) -> u32 {
    if !waitgraph::ENABLED {
        return u32::MAX;
    }
    PI_PRIO.get(idx).map_or(u32::MAX, |p| p.load(Ordering::Relaxed))
}

/// Per slot (Chain E cut 6): the task's base attribute as one integer
/// ([`PiAttr::quiet_key`]), what [`ClassPiInline::quiet_key`] hands the wait
/// graph's lock-free quiet test (`waitgraph::block_on_quiet`, every IPC call
/// with WAIT_GRAPH) in place of two class reads, a jump table and
/// `PiAttr::cmp`. It mirrors the two fields [`ClassPiInline::base_attr`]
/// reads, the SC's class and the task's `base_priority`, and is written
/// wherever the class is ([`store_class`]), which is wherever a base
/// priority is installed: `on_base_priority` runs beside each
/// `base_priority` store (task creation through `on_slot_reset`,
/// `set_current_sched_params`, `rt::set_base_priority`) and takes the
/// priority being installed. A writer that changes it on a live task
/// reports it with [`pi_attr_changed`] after this store, whose fence orders
/// it against a lazy call. Sized 0 without `WAIT_GRAPH`; the initial value
/// is the class [`SC`] starts in.
static QUIET_KEY: [AtomicU32; PI_SLOTS] = [const { AtomicU32::new(PiAttr::Fair.quiet_key()) }; PI_SLOTS];

/// The quiet key of a task in `class` at base priority `base`: exactly
/// [`ClassPiInline::base_attr`]'s value as a key, a DL task's being
/// [`waitgraph::QUIET_DL`] (its deadline is read on its own hart).
#[inline]
pub const fn quiet_key_of(class: Class, base: u32) -> u32 {
    match class {
        Class::Stop => PiAttr::Stop.quiet_key(),
        Class::Dl => waitgraph::QUIET_DL,
        Class::Rt => PiAttr::Rt { prio: if base > u8::MAX as u32 { u8::MAX } else { base as u8 } }.quiet_key(),
        Class::Fair => PiAttr::Fair.quiet_key(),
        Class::Idle => PiAttr::Idle.quiet_key(),
    }
}

/// `idx`'s quiet key as stored ([`waitgraph::QUIET_DL`] without
/// `WAIT_GRAPH`: never quiet). Inline always: the IPC call reads two
/// (out of line it was two calls and a callee-saved register more).
#[inline(always)]
pub fn quiet_key(idx: usize) -> u32 {
    QUIET_KEY.get(idx).map_or(waitgraph::QUIET_DL, |k| k.load(Ordering::Relaxed))
}

/// Put `idx`'s SC in `class` (`prio`: its level/weight,
/// `SchedContext::set_class`; `None`: the class alone) and store its quiet
/// key for base priority `base`. Every class write goes through here.
#[inline]
fn store_class(sc: &SchedContext, idx: usize, class: Class, prio: Option<u32>, base: u32) {
    match prio {
        Some(p) => sc.set_class(class, p),
        None => sc.class.store(class as u8, Ordering::Relaxed),
    }
    if let Some(k) = QUIET_KEY.get(idx) {
        k.store(quiet_key_of(class, base), Ordering::Relaxed);
    }
}

/// The Legacy priority number an effective attribute runs at. Stop and DL
/// take the top level: the class precedence (Q6) puts them above every RT
/// level, and Legacy dispatch has no per-task absolute deadline to install,
/// so a DL donor's deadline stays exact in the graph (`waitgraph::effective`)
/// and the owner runs at the top level. RT is its own number. Fair and idle
/// do not boost (stage 1: no weight inheritance).
pub const fn pi_prio(a: PiAttr) -> u32 {
    match a {
        PiAttr::Stop | PiAttr::Dl { .. } => 0,
        PiAttr::Rt { prio } => prio as u32,
        PiAttr::Fair | PiAttr::Idle => u32::MAX,
    }
}

const _: () = assert!(RT_PRIORITY_THRESHOLD <= u8::MAX as u32 && IDLE_PRIORITY <= u8::MAX as u32);

/// `azos_sync::waitgraph::SchedPi` over the dispatch classes.
pub struct ClassPi;

/// The hooks `boot::sched` registers with `WAIT_GRAPH`.
pub static PI: ClassPi = ClassPi;

impl ClassPi {
    /// Install the graph's floor `p` on `idx` and move its live priority:
    /// to `min(base, p)` with no counted donation in flight, else only
    /// upwards (the counted return lands on the floor; `TaskDonation::base`).
    fn write_floor(&self, idx: usize, p: u32) {
        use crate::donation::DonationCell;
        if idx >= MAX_TASKS || !waitgraph::ENABLED {
            return;
        }
        let p = graph_floored(idx, p);
        PI_PRIO[idx].store(p, Ordering::Relaxed);
        let c = super::TaskDonation::new(idx);
        c.lock();
        let target = c.base();
        let cur = c.prio();
        if target != cur && (c.count() == 0 || target < cur) {
            c.apply_prio(target);
        }
        c.unlock();
    }
}

/// The ring-3 floor on a graph boost (owner decision 10-10): `p`, the
/// floor the graph asks for `idx`, never goes more urgent than the floor
/// legacy `donate_priority` applies ([`super::ring3_floor_at`]:
/// `RT_PRIORITY_THRESHOLD` for a ring-3 task, none for a kernel task), so
/// no kmutex or PI futex waiter lifts a ring-3 owner into the band the tick
/// no longer preempts. The graph's own effective attribute stays exact; only
/// the priority this task runs at is floored. Runtime canary
/// `pi-ring3-unclamped` removes it (ktest `waitgraph_ring3_owner_floored`).
fn graph_floored(idx: usize, p: u32) -> u32 {
    if CANARY_PI_RING3_UNCLAMPED.load(Ordering::Relaxed) {
        return p;
    }
    crate::donation::floored(p, super::ring3_floor_at(idx))
}

static CANARY_PI_RING3_UNCLAMPED: AtomicBool = AtomicBool::new(false);

/// Runtime canary `pi-ring3-unclamped`: a graph boost lifts a ring-3 owner
/// to the donor's priority, past `RT_PRIORITY_THRESHOLD` (pre-10-10).
pub fn canary_pi_ring3_unclamped() {
    CANARY_PI_RING3_UNCLAMPED.store(true, Ordering::Relaxed);
}

impl SchedPi for ClassPi {
    fn base_attr(&self, t: TaskId) -> PiAttr {
        let idx = t as usize;
        if idx >= MAX_TASKS {
            return PiAttr::Idle;
        }
        let base = unsafe { task_ref(idx) }.base_priority.load(Ordering::Relaxed);
        let rt = PiAttr::Rt { prio: base.min(u8::MAX as u32) as u8 };
        match class_of(idx) {
            Some(Class::Stop) => PiAttr::Stop,
            Some(Class::Dl) => {
                // The absolute deadline is the reservation's hart's owner
                // state: read on that hart only; elsewhere the latest
                // deadline keeps the class (above every RT task) and loses
                // only the order inside DL.
                let s = azos_arch::ARCH.disable_all();
                let cpu = crate::smp::current_cpu_id();
                let d = if cpu < ncpu() { unsafe { rt::dl_deadline(cpu, idx) } } else { None };
                azos_arch::ARCH.restore(s);
                PiAttr::Dl { deadline_ns: d.map_or(u64::MAX, |us| us.saturating_mul(1000)) }
            }
            Some(Class::Rt) => rt,
            Some(Class::Idle) => PiAttr::Idle,
            Some(Class::Fair) | None => PiAttr::Fair,
        }
    }

    fn boost(&self, t: TaskId, to: PiAttr) {
        self.write_floor(t as usize, pi_prio(to));
    }

    fn unboost(&self, t: TaskId, to: PiAttr) {
        self.write_floor(t as usize, pi_prio(to));
    }

    fn set_blocked_on(&self, t: TaskId, on: Option<WaitObj>) {
        if let Some(sc) = sc_of(t as usize) {
            sc.blocked_on.store(on.map_or(0, WaitObj::addr), Ordering::Release);
        }
    }

    fn blocked_on(&self, t: TaskId) -> Option<WaitObj> {
        sc_of(t as usize).and_then(|sc| WaitObj::from_addr(sc.blocked_on.load(Ordering::Acquire)))
    }

    fn on_cpu(&self, t: TaskId) -> bool {
        on_cpu(t as usize) != NO_CPU
    }
}

/// [`ClassPi`] with its accessors inline, for the wait graph's lock-free
/// paths (`waitgraph::block_on_lazy` / `unblock_lazy`, every IPC call with
/// WAIT_GRAPH). The same values as [`PI`]; a DL task's base (a deadline read
/// on its hart) and every mutation stay [`PI`]'s, out of line. Every method
/// is `#[inline]` (the three accessors `always`: the IPC call arm is large
/// enough that the inliner otherwise keeps `base_attr` out of line, +40
/// instructions per round trip): nothing of it is compiled unless a lazy
/// path uses it.
pub struct ClassPiInline;

/// The hooks `fastcall` passes to the lazy wait-graph paths.
pub static PI_INLINE: ClassPiInline = ClassPiInline;

impl SchedPi for ClassPiInline {
    #[inline(always)]
    fn base_attr(&self, t: TaskId) -> PiAttr {
        let idx = t as usize;
        match class_of(idx) {
            Some(Class::Fair) => PiAttr::Fair,
            Some(Class::Rt) => {
                let base = unsafe { task_ref(idx) }.base_priority.load(Ordering::Relaxed);
                PiAttr::Rt { prio: base.min(u8::MAX as u32) as u8 }
            }
            Some(Class::Idle) => PiAttr::Idle,
            Some(Class::Stop) => PiAttr::Stop,
            Some(Class::Dl) | None => PI.base_attr(t),
        }
    }

    /// One load ([`QUIET_KEY`]) in place of [`base_attr`](Self::base_attr)'s
    /// class read, jump table and compare.
    #[inline(always)]
    fn quiet_key(&self, t: TaskId) -> u32 {
        quiet_key(t as usize)
    }

    #[inline]
    fn boost(&self, t: TaskId, to: PiAttr) {
        PI.boost(t, to)
    }

    #[inline]
    fn unboost(&self, t: TaskId, to: PiAttr) {
        PI.unboost(t, to)
    }

    #[inline(always)]
    fn set_blocked_on(&self, t: TaskId, on: Option<WaitObj>) {
        if let Some(sc) = sc_of(t as usize) {
            sc.blocked_on.store(on.map_or(0, WaitObj::addr), Ordering::Release);
        }
    }

    #[inline(always)]
    fn blocked_on(&self, t: TaskId) -> Option<WaitObj> {
        sc_of(t as usize).and_then(|sc| WaitObj::from_addr(sc.blocked_on.load(Ordering::Acquire)))
    }

    #[inline]
    fn on_cpu(&self, t: TaskId) -> bool {
        PI.on_cpu(t)
    }
}

/// A base attribute of `idx` changed (priority, reservation admitted or
/// dropped): the wait graph re-sorts it and walks. Call with no run-queue,
/// donation or admission lock held. Compiled out without `WAIT_GRAPH`.
#[inline]
pub(super) fn pi_attr_changed(idx: usize) {
    if waitgraph::ENABLED && idx < MAX_TASKS {
        waitgraph::attr_changed(idx as TaskId);
    }
}
