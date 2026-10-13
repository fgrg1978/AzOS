// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The fair class's run queue: EEVDF over the fair levels' ready lists.
//!
//! A child module of `scheduler.rs` (pulled in with `#[path]`, like
//! `classes.rs`). The model and every number are the pure `eevdf_core.rs`
//! (host-tested); this file stores the per-task state and walks the queue.
//!
//! # Membership and order
//!
//! A fair task (priority `RT_PRIORITY_THRESHOLD..IDLE_PRIORITY`) is queued
//! exactly as before: in its priority level's ready list, under its hart's
//! lock, with the `queued` claim (K-C12) and the level's bit in the ready
//! bitmap. The lists remain the membership truth, so the removal paths, the
//! claim audit and the K-C24/K-C26 re-enqueues are untouched. What changed is
//! the *order*: the pick walks every fair level of the hart and takes
//! [`eevdf_core::choose`](crate::eevdf_core::choose)'s task, and the priority
//! is no longer a strict order among fair tasks but a weight
//! ([`eevdf_core::weight_of_prio`](crate::eevdf_core::weight_of_prio), the
//! default priority being nice 0). The cost is O(ready fair tasks on the
//! hart) per pick, tick, wake and sleep; `eevdf_core.rs` says why that, and
//! not a tree, is the choice.
//!
//! # The running task counts
//!
//! The running task is not in a list but it is in the mean and a candidate of
//! the pick ([`pick`]): a task that is still the best keeps the CPU, and one
//! that is ahead of its share does not. The mean is recomputed from the
//! members every time (no stored sums): a missed hook costs one pick's
//! accuracy, never a wrong sum that lives on.
//!
//! # Where each rule runs
//!
//! | Rule | Where |
//! |---|---|
//! | the pick | [`pick`] from `cpu_dequeue` (a hart without RT state) and from `rt::pick`'s non-band levels |
//! | charge | [`on_switch`] (`set_current_task`, every switch incl. the IPC hand-off), [`tick`], [`begin`] |
//! | yield | [`begin`] (a `Voluntary` switch of a `Running` task) |
//! | lag stored | [`sleep`] (the `Blocked` arm of `do_schedule`), [`left`] (`cpu_remove_anywhere`: a priority change or a move) |
//! | lag applied | [`place`] (`cpu_enqueue`), except a re-queue of the task that was just running |
//!
//! A task that leaves without a stored lag (the IPC hand-off blocks without
//! `do_schedule`'s `Blocked` arm; a rebalance pops it from the queue) is
//! placed with the `v` it had, held within the lag limit of the mean.
//!
//! # The `qos_id` hook
//!
//! [`params`] is the one place a task's weight and slice are decided. Today
//! the weight is its priority's and the slice `FAIR_SLICE_US`; the SC's
//! `qos_id` will choose both there (`qos_override`), and nothing else moves.

use core::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};

use crate::eevdf_core::{self as eevdf, Avg, Choice, Ent};
use crate::task::{TaskState, DEFAULT_PRIORITY, IDLE_PRIORITY, RT_PRIORITY_THRESHOLD};

use super::{
    cpu_queues, prio_bucket, rt, task_ref, CpuLockGuard, CpuLockIrqsOff, MAX_TASKS, PER_CPU,
    RQ_NEXT,
};

/// One task's EEVDF state. The weight and slice are not stored: they are
/// [`params`] of the live priority (a priority-inheritance boost is a weight
/// change at once).
struct Slot {
    vruntime: AtomicI64,
    deadline: AtomicI64,
    /// The lag stored at the last sleep, [`NO_LAG`] when it left without one
    /// or has used it. A new task has lag 0: it joins at the mean.
    lag: AtomicI64,
    /// The timer count at which the task was last charged up to (its
    /// dispatch, then each tick); 0 = not running.
    since: AtomicU64,
}

/// No lag stored. Far outside the clamped range.
const NO_LAG: i64 = i64::MIN;

static SLOTS: [Slot; MAX_TASKS] = [const {
    Slot {
        vruntime: AtomicI64::new(0),
        deadline: AtomicI64::new(0),
        lag: AtomicI64::new(0),
        since: AtomicU64::new(0),
    }
}; MAX_TASKS];

/// The fair slice in timer counts (`FAIR_SLICE_US`).
const SLICE: u64 = azos_drv_sys::timebase::TIMER_FREQ * azos_limits::FAIR_SLICE_US / 1_000_000;

/// Is priority `prio` a fair level? The band is below, idle is above.
#[inline(always)]
pub fn is_fair(prio: u32) -> bool {
    prio >= RT_PRIORITY_THRESHOLD && prio < IDLE_PRIORITY
}

#[inline(always)]
fn prio_of(idx: usize) -> u32 {
    prio_bucket(unsafe { task_ref(idx) }.priority.load(Relaxed)) as u32
}

#[inline(always)]
fn now() -> u64 {
    azos_drv_sys::timebase::now() | 1
}

/// The scheduler tick in timer counts: the floor of the lag limit.
#[inline]
fn tick_len() -> u64 {
    azos_drv_sys::timebase::TIMER_FREQ / azos_drv_sys::timebase::sched_hz_get().max(1)
}

/// The `qos_id` hook: a weight and slice (timer counts) the QoS class of
/// task `idx` chooses, or `None` for the priority's. Not wired.
#[inline(always)]
fn qos_override(_idx: usize) -> Option<(u32, u64)> {
    None
}

/// Task `idx`'s weight and slice at priority `prio`.
#[inline]
fn params(idx: usize, prio: u32) -> (u32, u64) {
    match qos_override(idx) {
        Some(p) => p,
        None => (eevdf::weight_of_prio(prio, DEFAULT_PRIORITY), SLICE),
    }
}

#[inline]
fn ent(idx: usize, prio: u32) -> Ent {
    let (weight, slice) = params(idx, prio);
    let s = &SLOTS[idx];
    Ent { weight, slice, vruntime: s.vruntime.load(Relaxed), deadline: s.deadline.load(Relaxed) }
}

#[inline]
fn store(idx: usize, e: &Ent) {
    let s = &SLOTS[idx];
    s.vruntime.store(e.vruntime, Relaxed);
    s.deadline.store(e.deadline, Relaxed);
}

/// A slot is (re)used: the previous task's numbers are gone, and the new
/// one joins at the mean.
pub(super) fn reset(idx: usize) {
    if let Some(s) = SLOTS.get(idx) {
        s.vruntime.store(0, Relaxed);
        s.deadline.store(0, Relaxed);
        s.lag.store(0, Relaxed);
        s.since.store(0, Relaxed);
    }
}

/// The queued fair tasks of `cpu` with their numbers, reservations (the DL
/// class's) left out. Caller holds `CPU_LOCKS[cpu]`.
unsafe fn members(cpu: usize) -> impl Iterator<Item = (usize, Ent)> {
    let levels = PER_CPU[cpu].ready_bitmap.load(Relaxed) & rt::LEVELS_NONBAND;
    (RT_PRIORITY_THRESHOLD as usize..IDLE_PRIORITY as usize)
        .filter(move |l| levels >> l & 1 != 0)
        .flat_map(move |l| cpu_queues(cpu)[l].iter(&RQ_NEXT))
        .filter(move |&idx| idx < MAX_TASKS && !rt::reserved_here(cpu, idx))
        .map(|idx| (idx, ent(idx, prio_of(idx))))
}

/// The task running on `cpu` if it competes as a fair task: this hart's
/// (another hart's current task is not known to be fair-running to us), in
/// state `Running`, not in a list, not a reservation.
unsafe fn cur_cand(cpu: usize) -> Option<(usize, Ent)> {
    if cpu != crate::smp::current_cpu_id() {
        return None;
    }
    let idx = PER_CPU[cpu].current_idx.load(Relaxed);
    if idx >= MAX_TASKS {
        return None;
    }
    let t = unsafe { task_ref(idx) };
    let p = prio_of(idx);
    if !is_fair(p)
        || t.state() != TaskState::Running
        || t.queued.load(Relaxed)
        || rt::reserved_here(cpu, idx)
    {
        return None;
    }
    Some((idx, ent(idx, p)))
}

/// Everything on `cpu`'s queue but `skip`, the running task included.
unsafe fn others(cpu: usize, skip: usize) -> Avg {
    let mut a = Avg::new();
    for (i, e) in unsafe { members(cpu) } {
        if i != skip {
            a.add(&e);
        }
    }
    if let Some((i, e)) = unsafe { cur_cand(cpu) } {
        if i != skip {
            a.add(&e);
        }
    }
    a
}

/// What the pick found on `cpu`.
pub(super) enum Fair {
    /// No fair task is queued.
    Empty,
    /// The running task is still the best: nothing to switch to.
    Keep,
    /// This queued task takes the CPU (still in its list).
    Task(usize),
}

/// The pick: the running fair task (if it is one) against the queued ones.
/// Caller holds `CPU_LOCKS[cpu]`.
pub(super) unsafe fn pick(cpu: usize) -> Fair {
    match eevdf::choose(|| unsafe { members(cpu) }, unsafe { cur_cand(cpu) }) {
        Choice::Empty => Fair::Empty,
        Choice::Cur => Fair::Keep,
        Choice::Task(idx) => Fair::Task(idx),
    }
}

/// The class view (`classes::FairClass::pick`): the queued task EEVDF runs
/// next, the running one not considered, not removed.
pub(super) unsafe fn peek(cpu: usize) -> Option<usize> {
    let _g = CpuLockGuard::acquire(cpu);
    match eevdf::choose(|| unsafe { members(cpu) }, None) {
        Choice::Task(idx) => Some(idx),
        _ => None,
    }
}

/// Task `idx` runs for what has passed since it was last charged.
unsafe fn update_curr(idx: usize, prio: u32) {
    let s = &SLOTS[idx];
    let t = now();
    let since = s.since.swap(t, Relaxed);
    if since != 0 && t > since {
        let mut e = ent(idx, prio);
        eevdf::charge(&mut e, t - since);
        store(idx, &e);
    }
}

/// The scheduler tick on `cpu` with fair task `cur` running: charge it, and
/// say whether a queued task now beats it (its slice is used, or it is ahead
/// of its share, or a woken task has an earlier deadline).
pub(super) unsafe fn tick(cpu: usize, cur: usize) -> bool {
    let p = prio_of(cur);
    if !is_fair(p) {
        return false;
    }
    // A reservation at a fair level is the DL class's: it is switched at
    // every tick as before, and `rt::pick` decides whether it keeps the CPU.
    if rt::reserved_here(cpu, cur) {
        return true;
    }
    unsafe { update_curr(cur, p) };
    let bm = PER_CPU[cpu].ready_bitmap.load(Relaxed);
    // A band task queued outranks every fair task: the tick hands it the CPU.
    if bm & rt::LEVELS_BAND != 0 {
        return true;
    }
    if bm & rt::LEVELS_NONBAND == 0 {
        return false;
    }
    let _g = CpuLockGuard::acquire(cpu);
    matches!(unsafe { pick(cpu) }, Fair::Task(_))
}

/// The top of `do_schedule` on `cpu`: the current task, if fair, is charged
/// to now (the pick sees its true `v`), and a task that yields moves its
/// deadline a slice on so that the next eligible task is not passed over.
pub(super) unsafe fn begin(cpu: usize, voluntary: bool) {
    let idx = PER_CPU[cpu].current_idx.load(Relaxed);
    if idx >= MAX_TASKS {
        return;
    }
    let t = unsafe { task_ref(idx) };
    let p = prio_of(idx);
    let st = t.state();
    if !is_fair(p) || st == TaskState::Zombie {
        return;
    }
    unsafe { update_curr(idx, p) };
    if voluntary && st == TaskState::Running {
        let mut e = ent(idx, p);
        eevdf::yield_now(&mut e);
        store(idx, &e);
    }
}

/// `set_current_task`: `cpu` switches from `prev` to `next` (any index
/// outside the pool = none). The task that stops is charged, the one that
/// starts is stamped.
#[inline]
pub(super) unsafe fn on_switch(prev: usize, next: usize) {
    let prev_fair = prev < MAX_TASKS && is_fair(prio_of(prev));
    let next_fair = next < MAX_TASKS && is_fair(prio_of(next));
    if !prev_fair && !next_fair {
        return;
    }
    let t = now();
    if prev_fair {
        let s = &SLOTS[prev];
        let since = s.since.swap(0, Relaxed);
        if since != 0 && t > since {
            let mut e = ent(prev, prio_of(prev));
            eevdf::charge(&mut e, t - since);
            store(prev, &e);
        }
    }
    if next_fair {
        SLOTS[next].since.store(t, Relaxed);
    }
}

/// `idx` is blocking on `cpu` (the `Blocked` arm of `do_schedule`, interrupts
/// off): store the lag it keeps.
pub(super) unsafe fn sleep(cpu: usize, idx: usize) {
    let p = prio_of(idx);
    if !is_fair(p) {
        return;
    }
    let _g = CpuLockIrqsOff::acquire(cpu);
    let o = unsafe { others(cpu, idx) };
    let lag = eevdf::lag_on_sleep(&o, &ent(idx, p), tick_len());
    SLOTS[idx].lag.store(lag, Relaxed);
}

/// `idx` has just been taken off `cpu`'s lists to be re-queued (a priority
/// change, a reservation's move): store the lag it keeps. Caller holds
/// `CPU_LOCKS[cpu]`.
pub(super) unsafe fn left(cpu: usize, idx: usize) {
    let p = prio_of(idx);
    if !is_fair(p) {
        return;
    }
    let o = unsafe { others(cpu, idx) };
    let lag = eevdf::lag_on_sleep(&o, &ent(idx, p), tick_len());
    SLOTS[idx].lag.store(lag, Relaxed);
}

/// `idx` is about to join `cpu`'s lists (`cpu_enqueue`, lock held, not yet
/// linked). `requeue`: it is the task that was just running (or a pick put
/// back), which keeps its `v` and deadline; any other enqueue is a wake or a
/// move and is placed against the queue by its lag.
pub(super) unsafe fn place(cpu: usize, idx: usize, requeue: bool) {
    if requeue {
        return;
    }
    let p = prio_of(idx);
    if !is_fair(p) {
        return;
    }
    let o = unsafe { others(cpu, idx) };
    let mut e = ent(idx, p);
    let lag = SLOTS[idx].lag.swap(NO_LAG, Relaxed);
    eevdf::place_wake(&o, &mut e, (lag != NO_LAG).then_some(lag), tick_len());
    store(idx, &e);
}

/// Must queued `cand` take the CPU from running `cur` (the class's
/// `preempt_check`)?
pub(super) fn before(cand: usize, cur: usize) -> bool {
    eevdf::before(&ent(cand, prio_of(cand)), &ent(cur, prio_of(cur)))
}
