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
//! # Between CPUs
//!
//! Which CPU a fair task queues on is decided at wake and at creation
//! (`find_best_cpu`); the balancing section at the end of this file moves
//! queued tasks afterwards (`SCHED_BALANCE`, policy in `balance.rs`): an idle
//! CPU pulls on its way into the idle task ([`balance_idle`]), and a CPU with
//! fair work queued pushes from [`tick`].
//!
//! # The `qos_id` hook
//!
//! [`params`] is the one place a task's weight and slice are decided. Today
//! the weight is its priority's and the slice `FAIR_SLICE_US`; the SC's
//! `qos_id` will choose both there (`qos_override`), and nothing else moves.

use core::sync::atomic::{
    AtomicI64, AtomicU32, AtomicU64,
    Ordering::{Acquire, Relaxed, Release},
};

use azos_arch::Interrupts;

use crate::eevdf_core::{self as eevdf, Avg, Choice, Ent};
use crate::task::{CtxReg, TaskState, DEFAULT_PRIORITY, IDLE_PRIORITY, RT_PRIORITY_THRESHOLD};

use super::balance::{self, Load, Mask, Moved, Params, Rq, Take};
use super::{
    cpu_enqueue_locked, cpu_queues, cpu_remove, enqueue_remote_aware, hist_reaccount, ncpu,
    prio_bucket, rt, task_mut, task_ref, CpuLockGuard, CpuLockIrqsOff, CPU_LOCKS, MAX_CPUS,
    MAX_TASKS, PER_CPU, RQ_NEXT, SCHED_ENQ_REFUSED, TASK_VALID,
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
    // percpu-hint: the caller holds CPU_LOCKS[cpu] (lock_irqsave): interrupts are off
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

/// The fair task running on ANOTHER CPU, as a placement reference: its
/// numbers, charged up to now (the owner CPU charges it only at its own
/// tick, so its stored `v` is up to a tick behind). Read without that CPU's
/// lock: `current_idx` can name the task that is just leaving, or the one
/// just arriving, and both are fair tasks of that CPU, a few slices from
/// its mean, so a stale answer moves a placement by about a lag limit and
/// no more. `None` when it runs nothing fair.
fn remote_cur(cpu: usize) -> Option<(usize, Ent)> {
    // SAFETY: `current_idx` and the task table are atomics and plain data read
    // as the census reads them; a stale index names some task of this pool.
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Relaxed);
        if idx >= MAX_TASKS || !TASK_VALID[idx].load(Relaxed) {
            return None;
        }
        let t = task_ref(idx);
        let p = prio_of(idx);
        if !is_fair(p)
            || t.state() != TaskState::Running
            || t.queued.load(Relaxed)
            || rt::reserved_here(cpu, idx)
        {
            return None;
        }
        let mut e = ent(idx, p);
        let since = SLOTS[idx].since.load(Relaxed);
        let at = now();
        if since != 0 && at > since {
            eevdf::charge(&mut e, at - since);
        }
        Some((idx, e))
    }
}

/// Everything on `cpu`'s queue but `skip`, the running task included.
///
/// The running task counts on EVERY CPU, not only the calling one: a task
/// woken, created or moved onto another CPU is placed against that CPU's
/// mean, and a mean over its queue alone ignores what is running there. With
/// the queue empty it was no reference at all, and the task kept the `v` it
/// carried from elsewhere: a thread that joined an idle CPU at `v` 0 ran
/// alone for a few seconds while every task woken onto that CPU afterwards
/// (the exit of its own process among them) arrived tens of seconds of `v`
/// ahead of it, and waited that long for the CPU.
unsafe fn others(cpu: usize, skip: usize) -> Avg {
    let mut a = Avg::new();
    for (i, e) in unsafe { members(cpu) } {
        if i != skip {
            a.add(&e);
        }
    }
    // percpu-hint: the caller holds CPU_LOCKS[cpu] (lock_irqsave): interrupts are off
    let cur = if cpu == crate::smp::current_cpu_id() { unsafe { cur_cand(cpu) } } else { remote_cur(cpu) };
    if let Some((i, e)) = cur {
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
    // Fair work is waiting behind the running task: see whether another CPU
    // should have it (before the pick, so the pick sees what stays).
    unsafe { balance_push(cpu) };
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

// ── Between CPUs (`SCHED_BALANCE`, policy: `balance.rs`) ─────────────────────

/// Levels a pass walks: the last-level cache, the node, the package.
const HOPS: usize = 3;

/// Tasks moved by an idle pull / a tick push, and by the farthest topology
/// level a move crossed (0 = the cache, 1 = the node, 2 = the package). A
/// level equal to a nearer one is not a level of its own: on a one-node
/// machine a move beyond the cache counts at the node.
static PULLED: AtomicU32 = AtomicU32::new(0);
static PUSHED: AtomicU32 = AtomicU32::new(0);
static BY_HOP: [AtomicU32; HOPS] = [const { AtomicU32::new(0) }; HOPS];
/// Idle pulls attempted, and those that found nothing to take.
static IDLE_TRIES: AtomicU32 = AtomicU32::new(0);
static IDLE_EMPTY: AtomicU32 = AtomicU32::new(0);
/// Senders skipped because another CPU held their queue lock.
static BUSY: AtomicU32 = AtomicU32::new(0);
/// Tasks each CPU received and gave away.
static MOVED_IN: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
static MOVED_OUT: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
/// When each CPU may next push, and next retry a failed pull (timer counts).
static NEXT_PUSH: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static NEXT_PULL: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// The counters, as published in the inspect tree (`sched/balance`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BalanceStats {
    pub pulled: u32,
    pub pushed: u32,
    pub by_hop: [u32; HOPS],
    pub idle_tries: u32,
    pub idle_empty: u32,
    pub busy: u32,
}

/// [`BalanceStats`] since boot.
pub fn balance_stats() -> BalanceStats {
    BalanceStats {
        pulled: PULLED.load(Relaxed),
        pushed: PUSHED.load(Relaxed),
        by_hop: core::array::from_fn(|h| BY_HOP[h].load(Relaxed)),
        idle_tries: IDLE_TRIES.load(Relaxed),
        idle_empty: IDLE_EMPTY.load(Relaxed),
        busy: BUSY.load(Relaxed),
    }
}

/// `(received, given away)`: the tasks `cpu` took from other CPUs and the
/// ones other CPUs took from it, since boot.
pub fn balance_cpu_moves(cpu: usize) -> (u32, u32) {
    match (MOVED_IN.get(cpu), MOVED_OUT.get(cpu)) {
        (Some(i), Some(o)) => (i.load(Relaxed), o.load(Relaxed)),
        _ => (0, 0),
    }
}

/// The push interval and the failed-pull retry in timer counts.
#[inline]
fn balance_interval() -> u64 {
    azos_drv_sys::timebase::TIMER_FREQ * azos_limits::SCHED_BALANCE_INTERVAL_MS as u64 / 1000
}

/// The CPUs of `[sched] isolcpus`: kept for isolated real-time rows, so fair
/// tasks are neither balanced onto them nor off them, whatever they run at
/// the moment. Set once at boot ([`set_isolated_cpus`]).
static ISOLATED: AtomicU64 = AtomicU64::new(0);

/// Publish the isolated CPUs (bit n = CPU n). `kernel::boot::topology`, after
/// the topology is installed and before the first balancing pass.
pub fn set_isolated_cpus(mask: u64) {
    ISOLATED.store(mask, Relaxed);
    // Kconfig NOHZ_FULL: the same CPUs may stop their tick.
    crate::scheduler::nohz_publish(mask);
}

/// The isolated CPUs (bit n = CPU n); energy-aware wake placement leaves
/// them out too, and CPU hotplug refuses to take one offline.
#[inline]
pub(super) fn isolated_cpus() -> u64 {
    ISOLATED.load(Relaxed)
}

/// Does `cpu` hold real-time work right now, which keeps it out of balancing
/// as sender and as receiver? A band task running or queued, an exhausted
/// band window or an admitted reservation (`rt::active` is the last two and
/// the running band task). Read unlocked: a stale answer moves one task
/// wrongly, once. An isolated CPU ([`ISOLATED`]) is out whether or not its
/// real-time row is running yet.
#[inline]
pub(super) unsafe fn rt_cpu(cpu: usize) -> bool {
    if rt::active(cpu) || PER_CPU[cpu].ready_bitmap.load(Relaxed) & rt::LEVELS_BAND != 0 {
        return true;
    }
    let cur = PER_CPU[cpu].current_idx.load(Relaxed);
    cur < MAX_TASKS && task_ref(cur).priority.load(Relaxed) < RT_PRIORITY_THRESHOLD
}

/// The levels around `me`, nearest first, as `balance::pull`/`push` take them.
/// Before the topology is installed the machine is one level: every CPU.
fn levels_of(me: usize, online: Mask, out: &mut [balance::Ring; HOPS]) -> usize {
    use crate::topo::{self, Level};
    if topo::installed() == 0 {
        out[0] = balance::Ring { mask: online, level: 0 };
        return 1;
    }
    let m = [Level::Llc, Level::Node, Level::Package].map(|l| topo::mask(l, me));
    match balance::distinct_levels(&m, online, out) {
        // A CPU the topology does not describe: one level, everyone.
        0 => {
            out[0] = balance::Ring { mask: online, level: 0 };
            1
        }
        n => n,
    }
}

/// A CPU lock taken without waiting: another CPU's queue is never spun on
/// from the tick or the way to idle (the `SCHED_REMOTE_WAKE_DEFER` rule).
struct Held {
    cpu: usize,
    prev: azos_arch::InterruptState,
}

impl Held {
    fn try_take(cpu: usize) -> Option<Held> {
        let prev = azos_arch::ARCH.disable_all();
        if CPU_LOCKS[cpu].swap(1, Acquire) != 0 {
            azos_arch::ARCH.restore(prev);
            return None;
        }
        Some(Held { cpu, prev })
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        CPU_LOCKS[self.cpu].store(0, Release);
        azos_arch::ARCH.restore(self.prev);
    }
}

/// May the queued task `idx` (at fair level `level` of `cpu`) leave? Caller
/// holds `CPU_LOCKS[cpu]`. Not pinned, ready, switched out (a task whose save
/// is outstanding is left for the CPU that is saving it), not a reservation.
unsafe fn movable(cpu: usize, idx: usize, level: usize) -> bool {
    if idx >= MAX_TASKS || !TASK_VALID[idx].load(Relaxed) {
        return false;
    }
    let t = task_ref(idx);
    t.cpu_affinity < 0
        && t.state() == TaskState::Ready
        && !t.context_saving.load(Acquire)
        && prio_of(idx) as usize == level
        && !rt::reserved_here(cpu, idx)
}

/// The queues, for `balance.rs`. `me` is the CPU running the pass.
struct Queues {
    me: usize,
}

impl Rq for Queues {
    /// The slot and the CPU it came off.
    type Task = (usize, usize);

    fn load(&mut self, cpu: usize) -> Load {
        // SAFETY: lock-free reads of the per-CPU queue state and of a task
        // slot, which the scheduler's own `find_best_cpu` makes the same way.
        unsafe {
            let mut w = 0u32;
            let mut levels = PER_CPU[cpu].ready_bitmap.load(Relaxed) & rt::LEVELS_NONBAND;
            while levels != 0 {
                let l = levels.trailing_zeros() as usize;
                levels &= levels - 1;
                w = w.saturating_add(
                    (cpu_queues(cpu)[l].count() as u32)
                        .saturating_mul(eevdf::weight_of_prio(l as u32, DEFAULT_PRIORITY)),
                );
            }
            // The task it is running, if it is fair (another hart's current
            // task is read unlocked, like the rest).
            let cur = PER_CPU[cpu].current_idx.load(Relaxed);
            if cur < MAX_TASKS {
                let t = task_ref(cur);
                let p = prio_of(cur);
                if is_fair(p) && t.state() == TaskState::Running {
                    w = w.saturating_add(eevdf::weight_of_prio(p, DEFAULT_PRIORITY));
                }
            }
            Load { weight: w, capacity: crate::topo::capacity(cpu) }
        }
    }

    fn take(
        &mut self,
        src: usize,
        _dst: usize,
        scan: &mut u32,
        want: &mut dyn FnMut(u32) -> bool,
    ) -> Take<Self::Task> {
        let Some(_g) = Held::try_take(src) else {
            return Take::Busy;
        };
        // SAFETY: `CPU_LOCKS[src]` is held for the whole walk (`_g`), which is
        // what every list operation and `movable` require.
        unsafe {
            let mut levels = PER_CPU[src].ready_bitmap.load(Relaxed) & rt::LEVELS_NONBAND;
            while levels != 0 {
                let l = levels.trailing_zeros() as usize;
                levels &= levels - 1;
                for idx in cpu_queues(src)[l].iter(&RQ_NEXT) {
                    if *scan == 0 {
                        return Take::Nothing;
                    }
                    *scan -= 1;
                    if !movable(src, idx, l) {
                        continue;
                    }
                    if !want(params(idx, l as u32).0) {
                        continue;
                    }
                    // Out of the list now, keeping its lag, as a priority
                    // change does (`cpu_remove_anywhere`); the iterator is not
                    // used again.
                    if cpu_remove(src, idx) {
                        left(src, idx);
                        return Take::Got((idx, src));
                    }
                }
            }
        }
        Take::Nothing
    }

    fn give(&mut self, dst: usize, (idx, src): Self::Task) {
        // SAFETY: the slot was detached from its queue by `take` and is on no
        // list, so this CPU owns it until the enqueue below.
        unsafe {
            let t = task_mut(idx);
            // A reservation admitted since `take` pinned it: it goes where it
            // was pinned (`rt::reserve` moves a queued task the same way).
            let dst = if t.cpu_affinity >= 0 { (t.cpu_affinity as usize).min(ncpu() - 1) } else { dst };
            t.context.tp = dst as CtxReg;
            hist_reaccount(idx);
            t.ready_site.store(crate::task::ready_site::REBALANCE | ((dst as u8) << 4), Relaxed);
            let queued = if dst == self.me { cpu_enqueue_locked(dst, idx) } else { enqueue_remote_aware(dst, idx) };
            if !queued {
                SCHED_ENQ_REFUSED.fetch_add(1, Relaxed);
            }
            if dst != src {
                MOVED_IN[dst].fetch_add(1, Relaxed);
                MOVED_OUT[src].fetch_add(1, Relaxed);
            }
        }
    }
}

/// One pass for `cpu`: pull (`push == false`) or push.
unsafe fn balance_pass(cpu: usize, push: bool) -> Moved {
    let online = crate::smp::NUM_ONLINE_CPUS.load(Relaxed).min(ncpu()).min(MAX_CPUS);
    if online < 2 {
        return Moved::default();
    }
    let online_mask: Mask = if online >= 64 { !0 } else { (1u64 << online) - 1 };
    let isolated = ISOLATED.load(Relaxed);
    let mut eligible: Mask = 0;
    for c in 0..online {
        if isolated >> c & 1 == 0 && !rt_cpu(c) {
            eligible |= 1u64 << c;
        }
    }
    let mut lv = [balance::Ring::default(); HOPS];
    let n = levels_of(cpu, online_mask, &mut lv);
    let p = Params {
        moves: azos_limits::SCHED_BALANCE_MOVES as u32,
        scan: azos_limits::SCHED_BALANCE_SCAN as u32,
    };
    let mut q = Queues { me: cpu };
    let r = if push {
        balance::push(&mut q, cpu, &lv[..n], eligible, &p)
    } else {
        balance::pull(&mut q, cpu, &lv[..n], eligible, &p)
    };
    if r.moved != 0 {
        (if push { &PUSHED } else { &PULLED }).fetch_add(r.moved, Relaxed);
        BY_HOP[(r.hop as usize).min(HOPS - 1)].fetch_add(r.moved, Relaxed);
    }
    if r.busy != 0 {
        BUSY.fetch_add(r.busy, Relaxed);
    }
    r
}

/// The tick of `cpu`, with fair tasks queued behind its running one: once per
/// `SCHED_BALANCE_INTERVAL_MS`, hand some to a less loaded CPU.
#[inline]
unsafe fn balance_push(cpu: usize) {
    if !azos_limits::SCHED_BALANCE {
        return;
    }
    let t = now();
    if t < NEXT_PUSH[cpu].load(Relaxed) {
        return;
    }
    NEXT_PUSH[cpu].store(t + balance_interval(), Relaxed);
    balance_pass(cpu, true);
}

/// `do_schedule` on `cpu`, before the pick; `old` is the slot it is leaving
/// (`usize::MAX` for none). If nothing is left to run but the idle task, take
/// work from another CPU so the pick finds it. A pull that found nothing is
/// not retried for `SCHED_BALANCE_INTERVAL_MS`; one that moved a task is.
#[inline]
pub(super) unsafe fn balance_idle(cpu: usize, old: usize) {
    if !azos_limits::SCHED_BALANCE {
        return;
    }
    if PER_CPU[cpu].ready_bitmap.load(Relaxed) & (rt::LEVELS_BAND | rt::LEVELS_NONBAND) != 0 {
        return;
    }
    // A real task that keeps running is not an idle CPU.
    if old < MAX_TASKS {
        let t = task_ref(old);
        if t.state() == TaskState::Running && t.priority.load(Relaxed) < IDLE_PRIORITY {
            return;
        }
    }
    balance_idle_pull(cpu);
}

#[inline(never)]
unsafe fn balance_idle_pull(cpu: usize) {
    // No clock read unless a failed pull is waiting out its interval.
    let next = NEXT_PULL[cpu].load(Relaxed);
    if next != 0 && now() < next {
        return;
    }
    IDLE_TRIES.fetch_add(1, Relaxed);
    let r = balance_pass(cpu, false);
    if r.moved == 0 {
        IDLE_EMPTY.fetch_add(1, Relaxed);
        NEXT_PULL[cpu].store(now() + balance_interval(), Relaxed);
    } else {
        NEXT_PULL[cpu].store(0, Relaxed);
    }
}
