// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Where a wait-graph boost lands on a task: the `TaskDonation` cell (the
//! slot's donation lock), the boost and restore of a ready task, the ring-3
//! floor and its record. Child of `scheduler`. The locks and telemetry
//! statics stay in `mod.rs`, with the rest of the scheduler's state.

use super::*;

/// Donation target: task slot `idx`, through its donation lock, while it
/// still holds task `tid` (0: whoever holds it, for slot reuse itself).
pub(super) struct TaskDonation {
    idx: usize,
    tid: u32,
    irq: core::cell::Cell<Option<azos_arch::InterruptState>>,
}

impl TaskDonation {
    pub(super) fn new(idx: usize, tid: u32) -> Self {
        TaskDonation { idx, tid, irq: core::cell::Cell::new(None) }
    }
}

impl crate::donation::DonationCell for TaskDonation {
    fn lock(&self) {
        let prev = azos_arch::ARCH.disable_all();
        while DONATION_LOCKS[self.idx]
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        self.irq.set(Some(prev));
    }
    /// Slot reuse writes the new TID and resets count and priorities under
    /// this lock, so a holder that sees the old TID here acts before the
    /// reset, and one that sees the new TID does nothing.
    fn holds(&self) -> bool {
        self.tid == 0 || cfg!(feature = "donation-stale-slot-canary") || slot_holds(self.idx, self.tid)
    }
    fn unlock(&self) {
        DONATION_LOCKS[self.idx].store(false, Ordering::Release);
        if let Some(prev) = self.irq.take() {
            azos_arch::ARCH.restore(prev);
        }
    }
    fn count(&self) -> u32 {
        unsafe { task_mut(self.idx).donation_count.load(Ordering::Relaxed) }
    }
    fn set_count(&self, c: u32) {
        unsafe { task_mut(self.idx).donation_count.store(c, Ordering::Relaxed) }
    }
    fn prio(&self) -> u32 {
        unsafe { task_mut(self.idx).priority.load(Ordering::Relaxed) }
    }
    /// The base, held up by the wait graph's boost (`classes::pi_floor`).
    fn base(&self) -> u32 {
        let b = unsafe { task_mut(self.idx).base_priority.load(Ordering::Relaxed) };
        b.min(classes::pi_floor(self.idx))
    }
    fn apply_prio(&self, p: u32) {
        unsafe {
            let idx = self.idx;
            let task = task_mut(idx);
            let old = prio_bucket(task.priority.load(Ordering::Relaxed));
            // Only a Ready task sits in a run queue keyed by priority, so only
            // that case needs the remove/re-enqueue dance. Blocked and Running
            // tasks still need the field written: a blocked lessee must wake
            // at the donated priority, otherwise donation silently does
            // nothing in the most common case (lessee waiting on I/O).
            let mut removed_from = if task.state() == TaskState::Ready {
                cpu_remove_anywhere(idx)
            } else {
                None
            };
            #[cfg(feature = "ktest")]
            ktest_boost_window(idx);
            task.priority.store(p, Ordering::Relaxed);
            hist_reaccount(idx);
            // An enqueue reads the priority under its queue's lock (a wake, a
            // migration, a preempted task's requeue), and the state read above
            // says nothing about one in progress. Having read the old value it
            // linked the task under the old bucket, where nothing looks: the
            // boost is lost and no removal finds the task. Each queue's lock is
            // taken after the store, so an enqueue this walk misses holds it
            // later and reads the new priority.
            if removed_from.is_none()
                && prio_bucket(p) != old
                && !(azos_limits::CANARY_RUNTIME && CANARY_BOOST_STALE.load(Ordering::Relaxed))
            {
                removed_from = cpu_remove_stale(idx, old);
            }
            if let Some(q) = removed_from {
                // Back onto the SAME queue it came off, under that queue's
                // lock — `cpu_enqueue_locked` also wakes that hart, which is
                // what a donation is for.
                if !cpu_enqueue_locked(q, idx) {
                    SCHED_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

/// Runtime canary `pi-boost-stale-bucket` (`kernel/src/canary_rt.rs`): a priority
/// change does not look for an enqueue that read the old value (ktest
/// `pi_boost_lands_on_a_racing_wake`).
static CANARY_BOOST_STALE: AtomicBool = AtomicBool::new(false);

/// See [`CANARY_BOOST_STALE`].
pub fn canary_boost_stale_bucket() {
    CANARY_BOOST_STALE.store(true, Ordering::Relaxed);
}

/// Ktest: the slot whose next `apply_prio` wakes it inside the window, plus 1.
#[cfg(feature = "ktest")]
static KTEST_BOOST_WAKE: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "ktest")]
unsafe fn ktest_boost_window(idx: usize) {
    if KTEST_BOOST_WAKE.load(Ordering::Relaxed) == idx + 1 {
        KTEST_BOOST_WAKE.store(0, Ordering::Relaxed);
        wq_wake_by_tid(unsafe { task_ref(idx) }.tid);
    }
}

/// Ktest: `tid` sits parked, its registers saved.
#[cfg(feature = "ktest")]
pub fn ktest_parked(tid: u32) -> bool {
    let Some(idx) = idx_for_tid(tid) else { return false };
    let t = unsafe { task_ref(idx) };
    t.state_acquire() == TaskState::Blocked && !t.context_saving.load(Ordering::Acquire)
}

/// Ktest `pi_boost_lands_on_a_racing_wake`: boost parked `tid`, pinned to this
/// CPU, to `to`, with its WaitQueue wake inside `apply_prio`'s window. Interrupts
/// masked by the caller, so nothing dispatches it here. Whether the task is in
/// `to`'s list afterwards; it is put right either way.
#[cfg(feature = "ktest")]
pub fn ktest_boost_during_wake(tid: u32, to: u32) -> bool {
    let Some(idx) = idx_for_tid(tid) else { return false };
    let cpu = current_cpu_id();
    unsafe {
        let task = task_ref(idx);
        let before = task.priority.load(Ordering::Relaxed);
        KTEST_BOOST_WAKE.store(idx + 1, Ordering::Relaxed);
        boost_ready_task(tid, to);
        let _g = CpuLockIrqsOff::acquire(cpu);
        let found = cpu_remove(cpu, idx);
        if !found {
            let _ = cpu_remove_at(cpu, idx, prio_bucket(before));
        }
        cpu_enqueue(cpu, idx);
        found
    }
}

/// ktest: [`boost_ready_task`] with `between` run after the slot is resolved
/// and before the boost takes the target's donation lock.
#[cfg(feature = "ktest")]
pub fn ktest_boost_between(tid: u32, new_prio: u32, between: impl FnOnce()) {
    if let Some(idx) = idx_for_tid(tid) {
        between();
        crate::donation::boost_locked(&TaskDonation::new(idx, tid), new_prio);
    }
}

pub fn boost_ready_task(tid: u32, new_prio: u32) {
    // No `current_cpu_id()` here any more, and its absence is the fix: the
    // donor's hart was never the right queue to touch. See
    // `cpu_remove_anywhere`. Count, priority and re-bucketing all happen under
    // the target's donation lock (`donation::boost_locked`).
    if let Some(idx) = idx_for_tid(tid) {
        crate::donation::boost_locked(&TaskDonation::new(idx, tid), new_prio);
    }
}

/// The ring-3 floor of slot `idx` for the wait graph (owner decision
/// 10-10, `classes::graph_floored`): `RT_PRIORITY_THRESHOLD` for a ring-3
/// task and 0 for a kernel task. A ktest build also floors the one slot
/// [`ktest_flag_ring3`] names.
pub(crate) fn ring3_floor_at(idx: usize) -> u32 {
    if idx >= MAX_TASKS {
        return 0;
    }
    if unsafe { task_ref(idx).aspace.is_some() } || ktest_ring3(idx) {
        crate::task::RT_PRIORITY_THRESHOLD
    } else {
        0
    }
}

#[inline(always)]
fn ktest_ring3(_idx: usize) -> bool {
    #[cfg(feature = "ktest")]
    {
        KTEST_RING3_SLOT.load(Ordering::Relaxed) == _idx
    }
    #[cfg(not(feature = "ktest"))]
    {
        false
    }
}

/// ktest only: slot `idx` counts as ring-3 for [`ring3_floor_at`] (`None`
/// clears it), so a kernel probe task stands in for a ring-3 lock owner.
#[cfg(feature = "ktest")]
pub fn ktest_flag_ring3(idx: Option<usize>) {
    KTEST_RING3_SLOT.store(idx.unwrap_or(usize::MAX), Ordering::Relaxed);
}

/// Install the recorder of a boost the ring-3 floor bound. Called once at boot.
pub fn set_pi_floor_recorder(f: fn(target_tid: u32)) {
    PI_FLOOR_RECORDER.set(f);
}

/// The graph boosted slot `idx`, and the ring-3 floor bound it (`floored`):
/// one record per target task.
pub(super) fn note_pi_boost(idx: usize, floored: bool) {
    if !floored {
        return;
    }
    let target = unsafe { task_ref(idx) }.tid;
    if !slot_holds(idx, target) || FLOOR_RECORDED_TID[idx].swap(target, Ordering::Relaxed) == target {
        return;
    }
    if let Some(f) = PI_FLOOR_RECORDER.get() {
        f(target);
    }
}

/// Restore a (possibly ready) task's priority to `prio` and re-position it in
/// the ready queue if needed. Counterpart of [`boost_ready_task`] used to undo
/// an inherited boost. It re-buckets a task that is still sitting in the ready queue.
pub fn restore_ready_task(tid: u32) {
    // As in `boost_ready_task`: the donor's hart is not this task's queue.
    // Saturating count (an unbalanced restore must not wrap and pin the task
    // at a donated priority), base only when the LAST donor leaves, and the
    // whole of it under the target's donation lock — a boost can no longer
    // land between the count reaching 0 and the base being written.
    if let Some(idx) = idx_for_tid(tid) {
        crate::donation::restore_locked(&TaskDonation::new(idx, tid), || {});
    }
}
