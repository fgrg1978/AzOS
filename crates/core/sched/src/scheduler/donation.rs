// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Priority donation half of the scheduler: the `TaskDonation` cell, the boost
//! and restore of a ready task, and the legacy and fast-IPC donation entry
//! points. Child of `scheduler` (moved out of `scheduler/mod.rs` unchanged).
//! Policy only: the donation locks and telemetry statics stay in `mod.rs`,
//! with the rest of the scheduler's state.

use super::*;

/// Donation target: task slot `idx`, through its donation lock.
pub(super) struct TaskDonation {
    idx: usize,
    irq: core::cell::Cell<Option<azos_arch::InterruptState>>,
}

impl TaskDonation {
    pub(super) fn new(idx: usize) -> Self {
        TaskDonation { idx, irq: core::cell::Cell::new(None) }
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
    /// The base, held up by the wait graph's boost (`classes::pi_floor`, a
    /// constant `u32::MAX` without `WAIT_GRAPH`).
    fn base(&self) -> u32 {
        let b = unsafe { task_mut(self.idx).base_priority.load(Ordering::Relaxed) };
        b.min(classes::pi_floor(self.idx))
    }
    fn apply_prio(&self, p: u32) {
        unsafe {
            let idx = self.idx;
            // Only a Ready task sits in a run queue keyed by priority, so only
            // that case needs the remove/re-enqueue dance. Blocked and Running
            // tasks still need the field written: a blocked lessee must wake
            // at the donated priority, otherwise donation silently does
            // nothing in the most common case (lessee waiting on I/O).
            let removed_from = if task_mut(idx).state() == TaskState::Ready {
                cpu_remove_anywhere(idx)
            } else {
                None
            };
            task_mut(idx).priority.store(p, Ordering::Relaxed);
            hist_reaccount(idx);
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

pub fn boost_ready_task(tid: u32, new_prio: u32) {
    // No `current_cpu_id()` here any more, and its absence is the fix: the
    // donor's hart was never the right queue to touch. See
    // `cpu_remove_anywhere`. Count, priority and re-bucketing all happen under
    // the target's donation lock (`donation::boost_locked`).
    if let Some(idx) = idx_for_tid(tid) {
        crate::donation::boost_locked(&TaskDonation::new(idx), new_prio);
    }
}

/// Donate `donor`'s live priority to `target` for the span of a wait, when
/// [`crate::donation::donation_for`] allows it. `true` = a donation was made
/// and exactly one [`return_donation`]`(target)` is owed.
///
/// The entry point of the waiting donors, such as the user-driver proxy waiting
/// on a ring-3 driver's reply. They share one rule and one counter
/// (`donation_count`), which is what lets them stack on the same target.
///
/// **The ring-3 floor (wave 9).** A ring-3 target (one with a user page table)
/// is never donated a priority more urgent than `RT_PRIORITY_THRESHOLD` (12),
/// the floor the topology gives every ring-3 row: a kernel real-time client
/// (say 8) waiting on a ring-3 driver lends it 12, not 8. The clamp is
/// counted ([`DONATIONS_FLOORED`]) and recorded once per target task through
/// the recorder the kernel installs ([`set_donation_floor_recorder`]).
///
/// A target that exits between the priority read and the boost is a no-op in
/// `boost_ready_task`, and its `return_donation` is a no-op too.
pub fn donate_priority(donor: u32, target: u32) -> bool {
    let floor = ring3_donation_floor(target);
    match crate::donation::donation_for(
        donor, task_priority(donor), target, task_priority(target), floor,
    ) {
        Some((prio, floored)) => {
            boost_ready_task(target, prio);
            LAST_DONATION.store(((target as u64) << 32) | prio as u64, Ordering::Relaxed);
            if floored {
                note_floored_donation(target);
            }
            true
        }
        None => false,
    }
}

/// The floor [`donate_priority`] applies to `target`: `RT_PRIORITY_THRESHOLD`
/// for a ring-3 task, 0 (none) for a kernel task. `donation-floor-canary`
/// removes it, so the proxy smoke sees the driver at the client's 8.
fn ring3_donation_floor(target: u32) -> u32 {
    if cfg!(feature = "donation-floor-canary") {
        return 0;
    }
    match idx_for_tid(target) {
        Some(i) if unsafe { task_ref(i).user_pt } != 0 => crate::task::RT_PRIORITY_THRESHOLD,
        _ => 0,
    }
}

/// The ring-3 floor of slot `idx` for the wait graph (owner decision
/// 10-10, `classes::graph_floored`): the floor [`ring3_donation_floor`]
/// gives a legacy donation, `RT_PRIORITY_THRESHOLD` for a ring-3 task and 0
/// for a kernel task. A ktest build also floors the one slot
/// [`ktest_flag_ring3`] names.
pub(crate) fn ring3_floor_at(idx: usize) -> u32 {
    if idx >= MAX_TASKS {
        return 0;
    }
    if unsafe { task_ref(idx).user_pt } != 0 || ktest_ring3(idx) {
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

/// Install the floored-donation recorder. Called once at boot.
pub fn set_donation_floor_recorder(f: fn(target_tid: u32)) {
    DONATION_FLOOR_RECORDER.set(f);
}

fn note_floored_donation(target: u32) {
    DONATIONS_FLOORED.fetch_add(1, Ordering::Relaxed);
    let Some(i) = idx_for_tid(target) else { return };
    if FLOOR_RECORDED_TID[i].swap(target, Ordering::Relaxed) == target {
        return;
    }
    if let Some(f) = DONATION_FLOOR_RECORDER.get() {
        f(target);
    }
}

/// Undo one donation made by [`donate_priority`].
pub fn return_donation(target: u32) {
    restore_ready_task(target);
}

/// Fast-IPC donation (wave 11 PIFAST): the CURRENT task, about to block on a
/// call to the task in slot `ti` (TID `target`, both from the caller's own
/// existence check), lends it its live priority for the span of the call.
/// `true` = a donation was made and exactly one [`return_donation`]`(target)`
/// is owed — by the reply, the caller's collect or withdrawal, or the exit
/// sweep (`azos_ipc::fast_ipc`).
///
/// Differs from [`donate_priority`] on purpose:
///  * the rule is [`crate::donation::donation_for_call`], against the
///    target's BASE priority (two callers of one server; see there);
///  * it runs on EVERY fast call, so the decision is `#[inline]` and takes no
///    TID lookup of its own: the donor is this hart's current task
///    (`syscall::dispatch` runs inside the caller's own trap) and the target
///    slot comes from the caller. The boost, only when one is due, is out of
///    line. Measured on `ipc-roundtrip` (no donation due, equal priorities).
///
/// Same counted boost, same ring-3 floor and floor recording as
/// [`donate_priority`], so it stacks with the proxy donations. A
/// target that exits between the lookup and the boost: the same window
/// [`donate_priority`] has (`boost_ready_task` re-looks-up, this does not;
/// the slot's count is zeroed when it is reused).
#[inline]
pub fn donate_priority_for_call_at(ti: usize, target: u32) -> bool {
    match call_donation_at(ti, target) {
        Some((prio, floored)) => {
            donate_for_call_boost(ti, target, prio, floored);
            true
        }
        None => false,
    }
}

/// Would [`donate_priority_for_call_at`] lend the current task's priority to
/// `target` in slot `ti`? The IPC fast path (Kconfig IPC_FASTPATH) takes only
/// a call that lends nothing and leaves the others to the ordinary path.
#[inline]
pub fn call_needs_donation_at(ti: usize, target: u32) -> bool {
    call_donation_at(ti, target).is_some()
}

/// [`call_needs_donation_at`] for a caller that knows the current task's
/// slot, `cur` (the IPC fast path: the caller's own).
#[inline(always)]
pub fn call_needs_donation_from(cur: usize, ti: usize, target: u32) -> bool {
    call_donation_from(cur, ti, target).is_some()
}

/// The decision half of [`donate_priority_for_call_at`]: the donated
/// priority and whether the ring-3 floor bound it, or `None`.
#[inline(always)]
fn call_donation_at(ti: usize, target: u32) -> Option<(u32, bool)> {
    call_donation_from(my_idx(), ti, target)
}

/// [`call_donation_at`] with the current task's slot `cur` given.
#[inline(always)]
fn call_donation_from(cur: usize, ti: usize, target: u32) -> Option<(u32, bool)> {
    if cur >= MAX_TASKS || ti >= MAX_TASKS {
        return None;
    }
    // SAFETY: `ti` and `cur` are bounds-checked above.
    let (donor_tid, donor_prio, base, ring3) = unsafe {
        let d = task_ref(cur);
        let t = task_ref(ti);
        if t.tid != target {
            return None;
        }
        (d.tid, d.priority.load(Ordering::Relaxed), t.base_priority.load(Ordering::Relaxed),
         t.user_pt != 0)
    };
    let floor = if ring3 && !cfg!(feature = "donation-floor-canary") {
        crate::task::RT_PRIORITY_THRESHOLD
    } else {
        0
    };
    crate::donation::donation_for_call(donor_tid, Some(donor_prio), target, Some(base), floor)
}

/// The boost half of [`donate_priority_for_call_at`], out of line so the
/// no-donation path carries none of its register saves.
#[inline(never)]
fn donate_for_call_boost(ti: usize, target: u32, prio: u32, floored: bool) {
    crate::donation::boost_locked(&TaskDonation::new(ti), prio);
    LAST_DONATION.store(((target as u64) << 32) | prio as u64, Ordering::Relaxed);
    if floored {
        note_floored_donation(target);
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
        crate::donation::restore_locked(&TaskDonation::new(idx), || {});
    }
}
