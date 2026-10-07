// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Eligibility rule for the fast-IPC same-hart direct switch
//! (`scheduler::ipc_wake_then_block`).
//!
//! Pure logic in its own file so `tests/host/sched-wake-tests` can compile it;
//! the scheduler proper cannot leave the target. Same pattern as
//! `resident_histogram.rs` / `ready_list.rs`.
//!
//! # The rule is an equivalence, not a heuristic
//!
//! The direct switch skips the run queue: the woken task is never enqueued
//! and the waker never runs `do_schedule`'s pick. That is only allowed when
//! the pick it skips would have chosen the woken task anyway, so this answers
//! "would `do_schedule` on `cpu`, right after enqueueing the target there,
//! dispatch the target?" and refuses every case where the answer is not a
//! certain yes:
//!
//! * SCHED-RT state on the hart, or a band task on either side — `rt::pick`
//!   decides and the dispatch tail charges the band and the reservations;
//! * APS dispatch — its policies pick, not the bitmap queue;
//! * the target pinned to another hart — the ordinary wake would send it there;
//! * either task at `IDLE_PRIORITY` — `do_schedule` programs the tickless
//!   timer on a switch to or from idle, which this path does not replicate;
//! * **any task already queued on `cpu` at the target's priority bucket or
//!   better.** `cpu_dequeue` pops the lowest set bit of `ready_bitmap`, FIFO
//!   within a bucket, so a queued task of equal priority is ahead of a target
//!   enqueued behind it, and a better one wins outright. This clause is what
//!   keeps priority inheritance (RFC-0031 lease donation) intact: a lessee
//!   boosted by `boost_ready_task` sits in a better bucket, and the switch
//!   must refuse so the boosted task runs first.

/// Number of priority buckets the per-CPU `ready_bitmap` (a `u32`) carries.
/// Pinned to `task::NUM_PRIORITIES` by a const assert in `scheduler.rs`.
pub const BITMAP_BUCKETS: usize = 32;

/// Inputs of the rule, all read by the caller on the switching hart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectSwitch {
    /// `PER_CPU[cpu].ready_bitmap`: bit `b` set = something queued at bucket `b`.
    pub ready_bitmap: u32,
    /// The target's `prio_bucket(priority)`; lower is more urgent.
    pub target_bucket: usize,
    /// The target's `cpu_affinity` (`< 0` = unpinned).
    pub target_affinity: i8,
    /// The hart that would switch.
    pub cpu: usize,
    /// The target runs at `IDLE_PRIORITY`.
    pub target_is_idle: bool,
    /// The waker (the task about to block) runs at `IDLE_PRIORITY`.
    pub current_is_idle: bool,
    /// The hart has SCHED-RT state, or either side is a band task
    /// (`scheduler::rt::holds_direct_switch`): the pick must decide.
    pub deadline_live: bool,
    /// `aps_dispatch_enabled()`.
    pub aps: bool,
    /// The target's `context_saving` is clear, read with `Acquire` AFTER the
    /// dispatch CAS. The `saved` flag `wake_transition` was given is read
    /// BEFORE that CAS and can be stale: a task that blocked on another hart
    /// an instant ago is `Blocked` while that hart is still saving its
    /// registers. `do_schedule` covers this with its spin gate; the direct
    /// switch has no gate, so it must refuse instead. The CAS acquires the
    /// blocker's `Blocked` release, which follows its `context_saving = true`,
    /// so this read cannot miss a save still in flight.
    pub target_saved: bool,
}

/// Bitmap of every bucket at or better than `bucket` (bits `0..=bucket`).
#[inline(always)]
pub const fn at_or_above(bucket: usize) -> u32 {
    if bucket >= BITMAP_BUCKETS - 1 {
        u32::MAX
    } else {
        (2u32 << bucket) - 1
    }
}

/// `true` only when `do_schedule` would certainly dispatch the target next.
#[inline(always)]
pub fn allowed(s: DirectSwitch) -> bool {
    if !s.target_saved {
        return false;
    }
    if s.deadline_live || s.aps || s.target_is_idle || s.current_is_idle {
        return false;
    }
    if s.target_affinity >= 0 && s.target_affinity as usize != s.cpu {
        return false;
    }
    s.ready_bitmap & at_or_above(s.target_bucket) == 0
}

/// May the direct switch skip the histogram update for its two re-accounts?
///
/// `scheduler::hist_reaccount_pair` swaps both slots' recorded keys
/// (`oa`->`na`, `ob`->`nb`) and then applies `oa`->`na` and `ob`->`nb` to the
/// resident histogram — unless this says the two deltas sum to zero, which is
/// exactly when the swapped-out pair equals the swapped-in pair in some order
/// (the histogram is a multiset count of recorded keys). On a same-hart,
/// same-bucket hand-off the waker's `Running` key becomes the woken task's
/// and vice versa, so both applies are skipped.
#[inline(always)]
pub fn pair_cancels(oa: u32, ob: u32, na: u32, nb: u32) -> bool {
    (oa == nb && ob == na) || (oa == na && ob == nb)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> DirectSwitch {
        DirectSwitch {
            ready_bitmap: 0,
            target_bucket: 10,
            target_affinity: -1,
            cpu: 0,
            target_is_idle: false,
            current_is_idle: false,
            deadline_live: false,
            aps: false,
            target_saved: true,
        }
    }

    /// The target blocked on another hart and that hart has not finished
    /// saving its registers: switching to it would resume a half-saved
    /// context. Must refuse (the ordinary wake + `do_schedule` spin gate
    /// handles it).
    #[test]
    fn target_still_saving_refuses() {
        assert!(!allowed(DirectSwitch { target_saved: false, ..base() }));
    }

    #[test]
    fn empty_queue_allows() {
        assert!(allowed(base()));
    }

    #[test]
    fn only_worse_priority_queued_allows() {
        // idle (31) and a background task (20) queued: target at 10 wins.
        let s = DirectSwitch { ready_bitmap: (1 << 31) | (1 << 20), ..base() };
        assert!(allowed(s));
    }

    /// RFC-0031 lease priority inheritance: the lessee was boosted into a
    /// better bucket than the fast-IPC server being woken. `do_schedule` would
    /// dispatch the boosted lessee first, so the direct switch must refuse.
    #[test]
    fn boosted_lessee_in_better_bucket_refuses() {
        let s = DirectSwitch { ready_bitmap: 1 << 3, ..base() };
        assert!(!allowed(s));
    }

    /// FIFO within a bucket: an equal-priority task queued earlier is dequeued
    /// before a target enqueued behind it.
    #[test]
    fn equal_priority_queued_refuses() {
        let s = DirectSwitch { ready_bitmap: 1 << 10, ..base() };
        assert!(!allowed(s));
    }

    #[test]
    fn every_bucket_at_or_above_refuses_and_every_bucket_below_allows() {
        for t in 0..BITMAP_BUCKETS {
            for q in 0..BITMAP_BUCKETS {
                let s = DirectSwitch { ready_bitmap: 1 << q, target_bucket: t, ..base() };
                assert_eq!(allowed(s), q > t, "target bucket {t}, queued bucket {q}");
            }
        }
    }

    #[test]
    fn pinned_elsewhere_refuses_pinned_here_allows() {
        assert!(!allowed(DirectSwitch { target_affinity: 2, cpu: 1, ..base() }));
        assert!(allowed(DirectSwitch { target_affinity: 1, cpu: 1, ..base() }));
    }

    #[test]
    fn deadline_aps_and_idle_refuse() {
        assert!(!allowed(DirectSwitch { deadline_live: true, ..base() }));
        assert!(!allowed(DirectSwitch { aps: true, ..base() }));
        assert!(!allowed(DirectSwitch { target_is_idle: true, ..base() }));
        assert!(!allowed(DirectSwitch { current_is_idle: true, ..base() }));
    }

    /// `pair_cancels` is sound against the real histogram: whenever it says
    /// "skip", applying both deltas leaves every `(cpu, bucket)` load as it
    /// was; and it says "skip" for the same-hart hand-off it exists for.
    #[test]
    fn pair_cancels_only_when_the_two_applies_are_a_no_op() {
        use super::super::resident_histogram::{key, ResidentHistogram, MAX_CPUS};
        let keys: Vec<u32> = {
            let mut v = vec![key::NONE];
            for cpu in 0..2 { for b in [3usize, 10, 31] { for c in [false, true] {
                v.push(key::pack(cpu, b, c));
            } } }
            v
        };
        let snapshot = |h: &ResidentHistogram| -> Vec<_> {
            let mut out = Vec::new();
            for cpu in 0..MAX_CPUS { for b in 0..BITMAP_BUCKETS { out.push(h.load(cpu, b, 8)); } }
            out
        };
        let mut skipped = 0;
        for &oa in &keys { for &ob in &keys { for &na in &keys { for &nb in &keys {
            if !pair_cancels(oa, ob, na, nb) { continue; }
            skipped += 1;
            let h = ResidentHistogram::new();
            h.apply(key::NONE, oa);
            h.apply(key::NONE, ob);
            let before = snapshot(&h);
            h.apply(oa, na);
            h.apply(ob, nb);
            assert_eq!(snapshot(&h), before, "skip claimed for {oa:#x},{ob:#x} -> {na:#x},{nb:#x}");
        } } } }
        assert!(skipped > 0);
        // The hand-off itself: waker Running->Blocked, woken Blocked->Running,
        // same hart, same bucket.
        let (run, blk) = (key::pack(1, 10, true), key::pack(1, 10, false));
        assert!(pair_cancels(run, blk, blk, run));
        // Different buckets: the deltas do not cancel.
        assert!(!pair_cancels(run, key::pack(1, 11, false), blk, key::pack(1, 11, true)));
    }
}
