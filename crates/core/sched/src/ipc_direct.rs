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
//! * SCHED-RT state on the hart, or a band task on either side — the class walk
//!   decides and the dispatch tail charges the band and the reservations;
//! * the target pinned to another hart — the ordinary wake would send it there;
//! * either task at `IDLE_PRIORITY` — `do_schedule` programs the tickless
//!   timer on a switch to or from idle, which this path does not replicate;
//! * **any task queued on `cpu` besides its idle task.** The fair class
//!   orders its tasks by EEVDF virtual deadline, not by bucket, so a queued
//!   fair task of any priority may come before the target (model
//!   `formal/tla/sched_dispatch.tla`, `bucket-rule` mutation: the old bucket
//!   test let a worse-bucket task with an earlier deadline wait behind a
//!   direct switch), and a band task or a boosted owner beats it outright.
//!   With only the idle task queued the class walk certainly takes the target
//!   (`would_pick`); anything else is refused, never guessed.

/// Number of priority buckets the per-CPU `ready_bitmap` (a `u32`) carries.
/// Pinned to `task::NUM_PRIORITIES` by a const assert in `scheduler.rs`.
pub const BITMAP_BUCKETS: usize = 32;

/// Inputs of the rule, all read by the caller on the switching hart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectSwitch {
    /// `PER_CPU[cpu].ready_bitmap` without the idle level: bit `b` set =
    /// something queued at bucket `b`.
    pub queued: u32,
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
}

/// `true` only when `do_schedule` would certainly dispatch the target next.
#[inline(always)]
pub fn allowed(s: DirectSwitch) -> bool {
    if s.deadline_live || s.target_is_idle || s.current_is_idle {
        return false;
    }
    if s.target_affinity >= 0 && s.target_affinity as usize != s.cpu {
        return false;
    }
    s.queued == 0
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

/// The fast-IPC hand-off's own shape, readable from the two RECORDED keys
/// alone (Chain E, commit 3): the outgoing task `a` is recorded competing and
/// the incoming `b` recorded blocked, both on the same `(cpu, bucket)`. After
/// the hand-off (`a` Blocked, `b` Running, `b` homed here) their live keys
/// are exactly `(ob, oa)`, a pair [`pair_cancels`] skips, so the scheduler
/// can store the two keys crosswise without recomputing either key or
/// touching the histogram. Anything else (a migration, a priority change, a
/// zombie) fails this check and takes the full re-account.
pub fn handoff_swaps(oa: u32, ob: u32) -> bool {
    use super::resident_histogram::key;
    key::accounted(oa)
        && key::accounted(ob)
        && key::competes(oa)
        && !key::competes(ob)
        && key::cpu(oa) == key::cpu(ob)
        && key::bucket(oa) == key::bucket(ob)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> DirectSwitch {
        DirectSwitch {
            queued: 0,
            target_affinity: -1,
            cpu: 0,
            target_is_idle: false,
            current_is_idle: false,
            deadline_live: false,
        }
    }

    #[test]
    fn only_the_idle_task_queued_allows() {
        assert!(allowed(base()));
    }

    /// EEVDF orders fair tasks by virtual deadline, not by bucket: a queued
    /// task of any bucket may come first, so any queued task refuses (a
    /// boosted owner in a better bucket, an equal one queued earlier, and a
    /// worse-bucket one with an earlier deadline alike).
    #[test]
    fn any_queued_task_refuses() {
        for q in 0..BITMAP_BUCKETS {
            assert!(!allowed(DirectSwitch { queued: 1 << q, ..base() }), "queued bucket {q}");
        }
    }

    #[test]
    fn pinned_elsewhere_refuses_pinned_here_allows() {
        assert!(!allowed(DirectSwitch { target_affinity: 2, cpu: 1, ..base() }));
        assert!(allowed(DirectSwitch { target_affinity: 1, cpu: 1, ..base() }));
    }

    #[test]
    fn deadline_and_idle_refuse() {
        assert!(!allowed(DirectSwitch { deadline_live: true, ..base() }));
        assert!(!allowed(DirectSwitch { target_is_idle: true, ..base() }));
        assert!(!allowed(DirectSwitch { current_is_idle: true, ..base() }));
    }

    /// `pair_cancels` is sound against the real histogram: whenever it says
    /// "skip", applying both deltas leaves every `(cpu, bucket)` load as it
    /// was; and it says "skip" for the same-hart hand-off it exists for.
    /// `handoff_swaps` accepts exactly the competing/blocked twins of one
    /// `(cpu, bucket)`, and every pair it accepts is one `pair_cancels`
    /// skips with the keys swapped crosswise.
    #[test]
    fn handoff_swaps_only_the_same_slot_twins() {
        use super::super::resident_histogram::key;
        let mut keys = vec![key::NONE];
        for cpu in 0..3 { for b in [0usize, 3, 10, 31] { for c in [false, true] {
            keys.push(key::pack(cpu, b, c));
        } } }
        let mut accepted = 0;
        for &oa in &keys { for &ob in &keys {
            if !handoff_swaps(oa, ob) { continue; }
            accepted += 1;
            assert_eq!(oa, key::pack(key::cpu(ob), key::bucket(ob), true));
            assert_eq!(ob, key::pack(key::cpu(oa), key::bucket(oa), false));
            assert!(pair_cancels(oa, ob, ob, oa));
        } }
        assert_eq!(accepted, 3 * 4, "one accepted pair per (cpu, bucket)");
        assert!(!handoff_swaps(key::pack(0, 3, true), key::pack(1, 3, false)), "migration");
        assert!(!handoff_swaps(key::pack(0, 3, true), key::pack(0, 10, false)), "priority change");
        assert!(!handoff_swaps(key::pack(0, 3, false), key::pack(0, 3, true)), "reverse states");
        assert!(!handoff_swaps(key::NONE, key::pack(0, 3, false)), "unaccounted");
    }

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
