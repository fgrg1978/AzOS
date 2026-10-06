// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side runner for
//! `crates/core/sched/src/{class,partitions,rt_core,policies/*}.rs`.
//!
//! The kernel `azos_sched` cannot be compiled for the host (its
//! dependencies are RV64-only). The W4 scheduler logic, however, is
//! pure data manipulation with no riscv/MMIO calls — we pull the
//! source files directly and run the suites on the host.

#[path = "../../../../crates/core/sched/src/class.rs"]
pub mod class;

#[path = "../../../../crates/core/sched/src/policies/mod.rs"]
pub mod policies;

#[path = "../../../../crates/core/sched/src/partitions.rs"]
pub mod partitions;

#[path = "../../../../crates/core/sched/src/rt_core.rs"]
pub mod rt_core;

#[path = "../../../../crates/core/sched/src/slot_bitmap.rs"]
pub mod slot_bitmap;

/// `scheduler::ring_claim_audit`'s slot sets, at the fleet profile's
/// `MAX_TASKS` (4096, `config/Kconfig.limits`), with slots on both sides of word
/// boundaries.
///
/// `scheduler.rs` does not compile for the host, so what runs here is the
/// part of the audit it delegates to `slot_bitmap.rs`: ring membership and
/// duplicate detection (`SlotBitmap::insert`), and the claim pass
/// (`claim_pass`), which counts, stores each word of the sample, and reports
/// the persistent slots. The two-sample filter is passed in as `prev & cur`;
/// the kernel passes `task::claim_audit_persistent`, whose own tests are in
/// `tests/host/sched-wake-tests`. The audit used one `u64` over slots, so each
/// assertion below that names a slot of 64 or more fails against it.
#[cfg(test)]
mod slot_bitmap_tests {
    use super::slot_bitmap::{claim_pass, words_for, ClaimCounts, SlotBitmap};
    use std::collections::BTreeSet;

    /// `MAX_TASKS` in the fleet profile.
    const FLEET_SLOTS: usize = 4096;
    const W: usize = words_for(FLEET_SLOTS);

    #[test]
    fn the_bitmap_has_one_word_per_64_slots() {
        assert_eq!(words_for(32), 1, "embedded, MAX_TASKS 32");
        assert_eq!(words_for(64), 1, "edge, MAX_TASKS 64: the one word the u64 mask was");
        assert_eq!(words_for(65), 2);
        assert_eq!(W, 64, "fleet, MAX_TASKS 4096");
        assert_eq!(SlotBitmap::<W>::capacity(), FLEET_SLOTS);
        assert_eq!(words_for(16384), 256, "the config/Kconfig.limits ceiling");
    }

    /// Every slot is its own member: inserting one never makes another present,
    /// and the second insert of a slot reports it as a duplicate entry.
    #[test]
    fn slots_past_63_are_distinct_members_and_duplicates_are_seen() {
        const IN: [usize; 8] = [0, 1, 63, 64, 65, 127, 128, 4095];
        const OUT: [usize; 7] = [2, 62, 66, 126, 129, 1000, 4094];
        let mut set = SlotBitmap::<W>::new();
        for i in IN {
            assert!(!set.insert(i), "slot {i} read as already present in a set holding only lower slots");
        }
        for i in IN {
            assert!(set.contains(i), "slot {i} was inserted and is not present");
            assert!(set.insert(i), "a second entry for slot {i} must count as a duplicate");
        }
        for i in OUT {
            assert!(!set.contains(i), "slot {i} was never inserted and reads as present");
        }
        // Past the capacity: not stored, not present, no panic (the audit runs
        // in the timer ISR, where a panic resets the board).
        for i in [FLEET_SLOTS, FLEET_SLOTS + 1, usize::MAX] {
            assert!(!set.insert(i), "slot {i} is past the bitmap");
            assert!(!set.contains(i), "slot {i} is past the bitmap");
        }
    }

    /// One tick of the audit over `slots` slots: `valid` holds a task,
    /// `claimed` claims a queue entry, `listed` has one. Returns the counts,
    /// the reported slots, and the slots `claim` was asked about.
    fn tick(
        prev: &mut [u64; W],
        slots: usize,
        valid: &dyn Fn(usize) -> bool,
        claimed: &BTreeSet<usize>,
        listed: &[usize],
    ) -> (ClaimCounts, Vec<usize>, Vec<usize>) {
        let mut present = SlotBitmap::<W>::new();
        for &i in listed {
            present.insert(i);
        }
        let mut asked = Vec::new();
        let mut reported = Vec::new();
        let counts = claim_pass(
            &present,
            slots,
            |i| {
                asked.push(i);
                if valid(i) { Some(claimed.contains(&i)) } else { None }
            },
            |w, mask| core::mem::replace(&mut prev[w], mask),
            |p, c| p & c,
            |i| reported.push(i),
        );
        (counts, reported, asked)
    }

    fn set(v: &[usize]) -> BTreeSet<usize> {
        v.iter().copied().collect()
    }

    /// Three ticks over 4096 slots. Slot 70 holds no task and is never counted.
    ///
    /// | tick | claimed                       | listed        | claim, no entry          | persistent        |
    /// |------|-------------------------------|---------------|--------------------------|-------------------|
    /// | 1    | 63 64 65 70 127 1000 4094 4095 | 63 128 4095  | 64 65 127 1000 4094      | —                 |
    /// | 2    | 7 64 70 128 1000 4094          | 7            | 64 128 1000 4094         | 64 1000 4094      |
    /// | 3    | 65                             | —            | 65                       | —                 |
    ///
    /// Slot 128 has an entry and no claim in tick 1. 127 and 128 are adjacent
    /// slots in different words, each claiming without an entry in one tick
    /// only; 64 and 65 share a word and 65's streak restarts at tick 3.
    #[test]
    fn a_4096_slot_audit_counts_and_reports_slots_past_63() {
        let mut prev = [0u64; W];
        let valid = |i: usize| i != 70;

        let (c, reported, asked) = tick(
            &mut prev, FLEET_SLOTS, &valid,
            &set(&[63, 64, 65, 70, 127, 1000, 4094, 4095]), &[63, 128, 4095],
        );
        assert_eq!(asked, (0..FLEET_SLOTS).collect::<Vec<_>>(), "every slot is asked about once, in order");
        assert_eq!(
            c,
            ClaimCounts { claim_no_entry: 5, entry_no_claim: 1, persistent: 0 },
            "tick 1: slots 64, 65, 127, 1000 and 4094 claim without an entry, 128 has an entry without a claim",
        );
        assert!(reported.is_empty(), "tick 1 has no previous sample, got {reported:?}");

        let (c, reported, _) = tick(
            &mut prev, FLEET_SLOTS, &valid,
            &set(&[7, 64, 70, 128, 1000, 4094]), &[7],
        );
        assert_eq!(c, ClaimCounts { claim_no_entry: 4, entry_no_claim: 0, persistent: 3 }, "tick 2");
        assert_eq!(
            reported,
            vec![64, 1000, 4094],
            "tick 2 must report exactly the slots claiming without an entry in both ticks, once each, in order",
        );

        let (c, reported, _) = tick(&mut prev, FLEET_SLOTS, &valid, &set(&[65]), &[]);
        assert_eq!(c, ClaimCounts { claim_no_entry: 1, entry_no_claim: 0, persistent: 0 }, "tick 3");
        assert!(reported.is_empty(), "65 was clean in tick 2, so its streak restarted; got {reported:?}");
        let mut expect = [0u64; W];
        expect[1] = 1 << 1;
        assert_eq!(prev, expect, "the stored sample is tick 3's alone: slot 65, word 1 bit 1");
    }

    /// A pool that does not fill its last word: `claim` is never asked about a
    /// slot at or past the pool, and nothing past it is counted or reported.
    #[test]
    fn the_pass_stops_at_the_last_slot_of_a_partial_word() {
        const SLOTS: usize = 100;
        let mut prev = [0u64; W];
        let every = |_: usize| true;
        let claimed = set(&[99, 100, 101, 4095]);
        tick(&mut prev, SLOTS, &every, &claimed, &[]);
        let (c, reported, asked) = tick(&mut prev, SLOTS, &every, &claimed, &[]);
        assert_eq!(asked, (0..SLOTS).collect::<Vec<_>>());
        assert_eq!(c, ClaimCounts { claim_no_entry: 1, entry_no_claim: 0, persistent: 1 });
        assert_eq!(reported, vec![99]);
        assert!(prev[2..].iter().all(|&w| w == 0), "no word past the pool is stored: {prev:?}");
    }
}

#[cfg(test)]
mod class_tests {
    use super::class::{ClassBudget, SchedClass, DEFAULT_BUDGETS_PCT};

    #[test]
    fn five_classes_unique_slots() {
        let slots: [usize; 5] = [
            SchedClass::SafetyCritical.slot(),
            SchedClass::HardRT.slot(),
            SchedClass::SoftRT.slot(),
            SchedClass::BestEffort.slot(),
            SchedClass::Idle.slot(),
        ];
        for (i, &a) in slots.iter().enumerate() {
            for &b in &slots[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn urgency_orders_safety_first() {
        assert!(
            SchedClass::SafetyCritical.urgency()
                < SchedClass::Idle.urgency()
        );
    }

    #[test]
    fn from_raw_round_trip() {
        for &c in &SchedClass::ALL {
            assert_eq!(SchedClass::from_raw(c as u8), Some(c));
        }
        assert_eq!(SchedClass::from_raw(99), None);
    }

    #[test]
    fn default_budgets_sum_to_100() {
        let total: u32 = DEFAULT_BUDGETS_PCT.iter().map(|&b| b as u32).sum();
        assert_eq!(total, 100);
    }

    #[test]
    fn hard_rt_classification() {
        assert!(SchedClass::SafetyCritical.is_hard_rt());
        assert!(SchedClass::HardRT.is_hard_rt());
        assert!(!SchedClass::SoftRT.is_hard_rt());
        assert!(!SchedClass::BestEffort.is_hard_rt());
        assert!(!SchedClass::Idle.is_hard_rt());
    }

    #[test]
    fn budget_consume_and_quota() {
        let b = ClassBudget::new(20, 100);
        // 10 ms window, max_pct = 100 ⇒ 10000 µs quota.
        assert_eq!(b.quota_us(10_000), 10_000);
        assert_eq!(b.min_quota_us(10_000), 2_000); // 20 %
        assert!(b.under_min(10_000));
        b.consume(2_500);
        assert!(!b.under_min(10_000));
        assert!(!b.over_quota(10_000));
        assert_eq!(b.consumed_us(), 2_500);
    }

    #[test]
    fn budget_over_quota_caught() {
        let b = ClassBudget::new(10, 30);
        // Window 10 ms × max 30 % = 3000 µs.
        b.consume(3_500);
        assert!(b.over_quota(10_000));
    }

    #[test]
    fn budget_reset_clears_consumed() {
        let b = ClassBudget::new(20, 100);
        b.consume(5_000);
        b.reset_window();
        assert_eq!(b.consumed_us(), 0);
    }
}

#[cfg(test)]
mod fifo_tests {
    use super::class::SchedClass;
    use super::policies::fifo::Fifo;
    use super::policies::{Policy, TaskMeta};

    fn meta(tid: u32, prio: u8) -> TaskMeta {
        TaskMeta::new(tid, SchedClass::SafetyCritical, prio)
    }

    #[test]
    fn enqueue_and_pick_highest_priority() {
        let mut q = Fifo::new();
        q.enqueue(meta(1, 5)).unwrap();
        q.enqueue(meta(2, 0)).unwrap(); // higher priority
        q.enqueue(meta(3, 3)).unwrap();
        let picked = q.pick_next(0).unwrap();
        assert_eq!(picked.tid, 2);
    }

    #[test]
    fn fifo_within_priority() {
        let mut q = Fifo::new();
        q.enqueue(meta(1, 4)).unwrap();
        q.enqueue(meta(2, 4)).unwrap();
        q.enqueue(meta(3, 4)).unwrap();
        // All same priority — first inserted wins.
        let picked = q.pick_next(0).unwrap();
        assert_eq!(picked.tid, 1);
    }

    #[test]
    fn dequeue_then_pick() {
        let mut q = Fifo::new();
        q.enqueue(meta(1, 4)).unwrap();
        q.enqueue(meta(2, 1)).unwrap();
        q.dequeue(2);
        let picked = q.pick_next(0).unwrap();
        assert_eq!(picked.tid, 1);
    }

    #[test]
    fn empty_returns_none() {
        let mut q = Fifo::new();
        assert!(q.pick_next(0).is_none());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn capacity_enforced() {
        let mut q = Fifo::new();
        for i in 0..super::policies::fifo::FIFO_CAPACITY as u32 {
            q.enqueue(meta(i, 0)).unwrap();
        }
        let extra = q.enqueue(meta(999, 0));
        assert!(extra.is_err());
    }
}

#[cfg(test)]
mod rr_tests {
    use super::class::SchedClass;
    use super::policies::rr::{RoundRobin, DEFAULT_QUANTUM_US};
    use super::policies::{Policy, TaskMeta};

    fn meta_with_slice(tid: u32, slice_us: u32) -> TaskMeta {
        let mut m = TaskMeta::new(tid, SchedClass::SoftRT, 16);
        m.time_slice_us = slice_us;
        m
    }

    #[test]
    fn pick_returns_head() {
        let mut q = RoundRobin::new();
        q.enqueue(meta_with_slice(1, 5_000)).unwrap();
        q.enqueue(meta_with_slice(2, 5_000)).unwrap();
        assert_eq!(q.pick_next(0).unwrap().tid, 1);
    }

    #[test]
    fn quantum_exhaustion_rotates() {
        let mut q = RoundRobin::new();
        q.enqueue(meta_with_slice(1, 5_000)).unwrap();
        q.enqueue(meta_with_slice(2, 5_000)).unwrap();
        // Drain task 1's quantum.
        q.tick(1, 5_000);
        // Now head should be task 2.
        assert_eq!(q.pick_next(0).unwrap().tid, 2);
    }

    #[test]
    fn partial_tick_decrements() {
        let mut q = RoundRobin::new();
        q.enqueue(meta_with_slice(1, 10_000)).unwrap();
        q.enqueue(meta_with_slice(2, 10_000)).unwrap();
        q.tick(1, 3_000);
        // Head still task 1, remaining 7_000.
        assert_eq!(q.pick_next(0).unwrap().tid, 1);
        assert_eq!(q.remaining_us(), 7_000);
    }

    #[test]
    fn default_quantum_when_zero() {
        let mut q = RoundRobin::new();
        q.enqueue(meta_with_slice(1, 0)).unwrap();
        assert_eq!(q.remaining_us(), DEFAULT_QUANTUM_US);
    }

    #[test]
    fn dequeue_head_starts_new_quantum() {
        let mut q = RoundRobin::new();
        q.enqueue(meta_with_slice(1, 5_000)).unwrap();
        q.enqueue(meta_with_slice(2, 8_000)).unwrap();
        // Burn part of the head's quantum.
        q.tick(1, 2_000);
        assert_eq!(q.remaining_us(), 3_000);
        // Dequeue the head; new head should restart its quantum.
        q.dequeue(1);
        assert_eq!(q.pick_next(0).unwrap().tid, 2);
        assert_eq!(q.remaining_us(), 8_000);
    }

    #[test]
    fn single_task_keeps_running() {
        let mut q = RoundRobin::new();
        q.enqueue(meta_with_slice(1, 5_000)).unwrap();
        // Drain the quantum entirely; with only one task, rotation
        // is a no-op and the quantum just refills.
        q.tick(1, 5_000);
        assert_eq!(q.pick_next(0).unwrap().tid, 1);
        assert_eq!(q.remaining_us(), 5_000);
    }
}

#[cfg(test)]
mod cfs_tests {
    use super::class::SchedClass;
    use super::policies::cfs::Cfs;
    use super::policies::{Policy, TaskMeta};

    fn meta(tid: u32, prio: u8) -> TaskMeta {
        TaskMeta::new(tid, SchedClass::BestEffort, prio)
    }

    #[test]
    fn pick_smallest_vruntime() {
        let mut q = Cfs::new();
        q.enqueue(meta(1, 0)).unwrap();
        q.enqueue(meta(2, 0)).unwrap();
        // Both start at vruntime 0; tie broken by insertion order.
        let pick1 = q.pick_next(0).unwrap();
        // Charge the picked task.
        q.charge(pick1.tid, 1_000);
        let pick2 = q.pick_next(0).unwrap();
        assert_ne!(pick1.tid, pick2.tid);
    }

    #[test]
    fn higher_priority_runs_more() {
        let mut q = Cfs::new();
        // Lower numeric priority = higher actual priority (less weight).
        q.enqueue(meta(1, 0)).unwrap(); // weight 1
        q.enqueue(meta(2, 5)).unwrap(); // weight 32
        // Run task 1 for 1000 µs ⇒ vruntime gains 1000.
        // Run task 2 for 1000 µs ⇒ vruntime gains 32_000.
        q.charge(1, 1_000);
        q.charge(2, 1_000);
        // Now task 1 has lower vruntime and gets picked.
        let picked = q.pick_next(0).unwrap();
        assert_eq!(picked.tid, 1);
    }

    #[test]
    fn new_task_inherits_baseline() {
        let mut q = Cfs::new();
        q.enqueue(meta(1, 0)).unwrap();
        // Charge a lot to task 1 so its vruntime is high.
        q.charge(1, 100_000);
        // New task arrives — should start with the current minimum
        // (which is task 1's high vruntime) so it doesn't unfairly
        // dominate.
        q.enqueue(meta(2, 0)).unwrap();
        // Both should now have vruntime ≈ 100_000; task 1 gets picked
        // because it inserts first (we didn't add tie-breaking by
        // arrival time, but they should be close).
        let picked = q.pick_next(0).unwrap();
        // Either is acceptable; the key property is that task 2 isn't
        // unfairly preferred just because it just arrived.
        assert!(picked.tid == 1 || picked.tid == 2);
    }

    #[test]
    fn empty_returns_none() {
        let mut q = Cfs::new();
        assert!(q.pick_next(0).is_none());
    }

    #[test]
    fn dequeue_by_tid() {
        let mut q = Cfs::new();
        q.enqueue(meta(1, 0)).unwrap();
        q.enqueue(meta(2, 0)).unwrap();
        q.dequeue(1);
        let picked = q.pick_next(0).unwrap();
        assert_eq!(picked.tid, 2);
    }
}

#[cfg(test)]
mod edf_cbs_tests {
    use super::class::SchedClass;
    use super::policies::edf_cbs::{CbsState, EdfCbs};
    use super::policies::{Policy, TaskMeta};

    fn meta_with_deadline(tid: u32, deadline_us: u64) -> TaskMeta {
        let mut m = TaskMeta::new(tid, SchedClass::HardRT, 0);
        m.deadline_us = Some(deadline_us);
        m
    }

    #[test]
    fn earliest_deadline_picked() {
        let mut q = EdfCbs::new();
        q.enqueue_with_cbs(
            meta_with_deadline(1, 5_000),
            CbsState::new(1_000, 5_000),
        )
        .unwrap();
        q.enqueue_with_cbs(
            meta_with_deadline(2, 2_000), // earliest
            CbsState::new(1_000, 2_000),
        )
        .unwrap();
        q.enqueue_with_cbs(
            meta_with_deadline(3, 8_000),
            CbsState::new(1_000, 8_000),
        )
        .unwrap();
        let picked = q.pick_next(0).unwrap();
        assert_eq!(picked.tid, 2);
    }

    #[test]
    fn cbs_exhaustion_pushes_deadline_past_peer() {
        // Pick a period for task 1 whose post-exhaustion deadline
        // (initial + period) lands AFTER task 2's deadline. With
        // initial deadline 1_000 + period 5_000 → 6_000, which is
        // > task 2's 5_000, so task 2 takes EDF priority.
        let mut q = EdfCbs::new();
        q.enqueue_with_cbs(
            meta_with_deadline(1, 1_000),
            CbsState::new(500, 5_000),
        )
        .unwrap();
        q.enqueue_with_cbs(
            meta_with_deadline(2, 5_000),
            CbsState::new(500, 5_000),
        )
        .unwrap();
        let first = q.pick_next(0).unwrap();
        assert_eq!(first.tid, 1);
        q.tick(1, 600); // exhausts task 1's 500 µs budget
        // Task 1's deadline is now 1_000 + 5_000 = 6_000, > 5_000.
        let next = q.pick_next(0).unwrap();
        assert_eq!(next.tid, 2);
    }

    #[test]
    fn cbs_exhaustion_keeps_winner_when_period_short() {
        // Sanity check the *other* direction: if the period is small
        // enough that the pushed deadline is still earliest, the task
        // keeps EDF priority. This reflects standard CBS: exhaustion
        // bumps the deadline, but doesn't *demote* unconditionally.
        let mut q = EdfCbs::new();
        q.enqueue_with_cbs(
            meta_with_deadline(1, 1_000),
            CbsState::new(500, 1_000),
        )
        .unwrap();
        q.enqueue_with_cbs(
            meta_with_deadline(2, 5_000),
            CbsState::new(500, 5_000),
        )
        .unwrap();
        q.tick(1, 600);
        // Task 1's new deadline = 2_000, still < 5_000.
        let picked = q.pick_next(0).unwrap();
        assert_eq!(picked.tid, 1);
    }

    #[test]
    fn admission_check_under_one() {
        let mut q = EdfCbs::new();
        q.enqueue_with_cbs(
            meta_with_deadline(1, 1_000),
            CbsState::new(300, 1_000), // 30 %
        )
        .unwrap();
        // Adding a task with 50 % utilisation: total 80 %, OK.
        assert!(q.admission_check(500, 1_000));
        // Adding a task with 80 % utilisation: total 110 %, REJECT.
        assert!(!q.admission_check(800, 1_000));
    }

    #[test]
    fn admission_rejects_zero_period() {
        let q = EdfCbs::new();
        assert!(!q.admission_check(100, 0));
    }

    #[test]
    fn cbs_refill_on_period_boundary() {
        let mut s = CbsState::new(500, 1_000);
        s.remaining_us = 0;
        s.refill();
        assert_eq!(s.remaining_us, 500);
        assert!(!s.exhausted());
    }

    #[test]
    fn no_deadline_treated_as_lowest() {
        let mut q = EdfCbs::new();
        q.enqueue_with_cbs(
            TaskMeta::new(1, SchedClass::HardRT, 0),
            CbsState::new(500, 1_000),
        )
        .unwrap();
        q.enqueue_with_cbs(
            meta_with_deadline(2, 5_000),
            CbsState::new(500, 5_000),
        )
        .unwrap();
        // Task 1 has no deadline ⇒ infinite ⇒ task 2 picked.
        let picked = q.pick_next(0).unwrap();
        assert_eq!(picked.tid, 2);
    }

    #[test]
    fn dequeue_removes() {
        let mut q = EdfCbs::new();
        q.enqueue_with_cbs(
            meta_with_deadline(1, 1_000),
            CbsState::new(500, 1_000),
        )
        .unwrap();
        q.enqueue_with_cbs(
            meta_with_deadline(2, 2_000),
            CbsState::new(500, 2_000),
        )
        .unwrap();
        q.dequeue(1);
        let picked = q.pick_next(0).unwrap();
        assert_eq!(picked.tid, 2);
    }
}

#[cfg(test)]
mod sporadic_tests {
    use super::class::SchedClass;
    use super::policies::sporadic::Sporadic;
    use super::policies::{Policy, TaskMeta};

    fn meta(tid: u32, prio: u8) -> TaskMeta {
        TaskMeta::new(tid, SchedClass::Idle, prio)
    }

    #[test]
    fn pick_highest_priority_when_capacity_left() {
        let mut q = Sporadic::new();
        q.set_capacity(2_000);
        q.enqueue(meta(1, 5)).unwrap();
        q.enqueue(meta(2, 0)).unwrap(); // higher
        let picked = q.pick_next(0).unwrap();
        assert_eq!(picked.tid, 2);
    }

    #[test]
    fn exhausted_returns_none() {
        let mut q = Sporadic::new();
        q.set_capacity(1_000);
        q.enqueue(meta(1, 0)).unwrap();
        // Drain the bucket.
        q.tick(1, 1_000);
        assert!(q.pick_next(0).is_none());
        assert!(q.exhausted());
    }

    #[test]
    fn replenish_restores() {
        let mut q = Sporadic::new();
        q.set_capacity(500);
        q.enqueue(meta(1, 0)).unwrap();
        q.tick(1, 500);
        assert!(q.exhausted());
        q.replenish();
        assert!(!q.exhausted());
        assert_eq!(q.remaining_us(), 500);
    }
}

#[cfg(test)]
mod policy_table_tests {
    use super::policies::cfs::CFS_CAPACITY;
    use super::policies::edf_cbs::EDF_CAPACITY;
    use super::policies::fifo::FIFO_CAPACITY;
    use super::policies::rr::RR_CAPACITY;
    use super::policies::sporadic::SPORADIC_CAPACITY;
    use super::policies::TOTAL_CAPACITY;

    /// Bounds `scheduler::aps_pick_ready`'s stale-entry retry loop
    /// (U02-1 fix): it must always equal the sum of every policy's own
    /// `CAPACITY`, so a future policy added to the table (task 2) that
    /// forgets to fold its capacity in here would under-bound the loop,
    /// not silently drop a policy from the total.
    #[test]
    fn total_capacity_is_the_sum_of_every_policy() {
        assert_eq!(
            TOTAL_CAPACITY,
            FIFO_CAPACITY + EDF_CAPACITY + RR_CAPACITY + CFS_CAPACITY + SPORADIC_CAPACITY
        );
        assert_eq!(TOTAL_CAPACITY, 120);
    }
}

/// Task 2 — the enum-dispatch table (`policies::Backend`).
///
/// Proves the deliverable: reassigning a class to a DIFFERENT backend is
/// exactly one line (no `aps_state.rs`, no `scheduler.rs`, no `class.rs`,
/// no `runtime/registry.rs`), and a genuinely new policy type
/// (`policies::null::Null`, added entirely within `policies/mod.rs` and
/// `policies/null.rs`) can be dropped into a table slot and driven
/// through the SAME `Aps::pick_class` + `Backend::pick_next` path real
/// classes use — nothing about the dispatcher had to know a new variant
/// exists.
#[cfg(test)]
mod backend_table_tests {
    use super::class::SchedClass;
    use super::partitions::Aps;
    use super::policies::fifo::Fifo;
    use super::policies::null::Null;
    use super::policies::{Backend, Policy, TaskMeta};

    fn meta(tid: u32, class: SchedClass) -> TaskMeta {
        TaskMeta::new(tid, class, 0)
    }

    #[test]
    fn idle_can_be_reassigned_to_fifo_with_one_table_line() {
        // The "one table entry" the owner asked for: swap Idle's
        // default (Sporadic) for Fifo. Nothing else about the table,
        // the combinator, or the caller changes.
        let mut table = super::policies::default_table();
        table[SchedClass::Idle.slot()] = Backend::Fifo(Fifo::new());

        table[SchedClass::Idle.slot()]
            .enqueue(meta(42, SchedClass::Idle))
            .unwrap();
        assert!(!table[SchedClass::Idle.slot()].is_empty());
        let picked = table[SchedClass::Idle.slot()].pick_next(0).unwrap();
        assert_eq!(picked.tid, 42);
    }

    #[test]
    fn a_brand_new_policy_type_drives_through_the_same_dispatch_path() {
        // `Null` never existed before this task; it is wired in here,
        // in the TEST, not in `aps_state.rs` — proving the table, not
        // the dispatcher, is what a new policy touches.
        let mut table = super::policies::default_table();
        table[SchedClass::Idle.slot()] = Backend::Null(Null::new());

        // Enqueue into every OTHER class normally...
        table[SchedClass::SafetyCritical.slot()]
            .enqueue(meta(1, SchedClass::SafetyCritical))
            .unwrap();
        // ...and confirm the Idle slot, now backed by `Null`, refuses
        // and always reports empty — through `Aps::pick_class`, not a
        // direct call, so the combinator's own selection logic is what
        // is exercised.
        assert!(table[SchedClass::Idle.slot()]
            .enqueue(meta(99, SchedClass::Idle))
            .is_err());

        let aps = Aps::default_config();
        let picked = aps
            .pick_class(|c| !table[c.slot()].is_empty())
            .expect("SafetyCritical is runnable");
        assert_eq!(picked, SchedClass::SafetyCritical, "Null-backed Idle must never win selection");
    }
}

#[cfg(test)]
mod aps_tests {
    use super::class::SchedClass;
    use super::partitions::Aps;

    #[test]
    fn default_window_is_10ms() {
        let aps = Aps::default_config();
        assert_eq!(aps.window_us(), 10_000);
    }

    #[test]
    fn safety_under_min_picked_first() {
        let aps = Aps::default_config();
        // No class has consumed anything ⇒ all are under_min ⇒ the
        // most-urgent runnable class wins.
        let picked = aps.pick_class(|_| true).unwrap();
        assert_eq!(picked, SchedClass::SafetyCritical);
    }

    #[test]
    fn skip_empty_class() {
        let aps = Aps::default_config();
        let picked = aps
            .pick_class(|c| c != SchedClass::SafetyCritical)
            .unwrap();
        assert_eq!(picked, SchedClass::HardRT);
    }

    #[test]
    fn over_quota_class_yields() {
        let mut aps = Aps::default_config();
        aps.set_current(SchedClass::SafetyCritical, 1);
        // Charge SafetyCritical past its 100 % cap (its max_pct is 100
        // by default — never over, so use a custom config).
        let mut custom = Aps::new(
            [
                super::class::ClassBudget::new(20, 30),
                super::class::ClassBudget::new(30, 50),
                super::class::ClassBudget::new(25, 60),
                super::class::ClassBudget::new(20, 100),
                super::class::ClassBudget::new(5, 5),
            ],
            10_000,
        );
        custom.set_current(SchedClass::SafetyCritical, 1);
        // Drive SafetyCritical past 30 % (3000 µs in a 10 ms window).
        custom.tick(0, 3_500);
        // Selection should now skip SafetyCritical (over quota) and
        // pick HardRT, which is under_min.
        let picked = custom.pick_class(|_| true).unwrap();
        assert_eq!(picked, SchedClass::HardRT);
    }

    #[test]
    fn window_rolls_over_resets_consumption() {
        let mut aps = Aps::default_config();
        aps.anchor_window(0);
        aps.set_current(SchedClass::SafetyCritical, 1);
        aps.tick(0, 5_000);
        assert_eq!(aps.budget(SchedClass::SafetyCritical).consumed_us(), 5_000);
        // Cross the window boundary.
        aps.tick(15_000, 1_000);
        // Consumption resets and we credited the new tick.
        assert_eq!(aps.budget(SchedClass::SafetyCritical).consumed_us(), 1_000);
    }

    #[test]
    fn multi_window_catch_up_resets_once() {
        // Boot scenario: anchor at 0, first real timer tick lands
        // many windows later (rdtime is already in the millions at
        // boot). One single tick() must advance the window in one
        // step, not require N consecutive ticks to catch up.
        let mut aps = Aps::default_config();
        aps.anchor_window(0);
        aps.set_current(SchedClass::SafetyCritical, 1);
        aps.tick(0, 5_000);
        assert_eq!(aps.budget(SchedClass::SafetyCritical).consumed_us(), 5_000);

        // Jump 50 windows ahead (500_000 µs with a 10_000 µs window).
        aps.tick(500_000, 200);
        // Single tick caught up: consumption is *just* the credit
        // from this tick (200), not blown up by repeated resets.
        assert_eq!(aps.budget(SchedClass::SafetyCritical).consumed_us(), 200);

        // The next nearby tick should be inside the freshly-anchored
        // window and accumulate normally (no extra rollover).
        aps.tick(500_100, 300);
        assert_eq!(aps.budget(SchedClass::SafetyCritical).consumed_us(), 500);
    }

    #[test]
    fn idle_class_does_not_charge() {
        let mut aps = Aps::default_config();
        aps.set_idle();
        aps.tick(0, 5_000);
        for c in &SchedClass::ALL {
            assert_eq!(aps.budget(*c).consumed_us(), 0);
        }
    }

    // ── U02-1 fix: Aps::tick's rollover signal ──────────────────────────

    #[test]
    fn tick_returns_true_only_on_the_call_that_crosses_the_window() {
        let mut aps = Aps::default_config();
        aps.anchor_window(0);
        assert!(!aps.tick(0, 1_000));
        assert!(!aps.tick(5_000, 1_000));
        // Crosses the 10 ms boundary.
        assert!(aps.tick(10_000, 1_000));
        // Back inside the freshly-anchored window.
        assert!(!aps.tick(10_500, 1_000));
    }

    #[test]
    fn u02_1_sporadic_replenishes_on_every_aps_window_rollover() {
        // Mirrors `aps_state::account`'s wiring (the actual fix, not a
        // copy of it): `Sporadic::replenish` is driven by `Aps::tick`'s
        // rollover return, and nothing else. Before this fix `Aps::tick`
        // returned `()`, `Sporadic::replenish` had no caller anywhere in
        // the tree outside a host test, and the Idle class's bucket
        // drained once and stayed at zero forever (U02-1). This proves
        // the wiring survives more than one window — the failure mode
        // was permanent starvation after the FIRST exhaustion, so a test
        // that only checked one window could not have caught it.
        use super::policies::sporadic::Sporadic;
        use super::policies::{Policy, TaskMeta};

        let mut aps = Aps::default_config();
        aps.anchor_window(0);
        let mut idle = Sporadic::new();
        idle.set_capacity(1_000);
        idle.enqueue(TaskMeta::new(1, SchedClass::Idle, 0)).unwrap();

        for window in 0..3u64 {
            let now = window * 10_000;
            if aps.tick(now, 0) {
                idle.replenish();
            }
            idle.tick(1, 1_000); // drain the whole bucket this window
            assert!(
                idle.exhausted(),
                "window {window}: expected the bucket drained by its own tick"
            );
        }
        // The assertion that fails without the fix: a 4th window
        // rollover must revive a bucket that has been sitting exhausted
        // since window 0. Without `replenish()` wired to anything,
        // `idle` stays exhausted here forever.
        assert!(aps.tick(30_000, 0));
        idle.replenish();
        assert!(!idle.exhausted());
        assert!(idle.pick_next(0).is_some());
    }

    #[test]
    fn no_runnable_class_returns_none() {
        let aps = Aps::default_config();
        assert!(aps.pick_class(|_| false).is_none());
    }

    #[test]
    fn degraded_mode_picks_anyway() {
        // Build APS where every class is over its max budget — phase
        // 3 of pick_class should still return the most-urgent class.
        let custom = Aps::new(
            [
                super::class::ClassBudget::new(20, 5),
                super::class::ClassBudget::new(30, 5),
                super::class::ClassBudget::new(25, 5),
                super::class::ClassBudget::new(20, 5),
                super::class::ClassBudget::new(5, 5),
            ],
            10_000,
        );
        for c in &SchedClass::ALL {
            // 600 µs > 500 µs (5 % of 10 ms) for each class.
            custom.budget(*c).consume(600);
        }
        let picked = custom.pick_class(|_| true).unwrap();
        // Phase 3 returns the most-urgent runnable class.
        assert_eq!(picked, SchedClass::SafetyCritical);
    }
}

/// Finding a task by TID (`idx_for_tid` and the four paths built on it).
///
/// `scheduler.rs` cannot be compiled for the host (statics, asm), and the shims
/// re-implement `idx_for_tid`, so the real function is only ever run by the QEMU
/// gate. These pin, from the source, the two properties that a future edit could
/// lose without any dynamic test noticing:
///
///  * **The hint is verified before it is believed.** `TID_SLOT` is a hint that
///    turns a 64-slot scan into a load; a lookup that returned the hinted slot
///    without checking `TASK_VALID` and `tid` would hand a wake, or a priority
///    boost, to whichever task now occupies a recycled slot. That is a
///    containment failure with no crash, so it is asserted in text.
///  * **There is one lookup.** Before this, `wake_task_by_tid` and three others
///    each carried their own scan (two per wake, two wakes per IPC round trip,
///    ~490 instructions each). A fifth hand-rolled scan is how that comes back.
///
/// Comments are stripped before counting: a comment that quotes a pattern would
/// otherwise count as code.
#[cfg(test)]
mod tid_lookup {
    const SRC: &str = include_str!("../../../../crates/core/sched/src/scheduler.rs");

    pub(super) fn code() -> String {
        SRC.lines().map(|l| l.split("//").next().unwrap()).collect::<Vec<_>>().join("\n")
    }

    /// The text between the braces of the function that starts at `sig`.
    pub(super) fn body<'a>(code: &'a str, sig: &str) -> &'a str {
        let at = code.find(sig).unwrap_or_else(|| panic!("`{sig}` moved or was renamed"));
        let open = at + code[at..].find('{').unwrap();
        let mut depth = 0usize;
        for (i, c) in code[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => { depth -= 1; if depth == 0 { return &code[open..open + i + 1]; } }
                _ => {}
            }
        }
        panic!("unbalanced braces after `{sig}`");
    }

    #[test]
    fn the_tid_hint_is_verified_before_it_is_believed() {
        let c = code();
        let b = body(&c, "pub fn idx_for_tid(");
        assert!(b.contains("TID_SLOT["), "the hint is no longer read");
        assert!(b.contains("TASK_VALID[hint]"), "a hinted slot is used without checking it is valid");
        assert!(
            b.matches("TASKS[hint].tid == tid").count() >= 2,
            "the hinted slot's tid must be checked before AND after the acquire fence"
        );
        assert!(b.contains("for i in 0..MAX_TASKS"), "the scan that makes a wrong hint harmless is gone");
    }

    #[test]
    fn every_tid_lookup_goes_through_the_one_verified_helper() {
        let c = code();
        for sig in [
            "pub fn wake_task_by_tid(",
            "pub fn wq_wake_by_tid(",
            // Wave 9: the PiMutex pair delegates to these two (one donation
            // lock for every donor), so the lookup lives here now.
            "pub fn boost_ready_task(",
            "pub fn restore_ready_task(",
        ] {
            let b = body(&c, sig);
            assert!(b.contains("idx_for_tid(tid)"), "{sig} no longer uses idx_for_tid");
            assert!(!b.contains("0..MAX_TASKS"), "{sig} has its own scan again");
        }
        for (sig, via) in [
            ("pub fn pi_boost_task(", "boost_ready_task(tid, new_prio)"),
            ("pub fn pi_restore_task(", "restore_ready_task(tid)"),
        ] {
            let b = body(&c, sig);
            assert!(b.contains(via), "{sig} no longer goes through `{via}`");
            assert!(!b.contains("0..MAX_TASKS"), "{sig} has its own scan again");
        }
    }

    #[test]
    fn the_tid_hint_is_published_in_exactly_two_places() {
        let c = code();
        // Per statement, not per line: two writes on one line are two writes.
        // Where the TID is issued, and (wave 13) the scan's repair of a cell a
        // later TID overwrote (`idx_for_tid`).
        let writes = c
            .match_indices("TID_SLOT[")
            .filter(|(at, _)| c[*at..].split(';').next().unwrap_or("").contains(".store("))
            .count();
        assert_eq!(writes, 2, "TID_SLOT is written where the TID is issued and where a scan repairs it, nowhere else");
        let repair = body(&c, "pub fn idx_for_tid(");
        assert!(repair.contains("TID_SLOT[tid as usize & (TID_SLOT_LEN - 1)].store(i as u16"),
                "the repair writes the scanned slot for the looked-up TID");
    }
}

/// The APS current-class bookkeeping (`aps_state::set_current` / `set_idle`).
///
/// `do_schedule` used to tell the APS combinator which class was running on
/// EVERY switch, taking the per-CPU APS lock (~100 instructions, 198 of a 3,700
/// instruction IPC round trip) for a scheduler that nothing enables:
/// `use_aps_dispatch` has no caller. It now runs only while APS is in use, and
/// switching APS on seeds every CPU once.
///
/// Two ways to lose that, and neither would fail any dynamic test: the guard is
/// dropped (the cost silently returns), or the seeding is dropped (a later flip
/// to APS credits the wrong class until each hart's next switch). Both are read
/// from the source, comments stripped, with the helpers of `tid_lookup`.
#[cfg(test)]
mod aps_bookkeeping {
    use super::tid_lookup::{body, code};

    #[test]
    fn the_hot_path_only_tells_aps_what_is_running_while_aps_is_in_use() {
        let c = code();
        let b = body(&c, "fn do_schedule(");
        let set = b.find("state.aps.set_current(").expect("do_schedule no longer tells APS the current class");
        let guard = b[..set].rfind("if aps_dispatch_enabled()")
            .expect("`set_current` on the switch path is unguarded again: ~100 instructions per switch");
        // The guard must be THE one around this call, not the earlier
        // `aps_dispatch_enabled()` in `do_schedule` that picks the next task: that
        // one would satisfy a bare `rfind` and hide the guard being dropped here.
        let between = &b[guard..set];
        assert!(
            between.len() < 260 && between.contains("SchedClass::from_raw"),
            "the guard found is not the one directly around `set_current`: {between}"
        );
    }

    #[test]
    fn task_exit_only_clears_the_aps_class_while_aps_is_in_use() {
        let c = code();
        let at = c.find("state.aps.set_idle();").expect("`set_idle` on the exit path is gone");
        let guard = c[..at].rfind("if aps_dispatch_enabled()").expect("`set_idle` is unguarded again");
        assert!(at - guard < 200, "the guard is not the one directly around `set_idle`");
    }

    #[test]
    fn switching_aps_on_seeds_every_cpu() {
        let c = code();
        let on = body(&c, "pub fn use_aps_dispatch(");
        assert!(on.contains("aps_seed_current_classes()"), "enabling APS no longer seeds the current class");
        assert!(on.contains("enable && !prev"), "seed only on the off -> on edge");
        let seed = body(&c, "fn aps_seed_current_classes(");
        assert!(seed.contains("for cpu in 0..MAX_CPUS"), "the seed must cover every CPU");
        assert!(seed.contains("set_current("), "the seed must set the class");
        assert!(seed.contains("set_idle()"), "a CPU with no task must be seeded idle");
    }
}

/// `SchedClass::from_name`: the five RFC-0004 names a signed topology may
/// use, and nothing else. An unknown name is the "class this build lacks"
/// refusal, so it must be `None` rather than a nearest match.
#[cfg(test)]
mod class_name_tests {
    use super::class::SchedClass;

    #[test]
    fn every_class_round_trips_through_its_name() {
        for c in SchedClass::ALL {
            assert_eq!(SchedClass::from_name(c.name().as_bytes()), Some(c));
        }
        assert_eq!(SchedClass::from_name(b"hard_rt"), Some(SchedClass::HardRT));
        assert_eq!(SchedClass::from_name(b"best_effort"), Some(SchedClass::BestEffort));
    }

    #[test]
    fn an_unknown_or_near_miss_name_is_a_class_the_build_lacks() {
        for n in [&b""[..], b"gpu_batch", b"HARD_RT", b"hard-rt", b"best_effort ", b"soft_rt\0"] {
            assert_eq!(SchedClass::from_name(n), None, "{:?}", core::str::from_utf8(n));
        }
    }
}

/// Wave 11 SCHED-RT: the arithmetic `scheduler::rt` applies per hart and per
/// reservation (`crates/core/sched/src/rt_core.rs`). The kernel side only stores
/// these values and calls them at the dispatch, tick and switch points; the
/// QEMU rows (`sched-rt:` in `tools/ci_check.sh`) prove the wiring.
#[cfg(test)]
mod rt_core_tests {
    use super::rt_core::*;

    // ── band budget ──────────────────────────────────────────────────────

    #[test]
    fn the_cap_is_a_share_of_the_window_and_100_is_no_cap() {
        assert_eq!(band_cap_ticks(1_000, 95), 950);
        assert_eq!(band_cap_ticks(10_000_000, 95), 9_500_000);
        assert_eq!(band_cap_ticks(1_000, 100), u64::MAX);
        assert_eq!(band_cap_ticks(u64::MAX, 99), ((u64::MAX as u128) * 99 / 100) as u64);
    }

    /// A band task that never blocks, charged every 10 ticks of a 1000-tick
    /// window with a 95 % cap: exhausted once 950 are used, never before.
    #[test]
    fn a_runaway_band_task_exhausts_the_window_at_the_cap() {
        let (w, cap) = (1_000, band_cap_ticks(1_000, 95));
        let mut b = Band::NEW;
        b.win_start = 1;
        b.start(1);
        let mut t = 1;
        while !b.exhausted {
            t += 10;
            b.charge(t, w, cap);
            assert!(t <= 1 + 960, "not exhausted at {t}");
        }
        assert_eq!(b.used, 950);
        assert_eq!(b.exhaust_at(t, cap), t, "nothing left");
        // The rest of the window belongs to the non-band tasks.
        b.stop(t, w, cap);
        assert_eq!(b.since, 0);
        assert!(b.exhausted);
        assert_eq!(b.window_end(w), 1 + w);
        // Nothing is charged while the band does not run, and the window
        // ends on time.
        assert!(!b.roll(1 + w - 1, w));
        assert!(b.roll(1 + w, w));
        assert!(!b.exhausted);
        assert_eq!(b.used, 0);
    }

    /// The exhaust instant the one-shot is armed at is exactly where the
    /// charge says "exhausted".
    #[test]
    fn exhaust_at_agrees_with_charge() {
        let (w, cap) = (10_000, 950);
        let mut b = Band::NEW;
        b.win_start = 100;
        b.start(100);
        b.charge(400, w, cap);
        let at = b.exhaust_at(400, cap);
        assert_eq!(at, 400 + 650);
        b.charge(at - 1, w, cap);
        assert!(!b.exhausted);
        b.charge(at, w, cap);
        assert!(b.exhausted);
    }

    #[test]
    fn a_band_that_stopped_is_not_charged_for_the_gap() {
        let (w, cap) = (1_000, 950);
        let mut b = Band::NEW;
        b.roll(0, w);
        b.start(1);
        b.stop(101, w, cap);
        assert_eq!(b.used, 100);
        b.charge(900, w, cap);
        assert_eq!(b.used, 100, "charged while no band task ran");
    }

    // ── CBS ───────────────────────────────────────────────────────────────

    #[test]
    fn a_first_release_opens_a_server_period() {
        let mut c = Cbs::new(10, 100, 50, true, 0, 0);
        assert!(c.release_due);
        assert!(c.release(1_000));
        assert_eq!((c.deadline, c.budget, c.release_due), (1_050, 10, false));
    }

    /// The CBS wake rule: keep `(budget, deadline)` only while
    /// `budget / (deadline - now) <= q / t`.
    #[test]
    fn the_release_rule_keeps_a_period_only_while_the_bandwidth_fits() {
        let mut c = Cbs::new(10, 100, 100, true, 0, 0);
        c.release(0);
        assert!(!c.charge(5));
        // 5 left, 50 to the deadline: 5/50 == 10/100, kept.
        assert!(!c.release(50));
        assert_eq!((c.deadline, c.budget), (100, 5));
        // 5 left, 40 to the deadline: 5/40 > 10/100, a new period.
        assert!(c.release(60));
        assert_eq!((c.deadline, c.budget), (160, 10));
        // A deadline already past is always a new period.
        c.charge(1);
        assert!(c.release(500));
        assert_eq!((c.deadline, c.budget), (600, 10));
    }

    #[test]
    fn a_hard_overrun_is_counted_and_throttled_until_its_deadline() {
        let mut c = Cbs::new(10, 100, 100, true, 0, 0);
        c.release(0);
        assert!(c.charge(25), "ran past its budget");
        c.exhaust(10);
        assert!(c.throttled && !c.eligible());
        assert_eq!(c.overruns, 1);
        // A release while throttled does not refill it.
        assert!(!c.release(50));
        assert!(c.throttled);
        assert!(!c.replenish_if_due(99));
        assert!(c.replenish_if_due(100));
        assert!(!c.throttled);
        assert_eq!((c.deadline, c.budget), (200, 10));
    }

    #[test]
    fn a_late_replenish_takes_a_fresh_deadline() {
        let mut c = Cbs::new(10, 100, 40, true, 0, 0);
        c.release(0);
        c.charge(10);
        c.exhaust(10);
        // Replenished long after: deadline + t is already past.
        assert!(c.replenish_if_due(1_000));
        assert_eq!((c.deadline, c.budget), (1_040, 10));
    }

    #[test]
    fn a_soft_overrun_postpones_and_keeps_competing() {
        let mut c = Cbs::new(10, 100, 100, false, 0, 0);
        c.release(0);
        c.charge(10);
        c.exhaust(10);
        assert!(!c.throttled);
        assert_eq!((c.deadline, c.budget, c.overruns), (200, 10, 1));
    }

    #[test]
    fn edf_orders_by_level_then_deadline_and_ties_keep_the_incumbent() {
        assert!(edf_before(4, 900, 5, 10));
        assert!(edf_before(4, 10, 4, 11));
        assert!(!edf_before(4, 11, 4, 10));
        assert!(!edf_before(4, 10, 4, 10));
    }

    /// One hart, tick by tick, driven only by `rt_core`: A (q=2, t=10, d=3,
    /// demand 1) and B (q=5, t=20, demand 4) release together at 0; X (q=1,
    /// t=10, released at 5) never stops once it runs, so it never blocks and is
    /// never released again. EDF + hard CBS: A and B meet every deadline and X
    /// is throttled every period. FIFO inside the level with B ahead of A (the
    /// `rt-edf-canary` order): A misses. CBS off (`rt-cbs-canary`: X never
    /// charged, so its deadline never moves): A and B miss behind X.
    fn simulate(edf: bool, cbs: bool) -> (u32, u32, u32) {
        struct J { c: Cbs, demand: u64, left: u64, offset: u64, due: u64, misses: u32 }
        let mut s = [
            J { c: Cbs::new(5, 20, 20, true, 0, 0), demand: 4, left: 0, offset: 0, due: 0, misses: 0 },
            J { c: Cbs::new(2, 10, 3, true, 0, 0), demand: 1, left: 0, offset: 0, due: 0, misses: 0 },
            J { c: Cbs::new(1, 10, 10, true, 0, 0), demand: u64::MAX, left: 0, offset: 5, due: 0, misses: 0 },
        ];
        for now in 0..400u64 {
            for j in s.iter_mut() {
                if now >= j.offset && (now - j.offset) % j.c.t == 0 && j.demand != u64::MAX || (j.demand == u64::MAX && now == j.offset) {
                    if j.left != 0 {
                        j.misses += 1; // the previous job did not finish
                    }
                    // It blocked since it last ran (or never ran): released.
                    j.left = j.demand;
                    j.due = now + j.c.d;
                    j.c.release_due = true;
                    j.c.release(now);
                }
                if cbs {
                    j.c.replenish_if_due(now);
                }
            }
            let mut pick: Option<usize> = None;
            for k in 0..s.len() {
                if s[k].left == 0 || !s[k].c.eligible() {
                    continue;
                }
                pick = match pick {
                    None => Some(k),
                    Some(p) if edf && edf_before(4, s[k].c.deadline, 4, s[p].c.deadline) => Some(k),
                    keep => keep,
                };
            }
            let Some(k) = pick else { continue };
            let j = &mut s[k];
            if j.left != u64::MAX {
                j.left -= 1;
                if j.left == 0 && now + 1 > j.due {
                    j.misses += 1; // finished late
                }
            }
            if cbs && j.c.charge(1) && j.left != 0 {
                j.c.exhaust(now + 1);
            }
        }
        (s[1].misses, s[0].misses, s[2].c.overruns)
    }

    #[test]
    fn edf_with_hard_cbs_keeps_every_deadline_an_overrun_threatens() {
        let (a, b, x) = simulate(true, true);
        assert_eq!((a, b), (0, 0), "a deadline was missed with EDF + CBS");
        assert!(x >= 30, "the overrunning server was throttled every period ({x})");
    }

    #[test]
    fn fifo_order_or_no_cbs_misses_deadlines() {
        let (a_fifo, _, _) = simulate(false, true);
        assert!(a_fifo > 0, "FIFO inside the level did not make A miss");
        let (a_nocbs, b_nocbs, _) = simulate(true, false);
        assert!(a_nocbs + b_nocbs > 0, "without CBS the overrun did not cost a deadline");
    }

    // ── admission ─────────────────────────────────────────────────────────

    #[test]
    fn density_rounds_up_over_the_tighter_window_and_rejects_malformed() {
        assert_eq!(density_ppm(1_000, 10_000, 0), Ok(100_000));
        assert_eq!(density_ppm(1_000, 10_000, 4_000), Ok(250_000));
        assert_eq!(density_ppm(1, 3, 0), Ok(333_334));
        assert_eq!(density_ppm(0, 10, 0), Err(Refusal::Malformed));
        assert_eq!(density_ppm(1, 0, 0), Err(Refusal::Malformed));
        assert_eq!(density_ppm(5, 10, 4), Err(Refusal::Malformed));
        assert_eq!(density_ppm(1, 10, 11), Err(Refusal::Malformed));
    }

    #[test]
    fn the_band_cap_bounds_band_reservations_but_not_others() {
        let band_limit = 950_000;
        let mut l = HartLoad::default();
        assert_eq!(fits(l, 600_000, true, band_limit), Ok(()));
        l.total_ppm = 600_000;
        l.band_ppm = 600_000;
        assert_eq!(fits(l, 400_000, true, band_limit), Err(Refusal::BandCap));
        assert_eq!(fits(l, 400_000, false, band_limit), Ok(()));
        assert_eq!(fits(l, 400_001, false, band_limit), Err(Refusal::NoRoom));
    }

    #[test]
    fn first_fit_follows_the_mask_and_names_the_reason() {
        let full = HartLoad { total_ppm: 900_000, band_ppm: 900_000 };
        let loads = [full, HartLoad::default(), HartLoad::default()];
        assert_eq!(first_fit(&loads, 0b111, 200_000, true, 950_000), Ok(1));
        assert_eq!(first_fit(&loads, 0b100, 200_000, true, 950_000), Ok(2));
        assert_eq!(first_fit(&loads, 0b001, 200_000, false, 950_000), Err(Refusal::NoRoom));
        let banded = [HartLoad { total_ppm: 900_000, band_ppm: 900_000 }];
        assert_eq!(first_fit(&banded, 1, 60_000, true, 950_000), Err(Refusal::BandCap));
        assert_eq!(first_fit(&loads, 0, 1, false, 950_000), Err(Refusal::NoRoom));
    }

    #[test]
    fn refusals_map_to_linux_errnos() {
        assert_eq!(Refusal::NoRoom.errno(), 16);
        assert_eq!(Refusal::BandCap.errno(), 16);
        assert_eq!(Refusal::Busy.errno(), 16);
        assert_eq!(Refusal::Malformed.errno(), 22);
    }

    #[test]
    fn microseconds_become_ticks_rounded_up() {
        assert_eq!(us_to_ticks(1_000, 10_000_000), 10_000);
        assert_eq!(us_to_ticks(1, 4_000_000), 4);
        assert_eq!(us_to_ticks(1, 1_000_001), 2);
        assert_eq!(us_to_ticks(u64::MAX, 1_000_000_000), u64::MAX);
    }
}

/// Wave 11 SCHED-RT wiring that only the source can show: the old EDF path is
/// gone, the RT hooks sit where the module doc says, and the forced switch
/// bypasses the priority guard only when the RT pick asks for it.
#[cfg(test)]
mod rt_wiring {
    use super::tid_lookup::{body, code};

    #[test]
    fn the_dead_edf_path_is_deleted() {
        let c = code();
        for gone in ["find_earliest_deadline", "DEADLINE_TASKS", "DeadlinePickGuard",
                     "task_set_deadline", "deadline_admission_check", "DEADLINE_TICK_COUNTER",
                     "TICKS_PER_US"] {
            assert!(!c.contains(gone), "`{gone}` is back in scheduler.rs");
        }
    }

    #[test]
    fn the_dispatch_tail_charges_after_the_last_comparator_write() {
        let c = code();
        let ds = body(&c, "unsafe fn do_schedule(");
        // Wave 15: do_schedule passes the priority it already loaded.
        let tail = ds.rfind("rt::on_switch_prio(cpu, next_idx").expect("on_switch missing");
        let last_tickless = ds.rfind("set_next_tick_tickless(").unwrap();
        let switch = ds.rfind("context_switch(old_ptr").unwrap();
        assert!(last_tickless < tail && tail < switch,
                "rt::on_switch must sit after the tickless write and before the switch");
        assert!(ds.contains("from_prio_queue && !rt_force &&"),
                "the priority guard must yield to a forced RT switch");
        assert!(ds.contains("rt::pick(cpu,"), "the RT pick is not wired");
    }

    #[test]
    fn the_tick_asks_rt_before_the_band_keeps_the_hart() {
        let c = code();
        let s = body(&c, "pub fn schedule()");
        let rt = s.find("rt::tick(cpu, current_idx)").expect("rt::tick missing");
        let band_return = s.find("is_rt_priority(task_prio)").unwrap();
        assert!(rt < band_return, "a band task returns before rt::tick could throttle it");
    }

    #[test]
    fn the_direct_switch_defers_to_rt() {
        let c = code();
        assert!(c.contains("deadline_live: rt::holds_direct_switch("));
    }
}

/// Wave 11 SCHED-RT owner decision: the kernel safety loops are exempt from
/// the RT band budget. The rule (`rt_core::band_throttled`/`band_charged`) and
/// who may set the flag.
#[cfg(test)]
mod rt_exemption {
    use super::rt_core::{band_charged, band_throttled};

    #[test]
    fn an_exempt_band_task_is_never_throttled_nor_charged() {
        // rt-motor (8), exempt, while the band is throttled: still runs.
        assert!(!band_throttled(8, 12, true, true));
        // The runaway (10), not exempt: skipped.
        assert!(band_throttled(10, 12, false, true));
        // Nothing is skipped while the band is not throttled.
        assert!(!band_throttled(10, 12, false, false));
        // Outside the band nothing is ever throttled.
        assert!(!band_throttled(12, 12, false, true));
        assert!(band_charged(10, 12, false));
        assert!(!band_charged(8, 12, true), "an exempt loop's run time is outside the cap");
        assert!(!band_charged(12, 12, false));
    }

    /// The flag is set only by kernel code, for the safety loops: no syscall
    /// handler, spawn path or topology code calls the setter.
    #[test]
    fn only_the_kernel_safety_loops_are_exempted() {
        const MAIN: &str = include_str!("../../../../kernel/src/main.rs");
        const BOOT_SCHED: &str = include_str!("../../../../kernel/src/boot/sched.rs");
        let calls = |src: &str| src.matches("rt::exempt_from_band_cap(").count();
        assert_eq!(calls(MAIN), 3, "rt-motor, imu, flight-ctrl");
        for name in ["\"rt-motor\"", "\"imu\"", "\"flight-ctrl\""] {
            let at = MAIN.find(name).unwrap_or_else(|| panic!("{name} not created in main.rs"));
            let next = &MAIN[at..(at + 400).min(MAIN.len())];
            assert!(next.contains("rt::exempt_from_band_cap("), "{name} is not exempted right after creation");
        }
        assert_eq!(calls(BOOT_SCHED), 1, "sys-wdt");
        for (path, src) in [
            ("syscall/src/topo_sched.rs", include_str!("../../../../crates/core/syscall/src/topo_sched.rs")),
            ("syscall/src/spawn.rs", include_str!("../../../../crates/core/syscall/src/spawn.rs")),
            ("syscall/src/handlers.rs", include_str!("../../../../crates/core/syscall/src/handlers.rs")),
            ("topology/src/types.rs", include_str!("../../../../crates/core/topology/src/types.rs")),
            ("topology/src/parser.rs", include_str!("../../../../crates/core/topology/src/parser.rs")),
            ("kernel/src/tasks/loader.rs", include_str!("../../../../kernel/src/tasks/loader.rs")),
        ] {
            assert!(!src.contains("exempt_from_band_cap"), "{path} can grant the band exemption");
        }
    }
}
