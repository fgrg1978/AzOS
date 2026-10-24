// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side runner for
//! `crates/core/sched/src/{class,eevdf_core,rt_core,sc,slot_bitmap}.rs`.
//!
//! The kernel `azos_sched` cannot be compiled for the host (its
//! dependencies are RV64-only). The W4 scheduler logic, however, is
//! pure data manipulation with no riscv/MMIO calls — we pull the
//! source files directly and run the suites on the host.

#[path = "../../../../crates/core/sched/src/class.rs"]
pub mod class;

#[path = "../../../../crates/core/sched/src/eevdf_core.rs"]
pub mod eevdf_core;

#[cfg(test)]
mod eevdf_tests;

#[cfg(test)]
mod topo;

#[cfg(test)]
mod balance;

#[cfg(test)]
mod core_sched;

#[cfg(test)]
mod nohz;
#[cfg(test)]
mod cpu_power;
#[cfg(test)]
mod rt_exactness;

#[path = "../../../../crates/core/sched/src/rt_core.rs"]
pub mod rt_core;
#[path = "../../../../crates/core/sched/src/rt_receipt.rs"]
pub mod rt_receipt;

#[path = "../../../../crates/core/sched/src/sc.rs"]
pub mod sc;

#[path = "../../../../crates/core/sched/src/slot_bitmap.rs"]
pub mod slot_bitmap;

/// `scheduler::ring_claim_audit`'s slot sets, at the fleet profile's
/// `MAX_TASKS` (4096, `config/limits/Kconfig.limits`), with slots on both sides of word
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
        assert_eq!(words_for(16384), 256, "the config/limits/Kconfig.limits ceiling");
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
    use super::class::SchedClass;

    #[test]
    fn from_raw_round_trip() {
        for &c in &SchedClass::ALL {
            assert_eq!(SchedClass::from_raw(c as u8), Some(c));
        }
        assert_eq!(SchedClass::from_raw(99), None);
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
    const SRC: &str = concat!(
        include_str!("../../../../crates/core/sched/src/scheduler/mod.rs"),
        include_str!("../../../../crates/core/sched/src/scheduler/wake.rs"),
        include_str!("../../../../crates/core/sched/src/scheduler/ipc_fast.rs"),
        include_str!("../../../../crates/core/sched/src/scheduler/lifecycle.rs"),
        include_str!("../../../../crates/core/sched/src/scheduler/budget.rs"),
        include_str!("../../../../crates/core/sched/src/scheduler/donation.rs"),
    );

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
            // Wave 9: one donation lock for every donor, so the lookup
            // lives here.
            "pub fn boost_ready_task(",
            "pub fn restore_ready_task(",
        ] {
            let b = body(&c, sig);
            assert!(b.contains("idx_for_tid(tid)"), "{sig} no longer uses idx_for_tid");
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

/// `SchedClass::from_name`: the five scheduler class names a signed topology may
/// use, plus `session` (the shell's class, the interactive one), and nothing
/// else. An unknown name is the "class this build lacks" refusal, so it must be
/// `None` rather than a nearest match.
#[cfg(test)]
mod class_name_tests {
    use super::class::SchedClass;
    use azos_abi::syscall_nr::{QOS_DEFAULT, QOS_LATENCY};

    #[test]
    fn every_class_round_trips_through_its_name() {
        for c in SchedClass::ALL {
            if c == SchedClass::Interactive {
                // Reported as `interactive`, declared as `session`.
                continue;
            }
            assert_eq!(SchedClass::from_name(c.name().as_bytes()), Some(c));
        }
        assert_eq!(SchedClass::from_name(b"hard_rt"), Some(SchedClass::HardRT));
        assert_eq!(SchedClass::from_name(b"best_effort"), Some(SchedClass::BestEffort));
    }

    /// The class that carries `principal = "user"` is the interactive one: it
    /// reports as `interactive`, never `best_effort`, and runs at the latency
    /// QoS tier. **Canary**: map `session` back to `BestEffort` in
    /// `from_name` (the pre-16-10 behaviour): every assertion but the near
    /// misses goes red; or drop the `Interactive` arm of `qos_hint`: the QoS
    /// assertions go red.
    #[test]
    fn the_session_class_reports_and_runs_as_interactive() {
        let c = SchedClass::from_name(b"session").expect("the shell's class exists");
        assert_eq!(c, SchedClass::Interactive);
        assert_ne!(c, SchedClass::BestEffort);
        assert_eq!(c.name(), "interactive");
        // What `task_class_raw` stores and `class_name_of` reports.
        assert_eq!(SchedClass::from_raw(c as u8), Some(SchedClass::Interactive));
        assert_eq!(SchedClass::from_raw(c as u8).map(SchedClass::name), Some("interactive"));
        assert_eq!(c.qos_hint(), QOS_LATENCY);
        // Nothing else asks for the latency tier by its class, and a plain
        // task starts in the default tier and the best-effort class.
        for other in SchedClass::ALL.into_iter().filter(|o| *o != SchedClass::Interactive) {
            assert_eq!(other.qos_hint(), QOS_DEFAULT, "{}", other.name());
        }
        assert_eq!(SchedClass::from_raw(3), Some(SchedClass::BestEffort), "DEFAULT_SCHED_CLASS_RAW");
        // No wire byte moved, and it is not a real-time class
        // (`RT_CLASS_MAX` = 2).
        assert_eq!(SchedClass::Idle as u8, 4);
        assert!(c as u8 > 2);
        assert_eq!(SchedClass::from_name(b"Session"), None);
        assert_eq!(SchedClass::from_name(b"session "), None);
        // `interactive` is what it reports, not a name a topology declares.
        assert_eq!(SchedClass::from_name(b"interactive"), None);
    }

    /// The class's QoS reaches the task where the row's class is applied:
    /// at slot creation (spawn, fork) and at row application (autorun). The
    /// scheduler cannot run on the host, so the two call sites are pinned in
    /// the source. **Canary**: delete either call and this goes red.
    #[test]
    fn the_class_qos_is_applied_where_the_class_is_written() {
        let sched = include_str!("../../../../crates/core/sched/src/scheduler/mod.rs");
        let life = include_str!("../../../../crates/core/sched/src/scheduler/lifecycle.rs");
        let classes = include_str!("../../../../crates/core/sched/src/classes.rs");
        assert!(sched.contains("task.sched_class_raw = class_raw;\n            classes::on_row_class(idx, class_raw);"));
        assert!(life.contains("classes::on_row_class(idx, task.sched_class_raw);"));
        assert!(classes.contains("sc.set_qos(class.qos_hint());"));
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
/// QEMU rows (`sched-rt:` in `tools/gate/ci_check.sh`) prove the wiring.
#[cfg(test)]
mod rt_core_tests {
    use super::rt_core::*;

    // ── N6b: the dispatch rank (`classes` false is the `sched-dl-in-level` canary) ──────────────────

    /// The decision `rt::pick` takes between the best eligible reservation
    /// (`resv`: level, deadline) and the most urgent queued level `l`, with
    /// the same rank calls: `Some(true)` the reservation, `Some(false)` the
    /// level's task.
    fn pick_model(classes: bool, resv: &[(u32, u64)], level: u32) -> bool {
        let mut best: Option<(u32, u64)> = None;
        for &(p, d) in resv {
            let p = dl_rank(classes, p);
            if best.map_or(true, |(bp, bd)| edf_before(p, d, bp, bd)) {
                best = Some((p, d));
            }
        }
        matches!(best, Some((bp, _)) if bp <= level)
    }

    #[test]
    fn the_canary_rank_is_the_level() {
        for l in 0..32 {
            assert_eq!(dl_rank(false, l), l);
            for r in 0..32 {
                assert_eq!(exempt_first(false, l, Some(r)), l <= r, "exempt {l} vs {r}");
            }
            assert!(exempt_first(false, l, None));
        }
        // A reservation at level 5 runs before level 5's FIFO tasks, not
        // before level 2: the within-level order the canary restores.
        assert!(pick_model(false, &[(5, 100)], 5));
        assert!(!pick_model(false, &[(5, 100)], 2));
    }

    #[test]
    fn classes_rank_puts_every_reservation_above_the_band() {
        for l in 0..32 {
            assert_eq!(dl_rank(true, l), 0);
            assert!(pick_model(true, &[(11, 100)], l), "level {l} beat DL");
        }
    }

    /// Owner decision 10-10: the exempt safety loops
    /// are the stop class, above DL; legacy never takes the stop step.
    #[test]
    fn classes_puts_exempt_loops_above_dl_and_legacy_does_not() {
        for l in 0..12 {
            // Even at the band's last level, ahead of a rank-0 reservation.
            assert!(exempt_first(true, l, Some(0)), "exempt {l} lost to DL");
            assert!(exempt_first(true, l, None));
            assert_eq!(stop_pick(None, Some(l)), StopPick::Take);
            assert_eq!(stop_pick(Some(l), None), StopPick::Keep);
            assert!(stop_preempts(false, true));
            assert!(!stop_preempts(true, true));
            assert!(!stop_preempts(false, false));
        }
        // Between exempt loops: the more urgent level, a tie keeps the runner.
        assert_eq!(stop_pick(Some(5), Some(2)), StopPick::Take);
        assert_eq!(stop_pick(Some(2), Some(5)), StopPick::Keep);
        assert_eq!(stop_pick(Some(3), Some(3)), StopPick::Keep);
        assert_eq!(stop_pick(None, None), StopPick::Pass);
    }

    #[test]
    fn classes_orders_reservations_by_deadline_across_levels() {
        // Legacy: the level-2 reservation first though its deadline is later.
        let (a, b) = ((2u32, 900u64), (9u32, 100u64));
        assert!(edf_before(dl_rank(false, a.0), a.1, dl_rank(false, b.0), b.1));
        // Classes: deadline alone.
        assert!(edf_before(dl_rank(true, b.0), b.1, dl_rank(true, a.0), a.1));
        assert!(!edf_before(dl_rank(true, a.0), a.1, dl_rank(true, b.0), b.1));
    }

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

    /// A constrained server (`d < t`) is held to its density `q / d`: with
    /// budget left and its deadline close, a wake keeps the period while the
    /// budget fits `q / d` (the bandwidth `q / t` would have opened a new one).
    #[test]
    fn a_constrained_server_keeps_its_period_while_the_density_fits() {
        let mut c = Cbs::new(10, 100, 20, true, 0, 0);
        c.release(0);
        c.charge(5);
        // 5 left, 12 to the deadline: 5/12 <= 10/20, kept (5/12 > 10/100).
        assert!(!c.release(8));
        assert_eq!((c.deadline, c.budget), (20, 5));
        let mut old = Cbs::new(10, 100, 20, true, 0, 0);
        old.release(0);
        old.charge(5);
        assert!(old.release_at_rate(8, 100), "the q/t test opens a new period here");
        // 5 left, 8 to the deadline: 5/8 > 10/20, a new period.
        assert!(c.release(12));
        assert_eq!((c.deadline, c.budget), (32, 10));
    }

    /// The bound the density admission relies on: a server that computes and
    /// sleeps in any pattern gets, from a release to the deadline it holds,
    /// at most `q / d` of that span (plus one budget of rounding), here over
    /// 10,000 ticks of a run-1-sleep-1 pattern. The `q / t` test let it run
    /// half the time.
    #[test]
    fn a_self_suspending_server_never_runs_above_its_density() {
        for (span_is_d, limit) in [(true, true), (false, false)] {
            let (q, t, d) = (10u64, 200u64, 40u64);
            let mut c = Cbs::new(q, t, d, true, 0, 0);
            let (mut now, mut ran) = (0u64, 0u64);
            while now < 10_000 {
                if c.throttled {
                    now = now.max(c.deadline);
                    c.replenish_if_due(now);
                }
                if span_is_d { c.release(now); } else { c.release_at_rate(now, t); }
                if c.throttled {
                    continue;
                }
                // Run one tick, then sleep one.
                ran += 1;
                now += 1;
                if c.charge(1) {
                    c.exhaust(now);
                }
                c.release_due = true;
                now += 1;
            }
            let bound = 10_000 * q / d + q;
            assert_eq!(ran <= bound, limit, "ran {} of 10000, density bound {}", ran, bound);
        }
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

    // ── cross-level admission ─────────────────────────────────────────────

    fn bk(level: u32, q: u64, t: u64, d: u64) -> Booked {
        Booked { level, q, d, density_ppm: density_ppm(q, t, d).unwrap() }
    }

    /// The cross-level rule under fixed priority between levels.
    fn fixed(b: &[Booked]) -> bool {
        levels_check(LevelOrder::Fixed, b).is_ok()
    }

    /// The wave-15 `mixed` pair: 75 % of density, but under fixed priority
    /// H's 5 ms at level 4 run before L's 2 ms deadline at level 6. Refused
    /// there, naming level 6; at one level it fits. Under EDF across levels
    /// (the default dispatch) the rule does not bind: admitted. Canaries
    /// `rt-levels-always-canary` (EDF refused) and `rt-levels-never-canary`
    /// (fixed priority admitted).
    #[test]
    fn a_short_deadline_below_a_long_budget_is_refused_only_under_fixed_priority() {
        let mixed = [bk(4, 5_000, 20_000, 20_000), bk(6, 1_000, 20_000, 2_000)];
        assert_eq!(levels_check(LevelOrder::Fixed, &mixed), Err(6));
        assert_eq!(levels_check(LevelOrder::Edf, &mixed), Ok(()));
        assert!(fixed(&[bk(4, 5_000, 20_000, 20_000), bk(4, 1_000, 20_000, 2_000)]));
        // Upside down (the short deadline above) it fits too.
        assert!(fixed(&[bk(4, 1_000, 20_000, 2_000), bk(6, 5_000, 20_000, 20_000)]));
    }

    /// One level: exactly the density sum.
    #[test]
    fn one_level_is_the_density_sum() {
        assert!(fixed(&[bk(4, 5_000, 10_000, 10_000), bk(4, 5_000, 10_000, 10_000)]));
        assert!(!fixed(&[bk(4, 5_000, 10_000, 10_000), bk(4, 5_001, 10_000, 10_000)]));
    }

    /// The carried budget is real: a 6/10 ms server can run [d-6, d] and,
    /// replenished at d, [d, d+6]; a 3/10 ms reservation below it released at
    /// d-4 then gets nothing by d+6 when the level above runs first. Refused
    /// under fixed priority, while a 10/100 ms one fits.
    #[test]
    fn a_carried_budget_counts_against_the_level_below() {
        assert!(!fixed(&[bk(4, 6_000, 10_000, 10_000), bk(20, 3_000, 10_000, 10_000)]));
        assert!(fixed(&[bk(4, 6_000, 10_000, 10_000), bk(20, 10_000, 100_000, 100_000)]));
    }

    /// `first_fit_by`: a hart whose density fits but whose levels do not is
    /// skipped (the next hart takes it), and alone it refuses with `Levels`.
    #[test]
    fn first_fit_skips_a_hart_whose_levels_do_not_fit() {
        let loads = [HartLoad::default(), HartLoad::default()];
        assert_eq!(first_fit_by(&loads, 0b11, 100_000, false, 950_000, |h| h == 1), Ok(1));
        assert_eq!(first_fit_by(&loads, 0b01, 100_000, false, 950_000, |h| h == 1), Err(Refusal::Levels));
        assert_eq!(Refusal::Levels.errno(), 16);
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

    /// Every refusal's errno is one the ABI names, so a caller that reads the
    /// result as an `Errno` (`from_syscall_ret`) never gets `None`. A class
    /// compiled out is `ENOSYS`, `SYS_SCHEDCTL`'s own answer for it.
    #[test]
    fn every_refusal_errno_is_an_abi_errno() {
        use azos_abi::error::Errno;
        let all = [Refusal::Malformed, Refusal::NoRoom, Refusal::BandCap, Refusal::Busy, Refusal::Levels, Refusal::ClassOff, Refusal::Envelope];
        // Exhaustive: a new variant does not compile here until it is listed.
        for r in all {
            match r {
                Refusal::Malformed | Refusal::NoRoom | Refusal::BandCap | Refusal::Busy | Refusal::Levels | Refusal::ClassOff | Refusal::Envelope => {}
            }
            assert!(Errno::from_syscall_ret(-(r.errno() as i64)).is_some(), "{} answers {}", r.name(), r.errno());
        }
        assert_eq!(Refusal::ClassOff.errno(), Errno::ENOSYS as i32);
        assert_eq!(Refusal::Envelope.errno(), Errno::EACCES as i32);
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
        assert!(ds.contains("if !rt_force &&"),
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
        // sys-wdt, and the kill switch (gpio-edge-irq: the e-stop's GPIO edge
        // task, `actuation::kill_switch`).
        assert_eq!(calls(BOOT_SCHED), 2, "sys-wdt, kill-switch");
        assert!(BOOT_SCHED.contains("\"kill-switch\""), "the kill-switch task is created in boot/sched.rs");
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

/// What one CPU's per-CPU area holds besides its ready queues (wave 15,
/// NRCPUS-FLEET-AREA): the RT band state (`rt::RtCpu`: `SET_CAP` slot words,
/// `SET_CAP` CBS reservations, the owner's band and three words). It does not
/// depend on `MAX_TASKS`: `SET_CAP` is fixed, so these bytes are the same in
/// every profile.
/// Printed with `--nocapture` for the area table; the asserts pin the
/// profile-independence the table relies on.
#[cfg(test)]
mod percpu_area_sizes {
    use core::mem::size_of;

    /// `rt.rs`'s `SET_CAP` (the module does not compile for the host).
    const SET_CAP: usize = 16;

    #[test]
    fn rt_per_cpu_state_is_fixed_size() {
        let cbs = size_of::<super::rt_core::Cbs>();
        let band = size_of::<super::rt_core::Band>();
        let rt_cpu = SET_CAP * 8 + SET_CAP * cbs + (band + 3 * 8);
        println!("[AREA] Cbs {cbs} B, Band {band} B, RtCpu ~{rt_cpu} B");
        // Fixed-size: none of these types is generic over MAX_TASKS.
        assert!(rt_cpu < 4096, "the RT band's per-CPU state grew past a page");
    }
}

// N6: the dispatch-class model (`sc.rs`).
#[cfg(test)]
mod sc_tests {
    use crate::sc::*;

    const THR: u32 = 12;
    const IDLE: u32 = 31;

    #[test]
    fn precedence_is_stop_dl_rt_fair_idle() {
        assert_eq!(Class::PRECEDENCE, [Class::Stop, Class::Dl, Class::Rt, Class::Fair, Class::Idle]);
        for (i, c) in Class::PRECEDENCE.iter().enumerate() {
            assert_eq!(c.rank() as usize, i);
            assert_eq!(Class::from_raw(i as u8), Some(*c));
            assert_eq!(Class::from_name(c.name().as_bytes()), Some(*c));
        }
        assert!(Class::Dl.preempts(Class::Rt) && Class::Rt.preempts(Class::Fair));
        assert!(!Class::Fair.preempts(Class::Fair) && !Class::Idle.preempts(Class::Fair));
        assert_eq!(Class::from_raw(5), None);
    }

    #[test]
    fn classify_maps_legacy_state() {
        assert_eq!(classify(8, false, false, THR, IDLE), Class::Rt);
        assert_eq!(classify(11, false, false, THR, IDLE), Class::Rt);
        assert_eq!(classify(12, false, false, THR, IDLE), Class::Fair);
        assert_eq!(classify(16, false, false, THR, IDLE), Class::Fair);
        assert_eq!(classify(31, false, false, THR, IDLE), Class::Idle);
        // A reservation is DL whatever its level; a stop task beats it.
        assert_eq!(classify(16, true, false, THR, IDLE), Class::Dl);
        assert_eq!(classify(8, true, true, THR, IDLE), Class::Stop);
        // No RT class: the band levels are fair.
        assert_eq!(classify(8, false, false, 0, IDLE), Class::Fair);
    }

    #[test]
    fn sc_layout_is_frozen() {
        assert_eq!(core::mem::size_of::<SchedContext>(), SC_SIZE);
        let sc = SchedContext::new(Class::Fair);
        assert_eq!(sc.class(), Class::Fair);
        assert_eq!(sc.on_cpu.load(core::sync::atomic::Ordering::Relaxed), NO_CPU);
        sc.set_class(Class::Dl, 9);
        assert_eq!(sc.class(), Class::Dl);
    }

    /// The frozen size is six words and sixteen bytes of fixed-width fields
    /// (prio 4, qos 4, on_cpu 2, irq 2, class, criticality, cluster, flags):
    /// 64 on a 64-bit target, 40 on rv32, where the micro kernel compiles
    /// this file. The times are one word each; a value above the word is the
    /// word's maximum.
    #[test]
    fn sc_is_words_plus_fixed_fields() {
        assert_eq!(SC_SIZE, 6 * core::mem::size_of::<usize>() + 4 + 4 + 2 + 2 + 4);
        let sc = SchedContext::new(Class::Dl);
        sc.set_times(500, 10_000, 0);
        assert_eq!((sc.budget_us(), sc.period_us(), sc.deadline_us()), (500, 10_000, 0));
        sc.set_times(u64::MAX, 1, 2);
        assert_eq!(sc.budget_us(), usize::MAX as u64);
        assert_eq!((sc.period_us(), sc.deadline_us()), (1, 2));
    }

    /// The QoS hint (owner plan, Energy section 8): every SC starts at the
    /// default, a level is recorded and read back, a level above the highest is
    /// refused and leaves the old one, and the hint touches no class field.
    #[test]
    fn qos_hint_is_recorded_and_bounded() {
        let sc = SchedContext::new(Class::Rt);
        assert_eq!(sc.qos(), QOS_DEFAULT);
        for q in [QOS_LATENCY, QOS_THROUGHPUT, QOS_BACKGROUND, QOS_DEFAULT] {
            assert!(sc.set_qos(q));
            assert_eq!(sc.qos(), q);
        }
        sc.set_qos(QOS_LATENCY);
        assert!(!sc.set_qos(QOS_MAX + 1));
        assert!(!sc.set_qos(u32::MAX));
        assert_eq!(sc.qos(), QOS_LATENCY, "a refused hint changes nothing");
        assert_eq!(sc.class(), Class::Rt, "a hint is not a class");
        assert_eq!(core::mem::size_of::<SchedContext>(), SC_SIZE, "no field was added");
    }

    /// QoS timer tolerance, the class rule: only the fair class has slack.
    /// A stop, deadline, real-time or idle task gets 0 in every mode, at every
    /// hint, with the row's flag set and every tier non-zero. **Canary**
    /// `qos-rt-slack-canary` gives the real-time classes the fair rule.
    #[test]
    fn qos_timer_slack_is_fair_class_only() {
        let tiers = [100, 200, 300, 400];
        for class in [Class::Stop, Class::Dl, Class::Rt, Class::Idle] {
            for mode in [SlackMode::Off, SlackMode::Rows, SlackMode::All] {
                for qos in 0..=QOS_MAX + 1 {
                    for row in [false, true] {
                        assert_eq!(
                            timer_slack_us(class, qos, row, mode, &tiers), 0,
                            "{class:?} mode {mode:?} qos {qos} row {row} got a slack window"
                        );
                    }
                }
            }
        }
        // The positive control: the same call for a fair task is the tier.
        assert_eq!(timer_slack_us(Class::Fair, QOS_BACKGROUND, false, SlackMode::All, &tiers), 400);
    }

    /// The mode and the tier: off gives nothing; rows gives the tier only to
    /// a task whose row opted in; all gives every fair task its tier; a hint
    /// past the last tier reads the last; a zero tier is zero.
    #[test]
    fn qos_timer_slack_follows_mode_tier_and_row() {
        let tiers = [0, 0, 2_000, 20_000];
        for q in [QOS_DEFAULT, QOS_LATENCY, QOS_THROUGHPUT, QOS_BACKGROUND] {
            assert_eq!(timer_slack_us(Class::Fair, q, true, SlackMode::Off, &tiers), 0);
            assert_eq!(timer_slack_us(Class::Fair, q, false, SlackMode::Rows, &tiers), 0, "rows: no flag, no slack");
            assert_eq!(timer_slack_us(Class::Fair, q, true, SlackMode::Rows, &tiers), tiers[q as usize]);
            assert_eq!(timer_slack_us(Class::Fair, q, false, SlackMode::All, &tiers), tiers[q as usize]);
        }
        assert_eq!(timer_slack_us(Class::Fair, u32::MAX, false, SlackMode::All, &tiers), 20_000);
        assert_eq!(timer_slack_us(Class::Fair, QOS_LATENCY, false, SlackMode::All, &tiers), 0, "latency: exact");
    }

    /// The row's `timer_slack` is one bit of `flags`: set, read, cleared, and
    /// it touches nothing else of the SC.
    #[test]
    fn timer_slack_row_flag_is_one_bit() {
        let sc = SchedContext::new(Class::Fair);
        assert!(!sc.timer_slack_row());
        sc.flags.store(0x80, core::sync::atomic::Ordering::Relaxed);
        sc.set_timer_slack_row(true);
        assert!(sc.timer_slack_row());
        assert_eq!(sc.flags.load(core::sync::atomic::Ordering::Relaxed), 0x80 | SC_FLAG_TIMER_SLACK);
        sc.set_timer_slack_row(false);
        assert!(!sc.timer_slack_row());
        assert_eq!(sc.flags.load(core::sync::atomic::Ordering::Relaxed), 0x80, "the other bits stay");
        assert_eq!(core::mem::size_of::<SchedContext>(), SC_SIZE, "no field was added");
    }

    struct Stub(Class, Option<usize>);
    impl SchedClassOps for Stub {
        fn class(&self) -> Class { self.0 }
        fn enqueue(&self, _: usize, _: usize) -> bool { false }
        fn dequeue(&self, _: usize, _: usize) -> bool { false }
        fn pick(&self, _: usize) -> Option<usize> { self.1 }
        fn tick(&self, _: usize, _: usize) -> bool { false }
        fn preempt_check(&self, _: usize, cur: usize, cand: usize) -> bool { cand < cur }
    }

    #[test]
    fn walk_takes_the_first_class_with_work() {
        let (s, d, r, f, i) = (Stub(Class::Stop, None), Stub(Class::Dl, None),
            Stub(Class::Rt, Some(2)), Stub(Class::Fair, Some(3)), Stub(Class::Idle, Some(4)));
        let t: ClassTable<'_> = [Some(&s), Some(&d), Some(&r), Some(&f), Some(&i)];
        assert_eq!(pick_in_precedence(&t, 0), Some((Class::Rt, 2)));
        let t2: ClassTable<'_> = [None, None, None, Some(&f), Some(&i)];
        assert_eq!(pick_in_precedence(&t2, 0), Some((Class::Fair, 3)));
        let empty: ClassTable<'_> = [None, None, None, None, None];
        assert_eq!(pick_in_precedence(&empty, 0), None);
        assert!(should_preempt(&t, 0, (Class::Fair, 3), (Class::Rt, 2)));
        assert!(!should_preempt(&t, 0, (Class::Rt, 2), (Class::Fair, 3)));
        // Inside a class, the class decides.
        assert!(should_preempt(&t, 0, (Class::Fair, 7), (Class::Fair, 3)));
    }
}

/// The token bucket the durable denial records pass (`azos_decision::deny`):
/// the module's own tests, pulled in by path (the crate's `cargo test` does not
/// build on the host).
#[allow(dead_code)]
#[path = "../../../../crates/core/decision/src/deny.rs"]
mod deny_limiter;

/// Durable records of capability denials (`Verdict::Deny`, Kconfig
/// `DECISION_DENY_DURABLE_PER_SEC`/`_BURST`): rate-limited per subject, the
/// drops counted into the next record written, refusals untouched. Global
/// state (sink, buckets, counters), so each test takes a subject of its own and
/// moves the fake clock a hundred seconds on, which refills every bucket.
#[cfg(test)]
mod deny_receipts {
    use azos_decision::{record, Rule, Verdict, DENY_DURABLE_BURST as BURST, DENY_DURABLE_PER_SEC as RATE};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    const HZ: u64 = 1000;
    static GUARD: Mutex<()> = Mutex::new(());
    static NOW: AtomicU64 = AtomicU64::new(0);
    static GOT: Mutex<Vec<(u8, u8, u32, [u64; 3])>> = Mutex::new(Vec::new());

    fn clock() -> u64 { NOW.load(Ordering::Relaxed) }
    fn sink(p: &azos_decision::ProvenanceRecord) {
        GOT.lock().unwrap().push((p.rule, p.verdict, p.subject, p.n));
    }
    /// A fresh scene: the sink and clock installed, the clock a hundred
    /// seconds on, the sink's log empty, and the owed count taken by a denial
    /// of a throwaway subject.
    fn scene() -> std::sync::MutexGuard<'static, ()> {
        let g = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        azos_decision::set_durable_sink(sink);
        azos_decision::set_clock(clock, HZ);
        NOW.fetch_add(100 * HZ, Ordering::Relaxed);
        deny(0xFFFF_0000);
        GOT.lock().unwrap().clear();
        g
    }
    fn deny(subject: u32) { record(Rule::CapDenial, Verdict::Deny, subject, [1, 2, 0]); }
    fn written(subject: u32) -> Vec<[u64; 3]> {
        GOT.lock().unwrap().iter().filter(|r| r.2 == subject).map(|r| r.3).collect()
    }

    /// A subject's first `BURST` denials are durable, the rest in the same
    /// instant are not; a second later `RATE` more are (the bucket's depth
    /// bounds the refill).
    ///
    /// **Canary.** `deny_admit` answering `Some(0)` always: everything is
    /// written, red. The `Deny` branch missing from `record`: nothing is
    /// written, red. No refill in `refilled`: the second count is 0, red.
    #[test]
    fn a_subject_gets_its_burst_then_its_rate() {
        let _g = scene();
        for _ in 0..BURST * 3 { deny(11); }
        assert_eq!(written(11).len() as u64, BURST, "the burst");
        NOW.fetch_add(HZ, Ordering::Relaxed);
        for _ in 0..BURST * 3 { deny(11); }
        assert_eq!(written(11).len() as u64, BURST + RATE.min(BURST), "one second's refill");
    }

    /// Another subject's bucket is its own.
    ///
    /// **Canary.** Key the bucket on a constant instead of the subject: the
    /// second subject finds the first one's bucket empty, red.
    #[test]
    fn one_subjects_flood_does_not_cost_another() {
        let _g = scene();
        for _ in 0..BURST * 3 { deny(21); }
        deny(22);
        assert_eq!(written(22).len(), 1, "a quiet subject's first denial was dropped");
    }

    /// Two subjects that share a bucket key (the threads of one Domain) share
    /// one burst; a third with its own key has its own.
    ///
    /// **Canary.** Key `record_keyed` on the subject (not `bucket`): the two
    /// threads get a burst each, red.
    #[test]
    fn subjects_sharing_a_bucket_key_share_a_burst() {
        let _g = scene();
        let k = 0x7700_0001;
        for _ in 0..BURST { azos_decision::record_keyed(Rule::CapDenial, Verdict::Deny, 61, k, [1, 2, 0]); }
        for _ in 0..BURST { azos_decision::record_keyed(Rule::CapDenial, Verdict::Deny, 62, k, [1, 2, 0]); }
        assert_eq!(written(61).len() as u64 + written(62).len() as u64, BURST, "one bucket for the pair");
        azos_decision::record_keyed(Rule::CapDenial, Verdict::Deny, 63, 0x7700_0002, [1, 2, 0]);
        assert_eq!(written(63).len(), 1, "another key has its own bucket");
    }

    /// A warrant revoke is a `Deny` with the slot count in its third number:
    /// it is not a capability denial, so the bucket leaves it alone.
    ///
    /// **Canary.** Drop the `Rule::CapDenial` test in `record_keyed`: the
    /// record carries the dropped count and the burst limits it, red.
    #[test]
    fn a_warrant_revoke_is_not_limited_and_keeps_its_number() {
        let _g = scene();
        for _ in 0..BURST * 3 { record(Rule::CapRevoke, Verdict::Deny, 71, [5, 6, 3]); }
        assert!(written(71).is_empty(), "a revoke is a ring record, never durable through the bucket");
        if azos_decision::ON {
            let r = azos_decision::get(azos_decision::total()).expect("the ring has it");
            assert_eq!(r.n, [5, 6, 3], "the slot count is intact");
        }
    }

    /// The drops are counted and the count is in the third number of the next
    /// record that is written (and only that one); the total is public (it
    /// is the introspection tree's `decisions/deny_dropped`).
    ///
    /// **Canary.** Skip `n[2] = owed` in `record`: the record carries 0, red.
    /// Do not clear the pending count (`load` for `swap(0)`): the record after
    /// it repeats the count, red. Do not count (`DENY_DROPPED`): the delta is
    /// 0, red.
    #[test]
    fn the_dropped_count_rides_in_the_next_record_written() {
        let _g = scene();
        let t0 = azos_decision::deny_dropped_total();
        for _ in 0..BURST + 5 { deny(31); }
        assert_eq!(azos_decision::deny_dropped_total() - t0, 5);
        assert!(written(31).iter().all(|n| n[2] == 0), "a record carried a drop count before any was owed");
        NOW.fetch_add(HZ, Ordering::Relaxed);
        deny(31);
        deny(31);
        let w = written(31);
        assert_eq!(w[BURST as usize], [1, 2, 5], "the next record written carries the 5 dropped before it");
        assert_eq!(w[BURST as usize + 1], [1, 2, 0], "and only that one");
        assert_eq!(azos_decision::deny_dropped_total() - t0, 5, "a record that was written is not a drop");
        if azos_decision::ON {
            let r = azos_decision::get(azos_decision::total()).expect("the ring has it");
            assert_eq!((r.verdict, r.n), (Verdict::Deny as u8, [1, 2, 0]));
        }
    }

    /// The ring (when on) shows the count on the record that carries it too.
    ///
    /// Run with `--features decision-dev`; without it there is no ring to
    /// read and the test is a no-op.
    #[test]
    fn the_ring_shows_the_count_on_the_record_that_carries_it() {
        if !azos_decision::ON { return; }
        let _g = scene();
        for _ in 0..BURST + 3 { deny(41); }
        NOW.fetch_add(HZ, Ordering::Relaxed);
        deny(41);
        let r = azos_decision::get(azos_decision::total()).expect("the ring has it");
        assert_eq!((r.verdict, r.subject, r.n), (Verdict::Deny as u8, 41, [1, 2, 3]));
        let mut line = String::new();
        azos_decision::ProvenanceRecord::from_record(&r).write_line(&mut line).unwrap();
        assert!(line.contains(" dropped=3 "), "{line}");
        deny(41);
        let r = azos_decision::get(azos_decision::total()).expect("the ring has it");
        let mut line = String::new();
        azos_decision::ProvenanceRecord::from_record(&r).write_line(&mut line).unwrap();
        assert!(!line.contains("dropped"), "a zero count is not printed: {line}");
    }

    /// Refusals are unlimited and untouched: every one reaches the sink with
    /// its numbers as given, however many denials were dropped before, and
    /// none of them is counted as a drop or owes the next denial anything.
    ///
    /// **Canary.** Route `Refuse` through `deny_admit` too: only `BURST`
    /// arrive, red. Write the owed count into a refusal's `n[2]`: the numbers
    /// differ, red.
    #[test]
    fn refusals_are_not_limited_and_not_touched() {
        let _g = scene();
        for _ in 0..BURST * 3 { deny(51); }
        let t0 = azos_decision::deny_dropped_total();
        let n: usize = BURST as usize * 10;
        for i in 0..n {
            record(Rule::DeadlineAdmission, Verdict::Refuse, 52, [7, 8, 9 + i as u64]);
        }
        let got: Vec<_> = GOT.lock().unwrap().iter().filter(|r| r.1 == Verdict::Refuse as u8).cloned().collect();
        assert_eq!(got.len(), n, "a refusal was dropped");
        assert!(got.iter().enumerate().all(|(i, r)| r.3 == [7, 8, 9 + i as u64]), "a refusal's numbers changed");
        assert_eq!(azos_decision::deny_dropped_total(), t0, "a refusal counted as a drop");
        // The denials' owed count is still owed.
        NOW.fetch_add(HZ, Ordering::Relaxed);
        deny(51);
        assert_eq!(*written(51).last().unwrap(), [1, 2, BURST * 2], "the owed count was spent on a refusal");
    }
}

/// The receipt of a refused run-time reservation (`rt_receipt::record_refusal`,
/// called once from `rt::reserve`'s refusal arm; Kconfig
/// `DECISION_REFUSALS_DURABLE`). The sink here is the one the kernel installs
/// (`azos_decision::set_durable_sink`) with a recorder that keeps what it was
/// handed.
#[cfg(test)]
mod refusal_receipts {
    use super::rt_core::*;
    use super::rt_receipt::{held_by_row, record_refusal};
    use std::sync::Mutex;

    static GUARD: Mutex<()> = Mutex::new(());
    static GOT: Mutex<Vec<(u8, u8, u32, [u64; 3])>> = Mutex::new(Vec::new());

    fn sink(p: &azos_decision::ProvenanceRecord) {
        GOT.lock().unwrap().push((p.rule, p.verdict, p.subject, p.n));
    }

    const LIMIT: u32 = 700_000;
    const ASK: Ask = Ask { runtime_us: 300_000, period_us: 1_000_000, deadline_us: 0, band: false };

    /// `reserve`'s decision as the test sees it: density, first fit, and on
    /// a refusal the one `record_refusal` call. (`rt.rs` itself links the
    /// scheduler's statics; `reserve_calls_record_refusal_once_from_its_refusal_arm`
    /// ties this model to it.) Returns the sink's records and the ring total.
    fn reserve_model(tid: u32, ask: Ask, loads: &[HartLoad], mask: u32) -> (Result<usize, Refusal>, Vec<(u8, u8, u32, [u64; 3])>, u64) {
        azos_decision::set_durable_sink(sink);
        GOT.lock().unwrap().clear();
        let before = azos_decision::total();
        let res = density_ppm(ask.runtime_us, ask.period_us, ask.deadline_us)
            .and_then(|d| first_fit(loads, mask, d, ask.band, LIMIT));
        if let Err(why) = res {
            record_refusal(tid, why, ask, loads, mask, LIMIT);
        }
        let got = GOT.lock().unwrap().clone();
        (res, got, azos_decision::total() - before)
    }

    fn expect_one(got: &[(u8, u8, u32, [u64; 3])], tid: u32, n: [u64; 3]) {
        assert_eq!(got.len(), 1, "exactly one durable record per refusal: {got:?}");
        let rule = azos_decision::Rule::DeadlineAdmission as u8;
        let refuse = azos_decision::Verdict::Refuse as u8;
        assert_eq!(got[0], (rule, refuse, tid, n));
    }

    /// A reservation that does not fit leaves one record with the budget and
    /// period asked, the best room left (200 ms of the 1 s window: 800 000 ppm
    /// taken) and the reason (no-room = 2) above bit 32.
    #[test]
    fn a_refused_reserve_leaves_exactly_one_durable_record() {
        let _g = GUARD.lock().unwrap();
        let loads = [HartLoad { total_ppm: 800_000, band_ppm: 0 }, HartLoad { total_ppm: 900_000, band_ppm: 0 }];
        let (res, got, _) = reserve_model(41, ASK, &loads, 0b11);
        assert_eq!(res, Err(Refusal::NoRoom));
        expect_one(&got, 41, [300_000, 1_000_000, 200_000 | 2 << 32]);
    }

    /// The band cap is the tighter room for a band task: 200 000 ppm under
    /// the cap although 400 000 ppm are free, reason band-cap = 3.
    #[test]
    fn a_band_refusal_names_the_band_room() {
        let _g = GUARD.lock().unwrap();
        let loads = [HartLoad { total_ppm: 600_000, band_ppm: 500_000 }];
        let ask = Ask { band: true, ..ASK };
        let (res, got, _) = reserve_model(42, ask, &loads, 0b1);
        assert_eq!(res, Err(Refusal::BandCap));
        expect_one(&got, 42, [300_000, 1_000_000, 200_000 | 3 << 32]);
    }

    /// A reservation that is admitted leaves no record.
    #[test]
    fn an_admitted_reserve_leaves_none() {
        let _g = GUARD.lock().unwrap();
        let loads = [HartLoad { total_ppm: 500_000, band_ppm: 0 }];
        let (res, got, ring) = reserve_model(43, ASK, &loads, 0b1);
        assert_eq!(res, Ok(0));
        assert!(got.is_empty(), "an admitted reservation was recorded: {got:?}");
        assert_eq!(ring, 0);
        // Nor does an admission or a placement reach the sink, whoever records
        // it (a denial does, under its rate limit: `deny_receipts`).
        use azos_decision::{record, Rule, Verdict};
        for v in [Verdict::Admit, Verdict::Place] {
            record(Rule::DeadlineAdmission, v, 43, [1, 2, 3]);
        }
        assert!(GOT.lock().unwrap().is_empty(), "a verdict that is neither a refusal nor a denial reached the durable sink");
    }

    /// With the ring off (`DECISION_RECORDS_DEV=n`, the default) the durable
    /// receipt is still written; with it on the ring has the same refusal
    /// once. Run the suite with and without `--features decision-dev`.
    #[test]
    fn the_receipt_does_not_depend_on_the_ring() {
        let _g = GUARD.lock().unwrap();
        let loads = [HartLoad { total_ppm: 1_000_000, band_ppm: 0 }];
        let (res, got, ring) = reserve_model(44, ASK, &loads, 0b1);
        assert_eq!(res, Err(Refusal::NoRoom));
        expect_one(&got, 44, [300_000, 1_000_000, 2 << 32]);
        assert_eq!(azos_decision::ON, cfg!(feature = "decision-dev"));
        assert!(azos_decision::DURABLE);
        // One id claimed either way; the ring holds it only when it is built.
        assert_eq!(ring, 1, "ids claimed");
        assert_eq!(azos_decision::get(azos_decision::total()).is_some(), azos_decision::ON);
    }

    /// A malformed ask (no CPU in the mask, zero runtime) is a refusal too,
    /// with nothing available and the reason malformed = 1.
    #[test]
    fn a_malformed_ask_leaves_a_receipt() {
        let _g = GUARD.lock().unwrap();
        let ask = Ask { runtime_us: 0, ..ASK };
        let (res, got, _) = reserve_model(45, ask, &[HartLoad::default()], 0);
        assert_eq!(res, Err(Refusal::Malformed));
        expect_one(&got, 45, [0, 1_000_000, 1 << 32]);
    }

    /// `why`'s side of the receipt (`azos_decision::lookup` / `query`): the
    /// refusal is found by its id and by a filter on rule, verdict and
    /// subject, and its chain names the rule, the numbers and the reason.
    /// **Canary.** Stop `durable` storing into the journal (and build
    /// without `decision-dev`): `lookup` returns `None`, red.
    #[test]
    fn a_refused_reserve_resolves_through_the_query() {
        use azos_decision::{Filter, Rule, Verdict};
        let _g = GUARD.lock().unwrap();
        let loads = [HartLoad { total_ppm: 800_000, band_ppm: 0 }];
        let before = azos_decision::total();
        let (res, _, _) = reserve_model(46, ASK, &loads, 0b1);
        assert_eq!(res, Err(Refusal::NoRoom));
        let mut ids = [0u64; 4];
        let f = Filter { rule: Some(Rule::DeadlineAdmission as u8), verdict: Some(Verdict::Refuse as u8), subject: Some(46), after: before };
        assert_eq!(azos_decision::query(&f, &mut ids), 1, "one refusal, one id");
        let p = azos_decision::lookup(ids[0]).expect("the id resolves");
        assert_eq!((p.rule, p.verdict, p.subject, p.n), (Rule::DeadlineAdmission as u8, Verdict::Refuse as u8, 46, [300_000, 1_000_000, 200_000 | 2 << 32]));
        let mut chain = String::new();
        p.write_chain(&mut chain).unwrap();
        assert!(chain.contains("numbers   runtime_us=300000 period_us=1000000 available_us=200000 reason=2(no-room)"), "{chain}");
    }

    /// The decision crate names the refusal reasons ([`REFUSAL_REASONS`]) in
    /// the order `Refusal::code` numbers them.
    #[test]
    fn the_decision_crate_names_every_refusal_reason() {
        for r in [Refusal::Malformed, Refusal::NoRoom, Refusal::BandCap, Refusal::Busy, Refusal::Levels, Refusal::ClassOff, Refusal::Envelope] {
            assert_eq!(azos_decision::REFUSAL_REASONS[r.code() as usize], r.name());
        }
        assert_eq!(azos_decision::REFUSAL_REASONS.len(), 8);
    }

    /// The gate as the kernel wires it, modelled: task `HELD_TID` is in a Domain
    /// whose `rt_time` row caps one reservation at `ROW_CAP_PPM`; any other task
    /// is in a `full` one. A no writes the gate's own record
    /// (`Rule::EnvelopeRtTime`) and counts the question.
    const HELD_TID: u32 = 0xE1_0001;
    const FREE_TID: u32 = 0xE1_0002;
    const ROW_CAP_PPM: u32 = 200_000;
    static ASKED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    fn row_gate(a: azos_common::envelope::Ask) -> bool {
        use azos_common::envelope::Ask as A;
        ASKED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match a {
            A::RtTime { tid, density_ppm } if tid == HELD_TID && density_ppm > ROW_CAP_PPM => {
                azos_decision::record(
                    azos_decision::Rule::EnvelopeRtTime,
                    azos_decision::Verdict::Refuse,
                    tid,
                    [density_ppm as u64, ROW_CAP_PPM as u64, 1],
                );
                false
            }
            _ => true,
        }
    }

    /// `rt::reserve`'s two steps around the admission, run against the real
    /// `held_by_row` and `record_refusal`: ask the row first and refuse with
    /// `Refusal::Envelope` if it holds, else admit; on a refusal, one call to
    /// `record_refusal`. (The order in `rt.rs` is pinned by
    /// `reserve_asks_the_rt_time_row_once_before_it_takes_any_lock`.)
    fn reserve_with_row(tid: u32, ask: Ask, loads: &[HartLoad]) -> (Result<usize, Refusal>, Vec<(u8, u8, u32, [u64; 3])>, u64) {
        azos_decision::set_durable_sink(sink);
        GOT.lock().unwrap().clear();
        let before = azos_decision::total();
        let res = if held_by_row(tid, ask.runtime_us, ask.period_us, ask.deadline_us) {
            Err(Refusal::Envelope)
        } else {
            density_ppm(ask.runtime_us, ask.period_us, ask.deadline_us)
                .and_then(|d| first_fit(loads, 0b1, d, ask.band, LIMIT))
        };
        if let Err(why) = res {
            record_refusal(tid, why, ask, loads, 0b1, LIMIT);
        }
        let got = GOT.lock().unwrap().clone();
        (res, got, azos_decision::total() - before)
    }

    /// A reservation the Domain's `rt_time` row holds is refused with
    /// `Refusal::Envelope` (`EACCES`, reason 7, named `envelope`), after one
    /// question to the gate, with exactly one record, the gate's
    /// `Rule::EnvelopeRtTime`, and none of `Rule::DeadlineAdmission`; the
    /// same reservation of a Domain whose row lets it through is admitted.
    ///
    /// **Canary.** `--features rt-envelope-canary` (`held_by_row` never asks):
    /// the held reservation is admitted, red.
    #[test]
    fn a_reservation_the_row_holds_is_refused_and_leaves_one_record() {
        let _g = GUARD.lock().unwrap();
        azos_common::envelope::set_ask_gate(row_gate);
        let loads = [HartLoad { total_ppm: 0, band_ppm: 0 }];
        ASKED.store(0, std::sync::atomic::Ordering::SeqCst);
        let (res, got, ring) = reserve_with_row(HELD_TID, ASK, &loads);
        azos_common::envelope::clear_ask_gate_for_test();
        let Err(why) = res else { panic!("a reservation of 300000 ppm went through a row that caps one at {ROW_CAP_PPM}") };
        assert_eq!(why, Refusal::Envelope);
        assert_eq!((why.errno(), why.code(), why.name()), (13, 7, "envelope"));
        assert_eq!(ASKED.load(std::sync::atomic::Ordering::SeqCst), 1, "one question per reservation");
        assert_eq!(ring, 1, "one refusal, one record");
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, azos_decision::Rule::EnvelopeRtTime as u8, "the gate's record, not the admission's");
        assert_eq!(got[0].1, azos_decision::Verdict::Refuse as u8);
        assert!(got.iter().all(|r| r.0 != azos_decision::Rule::DeadlineAdmission as u8));

        // The same shape for a Domain of a `full` row is admitted, and asks once.
        azos_common::envelope::set_ask_gate(row_gate);
        ASKED.store(0, std::sync::atomic::Ordering::SeqCst);
        let (res, got, ring) = reserve_with_row(FREE_TID, ASK, &loads);
        azos_common::envelope::clear_ask_gate_for_test();
        assert_eq!(res, Ok(0));
        assert_eq!(ASKED.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!((got.is_empty(), ring) == (true, 0), "an admitted reservation left a record: {got:?}");
    }

    /// A shape with no density is not asked (admission refuses it for what is
    /// wrong with it, with its own receipt), a build with no gate holds
    /// nothing, and a reservation at the row's cap is let through.
    #[test]
    fn the_row_is_not_asked_about_a_malformed_shape_and_not_held_without_a_gate() {
        let _g = GUARD.lock().unwrap();
        azos_common::envelope::set_ask_gate(row_gate);
        ASKED.store(0, std::sync::atomic::Ordering::SeqCst);
        assert!(!held_by_row(HELD_TID, 0, 1_000_000, 0), "a zero runtime");
        assert!(!held_by_row(HELD_TID, 2_000_000, 1_000_000, 0), "a runtime above the period");
        assert_eq!(ASKED.load(std::sync::atomic::Ordering::SeqCst), 0, "asked about a malformed shape");
        assert!(!held_by_row(HELD_TID, 200_000, 1_000_000, 0), "exactly the cap");
        assert!(held_by_row(HELD_TID, 200_001, 1_000_000, 0), "one ppm past the cap");
        azos_common::envelope::clear_ask_gate_for_test();
        assert!(!held_by_row(HELD_TID, 900_000, 1_000_000, 0), "no gate installed");
    }

    /// A refusal by the row is the gate's record only: `record_refusal` for
    /// `Refusal::Envelope` writes none, while the same call for another reason
    /// still writes the admission's.
    #[test]
    fn record_refusal_leaves_the_envelope_refusal_to_the_gate() {
        let _g = GUARD.lock().unwrap();
        azos_decision::set_durable_sink(sink);
        GOT.lock().unwrap().clear();
        let before = azos_decision::total();
        record_refusal(60, Refusal::Envelope, ASK, &[HartLoad::default()], 0b1, LIMIT);
        assert!(GOT.lock().unwrap().is_empty(), "the envelope refusal was recorded twice");
        assert_eq!(azos_decision::total(), before);
        record_refusal(60, Refusal::NoRoom, ASK, &[HartLoad::default()], 0b1, LIMIT);
        assert_eq!(GOT.lock().unwrap().len(), 1);
    }

    /// The tie to `rt.rs`, read with its whitespace removed so a reformat does
    /// not break it: `reserve` asks `held_by_row` once, as the first step, before
    /// the critical section and the admission lock; the admission closure turns
    /// a hold into `Refusal::Envelope` before anything else; and `record_refusal`
    /// is called once, unguarded, from the refusal arm (the exemption of the
    /// envelope refusal is `record_refusal`'s own, tested above).
    ///
    /// **Canary.** Delete the ask from `rt.rs`, move it inside the critical
    /// section or past the lock, or drop the refusal from the closure: red.
    #[test]
    fn reserve_asks_the_rt_time_row_once_before_it_takes_any_lock() {
        let src: String = include_str!("../../../../crates/core/sched/src/rt.rs").split_whitespace().collect();
        let body = &src[src.find("pubfnreserve(").expect("reserve")..];
        // The next item after `reserve` is `release`.
        let body = &body[..body.find("pub(super)fnrelease(").expect("end of reserve")];
        assert_eq!(body.matches("held_by_row(").count(), 1, "one question per reservation");
        let ask = body.find("held_by_row(").unwrap();
        let section = body.find("critical_section()").expect("the admission section");
        let closure = body.find("letres_=(||{").expect("the admission closure");
        let refuse = body.find("ifheld{returnErr(Refusal::Envelope);}").expect("the row's refusal is the closure's first step");
        let lock = body.find("ADMIT.lock_irqsave()").expect("the admission lock");
        assert!(ask < section && section < closure && closure < refuse && refuse < lock, "out of order");
        assert_eq!(&body[closure + "letres_=(||{".len()..][..refuse - closure - "letres_=(||{".len()], "", "something runs before the row's refusal");
        assert!(body.contains("idx<MAX_TASKS&&crate::rt_receipt::held_by_row("), "a bad slot is asked about");
    }

    /// The tie to `rt.rs`: `reserve` calls `record_refusal` exactly once, in
    /// the arm that handles the refusal (after the closure that holds the
    /// `ADMIT` lock has returned and after the `admission REFUSED` line), and
    /// the admitted arm does not call it.
    ///
    /// **Canary.** Delete the call from `rt.rs`: red. Move it into the
    /// `Ok(..)` arm: red. Add a second one: red.
    #[test]
    fn reserve_calls_record_refusal_once_from_its_refusal_arm() {
        let src = include_str!("../../../../crates/core/sched/src/rt.rs");
        let body = &src[src.find("pub fn reserve(").expect("reserve")..];
        let body = &body[..body.find("\n}\n").expect("end of reserve")];
        assert_eq!(body.matches("record_refusal(").count(), 1, "reserve must record each refusal once");
        let call = body.find("record_refusal(").unwrap();
        let closure_end = body.find("})();").expect("the admission closure");
        let ok_arm = body.find("Ok((cpu, density, load)) =>").expect("the admitted arm");
        let err_arm = body.find("Err(why) =>").expect("the refusal arm");
        let line = body.find("admission REFUSED").expect("the refusal line");
        assert!(closure_end < ok_arm && ok_arm < err_arm, "arms out of order");
        assert!(err_arm < line && line < call, "the record is not in the refusal arm after its line");
    }
}

/// **The accessors of "the task running here" read the hart id and the slot
/// in one masked window.** `current_cpu_id()` then `PER_CPU[cpu].current_idx`
/// is two steps; a tick between them moves the task and the second read
/// returns another hart's task (found 2026-10-20: a kernel page fault copying
/// to a user VA). `scheduler::on_this_hart` is the one place that masks
/// interrupts across the pair, and every accessor of the running task goes
/// through it (`here`, `my_idx`, `current_slot`, the filter verdicts).
///
/// This pins the shape: no code reads a per-hart `current_idx`/`current_filter`
/// right after a `current_cpu_id()` of its own, except the functions listed in
/// `MASKED` below, which run with interrupts already off (the tick, the
/// dispatcher, a `disable_all` section, an interrupt handler), where nothing
/// can move the task.
#[cfg(test)]
mod percpu_accessor_window {
    use super::tid_lookup::{body, code};

    /// Functions that keep a hart-then-slot read of their own, and why that
    /// is sound: interrupts are already masked there, or the answer is a
    /// placement or display hint a stale hart only makes less good.
    const MASKED: &[(&str, &str)] = &[
        ("on_this_hart", "the window itself"),
        ("here", "reads through on_this_hart"),
        ("task_entry_wrapper", "first instructions of a task, entered from the switch with interrupts off"),
        ("set_current_sched_params", "disable_all around the read and the writes"),
        ("set_current_partition", "disable_all around the read, for the tag cached under the id"),
        ("block_current", "disable_all at the top"),
        ("ipc_wake_target_cpu", "co-location hint of a wake: a stale hart costs a placement, never a wrong task"),
        ("task_running_on_other_hart", "documented snapshot: a stale answer costs one bounded spin or one block"),
    ];

    /// Every function that has `current_cpu_id()` and, within the next few
    /// code lines, a load of the per-hart slot or filter word.
    fn two_step_functions() -> Vec<String> {
        let c = code();
        let lines: Vec<&str> = c.lines().collect();
        let mut out = Vec::new();
        for (i, l) in lines.iter().enumerate() {
            if !l.contains("current_cpu_id()") || l.contains("fn current_cpu_id") {
                continue;
            }
            let near = lines[i..lines.len().min(i + 6)].join("\n");
            if !(near.contains("current_idx.load(") || near.contains("current_filter.load(")) {
                continue;
            }
            // The enclosing function: the nearest `fn` above.
            let name = lines[..=i]
                .iter()
                .rev()
                .find_map(|p| p.find("fn ").map(|a| p[a + 3..].split(|ch: char| !(ch.is_alphanumeric() || ch == '_')).next().unwrap().to_string()))
                .unwrap_or_default();
            out.push(name);
        }
        out
    }

    #[test]
    fn no_accessor_reads_the_hart_id_and_then_the_slot_with_interrupts_on() {
        let bad: Vec<String> = two_step_functions()
            .into_iter()
            .filter(|f| !MASKED.iter().any(|(m, _)| m == f))
            .collect();
        assert!(
            bad.is_empty(),
            "these read `current_cpu_id()` and then a per-hart slot of their own; \
             go through `on_this_hart` / `here` / `my_idx` (or list the function in \
             MASKED with the reason interrupts are already off): {bad:?}"
        );
    }

    #[test]
    fn the_masked_list_names_only_functions_that_still_have_the_two_steps() {
        let have = two_step_functions();
        let stale: Vec<&str> = MASKED
            .iter()
            .map(|(m, _)| *m)
            .filter(|m| !["on_this_hart", "here"].contains(m) && !have.iter().any(|f| f == m))
            .collect();
        assert!(stale.is_empty(), "MASKED lists functions without the pattern (delete the entries): {stale:?}");
    }

    #[test]
    fn nothing_indexes_the_per_hart_table_by_an_inline_hart_read() {
        assert!(
            !code().contains("PER_CPU[current_cpu_id()]"),
            "`PER_CPU[current_cpu_id()]` is the two-step in one expression"
        );
    }

    #[test]
    fn the_window_masks_between_the_id_and_the_table_read() {
        let c = code();
        let w = body(&c, "pub(crate) fn on_this_hart<R>(");
        let off = w.find("irq_off()").expect("on_this_hart no longer masks");
        let id = w.find("current_cpu_id()").expect("on_this_hart no longer reads the hart id");
        let read = w.find("read(cpu)").expect("on_this_hart no longer runs the read");
        let on = w.find("irq_restore(").expect("on_this_hart no longer restores");
        assert!(off < id && id < read && read < on, "mask, id, read, restore: {w}");
        assert!(
            w.contains("percpu-accessor-race-canary"),
            "the gate canary that removes the mask is gone: {w}"
        );
    }

    #[test]
    fn the_filter_verdicts_read_the_word_inside_the_window() {
        let c = code();
        for sig in [
            "pub fn current_syscall_verdict(",
            "pub fn current_iface_verdict(",
            "pub fn current_op_verdict(",
        ] {
            let b = body(&c, sig);
            assert!(b.contains("on_this_hart(|cpu|"), "{sig} reads the word outside the window: {b}");
            assert!(b.contains("PER_CPU[cpu].current_filter.load(Ordering::Relaxed)"), "{sig}: {b}");
        }
    }

    #[test]
    fn the_writers_act_through_a_slot_read_in_the_window() {
        let c = code();
        for sig in ["pub(crate) fn set_current_task_satp(", "pub fn set_current_user_info("] {
            let b = body(&c, sig);
            assert!(b.contains("my_idx()"), "{sig} writes through a slot read outside the window: {b}");
            assert!(!b.contains("current_cpu_id()"), "{sig}: {b}");
        }
    }
}

/// **A new thread cannot run before its page table is set.** `thread_create_impl`
/// queues the thread (`try_task_create_init`) and only then writes its
/// `task_satp`/`user_pt` (`set_task_thread_info`), so the thread may be running
/// on another hart in between. It is harmless only because its sole way out of
/// the wait loop in `fork_child_entry` is the hand-off `set_task_fork_ctx`
/// publishes, which comes after those stores in `thread_create_impl`; and a
/// stop request is a recorded word, so no other hart ends the thread before it
/// has taken that hand-off. If either order changes, move the stores into the
/// creation (`TaskInit`) instead.
#[cfg(test)]
mod thread_birth_order {
    const PROCESS: &str = include_str!("../../../../crates/core/sched/src/process.rs");

    fn code() -> String {
        PROCESS.lines().map(|l| l.split("//").next().unwrap()).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn thread_user_pt_is_set_before_its_hand_off() {
        let c = code();
        let b = super::tid_lookup::body(&c, "pub fn thread_create_impl(");
        let create = b.find("try_task_create_init(").expect("thread creation moved");
        let info = b.find("set_task_thread_info(").expect("the thread's page table is no longer set here");
        let ctx = b.find("set_task_fork_ctx(").expect("the thread's hand-off moved");
        assert!(create < info && info < ctx, "queue, then page table, then hand-off: {b}");
    }

    #[test]
    fn a_new_thread_leaves_its_wait_loop_only_through_the_hand_off() {
        let c = code();
        let b = super::tid_lookup::body(&c, "pub(crate) fn fork_child_entry(");
        let take = b.find("take_current_task_fork_ctx()").expect("the hand-off is no longer taken here");
        let first_exit = ["exit_if_forced(", "sret_to_user_forked(", "task_exit"]
            .iter()
            .filter_map(|s| b.find(s))
            .min()
            .expect("the wait loop has no exit at all");
        assert!(take < first_exit, "the child can exit or enter user mode before its hand-off: {b}");
        // Nothing in the loop reads the page table it is waiting for.
        assert!(!b.contains("user_pt"), "the wait loop reads user_pt: {b}");
    }
}

/// Proxy execution (`rt_core::proxy_chain`): which task runs a reservation
/// whose holder is blocked in a chain of calls.
#[cfg(test)]
mod proxy_tests {
    use super::rt_core::proxy_chain;

    /// Tasks 0..8: `blocked[t]`, `calls[t]` (the server `t` is blocked
    /// calling), `reserved[t]`.
    struct Chain {
        blocked: [bool; 8],
        calls: [Option<usize>; 8],
        reserved: [bool; 8],
    }

    impl Chain {
        fn proxy(&self, holder: usize, depth: usize) -> Option<usize> {
            proxy_chain(holder, depth, |t| self.blocked[t], |t| self.calls[t], |t| self.reserved[t])
        }
    }

    const A: usize = 1;
    const B: usize = 2;
    const C: usize = 3;

    /// A deadline task A (reserved) calls B (passive), which calls C
    /// (passive): A's reservation runs C, the end of the chain, and runs B
    /// once C has answered. An active server (its own reservation) at the end
    /// runs on its own: no proxy. A holder that runs is its own runner.
    ///
    /// **Canary** `rt-proxy-canary` (`cargo test --features rt-proxy-canary`):
    /// no proxy is ever found, and this test goes red.
    #[test]
    fn a_passive_server_runs_on_the_reservation_of_the_call_it_serves() {
        let mut c = Chain { blocked: [false; 8], calls: [None; 8], reserved: [false; 8] };
        c.reserved[A] = true;
        c.blocked[A] = true;
        c.calls[A] = Some(B);
        c.blocked[B] = true;
        c.calls[B] = Some(C);
        assert_eq!(c.proxy(A, 16), Some(C), "two hops: the server at the end of the chain");
        // C answers B: B runs again, on A's reservation.
        c.blocked[B] = false;
        c.calls[B] = None;
        assert_eq!(c.proxy(A, 16), Some(B));
        // An active server serves on its own reservation.
        c.reserved[B] = true;
        assert_eq!(c.proxy(A, 16), None);
        // A runs: nothing to proxy.
        c.reserved[B] = false;
        c.blocked[A] = false;
        assert_eq!(c.proxy(A, 16), None);
    }

    /// The chain is followed only through calls, only `depth` hops, and
    /// never around a cycle.
    #[test]
    fn the_chain_stops_at_anything_but_a_call_at_the_depth_and_at_a_cycle() {
        let mut c = Chain { blocked: [true; 8], calls: [None; 8], reserved: [false; 8] };
        c.reserved[A] = true;
        // A blocked on something that is not a call (a futex, its accept).
        assert_eq!(c.proxy(A, 16), None);
        // A -> B -> C -> 4 -> 5, all blocked but 5.
        c.calls[A] = Some(B);
        c.calls[B] = Some(C);
        c.calls[C] = Some(4);
        c.calls[4] = Some(5);
        c.blocked[5] = false;
        assert_eq!(c.proxy(A, 4), Some(5));
        assert_eq!(c.proxy(A, 3), None, "longer than the depth");
        // B waits on something else: the chain ends there, blocked.
        c.calls[B] = None;
        assert_eq!(c.proxy(A, 16), None);
        // A cycle back to the holder.
        c.calls[B] = Some(A);
        assert_eq!(c.proxy(A, 16), None);
    }
}
