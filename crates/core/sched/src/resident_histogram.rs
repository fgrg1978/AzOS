// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! O(`NUM_PRIORITIES`) per-CPU resident placement histogram (U02-3, task
//! 3a: `find_best_cpu` used to scan all `MAX_TASKS` from the timer ISR
//! and under `POOL_LOCK` on every fork).
//!
//! No `unsafe`, no global state: `scheduler` holds the one real instance
//! plus one recorded [`key`] per pool slot, and after every write to a
//! field the placement score depends on (`state`, `priority`,
//! `cpu_affinity`, `context.tp`, `TASK_VALID`) it recomputes that slot's
//! key and applies the old→new delta here. Everything in this file is
//! free code the host test runner (`tests/host/sched-wake-tests`) exercises
//! directly against the old full scan (`task::resident_load_contribution`).
//!
//! ## Why a histogram, not one scalar per CPU
//!
//! `find_best_cpu`'s score (`task::resident_load_contribution`) is
//! relative to the CANDIDATE task's own priority bucket:
//! `outranks = resident_competes(state) && resident_bucket <
//! target_bucket`. A single per-CPU counter cannot answer "how many
//! residents outrank a priority I am only told at query time" — the
//! histogram can, as a prefix sum over buckets `0..target_bucket`
//! (`NUM_PRIORITIES` = 32 today, so the query is O(32) per CPU instead of
//! O(`MAX_TASKS`), independent of the profile's `MAX_TASKS`).
//!
//! ## The two counts this keeps, per CPU
//!
//! - `total[cpu]`: every valid, non-`Zombie` resident, regardless of
//!   state (mirrors `find_best_cpu`'s own pre-filter, which skips only
//!   `Zombie`).
//! - `competing[cpu][bucket]`: valid, non-`Zombie`, non-`Blocked`
//!   ("competing", `task::resident_competes`) residents, by priority
//!   bucket. `blocking`/`rt_blocking` are prefix sums of this.
//!
//! ## Why a recorded key per slot, not typed per-transition mutators
//!
//! The first wiring called `add`/`migrate`/`set_competing`/`move_bucket`
//! at six enumerated transitions, each with the competing-ness the caller
//! believed the task had. A live `-smp 4` boot cross-checking every query
//! against the scan disagreed during boot. Reading the code found four
//! classes of transition the enumeration did not describe: `pi_boost_task`
//! / `pi_restore_task` move the bucket with no call; `block_current`'s
//! commit returns `true` on an already-`Blocked` re-entry (a second
//! "stop competing" for one task) and `false` after consuming a stamp on a
//! `Blocked` task (a resume with no "start competing"); `do_schedule`'s
//! K-C24 rescue CAS takes `Blocked` → `Ready`; and creation queries with
//! `exclude` naming a slot that `alloc_slot` has already published.
//!
//! A per-slot key removes the class: the caller does not describe the
//! transition, it only says "this slot's fields may have changed". The
//! delta is computed from what the slot was last ACCOUNTED as (the key,
//! swapped atomically) to what its fields say now. Two properties follow:
//!
//! 1. The histogram always equals the sum of the recorded keys, under any
//!    interleaving of concurrent `apply`s: each key value is swapped in by
//!    exactly one caller and swapped out by exactly one caller, so it is
//!    added once and removed once. This needs wrapping arithmetic — a
//!    removal may land before the matching addition, and a saturating
//!    counter would clip that transient -1 to 0 and drift permanently.
//!    Readers clamp a transient negative to 0.
//! 2. A missed call is self-healing: the next recompute for that slot, for
//!    whatever reason, corrects it.
//!
//! Every counter is atomic with `Ordering::Relaxed` (bucket counts packed
//! as `u16` lanes in `AtomicU64` words, see [`LANES`]), not a lock:
//! `find_best_cpu`'s answer has always been "approximate and unlocked" (a
//! stale sample costs at worst one suboptimal placement — see
//! `task::pick_cpu_by_load`), and under O3.1 a non-irqsave lock touched
//! from both the tick ISR and syscall context on one hart can self-deadlock.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// One CPU's placement score, in the shape `find_best_cpu` already
/// returns via `task::pick_cpu_by_load`.
pub type Load = crate::task::CpuLoad;

/// Duplicated from `scheduler::MAX_CPUS`, deliberately: `scheduler.rs`
/// cannot be pulled into the host test runner (`tests/host/sched-wake-tests`),
/// so this module cannot name it. `scheduler.rs` has a `const _: () =
/// assert!(...)` tying the two together.
pub const MAX_CPUS: usize = 8;

/// A slot's recorded contribution, packed into one `u32` so it can be
/// swapped atomically. `NONE` (all zero — what a `zeroed()` static holds)
/// means "contributes nothing": a free slot, a `Zombie`, or a slot not yet
/// accounted.
pub mod key {
    pub const NONE: u32 = 0;
    const ACCOUNTED: u32 = 1;
    const COMPETES: u32 = 1 << 1;
    const BUCKET_SHIFT: u32 = 2;
    const BUCKET_MASK: u32 = 0x3F;
    const CPU_SHIFT: u32 = 8;
    const CPU_MASK: u32 = 0xFF;

    const _: () = assert!(crate::task::NUM_PRIORITIES <= (BUCKET_MASK as usize) + 1);
    const _: () = assert!(super::MAX_CPUS <= (CPU_MASK as usize) + 1);

    /// A live, non-`Zombie` resident at `cpu`, in `bucket`, competing or not.
    #[inline]
    pub const fn pack(cpu: usize, bucket: usize, competes: bool) -> u32 {
        ACCOUNTED
            | if competes { COMPETES } else { 0 }
            | (((bucket as u32) & BUCKET_MASK) << BUCKET_SHIFT)
            | (((cpu as u32) & CPU_MASK) << CPU_SHIFT)
    }
    #[inline]
    pub const fn accounted(k: u32) -> bool {
        k & ACCOUNTED != 0
    }
    #[inline]
    pub const fn competes(k: u32) -> bool {
        k & COMPETES != 0
    }
    #[inline]
    pub const fn bucket(k: u32) -> usize {
        ((k >> BUCKET_SHIFT) & BUCKET_MASK) as usize
    }
    #[inline]
    pub const fn cpu(k: u32) -> usize {
        ((k >> CPU_SHIFT) & CPU_MASK) as usize
    }
}

/// Bucket counts are packed four to a word, one `u16` lane each, so a
/// prefix sum over buckets reads `NUM_PRIORITIES / 4` words and adds each
/// word's lanes with one multiply ([`lane_sum`]) instead of loading every
/// bucket. A lane cannot overflow into its neighbour: a count is at most
/// `MAX_TASKS`, asserted below 2^16.
const LANES: usize = 4;
const WORDS: usize = crate::task::NUM_PRIORITIES.div_ceil(LANES);
const _: () = assert!(crate::task::MAX_TASKS < (1 << 16));

/// `competing[cpu]` is one CPU's bucket row, packed.
type Row = [AtomicU64; WORDS];

/// Per-CPU resident placement histogram. `MAX_CPUS` rows.
pub struct ResidentHistogram {
    total: [AtomicU32; MAX_CPUS],
    competing: [Row; MAX_CPUS],
}

/// Sum of a word's four `u16` lanes: the multiply accumulates every lane
/// into the top one. Exact while the lanes sum below 2^16 (a CPU's
/// residents, at most `MAX_TASKS`).
#[inline]
fn lane_sum(x: u64) -> u32 {
    (x.wrapping_mul(0x0001_0001_0001_0001) >> 48) as u32
}

/// The `u64` that adds one to `bucket`'s lane of its word.
#[inline]
fn lane_one(bucket: usize) -> u64 {
    1u64 << (16 * (bucket % LANES))
}

/// A counter read that a concurrent `apply` may have left transiently
/// negative (wrapped): clamp to 0 rather than report ~4 billion residents.
#[inline]
fn read_clamped(a: &AtomicU32) -> u32 {
    let v = a.load(Ordering::Relaxed);
    if (v as i32) < 0 { 0 } else { v }
}

impl ResidentHistogram {
    pub const fn new() -> Self {
        Self {
            total: [const { AtomicU32::new(0) }; MAX_CPUS],
            competing: [const { [const { AtomicU64::new(0) }; WORDS] }; MAX_CPUS],
        }
    }

    #[inline]
    fn credit(&self, k: u32) {
        if !key::accounted(k) {
            return;
        }
        let cpu = key::cpu(k);
        if cpu >= MAX_CPUS {
            return;
        }
        self.total[cpu].fetch_add(1, Ordering::Relaxed);
        if key::competes(k) {
            let b = key::bucket(k);
            self.competing[cpu][b / LANES].fetch_add(lane_one(b), Ordering::Relaxed);
        }
    }

    #[inline]
    fn debit(&self, k: u32) {
        if !key::accounted(k) {
            return;
        }
        let cpu = key::cpu(k);
        if cpu >= MAX_CPUS {
            return;
        }
        self.total[cpu].fetch_sub(1, Ordering::Relaxed);
        if key::competes(k) {
            let b = key::bucket(k);
            self.competing[cpu][b / LANES].fetch_sub(lane_one(b), Ordering::Relaxed);
        }
    }

    /// Move one slot's contribution from `old` (the key it was recorded
    /// with, as returned by the caller's atomic `swap`) to `new`. A no-op
    /// when they are equal — the common case for a re-account that changed
    /// nothing the score depends on.
    #[inline]
    pub fn apply(&self, old: u32, new: u32) {
        if old == new {
            return;
        }
        // Same resident, same cpu (a block, a same-hart wake, a priority
        // change): `total` does not move, and only the competing lanes do —
        // one atomic for a block or a wake instead of four.
        let cpu = key::cpu(new);
        if key::accounted(old) && key::accounted(new) && key::cpu(old) == cpu && cpu < MAX_CPUS {
            let row = &self.competing[cpu];
            if key::competes(old) {
                let b = key::bucket(old);
                row[b / LANES].fetch_sub(lane_one(b), Ordering::Relaxed);
            }
            if key::competes(new) {
                let b = key::bucket(new);
                row[b / LANES].fetch_add(lane_one(b), Ordering::Relaxed);
            }
            return;
        }
        self.credit(new);
        self.debit(old);
    }

    /// `find_best_cpu`'s per-CPU score for a task of `target_bucket`.
    /// `rt_threshold` is `task::RT_PRIORITY_THRESHOLD` as a bucket index
    /// (buckets `< rt_threshold` are the RT band, same rule as
    /// `is_rt_priority`).
    pub fn load(&self, cpu: usize, target_bucket: usize, rt_threshold: usize) -> Load {
        let blocking = self.prefix(cpu, target_bucket);
        let rt_blocking = if rt_threshold >= target_bucket {
            blocking
        } else {
            self.prefix(cpu, rt_threshold)
        };
        Load { rt_blocking, blocking, total: read_clamped(&self.total[cpu]) }
    }

    /// Competing residents of `cpu` in buckets `0..n`. A read racing two
    /// `apply`s of one slot (see the module doc) can see a borrowed lane
    /// and return a wrong count; like every other read here, that costs
    /// one placement, and the counters themselves stay exact.
    #[inline]
    fn prefix(&self, cpu: usize, n: usize) -> u32 {
        let n = n.min(crate::task::NUM_PRIORITIES);
        let row = &self.competing[cpu];
        let full = n / LANES;
        let mut s: u32 = 0;
        for w in row.iter().take(full) {
            s = s.wrapping_add(lane_sum(w.load(Ordering::Relaxed)));
        }
        let rem = n % LANES;
        if rem != 0 {
            let mask = (1u64 << (16 * rem)) - 1;
            s = s.wrapping_add(lane_sum(row[full].load(Ordering::Relaxed) & mask));
        }
        s
    }

    /// [`load`](Self::load) with some slots left out — `find_best_cpu`'s
    /// `exclude`, or the IPC-affinity check's woken task and waker. The scan
    /// skips those slots outright; here each one's RECORDED contribution
    /// (its current key) is subtracted, which is the same thing whatever
    /// the query's `target_bucket`: `total` on its cpu, and the bucket sums
    /// when it competes in a bucket that outranks the target. Pass distinct
    /// slots' keys (the same key twice subtracts twice).
    pub fn load_excluding(
        &self,
        cpu: usize,
        target_bucket: usize,
        rt_threshold: usize,
        excluded: &[u32],
    ) -> Load {
        let mut l = self.load(cpu, target_bucket, rt_threshold);
        for &k in excluded {
            if !key::accounted(k) || key::cpu(k) != cpu {
                continue;
            }
            l.total = l.total.saturating_sub(1);
            let b = key::bucket(k);
            if key::competes(k) && b < target_bucket {
                l.blocking = l.blocking.saturating_sub(1);
                if b < rt_threshold {
                    l.rt_blocking = l.rt_blocking.saturating_sub(1);
                }
            }
        }
        l
    }
}

impl Default for ResidentHistogram {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::{is_rt_priority, resident_competes, resident_load_contribution, TaskState};

    fn bucket(prio: u32) -> usize {
        (prio as usize).min(crate::task::NUM_PRIORITIES - 1)
    }

    /// One synthetic resident, for the ground-truth full scan below.
    #[derive(Clone, Copy, PartialEq, Debug)]
    struct Resident {
        cpu: usize,
        prio: u32,
        state: TaskState,
    }

    /// The key `scheduler::hist_key_of` computes for a slot, from the same
    /// fields: `None` (free slot) and `Zombie` contribute nothing.
    fn key_of(r: Option<Resident>) -> u32 {
        match r {
            Some(r) if r.state != TaskState::Zombie => {
                key::pack(r.cpu, bucket(r.prio), resident_competes(r.state))
            }
            _ => key::NONE,
        }
    }

    /// The OLD algorithm, verbatim: a full scan over every resident,
    /// scoring each via the same pure `resident_load_contribution` the
    /// real `find_best_cpu_scan` calls, skipping `exclude` outright.
    fn full_scan(
        residents: &[Option<Resident>],
        cpu: usize,
        target_prio: u32,
        exclude: &[usize],
    ) -> Load {
        let target_bucket = bucket(target_prio);
        let mut acc = Load { rt_blocking: 0, blocking: 0, total: 0 };
        for (i, r) in residents.iter().enumerate() {
            let Some(r) = r else { continue };
            if exclude.contains(&i) || r.cpu != cpu || r.state == TaskState::Zombie {
                continue;
            }
            let (rt, blk, tot) = resident_load_contribution(
                r.state,
                bucket(r.prio),
                is_rt_priority(r.prio),
                target_bucket,
            );
            acc.rt_blocking += rt;
            acc.blocking += blk;
            acc.total += tot;
        }
        acc
    }

    const RT_THRESHOLD: usize = crate::task::RT_PRIORITY_THRESHOLD as usize;

    struct Xorshift32(u32);
    impl Xorshift32 {
        fn next(&mut self) -> u32 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.0 = x;
            x
        }
        fn below(&mut self, n: u32) -> u32 {
            self.next() % n
        }
    }

    #[test]
    fn empty_histogram_scores_zero() {
        let h = ResidentHistogram::new();
        let l = h.load(0, 16, RT_THRESHOLD);
        assert_eq!((l.rt_blocking, l.blocking, l.total), (0, 0, 0));
    }

    #[test]
    fn key_round_trips_every_field() {
        for cpu in 0..MAX_CPUS {
            for b in 0..crate::task::NUM_PRIORITIES {
                for c in [false, true] {
                    let k = key::pack(cpu, b, c);
                    assert!(key::accounted(k));
                    assert_ne!(k, key::NONE);
                    assert_eq!((key::cpu(k), key::bucket(k), key::competes(k)), (cpu, b, c));
                }
            }
        }
        assert!(!key::accounted(key::NONE));
    }

    /// The replay: every step picks a slot and rewrites ANY of the fields
    /// the score depends on — create, free, state (all four, including
    /// `Blocked` → `Running` and `Blocked` → `Zombie`, which the typed
    /// transitions never modelled), priority in any state, home cpu in any
    /// state — then re-accounts that slot exactly the way the scheduler
    /// does (swap the recorded key, `apply(old, new)`). After EVERY step,
    /// every cpu × target is checked against the scan, both plain and with
    /// a random slot excluded at an arbitrary target priority (no
    /// "target must be the excluded task's own bucket" precondition).
    #[test]
    fn random_field_replay_matches_full_scan_at_every_step() {
        const N_TASKS: usize = 40;
        let states = [TaskState::Ready, TaskState::Running, TaskState::Blocked, TaskState::Zombie];

        let mut rng = Xorshift32(0xC0FF_EE01);
        let h = ResidentHistogram::new();
        let mut residents: [Option<Resident>; N_TASKS] = [None; N_TASKS];
        let mut keys = [key::NONE; N_TASKS];

        for step in 0..4000 {
            let slot = rng.below(N_TASKS as u32) as usize;
            let next = match residents[slot] {
                None => Some(Resident {
                    cpu: rng.below(MAX_CPUS as u32) as usize,
                    prio: rng.below(32),
                    state: TaskState::Ready,
                }),
                Some(r) => match rng.below(5) {
                    0 => Some(Resident { state: states[rng.below(4) as usize], ..r }),
                    1 => Some(Resident { prio: rng.below(40), ..r }),
                    2 => Some(Resident { cpu: rng.below(MAX_CPUS as u32) as usize, ..r }),
                    3 => Some(Resident {
                        cpu: rng.below(MAX_CPUS as u32) as usize,
                        state: states[rng.below(4) as usize],
                        ..r
                    }),
                    _ => None,
                },
            };
            residents[slot] = next;
            let new = key_of(next);
            let old = core::mem::replace(&mut keys[slot], new);
            h.apply(old, new);

            let excl = rng.below(N_TASKS as u32) as usize;
            // A second, distinct excluded slot (the IPC-affinity check
            // excludes the woken task and the waker).
            let excl2 = (excl + 1 + rng.below(N_TASKS as u32 - 1) as usize) % N_TASKS;
            for cpu in 0..MAX_CPUS {
                for target in [0u32, 5, 8, 11, 12, 16, 24, 31, 35] {
                    let got = h.load(cpu, bucket(target), RT_THRESHOLD);
                    let want = full_scan(&residents, cpu, target, &[]);
                    assert_eq!(got, want, "step {step}: cpu={cpu} target={target}");
                    let got = h.load_excluding(cpu, bucket(target), RT_THRESHOLD, &[keys[excl]]);
                    let want = full_scan(&residents, cpu, target, &[excl]);
                    assert_eq!(got, want, "step {step}: cpu={cpu} target={target} excl={excl}");
                    let got = h.load_excluding(
                        cpu, bucket(target), RT_THRESHOLD, &[keys[excl], keys[excl2]],
                    );
                    let want = full_scan(&residents, cpu, target, &[excl, excl2]);
                    assert_eq!(got, want, "step {step}: cpu={cpu} target={target} excl={excl},{excl2}");
                }
            }
        }
    }

    /// Two re-accounts of ONE slot racing on two harts, in the order that
    /// hurts: A swaps k0→kA, B swaps kA→kB, and B's debit of kA lands
    /// before A's credit of kA. The counters must end exactly at kB's
    /// contribution; a saturating counter clips B's early debit at 0 and
    /// keeps a phantom resident forever.
    #[test]
    fn interleaved_applies_on_one_slot_end_exact() {
        let h = ResidentHistogram::new();
        let k0 = key::pack(0, 3, true);
        let ka = key::pack(1, 3, true);
        let kb = key::pack(2, 5, false);
        h.apply(key::NONE, k0);
        // A: swap returned k0, installs kA. B: swap returned kA, installs kB.
        // Order of effects: B.credit(kB), B.debit(kA), A.credit(kA), A.debit(k0).
        h.credit(kb);
        h.debit(ka);
        // Mid-race read of cpu 1: `total` transiently -1, must read as 0.
        // (The packed bucket lane is garbage at this instant — documented.)
        assert_eq!(h.load(1, 31, RT_THRESHOLD).total, 0);
        h.credit(ka);
        h.debit(k0);
        for cpu in 0..MAX_CPUS {
            let want_total = u32::from(cpu == 2);
            let l = h.load(cpu, 31, RT_THRESHOLD);
            assert_eq!((l.rt_blocking, l.blocking, l.total), (0, 0, want_total), "cpu={cpu}");
        }
    }

    /// Lanes do not bleed into each other: a bucket far fuller than any
    /// real one (1000 residents) leaves its neighbours' prefix sums exact.
    #[test]
    fn packed_lanes_stay_independent() {
        let h = ResidentHistogram::new();
        for _ in 0..1000 {
            h.apply(key::NONE, key::pack(0, 3, true));
        }
        h.apply(key::NONE, key::pack(0, 4, true));
        h.apply(key::NONE, key::pack(0, 31, true));
        assert_eq!(h.prefix(0, 3), 0);
        assert_eq!(h.prefix(0, 4), 1000);
        assert_eq!(h.prefix(0, 5), 1001);
        assert_eq!(h.prefix(0, 31), 1001);
        assert_eq!(h.prefix(0, 32), 1002);
        assert_eq!(h.load(0, 16, RT_THRESHOLD).total, 1002);
        assert_eq!(h.prefix(1, 32), 0);
    }

    /// A missed re-account heals at the slot's next one: the key records
    /// what was last accounted, so the delta then covers both changes.
    #[test]
    fn missed_reaccount_heals_on_the_next_one() {
        let h = ResidentHistogram::new();
        let r0 = Resident { cpu: 0, prio: 4, state: TaskState::Running };
        let k0 = key_of(Some(r0));
        h.apply(key::NONE, k0);
        // Field change with NO apply (the bug class): blocked on cpu 0.
        let r1 = Resident { state: TaskState::Blocked, ..r0 };
        let arr1 = [Some(r1)];
        assert_ne!(h.load(0, 16, RT_THRESHOLD), full_scan(&arr1, 0, 16, &[]));
        // Next transition, re-accounted: woken onto cpu 3 at prio 9.
        let r2 = Resident { cpu: 3, prio: 9, state: TaskState::Ready };
        h.apply(k0, key_of(Some(r2)));
        let arr2 = [Some(r2)];
        for cpu in 0..MAX_CPUS {
            assert_eq!(h.load(cpu, 16, RT_THRESHOLD), full_scan(&arr2, cpu, 16, &[]), "cpu={cpu}");
        }
    }
}
