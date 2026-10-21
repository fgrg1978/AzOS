// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The arithmetic of the fair class: EEVDF (Earliest Eligible Virtual
//! Deadline First, Stoica and Abdel-Wahab 1995; Linux 6.6's fair class), with
//! no scheduler state in it.
//!
//! `scheduler.rs` cannot be compiled for the host, so everything that decides
//! *who runs next*, *how much a run costs* and *what a sleeper keeps* lives
//! here, and `tests/host/sched-policy-tests` pulls this file in with
//! `#[path]`. `fairq.rs` only stores the per-task numbers, walks the ready
//! lists and calls these functions. `core` only: weights, slices and the tick
//! come in as arguments, never from `azos_limits`.
//!
//! # The model
//!
//! Each entity has a weight `w` (a nice level through [`WEIGHTS`], Linux's
//! `sched_prio_to_weight`), a slice `r` (a time) and a virtual runtime `v`
//! that advances `dt * 1024 / w` while it runs ([`vdelta`]). Its *virtual
//! deadline* is `d = v + r * 1024 / w` ([`vslice`]), renewed when `v` reaches
//! it. With `V` the weighted mean of the `v` of every entity on the queue
//! (the running one included), an entity is *eligible* when `v <= V` (its
//! *lag* `V - v` is not negative: it is not owed less than it has had). The
//! pick is the eligible entity with the earliest deadline ([`choose`]).
//!
//! Eligibility bounds how far ahead of its share an entity can get; the
//! deadline order lets a short slice be served soon without more than its
//! share: a small `r` is an early `d`.
//!
//! # Units
//!
//! `dt`, `slice` and `tick` are counts of one monotonic time unit (the kernel
//! passes the timer counter's ticks, never scheduler ticks: a task that runs
//! 40 us and blocks must still be charged). `v` and `d` are `i64` in the same
//! unit scaled by `1024 / w`. Sums are `i128`, so nothing here overflows or
//! panics inside the timer interrupt; every other operation saturates.
//!
//! # Lag
//!
//! A sleeper keeps its lag, not its `v`: [`lag_on_sleep`] stores
//! `V - v` (clamped to `+-` [`lag_limit`], two slices or one tick, whichever
//! is longer, converted to virtual time), and [`place_wake`] gives the waking
//! entity `v = V - lag * (W + w) / W` (`W` the weight already queued, so that
//! `V - v` is the stored lag again once it has joined). An entity that slept
//! an hour returns at most two slices ahead; one that was owed service
//! returns owed at most two slices, not an hour.
//!
//! # Why no tree
//!
//! Linux keeps the queue in an rb-tree augmented with the subtree's minimum
//! deadline (O(log n) pick). Here the *membership* of a ready queue is the
//! per-priority ready lists (`ready_list.rs`): `queued` (K-C12), the removal
//! paths, the claim audit and the K-C24/K-C26 re-enqueues are all written
//! against them. A tree would be a second membership structure with its own
//! copy of each of those invariants, and it would buy nothing at the queue
//! lengths this kernel has: a hart's ready *fair* set, not `MAX_TASKS`, is
//! what [`choose`] walks (two passes, no allocation, no stored sums that a
//! missed hook could leave wrong: the mean is recomputed from the members
//! every time). If a fleet profile shows that walk in a profile, the tree
//! goes behind this same interface.
//!
//! # The hook
//!
//! `weight` and `slice` are fields of [`Ent`], supplied by the caller. The
//! kernel derives them from the priority today (`fairq::params`); `qos_id`
//! will override them there, and nothing in this file changes.

/// Weight of nice level 0, the unit of virtual time.
pub const NICE_0_WEIGHT: u32 = 1024;

/// Linux's `sched_prio_to_weight`: nice -20 (index 0) to 19 (index 39),
/// 1.25 x per level, 1024 at nice 0.
pub const WEIGHTS: [u32; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, //
    9548, 7620, 6100, 4904, 3906, 3121, 2501, 1991, 1586, 1277, //
    1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, //
    110, 87, 70, 56, 45, 36, 29, 23, 18, 15,
];

/// The weight of a nice level; outside -20..=19 the nearest end.
#[inline]
pub const fn weight_of_nice(nice: i32) -> u32 {
    let i = nice as i64 + 20;
    let i = if i < 0 {
        0
    } else if i > 39 {
        39
    } else {
        i
    };
    WEIGHTS[i as usize]
}

/// The weight of priority `prio` when `nice0` is the priority that weighs
/// [`NICE_0_WEIGHT`]: a lower priority number is a better (lower) nice.
#[inline]
pub const fn weight_of_prio(prio: u32, nice0: u32) -> u32 {
    weight_of_nice(prio as i32 - nice0 as i32)
}

/// One entity's numbers. `vruntime` and `deadline` are virtual time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ent {
    /// Share of the CPU against the other entities (> 0).
    pub weight: u32,
    /// The run it asks for before its deadline, in time units. A short slice
    /// is an early deadline (lower latency), not a bigger share.
    pub slice: u64,
    /// Virtual runtime: service received, scaled by `1024 / weight`.
    pub vruntime: i64,
    /// Virtual deadline: when the slice it asked for is due.
    pub deadline: i64,
}

impl Ent {
    /// An entity that has not run: `v = 0` and its first deadline one slice on.
    pub fn new(weight: u32, slice: u64) -> Self {
        let mut e = Self { weight, slice, vruntime: 0, deadline: 0 };
        e.deadline = vslice(&e);
        e
    }
}

/// Virtual time `dt` of real time costs an entity of `weight`.
/// `eevdf-weight-canary`: weight ignored, every entity pays the same.
#[inline]
pub fn vdelta(dt: u64, weight: u32) -> i64 {
    #[cfg(feature = "eevdf-weight-canary")]
    let weight = NICE_0_WEIGHT;
    let v = dt.saturating_mul(NICE_0_WEIGHT as u64) / weight.max(1) as u64;
    v.min(i64::MAX as u64) as i64
}

/// The virtual length of `e`'s slice (at least 1: a zero-length slice is a
/// deadline that is already due).
#[inline]
pub fn vslice(e: &Ent) -> i64 {
    vdelta(e.slice, e.weight).max(1)
}

/// How far a sleeper's lag may go either way, in virtual time: two slices or
/// one `tick`, whichever is longer (Linux's limit).
#[inline]
pub fn lag_limit(e: &Ent, tick: u64) -> i64 {
    vdelta(e.slice.saturating_mul(2).max(tick), e.weight).max(1)
}

#[inline]
fn clamp_lag(lag: i64, limit: i64) -> i64 {
    // `eevdf-noclamp-canary`: a sleeper keeps whatever lag it left with.
    if cfg!(feature = "eevdf-noclamp-canary") {
        lag
    } else {
        lag.clamp(-limit, limit)
    }
}

/// `e` ran for `dt`: advance `v`, and renew the deadline if `v` reached it.
/// Returns whether the slice ended.
#[inline]
pub fn charge(e: &mut Ent, dt: u64) -> bool {
    e.vruntime = e.vruntime.saturating_add(vdelta(dt, e.weight));
    if e.vruntime >= e.deadline {
        e.deadline = e.vruntime.saturating_add(vslice(e));
        true
    } else {
        false
    }
}

/// `e` gives up the CPU voluntarily: its deadline moves one slice on, so an
/// entity that is eligible and next in deadline order does not take the CPU
/// straight back.
#[inline]
pub fn yield_now(e: &mut Ent) {
    e.deadline = e.deadline.saturating_add(vslice(e));
}

/// The weighted mean of the `v` of a set of entities, kept as the anchor
/// `v0`, the total weight `W` and `S = sum w_i * (v_i - v0)`. Nothing is
/// divided until [`mean`](Self::mean): eligibility is the exact comparison
/// `S >= (v - v0) * W`.
#[derive(Clone, Copy, Debug)]
pub struct Avg {
    anchor: i64,
    w: u64,
    s: i128,
}

impl Avg {
    /// The empty set.
    pub const fn new() -> Self {
        Self { anchor: 0, w: 0, s: 0 }
    }

    /// Add `e` to the set.
    pub fn add(&mut self, e: &Ent) {
        if self.w == 0 {
            self.anchor = e.vruntime;
        }
        self.w += e.weight as u64;
        self.s += e.weight as i128 * (e.vruntime as i128 - self.anchor as i128);
    }

    /// Nothing in the set.
    pub fn is_empty(&self) -> bool {
        self.w == 0
    }

    /// `V`: the weighted mean (rounded toward the anchor); `None` for the
    /// empty set. The sum is clamped to `i64` before the divide (an `i128`
    /// divide is a library call): it is a few slices times the queued weight,
    /// far inside `i64`.
    pub fn mean(&self) -> Option<i64> {
        if self.w == 0 {
            return None;
        }
        let s = self.s.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
        Some(self.anchor.saturating_add(s / self.w.min(i64::MAX as u64) as i64))
    }

    /// Is `e` eligible (`v <= V`)? Everything is, in the empty set.
    /// `eevdf-eligible-canary`: everything is eligible, always.
    pub fn eligible(&self, e: &Ent) -> bool {
        if cfg!(feature = "eevdf-eligible-canary") || self.w == 0 {
            return true;
        }
        self.s >= (e.vruntime as i128 - self.anchor as i128) * self.w as i128
    }
}

impl Default for Avg {
    fn default() -> Self {
        Self::new()
    }
}

/// The mean over a set of entities.
pub fn avg_of(it: impl Iterator<Item = Ent>) -> Avg {
    let mut a = Avg::new();
    for e in it {
        a.add(&e);
    }
    a
}

/// `e` is leaving the queue (it blocks, or moves): the lag it keeps.
/// `others` is every entity that stays, the running one included.
pub fn lag_on_sleep(others: &Avg, e: &Ent, tick: u64) -> i64 {
    let mut with = *others;
    with.add(e);
    let v = with.mean().unwrap_or(e.vruntime);
    clamp_lag(v.saturating_sub(e.vruntime), lag_limit(e, tick))
}

/// `e` joins the queue `others` (every entity already there, the running one
/// included). `lag`: what [`lag_on_sleep`] stored; `None` for an entity that
/// left without it, which keeps its `v`, held within the lag limit of `V`.
/// Either way the deadline is one slice past the new `v`.
pub fn place_wake(others: &Avg, e: &mut Ent, lag: Option<i64>, tick: u64) {
    // `eevdf-nowake-canary`: the waker keeps the `v` it slept with.
    if !cfg!(feature = "eevdf-nowake-canary") {
        if let Some(v) = others.mean() {
            let lim = lag_limit(e, tick);
            e.vruntime = match lag {
                Some(l) => {
                    let l = clamp_lag(l, lim);
                    // l * (W + w) / W, as l + l * w / W: no product past i64
                    // (|l| is a few slices, w < 2^17).
                    let share = l.saturating_mul(e.weight as i64) / others.w.min(i64::MAX as u64) as i64;
                    v.saturating_sub(l).saturating_sub(share)
                }
                None => {
                    if cfg!(feature = "eevdf-noclamp-canary") {
                        e.vruntime
                    } else {
                        e.vruntime.clamp(v.saturating_sub(lim), v.saturating_add(lim))
                    }
                }
            };
        }
    }
    e.deadline = e.vruntime.saturating_add(vslice(e));
}

/// What [`choose`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    /// Nothing is runnable.
    Empty,
    /// The running entity keeps the CPU.
    Cur,
    /// This queued entity takes it.
    Task(usize),
}

/// The pick: among the queued entities (`queued` is walked twice, in the same
/// order, so it is a function) and the running one `cur`, the eligible
/// one with the earliest deadline. Ties go to `cur`, then to the first queued
/// (FIFO). `V` is the mean over the queue and `cur`.
///
/// `eevdf-fifo-canary`: the first eligible queued entity, not the earliest
/// deadline (a round robin over the eligible).
pub fn choose<I>(queued: impl Fn() -> I, cur: Option<(usize, Ent)>) -> Choice
where
    I: Iterator<Item = (usize, Ent)>,
{
    let mut avg = Avg::new();
    let mut n = 0usize;
    for (_, e) in queued() {
        avg.add(&e);
        n += 1;
    }
    if n == 0 {
        return if cur.is_some() { Choice::Cur } else { Choice::Empty };
    }
    if let Some((_, c)) = &cur {
        avg.add(c);
    }
    let mut best: Option<(usize, i64)> = None;
    for (id, e) in queued() {
        if !avg.eligible(&e) {
            continue;
        }
        if cfg!(feature = "eevdf-fifo-canary") {
            best = Some((id, e.deadline));
            break;
        }
        if best.is_none_or(|(_, d)| e.deadline < d) {
            best = Some((id, e.deadline));
        }
    }
    match (best, cur) {
        // The mean lies between the smallest and the largest `v`, so a queued
        // entity is eligible unless `cur` is the one below it, and then `cur`
        // is. A queue with a member and no eligible one cannot happen; the
        // earliest deadline overall keeps the answer total anyway.
        (None, Some(_)) => Choice::Cur,
        (None, None) => queued()
            .min_by_key(|(_, e)| e.deadline)
            .map_or(Choice::Empty, |(id, _)| Choice::Task(id)),
        (Some((id, _)), None) => Choice::Task(id),
        (Some((id, d)), Some((_, c))) => {
            if avg.eligible(&c) && c.deadline <= d {
                Choice::Cur
            } else {
                Choice::Task(id)
            }
        }
    }
}

/// Does `cand` come before `cur` in deadline order (the fair class's
/// `preempt_check`)?
#[inline]
pub fn before(cand: &Ent, cur: &Ent) -> bool {
    cand.deadline < cur.deadline
}
