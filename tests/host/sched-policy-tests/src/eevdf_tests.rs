// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of `crates/core/sched/src/eevdf_core.rs`.
//!
//! The simulator below is the kernel's flow (`fairq.rs`) with the lists and
//! the locks taken out: the running entity is not in the queue but counts in
//! the mean; a tick charges it and asks `choose`; a sleep stores the lag; a
//! wake places the entity against the queue and the running one.
//!
//! Canary discipline (three buckets), run with `cargo +stable test --features
//! <canary>`; the tests it must turn red are in the table. A canary that
//! turned nothing red would be a check that does not discriminate.
//!
//! | canary | breaks | red tests |
//! |---|---|---|
//! | `eevdf-weight-canary` | the virtual clock ignores the weight | `shares_follow_weights_*`, `vdelta_scales_with_weight`, `a_heavier_entity_gets_a_later_virtual_deadline_per_slice`, `lag_is_clamped_when_stored` |
//! | `eevdf-eligible-canary` | everything is eligible | `choose_matches_the_definition`, `a_runner_ahead_of_its_share_yields`, `an_ineligible_entity_is_not_picked_whatever_its_deadline`, `the_mean_is_weighted_and_eligibility_is_exact`, `a_short_slice_is_served_within_its_deadline` |
//! | `eevdf-fifo-canary` | first eligible, not earliest deadline | `choose_matches_the_definition`, `an_earlier_deadline_wins_among_the_eligible`, `a_short_slice_is_served_within_its_deadline` |
//! | `eevdf-noclamp-canary` | lag never clamped | `lag_is_clamped_when_stored`, `lag_is_clamped_when_placed`, `a_sleeper_that_left_without_a_lag_does_not_starve_the_others` |
//! | `eevdf-nowake-canary` | a waker keeps its old `v` | `lag_survives_a_sleep`, `lag_is_clamped_when_placed`, `a_long_sleeper_does_not_starve_the_others`, `a_sleeper_that_left_without_a_lag_does_not_starve_the_others`, `a_short_slice_is_served_within_its_deadline` |

use super::eevdf_core::*;

const SLICE: u64 = 3000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum St {
    Queued,
    Asleep,
}

struct T {
    e: Ent,
    st: St,
    /// What the last sleep stored (`None`: it left without).
    lag: Option<i64>,
    ran: u64,
}

struct Sim {
    t: Vec<T>,
    cur: Option<usize>,
    tick: u64,
}

impl Sim {
    fn new(tick: u64) -> Self {
        Self { t: Vec::new(), cur: None, tick }
    }

    /// The queue as the kernel walks it: the queued entities, `cur` apart.
    fn queued(&self) -> impl Iterator<Item = (usize, Ent)> + '_ {
        self.t
            .iter()
            .enumerate()
            .filter(|(i, t)| t.st == St::Queued && Some(*i) != self.cur)
            .map(|(i, t)| (i, t.e))
    }

    fn cur_ent(&self) -> Option<(usize, Ent)> {
        self.cur.map(|c| (c, self.t[c].e))
    }

    /// Everything on the queue except `skip`, the running entity included.
    fn others(&self, skip: usize) -> Avg {
        avg_of(self.queued().filter(|(i, _)| *i != skip).map(|(_, e)| e).chain(
            self.cur_ent().filter(|(c, _)| *c != skip).map(|(_, e)| e),
        ))
    }

    /// A new entity, woken at once with the lag 0 a fresh task has.
    fn add(&mut self, weight: u32, slice: u64) -> usize {
        self.t.push(T { e: Ent::new(weight, slice), st: St::Asleep, lag: Some(0), ran: 0 });
        let i = self.t.len() - 1;
        self.wake(i);
        i
    }

    fn wake(&mut self, i: usize) {
        assert_eq!(self.t[i].st, St::Asleep);
        let o = self.others(i);
        let lag = self.t[i].lag.take();
        place_wake(&o, &mut self.t[i].e, lag, self.tick);
        self.t[i].st = St::Queued;
    }

    /// `i` blocks. It is the running entity or queued.
    fn sleep(&mut self, i: usize) {
        let o = self.others(i);
        self.t[i].lag = Some(lag_on_sleep(&o, &self.t[i].e, self.tick));
        self.t[i].st = St::Asleep;
        if self.cur == Some(i) {
            self.cur = None;
            self.decide();
        }
    }

    /// `do_schedule`: the pick, with the running entity a candidate.
    fn decide(&mut self) {
        let c = choose(|| self.queued(), self.cur_ent());
        if let Choice::Task(i) = c {
            self.cur = Some(i);
        }
    }

    /// The timer tick: charge the runner for `dt`, then decide.
    fn run(&mut self, dt: u64) {
        if let Some(c) = self.cur {
            self.t[c].ran += dt;
            charge(&mut self.t[c].e, dt);
        }
        self.decide();
    }

    fn v_mean(&self) -> i64 {
        avg_of(self.queued().map(|(_, e)| e).chain(self.cur_ent().map(|(_, e)| e)))
            .mean()
            .unwrap()
    }
}

/// Deterministic generator (xorshift64*).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

// ───────────────────────────── the clock and the table ─────────────────────

#[test]
fn the_weight_table_is_linuxs() {
    assert_eq!(WEIGHTS.len(), 40);
    assert_eq!(weight_of_nice(0), NICE_0_WEIGHT);
    assert_eq!(weight_of_nice(-20), 88761);
    assert_eq!(weight_of_nice(19), 15);
    assert_eq!(weight_of_nice(-100), 88761, "past the table: the end");
    assert_eq!(weight_of_nice(100), 15);
    for w in WEIGHTS.windows(2) {
        let r = w[0] as f64 / w[1] as f64;
        assert!((1.2..1.3).contains(&r), "1.25x per level, got {r}");
    }
}

#[test]
fn the_priority_scale_puts_nice_zero_at_the_default() {
    // The fair levels are 12..=30; the default priority is 16.
    assert_eq!(weight_of_prio(16, 16), 1024);
    assert_eq!(weight_of_prio(12, 16), 2501, "four levels better: nice -4");
    assert_eq!(weight_of_prio(30, 16), 45, "fourteen worse: nice 14");
    assert!(weight_of_prio(12, 16) > weight_of_prio(13, 16));
}

#[test]
fn vdelta_scales_with_weight() {
    assert_eq!(vdelta(1000, 1024), 1000);
    assert_eq!(vdelta(1000, 2048), 500, "twice the weight ages half as fast");
    assert_eq!(vdelta(1000, 512), 2000);
    assert_eq!(vdelta(u64::MAX, 1), i64::MAX, "saturates");
}

#[test]
fn a_heavier_entity_gets_a_later_virtual_deadline_per_slice() {
    let a = Ent::new(1024, SLICE);
    let b = Ent::new(2048, SLICE);
    assert_eq!(vslice(&a), 3000);
    assert_eq!(vslice(&b), 1500, "the same slice is half the virtual time at twice the weight");
    // A zero-length slice would be a deadline that is already due.
    assert_eq!(vslice(&Ent::new(1024, 0)), 1);
}

#[test]
fn charge_renews_the_deadline_when_the_slice_is_used() {
    let mut e = Ent::new(1024, SLICE);
    assert!(!charge(&mut e, 2999));
    assert_eq!((e.vruntime, e.deadline), (2999, 3000));
    assert!(charge(&mut e, 1), "v reaches the deadline");
    assert_eq!((e.vruntime, e.deadline), (3000, 6000), "a slice past the new v");
}

// ───────────────────────────────── the mean ────────────────────────────────

#[test]
fn the_mean_is_weighted_and_eligibility_is_exact() {
    let mut a = Entities::default();
    // v=0 w=1024 and v=3000 w=3072: V = 2250.
    a.push(1024, 0);
    a.push(3072, 3000);
    let avg = avg_of(a.0.iter().copied());
    assert_eq!(avg.mean(), Some(2250));
    assert!(avg.eligible(&a.0[0]));
    assert!(!avg.eligible(&a.0[1]), "3000 > 2250");
    let mut at = a.0[1];
    at.vruntime = 2250;
    assert!(avg.eligible(&at), "v == V is eligible");
    at.vruntime = 2251;
    assert!(!avg.eligible(&at));
    assert_eq!(Avg::new().mean(), None);
    assert!(Avg::new().eligible(&at), "everything is eligible in the empty set");
}

#[derive(Default)]
struct Entities(Vec<Ent>);
impl Entities {
    fn push(&mut self, w: u32, v: i64) {
        let mut e = Ent::new(w, SLICE);
        e.vruntime = v;
        e.deadline = v + vslice(&e);
        self.0.push(e);
    }
}

// ───────────────────────────────── fairness ────────────────────────────────

fn shares(weights: &[u32], slices: &[u64], total: u64, tick: u64) -> Vec<f64> {
    let mut s = Sim::new(tick);
    for (w, r) in weights.iter().zip(slices) {
        s.add(*w, *r);
    }
    s.decide();
    for _ in 0..total / tick {
        s.run(tick);
    }
    let sum: u64 = s.t.iter().map(|t| t.ran).sum();
    assert_eq!(sum, total / tick * tick, "every tick belongs to somebody");
    s.t.iter().map(|t| t.ran as f64 / sum as f64).collect()
}

#[test]
fn shares_follow_weights_one_to_two() {
    for tick in [100u64, 1000] {
        let sh = shares(&[1024, 2048], &[SLICE, SLICE], 3_000_000, tick);
        let ratio = sh[1] / sh[0];
        assert!((1.95..2.05).contains(&ratio), "tick {tick}: shares {sh:?}, ratio {ratio}");
    }
}

#[test]
fn shares_follow_weights_four_entities() {
    let w = [1024, 2048, 4096, 512];
    let sh = shares(&w, &[SLICE; 4], 7_600_000, 1000);
    let tot: f64 = w.iter().map(|&x| x as f64).sum();
    for (i, x) in sh.iter().enumerate() {
        let want = w[i] as f64 / tot;
        assert!((x - want).abs() < 0.01, "entity {i}: {x} vs {want}");
    }
}

#[test]
fn shares_follow_weights_across_nice_levels() {
    // Priorities 12 and 16 of the kernel's scale: 2501 against 1024.
    let w = [weight_of_prio(12, 16), weight_of_prio(16, 16)];
    let sh = shares(&w, &[SLICE; 2], 3_000_000, 1000);
    let want = w[0] as f64 / w[1] as f64;
    let got = sh[0] / sh[1];
    assert!((got / want - 1.0).abs() < 0.03, "got {got}, want {want}");
}

#[test]
fn equal_weights_with_different_slices_still_share_equally() {
    // The slice is a latency knob, not a share: 300 against 6000.
    let sh = shares(&[1024, 1024], &[300, 6000], 3_000_000, 100);
    assert!((sh[0] - 0.5).abs() < 0.02, "{sh:?}");
}

// ───────────────────────────────── latency ─────────────────────────────────

/// Wakes entity `x` every `period` with lag 0 (a task that is new, or owed
/// nothing: `v = V`), for `work`; returns the waits (wake to dispatch) over
/// `cycles` cycles. The hogs never sleep.
fn waits(
    hogs: usize,
    x_weight: u32,
    x_slice: u64,
    tick: u64,
    period: u64,
    work: u64,
    cycles: usize,
) -> Vec<u64> {
    let mut s = Sim::new(tick);
    for _ in 0..hogs {
        s.add(1024, SLICE);
    }
    s.decide();
    let x = s.add(x_weight, x_slice);
    s.sleep_if_queued(x);
    let mut out = Vec::new();
    let mut now = 0u64;
    let mut next_wake = period;
    let mut ran_in_cycle = 0u64;
    let mut woke_at: Option<u64> = None;
    while out.len() < cycles {
        if s.t[x].st == St::Asleep && now >= next_wake {
            // A task that is new, or owed nothing: lag 0, v = V.
            s.t[x].lag = Some(0);
            s.wake(x);
            woke_at = Some(now);
            ran_in_cycle = 0;
        }
        if let Some(w) = woke_at {
            if s.cur == Some(x) {
                out.push(now - w);
                woke_at = None;
            }
        }
        if s.cur == Some(x) && ran_in_cycle >= work {
            s.sleep(x);
            next_wake = now + period;
        }
        s.run(tick);
        if s.cur == Some(x) || s.t[x].ran > 0 && s.cur == Some(x) {
            ran_in_cycle += tick;
        }
        now += tick;
    }
    out
}

impl Sim {
    fn sleep_if_queued(&mut self, i: usize) {
        if self.t[i].st == St::Queued && self.cur != Some(i) {
            self.sleep(i);
        }
    }
}

#[test]
fn a_short_slice_is_served_within_its_deadline() {
    for tick in [100u64, 1000] {
        let short = waits(3, 1024, 300, tick, 7000, 100, 300);
        let long = waits(3, 1024, SLICE, tick, 7000, 100, 300);
        let max_short = *short.iter().max().unwrap();
        let mean = |v: &[u64]| v.iter().sum::<u64>() as f64 / v.len() as f64;
        // Due within its slice plus the tick that notices it.
        assert!(max_short <= 300 + tick, "tick {tick}: short slice waited {max_short}");
        // The same weight and the same work with a slice ten times longer
        // queues behind the hogs' earlier deadlines.
        assert!(
            mean(&short) < mean(&long),
            "tick {tick}: short {} vs long {}: the slice is the latency knob",
            mean(&short),
            mean(&long)
        );
    }
}

// ───────────────────────────────── the pick ────────────────────────────────

/// The definition, without the anchor: `i` is eligible when
/// `sum_j w_j * (v_j - v_i) >= 0` over every entity; the pick is the eligible
/// queued entity with the earliest deadline, `cur` on a tie.
fn reference(queued: &[(usize, Ent)], cur: Option<(usize, Ent)>) -> Choice {
    if queued.is_empty() {
        return if cur.is_some() { Choice::Cur } else { Choice::Empty };
    }
    let all: Vec<Ent> = queued.iter().map(|(_, e)| *e).chain(cur.map(|(_, e)| e)).collect();
    let eligible = |e: &Ent| -> bool {
        all.iter().map(|o| o.weight as i128 * (o.vruntime as i128 - e.vruntime as i128)).sum::<i128>() >= 0
    };
    let mut best: Option<(usize, i64)> = None;
    for (id, e) in queued {
        if eligible(e) && best.map_or(true, |(_, d)| e.deadline < d) {
            best = Some((*id, e.deadline));
        }
    }
    match (best, cur) {
        (None, Some(_)) => Choice::Cur,
        (Some((id, _)), None) => Choice::Task(id),
        (Some((id, d)), Some((_, c))) => {
            if eligible(&c) && c.deadline <= d {
                Choice::Cur
            } else {
                Choice::Task(id)
            }
        }
        (None, None) => unreachable!("a non-empty queue has an eligible member"),
    }
}

#[test]
fn choose_matches_the_definition() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for case in 0..5000 {
        let n = 1 + rng.below(8) as usize;
        let mut q = Vec::new();
        for id in 0..n {
            let w = WEIGHTS[rng.below(40) as usize];
            let mut e = Ent::new(w, 100 + rng.below(6000));
            e.vruntime = rng.below(20_000) as i64 - 10_000;
            e.deadline = e.vruntime + 1 + rng.below(8000) as i64;
            q.push((id + 10, e));
        }
        let cur = if rng.below(3) > 0 {
            let w = WEIGHTS[rng.below(40) as usize];
            let mut e = Ent::new(w, 100 + rng.below(6000));
            e.vruntime = rng.below(20_000) as i64 - 10_000;
            e.deadline = e.vruntime + 1 + rng.below(8000) as i64;
            Some((99, e))
        } else {
            None
        };
        let got = choose(|| q.iter().copied(), cur);
        let want = reference(&q, cur);
        assert_eq!(got, want, "case {case}: queue {q:?} cur {cur:?}");
    }
}

#[test]
fn nothing_runnable_is_empty_and_a_lone_runner_keeps_the_cpu() {
    let e = Ent::new(1024, SLICE);
    let none: Vec<(usize, Ent)> = Vec::new();
    assert_eq!(choose(|| none.iter().copied(), None), Choice::Empty);
    assert_eq!(choose(|| none.iter().copied(), Some((1, e))), Choice::Cur);
    let one = vec![(2usize, e)];
    assert_eq!(choose(|| one.iter().copied(), None), Choice::Task(2));
}

#[test]
fn ties_go_to_the_runner_then_to_the_first_queued() {
    let e = Ent::new(1024, SLICE);
    let q = vec![(1usize, e), (2usize, e)];
    assert_eq!(choose(|| q.iter().copied(), None), Choice::Task(1), "FIFO");
    assert_eq!(choose(|| q.iter().copied(), Some((9, e))), Choice::Cur, "the runner keeps it");
}

#[test]
fn an_earlier_deadline_wins_among_the_eligible() {
    let mut a = Ent::new(1024, SLICE);
    let mut b = Ent::new(1024, SLICE);
    a.deadline = 900;
    b.deadline = 400;
    let q = vec![(1usize, a), (2usize, b)];
    assert_eq!(choose(|| q.iter().copied(), None), Choice::Task(2));
}

#[test]
fn an_ineligible_entity_is_not_picked_whatever_its_deadline() {
    // 2 is far ahead of its share (v = 5000 against 0) with the earliest deadline.
    let mut a = Ent::new(1024, SLICE);
    let mut b = Ent::new(1024, SLICE);
    a.vruntime = 0;
    a.deadline = 3000;
    b.vruntime = 5000;
    b.deadline = 100;
    let q = vec![(1usize, a), (2usize, b)];
    assert_eq!(choose(|| q.iter().copied(), None), Choice::Task(1));
}

#[test]
fn a_runner_ahead_of_its_share_yields() {
    // The runner has had more than the mean: it is not eligible even with the
    // best deadline, and the queued entity (eligible) takes the CPU.
    let mut cur = Ent::new(1024, SLICE);
    cur.vruntime = 5000;
    cur.deadline = 10;
    let mut q = Ent::new(1024, SLICE);
    q.vruntime = 0;
    q.deadline = 3000;
    let v = vec![(1usize, q)];
    assert_eq!(choose(|| v.iter().copied(), Some((9, cur))), Choice::Task(1));
}

#[test]
fn yield_moves_the_deadline_one_slice_on() {
    let mut a = Ent::new(1024, SLICE);
    let b = Ent::new(1024, SLICE);
    // Equal but for the order: the runner would keep the CPU on the tie.
    let q = vec![(1usize, b)];
    assert_eq!(choose(|| q.iter().copied(), Some((9, a))), Choice::Cur);
    yield_now(&mut a);
    assert_eq!(a.deadline, 6000);
    assert_eq!(choose(|| q.iter().copied(), Some((9, a))), Choice::Task(1));
}

// ───────────────────────────────── lag ─────────────────────────────────────

#[test]
fn lag_is_clamped_when_stored() {
    let tick = 1000;
    let mut others = Avg::new();
    let mut base = Ent::new(1024, SLICE);
    base.vruntime = 0;
    others.add(&base);
    let lim = lag_limit(&Ent::new(1024, SLICE), tick);
    assert_eq!(lim, 6000, "two slices");
    // Far behind everyone (owed a great deal) and far ahead.
    let mut behind = Ent::new(1024, SLICE);
    behind.vruntime = -10_000_000;
    let mut ahead = Ent::new(1024, SLICE);
    ahead.vruntime = 10_000_000;
    assert_eq!(lag_on_sleep(&others, &behind, tick), lim);
    assert_eq!(lag_on_sleep(&others, &ahead, tick), -lim);
    // Inside the limit it is exact: V = 0 and 1000 -> 500, lag 500 - 1000.
    let mut near = Ent::new(1024, SLICE);
    near.vruntime = 1000;
    assert_eq!(lag_on_sleep(&others, &near, tick), -500);
    // A short slice has a short limit, but never below the tick.
    assert_eq!(lag_limit(&Ent::new(1024, 100), 1000), 1000);
    // Heavy entities' limit is smaller in virtual time.
    assert_eq!(lag_limit(&Ent::new(2048, SLICE), tick), 3000);
}

#[test]
fn lag_is_clamped_when_placed() {
    let tick = 1000;
    let mut others = Avg::new();
    others.add(&Ent::new(1024, SLICE));
    let lim = lag_limit(&Ent::new(1024, SLICE), tick);
    for huge in [i64::MAX / 4, i64::MIN / 4] {
        let mut e = Ent::new(1024, SLICE);
        place_wake(&others, &mut e, Some(huge), tick);
        let mut with = others;
        with.add(&e);
        let lag = with.mean().unwrap() - e.vruntime;
        assert!(lag.abs() <= lim + 1, "lag {lag} past the limit {lim} (stored {huge})");
        assert!(lag.abs() >= lim - 1, "and it is the limit, not less: {lag}");
    }
    // An entity that left without a lag keeps its v, held within the limit.
    let mut e = Ent::new(1024, SLICE);
    e.vruntime = 9_000_000;
    place_wake(&others, &mut e, None, tick);
    assert_eq!(e.vruntime, lim, "V is 0");
    e.vruntime = -9_000_000;
    place_wake(&others, &mut e, None, tick);
    assert_eq!(e.vruntime, -lim);
    e.vruntime = 1234;
    place_wake(&others, &mut e, None, tick);
    assert_eq!(e.vruntime, 1234, "inside the limit it is untouched");
    assert_eq!(e.deadline, 1234 + 3000);
}

#[test]
fn lag_survives_a_sleep() {
    // The lag stored at the sleep is the lag the waker has once it has joined,
    // whatever the queue's weight (the (W + w) / W correction).
    let tick = 1000;
    for (wq, we) in [(1024u32, 1024u32), (4096, 1024), (1024, 4096), (88761, 15), (15, 88761)] {
        let mut q = Ent::new(wq, SLICE);
        q.vruntime = 0;
        let mut others = Avg::new();
        others.add(&q);
        let mut e = Ent::new(we, SLICE);
        e.vruntime = -((SLICE / 2) as i64);
        let lag = lag_on_sleep(&others, &e, tick);
        // Time passes: the queue's V moves on.
        q.vruntime = 40_000;
        let mut others = Avg::new();
        others.add(&q);
        place_wake(&others, &mut e, Some(lag), tick);
        let mut with = others;
        with.add(&e);
        let after = with.mean().unwrap() - e.vruntime;
        assert!((after - lag).abs() <= 2, "w {wq}/{we}: stored {lag}, after joining {after}");
    }
}

/// `with_lag`: the sleep stored its lag; otherwise the sleeper left without
/// one (the IPC hand-off path, a migration) and wakes with the `v` it had.
fn long_sleep(with_lag: bool) {
    let tick = 100;
    let mut s = Sim::new(tick);
    let a = s.add(1024, SLICE);
    let b = s.add(1024, SLICE);
    s.decide();
    for _ in 0..50 {
        s.run(tick);
    }
    while s.cur != Some(b) {
        s.run(tick);
    }
    s.sleep(b);
    if !with_lag {
        s.t[b].lag = None;
    }
    for _ in 0..10_000_000u64 / tick {
        s.run(tick);
    }
    let ran_a = s.t[a].ran;
    s.wake(b);
    // From here count the longest stretch b runs without a.
    let mut stretch = 0u64;
    let mut longest = 0u64;
    for _ in 0..20_000 {
        s.run(tick);
        if s.cur == Some(b) {
            stretch += tick;
            longest = longest.max(stretch);
        } else {
            stretch = 0;
        }
    }
    let lim = lag_limit(&Ent::new(1024, SLICE), tick) as u64;
    assert!(ran_a > 9_000_000);
    // b is owed at most the lag limit: it can monopolise the CPU for about
    // that and a slice, not for the 10 s it slept.
    assert!(longest <= 2 * lim + SLICE + tick, "b ran {longest} in a row after its sleep");
}

#[test]
fn a_long_sleeper_does_not_starve_the_others() {
    long_sleep(true);
}

#[test]
fn a_sleeper_that_left_without_a_lag_does_not_starve_the_others() {
    // Its v is ten seconds behind V. Held within the lag limit it runs a few
    // slices; kept as it was it would run for ten seconds.
    long_sleep(false);
}

#[test]
fn a_sleeper_keeps_its_credit_up_to_the_limit() {
    // b sleeps right after running less than its share; on waking it is
    // placed behind V by its lag and wins the next picks.
    let tick = 100;
    let mut s = Sim::new(tick);
    let a = s.add(1024, SLICE);
    let b = s.add(1024, SLICE);
    s.decide();
    while s.cur != Some(b) {
        s.run(tick);
    }
    // make a hog the CPU for a while, b owed; then b sleeps and wakes.
    for _ in 0..5 {
        s.run(tick);
    }
    s.sleep(b);
    for _ in 0..20 {
        s.run(tick);
    }
    let v = s.v_mean();
    s.wake(b);
    assert!(s.t[b].e.vruntime <= v + 1, "owed service: not ahead of V");
    let _ = a;
}
