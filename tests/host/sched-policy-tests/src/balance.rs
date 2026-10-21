// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `crates/core/sched/src/scheduler/balance.rs`: the fair class's load
//! balancing policy, on a model of N CPUs.
//!
//! The model is the queue side (`Rq`) the kernel implements in `fairq.rs`: per
//! CPU a running weight and a queue of tasks that each carry an allowed-CPU
//! mask; `take` refuses a task that may not run on the receiver, a locked
//! sender is `Busy`, and the scan budget is charged per entry looked at.
//!
//! Registered in `lib.rs` by `#[cfg(test)] mod balance;`.

#[path = "../../../../crates/core/sched/src/scheduler/balance.rs"]
#[allow(dead_code)]
mod subject;

use subject::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct T {
    id: u32,
    w: u32,
    /// CPUs the task may run on.
    allowed: Mask,
}

struct Model {
    run: Vec<u32>,
    q: Vec<Vec<T>>,
    cap: Vec<u16>,
    /// Senders whose lock is held.
    locked: Mask,
    /// Every move, `(id, from, to)`.
    log: Vec<(u32, usize, usize)>,
    /// Entries `take` looked at, in all.
    looked: u32,
}

const ANY: Mask = !0;

impl Model {
    fn new(n: usize) -> Model {
        Model { run: vec![0; n], q: vec![vec![]; n], cap: vec![1024; n], locked: 0, log: vec![], looked: 0 }
    }

    fn n(&self) -> usize {
        self.run.len()
    }

    fn add(&mut self, cpu: usize, id: u32, w: u32, allowed: Mask) {
        self.q[cpu].push(T { id, w, allowed });
    }

    fn weight(&self, cpu: usize) -> u32 {
        self.run[cpu] + self.q[cpu].iter().map(|t| t.w).sum::<u32>()
    }

    fn cpu_of(&self, id: u32) -> usize {
        (0..self.n()).find(|&c| self.q[c].iter().any(|t| t.id == id)).expect("task lost")
    }

    fn ids(&self, cpu: usize) -> Vec<u32> {
        self.q[cpu].iter().map(|t| t.id).collect()
    }

    fn total(&self) -> usize {
        self.q.iter().map(|q| q.len()).sum()
    }

    /// The CPUs' scaled loads, largest first. Every move replaces the
    /// sender's load by a smaller one and keeps the receiver's below the
    /// sender's old one, so this vector falls in lexicographic order with each
    /// move: the termination argument (the sum of squares is not enough once
    /// capacities differ).
    fn key(&self) -> Vec<u64> {
        let mut v: Vec<u64> = (0..self.n()).map(|c| Load { weight: self.weight(c), capacity: self.cap[c] }.scaled(0)).collect();
        v.sort_unstable_by(|a, b| b.cmp(a));
        v
    }
}

impl Rq for Model {
    type Task = (T, usize);

    fn load(&mut self, cpu: usize) -> Load {
        Load { weight: self.weight(cpu), capacity: self.cap[cpu] }
    }

    fn take(&mut self, src: usize, dst: usize, scan: &mut u32, want: &mut dyn FnMut(u32) -> bool) -> Take<(T, usize)> {
        if self.locked >> src & 1 != 0 {
            return Take::Busy;
        }
        for i in 0..self.q[src].len() {
            if *scan == 0 {
                return Take::Nothing;
            }
            *scan -= 1;
            self.looked += 1;
            let t = self.q[src][i];
            if t.allowed >> dst & 1 == 0 || !want(t.w) {
                continue;
            }
            self.q[src].remove(i);
            return Take::Got((t, src));
        }
        Take::Nothing
    }

    fn give(&mut self, dst: usize, (t, src): (T, usize)) {
        self.log.push((t.id, src, dst));
        self.q[dst].push(t);
    }
}

const P: Params = Params { moves: 2, scan: 16 };

/// Two last-level caches of four CPUs; one node and package over both.
fn two_llcs(n: usize) -> impl Fn(usize) -> Vec<Ring> {
    move |cpu| {
        let half = n / 2;
        let llc: Mask = if cpu < half { (1u64 << half) - 1 } else { ((1u64 << n) - 1) & !((1u64 << half) - 1) };
        let all: Mask = (1u64 << n) - 1;
        let mut out = [Ring::default(); 3];
        let k = distinct_levels(&[llc, all, all], all, &mut out);
        out[..k].to_vec()
    }
}

fn all(n: usize) -> Mask {
    if n >= 64 { !0 } else { (1u64 << n) - 1 }
}

/// One pass of every eligible CPU in order: an idle one pulls, one with fair
/// work queued pushes. Returns the tasks moved.
fn round(m: &mut Model, lv: &impl Fn(usize) -> Vec<Ring>, eligible: Mask, p: &Params) -> u32 {
    let mut moved = 0;
    for cpu in 0..m.n() {
        let l = lv(cpu);
        let r = if m.weight(cpu) == 0 {
            pull(m, cpu, &l, eligible, p)
        } else if !m.q[cpu].is_empty() {
            push(m, cpu, &l, eligible, p)
        } else {
            Moved::default()
        };
        assert!(r.moved <= p.moves, "a pass moved {} with a budget of {}", r.moved, p.moves);
        moved += r.moved;
    }
    moved
}

/// Rounds until nothing moves. Panics if that takes `cap` rounds.
fn settle(m: &mut Model, lv: &impl Fn(usize) -> Vec<Ring>, eligible: Mask, p: &Params, cap: u32) -> u32 {
    for r in 0..cap {
        let before = m.key();
        let moved = round(m, lv, eligible, p);
        assert!(m.key() <= before, "a round raised the loads");
        if moved == 0 {
            return r;
        }
    }
    panic!("no fixed point in {cap} rounds");
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

// ── The move test ────────────────────────────────────────────────────────────

fn load(w: u32, cap: u16) -> Load {
    Load { weight: w, capacity: cap }
}

#[test]
fn a_move_needs_a_gap_that_survives_it() {
    let big = load(2048, 1024);
    // 2 -> 0 of weight 1024: the receiver ends at 1024, below 2048.
    assert!(improves(&big, &load(0, 1024), 1024, 0));
    // 1 -> 0: the receiver would end where the sender was. No gain.
    assert!(!improves(&load(1024, 1024), &load(0, 1024), 1024, 0));
    // 2 -> 1: swaps the imbalance.
    assert!(!improves(&big, &load(1024, 1024), 1024, 0));
    // A level further out costs one more task.
    assert!(!improves(&load(3072, 1024), &load(1024, 1024), 1024, 1));
    assert!(improves(&load(4096, 1024), &load(1024, 1024), 1024, 1));
}

#[test]
fn the_reverse_of_a_move_never_improves() {
    // After src -> dst of weight w, the pair is (src - w, dst + w). Moving the
    // same task back must not qualify, at any hop, or the pair would bounce.
    let mut rng = Rng(7);
    for _ in 0..20_000 {
        let (cs, cd) = ([256u16, 512, 1024][rng.below(3) as usize], [256u16, 512, 1024][rng.below(3) as usize]);
        let (s, d, w) = (rng.below(4000) as u32, rng.below(4000) as u32, 1 + rng.below(500) as u32);
        let hop = rng.below(3) as u32;
        if s < w || !improves(&load(s, cs), &load(d, cd), w, hop) {
            continue;
        }
        let (s2, d2) = (load(s - w, cs), load(d + w, cd));
        for h2 in 0..3 {
            assert!(!improves(&d2, &s2, w, h2), "{s}/{cs} -> {d}/{cd} by {w} bounces at hop {h2}");
        }
    }
}

// ── Convergence ──────────────────────────────────────────────────────────────

#[test]
fn an_imbalance_converges_and_stays() {
    let n = 8;
    let lv = two_llcs(n);
    let mut m = Model::new(n);
    for i in 0..16 {
        m.add(0, i, 1024, ANY);
    }
    m.run[0] = 1024;
    let rounds = settle(&mut m, &lv, all(n), &P, 64);
    // Within a cache the spread is at most one task; across the two caches at
    // most two (the far level costs one more).
    for llc in [0..4, 4..8] {
        let ws: Vec<u32> = llc.map(|c| m.weight(c) / 1024).collect();
        assert!(ws.iter().max().unwrap() - ws.iter().min().unwrap() <= 1, "within a cache: {ws:?}");
    }
    let ws: Vec<u32> = (0..n).map(|c| m.weight(c) / 1024).collect();
    assert!(ws.iter().max().unwrap() - ws.iter().min().unwrap() <= 2, "across caches: {ws:?}");
    assert_eq!(m.total(), 16, "no task lost or duplicated");
    // It stays: another round moves nothing.
    assert_eq!(round(&mut m, &lv, all(n), &P), 0);
    assert!(rounds > 0);
}

#[test]
fn random_imbalances_converge_with_every_task_kept() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    for case in 0..300 {
        let n = [2usize, 3, 4, 6, 8, 16][rng.below(6) as usize];
        let lv = two_llcs(n & !1);
        let n = n & !1;
        let mut m = Model::new(n);
        for c in 0..n {
            m.cap[c] = [256u16, 512, 1024][rng.below(3) as usize];
            m.run[c] = if rng.below(2) == 0 { 0 } else { 1 + rng.below(8) as u32 * 128 };
        }
        let tasks = rng.below(40) as u32;
        for id in 0..tasks {
            let allowed = if rng.below(4) == 0 { 1u64 << rng.below(n as u64) } else { ANY };
            let at = if allowed == ANY { rng.below(n as u64) as usize } else { allowed.trailing_zeros() as usize };
            m.add(at, id, 1 + rng.below(12) as u32 * 64, allowed);
        }
        let p = Params { moves: 1 + rng.below(4) as u32, scan: 1 + rng.below(40) as u32 };
        settle(&mut m, &lv, all(n), &p, 4000);
        assert_eq!(m.total(), tasks as usize, "case {case}: tasks lost");
        for c in 0..n {
            for t in &m.q[c] {
                assert!(t.allowed >> c & 1 != 0, "case {case}: task {} on CPU {c} outside {:#x}", t.id, t.allowed);
            }
        }
    }
}

#[test]
fn every_move_lowers_the_load_vector() {
    // The termination argument, one move at a time.
    let mut rng = Rng(42);
    for _ in 0..200 {
        let n = 8;
        let lv = two_llcs(n);
        let mut m = Model::new(n);
        for c in 0..n {
            m.cap[c] = [512u16, 1024][rng.below(2) as usize];
        }
        for id in 0..30 {
            m.add(rng.below(n as u64) as usize, id, 64 + rng.below(8) as u32 * 64, ANY);
        }
        let one = Params { moves: 1, scan: 64 };
        for _ in 0..400 {
            let before = m.key();
            let logged = m.log.len();
            let cpu = rng.below(n as u64) as usize;
            let l = lv(cpu);
            if rng.below(2) == 0 { pull(&mut m, cpu, &l, all(n), &one); } else { push(&mut m, cpu, &l, all(n), &one); }
            if m.log.len() > logged {
                assert!(m.key() < before, "a move did not lower the load vector");
            }
        }
    }
}

#[test]
fn a_capacity_skew_gets_work_in_proportion() {
    // Four big CPUs (1024) and four little (256) in one cache.
    let n = 8;
    let mut m = Model::new(n);
    for c in 4..8 {
        m.cap[c] = 256;
    }
    for i in 0..40 {
        m.add(4, i, 256, ANY);
    }
    let lv = |_c: usize| vec![Ring { mask: all(n), level: 0 }];
    settle(&mut m, &lv, all(n), &P, 200);
    let big: u32 = (0..4).map(|c| m.weight(c)).sum();
    let little: u32 = (4..8).map(|c| m.weight(c)).sum();
    assert!(big > 2 * little, "big CPUs hold {big}, little ones {little}");
}

// ── Who may move ─────────────────────────────────────────────────────────────

#[test]
fn a_pinned_or_masked_task_never_moves_off_its_cpus() {
    let n = 8;
    let lv = two_llcs(n);
    let mut m = Model::new(n);
    // Eight pinned to CPU 0, eight allowed on CPUs 0 and 5, eight free.
    for i in 0..8 {
        m.add(0, i, 1024, 1);
    }
    for i in 8..16 {
        m.add(0, i, 1024, 1 | 1 << 5);
    }
    for i in 16..24 {
        m.add(0, i, 1024, ANY);
    }
    settle(&mut m, &lv, all(n), &P, 200);
    for i in 0..8 {
        assert_eq!(m.cpu_of(i), 0, "task {i} is pinned to CPU 0");
    }
    for i in 8..16 {
        assert!([0, 5].contains(&m.cpu_of(i)), "task {i} left its mask");
    }
    assert!(m.log.iter().all(|&(id, _, _)| id >= 8), "a pinned task was moved");
    // The free ones did spread.
    assert!((1..8).any(|c| m.weight(c) > 0));
}

#[test]
fn isolated_cpus_are_neither_sender_nor_receiver() {
    let n = 8;
    let lv = two_llcs(n);
    let iso: Mask = 1 << 6 | 1 << 7;
    let eligible = all(n) & !iso;
    let mut m = Model::new(n);
    for i in 0..10 {
        m.add(0, i, 1024, ANY);
    }
    // Real-time CPUs hold fair work too, and one is idle.
    for i in 100..106 {
        m.add(6, i, 1024, ANY);
    }
    let (before6, before7) = (m.ids(6), m.ids(7));
    settle(&mut m, &lv, eligible, &P, 200);
    assert_eq!(m.ids(6), before6, "work left or joined an isolated CPU");
    assert_eq!(m.ids(7), before7);
    assert!(m.log.iter().all(|&(_, from, to)| iso >> from & 1 == 0 && iso >> to & 1 == 0));
    // A pass started on an isolated CPU does nothing at all, push or pull.
    for cpu in [6usize, 7] {
        let l = lv(cpu);
        assert_eq!(pull(&mut m, cpu, &l, eligible, &P), Moved::default());
        assert_eq!(push(&mut m, cpu, &l, eligible, &P), Moved::default());
    }
    assert_eq!(m.ids(6), before6);
}

#[test]
fn nothing_is_taken_from_a_cpu_with_one_task() {
    // The only task of a CPU is the one it runs: nothing queued to take, and
    // an idle peer gains nothing from it moving anyway.
    let n = 4;
    let lv = two_llcs(n);
    let mut m = Model::new(n);
    m.run[0] = 1024;
    assert_eq!(pull(&mut m, 1, &lv(1), all(n), &P).moved, 0);
    // One queued behind the running one: the idle CPU takes it.
    m.add(0, 1, 1024, ANY);
    assert_eq!(pull(&mut m, 1, &lv(1), all(n), &P).moved, 1);
    // And the first CPU does not take it back, or push anything.
    assert_eq!(pull(&mut m, 0, &lv(0), all(n), &P).moved, 0);
    assert_eq!(push(&mut m, 1, &lv(1), all(n), &P).moved, 0);
}

// ── Bounds ───────────────────────────────────────────────────────────────────

#[test]
fn a_pass_is_bounded_whatever_the_machine() {
    let n = 64;
    let lv = |_c: usize| vec![Ring { mask: all(n), level: 0 }];
    let mut m = Model::new(n);
    for i in 0..2000 {
        m.add(0, i, 1024, ANY);
    }
    for (moves, scan) in [(1, 1), (2, 4), (3, 7), (16, 256)] {
        let p = Params { moves, scan };
        let looked = m.looked;
        let r = pull(&mut m, 33, &lv(33), all(n), &p);
        assert!(r.moved <= moves, "{} moves, budget {moves}", r.moved);
        assert!(m.looked - looked <= scan, "{} entries looked at, budget {scan}", m.looked - looked);
        assert_eq!(r.scanned, m.looked - looked);
        let looked = m.looked;
        let r = push(&mut m, 0, &lv(0), all(n), &p);
        assert!(r.moved <= moves);
        assert!(m.looked - looked <= scan);
    }
    assert_eq!(m.total(), 2000);
}

#[test]
fn a_queue_longer_than_the_scan_budget_is_not_searched_to_its_end() {
    // 40 pinned tasks and one free one at the back: with a budget of 16 the
    // pass gives up rather than walk to it.
    let n = 2;
    let mut m = Model::new(n);
    for i in 0..40 {
        m.add(0, i, 1024, 1);
    }
    m.add(0, 99, 1024, ANY);
    let lv = |_c: usize| vec![Ring { mask: all(n), level: 0 }];
    let r = pull(&mut m, 1, &lv(1), all(n), &Params { moves: 1, scan: 16 });
    assert_eq!((r.moved, r.scanned), (0, 16));
    let r = pull(&mut m, 1, &lv(1), all(n), &Params { moves: 1, scan: 64 });
    assert_eq!(r.moved, 1);
    assert_eq!(m.cpu_of(99), 1);
}

// ── Levels ───────────────────────────────────────────────────────────────────

#[test]
fn a_pull_takes_from_the_nearest_level_that_has_work() {
    let n = 8;
    let lv = two_llcs(n);
    let mut m = Model::new(n);
    // CPU 1 is idle. CPU 3 (same cache) has two tasks; CPU 6 (other cache) has
    // six.
    for i in 0..2 {
        m.add(3, i, 1024, ANY);
    }
    for i in 10..16 {
        m.add(6, i, 1024, ANY);
    }
    let r = pull(&mut m, 1, &lv(1), all(n), &Params { moves: 1, scan: 16 });
    assert_eq!((r.moved, r.hop), (1, 0));
    assert_eq!(m.log[0].1, 3, "taken from the cache, not from the busier far CPU");
    // Cache empty of spare work: now it goes to the far level.
    let mut m = Model::new(n);
    for i in 10..16 {
        m.add(6, i, 1024, ANY);
    }
    let r = pull(&mut m, 1, &lv(1), all(n), &Params { moves: 1, scan: 16 });
    assert_eq!((r.moved, r.hop), (1, 1));
    assert_eq!(m.log[0].1, 6);
}

#[test]
fn a_pull_stops_at_the_level_that_gave() {
    let n = 8;
    let lv = two_llcs(n);
    let mut m = Model::new(n);
    // One spare task in the cache, plenty far away; a budget of four moves.
    m.add(3, 0, 1024, ANY);
    m.run[3] = 1024;
    for i in 10..20 {
        m.add(6, i, 1024, ANY);
    }
    let r = pull(&mut m, 1, &lv(1), all(n), &Params { moves: 4, scan: 64 });
    assert_eq!(r.moved, 1, "the far level is left alone once the near one gave");
    assert_eq!(r.hop, 0);
}

#[test]
fn a_push_goes_to_the_least_loaded_cpu_of_the_nearest_level() {
    let n = 8;
    let lv = two_llcs(n);
    let mut m = Model::new(n);
    for i in 0..6 {
        m.add(0, i, 1024, ANY);
    }
    // In the cache CPU 2 is the lightest; CPU 5, far away, is idle.
    m.run[1] = 2048;
    m.run[2] = 1024;
    m.run[3] = 2048;
    let r = push(&mut m, 0, &lv(0), all(n), &Params { moves: 1, scan: 16 });
    assert_eq!(r.moved, 1);
    assert_eq!(m.log[0].2, 2);
}

#[test]
fn a_busy_sender_is_skipped_and_counted() {
    let n = 4;
    let lv = two_llcs(n);
    let mut m = Model::new(n);
    for i in 0..4 {
        m.add(0, i, 1024, ANY);
    }
    for i in 10..14 {
        m.add(1, i, 1024, ANY);
    }
    m.locked = 1; // CPU 0's lock is held, and it is the busiest by id
    let r = pull(&mut m, 3, &lv(3), all(n), &P);
    assert!(r.busy >= 1);
    assert!(r.moved >= 1, "the next sender is tried");
    assert!(m.log.iter().all(|&(_, from, _)| from == 1));
}

#[test]
fn distinct_levels_drops_a_repeat_and_clips_to_the_online_cpus() {
    let mut out = [Ring::default(); 3];
    let r = |mask, level| Ring { mask, level };
    // One node: the node and the package are the same mask; the survivors
    // are the cache (level 0) and the node (level 1).
    let k = distinct_levels(&[0b1111, 0xFF, 0xFF], 0xFF, &mut out);
    assert_eq!((k, out[0], out[1]), (2, r(0b1111, 0), r(0xFF, 1)));
    // Only CPUs 0-5 are online.
    let k = distinct_levels(&[0b1111, 0xFF, 0xFF], 0b11_1111, &mut out);
    assert_eq!((k, out[0], out[1]), (2, r(0b1111, 0), r(0b11_1111, 1)));
    // The cache is the whole machine.
    let k = distinct_levels(&[0xFF, 0xFF, 0xFF], 0xFF, &mut out);
    assert_eq!((k, out[0]), (1, r(0xFF, 0)));
    // A cache with one online CPU in it is still a level (a ring of nobody).
    let k = distinct_levels(&[0b1, 0xFF, 0xFF], 0xFF, &mut out);
    assert_eq!(k, 2);
    // The cache is the node, the package is wider: the package keeps level 2
    // (it used to be renumbered 1 and counted as the node).
    let k = distinct_levels(&[0b1111, 0b1111, 0xFF], 0xFF, &mut out);
    assert_eq!((k, out[0], out[1]), (2, r(0b1111, 0), r(0xFF, 2)));
    // The cache is one CPU, the node is the package: the node is level 1.
    let k = distinct_levels(&[0b1, 0b1111, 0b1111], 0xFF, &mut out);
    assert_eq!((k, out[1]), (2, r(0b1111, 1)));
}

/// A move reports the true level it crossed, and a farther level costs more.
#[test]
fn a_move_reports_the_true_topology_level_and_charges_it() {
    let n = 8;
    // CPU 4: cache = node = CPUs 4-7, package = all, the work is on CPU 0.
    let mut lv = [Ring::default(); 3];
    let k = distinct_levels(&[0xF0, 0xF0, 0xFF], all(n), &mut lv);
    let mut m = Model::new(n);
    m.run[0] = 1024;
    for id in 0..4 {
        m.add(0, id, 1024, ANY);
    }
    let r = pull(&mut m, 4, &lv[..k], all(n), &Params { moves: 1, scan: 16 });
    assert_eq!((r.moved, r.hop), (1, 2), "package level, not the renumbered 1");
}
