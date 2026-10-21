// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `crates/core/sched/src/topo.rs`, core scheduling (Kconfig SCHED_CORE): the
//! claims of SMT siblings, the admission of a candidate, and the pick filter
//! (`core_pick`), on a model of two siblings (and of two cores) that share a
//! run queue per hart.
//!
//! The model is the queue side the kernel has in `scheduler/mod.rs`: per hart a
//! list of ready tasks in dequeue order (best first), taken off by `redraw`
//! and put back by the caller. Everything that decides is the kernel's own
//! code, pulled by path.
//!
//! Registered in `lib.rs` by `#[cfg(test)] mod core_sched;`.

#[path = "../../../../crates/core/sched/src/topo.rs"]
#[allow(dead_code)]
mod subject;

use subject::*;

const PATIENCE: u64 = 100;
const SCAN: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct T {
    id: usize,
    cookie: u32,
    strong: bool,
    /// The hart's idle task.
    idle: bool,
}

impl T {
    /// Band 0, fair 16, idle 31, as the kernel's levels.
    fn prio(&self) -> u32 {
        if self.idle { 31 } else if self.strong { 0 } else { 16 }
    }
}

fn claim(t: &T) -> Claim {
    if t.idle { Claim::IDLE } else { Claim::task(t.cookie, t.strong) }
}

/// Two or more harts over `CoreSched`, `smt` masks from a real topology.
struct M {
    core: CoreSched,
    topo: Topology,
    tasks: Vec<T>,
    /// Per hart: ready tasks, best first.
    q: Vec<Vec<usize>>,
    /// Per hart: what runs (a task id), `None` before anything ran.
    run: Vec<Option<usize>>,
    now: u64,
    kicks: Vec<(usize, usize)>,
}

impl M {
    /// `harts` harts; hart `2k` and `2k+1` are the threads of core `k`.
    fn new(harts: usize) -> M {
        let raw: Vec<CpuRaw> = (0..harts)
            .map(|c| CpuRaw { core: (c / 2) as u32, cluster: NONE, llc: 0, node: 0, package: 0, dmips: 0 })
            .collect();
        let mut m = M {
            core: CoreSched::new(),
            topo: build(&raw, Source::Dt),
            tasks: vec![],
            q: vec![vec![]; harts],
            run: vec![None; harts],
            now: 1,
            kicks: vec![],
        };
        for h in 0..harts {
            // Each hart's idle task is queued last.
            let id = m.tasks.len();
            m.tasks.push(T { id, cookie: 0, strong: false, idle: true });
            m.q[h].push(id);
        }
        m
    }

    fn smt(&self, cpu: usize) -> Mask {
        self.topo.mask(Level::Smt, cpu)
    }

    fn task(&mut self, cookie: u32, strong: bool) -> usize {
        let id = self.tasks.len();
        self.tasks.push(T { id, cookie, strong, idle: false });
        id
    }

    /// Queue `id` on `cpu` ahead of the idle task, behind earlier ones.
    fn ready(&mut self, cpu: usize, id: usize) {
        let at = self.q[cpu].len() - 1;
        self.q[cpu].insert(at, id);
    }

    fn idle_of(&self, cpu: usize) -> usize {
        cpu
    }

    /// A strong task goes first.
    fn ready_first(&mut self, cpu: usize, id: usize) {
        self.q[cpu].insert(0, id);
    }

    /// Hart `cpu` picks at a tick or a wake: what ran is still `Running`.
    fn pick(&mut self, cpu: usize) -> Option<usize> {
        let old_runs = self.run[cpu].is_some();
        self.pick_as(cpu, old_runs)
    }

    fn pick_as(&mut self, cpu: usize, old_runs: bool) -> Option<usize> {
        let smt = self.smt(cpu);
        let old = self.run[cpu];
        let old_idle = old.is_some_and(|o| self.tasks[o].idle);
        let tasks = self.tasks.clone();
        let first = if self.q[cpu].is_empty() {
            return None;
        } else {
            self.q[cpu].remove(0)
        };
        let q = std::cell::RefCell::new(std::mem::take(&mut self.q[cpu]));
        let mut stash = [usize::MAX; SCAN];
        let old_prio = old.map_or(0, |o| tasks[o].prio());
        let p = core_pick(
            &self.core,
            &CorePick { smt, cpu, now: self.now, patience: PATIENCE, old_runs, old_idle: old_runs && old_idle },
            first,
            &mut stash,
            |i| claim(&tasks[i]),
            || {
                let mut q = q.borrow_mut();
                if q.is_empty() { None } else { Some(q.remove(0)) }
            },
            // The scheduler's priority guard: a worse level than the running
            // task's does not preempt it, but two fair ones are ordered by EEVDF.
            |i| {
                let np = tasks[i].prio();
                let fair = |p: u32| (1..31).contains(&p);
                np > old_prio && !(fair(old_prio) && fair(np))
            },
            || {
                let mut q = q.borrow_mut();
                let at = q.iter().position(|&t| tasks[t].idle)?;
                Some(q.remove(at))
            },
        );
        let mut q = q.into_inner();
        // The caller puts every refused candidate back, ahead of the idle task.
        for &i in &stash[..p.stashed] {
            let at = q.iter().position(|&t| tasks[t].idle).unwrap_or(q.len());
            q.insert(at, i);
        }
        self.q[cpu] = q;
        for h in 0..self.run.len() {
            if p.kick & (1 << h) != 0 {
                self.kicks.push((cpu, h));
            }
        }
        match p.run {
            Some(t) => {
                // The task left running goes back, unless it blocked or idles.
                if let Some(o) = old {
                    if old_runs && o != t && !tasks[o].idle {
                        let at = self.q[cpu].iter().position(|&x| tasks[x].idle).unwrap_or(self.q[cpu].len());
                        self.q[cpu].insert(at, o);
                    }
                    if tasks[o].idle && o != t {
                        self.q[cpu].push(o);
                    }
                }
                self.run[cpu] = Some(t);
                Some(t)
            }
            None => old,
        }
    }

    fn yields(&self, cpu: usize) -> bool {
        self.core.must_yield(self.smt(cpu), cpu, self.now)
    }

    /// The task on `cpu` blocks (or exits): the hart picks again.
    fn block(&mut self, cpu: usize) -> Option<usize> {
        self.pick(cpu)
    }

    /// Cookies running on the hart pair, idle ones as `None`.
    fn running(&self, cpu: usize) -> Option<u32> {
        self.run[cpu].filter(|&t| !self.tasks[t].idle).map(|t| self.tasks[t].cookie)
    }
}

/// The invariant: no two siblings run tasks of different cookies.
fn co_runs_incompatible(m: &M) -> bool {
    for cpu in 0..m.run.len() {
        for other in 0..m.run.len() {
            if cpu != other && m.smt(cpu) & (1 << other) != 0 {
                if let (Some(a), Some(b)) = (m.running(cpu), m.running(other)) {
                    if a != b {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[test]
fn the_topology_the_model_uses_pairs_the_threads() {
    let m = M::new(4);
    assert_eq!(m.smt(0), 0b0011);
    assert_eq!(m.smt(3), 0b1100);
}

#[test]
fn an_incompatible_pair_never_co_runs() {
    let mut m = M::new(2);
    let (a, b) = (m.task(1, false), m.task(2, false));
    m.ready(0, a);
    m.ready(1, b);
    assert_eq!(m.pick(0), Some(a));
    // Hart 1's only ready task is of another Domain: it idles.
    let got = m.pick(1).unwrap();
    assert!(m.tasks[got].idle);
    assert!(!co_runs_incompatible(&m));
    assert_eq!(m.core.claim(0), Claim::task(1, false));
    assert_eq!(m.core.claim(1), Claim::IDLE);
    // The refused task is back in its queue, ahead of idle.
    assert_eq!(m.q[1][0], b);
}

#[test]
fn a_compatible_pair_co_runs() {
    let mut m = M::new(2);
    let (a1, a2) = (m.task(7, false), m.task(7, false));
    m.ready(0, a1);
    m.ready(1, a2);
    assert_eq!(m.pick(0), Some(a1));
    assert_eq!(m.pick(1), Some(a2));
    assert_eq!(m.running(0), Some(7));
    assert_eq!(m.running(1), Some(7));
}

#[test]
fn the_sibling_of_an_idle_hart_runs_anything() {
    let mut m = M::new(2);
    let b = m.task(2, false);
    m.ready(1, b);
    // Hart 0 has nothing but idle.
    { let g = m.pick(0).unwrap(); assert!(m.tasks[g].idle); }
    assert_eq!(m.pick(1), Some(b));
}

#[test]
fn a_hart_skips_a_task_that_does_not_fit_for_one_that_does() {
    let mut m = M::new(2);
    let (a, b, a2) = (m.task(1, false), m.task(2, false), m.task(1, false));
    m.ready(0, a);
    m.pick(0);
    // Hart 1: the best task is B's, behind it one of A's.
    m.ready(1, b);
    m.ready(1, a2);
    assert_eq!(m.pick(1), Some(a2));
    assert_eq!(m.q[1][0], b, "the skipped task is still queued, first");
    assert!(!co_runs_incompatible(&m));
}

#[test]
fn force_idle_ends_when_the_siblings_domain_leaves() {
    let mut m = M::new(2);
    let (a, b) = (m.task(1, false), m.task(2, false));
    m.ready(0, a);
    m.ready(1, b);
    m.pick(0);
    { let g = m.pick(1).unwrap(); assert!(m.tasks[g].idle); }
    m.kicks.clear();
    // A blocks: hart 0 idles and rings the waiting hart 1.
    { let g = m.block(0).unwrap(); assert!(m.tasks[g].idle); }
    assert_eq!(m.kicks, vec![(0, 1)]);
    // Hart 1, woken, runs B.
    assert_eq!(m.pick(1), Some(b));
    assert!(!co_runs_incompatible(&m));
}

#[test]
fn a_running_task_keeps_the_hart_when_only_an_incompatible_one_is_ready() {
    let mut m = M::new(2);
    let (a1, a2, b) = (m.task(1, false), m.task(1, false), m.task(2, false));
    m.ready(0, a1);
    m.ready(1, a2);
    m.pick(0);
    m.pick(1);
    // Hart 1's tick: B is ready, the running A2 is compatible and stays.
    m.ready(1, b);
    assert_eq!(m.pick(1), Some(a2));
    assert_eq!(m.run[1], Some(a2));
    assert!(!co_runs_incompatible(&m));
}

#[test]
fn a_refused_fair_task_waits_its_patience_then_reserves_the_core() {
    let mut m = M::new(2);
    let (a1, a2, b) = (m.task(1, false), m.task(1, false), m.task(2, false));
    m.ready(0, a1);
    m.ready(1, a2);
    m.pick(0);
    m.pick(1);
    m.ready(1, b);
    // Before the patience: no reservation, nobody is asked to yield.
    m.now = 50;
    assert_eq!(m.pick(1), Some(a2));
    assert!(!m.yields(0));
    // After it: the next refusal reserves the core, and hart 0 is rung.
    m.now = 50 + PATIENCE + 1;
    m.kicks.clear();
    let got = m.pick(1).unwrap();
    assert!(m.tasks[got].idle, "the sibling's Domain is displaced: hart 1 idles for B");
    assert!(m.kicks.contains(&(1, 0)));
    assert!(m.yields(0));
    // Hart 0 yields at its pick (the caller's pick takes its idle task) ...
    m.now += 1;
    let idle0 = m.idle_of(0);
    assert!(m.tasks[idle0].idle);
    m.q[0].retain(|&t| t != idle0);
    m.q[0].push(idle0);
    let got = m.pick_forced_idle(0);
    assert!(m.tasks[got].idle);
    // ... which rings the waiting hart, whose pick now takes B.
    assert!(m.kicks.contains(&(0, 1)));
    assert_eq!(m.pick(1), Some(b));
    assert!(!co_runs_incompatible(&m));
    // The reservation is spent: B runs, and A1 can no longer be admitted beside it.
    assert!(!m.yields(0));
}

impl M {
    /// A hart that must yield picks its idle task first, as `do_schedule` does.
    fn pick_forced_idle(&mut self, cpu: usize) -> usize {
        let i = self.q[cpu].iter().position(|&t| self.tasks[t].idle).unwrap();
        let idle = self.q[cpu].remove(i);
        self.q[cpu].insert(0, idle);
        // The task that ran is put back by the caller after the pick.
        let old = self.run[cpu];
        if let Some(o) = old {
            self.q[cpu].retain(|&t| t != o);
            let at = self.q[cpu].iter().position(|&x| self.tasks[x].idle).unwrap_or(self.q[cpu].len());
            self.q[cpu].insert(at + 1, o);
        }
        self.pick(cpu).unwrap()
    }
}

#[test]
fn a_strong_task_displaces_fair_siblings_at_once() {
    let mut m = M::new(2);
    let (a, rt) = (m.task(1, false), m.task(2, true));
    m.ready(0, a);
    m.pick(0);
    m.ready_first(1, rt);
    let got = m.pick(1).unwrap();
    // Refused for now (hart 0 still runs A), but the core is reserved for it.
    assert!(m.tasks[got].idle);
    assert!(m.yields(0), "no patience: strong claims displace immediately");
    assert!(m.kicks.contains(&(1, 0)));
    m.pick_forced_idle(0);
    assert_eq!(m.pick(1), Some(rt));
    assert!(!co_runs_incompatible(&m));
}

#[test]
fn a_fair_task_never_displaces_a_strong_one() {
    let mut m = M::new(2);
    let (rt, b) = (m.task(1, true), m.task(2, false));
    m.ready(0, rt);
    m.pick(0);
    m.ready(1, b);
    // However long B waits, hart 0 is not asked to yield.
    for k in 0..5 {
        m.now += PATIENCE * 2;
        let got = m.pick(1).unwrap();
        assert!(m.tasks[got].idle, "round {k}");
        assert!(!m.yields(0), "round {k}");
    }
    // Not even a ring: nothing was asked of the strong sibling, and the core
    // holds no reservation that would keep other Domains off it.
    assert!(m.kicks.is_empty());
    let c = Claim::task(2, false);
    assert_eq!(m.core.admit(m.smt(1), 1, c, m.now + 1, PATIENCE), Admit::Refuse { kick: 0, drain: false });
    assert_eq!(m.running(0), Some(1));
    assert!(!co_runs_incompatible(&m));
}

#[test]
fn a_strong_task_waits_behind_a_strong_sibling_of_another_domain() {
    let mut m = M::new(2);
    let (rt1, rt2) = (m.task(1, true), m.task(2, true));
    m.ready(0, rt1);
    m.pick(0);
    m.ready_first(1, rt2);
    let got = m.pick(1).unwrap();
    assert!(m.tasks[got].idle);
    assert!(!m.yields(0));
    assert!(!co_runs_incompatible(&m));
}

#[test]
fn a_reservation_expires_when_its_owner_never_comes() {
    let mut m = M::new(2);
    let (a1, a2, b) = (m.task(1, false), m.task(1, false), m.task(2, false));
    m.ready(0, a1);
    m.ready(1, a2);
    m.pick(0);
    m.pick(1);
    m.ready(1, b);
    m.now = 1000;
    m.pick(1);
    m.now = 1000 + PATIENCE + 1;
    m.pick(1);
    assert!(m.yields(0));
    // B goes away (migrated, exited) and its hart never asks again.
    m.now += PATIENCE + 1;
    assert!(!m.yields(0), "the reservation is spent after one more patience");
    // Hart 0 may take new work of its own Domain, and B's Domain is still out.
    let a3 = m.task(1, false);
    m.ready(0, a3);
    m.pick(0);
    assert!(!co_runs_incompatible(&m));
}

#[test]
fn while_the_core_is_reserved_only_the_reserved_domain_is_admitted() {
    let mut m = M::new(2);
    let (a1, a2, b, a3) = (m.task(1, false), m.task(1, false), m.task(2, false), m.task(1, false));
    m.ready(0, a1);
    m.ready(1, a2);
    m.pick(0);
    m.pick(1);
    m.ready(1, b);
    m.now = 10;
    m.pick(1);
    m.now = 10 + PATIENCE + 1;
    m.pick(1);
    // Hart 0 yields. Its other A task is refused while the core is B's.
    m.pick_forced_idle(0);
    m.ready(0, a3);
    let got = m.pick(0).unwrap();
    assert!(m.tasks[got].idle, "an A task does not take the core back from the reserver");
    assert_eq!(m.pick(1), Some(b));
    assert!(!co_runs_incompatible(&m));
}

#[test]
fn a_hart_with_no_idle_task_is_claimed_for_its_only_candidate() {
    let mut m = M::new(2);
    let (a, b) = (m.task(1, false), m.task(2, false));
    m.ready(0, a);
    m.pick(0);
    // Hart 1 has B alone: take its idle task away.
    m.q[1].clear();
    m.q[1].push(b);
    assert_eq!(m.pick(1), Some(b));
    assert_eq!(m.core.claim(1), Claim::task(2, false), "the claim is recorded, so siblings see it");
}

#[test]
fn harts_of_different_cores_do_not_constrain_each_other() {
    let mut m = M::new(4);
    let (a, b) = (m.task(1, false), m.task(2, false));
    m.ready(0, a);
    m.ready(2, b);
    assert_eq!(m.pick(0), Some(a));
    assert_eq!(m.pick(2), Some(b));
    assert!(!co_runs_incompatible(&m));
}

#[test]
fn the_idle_task_claims_nothing_and_never_blocks_a_sibling() {
    let m = M::new(2);
    assert!(Claim::IDLE.compatible(Claim::task(5, true)));
    assert!(Claim::task(5, true).compatible(Claim::IDLE));
    assert!(!Claim::task(5, false).compatible(Claim::task(6, false)));
    assert!(Claim::task(5, false).compatible(Claim::task(5, true)));
    drop(m);
}

#[test]
fn force_records_the_first_task_of_a_hart() {
    let c = CoreSched::new();
    let smt = 0b11;
    assert_eq!(c.force(smt, 0, Claim::task(3, false)), 0);
    // The sibling now sees it.
    assert_eq!(c.admit(smt, 1, Claim::task(4, false), 1, 10), Admit::Refuse { kick: 0, drain: false });
    assert!(matches!(c.admit(smt, 1, Claim::task(3, false), 1, 10), Admit::Run { .. }));
}

/// A randomised run of four harts (two cores): whatever the interleaving of
/// ticks, wakes and blocks, siblings never run different cookies.
#[test]
fn a_random_schedule_never_co_runs_incompatible_pairs() {
    let mut seed = 0x2545F4914F6CDD1Du64;
    let mut rnd = move |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    let mut m = M::new(4);
    let mut tasks = vec![];
    for k in 0..24 {
        tasks.push(m.task(1 + (k % 3) as u32, k % 11 == 0));
    }
    for (k, &t) in tasks.iter().enumerate() {
        m.ready(k % 4, t);
    }
    for hart in 0..4 {
        m.pick(hart);
    }
    let mut yielded = 0;
    for step in 0..4000 {
        m.now += rnd(40);
        let hart = rnd(4) as usize;
        if m.yields(hart) {
            m.pick_forced_idle(hart);
            yielded += 1;
        } else if rnd(3) == 0 {
            m.block(hart);
        } else {
            m.pick(hart);
        }
        // Wake sleepers: a task not queued anywhere is made ready somewhere.
        for &t in &tasks {
            let queued = m.q.iter().any(|q| q.contains(&t));
            let running = m.run.iter().any(|&r| r == Some(t));
            if !queued && !running && rnd(2) == 0 {
                m.ready(rnd(4) as usize, t);
            }
        }
        assert!(!co_runs_incompatible(&m), "step {step}: {:?}", m.run);
    }
    assert!(yielded > 0, "the walk reserved a core at least once");
}

/// The canary of the invariant above: the same walk with the filter off (every
/// claim admitted) does co-run incompatible pairs, so the check can fail.
#[test]
fn the_invariant_check_fails_on_an_unfiltered_pick() {
    let mut m = M::new(2);
    let (a, b) = (m.task(1, false), m.task(2, false));
    // No core_pick: both harts just take their best task.
    m.run[0] = Some(a);
    m.run[1] = Some(b);
    assert!(co_runs_incompatible(&m));
}

/// Real threads on one core: whoever is admitted bumps its cookie's counter and
/// must never see the other cookie's counter above zero.
#[test]
fn two_threads_racing_for_a_core_never_run_both_cookies() {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    let core = Arc::new(CoreSched::new());
    let live = Arc::new([AtomicU32::new(0), AtomicU32::new(0)]);
    let smt = 0b11;
    let hs: Vec<_> = (0..2usize)
        .map(|cpu| {
            let (core, live) = (core.clone(), live.clone());
            std::thread::spawn(move || {
                // Until it has run 500 times: the other thread may hold the core
                // for a long stretch, and ends with it idle.
                let (mut ran, mut i) = (0u32, 0u64);
                while ran < 500 {
                    i += 1;
                    let me = cpu;
                    match core.admit(smt, cpu, Claim::task(me as u32, false), i + 1, 1 << 40) {
                        Admit::Run { .. } => {
                            live[me].fetch_add(1, Ordering::SeqCst);
                            assert_eq!(live[1 - me].load(Ordering::SeqCst), 0, "co-ran at {i}");
                            ran += 1;
                            live[me].fetch_sub(1, Ordering::SeqCst);
                            core.admit(smt, cpu, Claim::IDLE, i + 1, 1 << 40);
                        }
                        Admit::Refuse { .. } => std::thread::yield_now(),
                    }
                }
                ran
            })
        })
        .collect();
    let ran: Vec<u32> = hs.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(ran, vec![500, 500]);
}
