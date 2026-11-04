// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of `crates/core/sched/src/eevdf_tree.rs`.
//!
//! The reference is the definition read off a plain list: the queued entities
//! in the order the ready lists give (level, then arrival), `V` over them and
//! the running one, the eligible one with the earliest deadline, ties to the
//! running one and then the first. The tree must pick the same task after any
//! sequence of links, unlinks, reweights and charges, and its augmented data
//! must satisfy `Tree::check` after each step.
//!
//! Canary: `eevdf-tree-canary` leaves a node's least `v` as first linked; the
//! differential tests below go red (`the_tree_picks_what_the_list_picks_*`,
//! `the_tree_holds_its_invariants_*`). `eevdf-fifo-canary` goes red here too.

use core::cell::Cell;

use super::eevdf_core::*;
use super::eevdf_tree::*;

const BLANK: Node =
    Node { left: NIL, right: NIL, parent: NIL, weight: 0, height: 0, owner: 0, deadline: 0, vruntime: 0, min_v: 0, tie: 0 };

/// A node table in a `Vec`, counting the nodes read.
pub struct VecStore {
    n: Vec<Cell<Node>>,
    reads: Cell<u64>,
}

impl VecStore {
    pub fn new(len: usize) -> Self {
        Self { n: (0..len).map(|_| Cell::new(BLANK)).collect(), reads: Cell::new(0) }
    }
}

impl Store for VecStore {
    fn node(&self, i: usize) -> Node {
        self.reads.set(self.reads.get() + 1);
        self.n[i].get()
    }
    fn set(&self, i: usize, n: Node) {
        self.n[i].set(n);
    }
}

/// The pick over `queued` (all at level 0, in iteration order) and `cur`,
/// through a tree built for the call: the other host suites' simulators run on
/// the real pick.
pub fn choose<I>(queued: impl Fn() -> I, cur: Option<(usize, Ent)>) -> Choice
where
    I: Iterator<Item = (usize, Ent)>,
{
    let items: Vec<(usize, Ent)> = queued().collect();
    let len = items.iter().map(|(i, _)| i + 1).chain(cur.map(|(i, _)| i + 1)).max().unwrap_or(0);
    let st = VecStore::new(len);
    let mut t = Tree::new(0);
    for (i, e) in &items {
        assert!(t.insert(&st, *i, e, 0));
    }
    t.check(&st).unwrap();
    t.pick(&st, cur)
}

/// The definition, on a list already in the lists' order. `reads` counts the
/// entities looked at.
fn choose_linear(queued: &[(usize, Ent)], cur: Option<(usize, Ent)>, reads: &mut u64) -> Choice {
    let mut avg = Avg::new();
    for (_, e) in queued {
        avg.add(e);
        *reads += 1;
    }
    if queued.is_empty() {
        return if cur.is_some() { Choice::Cur } else { Choice::Empty };
    }
    if let Some((_, c)) = &cur {
        avg.add(c);
    }
    let mut best: Option<(usize, i64)> = None;
    for (id, e) in queued {
        *reads += 1;
        if avg.eligible(e) && best.is_none_or(|(_, d)| e.deadline < d) {
            best = Some((*id, e.deadline));
        }
    }
    match (best, cur) {
        (None, Some(_)) => Choice::Cur,
        (None, None) => Choice::Task(queued.iter().min_by_key(|(_, e)| e.deadline).unwrap().0),
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

#[derive(Clone, Copy)]
struct M {
    e: Ent,
    level: u32,
    seq: u64,
}

/// The queue as a list, and the tree kept beside it.
struct Q {
    st: VecStore,
    tree: Tree,
    m: Vec<Option<M>>,
    cur: Option<(usize, M)>,
    seq: u64,
    rng: Rng,
}

impl Q {
    fn new(ids: usize, seed: u64) -> Self {
        Self { st: VecStore::new(ids), tree: Tree::new(0), m: vec![None; ids], cur: None, seq: 0, rng: Rng(seed) }
    }

    fn ent(&mut self) -> Ent {
        let w = WEIGHTS[self.rng.below(40) as usize];
        let mut e = Ent::new(w, 100 + self.rng.below(4000));
        // A narrow range of `v` and of deadlines: ties and ineligible
        // entities are the common case.
        e.vruntime = self.rng.below(60) as i64 - 30;
        e.deadline = self.rng.below(24) as i64;
        e
    }

    fn link(&mut self, id: usize, e: Ent, level: u32) {
        assert!(self.tree.insert(&self.st, id, &e, level));
        self.m[id] = Some(M { e, level, seq: self.seq });
        self.seq += 1;
    }

    fn unlink(&mut self, id: usize) {
        assert_eq!(self.tree.remove(&self.st, id), Unlink::Done);
        self.m[id] = None;
    }

    fn list(&self) -> Vec<(usize, Ent)> {
        let mut v: Vec<(usize, M)> = self.m.iter().enumerate().filter_map(|(i, m)| m.map(|m| (i, m))).collect();
        v.sort_by_key(|(_, m)| (m.level, m.seq));
        v.into_iter().map(|(i, m)| (i, m.e)).collect()
    }

    fn cur_ent(&self) -> Option<(usize, Ent)> {
        self.cur.map(|(i, m)| (i, m.e))
    }

    fn free_id(&mut self) -> Option<usize> {
        let n = self.m.len();
        let s = self.rng.below(n as u64) as usize;
        (0..n).map(|k| (s + k) % n).find(|&i| self.m[i].is_none() && self.cur.map(|c| c.0) != Some(i))
    }

    fn member(&mut self) -> Option<usize> {
        let ids: Vec<usize> = (0..self.m.len()).filter(|&i| self.m[i].is_some()).collect();
        if ids.is_empty() {
            None
        } else {
            Some(ids[self.rng.below(ids.len() as u64) as usize])
        }
    }

    /// One random operation, then the pick against the reference.
    fn step(&mut self, levels: u64) -> (Choice, u64) {
        match self.rng.below(8) {
            0..=2 => {
                if let Some(id) = self.free_id() {
                    let e = self.ent();
                    let level = self.rng.below(levels) as u32;
                    self.link(id, e, level);
                }
            }
            3 => {
                if let Some(id) = self.member() {
                    self.unlink(id);
                }
            }
            4 => {
                // A reweight: a priority change takes the task off and puts it back.
                if let Some(id) = self.member() {
                    let m = self.m[id].unwrap();
                    self.unlink(id);
                    let mut e = m.e;
                    e.weight = WEIGHTS[self.rng.below(40) as usize];
                    self.link(id, e, m.level);
                }
            }
            5 | 6 => {
                if let Some((_, m)) = self.cur.as_mut() {
                    let dt = 1 + self.rng.below(3000);
                    charge(&mut m.e, dt);
                }
            }
            _ => {
                if self.cur.is_some() && self.rng.below(4) == 0 {
                    self.cur = None;
                }
            }
        }
        let mut reads = 0;
        let want = choose_linear(&self.list(), self.cur_ent(), &mut reads);
        self.st.reads.set(0);
        let got = self.tree.pick(&self.st, self.cur_ent());
        let used = self.st.reads.get();
        assert_eq!(got, want, "tree and list pick differently");
        self.tree.check(&self.st).expect("the tree's invariants");
        assert_eq!(self.tree.len(), self.m.iter().flatten().count());
        // The switch the pick asked for: the old runner goes back in the queue.
        if let Choice::Task(id) = got {
            let m = self.m[id].unwrap();
            self.unlink(id);
            if let Some((old, om)) = self.cur.take() {
                self.link(old, om.e, om.level);
            }
            self.cur = Some((id, m));
        }
        (got, used)
    }
}

#[test]
fn the_tree_picks_what_the_list_picks_over_random_sequences() {
    for seed in 1..=40u64 {
        let ids = [6, 24, 64][seed as usize % 3];
        let mut q = Q::new(ids, seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        for _ in 0..1500 {
            q.step(1 + seed % 3);
        }
    }
}

#[test]
fn the_tree_picks_what_the_list_picks_at_five_hundred_members() {
    let mut q = Q::new(700, 0xC0FFEE);
    for _ in 0..3000 {
        q.step(4);
    }
    assert!(q.m.iter().flatten().count() > 100);
}

#[test]
fn the_tree_holds_its_invariants_when_drained_and_refilled() {
    let mut q = Q::new(200, 7);
    for round in 0..4 {
        for id in 0..200 {
            let e = q.ent();
            q.link(id, e, (id % 3) as u32);
            q.tree.check(&q.st).unwrap();
        }
        let mut ids: Vec<usize> = (0..200).collect();
        // Out of arrival order.
        ids.sort_by_key(|i| (i * 37 + round * 11) % 200);
        for id in ids {
            q.unlink(id);
            q.tree.check(&q.st).unwrap();
        }
        assert!(q.tree.is_empty());
        assert_eq!(q.tree.pick(&q.st, None), Choice::Empty);
    }
}

#[test]
fn equal_deadlines_go_to_the_lower_level_then_the_first_linked() {
    let st = VecStore::new(8);
    let mut t = Tree::new(0);
    let e = Ent::new(1024, 1000);
    assert!(t.insert(&st, 3, &e, 2));
    assert!(t.insert(&st, 4, &e, 1));
    assert!(t.insert(&st, 5, &e, 1));
    assert!(t.insert(&st, 6, &e, 2));
    assert_eq!(t.pick(&st, None), Choice::Task(4));
    t.remove(&st, 4);
    assert_eq!(t.pick(&st, None), Choice::Task(5));
    t.remove(&st, 5);
    assert_eq!(t.pick(&st, None), Choice::Task(3));
    assert_eq!(t.pick(&st, Some((7, e))), Choice::Cur, "the runner wins a tie");
}

#[test]
fn a_node_unlinked_is_not_found_again_and_a_relink_replaces_it() {
    let st = VecStore::new(4);
    let mut t = Tree::new(0);
    let e = Ent::new(1024, 1000);
    assert!(t.insert(&st, 1, &e, 0));
    assert_eq!(t.remove(&st, 1), Unlink::Done);
    assert_eq!(t.remove(&st, 1), Unlink::Absent);
    assert_eq!(t.remove(&st, 2), Unlink::Absent);
    assert!(t.insert(&st, 1, &e, 0));
    assert!(t.insert(&st, 1, &e, 0));
    assert_eq!(t.len(), 1);
    t.check(&st).unwrap();
}

/// Nodes read by a pick at N queued, the tree against the two passes over the
/// list; printed with `--nocapture`.
#[test]
fn a_pick_reads_a_logarithm_of_the_queue_not_the_queue() {
    for n in [8usize, 64, 512] {
        let mut sum = 0u64;
        let mut max = 0u64;
        let mut old = 0u64;
        let runs = 200;
        for seed in 1..=runs {
            let mut q = Q::new(n, seed * 0x2545_F491 + n as u64);
            for id in 0..n {
                let e = q.ent();
                q.link(id, e, 0);
            }
            let cur = q.ent();
            let mut reads = 0;
            let want = choose_linear(&q.list(), Some((n, cur)), &mut reads);
            old += reads;
            q.st.reads.set(0);
            // `cur` is outside the table: it is not linked.
            let got = q.tree.pick(&q.st, Some((n, cur)));
            let used = q.st.reads.get();
            assert_eq!(got, want);
            sum += used;
            max = max.max(used);
        }
        println!(
            "# pick at N={n}: old {} entities read (two passes), new {:.1} nodes read on average, {max} at most",
            old / runs,
            sum as f64 / runs as f64
        );
        if n == 512 {
            assert!(max * 8 < old / runs, "a pick at 512 read {max} nodes");
        }
    }
}

/// The order the K-C12 race gives without the claim: a node still linked on one
/// CPU's tree reaches another's. Both refuse, nothing moves, and the holder
/// unlinks it afterwards as if nothing had happened.
#[test]
fn a_node_another_tree_holds_is_refused_and_both_stay_whole() {
    let st = VecStore::new(16);
    let (mut a, mut b) = (Tree::new(0), Tree::new(1));
    for i in 0..8 {
        let mut e = Ent::new(1024, 1000);
        e.deadline = i as i64;
        assert!(a.insert(&st, i, &e, 0));
    }
    for i in 8..12 {
        let mut e = Ent::new(1024, 1000);
        e.deadline = i as i64;
        assert!(b.insert(&st, i, &e, 0));
    }
    let held = st.n[3].get();
    let e = Ent::new(1024, 1000);
    assert!(!b.insert(&st, 3, &e, 0), "a held node was taken");
    assert_eq!(b.remove(&st, 3), Unlink::Foreign);
    assert_eq!(st.n[3].get(), held, "a refusal wrote to the node");
    assert_eq!((a.len(), b.len()), (8, 4));
    a.check(&st).unwrap();
    b.check(&st).unwrap();
    assert_eq!(a.remove(&st, 3), Unlink::Done);
    a.check(&st).unwrap();
    assert!(b.insert(&st, 3, &e, 0), "the node is free once its holder let go");
    b.check(&st).unwrap();
}

/// A pick the lists do not back is unlinked, so the next one differs; the tries
/// are bounded even when no node is ever backed.
#[test]
fn a_pick_the_lists_refuse_is_dropped_and_never_repeated() {
    use core::cell::RefCell;
    let st = VecStore::new(32);
    let t = RefCell::new(Tree::new(0));
    for i in 0..20 {
        let mut e = Ent::new(1024, 1000);
        e.deadline = i as i64;
        assert!(t.borrow_mut().insert(&st, i, &e, 0));
    }
    let picks = RefCell::new(Vec::new());
    let run = |tries: usize, exhausted: Choice, backed: &dyn Fn(usize) -> bool| {
        take(
            tries,
            exhausted,
            || t.borrow().pick(&st, None),
            |i| {
                picks.borrow_mut().push(i);
                backed(i)
            },
            |i| {
                assert_eq!(t.borrow_mut().remove(&st, i), Unlink::Done);
            },
        )
    };
    // The first two are stale: the third is taken in the same pass.
    assert_eq!(run(TAKE_TRIES, Choice::Cur, &|i| i >= 2), Choice::Task(2));
    assert_eq!(*picks.borrow(), vec![0, 1, 2]);
    assert_eq!(t.borrow().len(), 18);
    // All stale, a running task to fall back on: the bound, then the next pass.
    picks.borrow_mut().clear();
    assert_eq!(run(TAKE_TRIES, Choice::Cur, &|_| false), Choice::Cur);
    assert_eq!(picks.borrow().len(), TAKE_TRIES);
    let seen = picks.borrow().clone();
    picks.borrow_mut().clear();
    assert_eq!(run(TAKE_TRIES, Choice::Cur, &|_| false), Choice::Cur);
    assert!(picks.borrow().iter().all(|i| !seen.contains(i)), "a dropped node came back");
    t.borrow().check(&st).unwrap();
    // All stale, nothing running: every node is looked at and the answer is true.
    let len = t.borrow().len();
    assert_eq!(run(len + 1, Choice::Empty, &|_| false), Choice::Empty);
    assert!(t.borrow().is_empty());
}

/// The most nodes an AVL tree of height `h` can need at least: the height bound
/// for `n` nodes is the largest `h` this does not exceed `n` for.
fn avl_height_bound(n: usize) -> u32 {
    let (mut least, mut below, mut h) = (1usize, 0usize, 1u32);
    loop {
        let next = least + below + 1;
        if next > n {
            return h;
        }
        below = least;
        least = next;
        h += 1;
    }
}

fn depth_of(st: &VecStore, root: u32) -> u32 {
    let (mut worst, mut stack) = (0, vec![(root, 1u32)]);
    while let Some((t, d)) = stack.pop() {
        if t == NIL {
            continue;
        }
        worst = worst.max(d);
        let n = st.n[t as usize].get();
        stack.push((n.left, d + 1));
        stack.push((n.right, d + 1));
    }
    worst
}

/// What a sequence read: worst and total reads, and how many operations.
#[derive(Default, Clone, Copy)]
struct Reads {
    worst: u64,
    total: u64,
    ops: u64,
}

impl Reads {
    fn add(&mut self, r: u64) {
        self.worst = self.worst.max(r);
        self.total += r;
        self.ops += 1;
    }
    fn mean(&self) -> f64 {
        self.total as f64 / self.ops.max(1) as f64
    }
}

struct Adversary {
    n: usize,
    st: VecStore,
    t: Tree,
    root_of: fn(&Tree) -> u32,
    bound: u32,
    pick: Reads,
    insert: Reads,
    remove: Reads,
    deepest: u32,
}

impl Adversary {
    fn new(n: usize, st: VecStore) -> Self {
        Self {
            n,
            st,
            t: Tree::new(0),
            root_of: Tree::root,
            bound: avl_height_bound(n),
            pick: Reads::default(),
            insert: Reads::default(),
            remove: Reads::default(),
            deepest: 0,
        }
    }

    fn after(&mut self) {
        let d = depth_of(&self.st, (self.root_of)(&self.t));
        self.deepest = self.deepest.max(d);
        assert!(d <= self.bound, "depth {d} past the bound {} at N={}", self.bound, self.n);
        self.st.reads.set(0);
        let _ = self.t.pick(&self.st, None);
        self.pick.add(self.st.reads.get());
        if self.n <= 64 {
            self.t.check(&self.st).unwrap();
        }
    }

    fn link(&mut self, id: usize, deadline: i64, v: i64) {
        let mut e = Ent::new(1024, 1000);
        e.deadline = deadline;
        e.vruntime = v;
        self.st.reads.set(0);
        assert!(self.t.insert(&self.st, id, &e, 0));
        self.insert.add(self.st.reads.get());
        self.after();
    }

    fn unlink(&mut self, id: usize) {
        self.st.reads.set(0);
        assert_eq!(self.t.remove(&self.st, id), Unlink::Done);
        self.remove.add(self.st.reads.get());
        self.after();
    }
}

/// Arrivals chosen against the shape: deadlines in order, in reverse, from both
/// ends, the yields of a paced user, and a `v` that hides the only eligible node
/// at the far end of the order, so a pick descends the whole height. The depth
/// never passes the AVL bound for that N. Printed with `--nocapture`.
#[test]
fn no_arrival_order_passes_the_height_bound() {
    for n in [8usize, 64, 512] {
        let mut a = Adversary::new(n, VecStore::new(n));
        let tail_v = |i: usize| if i + 1 == n { 0 } else { 1_000_000 };
        for i in 0..n {
            a.link(i, i as i64, tail_v(i));
        }
        for i in 0..n {
            a.unlink(i);
        }
        for i in 0..n {
            a.link(i, (n - i) as i64, tail_v(n - 1 - i));
        }
        for i in (0..n).rev() {
            a.unlink(i);
        }
        for i in 0..n {
            let d = if i % 2 == 0 { i as i64 } else { (2 * n - i) as i64 };
            a.link(i, d, 0);
        }
        // Paced yields: the earliest deadline leaves and arrives behind all the
        // others, the arrival number moving on with every one.
        let mut next = 2 * n as i64;
        for i in 0..8 * n {
            let id = i % n;
            a.unlink(id);
            a.link(id, next, 0);
            next += 1;
        }
        // The root goes every time: the removal with two children, at its worst.
        for _ in 0..n {
            let root = (a.root_of)(&a.t);
            a.unlink(root as usize);
        }
        assert!(a.t.is_empty());
        a.t.check(&a.st).unwrap();
        println!(
            "# adversarial N={n}: depth {} of bound {}; nodes read: pick {} worst {:.1} mean, insert {} worst {:.1} mean, remove {} worst {:.1} mean",
            a.deepest,
            a.bound,
            a.pick.worst,
            a.pick.mean(),
            a.insert.worst,
            a.insert.mean(),
            a.remove.worst,
            a.remove.mean(),
        );
        let b = a.bound as u64;
        assert!(a.pick.worst <= 2 * b + 1, "a pick read {} nodes", a.pick.worst);
        assert!(a.insert.worst <= 8 * b, "an insert read {} nodes", a.insert.worst);
        assert!(a.remove.worst <= 8 * b, "a remove read {} nodes", a.remove.worst);
    }
}

/// The mean a placement reads is the tree's own sums: every linked entity but
/// the one being placed, equal to the mean over the others read one by one.
#[test]
fn the_placement_mean_is_the_trees_sums_without_the_task() {
    let st = VecStore::new(8);
    let mut t = Tree::new(0);
    let es: Vec<Ent> = (0..5i64)
        .map(|i| Ent { weight: 1024 + 300 * i as u32, slice: 1000, vruntime: i * 700 - 900, deadline: i * 700 + 100 })
        .collect();
    for (i, e) in es.iter().enumerate() {
        assert!(t.insert(&st, i, e, 0));
    }
    for skip in 0..es.len() {
        let others = avg_of(es.iter().enumerate().filter(|&(i, _)| i != skip).map(|(_, e)| *e));
        assert!(t.avg_without(&st, skip).same_sums(&others), "skip {skip}");
    }
    // A task this tree does not hold takes nothing out.
    assert!(t.avg_without(&st, 7).same_sums(&avg_of(es.iter().copied())));
    let other = Tree::new(1);
    assert!(other.avg_without(&st, 2).is_empty(), "another tree's node is not this tree's");
}
