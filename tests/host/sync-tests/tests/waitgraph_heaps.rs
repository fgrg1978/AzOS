// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The wait graph's sets at the size of the largest task table: the heap's
//! order and shape against a model, and random graphs against effective
//! attributes recomputed from scratch.

use azos_sync_tests::pi_heap::{self, Node, NIL};
use azos_sync_tests::waitgraph::*;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

struct Xorshift(u64);
impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn spine(nodes: &[Node], root: u32) -> usize {
    let (mut n, mut c) = (0, root);
    while c != NIL {
        n += 1;
        c = nodes[c as usize].right();
    }
    n
}

/// Every operation against a sorted model, with the right spine, what a merge
/// walks, at most `log2(n + 1)` long.
#[test]
fn heap_matches_a_sorted_model_and_keeps_its_spine_logarithmic() {
    const N: usize = 4096;
    let mut rng = Xorshift(0x9e37_79b9_7f4a_7c15);
    let mut key = vec![0u64; N];
    let mut nodes = vec![Node::EMPTY; N];
    let mut root = NIL;
    let mut model: Vec<u32> = Vec::new();
    let mut clock = 0;
    let mut joined = vec![0u64; N];
    for step in 0..200_000 {
        let grow = model.len() < N / 2 || (step / 40_000) % 2 == 0;
        let free: Option<u32> = (0..8).map(|_| (rng.next() as usize % N) as u32).find(|&t| !nodes[t as usize].in_heap());
        if let (true, Some(t)) = (grow || model.is_empty(), free) {
            key[t as usize] = rng.next() % 16;
            clock += 1;
            joined[t as usize] = clock;
            let first = |x: u32, y: u32| (key[x as usize], joined[x as usize]) < (key[y as usize], joined[y as usize]);
            root = pi_heap::insert(&mut nodes, root, t, &first);
            model.push(t);
        } else if !model.is_empty() {
            let t = model.swap_remove(rng.next() as usize % model.len());
            // The key may already have moved: a removal does not read it.
            key[t as usize] = rng.next() % 16;
            let first = |x: u32, y: u32| (key[x as usize], joined[x as usize]) < (key[y as usize], joined[y as usize]);
            root = pi_heap::remove(&mut nodes, root, t, &first);
            assert!(!nodes[t as usize].in_heap());
        }
        let top = model.iter().copied().min_by_key(|&t| (key[t as usize], joined[t as usize]));
        assert_eq!(if root == NIL { None } else { Some(root) }, top, "step {step}: wrong top");
        let bound = (usize::BITS - model.len().leading_zeros()) as usize;
        assert!(spine(&nodes, root) <= bound, "step {step}: spine {} past {bound} with {} nodes", spine(&nodes, root), model.len());
    }
}

const N: usize = 512;

struct Rec {
    base: [AtomicU8; N],
    on: [AtomicUsize; N],
}

impl SchedPi for Rec {
    fn base_attr(&self, t: TaskId) -> PiAttr { PiAttr::Rt { prio: self.base[t as usize].load(Ordering::Relaxed) } }
    fn boost(&self, _t: TaskId, _to: PiAttr) {}
    fn unboost(&self, _t: TaskId, _to: PiAttr) {}
    fn set_blocked_on(&self, t: TaskId, on: Option<WaitObj>) {
        self.on[t as usize].store(on.map_or(0, WaitObj::addr), Ordering::Relaxed);
    }
    fn blocked_on(&self, t: TaskId) -> Option<WaitObj> {
        WaitObj::from_addr(self.on[t as usize].load(Ordering::Relaxed))
    }
    fn on_cpu(&self, _t: TaskId) -> bool { false }
}

static S: Rec = Rec { base: [const { AtomicU8::new(0) }; N], on: [const { AtomicUsize::new(0) }; N] };
static G: Graph<N> = Graph::new();
static O: [PiWaiters; N] = [const { PiWaiters::new(EdgeKind::Mutex) }; N];

/// Waiters come and go, and owners change, on objects no chain joins: what an
/// owner inherits is the most urgent of all it owns, however it got there.
#[test]
fn an_owner_inherits_the_most_urgent_of_everything_it_owns() {
    G.register_sched(&S);
    let mut rng = Xorshift(0x2545_f491_4f6c_dd1d);
    // Tasks below 32 own and never wait, the rest wait and never own: no chains.
    const OWNERS: usize = 32;
    let mut waits_on: Vec<Option<usize>> = vec![None; N];
    let mut owner: Vec<Option<u32>> = vec![None; N];
    for t in 0..N {
        S.base[t].store(if t < OWNERS { 90 } else { (rng.next() % 90) as u8 }, Ordering::Relaxed);
    }
    for step in 0..100_000 {
        let w = OWNERS + rng.next() as usize % (N - OWNERS);
        let o = rng.next() as usize % N;
        match rng.next() % 8 {
            0 => {
                let new = (rng.next() as usize % OWNERS) as u32;
                G.set_owner(&O[o], if rng.next() % 4 == 0 { None } else { Some(new) });
                owner[o] = O[o].owner();
            }
            1..=4 => {
                if waits_on[w].is_none() && owner[o].is_some() {
                    G.block_on(w as u32, &O[o]).expect("no chains, no cycles");
                    waits_on[w] = Some(o);
                }
            }
            _ => {
                if let Some(o) = waits_on[w].take() {
                    G.unblock(w as u32, &O[o], UnblockReason::Timeout);
                }
            }
        }
        if step % 64 != 0 {
            continue;
        }
        for t in 0..OWNERS as u32 {
            let want = (OWNERS..N)
                .filter(|&w| waits_on[w].is_some_and(|o| owner[o] == Some(t)))
                .map(|w| S.base_attr(w as u32))
                .fold(S.base_attr(t), |a, b| a.max_urgent(b));
            let got = G.effective(t).unwrap_or(S.base_attr(t));
            assert_eq!(got, want, "step {step}: task {t}");
        }
        for o in 0..N {
            let first = (OWNERS..N)
                .filter(|&w| waits_on[w] == Some(o))
                .map(|w| S.base_attr(w as u32))
                .fold(None::<PiAttr>, |a, b| Some(a.map_or(b, |a| a.max_urgent(b))));
            assert_eq!(G.top_waiter(&O[o]).map(|(_, a)| a), first, "step {step}: object {o}");
        }
    }
}
