// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The order of the fair queue: the pick of `eevdf_core.rs` in O(log n).
//!
//! A treap keyed by (virtual deadline, level, arrival), so the in-order walk
//! is the order the ready lists give among equal deadlines: a lower priority
//! level first, then FIFO. Each node carries the least `v` of its subtree, so
//! the first eligible node in key order is found by one descent: go left while
//! the left subtree holds an eligible `v` (eligibility is `v <= V`, so the
//! subtree's least `v` is the test), else take this node if it is eligible,
//! else go right. The mean `V` comes from the sums of the whole tree, kept as
//! entities are linked and unlinked.
//!
//! The nodes live in a table indexed by task slot ([`Store`]), one per task
//! because a task is on one queue at a time; a node is linked while its weight
//! is not 0, and holds the numbers the entity had when it was linked, which is
//! what unlinking subtracts from the sums. The heap priority of a node is a
//! hash of its arrival number, so the shape does not depend on what a user
//! chooses. No allocation; recursion is as deep as the tree.
//!
//! Pure (`core` only): the kernel's `fairq.rs` owns one [`Tree`] per CPU under
//! that CPU's lock, and `tests/host/sched-policy-tests` pulls this file in.

use core::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering::Relaxed};

use crate::eevdf_core::{Avg, Choice, Ent};

/// No child.
pub const NIL: u32 = u32::MAX;

const SEQ_MASK: u64 = (1 << 56) - 1;
/// A tree this deep is a cycle.
const MAX_DEPTH: u32 = 128;

/// One entity's node. Linked while `weight != 0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node {
    pub left: u32,
    pub right: u32,
    pub weight: u32,
    pub deadline: i64,
    pub vruntime: i64,
    /// The least `vruntime` of this node and everything below it.
    pub min_v: i64,
    /// Level and arrival number: the order among equal deadlines.
    pub tie: u64,
}

/// The table of nodes. `i` is below the number of tasks the caller manages.
pub trait Store {
    fn node(&self, i: usize) -> Node;
    fn set(&self, i: usize, n: Node);
}

struct Slot {
    left: AtomicU32,
    right: AtomicU32,
    weight: AtomicU32,
    deadline: AtomicI64,
    vruntime: AtomicI64,
    min_v: AtomicI64,
    tie: AtomicU64,
}

/// `N` nodes in atomics, all unlinked. Every access is `Relaxed`: the lock of
/// the queue a node is linked on orders them, as it does the ready lists'.
pub struct AtomicNodes<const N: usize>([Slot; N]);

impl<const N: usize> AtomicNodes<N> {
    pub const fn new() -> Self {
        Self(
            [const {
                Slot {
                    left: AtomicU32::new(NIL),
                    right: AtomicU32::new(NIL),
                    weight: AtomicU32::new(0),
                    deadline: AtomicI64::new(0),
                    vruntime: AtomicI64::new(0),
                    min_v: AtomicI64::new(0),
                    tie: AtomicU64::new(0),
                }
            }; N],
        )
    }
}

impl<const N: usize> Default for AtomicNodes<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Store for AtomicNodes<N> {
    #[inline]
    fn node(&self, i: usize) -> Node {
        let n = &self.0[i];
        Node {
            left: n.left.load(Relaxed),
            right: n.right.load(Relaxed),
            weight: n.weight.load(Relaxed),
            deadline: n.deadline.load(Relaxed),
            vruntime: n.vruntime.load(Relaxed),
            min_v: n.min_v.load(Relaxed),
            tie: n.tie.load(Relaxed),
        }
    }

    #[inline]
    fn set(&self, i: usize, v: Node) {
        let n = &self.0[i];
        n.left.store(v.left, Relaxed);
        n.right.store(v.right, Relaxed);
        n.weight.store(v.weight, Relaxed);
        n.deadline.store(v.deadline, Relaxed);
        n.vruntime.store(v.vruntime, Relaxed);
        n.min_v.store(v.min_v, Relaxed);
        n.tie.store(v.tie, Relaxed);
    }
}

#[inline]
fn hprio(tie: u64) -> u32 {
    (tie.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as u32
}

#[inline]
fn before(d: i64, tie: u64, n: &Node) -> bool {
    (d, tie) < (n.deadline, n.tie)
}

/// Recompute `t`'s least `v` from its children.
/// `eevdf-tree-canary`: left stale, as the node was first linked.
fn pull<S: Store>(s: &S, t: u32) {
    if cfg!(feature = "eevdf-tree-canary") {
        return;
    }
    let mut n = s.node(t as usize);
    let mut m = n.vruntime;
    if n.left != NIL {
        m = m.min(s.node(n.left as usize).min_v);
    }
    if n.right != NIL {
        m = m.min(s.node(n.right as usize).min_v);
    }
    n.min_v = m;
    s.set(t as usize, n);
}

/// Keys below `(d, tie)` in the first tree, the rest in the second.
fn split<S: Store>(s: &S, t: u32, d: i64, tie: u64) -> (u32, u32) {
    if t == NIL {
        return (NIL, NIL);
    }
    let mut n = s.node(t as usize);
    if before(d, tie, &n) {
        let (l, r) = split(s, n.left, d, tie);
        n.left = r;
        s.set(t as usize, n);
        pull(s, t);
        (l, t)
    } else {
        let (l, r) = split(s, n.right, d, tie);
        n.right = l;
        s.set(t as usize, n);
        pull(s, t);
        (t, r)
    }
}

/// Every key of `a` is below every key of `b`.
fn merge<S: Store>(s: &S, a: u32, b: u32) -> u32 {
    if a == NIL {
        return b;
    }
    if b == NIL {
        return a;
    }
    let (mut na, nb) = (s.node(a as usize), s.node(b as usize));
    if hprio(na.tie) > hprio(nb.tie) {
        na.right = merge(s, na.right, b);
        s.set(a as usize, na);
        pull(s, a);
        a
    } else {
        let mut nb = nb;
        nb.left = merge(s, a, nb.left);
        s.set(b as usize, nb);
        pull(s, b);
        b
    }
}

/// The subtree at `t` without the node keyed `(d, tie)`, and whether it was there.
fn erase<S: Store>(s: &S, t: u32, d: i64, tie: u64) -> (u32, bool) {
    if t == NIL {
        return (NIL, false);
    }
    let mut n = s.node(t as usize);
    if n.tie == tie && n.deadline == d {
        return (merge(s, n.left, n.right), true);
    }
    let found;
    if before(d, tie, &n) {
        let (c, f) = erase(s, n.left, d, tie);
        n.left = c;
        found = f;
    } else {
        let (c, f) = erase(s, n.right, d, tie);
        n.right = c;
        found = f;
    }
    if found {
        s.set(t as usize, n);
        pull(s, t);
    }
    (t, found)
}

/// One queue's order and sums.
#[derive(Clone, Copy, Debug)]
pub struct Tree {
    root: u32,
    len: u32,
    seq: u64,
    avg: Avg,
}

impl Tree {
    pub const fn new() -> Self {
        Self { root: NIL, len: 0, seq: 0, avg: Avg::new() }
    }

    /// Linked entities.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Link task `idx` with `e`'s numbers at priority `level`, after the
    /// entities already linked with the same deadline and level. An `idx` that
    /// is still linked is unlinked first.
    pub fn insert<S: Store>(&mut self, s: &S, idx: usize, e: &Ent, level: u32) {
        if s.node(idx).weight != 0 {
            self.remove(s, idx);
        }
        let tie = (level as u64) << 56 | (self.seq & SEQ_MASK);
        self.seq = self.seq.wrapping_add(1);
        let weight = e.weight.max(1);
        let deadline = if cfg!(feature = "eevdf-fifo-canary") { 0 } else { e.deadline };
        s.set(idx, Node { left: NIL, right: NIL, weight, deadline, vruntime: e.vruntime, min_v: e.vruntime, tie });
        let (l, r) = split(s, self.root, deadline, tie);
        let m = merge(s, l, idx as u32);
        self.root = merge(s, m, r);
        self.len += 1;
        self.avg.add(&Ent { weight, ..*e });
    }

    /// Unlink task `idx`; false when it is not linked here.
    pub fn remove<S: Store>(&mut self, s: &S, idx: usize) -> bool {
        let n = s.node(idx);
        if n.weight == 0 {
            return false;
        }
        let (root, found) = erase(s, self.root, n.deadline, n.tie);
        if !found {
            return false;
        }
        self.root = root;
        self.len -= 1;
        s.set(idx, Node { weight: 0, left: NIL, right: NIL, ..n });
        self.avg.remove(&Ent { weight: n.weight, slice: 0, vruntime: n.vruntime, deadline: n.deadline });
        true
    }

    /// The eligible entity with the earliest deadline among the linked ones and
    /// `cur`, the running entity, which counts in the mean and keeps the CPU on
    /// a tie (then the first linked one wins, FIFO). `V` is the mean over both.
    ///
    /// `eevdf-fifo-canary`: nodes are keyed by arrival alone, so the first
    /// eligible one is picked, not the earliest deadline.
    pub fn pick<S: Store>(&self, s: &S, cur: Option<(usize, Ent)>) -> Choice {
        if self.root == NIL {
            return if cur.is_some() { Choice::Cur } else { Choice::Empty };
        }
        let mut avg = self.avg;
        if let Some((_, c)) = &cur {
            avg.add(c);
        }
        let mut best = None;
        let mut t = self.root;
        let mut n = s.node(t as usize);
        loop {
            if n.left != NIL {
                let l = s.node(n.left as usize);
                if avg.admits(l.min_v) {
                    t = n.left;
                    n = l;
                    continue;
                }
            }
            if avg.admits(n.vruntime) {
                best = Some((t as usize, n.deadline));
                break;
            }
            if n.right == NIL {
                break;
            }
            t = n.right;
            n = s.node(t as usize);
        }
        match (best, cur) {
            // The mean lies between the smallest and the largest `v`, so a
            // linked entity is eligible unless `cur` is the one below it, and
            // then `cur` is. A tree with a member and no eligible one cannot
            // happen; the earliest deadline overall keeps the answer total.
            (None, Some(_)) => Choice::Cur,
            (None, None) => Choice::Task(self.first(s)),
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

    /// The node with the earliest deadline. The tree is not empty.
    fn first<S: Store>(&self, s: &S) -> usize {
        let mut t = self.root;
        for _ in 0..MAX_DEPTH {
            let n = s.node(t as usize);
            if n.left == NIL {
                break;
            }
            t = n.left;
        }
        t as usize
    }

    /// The invariants: key order, heap order, the least `v` of every node, the
    /// count and the sums against the nodes found.
    pub fn check<S: Store>(&self, s: &S) -> Result<(), &'static str> {
        struct Acc {
            n: u32,
            prev: Option<(i64, u64)>,
            avg: Avg,
        }
        fn walk<S: Store>(s: &S, t: u32, up: u32, depth: u32, acc: &mut Acc) -> Result<i64, &'static str> {
            if depth > MAX_DEPTH {
                return Err("tree deeper than any treap of this size (a cycle)");
            }
            let n = s.node(t as usize);
            if n.weight == 0 {
                return Err("an unlinked node is in the tree");
            }
            let p = hprio(n.tie);
            if p > up {
                return Err("heap order broken");
            }
            let mut m = n.vruntime;
            if n.left != NIL {
                m = m.min(walk(s, n.left, p, depth + 1, acc)?);
            }
            if acc.prev.is_some_and(|k| k >= (n.deadline, n.tie)) {
                return Err("key order broken");
            }
            acc.prev = Some((n.deadline, n.tie));
            acc.n += 1;
            acc.avg.add(&Ent { weight: n.weight, slice: 0, vruntime: n.vruntime, deadline: n.deadline });
            if n.right != NIL {
                m = m.min(walk(s, n.right, p, depth + 1, acc)?);
            }
            if m != n.min_v {
                return Err("a node's least v is not the least of its subtree");
            }
            Ok(m)
        }
        let mut acc = Acc { n: 0, prev: None, avg: Avg::new() };
        if self.root != NIL {
            walk(s, self.root, u32::MAX, 0, &mut acc)?;
        }
        if acc.n != self.len {
            return Err("the count is not the nodes found");
        }
        if !acc.avg.same_sums(&self.avg) {
            return Err("the sums are not the nodes found");
        }
        Ok(())
    }
}

impl Default for Tree {
    fn default() -> Self {
        Self::new()
    }
}
