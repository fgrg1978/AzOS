// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The order of the fair queue: the pick of `eevdf_core.rs` in O(log n), for
//! any order of arrivals.
//!
//! An AVL tree keyed by (virtual deadline, level, arrival), so the in-order
//! walk is the order the ready lists give among equal deadlines: a lower
//! priority level first, then FIFO. Each node carries the least `v` of its
//! subtree, so the first eligible node in key order is found by one descent: go
//! left while the left subtree holds an eligible `v` (eligibility is `v <= V`,
//! so the subtree's least `v` is the test), else take this node if it is
//! eligible, else go right. The mean `V` comes from the sums of the whole tree,
//! kept as entities are linked and unlinked.
//!
//! The pick runs with interrupts masked and an unprivileged user chooses the
//! arrivals, so the height has a worst case and not an expected one: at most
//! 1.44 log2(n + 2), reached by no sequence a user can pace past it. Nothing
//! here recurses, and every walk stops at [`MAX_HEIGHT`].
//!
//! The nodes live in a table indexed by task slot ([`Store`]), one per task
//! because a task is on one queue at a time; a node is linked while its weight
//! is not 0, and holds the numbers the entity had when it was linked, which is
//! what unlinking subtracts from the sums. It also names the tree holding it: a
//! tree refuses a node another tree holds, whose links it may not touch.
//!
//! Pure (`core` only): the kernel's `fairq.rs` owns one [`Tree`] per CPU under
//! that CPU's lock, and `tests/host/sched-policy-tests` pulls this file in.

use core::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering::Relaxed};

use crate::eevdf_core::{Avg, Choice, Ent};

/// No child, no parent.
pub const NIL: u32 = u32::MAX;

const SEQ_MASK: u64 = (1 << 56) - 1;
/// An AVL tree this high holds more nodes than a `u32` can index: past it the
/// links are a cycle.
pub const MAX_HEIGHT: u32 = 46;
/// Picks [`take`] tries while a running task can keep the CPU for the next pass.
pub const TAKE_TRIES: usize = 4;

/// One entity's node. Linked while `weight != 0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node {
    pub left: u32,
    pub right: u32,
    pub parent: u32,
    pub weight: u32,
    /// Of the subtree: a leaf is 1.
    pub height: u32,
    /// The [`Tree::id`] holding it, while linked.
    pub owner: u32,
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
    parent: AtomicU32,
    weight: AtomicU32,
    height: AtomicU32,
    owner: AtomicU32,
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
                    parent: AtomicU32::new(NIL),
                    weight: AtomicU32::new(0),
                    height: AtomicU32::new(0),
                    owner: AtomicU32::new(0),
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
            parent: n.parent.load(Relaxed),
            weight: n.weight.load(Relaxed),
            height: n.height.load(Relaxed),
            owner: n.owner.load(Relaxed),
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
        n.parent.store(v.parent, Relaxed);
        n.weight.store(v.weight, Relaxed);
        n.height.store(v.height, Relaxed);
        n.owner.store(v.owner, Relaxed);
        n.deadline.store(v.deadline, Relaxed);
        n.vruntime.store(v.vruntime, Relaxed);
        n.min_v.store(v.min_v, Relaxed);
        n.tie.store(v.tie, Relaxed);
    }
}

/// What [`Tree::remove`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unlink {
    Done,
    /// The node is linked nowhere.
    Absent,
    /// Another tree holds the node: nothing was touched.
    Foreign,
}

#[inline]
fn height_of<S: Store>(s: &S, t: u32) -> u32 {
    if t == NIL {
        0
    } else {
        s.node(t as usize).height
    }
}

fn set_parent<S: Store>(s: &S, t: u32, parent: u32) {
    if t != NIL {
        let mut n = s.node(t as usize);
        n.parent = parent;
        s.set(t as usize, n);
    }
}

/// What [`pull`] found.
struct Pulled {
    node: Node,
    left_height: u32,
    right_height: u32,
    moved: bool,
}

/// Recompute `t`'s height and least `v` from its children.
/// `eevdf-tree-canary`: the least `v` is left stale, as the node was first linked.
fn pull<S: Store>(s: &S, t: u32) -> Pulled {
    let mut n = s.node(t as usize);
    let (mut left_height, mut right_height, mut m) = (0, 0, n.vruntime);
    if n.left != NIL {
        let k = s.node(n.left as usize);
        left_height = k.height;
        m = m.min(k.min_v);
    }
    if n.right != NIL {
        let k = s.node(n.right as usize);
        right_height = k.height;
        m = m.min(k.min_v);
    }
    let height = left_height.max(right_height) + 1;
    if cfg!(feature = "eevdf-tree-canary") {
        m = n.min_v;
    }
    let moved = height != n.height || m != n.min_v;
    if moved {
        n.height = height;
        n.min_v = m;
        s.set(t as usize, n);
    }
    Pulled { node: n, left_height, right_height, moved }
}

/// One queue's order and sums.
#[derive(Debug)]
pub struct Tree {
    root: u32,
    len: u32,
    id: u32,
    seq: u64,
    avg: Avg,
}

impl Tree {
    /// `id` tells this tree's nodes from those of the others sharing the table.
    pub const fn new(id: u32) -> Self {
        Self { root: NIL, len: 0, id, seq: 0, avg: Avg::new() }
    }

    /// The topmost node, [`NIL`] when empty.
    pub fn root(&self) -> u32 {
        self.root
    }

    /// Linked entities.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The sums of every linked entity but `skip` (when this tree holds it):
    /// the mean a placement reads, in O(1). `skip` is subtracted with the
    /// numbers it was linked with, as unlinking it would.
    pub fn avg_without<S: Store>(&self, s: &S, skip: usize) -> Avg {
        let mut a = self.avg;
        let n = s.node(skip);
        if n.weight != 0 && n.owner == self.id {
            a.remove(&Ent { weight: n.weight, slice: 0, vruntime: n.vruntime, deadline: n.deadline });
        }
        a
    }

    fn replace_child<S: Store>(&mut self, s: &S, parent: u32, old: u32, new: u32) {
        if parent == NIL {
            self.root = new;
            return;
        }
        let mut p = s.node(parent as usize);
        if p.left == old {
            p.left = new;
        } else {
            p.right = new;
        }
        s.set(parent as usize, p);
    }

    /// `t`'s child on the other side takes its place and `t` goes `to_left`.
    /// Returns the parent of the node now on top.
    fn rotate<S: Store>(&mut self, s: &S, t: u32, to_left: bool) -> u32 {
        let mut a = s.node(t as usize);
        let c = if to_left { a.right } else { a.left };
        let mut b = s.node(c as usize);
        let inner = if to_left {
            let i = b.left;
            a.right = i;
            b.left = t;
            i
        } else {
            let i = b.right;
            a.left = i;
            b.right = t;
            i
        };
        b.parent = a.parent;
        a.parent = c;
        s.set(t as usize, a);
        s.set(c as usize, b);
        set_parent(s, inner, t);
        self.replace_child(s, b.parent, t, c);
        pull(s, t);
        pull(s, c);
        b.parent
    }

    /// Height, least `v` and balance from `t` up, stopping where nothing moved
    /// above `stale`, a node whose own numbers are not to be trusted.
    fn fix_up<S: Store>(&mut self, s: &S, mut t: u32, mut stale: u32) {
        for _ in 0..=MAX_HEIGHT {
            if t == NIL {
                return;
            }
            let p = pull(s, t);
            if t == stale {
                stale = NIL;
            }
            let n = p.node;
            t = if p.left_height > p.right_height + 1 {
                let l = s.node(n.left as usize);
                if height_of(s, l.right) > height_of(s, l.left) {
                    self.rotate(s, n.left, true);
                }
                self.rotate(s, t, false)
            } else if p.right_height > p.left_height + 1 {
                let r = s.node(n.right as usize);
                if height_of(s, r.left) > height_of(s, r.right) {
                    self.rotate(s, n.right, false);
                }
                self.rotate(s, t, true)
            } else {
                if !p.moved && stale == NIL {
                    return;
                }
                n.parent
            };
        }
    }

    /// Link task `idx` with `e`'s numbers at priority `level`, after the
    /// entities already linked with the same deadline and level. An `idx` still
    /// linked here is unlinked first. False, nothing touched, when another tree
    /// holds `idx` or this one is not a tree any more.
    #[must_use]
    pub fn insert<S: Store>(&mut self, s: &S, idx: usize, e: &Ent, level: u32) -> bool {
        if self.remove(s, idx) == Unlink::Foreign {
            return false;
        }
        let tie = (level as u64) << 56 | (self.seq & SEQ_MASK);
        let weight = e.weight.max(1);
        let deadline = if cfg!(feature = "eevdf-fifo-canary") { 0 } else { e.deadline };
        let (mut parent, mut t, mut to_left) = (NIL, self.root, false);
        let mut depth = 0;
        while t != NIL {
            if depth > MAX_HEIGHT {
                return false;
            }
            depth += 1;
            let n = s.node(t as usize);
            to_left = (deadline, tie) < (n.deadline, n.tie);
            parent = t;
            t = if to_left { n.left } else { n.right };
        }
        self.seq = self.seq.wrapping_add(1);
        s.set(idx, Node {
            left: NIL,
            right: NIL,
            parent,
            weight,
            height: 1,
            owner: self.id,
            deadline,
            vruntime: e.vruntime,
            min_v: e.vruntime,
            tie,
        });
        if parent == NIL {
            self.root = idx as u32;
        } else {
            let mut p = s.node(parent as usize);
            if to_left {
                p.left = idx as u32;
            } else {
                p.right = idx as u32;
            }
            s.set(parent as usize, p);
            self.fix_up(s, parent, NIL);
        }
        self.len += 1;
        self.avg.add(&Ent { weight, ..*e });
        true
    }

    /// Unlink task `idx`.
    pub fn remove<S: Store>(&mut self, s: &S, idx: usize) -> Unlink {
        let n = s.node(idx);
        if n.weight == 0 {
            return Unlink::Absent;
        }
        if n.owner != self.id {
            return Unlink::Foreign;
        }
        let t = idx as u32;
        let (start, stale) = if n.left != NIL && n.right != NIL {
            // The successor takes the node's place in the links: a node's index
            // is its task, so the numbers cannot be what moves.
            let mut y = n.right;
            let mut ny = s.node(y as usize);
            for _ in 0..MAX_HEIGHT {
                if ny.left == NIL {
                    break;
                }
                y = ny.left;
                ny = s.node(y as usize);
            }
            let start = if ny.parent == t {
                y
            } else {
                let up = ny.parent;
                self.replace_child(s, up, y, ny.right);
                set_parent(s, ny.right, up);
                ny.right = n.right;
                set_parent(s, n.right, y);
                up
            };
            ny.left = n.left;
            ny.parent = n.parent;
            ny.height = n.height;
            ny.min_v = n.min_v;
            s.set(y as usize, ny);
            set_parent(s, n.left, y);
            self.replace_child(s, n.parent, t, y);
            (start, y)
        } else {
            let c = if n.left != NIL { n.left } else { n.right };
            set_parent(s, c, n.parent);
            self.replace_child(s, n.parent, t, c);
            (n.parent, NIL)
        };
        self.fix_up(s, start, stale);
        self.len -= 1;
        s.set(idx, Node { weight: 0, left: NIL, right: NIL, parent: NIL, ..n });
        self.avg.remove(&Ent { weight: n.weight, slice: 0, vruntime: n.vruntime, deadline: n.deadline });
        Unlink::Done
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
        for _ in 0..MAX_HEIGHT {
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
        leftmost(s, self.root).unwrap_or(self.root) as usize
    }

    /// The invariants: key order, balance, the links both ways, the height and
    /// the least `v` of every node, the count and the sums against the nodes
    /// found.
    pub fn check<S: Store>(&self, s: &S) -> Result<(), &'static str> {
        let mut seen = 0;
        let mut prev = None;
        let mut avg = Avg::new();
        if self.root != NIL {
            if s.node(self.root as usize).parent != NIL {
                return Err("the root has a parent");
            }
            let mut t = leftmost(s, self.root).ok_or("a left spine past any tree's height (a cycle)")?;
            loop {
                let n = s.node(t as usize);
                self.check_node(s, t, &n)?;
                if prev.is_some_and(|k| k >= (n.deadline, n.tie)) {
                    return Err("key order broken");
                }
                prev = Some((n.deadline, n.tie));
                seen += 1;
                if seen > self.len {
                    return Err("more nodes than the count (a cycle)");
                }
                avg.add(&Ent { weight: n.weight, slice: 0, vruntime: n.vruntime, deadline: n.deadline });
                if n.right != NIL {
                    t = leftmost(s, n.right).ok_or("a left spine past any tree's height (a cycle)")?;
                    continue;
                }
                let (mut c, mut p, mut up) = (t, n.parent, 0);
                while p != NIL && s.node(p as usize).right == c {
                    c = p;
                    p = s.node(p as usize).parent;
                    up += 1;
                    if up > MAX_HEIGHT {
                        return Err("a climb past any tree's height (a cycle)");
                    }
                }
                if p == NIL {
                    break;
                }
                t = p;
            }
        }
        if seen != self.len {
            return Err("the count is not the nodes found");
        }
        if !avg.same_sums(&self.avg) {
            return Err("the sums are not the nodes found");
        }
        Ok(())
    }

    fn check_node<S: Store>(&self, s: &S, t: u32, n: &Node) -> Result<(), &'static str> {
        if n.weight == 0 {
            return Err("an unlinked node is in the tree");
        }
        if n.owner != self.id {
            return Err("a node of another tree is in this one");
        }
        let (mut hl, mut hr, mut m) = (0, 0, n.vruntime);
        if n.left != NIL {
            let c = s.node(n.left as usize);
            if c.parent != t {
                return Err("a left child does not name its parent");
            }
            hl = c.height;
            m = m.min(c.min_v);
        }
        if n.right != NIL {
            let c = s.node(n.right as usize);
            if c.parent != t {
                return Err("a right child does not name its parent");
            }
            hr = c.height;
            m = m.min(c.min_v);
        }
        if n.height != hl.max(hr) + 1 {
            return Err("a node's height is not its children's");
        }
        if hl.abs_diff(hr) > 1 {
            return Err("balance broken");
        }
        if m != n.min_v {
            return Err("a node's least v is not the least of its subtree");
        }
        Ok(())
    }
}

/// The leftmost node under `t`, `None` past any tree's height.
fn leftmost<S: Store>(s: &S, mut t: u32) -> Option<u32> {
    for _ in 0..=MAX_HEIGHT {
        let l = s.node(t as usize).left;
        if l == NIL {
            return Some(t);
        }
        t = l;
    }
    None
}

/// The pick with its way out of the lists: `claim` takes the picked task off its
/// list, and a pick it refuses (the tree and the lists disagree) goes through
/// `unlink`, so the next pick differs. After `tries` the answer is `exhausted`.
pub fn take(
    tries: usize,
    exhausted: Choice,
    mut pick: impl FnMut() -> Choice,
    mut claim: impl FnMut(usize) -> bool,
    mut unlink: impl FnMut(usize),
) -> Choice {
    for _ in 0..tries {
        match pick() {
            Choice::Task(idx) => {
                if claim(idx) {
                    return Choice::Task(idx);
                }
                unlink(idx);
            }
            other => return other,
        }
    }
    exhausted
}
