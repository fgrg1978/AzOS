// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The wait graph's ordered sets: a leftist heap threaded through arrays
//! indexed by task slot, with no allocation and no comparison on removal.
//!
//! A set's cost is what a user sizes (threads on one futex, futexes one thread
//! owns), and the graph runs with interrupts masked, so every operation is
//! logarithmic. The right spine of a leftist heap of `n` nodes is at most
//! `log2(n + 1)` long and a merge walks only right spines. A removal merges
//! the node's children and repairs upward only while the rank changes; the
//! rank strictly grows on the way, so that is at most `log2(n + 1)` steps too.
//!
//! Only the root can be read in order, which is all the graph asks for. The
//! order is a `dyn` so that one copy serves every crate that instantiates `Graph`.

/// No slot.
pub const NIL: u32 = u32::MAX;

/// One slot's links. `rank`: the distance to the nearest missing child.
#[derive(Clone, Copy)]
pub struct Node {
    left: u32,
    right: u32,
    parent: u32,
    rank: u8,
}

impl Node {
    pub const EMPTY: Node = Node { left: NIL, right: NIL, parent: NIL, rank: 0 };

    /// Is the slot in a heap? A member's rank is at least 1.
    #[inline]
    pub const fn in_heap(&self) -> bool {
        self.rank != 0
    }

    /// The right child, [`NIL`] = none: what bounds a merge.
    #[inline]
    pub const fn right(&self) -> u32 {
        self.right
    }
}

#[inline]
fn rank(nodes: &[Node], i: u32) -> u8 {
    if i == NIL { 0 } else { nodes[i as usize].rank }
}

/// Keep the leftist shape at `i` and answer its rank from the children.
#[inline]
fn settle(nodes: &mut [Node], i: u32) -> u8 {
    let n = nodes[i as usize];
    let (l, r) = (rank(nodes, n.left), rank(nodes, n.right));
    // `pi-heap-no-swap-canary`: the shape is lost, the right spine grows with
    // the set, and the graph's holds with it.
    if l < r && !cfg!(feature = "pi-heap-no-swap-canary") {
        let node = &mut nodes[i as usize];
        node.left = n.right;
        node.right = n.left;
    }
    l.min(r).saturating_add(1)
}

/// Merge the heaps at `a` and `b` (the returned root's parent is the caller's
/// to write). `first(x, y)`: `x` comes before `y`.
fn merge(nodes: &mut [Node], mut a: u32, mut b: u32, first: &dyn Fn(u32, u32) -> bool) -> u32 {
    if a == NIL {
        return b;
    }
    if b == NIL {
        return a;
    }
    if first(b, a) {
        core::mem::swap(&mut a, &mut b);
    }
    let root = a;
    // `cur` heads the merged part; `b` is what is left to merge under it.
    let mut cur = a;
    loop {
        let r = nodes[cur as usize].right;
        if r == NIL {
            nodes[cur as usize].right = b;
            nodes[b as usize].parent = cur;
            break;
        }
        if first(b, r) {
            nodes[cur as usize].right = b;
            nodes[b as usize].parent = cur;
            cur = b;
            b = r;
        } else {
            cur = r;
        }
    }
    loop {
        let rk = settle(nodes, cur);
        nodes[cur as usize].rank = rk;
        if cur == root {
            return root;
        }
        cur = nodes[cur as usize].parent;
    }
}

/// Add `t`, not in any set, to the heap at `root`; the new root is returned.
pub fn insert(nodes: &mut [Node], root: u32, t: u32, first: &dyn Fn(u32, u32) -> bool) -> u32 {
    nodes[t as usize] = Node { left: NIL, right: NIL, parent: NIL, rank: 1 };
    let r = merge(nodes, root, t, first);
    nodes[r as usize].parent = NIL;
    r
}

/// Take `t` out of the heap at `root`; the new root is returned. `t`'s own key
/// may already have changed: it is not compared.
pub fn remove(nodes: &mut [Node], root: u32, t: u32, first: &dyn Fn(u32, u32) -> bool) -> u32 {
    let n = nodes[t as usize];
    nodes[t as usize] = Node::EMPTY;
    let m = merge(nodes, n.left, n.right, first);
    if m != NIL {
        nodes[m as usize].parent = n.parent;
    }
    if n.parent == NIL {
        debug_assert!(root == t);
        return m;
    }
    let p = &mut nodes[n.parent as usize];
    if p.left == t {
        p.left = m;
    } else {
        p.right = m;
    }
    let mut c = n.parent;
    while c != NIL {
        let rk = settle(nodes, c);
        if rk == nodes[c as usize].rank {
            break;
        }
        nodes[c as usize].rank = rk;
        c = nodes[c as usize].parent;
    }
    root
}
