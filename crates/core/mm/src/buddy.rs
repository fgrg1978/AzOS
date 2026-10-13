// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The buddy allocator over the frame descriptors, and the per-hart order-0
//! caches that sit in front of it.
//!
//! Pure data-structure code: it touches only a [`FrameTable`] and its own
//! lists, takes no lock and reads no CPU state, so the host can link it
//! (`tests/host/mm-tests`, `#[path]`). `pmm.rs` owns the statics, the lock and
//! the interrupt masking that make these calls safe on a board.
//!
//! # Blocks
//!
//! A free block of order `k` is `2^k` frames starting at a frame number
//! divisible by `2^k` (absolute, from physical address 0). Only the first
//! frame of a free block is linked into a list and carries the block's order;
//! every frame of it, head or not, has `F_FREE` set, so the state of any one
//! frame can be answered without searching for its block. A block's buddy is
//! `pfn ^ (1 << order)`; if that frame lies outside the table the block has no
//! buddy and never merges.
//!
//! # Orders
//!
//! `0..=MAX_ORDER` (Kconfig `PMM_MAX_ORDER`). Blocks bigger than `MAX_ORDER`
//! are never formed: RAM is seeded as maximal blocks of at most that order.

use core::sync::atomic::{AtomicU32, Ordering};
use crate::frame::{
    FrameTable, Pfn, F_ALLOCATED, F_CACHED, F_FREE, F_RESERVED, NIL, NOT_HEAD,
};

/// The largest block order, Kconfig `PMM_MAX_ORDER`.
pub const MAX_ORDER: usize = azos_limits::PMM_MAX_ORDER;

/// The smallest order whose block holds `frames` frames.
#[inline(always)]
pub const fn order_for(frames: usize) -> usize {
    if frames <= 1 { 0 } else { (usize::BITS - (frames - 1).leading_zeros()) as usize }
}

/// The free lists: one per order, linked through the descriptors.
pub struct Buddy {
    head: [u32; MAX_ORDER + 1],
    blocks: [usize; MAX_ORDER + 1],
    free: usize,
}

impl Buddy {
    /// Empty lists: nothing is free.
    pub const fn new() -> Buddy {
        Buddy { head: [NIL; MAX_ORDER + 1], blocks: [0; MAX_ORDER + 1], free: 0 }
    }

    /// Forget every block (the descriptors are rebuilt by the caller).
    pub fn reset(&mut self) { *self = Buddy::new(); }

    /// Frames in the lists (not counting any hart's cache).
    #[inline(always)]
    pub fn free_frames(&self) -> usize { self.free }

    /// Free blocks of exactly `order`.
    pub fn blocks(&self, order: usize) -> usize { self.blocks[order] }

    fn push(&mut self, t: &FrameTable, idx: usize, order: usize) {
        let d = t.at(idx);
        let h = self.head[order];
        d.order.store(order as u32, Ordering::Relaxed);
        d.prev.store(NIL, Ordering::Relaxed);
        d.next.store(h, Ordering::Relaxed);
        if h != NIL {
            t.at(h as usize).prev.store(idx as u32, Ordering::Relaxed);
        }
        self.head[order] = idx as u32;
        self.blocks[order] += 1;
        self.free += 1 << order;
    }

    fn unlink(&mut self, t: &FrameTable, idx: usize, order: usize) {
        let d = t.at(idx);
        let n = d.next.load(Ordering::Relaxed);
        let p = d.prev.load(Ordering::Relaxed);
        if p != NIL {
            t.at(p as usize).next.store(n, Ordering::Relaxed);
        } else {
            self.head[order] = n;
        }
        if n != NIL {
            t.at(n as usize).prev.store(p, Ordering::Relaxed);
        }
        d.order.store(NOT_HEAD, Ordering::Relaxed);
        d.next.store(NIL, Ordering::Relaxed);
        d.prev.store(NIL, Ordering::Relaxed);
        self.blocks[order] -= 1;
        self.free -= 1 << order;
    }

    /// Put the block `[pfn, pfn + 2^order)` into the lists, merging with its
    /// buddy for as long as the buddy is a whole free block of the same order.
    /// Every frame of the block must already carry exactly `F_FREE`.
    pub fn release(&mut self, t: &FrameTable, pfn: Pfn, order: usize) {
        debug_assert!(pfn.0 & ((1 << order) - 1) == 0);
        let mut p = pfn.0;
        let mut o = order;
        // Canary `buddy-merge-canary`: blocks never merge.
        while o < MAX_ORDER && !cfg!(feature = "buddy-merge-canary") {
            let bp = p ^ (1 << o);
            let Some(bi) = t.index(Pfn(bp)) else { break };
            let b = t.at(bi);
            if b.flags.load(Ordering::Relaxed) != F_FREE || b.order.load(Ordering::Relaxed) != o as u32 {
                break;
            }
            self.unlink(t, bi, o);
            p = p.min(bp);
            o += 1;
        }
        self.push(t, t.index(Pfn(p)).expect("block inside the table"), o);
    }

    /// [`release`](Self::release) for every frame of `[lo, hi)`, as the
    /// fewest aligned blocks (largest first at each position). The frames
    /// must already carry `F_FREE`.
    pub fn release_range(&mut self, t: &FrameTable, lo: Pfn, hi: Pfn) {
        let mut p = lo.0;
        while p < hi.0 {
            let mut k = if p == 0 { MAX_ORDER } else { (p.trailing_zeros() as usize).min(MAX_ORDER) };
            while p + (1 << k) > hi.0 {
                k -= 1;
            }
            self.release(t, Pfn(p), k);
            p += 1 << k;
        }
    }

    /// Take a block of `2^order` frames, or `None` when no block that size
    /// can be made. The frames come back `F_ALLOCATED`, unshared and owned by
    /// the kernel; their contents are whatever they were.
    pub fn alloc(&mut self, t: &FrameTable, order: usize) -> Option<Pfn> {
        if order > MAX_ORDER { return None; }
        let mut o = order;
        while self.head[o] == NIL {
            o += 1;
            if o > MAX_ORDER { return None; }
        }
        let idx = self.head[o] as usize;
        self.unlink(t, idx, o);
        let pfn = t.pfn(idx).0;
        // Keep the lower half, give the upper half back, until the block fits.
        while o > order {
            o -= 1;
            let up = t.index(Pfn(pfn + (1 << o))).expect("upper half inside the table");
            // Canary `buddy-split-canary`: the upper half is dropped, not
            // given back, so every split loses frames.
            if !cfg!(feature = "buddy-split-canary") {
                self.push(t, up, o);
            }
        }
        for i in idx..idx + (1 << order) {
            let d = t.at(i);
            d.flags.store(F_ALLOCATED, Ordering::Relaxed);
            d.refcount.store(0, Ordering::Relaxed);
        }
        Some(Pfn(pfn))
    }

    /// Take exactly `frames` contiguous frames, starting at a multiple of
    /// `2^min_order` frames: a block of the order that holds them is taken
    /// and the frames past `frames` go straight back.
    pub fn alloc_run(&mut self, t: &FrameTable, frames: usize, min_order: usize) -> Option<Pfn> {
        let order = order_for(frames).max(min_order);
        let pfn = self.alloc(t, order)?;
        let (lo, hi) = (pfn.0 + frames, pfn.0 + (1 << order));
        if lo < hi {
            let i0 = t.index(Pfn(lo)).expect("tail inside the table");
            for i in i0..i0 + (hi - lo) {
                t.at(i).flags.store(F_FREE, Ordering::Relaxed);
            }
            self.release_range(t, Pfn(lo), Pfn(hi));
        }
        Some(pfn)
    }

    /// Take `[lo, hi)` out of the lists and mark what was free in it
    /// `F_RESERVED`. Frames in use, cached or already reserved are left as
    /// they are. A block that straddles an edge is split and its outside part
    /// goes back.
    pub fn carve(&mut self, t: &FrameTable, lo: Pfn, hi: Pfn) {
        let mut p = lo.0.max(t.first().0);
        let hi = hi.0.min(t.end().0);
        while p < hi {
            let i = t.index(Pfn(p)).expect("inside the table");
            if t.at(i).flags.load(Ordering::Relaxed) != F_FREE {
                p += 1;
                continue;
            }
            let Some((hp, k)) = self.head_of(t, p) else {
                p += 1;
                continue;
            };
            self.unlink(t, t.index(Pfn(hp)).expect("head inside the table"), k);
            let bend = hp + (1 << k);
            let (cut_lo, cut_hi) = (hp.max(lo.0), bend.min(hi));
            for q in cut_lo..cut_hi {
                let d = t.at(t.index(Pfn(q)).expect("inside the table"));
                d.flags.store(F_RESERVED, Ordering::Relaxed);
            }
            self.release_range(t, Pfn(hp), Pfn(cut_lo));
            self.release_range(t, Pfn(cut_hi), Pfn(bend));
            p = cut_hi;
        }
    }

    /// The free block holding `pfn`: its first frame and order.
    fn head_of(&self, t: &FrameTable, pfn: usize) -> Option<(usize, usize)> {
        for k in 0..=MAX_ORDER {
            let hp = pfn & !((1usize << k) - 1);
            if let Some(hi) = t.index(Pfn(hp)) {
                let d = t.at(hi);
                if d.flags.load(Ordering::Relaxed) == F_FREE && d.order.load(Ordering::Relaxed) == k as u32 {
                    return Some((hp, k));
                }
            }
        }
        None
    }
}

/// One hart's cache of free order-0 frames, a stack linked through the
/// descriptors. Only its own hart, interrupts off, touches `head` and the
/// links; `count` is read (relaxed) by anyone who wants the free total.
#[repr(align(64))]
pub struct Pcp {
    head: AtomicU32,
    count: AtomicU32,
}

impl Pcp {
    pub const fn new() -> Pcp { Pcp { head: AtomicU32::new(NIL), count: AtomicU32::new(0) } }

    /// Frames held.
    #[inline(always)]
    pub fn len(&self) -> usize { self.count.load(Ordering::Relaxed) as usize }

    /// Forget the frames held (their descriptors are rebuilt by the caller).
    pub fn reset(&self) {
        self.head.store(NIL, Ordering::Relaxed);
        self.count.store(0, Ordering::Relaxed);
    }

    /// Take the newest frame: it comes back `F_ALLOCATED`, unshared.
    #[inline(always)]
    pub fn pop(&self, t: &FrameTable) -> Option<Pfn> {
        let h = self.head.load(Ordering::Relaxed);
        if h == NIL { return None; }
        let d = t.at(h as usize);
        self.head.store(d.next.load(Ordering::Relaxed), Ordering::Relaxed);
        self.count.store(self.count.load(Ordering::Relaxed) - 1, Ordering::Relaxed);
        d.next.store(NIL, Ordering::Relaxed);
        d.flags.store(F_ALLOCATED, Ordering::Relaxed);
        d.refcount.store(0, Ordering::Relaxed);
        Some(t.pfn(h as usize))
    }

    /// Keep the frame `idx` (array index) for this hart: `F_CACHED`.
    #[inline(always)]
    pub fn push(&self, t: &FrameTable, idx: usize) {
        let d = t.at(idx);
        d.flags.store(F_CACHED, Ordering::Relaxed);
        d.next.store(self.head.load(Ordering::Relaxed), Ordering::Relaxed);
        self.head.store(idx as u32, Ordering::Relaxed);
        self.count.store(self.count.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
    }

    /// Put a chain of frames (from [`Buddy::take_chain`], `F_CACHED`) on top of
    /// the cache, in one step.
    #[inline(always)]
    pub fn splice(&self, t: &FrameTable, c: Chain) {
        if c.n == 0 { return; }
        t.at(c.tail as usize).next.store(self.head.load(Ordering::Relaxed), Ordering::Relaxed);
        self.head.store(c.head, Ordering::Relaxed);
        self.count.store(self.count.load(Ordering::Relaxed) + c.n, Ordering::Relaxed);
    }

    /// Cut the newest `n` frames (fewer if it holds fewer) off the cache as a
    /// chain, still `F_CACHED`. Walks the `n` frames and touches no lock: the
    /// caller releases the chain to the lists after it has unmasked
    /// interrupts ([`Buddy::release_chain`]).
    #[inline(always)]
    pub fn detach(&self, t: &FrameTable, n: usize) -> Chain {
        let head = self.head.load(Ordering::Relaxed);
        let (mut cur, mut tail, mut k) = (head, NIL, 0u32);
        while (k as usize) < n && cur != NIL {
            tail = cur;
            cur = t.at(cur as usize).next.load(Ordering::Relaxed);
            k += 1;
        }
        if k == 0 { return Chain::EMPTY; }
        t.at(tail as usize).next.store(NIL, Ordering::Relaxed);
        self.head.store(cur, Ordering::Relaxed);
        self.count.store(self.count.load(Ordering::Relaxed) - k, Ordering::Relaxed);
        Chain { head, tail, n: k }
    }
}

/// Order-0 frames linked through `next` (all `F_CACHED`), on their way
/// between the lists and a cache. Built and consumed in two steps so that the
/// walk over the lists happens under the lock with interrupts as the caller
/// had them, and the splice onto (or cut from) a cache happens masked, with
/// no lock: neither window holds the other's cost.
pub struct Chain {
    head: u32,
    tail: u32,
    n: u32,
}

impl Chain {
    pub const EMPTY: Chain = Chain { head: NIL, tail: NIL, n: 0 };

    /// Frames in the chain.
    pub fn len(&self) -> usize { self.n as usize }

    /// Put the frame at array index `idx`, which `free` claimed, in front.
    pub fn push_front(&mut self, t: &FrameTable, idx: usize) {
        let d = t.at(idx);
        d.flags.store(F_CACHED, Ordering::Relaxed);
        d.next.store(self.head, Ordering::Relaxed);
        if self.tail == NIL { self.tail = idx as u32; }
        self.head = idx as u32;
        self.n += 1;
    }
}

impl Buddy {
    /// Take up to `n` order-0 frames off the lists as a chain (`F_CACHED`);
    /// fewer when the lists run dry.
    pub fn take_chain(&mut self, t: &FrameTable, n: usize) -> Chain {
        let mut c = Chain::EMPTY;
        // Canary `pcp-refill-canary`: a batch is one frame short.
        let n = if cfg!(feature = "pcp-refill-canary") { n.saturating_sub(1) } else { n };
        while (c.n as usize) < n {
            let Some(pfn) = self.alloc(t, 0) else { break };
            c.push_front(t, t.index(pfn).expect("inside the table"));
        }
        c
    }

    /// Give a chain's frames back to the lists, each merging with its buddy.
    pub fn release_chain(&mut self, t: &FrameTable, c: Chain) {
        let mut cur = c.head;
        while cur != NIL {
            let d = t.at(cur as usize);
            let next = d.next.load(Ordering::Relaxed);
            d.next.store(NIL, Ordering::Relaxed);
            d.flags.store(F_FREE, Ordering::Relaxed);
            // Canary `pcp-drain-canary`: the frames are taken as given back
            // and never reach the lists.
            if !cfg!(feature = "pcp-drain-canary") {
                self.release(t, t.pfn(cur as usize), 0);
            }
            cur = next;
        }
    }
}
