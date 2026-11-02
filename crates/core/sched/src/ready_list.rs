// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The per-priority ready queues: intrusive doubly linked FIFO lists.
//!
//! **Why lists (wave 15, NRCPUS-FLEET-AREA).** The queues were rings of
//! `MAX_TASKS` slots each, `NUM_PRIORITIES` of them per CPU: `32 x MAX_TASKS`
//! words a CPU, so that any one queue could hold every task. That is 1 MiB of
//! each fleet CPU's per-CPU area (4096 tasks) and 64 MiB at 64 CPUs, for at
//! most `MAX_TASKS` entries in the whole system: a task is in at most one
//! queue at a time (the `queued` claim, K-C12). A list needs one link per
//! TASK, not per queue slot: a single `MAX_TASKS`-long link array shared by
//! every queue of every CPU, plus three words per queue. Linux does the same
//! (`sched_entity.run_node` / `rt_rq` lists threaded through the task).
//!
//! **Doubly linked, naming the list.** The fair pick and a priority change take
//! a known task out of the middle with interrupts masked, under a queue a user
//! can fill: [`ReadyList::remove`] reads that task and its two neighbours, for
//! any length. Its [`Link`] says which list holds it, because a removal is also
//! how a caller asks whether the task is there (`cpu_remove_anywhere`).
//!
//! **Encoding.** Every stored value is the slot itself, and a list ends at
//! its `count`, not at a sentinel link: `head`, `tail` and the last member's
//! link mean something only while `count > 0`. So an all-zero `ReadyList`
//! (count 0) is the empty list (the per-CPU areas are zeroed), and no
//! operation spends an instruction on a `+ 1`/`- 1` or on clearing a link.
//! `links[i].next` is the successor of slot `i` in whichever list holds it,
//! `prev` its predecessor, meaningful unless `i` is the head. Every stored value
//! is read sign-extended (see [`rd`]), so one `< links.len()` compare
//! range-checks it. Wave 15 integration: with `slot + 1` links, a
//! zero-terminated pop and zero-extended reads, a context switch paid +12
//! instructions for lists over the rings they replaced (vsbench ctxsw-loaded,
//! riscv64 -icount, 532 -> 544); these three changes removed that.
//!
//! **Concurrency.** Every mutation runs under the owning CPU's lock; the
//! atomics are `Relaxed` for the same reason the ring's were (shared `&`
//! without aliasing UB), not for lock-free readers. A reader walks under the
//! same lock. Every walk is bounded by `count` and by `links.len()`, and stops
//! at an out-of-range link, so a broken invariant ends a walk instead of
//! looping or indexing out of bounds.
//!
//! Pure (`core` only), pulled into `tests/host/sched-wake-tests` with
//! `#[path]`: the scheduler itself cannot run on the host.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering::Relaxed};

/// One slot's place in a list: all-zero is in none.
#[derive(Default)]
#[repr(C, align(16))]
pub struct Link {
    next: AtomicU32,
    prev: AtomicU32,
    /// The address of the [`ReadyList`] holding the slot, 0 for none. Written
    /// under that list's lock, so a holder of a list's lock reads a stable
    /// answer to "is it in this one" even while another list takes the slot.
    list: AtomicUsize,
}

impl Link {
    pub const fn new() -> Self {
        Self { next: AtomicU32::new(0), prev: AtomicU32::new(0), list: AtomicUsize::new(0) }
    }

    /// The successor word as it stands: for host tests that break a list.
    #[cfg(test)]
    pub fn set_next(&self, v: u32) {
        self.next.store(v, Relaxed);
    }
}

/// One priority level's ready queue on one CPU: 16 bytes, all-zero = empty.
/// Three words padded to 16 so that a CPU's level `p` is one shift from the
/// first (`p << 4`, where 12 bytes cost two shifts and an add on every
/// enqueue and dequeue).
#[derive(Default)]
#[repr(C, align(16))]
pub struct ReadyList {
    /// First slot (meaningful while `count > 0`).
    head: AtomicU32,
    /// Last slot (meaningful while `count > 0`).
    tail: AtomicU32,
    /// Entries in the list.
    count: AtomicU32,
}

/// The empty list.
#[allow(clippy::declare_interior_mutable_const)]
pub const EMPTY: ReadyList = ReadyList { head: AtomicU32::new(0), tail: AtomicU32::new(0), count: AtomicU32::new(0) };

/// A stored slot as an index. Through `i32` because riscv64's `lw` already
/// sign-extends, where `as usize` (zero-extension) costs two shifts on every
/// read; a value past `i32::MAX` (never stored) becomes a huge index, which
/// the `get` that follows every read rejects.
#[inline(always)]
fn rd(v: u32) -> usize {
    v as i32 as isize as usize
}

impl ReadyList {
    /// Entries in the list. Sign-extended for the reason [`rd`] is: a count
    /// past `i32::MAX` (never stored) reads huge, i.e. full, and every walk
    /// clamps it to `links.len()`.
    #[inline(always)]
    pub fn count(&self) -> usize {
        rd(self.count.load(Relaxed))
    }

    #[inline(always)]
    fn addr(&self) -> usize {
        self as *const Self as usize
    }

    /// Append `slot`, given the `count` the caller has just read under the
    /// lock (so the hot path does not load it twice).
    ///
    /// The caller guarantees `slot < links.len()` and that `slot` is in no
    /// list (the `queued` claim). The new tail's own `next` is not written: the
    /// list ends at `count`.
    #[inline(always)]
    pub fn push_back(&self, links: &[Link], slot: usize, count: usize) {
        let s = slot as u32;
        if count == 0 {
            self.head.store(s, Relaxed);
        } else {
            let tail = self.tail.load(Relaxed);
            if let Some(t) = links.get(rd(tail)) {
                t.next.store(s, Relaxed);
            }
            if let Some(l) = links.get(slot) {
                l.prev.store(tail, Relaxed);
            }
        }
        if let Some(l) = links.get(slot) {
            l.list.store(self.addr(), Relaxed);
        }
        self.tail.store(s, Relaxed);
        self.count.store(count as u32 + 1, Relaxed);
    }

    /// Remove and return the first slot, given the nonzero `count` the caller
    /// has just read under the lock. `None` when the head is out of range (a
    /// broken invariant), in which case the list is reset to empty rather
    /// than left pointing nowhere.
    #[inline(always)]
    pub fn pop_front(&self, links: &[Link], count: usize) -> Option<usize> {
        let slot = rd(self.head.load(Relaxed));
        let Some(link) = links.get(slot) else {
            self.reset();
            return None;
        };
        // The last entry leaves `head` as it is: count 0 makes it meaningless.
        if count > 1 {
            self.head.store(link.next.load(Relaxed), Relaxed);
        }
        link.list.store(0, Relaxed);
        self.count.store(count.saturating_sub(1) as u32, Relaxed);
        Some(slot)
    }

    /// Remove `slot` wherever it is in the list, keeping the order of the
    /// rest. Returns the new count, or `None` (nothing written) when `slot`
    /// is not in the list or its neighbours do not name it back.
    pub fn remove(&self, links: &[Link], slot: usize) -> Option<usize> {
        let link = links.get(slot)?;
        let n = self.count();
        if link.list.load(Relaxed) != self.addr() || n == 0 {
            return None;
        }
        let want = slot as u32;
        let (next, prev) = (link.next.load(Relaxed), link.prev.load(Relaxed));
        let is_head = self.head.load(Relaxed) == want;
        let is_tail = self.tail.load(Relaxed) == want;
        let before = if is_head { None } else { Some(links.get(rd(prev)).filter(|p| p.next.load(Relaxed) == want)?) };
        let after = if is_tail { None } else { Some(links.get(rd(next)).filter(|a| a.prev.load(Relaxed) == want)?) };
        match before {
            None => self.head.store(next, Relaxed),
            Some(p) => p.next.store(next, Relaxed),
        }
        match after {
            None => self.tail.store(prev, Relaxed),
            Some(a) => a.prev.store(prev, Relaxed),
        }
        link.list.store(0, Relaxed);
        self.count.store(n as u32 - 1, Relaxed);
        Some(n - 1)
    }

    /// The slots in order, at most `count` and at most `links.len()` of them,
    /// stopping early at an out-of-range link.
    pub fn iter<'a>(&'a self, links: &'a [Link]) -> impl Iterator<Item = usize> + 'a {
        let mut cur = self.head.load(Relaxed);
        let mut left = self.count().min(links.len());
        core::iter::from_fn(move || {
            if left == 0 {
                return None;
            }
            let slot = rd(cur);
            let link = links.get(slot)?;
            left -= 1;
            cur = link.next.load(Relaxed);
            Some(slot)
        })
    }

    /// Back to the empty list (the links of former members are left as they
    /// are: `push_back` rewrites a member's link when it enters a list, and
    /// `remove` refuses one whose neighbours do not name it).
    pub fn reset(&self) {
        self.head.store(0, Relaxed);
        self.tail.store(0, Relaxed);
        self.count.store(0, Relaxed);
    }
}
