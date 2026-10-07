// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The per-priority ready queues: intrusive singly linked FIFO lists.
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
//! **Encoding.** Every stored value is the slot itself, and a list ends at
//! its `count`, not at a sentinel link: `head`, `tail` and the last member's
//! link mean something only while `count > 0`. So an all-zero `ReadyList`
//! (count 0) is the empty list (the per-CPU areas are zeroed), and no
//! operation spends an instruction on a `+ 1`/`- 1` or on clearing a link.
//! `next[i]` is the successor of slot `i` in whichever list holds it. Every
//! stored value is read sign-extended (see [`rd`]), so one `< next.len()`
//! compare range-checks it. Wave 15 integration: with `slot + 1` links, a
//! zero-terminated pop and zero-extended reads, a context switch paid +12
//! instructions for lists over the rings they replaced (vsbench ctxsw-loaded,
//! riscv64 -icount, 532 -> 544); these three changes removed that.
//!
//! **Concurrency.** Every mutation runs under the owning CPU's lock; the
//! atomics are `Relaxed` for the same reason the ring's were (shared `&`
//! without aliasing UB), not for lock-free readers. A reader walks under the
//! same lock. Every walk is bounded by `count` and by `next.len()`, and stops
//! at an out-of-range link, so a broken invariant ends a walk instead of
//! looping or indexing out of bounds.
//!
//! Pure (`core` only), pulled into `tests/host/sched-wake-tests` with
//! `#[path]`: the scheduler itself cannot run on the host.

use core::sync::atomic::{AtomicU32, Ordering::Relaxed};

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
    /// clamps it to `next.len()`.
    #[inline(always)]
    pub fn count(&self) -> usize {
        rd(self.count.load(Relaxed))
    }

    /// Append `slot`, given the `count` the caller has just read under the
    /// lock (so the hot path does not load it twice).
    ///
    /// The caller guarantees `slot < next.len()` and that `slot` is in no
    /// list (the `queued` claim). The new tail's own link is not written: the
    /// list ends at `count`.
    #[inline(always)]
    pub fn push_back(&self, next: &[AtomicU32], slot: usize, count: usize) {
        let s = slot as u32;
        if count == 0 {
            self.head.store(s, Relaxed);
        } else if let Some(t) = next.get(rd(self.tail.load(Relaxed))) {
            t.store(s, Relaxed);
        }
        self.tail.store(s, Relaxed);
        self.count.store(count as u32 + 1, Relaxed);
    }

    /// Remove and return the first slot, given the nonzero `count` the caller
    /// has just read under the lock. `None` when the head is out of range (a
    /// broken invariant), in which case the list is reset to empty rather
    /// than left pointing nowhere.
    #[inline(always)]
    pub fn pop_front(&self, next: &[AtomicU32], count: usize) -> Option<usize> {
        let slot = rd(self.head.load(Relaxed));
        let Some(link) = next.get(slot) else {
            self.reset();
            return None;
        };
        // The last entry leaves `head` as it is: count 0 makes it meaningless.
        if count > 1 {
            self.head.store(link.load(Relaxed), Relaxed);
        }
        self.count.store(count.saturating_sub(1) as u32, Relaxed);
        Some(slot)
    }

    /// Remove `slot` wherever it is in the list, keeping the order of the
    /// rest. Returns the new count, or `None` (nothing written) when `slot`
    /// is not in the list. O(position).
    pub fn remove(&self, next: &[AtomicU32], slot: usize) -> Option<usize> {
        let n = self.count().min(next.len());
        let want = slot as u32;
        let mut prev: Option<(u32, &AtomicU32)> = None;
        let mut cur = self.head.load(Relaxed);
        for i in 0..n {
            let link = next.get(rd(cur))?;
            let succ = link.load(Relaxed);
            if cur == want {
                match prev {
                    None => self.head.store(succ, Relaxed),
                    Some((_, p)) => p.store(succ, Relaxed),
                }
                // The last member: its predecessor is the new tail (none
                // left when it was the only one, and then count 0 says so).
                if i + 1 == n {
                    if let Some((pv, _)) = prev {
                        self.tail.store(pv, Relaxed);
                    }
                }
                let left = n - 1;
                self.count.store(left as u32, Relaxed);
                return Some(left);
            }
            prev = Some((cur, link));
            cur = succ;
        }
        None
    }

    /// The slots in order, at most `count` and at most `next.len()` of them,
    /// stopping early at an out-of-range link.
    pub fn iter<'a>(&'a self, next: &'a [AtomicU32]) -> impl Iterator<Item = usize> + 'a {
        let mut cur = self.head.load(Relaxed);
        let mut left = self.count().min(next.len());
        core::iter::from_fn(move || {
            if left == 0 {
                return None;
            }
            let slot = rd(cur);
            let link = next.get(slot)?;
            left -= 1;
            cur = link.load(Relaxed);
            Some(slot)
        })
    }

    /// Back to the empty list (the links of former members are left as they
    /// are: `push_back` rewrites a member's link when it enters a list).
    pub fn reset(&self) {
        self.head.store(0, Relaxed);
        self.tail.store(0, Relaxed);
        self.count.store(0, Relaxed);
    }
}
