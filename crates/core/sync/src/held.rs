// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The held-lock counts the panic policy reads: how
//! many sleeping locks each task holds. [`crate::kmutex::Mutex`] counts its
//! holder here (its guard raises, its unlock lowers); [`crate::claim`]
//! keeps a second table of its own, the same type, for the claims held
//! across a device wait.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
#[cfg(feature = "pi-held-trace")]
use core::sync::atomic::AtomicUsize;

/// A no-owner sentinel: the TID [`caller_tid`] answers before a task runs.
const NO_OWNER: u32 = u32::MAX;


/// Entries of a [`HeldTable`].
const PI_HELD_SLOTS: usize = 64;

/// Entries of the second level of a [`HeldTable`].
const PI_HELD_OVERFLOW_SLOTS: usize = 16;

/// Locks acquired and not yet released, per task, for the panic policy's
/// containment predicate: a task that panics while
/// it holds a lock nobody else would release cannot be parked. One table
/// for the `Mutex`es ([`held_by`]), one for the claims
/// (`crate::claim::held_by`, owner rule F1: what is held across a device
/// wait).
///
/// Keyed by the exact TID: each entry packs `tid << 32 | count`, and an entry
/// whose count is 0 is free whatever TID it last carried. An acquisition
/// probes from `tid % PI_HELD_SLOTS` and raises the first entry that is its
/// own, or claims the first free one; a release lowers the first entry that
/// is its own. Both are one compare-and-swap on the packed word, so a claim,
/// a raise and a drop to zero cannot interleave. Before wave 13 the table was
/// `count[tid % 64]`: two live tasks 64 TIDs apart shared a word, and TIDs
/// only grow, so after enough task churn a culprit that held nothing read as
/// holding its neighbour's lock and a containable panic became a reset.
///
/// A task can end up with two entries (its first one was freed and re-claimed
/// by another TID while the task held a second lock further along the probe
/// sequence). [`HeldTable::held_by`] sums every entry with the TID and a
/// release lowers any one of them, so the total stays exact.
///
/// When every entry is taken by another TID the acquisition goes to a second
/// level of the same shape (`spill`, `PI_HELD_OVERFLOW_SLOTS` entries), still
/// keyed by TID, so [`HeldTable::forget`] drops a dead task's spilled counts
/// with the rest of its own. Only when the second level is full too is the
/// acquisition counted in `overflow`, which [`HeldTable::held_by`] adds for
/// EVERY TID: an over-count, the reset path, the safe direction — never an
/// under-count. `forget` cannot attribute that counter to a task, so it is
/// the one residue a dead task can leave (more than `PI_HELD_SLOTS +
/// PI_HELD_OVERFLOW_SLOTS` distinct tasks holding locks at once). Before the
/// second level, `forget` left every overflowed raise in a counter nobody
/// lowered once the holder was dead, and a dead holder read as still holding
/// (ktest `kmutex_dead_holder_leaves_the_held_table`).
pub(crate) struct HeldTable {
    slots:    [AtomicU64; PI_HELD_SLOTS],
    spill:    [AtomicU64; PI_HELD_OVERFLOW_SLOTS],
    overflow: AtomicU32,
}

#[inline(always)]
const fn held_tid(e: u64) -> u32 {
    (e >> 32) as u32
}

#[inline(always)]
const fn held_count(e: u64) -> u32 {
    e as u32
}

/// Raise `tid`'s entry in `slots`, or claim a free one: the entry and its
/// new count, `None` when every entry belongs to another TID.
#[inline(always)]
fn slots_raise(slots: &[AtomicU64], tid: u32) -> Option<(usize, u32)> {
    let n = slots.len();
    let home = tid as usize % n;
    let mut k = 0;
    while k < n {
        let i = (home + k) % n;
        let slot = &slots[i];
        let mut e = slot.load(Ordering::Acquire);
        loop {
            let next = if held_count(e) == 0 {
                (tid as u64) << 32 | 1
            } else if held_tid(e) == tid {
                e + 1
            } else {
                break;
            };
            match slot.compare_exchange_weak(e, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some((i, held_count(next))),
                Err(now) => e = now,
            }
        }
        k += 1;
    }
    None
}

/// Lower the first entry of `slots` that is `tid`'s; `false` if none.
#[inline(always)]
fn slots_lower(slots: &[AtomicU64], tid: u32) -> bool {
    let n = slots.len();
    let home = tid as usize % n;
    let mut k = 0;
    while k < n {
        let slot = &slots[(home + k) % n];
        let mut e = slot.load(Ordering::Acquire);
        while held_count(e) != 0 && held_tid(e) == tid {
            match slot.compare_exchange_weak(e, e - 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(now) => e = now,
            }
        }
        k += 1;
    }
    false
}

impl HeldTable {
    pub(crate) const fn new() -> Self {
        Self {
            slots:    [const { AtomicU64::new(0) }; PI_HELD_SLOTS],
            spill:    [const { AtomicU64::new(0) }; PI_HELD_OVERFLOW_SLOTS],
            overflow: AtomicU32::new(0),
        }
    }

    /// Count one acquisition by `tid`: the entry and its new count, or
    /// `None` when it spilled (no entry in the first level to trace).
    #[inline(always)]
    pub(crate) fn raise(&self, tid: u32) -> Option<(usize, u32)> {
        if let Some(r) = slots_raise(&self.slots, tid) {
            return Some(r);
        }
        if slots_raise(&self.spill, tid).is_none() {
            self.overflow.fetch_add(1, Ordering::AcqRel);
        }
        None
    }

    /// Undo one [`HeldTable::raise`] by `tid`.
    #[inline(always)]
    pub(crate) fn lower(&self, tid: u32) {
        if slots_lower(&self.slots, tid) || slots_lower(&self.spill, tid) {
            return;
        }
        // Not in either level: the raise overflowed.
        let _ = self.overflow.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |n| n.checked_sub(1));
    }

    /// Task `tid` exited: drop every entry it still holds, in both levels
    /// (a lock it died holding is no longer its own, N7d). The `overflow`
    /// counter is left alone: it is nobody's, and an over-count is the safe
    /// direction. O(`PI_HELD_SLOTS`), one load per entry, a CAS per hit.
    pub(crate) fn forget(&self, tid: u32) {
        for slot in self.slots.iter().chain(self.spill.iter()) {
            let mut e = slot.load(Ordering::Acquire);
            while held_count(e) != 0 && held_tid(e) == tid {
                match slot.compare_exchange_weak(e, 0, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => break,
                    Err(now) => e = now,
                }
            }
        }
    }

    /// Acquisitions task `tid` has not released. Exact, unless more tasks
    /// than both levels hold locks at once (then an over-count by the
    /// `overflow` counter, never an under-count). O(`PI_HELD_SLOTS`): the
    /// panic path's question.
    pub(crate) fn held_by(&self, tid: u32) -> u32 {
        let mut n = self.overflow.load(Ordering::Acquire);
        for slot in self.slots.iter().chain(self.spill.iter()) {
            let e = slot.load(Ordering::Acquire);
            if held_count(e) != 0 && held_tid(e) == tid {
                n = n.saturating_add(held_count(e));
            }
        }
        n
    }

    /// `(entry, count)` of each first-level entry task `tid` has.
    #[cfg(feature = "pi-held-trace")]
    fn entries_of(&self, tid: u32, mut f: impl FnMut(usize, u32)) {
        for (i, slot) in self.slots.iter().enumerate() {
            let e = slot.load(Ordering::Acquire);
            if held_count(e) != 0 && held_tid(e) == tid { f(i, held_count(e)); }
        }
    }
}

/// The `Mutex` acquisitions ([`HeldTable`]).
static PI_HELD: HeldTable = HeldTable::new();

/// `pi-held-trace` (diagnostics, the `lat-fat` smoke): the address of each
/// `Mutex` a task holds, by nesting depth, beside its [`PI_HELD`] entry.
/// Only the first `PI_TRACE_DEPTH` levels are kept. Off: nothing compiled.
#[cfg(feature = "pi-held-trace")]
const PI_TRACE_DEPTH: usize = azos_limits::PI_TRACE_DEPTH;
#[cfg(feature = "pi-held-trace")]
static PI_HELD_ADDR: [[AtomicUsize; PI_TRACE_DEPTH]; PI_HELD_SLOTS] =
    [const { [const { AtomicUsize::new(0) }; PI_TRACE_DEPTH] }; PI_HELD_SLOTS];

/// The `Mutex`es task `tid` holds, outermost first (at most `out.len()`
/// and the trace depth); returns how many were written.
#[cfg(feature = "pi-held-trace")]
pub fn held_addrs(tid: u32, out: &mut [usize]) -> usize {
    let mut n = 0;
    PI_HELD.entries_of(tid, |i, count| {
        for d in 0..(count as usize).min(PI_TRACE_DEPTH) {
            if n < out.len() {
                out[n] = PI_HELD_ADDR[i][d].load(Ordering::Relaxed);
                n += 1;
            }
        }
    });
    n
}

/// Count one acquisition by `tid` (of the mutex at `_addr`).
#[inline(always)]
pub(crate) fn held_raise(tid: u32, _addr: usize) {
    let _r = PI_HELD.raise(tid);
    #[cfg(feature = "pi-held-trace")]
    if let Some((i, count)) = _r {
        let d = count as usize - 1;
        if d < PI_TRACE_DEPTH {
            PI_HELD_ADDR[i][d].store(_addr, Ordering::Relaxed);
        }
    }
}

/// Task `tid` exited (scheduler exit paths, after the wait graph's
/// owner-died hand-over): its entries in the held table go, so the panic
/// policy's `mutex-held` check never counts a dead holder and stale
/// entries never fill the table (N7d). A `Mutex` it died
/// holding stays held by the lock word; only the count is dropped.
/// O([`PI_HELD_SLOTS`]). Runtime canary `canary=held-keeps-dead` skips it.
pub fn held_forget(tid: u32) {
    if CANARY_HELD_KEEPS_DEAD.load(Ordering::Relaxed) {
        return;
    }
    PI_HELD.forget(tid);
}

static CANARY_HELD_KEEPS_DEAD: AtomicBool = AtomicBool::new(false);

/// Arm the `held-keeps-dead` canary (boot, from the command line): a dead
/// holder's held-table entries stay (pre-N7d); ktest
/// `pilock_dead_holder_leaves_the_held_table` goes red.
pub fn canary_held_keeps_dead() {
    CANARY_HELD_KEEPS_DEAD.store(true, Ordering::Relaxed);
}

/// Undo one [`held_raise`] by `tid`.
#[inline(always)]
pub(crate) fn held_lower(tid: u32) {
    PI_HELD.lower(tid);
}

/// `Mutex` acquisitions task `tid` has not released. Exact, unless an
/// acquisition by any task overflowed the table (then an over-count, never
/// an under-count). O([`PI_HELD_SLOTS`]): the panic path's question.
pub fn held_by(tid: u32) -> u32 {
    PI_HELD.held_by(tid)
}

/// Does the calling task hold any `Mutex`? The console's question before
/// it waits for its line lock (`azos_drv_sys::console_defer::may_wait`): a
/// waiter that holds a sleeping lock could wait on a holder that needs it.
pub fn caller_holds_any() -> bool {
    held_by(caller_tid()) != 0
}

/// The calling task's TID (`NO_OWNER`: none; the per-CPU accessor answers 0
/// when no task is current on this hart).
pub fn caller_tid() -> u32 {
    match crate::waitqueue::caller_tid() {
        0 => NO_OWNER,
        tid => tid,
    }
}
