// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The COW share count: which physical pages are shared, and by how many.
//!
//! The count is `FrameDesc::refcount` (`frame.rs`), one atomic per managed
//! frame, found by frame number; there is no table of its own, no lock and no
//! capacity to run out of before RAM does. A hit, a miss and an insert cost
//! the same handful of instructions. It replaced a `u16` array under one
//! global lock, which every fork and every teardown of every task serialized
//! on, and whose frame lookup (`pmm::frame_index`) it shares with the
//! descriptors.
//!
//! `cow.rs` re-exports the public items, so `azos_mm::cow::page_addref`
//! and `vmm::page_addref` keep their paths. The lookups here decide whether a
//! frame is freed, which is where a mistake is not an error but a leak or a
//! double free; the host links this file (`tests/host/mm-tests`, `#[path]`).
//!
//! # What a count means
//!
//! `0` is "untracked", i.e. a single owner: the case for every private page,
//! which never enters the COW machinery. The first `addref` takes a page to `2`
//! (the parent that already held it, plus the child). A `decref` from `1` or `0`
//! answers "free it", and clears the count. Counts saturate at `u32::MAX` rather
//! than wrap: a saturated page is never freed, which leaks it but cannot hand
//! a live frame back to the allocator.
//!
//! # No lock
//!
//! Each operation is one compare-and-swap loop on one word, so concurrent
//! `addref`/`decref` of a frame never lose an update. What the old table's lock
//! also gave, a read of the count and a page-table write as one step, is not
//! there: `handle_cow_fault`'s reuse and `rewrite_leaf_write` read the count
//! and write the entry separately, and `forget_if_sole` is the compare-and-swap
//! that tells the first of them whether a fork got in between.

use core::sync::atomic::{AtomicU32, Ordering};
use crate::pmm;
use azos_common::error::{KResult, KernelError};

/// Initial count when a page first becomes shared: one for the parent that
/// already held it, one for the child.
const INITIAL_SHARED_REFCOUNT: u32 = 2;

/// Increment the count for a physical page (used by COW fork).
///
/// An untracked page becomes `INITIAL_SHARED_REFCOUNT`; a tracked one gains one.
///
/// Fails with `InvalidArg` when `phys` is not a managed, page-aligned frame:
/// there is no counter to keep for it, and a fork that cannot account for a page
/// must refuse rather than share it uncounted. The caller (`fork_cow`) tears down
/// what it built.
pub fn page_addref(phys: usize) -> KResult<()> {
    let d = pmm::desc_of(phys).ok_or(KernelError::InvalidArg)?;
    let mut cur = d.refcount.load(Ordering::Relaxed);
    loop {
        let new = match cur {
            0 => INITIAL_SHARED_REFCOUNT,
            n => n.saturating_add(1),
        };
        match d.refcount.compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return Ok(()),
            Err(now) => cur = now,
        }
    }
}

/// Decrement the count for a physical page.
///
/// Returns `true` if the page should be freed: it was at 1 (the last holder),
/// or it was never tracked, or it is not a managed frame at all (nothing to
/// count, so the caller is the sole owner and `pmm::free_page` is the judge).
pub fn page_decref(phys: usize) -> bool {
    let Some(d) = pmm::desc_of(phys) else { return true };
    let mut cur = d.refcount.load(Ordering::Relaxed);
    loop {
        if cur == 0 { return true; }
        // Canary `refcount-canary`: the second-to-last holder is told it is
        // the last, and frees a frame the other still maps.
        let last = cur == 1 || (cfg!(feature = "refcount-canary") && cur == 2);
        let new = if last { 0 } else { cur - 1 };
        match d.refcount.compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return last,
            Err(now) => cur = now,
        }
    }
}

/// Query the current count for a physical page. `0` if untracked.
pub fn page_getref(phys: usize) -> u32 {
    pmm::desc_of(phys).map_or(0, |d| d.refcount())
}

/// Is the caller this frame's only holder (count 0 or 1)? `false` for a
/// frame the table does not manage: there is no count to trust (wave 14,
/// the copy-on-write reuse in `handle_cow_fault`).
#[inline(always)]
pub fn page_is_sole(phys: usize) -> bool {
    pmm::desc_of(phys).is_some_and(|d| d.refcount() <= 1)
}

/// Does another holder share this frame (count above 1)? `false` for a
/// frame the table does not manage (shared memory and device frames are
/// owned elsewhere and never counted here).
#[inline(always)]
pub fn page_is_shared(phys: usize) -> bool {
    pmm::desc_of(phys).is_some_and(|d| d.refcount() > 1)
}

/// The only holder keeps the frame as a private page: back to untracked.
/// `false`, and the count untouched, when it is above 1 by now (a fork took a
/// reference since the caller looked) or the frame is not managed.
#[inline(always)]
pub fn page_forget_if_sole(phys: usize) -> bool {
    let Some(d) = pmm::desc_of(phys) else { return false };
    let mut cur = d.refcount.load(Ordering::Relaxed);
    while cur <= 1 {
        match d.refcount.compare_exchange_weak(cur, 0, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(now) => cur = now,
        }
    }
    false
}

/// Host test harnesses only, like `shim_set_cow_breaks`: put `n` in the count
/// of the frame at `phys`, so a test can start near the saturation edge
/// without `u32::MAX` calls.
#[cfg(not(target_os = "none"))]
pub fn shim_set_refcount(phys: usize, n: u32) {
    pmm::desc_of(phys).expect("a managed frame").refcount.store(n, Ordering::Relaxed);
}

// ── COW-break accounting (scan unit 3 finding 3, the open half) ────────────
//
// `handle_cow_fault` (`cow.rs`) allocates a fresh frame on every break and is
// not charged against the per-task quota. That is deliberate, not an
// oversight. Three of
// the handler's four failure paths (null deref, unmapped VA, a write to a
// non-COW page) are the calling program's own bug, and the store-page-fault
// arm in `kernel/src/entry/riscv64/trap.rs` kills the task on any `Err` from it — there is
// no signal/upcall ABI to hand a refusal back (verified: nothing in
// `syscall_nr.rs` or `task.rs`). Folding a quota check into that same trap
// would add a FIFTH path with the same outcome (task dies) for a task that did
// nothing wrong, and the note's own conclusion is to make the innocent case
// (`OutOfMemory`) legible FIRST and treat charging as a later, separate
// decision. This counter is that legibility step: it observes the cost
// without ever refusing anything.
//
// Global rather than per-task, like `MM_PEAK_GLOBAL` in `scheduler.rs`: the
// task whose break this was may have already exited by the time anything
// reads the count.

/// Frames added to some task's footprint by breaking copy-on-write, total
/// across every task, ever. See the module note above for why this is
/// observed rather than charged.
static COW_BREAK_FRAMES: AtomicU32 = AtomicU32::new(0);

/// Record that a COW break allocated a fresh frame.
///
/// `AtomicU32::fetch_add` does not go through `overflow-checks` — atomics are
/// not instrumented by that lint, so an unguarded counter would wrap silently
/// on the target instead of the workspace's usual panic = abort. Load-then-
/// `saturating_add`-then-store instead, the same shape as `note_stalled_tick`
/// (`crates/core/actuation/src/watchdog.rs`): a wrapped counter would read as
/// "no COW breaks happened" rather than "over four billion", which is the
/// wrong direction for a diagnostic to fail in.
pub fn note_cow_break() {
    let n = COW_BREAK_FRAMES.load(Ordering::Relaxed).saturating_add(1);
    COW_BREAK_FRAMES.store(n, Ordering::Relaxed);
}

/// See [`note_cow_break`].
#[must_use]
pub fn cow_break_frames() -> u32 {
    COW_BREAK_FRAMES.load(Ordering::Relaxed)
}

/// Host test harnesses only, like `shim_reset_refs`: seed the counter near its
/// saturation edge so a test can pin that `note_cow_break` does not wrap.
#[cfg(not(target_os = "none"))]
pub fn shim_set_cow_breaks(n: u32) {
    COW_BREAK_FRAMES.store(n, Ordering::Relaxed);
}
