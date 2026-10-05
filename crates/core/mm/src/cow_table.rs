// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The COW refcount table: which physical pages are shared, and by how many.
//!
//! Carved out of `cow.rs` so the host can link it. `cow.rs` walks live page
//! tables and executes `sfence.vma`, so nothing in it is reachable off-target;
//! this file touches no page table and dereferences nothing, and is pulled into
//! `tests/host/mm-tests` with `#[path]`, the same way `wx.rs` was carved out of
//! `vmm.rs`. The lookups here decide whether a frame is freed, which is where a
//! mistake is not an error but a leak or a double free.
//!
//! `cow.rs` re-exports the public items, so `azos_mm::cow::page_addref`
//! and `vmm::page_addref` keep their paths.
//!
//! # One counter per frame, indexed by frame number
//!
//! `REFS[pmm::frame_index(phys)]` is the count for that frame. There is no
//! search, so a hit, a miss and an insert all cost the same handful of
//! instructions, and there is no capacity to run out of before RAM does.
//!
//! This replaced a 512-entry table scanned from index 0. That table was
//! O(occupancy) per lookup, which made a fork of an M-page process cost M²/2
//! comparisons (126 k instructions per fork of `vsbench`, ~200 pages, measured
//! 2026-09-18), and it capped `fork` at 512 shared pages: a process with more
//! failed with `CapacityFull`, a ~2 MiB ceiling that had nothing to do with
//! memory. A scan hint fixed the hit path and left both the miss path and the
//! ceiling; an indexed array removes all three, and it is simpler than the hash
//! table it would otherwise have needed (no probing, no tombstones, no
//! backward-shift deletion to get wrong).
//!
//! Cost: `RAM_SIZE` MiB × 512 bytes of `.bss` (2 bytes per 4 KiB frame): 32 KiB
//! on `embedded` (64 MiB), 512 KiB on `fleet` (1 GiB), 4 MiB on `edge` (8 GiB).
//!
//! # What a count means
//!
//! `0` is "untracked", i.e. a single owner: the case for every private page,
//! which never enters the COW machinery. The first `addref` takes a page to `2`
//! (the parent that already held it, plus the child). A `decref` from `1` or `0`
//! answers "free it", and clears the count. Counts saturate at `u16::MAX` rather
//! than wrap: a saturated page is never freed, which leaks it but cannot hand
//! a live frame back to the allocator.

use core::sync::atomic::{AtomicU32, Ordering};
use crate::pmm;
use azos_common::error::{KResult, KernelError};
use azos_sync::SpinLock;

/// Initial count when a page first becomes shared: one for the parent that
/// already held it, one for the child.
const INITIAL_SHARED_REFCOUNT: u16 = 2;

/// One counter per managed frame. All zero (untracked) until a fork shares it.
static REFS: SpinLock<[u16; pmm::MAX_PAGES]> = SpinLock::new([0; pmm::MAX_PAGES]);

/// Increment the count for a physical page (used by COW fork).
///
/// An untracked page becomes `INITIAL_SHARED_REFCOUNT`; a tracked one gains one.
///
/// Fails with `InvalidArg` when `phys` is not a managed, page-aligned frame:
/// there is no counter to keep for it, and a fork that cannot account for a page
/// must refuse rather than share it uncounted. The caller (`fork_cow`) tears down
/// what it built.
/// Forget every refcount. **Host test harnesses only** — compiled out on the
/// target, like `vmm::shim_forget_kernel_pt`.
///
/// # Why this had to exist
///
/// `REFS` is process-global and had no reset, while `syscall-tests`' `serial()`
/// re-initialises the PMM arena for every test. So a test that took a second
/// reference on a frame left that refcount behind, `shim_reset` handed the
/// same frame to the next test, and `unmap_user_and_free` then correctly
/// refused to free it — "another COW holder". It reads as a leak in the test
/// that inherited the frame, which is where the cost went: a COW test was
/// written, turned two unrelated `mmap_guards` tests red, and was **withdrawn
/// on the wrong diagnosis** ("there is no per-test allocator isolation" — there
/// is, and it is `serial()`; what was missing was this).
///
/// Not a kernel operation: on a board a frame's refcount is the only record of
/// who shares it, and forgetting them all would free pages other tasks are
/// still reading.
#[cfg(not(target_os = "none"))]
pub fn shim_reset_refs() {
    let mut refs = REFS.lock();
    for r in refs.iter_mut() {
        *r = 0;
    }
}

pub fn page_addref(phys: usize) -> KResult<()> {
    ref_batch().addref(phys)
}

/// The refcount table held for a run of updates: [`page_addref`] and
/// [`page_decref`] without taking the lock once per page (wave 13: a fork of
/// ~200 pages spent ~20k instructions in each, almost all of it on the lock).
/// A fork holds it over one leaf table's pages, and a teardown the same; the
/// nesting is this lock, then the frame allocator's (a teardown frees under
/// it), never the reverse.
pub struct RefBatch<'a> {
    refs: azos_sync::SpinLockGuard<'a, [u16; pmm::MAX_PAGES]>,
}

/// Take the refcount table for a [`RefBatch`].
pub fn ref_batch() -> RefBatch<'static> {
    RefBatch { refs: REFS.lock() }
}

impl RefBatch<'_> {
    /// [`page_addref`] under the held table.
    #[inline(always)]
    pub fn addref(&mut self, phys: usize) -> KResult<()> {
        let idx = pmm::frame_index(phys).ok_or(KernelError::InvalidArg)?;
        self.refs[idx] = match self.refs[idx] {
            0 => INITIAL_SHARED_REFCOUNT,
            n => n.saturating_add(1),
        };
        Ok(())
    }

    /// [`page_decref`] under the held table.
    #[inline(always)]
    pub fn decref(&mut self, phys: usize) -> bool {
        let Some(idx) = pmm::frame_index(phys) else { return true };
        match self.refs[idx] {
            0 | 1 => {
                self.refs[idx] = 0;
                true
            }
            n => {
                self.refs[idx] = n - 1;
                false
            }
        }
    }
}

impl RefBatch<'_> {
    /// Is the caller this frame's only holder (count 0 or 1)? `false` for a
    /// frame the table does not manage: there is no count to trust (wave 14,
    /// the copy-on-write reuse in `handle_cow_fault`).
    #[inline(always)]
    pub fn sole(&self, phys: usize) -> bool {
        match pmm::frame_index(phys) {
            Some(idx) => self.refs[idx] <= 1,
            None => false,
        }
    }

    /// Does another holder share this frame (count above 1)? `false` for a
    /// frame the table does not manage (shared memory and device frames are
    /// owned elsewhere and never counted here).
    #[inline(always)]
    pub fn shared(&self, phys: usize) -> bool {
        pmm::frame_index(phys).is_some_and(|idx| self.refs[idx] > 1)
    }

    /// The only holder keeps the frame as a private page: back to untracked.
    #[inline(always)]
    pub fn forget(&mut self, phys: usize) {
        if let Some(idx) = pmm::frame_index(phys) {
            self.refs[idx] = 0;
        }
    }
}

/// Decrement the count for a physical page.
///
/// Returns `true` if the page should be freed: it was at 1 (the last holder),
/// or it was never tracked, or it is not a managed frame at all (nothing to
/// count, so the caller is the sole owner and `pmm::free_page` is the judge).
pub fn page_decref(phys: usize) -> bool {
    ref_batch().decref(phys)
}

/// Query the current count for a physical page. `0` if untracked.
pub fn page_getref(phys: usize) -> u16 {
    match pmm::frame_index(phys) {
        Some(idx) => REFS.lock()[idx],
        None => 0,
    }
}

// ── COW-break accounting (scan unit 3 finding 3, the open half) ────────────
//
// `handle_cow_fault` (`cow.rs`) allocates a fresh frame on every break and is
// not charged against the per-task quota. That is deliberate, not an
// oversight. Three of
// the handler's four failure paths (null deref, unmapped VA, a write to a
// non-COW page) are the calling program's own bug, and the store-page-fault
// arm in `kernel/src/trap/exception.rs` kills the task on any `Err` from it — there is
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
