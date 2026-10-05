// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-task allocator for the shm/MMIO VA window.
//!
//! `shm_map_user` and `mmio_map_user` (`process.rs`) place their mappings in
//! `[USER_MMIO_BASE, USER_MMIO_LIMIT)`. Each task keeps its own reservations
//! (`Task::user_window`): a release gives its addresses back to the task that
//! reserved them, and the slot reuse after an exit gives back the rest.
//!
//! Pure bookkeeping over a slice of `[base, span]` pairs, with no page tables
//! and no locks, so `tests/host/sched-wake-tests` runs it on the host unmodified
//! and `tests/host/syscall-tests` maps through it. A pair with `span == 0` is
//! free, so an all-zero table (the `core::mem::zeroed` task pool) is empty.

/// Reservations one task can hold at once: `MAX_SHM_REGIONS_PER_TASK` (8) shm
/// mappings plus as many MMIO mappings. A map past it is refused.
pub const USER_WINDOW_RANGES: usize = 16;

/// Reserve `span` bytes inside `[lo, hi)` at the lowest address where they
/// overlap no reserved pair. `None` when `span` is 0, when no pair is free, or
/// when no gap below `hi` is wide enough.
///
/// The result is page-aligned when `lo` and every span are, which the callers
/// guarantee (page counts times `PAGE_SIZE`).
pub fn reserve(ranges: &mut [[usize; 2]], lo: usize, hi: usize, span: usize) -> Option<usize> {
    if span == 0 {
        return None;
    }
    let slot = ranges.iter().position(|r| r[1] == 0)?;
    let mut base = lo;
    loop {
        let end = base.checked_add(span)?;
        if end > hi {
            return None;
        }
        // Every address below the highest end among the pairs overlapping
        // `[base, end)` overlaps that pair too, so the next candidate is that
        // end. It is above `base`, so the loop runs at most once per pair.
        let blocker = ranges
            .iter()
            .filter(|r| r[1] != 0 && r[0] < end && base < r[0].saturating_add(r[1]))
            .map(|r| r[0].saturating_add(r[1]))
            .max();
        match blocker {
            Some(next) => base = next,
            None => break,
        }
    }
    ranges[slot] = [base, span];
    Some(base)
}

/// Give back the reservation `[base, base + span)`. Only the exact pair a
/// [`reserve`] returned is released; for anything else nothing changes and
/// the answer is `false`.
pub fn release(ranges: &mut [[usize; 2]], base: usize, span: usize) -> bool {
    if span == 0 {
        return false;
    }
    match ranges.iter_mut().find(|r| r[0] == base && r[1] == span) {
        Some(r) => {
            *r = [0, 0];
            true
        }
        None => false,
    }
}
