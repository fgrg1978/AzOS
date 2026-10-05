// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Boot-reserved regions of `mem = "locked"` topology rows, mapped with
//! level-1 leaves (Kconfig `LOCKED_HUGE_LEAVES`; 2 MiB on Sv39).
//!
//! A row that declares `mem_huge_mib = N` gets N MiB of physically
//! contiguous RAM, aligned to the level-1 leaf size, taken from the allocator
//! ONCE, at boot, right after memory admission counted it — a 2 MiB-aligned
//! run is exactly what fragmentation makes impossible later. The region is
//! keyed by the row (index + 1, `azos_sched::MemSpec::row`) and is never
//! given back: the row's next instance gets the same frames, zeroed again by
//! exec. Teardown never frees it either — a level-1 user leaf is skipped by
//! `vmm::destroy_user_pagetable_skip_range`, and the region lies in the
//! shm/MMIO window whose frames teardown does not own.

use azos_common::error::{KResult, KernelError};
use azos_sync::SpinLock;

use crate::{pmm, vmm};
use azos_arch::mmu::PAGE_SIZE;

/// Rows with a region at once. A topology declaring more is refused at boot.
pub const MAX_HUGE_REGIONS: usize = 8;

/// `(row + 1, physical base, bytes)`; `row + 1 == 0` is a free slot.
static REGIONS: SpinLock<[(u16, usize, usize); MAX_HUGE_REGIONS]> =
    SpinLock::new([(0, 0, 0); MAX_HUGE_REGIONS]);

/// Reserve `bytes` (a whole number of level-1 leaves) for the row `row`
/// (index + 1). Returns the physical base. Refused when the row already has
/// one, the table is full, or no aligned run is free.
pub fn reserve(row: u16, bytes: usize) -> KResult<usize> {
    if row == 0 || bytes == 0 || bytes % vmm::MEGA_SIZE != 0 {
        return Err(KernelError::InvalidArg);
    }
    let mut regions = REGIONS.lock();
    if regions.iter().any(|r| r.0 == row) {
        return Err(KernelError::AlreadyMapped);
    }
    let slot = regions.iter().position(|r| r.0 == 0).ok_or(KernelError::OutOfMemory)?;
    let pa = pmm::alloc_contiguous_aligned(bytes / PAGE_SIZE, vmm::MEGA_SIZE)?.as_usize();
    regions[slot] = (row, pa, bytes);
    Ok(pa)
}

/// `(physical base, bytes)` of the row's region, if it has one.
pub fn region(row: u16) -> Option<(usize, usize)> {
    if row == 0 {
        return None;
    }
    REGIONS.lock().iter().find(|r| r.0 == row).map(|r| (r.1, r.2))
}

/// `(regions, bytes)` reserved so far, for the boot log.
pub fn reserved() -> (usize, usize) {
    let regions = REGIONS.lock();
    regions.iter().filter(|r| r.0 != 0).fold((0, 0), |(n, b), r| (n + 1, b + r.2))
}
