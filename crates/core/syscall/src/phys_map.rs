// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Physical ranges lent to the calling task: a device's register window, a ring
//! page, the per-task vDSO page.
//!
//! Each is a record of the task's address space (`azos_mm::pager::reserve_phys`),
//! placed in the mmap area like a shared object, with its leaves made after the
//! record: a failure to map releases the record, which takes the leaves done
//! with it, and the space's end clears them without freeing a frame. The
//! caller owns the range. Ring 3 cannot `munmap` or `mprotect` one (the pager
//! refuses a physical range), so the owner's release is the only way out.

use azos_arch::PAGE_SIZE;
use azos_arch_api::MemType;

/// What to lend: `pages` pages from `pa`, cached as `mem`.
pub(crate) struct Grant {
    pub pa: usize,
    pub pages: usize,
    pub write: bool,
    pub mem: MemType,
}

/// Map `g` into the calling task. The address, or `None` for a kernel task, a
/// range of no pages or one that wraps, no room in the mmap area, or no free
/// record in the space.
pub(crate) fn map_user(g: &Grant) -> Option<usize> {
    let _mm = azos_sched::group::mm_lock();
    let space = azos_sched::current_aspace()?;
    let span = g.pages.checked_mul(PAGE_SIZE).filter(|&s| s != 0)?;
    g.pa.checked_add(span)?;
    let va = crate::handlers::mmap_place_shared(space.root(), span).ok()?;
    // Canary `phys-leaves-unrecorded-canary`: a range the space cannot record is mapped anyway.
    let recorded = azos_mm::pager::reserve_phys(space, va, va + span, g.write, g.pa, g.mem, false);
    if recorded.is_err() && !cfg!(feature = "phys-leaves-unrecorded-canary") {
        return None;
    }
    if azos_mm::vmm::map_phys(space.root(), va, g.pa, g.pages, g.write, g.mem).is_err() {
        let _ = azos_mm::pager::release_range(space, va, va + span);
        return None;
    }
    crate::handlers::mmap_area_placed(va);
    Some(va)
}

/// End the calling task's mapping of `pages` pages at `va`: its record and
/// leaves go, the address comes back, no frame is freed.
pub(crate) fn unmap_user(va: usize, pages: usize) {
    let _mm = azos_sched::group::mm_lock();
    let Some(space) = azos_sched::current_aspace() else { return };
    let end = va.saturating_add(pages.saturating_mul(PAGE_SIZE));
    if azos_mm::pager::release_range(space, va, end).is_ok() {
        crate::handlers::mmap_unmapped(va, end);
    }
}
