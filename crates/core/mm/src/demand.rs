// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Demand paging (AQ10).
//!
//! Lets a user task reserve a virtual address range without consuming any
//! physical memory up front.  A physical page is allocated and zeroed on
//! the first access to each page (page fault → `handle_demand_fault()`).
//!
//! Encoding: a demand-mapped PTE has `VALID = 0` (so the MMU traps on
//! access) but the OS-defined `DEMAND` bit (bit 9, RSW field) is set.
//! The desired final flags (USER/READ/WRITE/EXEC) are stored in the same
//! PTE word so the fault handler can recover them.
//!
//! Interaction with the existing MM:
//!   - `map_demand()` is called for each page of the reservation.  It uses
//!     the same `walk()` helper as `vmm::map()`, so intermediate page
//!     tables are allocated lazily when the first demand PTE is written.
//!   - On fault, `handle_demand_fault()` calls `pmm::alloc_page()` (which
//!     already zeroes the page) and rewrites the PTE with the stored flags
//!     + VALID + DIRTY.
//!   - Free path is unchanged: `vmm::unmap()` will clear demand PTEs the
//!     same way it clears regular ones (no physical page to free until
//!     the fault has materialized it).
//!
//! `no-mmu` behaviour:
//!   - On the RV64 `no-mmu` feature the module still compiles (same target
//!     as the normal RV64 kernel, vmm is available), but the kernel's
//!     page-fault dispatch is gated with `#[cfg(not(feature = "no-mmu"))]`
//!     so `handle_demand_fault` is never reached; `map_demand()` remains
//!     functional for unit-style use but should not be called.

use azos_arch::ARCH;
use azos_arch_api::{Mmu, PagePerms, PAGE_SIZE};
use azos_common::error::{KResult, KernelError};
use crate::{pmm, vmm};

/// Maximum total bytes a single `sys_alloc_demand()` call may reserve.
///
/// 64 MiB = 16384 pages.  Protects against pathological sizes that would
/// consume a large chunk of the kernel's page-table budget even without
/// materializing physical memory.
pub const MAX_DEMAND_ALLOC_BYTES: usize = 64 * 1024 * 1024;

/// Default permissions for user demand pages (read-write, user-accessible).
///
/// ACCESSED is preset; DIRTY is added when the page materializes (see
/// `handle_demand_fault`) — before that the PTE is invalid anyway.
fn default_user_flags() -> PagePerms {
    PagePerms { accessed: true, ..PagePerms::USER_RW }
}

/// Reserve a single 4 KiB virtual page without allocating a physical page.
///
/// Writes a marker PTE: `VALID = 0` but `DEMAND` and the provided `flags`
/// are stored in-line so `handle_demand_fault()` can reconstitute them.
///
/// Errors:
///   - `NotAligned` if `vaddr` is not a 4 KiB multiple.
///   - `AlreadyMapped` if a mapping already exists there (either real or
///     demand-marked).
pub fn map_demand(pt_phys: usize, vaddr: usize, flags: PagePerms) -> KResult<()> {
    if vaddr & (PAGE_SIZE - 1) != 0 {
        return Err(KernelError::NotAligned);
    }

    // **This path reaches the page table without going through `vmm::map`.**
    //
    // `map`'s doc comment lists `sys_alloc_demand` among the paths that reach
    // a user page table through it. That was not true: demand reservation
    // walks straight to the PTE here, so `write_would_enter_kernel_table` —
    // the guard added after a ring-3 `munmap` of a kernel MMIO page reset the
    // board — was never consulted on the allocation side.
    //
    // What it costs when a demand march reaches a shared kernel L0: a DEMAND
    // marker is written into the KERNEL's table for every hole it passes, and
    // left there by design. The first user fault on one of those addresses,
    // from any task, materialises a USER_RW page inside the kernel page table,
    // and teardown skips borrowed tables so it is never freed.
    //
    // It was not reachable from ring 3, and the reason it was not is the point:
    // four coincidences held it shut. `brk` is the only base a caller can
    // influence; `USER_LOW_MAX` happens to equal the CLINT base; the CLINT base
    // happens to be 2 MiB-aligned so the only shared L0 in range is that one;
    // its first entry happens to be VALID, so the march stops immediately; and
    // a failed call happens not to advance `brk`. Move any MMIO mapping by one
    // page and it opens. A safety property held by coincidence is not held.
    if vmm::write_would_enter_kernel_table(pt_phys, vaddr) {
        return Err(KernelError::AlreadyMapped);
    }

    let pte_ptr = vmm::walk(pt_phys, vaddr, true)?;
    let old = unsafe { core::ptr::read_volatile(pte_ptr) };
    if ARCH.pte_is_valid(old) {
        return Err(KernelError::AlreadyMapped);
    }
    if ARCH.pte_is_demand(old) {
        return Err(KernelError::AlreadyMapped);
    }

    // Store DEMAND + the desired perms.  The physical-address portion of
    // the PTE stays 0 since no page has been allocated yet.
    let marker = ARCH.pte_make_demand(flags);
    unsafe { core::ptr::write_volatile(pte_ptr, marker) };

    Ok(())
}

/// Reserve a contiguous virtual range `[base, base + pages*PAGE_SIZE)`
/// with demand paging.  All pages get `USER_RW` flags.
///
/// On error any partial mapping is left in place; caller is responsible
/// for tearing it down.
pub fn map_demand_range(pt_phys: usize, base: usize, pages: usize) -> KResult<()> {
    let flags = default_user_flags();
    for i in 0..pages {
        map_demand(pt_phys, base + i * PAGE_SIZE, flags)?;
    }
    Ok(())
}

/// Handle a page fault on a demand-mapped page.
///
/// Returns `Ok(())` when the fault was resolved; `NotMapped` / `InvalidArg`
/// when the fault doesn't concern a demand-marked PTE and the caller
/// should continue its normal fault-handling path.
pub fn handle_demand_fault(pt: usize, fault_addr: usize) -> KResult<()> {
    let aligned_addr = fault_addr & !(PAGE_SIZE - 1);
    let pte_ptr = vmm::walk(pt, aligned_addr, false)?;
    let pte = unsafe { core::ptr::read_volatile(pte_ptr) };

    // Must be invalid and have the DEMAND marker set.
    if ARCH.pte_is_valid(pte) {
        return Err(KernelError::AlreadyMapped);
    }
    if !ARCH.pte_is_demand(pte) {
        return Err(KernelError::NotMapped);
    }

    // Recover the perms stored in the marker.
    let mut stored_perms = ARCH.pte_demand_perms(pte);

    // Allocate a physical page. `alloc_page` zero-fills it, and that is the
    // ONLY zero: the user must never see a previous owner's bytes, and the
    // guarantee rests on this being `alloc_page` and not
    // `alloc_page_uninit`. A second explicit zero used to follow here; it
    // wrote the same 4 KiB again on every demand fault (one `zero_memory`
    // call: ~1,560 instructions scalar, fewer with `cbo.zero`).
    let new_page = pmm::alloc_page()?;
    let new_phys = new_page.as_usize();

    // Install the real PTE: VALID + original perms (+ DIRTY because the
    // page was freshly written by `alloc_page`'s zeroing; avoids a second
    // fault on implementations with software-managed A/D bits).
    stored_perms.dirty = true;
    let new_pte = match ARCH.pte_make_leaf(new_phys, stored_perms, 0) {
        Ok(w) => w,
        Err(_) => {
            let _ = pmm::free_page(crate::addr::PhysAddr::new(new_phys));
            return Err(KernelError::InvalidArg);
        }
    };
    // Compare-and-swap (wave 13): two threads of one process may fault on the
    // same page at once. The loser frees its frame and returns as resolved:
    // its access retries on the winner's page.
    // SAFETY: `pte_ptr` is an aligned entry of a live table page.
    let slot = unsafe { &*(pte_ptr as *const core::sync::atomic::AtomicU64) };
    if slot
        .compare_exchange(pte, new_pte, core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire)
        .is_err()
    {
        let _ = pmm::free_page(crate::addr::PhysAddr::new(new_phys));
        return Ok(());
    }

    ARCH.flush_tlb_page(aligned_addr);

    Ok(())
}

/// Clear the DEMAND marker at `vaddr`, if there is one, and say whether there
/// was. For `sys_munmap`: a reserved page that was never touched holds no
/// frame, so `vmm::unmap_user_and_free` reports nothing freed for it, yet
/// `sys_alloc_demand` charged it (RFC-0049 M1: a demand reservation is
/// charged when it is made). Without this an untouched reservation stayed
/// charged until exec or exit.
pub fn clear_demand_marker(pt_phys: usize, vaddr: usize) -> bool {
    if vmm::write_would_enter_kernel_table(pt_phys, vaddr) {
        return false;
    }
    let Ok(pte_ptr) = vmm::walk(pt_phys, vaddr & !(PAGE_SIZE - 1), false) else {
        return false;
    };
    let pte = unsafe { core::ptr::read_volatile(pte_ptr) };
    if ARCH.pte_is_valid(pte) || !ARCH.pte_is_demand(pte) {
        return false;
    }
    unsafe { core::ptr::write_volatile(pte_ptr, ARCH.pte_empty()) };
    true
}
