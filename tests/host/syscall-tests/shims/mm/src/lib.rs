// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_mm`, used only by `tests/host/syscall-tests`.
//!
//! **Almost none of this is a stand-in.** `addr`, `pmm`, `vmm`, `cow` and
//! `demand` are the actual files from `crates/core/mm/src`, pulled in with
//! `#[path]` — the same trick `tests/host/mm-tests` already uses for `pmm.rs`
//! and `tests/host/cap-tests` uses for `cap.rs`. The mmap/munmap guards in
//! `handlers.rs` are tested against the kernel's own Sv39 walker, its own
//! bitmap allocator, and its own `PteFlags`, not against a model.
//!
//! **WHY a model was rejected.** A model page table keyed on
//! `(pt_phys, vaddr) -> (paddr, flags)` cannot represent the one thing the
//! munmap guard exists to prevent: user and kernel page tables *sharing*
//! their L1/L0 tables, so that zeroing a PTE reached through the user root
//! zeroes a PTE the kernel is walking. That sharing is the mechanism of the
//! historical board reset recorded at `handlers.rs:1247`. Testing the guard
//! against a structure that cannot express the hazard would make every
//! assertion a tautology.
//!
//! **What makes the real walker work on a host.** Everything in `vmm.rs`
//! and `pmm.rs` treats a physical address as a raw pointer (RAM is
//! identity-mapped before paging, and the kernel keeps it identity-mapped
//! after). So the only thing needed is for the "physical" addresses to be
//! memory this process actually owns: [`shim_reset`] hands `pmm::init` a
//! leaked, page-aligned host arena, exactly as `tests/host/mm-tests` does. A
//! first attempt at that suite passed a made-up `0x8000_0000` and died with
//! SIGSEGV before printing a result; the arena is not a workaround, it is
//! what makes the real allocator run instead of a version with the zeroing
//! removed.
//!
//! **What is faked, precisely:** `azos_arch::csr` — `sfence.vma` and
//! `satp` (see `tests/host/syscall-tests/shims/arch/src/lib.rs`). Those are TLB
//! and MMU-enable side effects with no host meaning. Nothing here reads
//! through a translation: every walk reads the PTE array directly, so a
//! missing TLB shootdown cannot make a wrong answer look right.

#[allow(dead_code)]
#[path = "../../../../../../crates/core/mm/src/addr.rs"]
pub mod addr;

#[allow(dead_code)]
#[path = "../../../../../../crates/core/mm/src/pmm.rs"]
pub mod pmm;

#[allow(dead_code)]
// Pulled in because `vmm.rs` uses it: the W^X boundary rule was carved out of
// `enforce_wx` so the enforcer and the verifier could not drift apart, and it
// is pure arithmetic over `PteFlags` with no page table behind it.
#[path = "../../../../../../crates/core/mm/src/wx.rs"]
pub mod wx;

#[path = "../../../../../../crates/core/mm/src/vmm.rs"]
pub mod vmm;

// `cow.rs` re-exports the refcount table from here; the real crate declares it
// in `lib.rs`, so a shim that pulls `cow.rs` in by path has to as well.
#[allow(dead_code)]
#[path = "../../../../../../crates/core/mm/src/cow_table.rs"]
mod cow_table;

#[allow(dead_code)]
#[path = "../../../../../../crates/core/mm/src/cow.rs"]
pub mod cow;

#[allow(dead_code)]
#[path = "../../../../../../crates/core/mm/src/demand.rs"]
pub mod demand;

// Wave 14 (DEMANDPAGE): `vmm.rs` sends unowned faults to the region pagers,
// and the region records are the pure seam they keep.
#[allow(dead_code)]
#[path = "../../../../../../crates/core/mm/src/region.rs"]
pub mod region;

#[allow(dead_code)]
#[path = "../../../../../../crates/core/mm/src/pager.rs"]
pub mod pager;

// Wave 14 (SPAWNCACHE): a verified image's kept frames, the real file
// (`image_cache.rs`, pulled into this suite, keeps and maps them).
#[path = "../../../../../../crates/core/mm/src/image_frames.rs"]
pub mod image_frames;

// Pulled only because `vmm::destroy_user_pagetable_skip_range` asks it which
// page backs the vDSO, so that teardown does not free a page shared with
// every other task. Nothing under test calls into it; it is here to keep the
// real `vmm.rs` compiling unmodified, which is the whole point.
#[allow(dead_code)]
#[path = "../../../../../../crates/core/mm/src/vdso.rs"]
pub mod vdso;

// ── Test-only control surface (not part of the real `azos_mm`) ─────────

/// Pages in the fake "RAM" arena. 64 MiB of usable pages plus slack for the
/// page tables that map them.
///
/// **The 64 MiB is not arbitrary.** It is
/// [`demand::MAX_DEMAND_ALLOC_BYTES`], the ceiling both `sys_mmap` and
/// `sys_alloc_demand` enforce. A `len > MAX` guard's mutant (`>` -> `>=`)
/// differs from the original at exactly one input — `len == MAX` — and the
/// only way to tell them apart is for `len == MAX` to *succeed*. That needs
/// an arena that can actually back 16,384 pages.
const ARENA_PAGES: usize = 16 * 1024 + 512;

/// Base of the leaked host arena the PMM manages. Page-aligned.
///
/// Leaked on purpose: the allocator stores the base in a `static`, and every
/// PTE in every page table points into it, so it must outlive every test.
pub fn shim_arena_base() -> usize {
    use azos_arch::mmu::PAGE_SIZE;
    use std::sync::OnceLock;
    static BASE: OnceLock<usize> = OnceLock::new();
    *BASE.get_or_init(|| {
        // One page of slack so the base can be rounded up to alignment.
        let raw = vec![0u8; ARENA_PAGES * PAGE_SIZE + PAGE_SIZE].leak();
        let addr = raw.as_ptr() as usize;
        (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
    })
}

/// Give every page back. Call at the start of every test that allocates.
///
/// This is the real `pmm::init`, not a bespoke reset path: the bitmap, the
/// free count and the managed range all go back to the state the kernel
/// starts in. Tests therefore cannot inherit each other's leaks — which is
/// the point, because "how many pages are still in use" is the assertion
/// that catches a missing unwind.
pub fn shim_reset() {
    use azos_arch::mmu::PAGE_SIZE;
    let base = shim_arena_base();
    // `kernel_end == mem_start` reserves nothing: the whole arena is free.
    pmm::init(base, ARENA_PAGES * PAGE_SIZE, base);
}

/// Pages currently handed out and not yet returned.
///
/// The real allocator's own counter, not a parallel tally — a shim that
/// counted separately could report "0 in use" while the bitmap said
/// otherwise, which is precisely the leak these tests look for.
pub fn shim_pages_in_use() -> usize {
    pmm::used_pages()
}
