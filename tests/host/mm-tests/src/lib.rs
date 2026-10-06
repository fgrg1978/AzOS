// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the physical page allocator, `crates/core/mm/src/pmm.rs`.
//!
//! **WHY.** `crates/core/mm` is 2209 lines with no test of any kind, and the
//! allocator is where a mistake is not an error but silent corruption: hand
//! the same physical page out twice and two subsystems write over each other,
//! with the symptom appearing arbitrarily far from the cause.
//!
//! The real module is pulled in with `#[path]`, and the `azos_arch` shim
//! re-exports the **real** Sv39 `mmu` module rather than stubbing it — so the
//! allocator computes against the kernel's own `PAGE_SIZE`, not a copy that
//! can drift.

#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/addr.rs"]
mod addr;

#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/pmm.rs"]
mod pmm;

// `wx.rs` was carved out of `vmm.rs` precisely so it could be pulled in here:
// it touches no page table and dereferences nothing, so the whole W^X boundary
// rule is reachable on the host. `vmm.rs` itself is not — it needs `csr`,
// raw physical pointers and a live MMU.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/wx.rs"]
mod wx;

// The COW refcount table, carved out of `cow.rs` so the host can link the real
// code (see its header). Its own tests are `cow_table_tests` below.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/cow_table.rs"]
mod cow_table;

// Per-task frame budget arithmetic (owner decision 102), carved out of
// `crates/core/sched/src/scheduler.rs`'s `mm_charge`/`mm_discharge`/
// `mm_reset_charge` so the host can link the real code. See its header for
// why the original functions cannot be pulled directly, and for what is (and
// is not yet) wired to production. Zero dependencies, so no shim is needed.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/budget.rs"]
mod budget;

// Wave 14 (DEMANDPAGE): the region records of demand-paged `mmap`. Pure
// (only `azos_arch_api::PAGE_SHIFT`), so the real file is tested as is; the
// fault path and table that use it are tested in syscall-tests.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/region.rs"]
mod region;

// Wave 15 (SLAB): the per-CPU magazine layer of the kernel heap. Depends on
// `core` only; its rows are in `slab_tests.rs`.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/slab.rs"]
mod slab;
#[cfg(test)]
mod slab_tests;

/// Every test that touches the `pmm` singleton or the frame window it
/// publishes takes this.
#[cfg(test)]
static PMM_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod alloc {
    use super::{addr::PhysAddr, pmm};
    use azos_arch::mmu::PAGE_SIZE;

    /// The allocator is a kernel singleton backed by one static bitmap, so
    /// these tests must not run concurrently. A lock rather than a documented
    /// `--test-threads=1`, for the reason fs-tests records: a flag lives in
    /// whoever remembers to type it.
    ///
    /// The lock is crate-wide (`PMM_SERIAL`), not this module's: `cow_table`
    /// indexes its counters by the frame window `pmm::init` publishes, so its
    /// tests share the singleton and must not overlap these.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        super::PMM_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    const PAGES: usize = 64;
    const SIZE: usize = PAGES * PAGE_SIZE;

    /// **A real, page-aligned arena, not a made-up base address.**
    ///
    /// `alloc_page` zeroes the page it returns by writing to its physical
    /// address (`pmm.rs:127`) -- correct on the kernel, where RAM is
    /// identity-mapped, and a wild pointer on a host. A first version passed
    /// `0x8000_0000` and the suite died with SIGSEGV before printing a single
    /// result. Backing the arena with memory the process actually owns is not
    /// a workaround: it is what makes the test exercise the real allocator
    /// instead of a version with the zeroing removed.
    ///
    /// Leaked on purpose. It must outlive every test, and the allocator holds
    /// its base in a static.
    fn arena_base() -> usize {
        use std::sync::OnceLock;
        static BASE: OnceLock<usize> = OnceLock::new();
        *BASE.get_or_init(|| {
            // One page of slack so the base can be rounded up to alignment.
            let raw = vec![0u8; SIZE + PAGE_SIZE].leak();
            let addr = raw.as_ptr() as usize;
            (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
        })
    }

    /// Reserve exactly the first `n` pages, leaving the rest free.
    fn init(reserved_pages: usize) {
        let base = arena_base();
        pmm::init(base, SIZE, base + reserved_pages * PAGE_SIZE);
    }

    /// Pages below `kernel_end` are the kernel's own image: handing one out
    /// overwrites running code. The accounting must match the reservation
    /// exactly, not approximately.
    #[test]
    fn init_reserves_exactly_the_kernel_pages() {
        let _g = serial();
        init(8);
        assert_eq!(pmm::total_pages(), PAGES);
        assert_eq!(pmm::used_pages(), 8, "8 pages reserved");
        assert_eq!(pmm::free_pages(), 56);
        assert_eq!(pmm::total_pages(), pmm::used_pages() + pmm::free_pages(),
                   "accounting must close");
    }

    /// **No page may be handed out twice.** This is the defect that does not
    /// announce itself: two owners write the same frame and the corruption
    /// surfaces somewhere else entirely. Drain the arena and check every
    /// address is distinct and in range.
    #[test]
    fn every_allocation_is_unique_and_in_range() {
        let _g = serial();
        init(4);
        let mut seen = std::collections::HashSet::new();
        let mut n = 0;
        while let Ok(p) = pmm::alloc_page() {
            let a = p.as_usize();
            assert!(seen.insert(a), "page {a:#x} handed out twice");
            assert!(a >= arena_base() + 4 * PAGE_SIZE, "allocated a reserved page {a:#x}");
            assert!(a < arena_base() + SIZE, "allocated past the arena: {a:#x}");
            assert_eq!(a % PAGE_SIZE, 0, "page {a:#x} is not page-aligned");
            n += 1;
        }
        assert_eq!(n, 60, "60 free pages should be allocatable, got {n}");
    }

    /// Exhaustion must return an error, not wrap round to a page already in
    /// use. The whole arena is drained first, so this exercises the real
    /// boundary rather than a contrived one.
    #[test]
    fn exhaustion_returns_an_error_rather_than_reusing() {
        let _g = serial();
        init(4);
        while pmm::alloc_page().is_ok() {}
        assert!(pmm::alloc_page().is_err(), "allocation past the end must fail");
        assert_eq!(pmm::free_pages(), 0);
    }

    /// A freed page must come back, and the accounting must return with it.
    /// A free that decrements nothing leaks the arena one page per cycle.
    #[test]
    fn a_freed_page_is_reusable_and_the_count_returns() {
        let _g = serial();
        init(4);
        let before = pmm::free_pages();
        let p = pmm::alloc_page().expect("arena has free pages");
        assert_eq!(pmm::free_pages(), before - 1);
        pmm::free_page(p).expect("a page just allocated must be freeable");
        assert_eq!(pmm::free_pages(), before, "free did not return the page");
        let again = pmm::alloc_page().expect("the freed page must be reusable");
        assert_eq!(again.as_usize(), p.as_usize(), "first-fit must return it");
    }

    /// **A range taken as one block must be all free pages of the arena.** The
    /// kernel heap is handed to `kheap` whole; `reserve_range` skips pages
    /// already in use and stops at the arena's end without a word, which is
    /// how the boot stack ended up inside the heap.
    #[test]
    fn range_is_free_refuses_a_used_page_and_the_arena_edges() {
        let _g = serial();
        init(4);
        let base = arena_base();
        assert!(pmm::range_is_free(base + 4 * PAGE_SIZE, 60 * PAGE_SIZE), "the free tail");
        assert!(!pmm::range_is_free(base + 3 * PAGE_SIZE, 2 * PAGE_SIZE),
                "starts on a reserved page");
        assert!(!pmm::range_is_free(base + 4 * PAGE_SIZE, 61 * PAGE_SIZE),
                "one page past the arena");
        assert!(!pmm::range_is_free(base - PAGE_SIZE, PAGE_SIZE), "below the arena");
        pmm::reserve_range(base + 40 * PAGE_SIZE, PAGE_SIZE);
        assert!(!pmm::range_is_free(base + 4 * PAGE_SIZE, 60 * PAGE_SIZE),
                "a used page in the middle");
        assert!(pmm::range_is_free(base + 41 * PAGE_SIZE, 23 * PAGE_SIZE), "the run after it");
    }

    /// **Freeing outside the arena must be refused.** The address comes from
    /// callers that computed it; accepting one flips a bit for a page the
    /// allocator does not own, which shows up later as a double allocation
    /// with no trace of the cause.
    #[test]
    fn freeing_outside_the_arena_is_refused() {
        let _g = serial();
        init(4);
        assert!(pmm::free_page(PhysAddr::new(arena_base() - PAGE_SIZE)).is_err(),
                "below the arena");
        assert!(pmm::free_page(PhysAddr::new(arena_base() + SIZE)).is_err(),
                "past the arena");
        assert!(pmm::free_page(PhysAddr::new(arena_base() + SIZE + 0x100000)).is_err(),
                "far past the arena");
    }

    /// `reserve_range` must mark every page the range touches, including a
    /// partial final page. Rounding down instead of up leaves the last page
    /// allocatable while a device or a table already lives in it.
    #[test]
    fn reserve_range_rounds_up_to_cover_a_partial_page() {
        let _g = serial();
        init(4);
        let before = pmm::free_pages();
        // One byte into the second page of the range: two pages are touched.
        pmm::reserve_range(arena_base() + 10 * PAGE_SIZE, PAGE_SIZE + 1);
        assert_eq!(pmm::free_pages(), before - 2,
                   "a range spilling into a second page must reserve both");
    }

    /// **The zeroing guarantee must survive old content.** `alloc_page`
    /// zeroes the page it returns; this only proves something if the page
    /// has actually carried non-zero bytes before. A fresh arena starts at
    /// zero already, so an allocate-and-check test would pass even with the
    /// `write_bytes` call deleted. Write a full page of `0xAA`, free it, and
    /// force it to come back via first-fit before checking.
    #[test]
    fn a_reallocated_page_is_zeroed_not_the_old_content() {
        let _g = serial();
        init(4);
        let p = pmm::alloc_page().expect("arena has free pages");
        unsafe {
            core::ptr::write_bytes(p.as_usize() as *mut u8, 0xAA, PAGE_SIZE);
        }
        pmm::free_page(p).expect("a page just allocated must be freeable");
        let again = pmm::alloc_page().expect("the freed page must be reusable");
        assert_eq!(again.as_usize(), p.as_usize(),
                   "first-fit must return the page we just poisoned, not a fresh one");
        let bytes = unsafe {
            core::slice::from_raw_parts(again.as_usize() as *const u8, PAGE_SIZE)
        };
        assert!(bytes.iter().all(|&b| b == 0),
                "reallocated page still carries the old 0xAA content — zeroing did not happen \
                 (or happened before the old owner's last write was visible)");
    }

    /// U09-11: `alloc_page_uninit` is `alloc_page` MINUS the zero-fill —
    /// same bitmap, same accounting, same reused-address behaviour under
    /// first-fit, but the bytes it hands back are whatever was there
    /// before. Proven the same way the zeroing guarantee above is proven:
    /// poison the page, free it, force it back via first-fit, and check
    /// the poison SURVIVED — the inverse assertion of
    /// `a_reallocated_page_is_zeroed_not_the_old_content`. If a future
    /// change made `alloc_page_uninit` zero after all (e.g. by accidentally
    /// calling `alloc_page` internally instead of `alloc_page_raw`), this
    /// is what would catch it — the whole point of the function is to NOT
    /// pay for that zero on the COW-break path.
    #[test]
    fn alloc_page_uninit_does_not_zero_old_content() {
        let _g = serial();
        init(4);
        let p = pmm::alloc_page().expect("arena has free pages");
        unsafe {
            core::ptr::write_bytes(p.as_usize() as *mut u8, 0xAA, PAGE_SIZE);
        }
        pmm::free_page(p).expect("a page just allocated must be freeable");
        let again = unsafe { pmm::alloc_page_uninit() }
            .expect("the freed page must be reusable");
        assert_eq!(again.as_usize(), p.as_usize(),
                   "first-fit must return the page we just poisoned, not a fresh one");
        let bytes = unsafe {
            core::slice::from_raw_parts(again.as_usize() as *const u8, PAGE_SIZE)
        };
        assert!(bytes.iter().all(|&b| b == 0xAA),
                "alloc_page_uninit zeroed the page — it is supposed to skip exactly that cost");
    }

    /// Accounting (`free_pages`/bitmap) must be identical to `alloc_page`'s
    /// — `alloc_page_uninit` is only supposed to skip the zero, nothing
    /// about which page gets claimed or how the count moves.
    #[test]
    fn alloc_page_uninit_accounting_matches_alloc_page() {
        let _g = serial();
        init(4);
        let before = pmm::free_pages();
        let p = unsafe { pmm::alloc_page_uninit() }.expect("arena has free pages");
        assert_eq!(pmm::free_pages(), before - 1);
        pmm::free_page(p).expect("an uninit-allocated page must be freeable");
        assert_eq!(pmm::free_pages(), before, "free did not return the page");
    }

    /// A second arena, exactly two bitmap words (128 pages) with nothing
    /// reserved, used only by the scan-hint test below. `alloc_page`
    /// remembers which bitmap word it last allocated from and resumes
    /// scanning there — this needs an arena big enough for that cursor to
    /// actually leave word 0.
    const PAGES2: usize = 128;
    const SIZE2: usize = PAGES2 * PAGE_SIZE;

    fn arena2_base() -> usize {
        use std::sync::OnceLock;
        static BASE2: OnceLock<usize> = OnceLock::new();
        *BASE2.get_or_init(|| {
            let raw = vec![0u8; SIZE2 + PAGE_SIZE].leak();
            let addr = raw.as_ptr() as usize;
            (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
        })
    }

    /// **The scan-hint canary.** `alloc_page` resumes its bitmap scan from
    /// the word the previous allocation was satisfied from, instead of
    /// word 0 every time. A hint that only looks *forward* from that
    /// cursor — and forgets to come back for words below it — reports
    /// `OutOfMemory` even though a page is free, silently, since nothing
    /// about the call's signature changes.
    ///
    /// The bug only shows up under two conditions at once: the cursor must
    /// have actually left word 0 (which needs a full word's worth of
    /// allocations first), and the only free page left must be below that
    /// cursor. A test that allocates two pages from a fresh arena and frees
    /// one would pass against a completely broken hint — the cursor never
    /// leaves word 0 in that scenario, so "look below the cursor" is never
    /// exercised. This test forces both conditions: drain the whole
    /// two-word arena (pushing the cursor into the second word), then free
    /// only the very first page ever handed out (word 0), leaving it as
    /// the sole free page, strictly below the cursor.
    #[test]
    fn a_page_freed_below_the_scan_hint_is_still_found() {
        let _g = serial();
        let base = arena2_base();
        // No reservation: kernel_end == mem_start, all 128 pages start free.
        pmm::init(base, SIZE2, base);
        assert_eq!(pmm::free_pages(), PAGES2);

        // Drain the whole arena. Pages 64-127 (the second bitmap word) are
        // allocated last, so the scan cursor ends up pointing past word 0.
        let mut all = Vec::with_capacity(PAGES2);
        while let Ok(p) = pmm::alloc_page() {
            all.push(p);
        }
        assert_eq!(all.len(), PAGES2, "every page in a fresh arena must be allocatable");
        assert_eq!(pmm::free_pages(), 0);

        let first = all[0];
        assert_eq!(first.as_usize(), base,
                   "first-fit from a fresh arena must hand out the very first page");

        // The only free page in the arena is now word 0 — below wherever
        // the cursor landed after draining word 1 last.
        pmm::free_page(first).expect("a page just allocated must be freeable");
        assert_eq!(pmm::free_pages(), 1);

        let reused = pmm::alloc_page()
            .expect("the freed page below the scan cursor must still be found, not OutOfMemory");
        assert_eq!(reused.as_usize(), first.as_usize(),
                   "the only free page must be the one recovered");
        assert_eq!(pmm::free_pages(), 0);
    }

    /// **DTB audit, consumer side.** `init` computes `kernel_end - mem_start`
    /// to size the reservation; a `mem_start` greater than `kernel_end` — a
    /// DTB `/memory` node claiming RAM starts after the kernel's own image,
    /// impossible on real hardware — used to underflow that subtraction. On
    /// the kernel's real release profile (`overflow-checks = true`,
    /// `panic = "abort"`, reproduced by this crate's `[profile.release]`)
    /// that is a panic, and an abort panic is a board reset with nothing on
    /// the console to explain why. `init` must instead return `false` and
    /// leave the allocator in its all-zero, pre-init state.
    ///
    /// Canary, verified by hand (not left in the tree): reverting `init`'s
    /// guard to the bare `let reserved_pages = (kernel_end - mem_start ...)`
    /// line makes `cargo test --release` here abort with
    /// "attempt to subtract with overflow" instead of failing this
    /// assertion — the panic message itself becomes the failure, which is
    /// exactly the undiagnosed-abort class this test exists to close off.
    #[test]
    fn init_refuses_a_mem_start_past_kernel_end_instead_of_underflowing() {
        let _g = serial();
        // Establish a known-initialized state first, so a refusal that
        // merely NO-OPS (leaves the previous successful init's counts
        // standing) is caught rather than mistaken for "already zero".
        init(4);
        assert_eq!(pmm::total_pages(), PAGES);
        assert!(pmm::free_pages() > 0);

        let base = arena_base();
        let hostile_kernel_end = base - PAGE_SIZE; // one page BELOW mem_start
        let accepted = pmm::init(base, SIZE, hostile_kernel_end);

        assert!(!accepted, "a mem_start past kernel_end must be refused, not accepted");
        assert_eq!(pmm::total_pages(), 0, "refusal must reset total_pages, not leave the prior init standing");
        assert_eq!(pmm::free_pages(), 0);
        assert!(pmm::alloc_page().is_err(), "a refused init must not hand out any page");
    }

    /// The boundary itself must still be accepted: `mem_start == kernel_end`
    /// is the `kernel_end == mem_start` case every other test in this file
    /// already relies on (nothing reserved), so the guard must be `>`, not
    /// `>=`.
    #[test]
    fn init_accepts_mem_start_exactly_equal_to_kernel_end() {
        let _g = serial();
        let base = arena_base();
        let accepted = pmm::init(base, SIZE, base);
        assert!(accepted, "mem_start == kernel_end is the legitimate zero-reservation case");
        assert_eq!(pmm::total_pages(), PAGES);
        assert_eq!(pmm::free_pages(), PAGES, "nothing reserved when kernel_end == mem_start");
    }

    // ── `alloc_contiguous` (RFC-0049 M0; the legacy virtio-mmio queue) ─────

    /// Drain the 64-page arena (nothing reserved), then free `holes`. Returns
    /// the arena base. Every test below starts from a fully used bitmap so the
    /// only free pages are the ones it names.
    fn drained_with_holes(holes: &[usize]) -> usize {
        let base = arena_base();
        pmm::init(base, SIZE, base);
        while pmm::alloc_page().is_ok() {}
        assert_eq!(pmm::free_pages(), 0);
        for &h in holes {
            pmm::free_page(PhysAddr::new(base + h * PAGE_SIZE)).expect("a drained page frees");
        }
        base
    }

    /// **The premise `virtq_init` used to rely on is false.** Two consecutive
    /// `alloc_page` calls after a low page is freed return that low page and
    /// then one 30 pages above it. The legacy queue took the first as its base
    /// and wrote the used ring into the frame after it, which here is a page
    /// another owner still holds.
    #[test]
    fn consecutive_alloc_page_calls_are_not_physically_contiguous() {
        let _g = serial();
        let base = drained_with_holes(&[10, 40, 41]);
        let a = pmm::alloc_page().expect("hole").as_usize();
        let b = pmm::alloc_page().expect("hole").as_usize();
        assert_eq!(a, base + 10 * PAGE_SIZE);
        assert_ne!(b, a + PAGE_SIZE, "the second page is not the one after the first");
    }

    /// The run search skips a single hole and takes the first run long enough.
    ///
    /// **Canary.** In `alloc_contiguous`, delete the `run_len = 0` that a used
    /// page sets: the search counts page 10 and page 40 as a run of two and
    /// returns page 10, so this fails.
    #[test]
    fn alloc_contiguous_takes_the_run_not_the_lone_hole() {
        let _g = serial();
        let base = drained_with_holes(&[10, 40, 41]);
        let p = pmm::alloc_contiguous(2).expect("pages 40-41 are a run of two").as_usize();
        assert_eq!(p, base + 40 * PAGE_SIZE, "got page {}", (p - base) / PAGE_SIZE);
        assert_eq!(pmm::free_pages(), 1, "exactly two pages claimed");
        assert_eq!(pmm::alloc_page().expect("page 10 is still free").as_usize(),
                   base + 10 * PAGE_SIZE);
    }

    /// Enough free pages but no run: refused, and nothing claimed.
    #[test]
    fn alloc_contiguous_refuses_isolated_pages_and_claims_nothing() {
        let _g = serial();
        let _ = drained_with_holes(&[10, 20, 30]);
        assert!(pmm::alloc_contiguous(2).is_err(), "three isolated pages are not a run of two");
        assert_eq!(pmm::free_pages(), 3, "a refused run search must not claim pages");
        assert!(pmm::alloc_contiguous(0).is_err(), "zero pages is an argument error");
        assert_eq!(pmm::free_pages(), 3);
    }

    /// The last bitmap word's bits past `total_pages` read as free. A run must
    /// never extend into them.
    ///
    /// **Canary.** Bound the scan by the whole last word
    /// (`while page < (total + 63) / 64 * 64`): the free tail 30..40 plus the
    /// phantom page 40 make a run of 11 and the call succeeds.
    #[test]
    fn alloc_contiguous_never_counts_phantom_tail_bits() {
        let _g = serial();
        let base = arena_base();
        pmm::init(base, 40 * PAGE_SIZE, base); // 40 pages: the word's tail is phantom
        for _ in 0..30 {
            pmm::alloc_page().expect("fresh arena");
        }
        pmm::free_page(PhysAddr::new(base + 5 * PAGE_SIZE)).expect("allocated");
        assert_eq!(pmm::free_pages(), 11, "precondition: page 5 plus the run 30..40");
        assert!(pmm::alloc_contiguous(11).is_err(), "a run of 11 exists only with phantom bits");
        assert_eq!(pmm::free_pages(), 11);
        assert_eq!(pmm::alloc_contiguous(10).expect("the real tail run").as_usize(),
                   base + 30 * PAGE_SIZE);
    }

    // ── `alloc_contiguous_aligned` (Kconfig LOCKED_HUGE_LEAVES) ────────────

    /// The first page index of the arena whose address is `align`-aligned.
    fn first_aligned(base: usize, align: usize) -> usize {
        (((base + align - 1) & !(align - 1)) - base) / PAGE_SIZE
    }

    /// The run starts on the alignment, not at the first free page: a level-1
    /// leaf's physical base must be a multiple of the leaf size.
    ///
    /// **Canary.** Start the candidate scan at index 0 with a step of one page
    /// (an unaligned first fit): the call returns page `f + 1` and this fails.
    #[test]
    fn alloc_contiguous_aligned_starts_on_the_alignment() {
        let _g = serial();
        let align = 8 * PAGE_SIZE;
        let f = first_aligned(arena_base(), align);
        assert!(f + 12 <= PAGES, "precondition: the arena holds the run");
        let holes: Vec<usize> = (f + 1..f + 12).collect();
        let base = drained_with_holes(&holes);
        let p = pmm::alloc_contiguous_aligned(4, align).expect("pages f+8..f+12 are an aligned run").as_usize();
        assert_eq!(p % align, 0, "physical base {p:#x} is not {align:#x}-aligned");
        assert_eq!(p, base + (f + 8) * PAGE_SIZE, "got page {}", (p - base) / PAGE_SIZE);
        assert_eq!(pmm::free_pages(), 11 - 4, "exactly four pages claimed");
    }

    /// Free pages, even a long run, but no aligned run of the size: refused,
    /// and nothing claimed. Bad arguments are refused too.
    #[test]
    fn alloc_contiguous_aligned_refuses_unaligned_runs_and_claims_nothing() {
        let _g = serial();
        let align = 8 * PAGE_SIZE;
        let f = first_aligned(arena_base(), align);
        let holes: Vec<usize> = (f + 1..f + 8).collect();
        let _ = drained_with_holes(&holes);
        assert!(pmm::alloc_contiguous_aligned(4, align).is_err(), "seven free pages, none aligned");
        assert_eq!(pmm::free_pages(), 7, "a refused search must not claim pages");
        assert!(pmm::alloc_contiguous_aligned(0, align).is_err());
        assert!(pmm::alloc_contiguous_aligned(1, 3 * PAGE_SIZE).is_err(), "not a power of two");
        assert!(pmm::alloc_contiguous_aligned(1, PAGE_SIZE / 2).is_err(), "below one page");
        assert_eq!(pmm::free_pages(), 7);
    }

    /// Every page of a recycled run comes back zeroed, not just the first.
    ///
    /// **Canary.** Delete the `zero_new_page` loop at the end of
    /// `alloc_contiguous`: the poison survives and this fails.
    #[test]
    fn alloc_contiguous_zeroes_every_page_of_a_recycled_run() {
        let _g = serial();
        init(4);
        let p = pmm::alloc_contiguous(3).expect("fresh arena").as_usize();
        unsafe { core::ptr::write_bytes(p as *mut u8, 0xAA, 3 * PAGE_SIZE) };
        for i in 0..3 {
            pmm::free_page(PhysAddr::new(p + i * PAGE_SIZE)).expect("each page frees alone");
        }
        let q = pmm::alloc_contiguous(3).expect("the same run is free again").as_usize();
        assert_eq!(q, p, "precondition: first fit returns the poisoned run");
        let bytes = unsafe { core::slice::from_raw_parts(q as *const u8, 3 * PAGE_SIZE) };
        assert!(bytes.iter().all(|&b| b == 0), "a recycled run carries the old bytes");
    }
}

/// The W^X boundary rule (`crates/core/mm/src/wx.rs`).
///
/// **WHY.** `enforce_wx` computed these boundaries inline and returned `()`.
/// Nothing read a PTE back, so "W^X enforced" in the boot log was a `kprintln`
/// placed after the call, not a result — every way the enforcement could fail
/// (a megapage the split skipped on OOM, a page `remap_range` passed over
/// because it was not a valid 4 KiB leaf) printed the same green line. The
/// arithmetic now lives here so the verifier reads the SAME ranges instead of
/// re-deriving them, and these tests hold the rule that both of them obey.
#[cfg(test)]
mod wx_rule {
    use super::wx::{self, PageVerdict, WxReport};
    use azos_arch_api::{PagePerms, PAGE_SIZE};

    /// A kernel image laid out like the real linker script: sections in
    /// order, each starting where the last ended, none page-aligned by
    /// accident. Offsets chosen so `.text`/`.rodata` share a page and
    /// `.rodata`/`.data` share a different one — the only interesting part
    /// of the rule.
    const BASE: usize = 0x8020_0000;
    const TEXT_START: usize = BASE;
    const TEXT_END: usize = BASE + 0x3_0800;      // mid-page
    const RO_START: usize = TEXT_END;
    const RO_END: usize = BASE + 0x4_0400;        // mid-page
    const DATA_START: usize = RO_END;
    const KERNEL_END: usize = BASE + 0x5_0000;    // page-aligned

    fn plan() -> [wx::WxRange; 3] {
        wx::plan(TEXT_START, TEXT_END, RO_START, RO_END, DATA_START, KERNEL_END)
    }

    /// The tie-break the original comment promised: a page holding the end of
    /// `.text` and the start of `.rodata` keeps X, because dropping it would
    /// fault the code in that page's first half.
    #[test]
    fn a_page_shared_by_text_and_rodata_stays_executable() {
        let [text, rodata, _] = plan();
        let shared = TEXT_END & !(PAGE_SIZE - 1);
        assert!(
            shared < text.end,
            ".text must extend past {shared:#x} to cover the shared page",
        );
        assert!(
            rodata.start > shared,
            ".rodata must start after the shared page, not reclaim it: \
             starts {:#x}, shared page {shared:#x}", rodata.start,
        );
        assert!(text.flags.exec);
    }

    /// And the same tie-break one section down.
    #[test]
    fn a_page_shared_by_rodata_and_data_stays_read_only() {
        let [_, rodata, data] = plan();
        let shared = RO_END & !(PAGE_SIZE - 1);
        assert!(shared < rodata.end, ".rodata must cover the shared page");
        assert!(
            data.start >= rodata.end,
            ".data must not reclaim the page .rodata still needs",
        );
        assert!(!rodata.flags.write);
    }

    /// No range the planner emits may be writable and executable — the whole
    /// point, held against the plan itself rather than against a page table.
    #[test]
    fn no_planned_range_is_both_writable_and_executable() {
        for r in plan() {
            assert!(
                !wx::is_write_exec(r.flags),
                "{} was planned W+X: {:?}", r.name, r.flags,
            );
        }
    }

    /// Each section gets the permission its name implies, and nothing more.
    #[test]
    fn each_section_gets_exactly_the_permission_it_needs() {
        let [text, rodata, data] = plan();
        assert!(text.flags.exec && !text.flags.write);
        assert!(!rodata.flags.exec && !rodata.flags.write);
        assert!(data.flags.write && !data.flags.exec);
        // `.rodata`'s flags used to be spelled out as a literal
        // `VALID | READ | ACCESSED`. Same permissions, and this pins that the
        // rename to a named constant did not change them.
        assert_eq!(rodata.flags, PagePerms::KERNEL_RO);
    }

    /// The ranges must tile the image without overlapping, or a later
    /// `remap_range` silently undoes an earlier one somewhere other than the
    /// two boundary pages where that is intended.
    #[test]
    fn the_three_ranges_tile_the_image_without_gaps() {
        let [text, rodata, data] = plan();
        assert_eq!(text.start, TEXT_START & !(PAGE_SIZE - 1));
        assert_eq!(rodata.start, text.end, "gap or overlap between .text and .rodata");
        assert_eq!(data.start, rodata.end, "gap or overlap between .rodata and .data");
        assert_eq!(data.end, KERNEL_END, "the plan must reach the end of the image");
    }

    /// A section that is entirely inside its predecessor's last page produces
    /// an EMPTY range, not a backwards one. `enforce_wx` skips empty ranges;
    /// a range with `end < start` would make its loop run to overflow.
    #[test]
    fn a_section_swallowed_by_the_previous_page_is_empty_not_backwards() {
        // `.text` must end MID-page for this to bite: its range then rounds
        // up over the whole page, and a 16-byte `.rodata` living in that same
        // page has nothing left to claim. (A first version of this test had
        // `.text` ending exactly on a page boundary, where `.rodata` does get
        // its own page — it failed, correctly, and said so.)
        let t_end = BASE + 0x800;
        let p = wx::plan(BASE, t_end, t_end, t_end + 16, t_end + 16, BASE + 0x2000);
        let rodata = p[1];
        assert!(rodata.is_empty(), "expected an empty range, got {rodata:?}");
        assert_eq!(rodata.pages(), 0);
        assert!(
            rodata.start <= rodata.end,
            "a range must never run backwards: enforce_wx would loop past it \
             and verify_wx would walk to overflow — {rodata:?}",
        );
        // And the section after it still lands where it should.
        assert_eq!(p[2].start, BASE + 0x1000, ".data must start on the next whole page");
        assert_eq!(p[2].end, BASE + 0x2000);
    }

    /// `is_write_exec` is the security predicate; an invalid PTE is not a
    /// violation no matter which permission bits are left in it.
    #[test]
    fn only_a_valid_mapping_can_violate_wx() {
        assert!(wx::is_write_exec(PagePerms::KERNEL_RWX));
        assert!(!wx::is_write_exec(PagePerms::KERNEL_RX));
        assert!(!wx::is_write_exec(PagePerms::KERNEL_RW));
        assert!(!wx::is_write_exec(PagePerms::KERNEL_RO));
    }

    /// A W+X page is reported as a violation even when it is what the plan
    /// asked for — the predicate is about the hardware, not about intent.
    /// Nothing should ever plan W+X (pinned above), so this is the belt to
    /// that test's braces.
    #[test]
    fn write_exec_outranks_a_flag_match() {
        assert_eq!(
            wx::judge(PagePerms::KERNEL_RWX, PagePerms::KERNEL_RWX),
            PageVerdict::WriteExec,
            "matching a W+X plan is still a W+X page",
        );
    }

    /// Flags that differ from the plan but are not W+X are a separate,
    /// weaker finding: the enforcer and the page table disagree.
    #[test]
    fn a_mismatch_that_is_not_write_exec_is_reported_apart() {
        assert_eq!(wx::judge(PagePerms::KERNEL_RX, PagePerms::KERNEL_RX), PageVerdict::Ok);
        assert_eq!(
            wx::judge(PagePerms::KERNEL_RX, PagePerms::KERNEL_RO),
            PageVerdict::WrongFlags,
            "a .text page that lost X is not a W^X violation, and is still wrong",
        );
    }

    /// `is_clean` and `has_wx_violation` are different questions and the
    /// report must not conflate them: an unmapped page inside the image is a
    /// surprise worth failing on, but it is not a security violation.
    #[test]
    fn a_clean_report_and_a_safe_report_are_not_the_same_question() {
        let mut r = WxReport::default();
        r.record(0x1000, PageVerdict::Ok);
        assert!(r.is_clean() && !r.has_wx_violation());

        let mut unmapped = WxReport::default();
        unmapped.record(0x2000, PageVerdict::Unmapped);
        assert!(!unmapped.is_clean(), "an unmapped image page must not read as clean");
        assert!(
            !unmapped.has_wx_violation(),
            "and it must not be reported as a security violation either",
        );

        let mut wx_bad = WxReport::default();
        wx_bad.record(0x3000, PageVerdict::WriteExec);
        assert!(!wx_bad.is_clean() && wx_bad.has_wx_violation());
    }

    /// An unsplit megapage IS a security violation: `remap_range` would write
    /// 4 KiB flags into a 2 MiB leaf and retag the whole span with whichever
    /// section wrote last.
    #[test]
    fn an_unsplit_megapage_counts_as_a_violation_not_a_surprise() {
        let mut r = WxReport::default();
        r.record(0x4000, PageVerdict::UnsplitMegapage);
        assert!(
            r.has_wx_violation(),
            "a 2 MiB leaf under the kernel image means the enforcement did not happen",
        );
    }

    /// The first bad address is kept so the boot line names a page a person
    /// can go look at, and later failures do not overwrite it.
    #[test]
    fn the_report_remembers_the_first_bad_page_not_the_last() {
        let mut r = WxReport::default();
        r.record(0x1000, PageVerdict::Ok);
        r.record(0x2000, PageVerdict::WriteExec);
        r.record(0x3000, PageVerdict::WrongFlags);
        assert_eq!(r.first_bad, 0x2000);
        assert_eq!(r.checked, 3);
        assert_eq!(r.write_exec, 1);
        assert_eq!(r.wrong_flags, 1);
    }
}

/// EXEC outside the kernel image (`crates/core/mm/src/wx.rs`, RAM half).
///
/// **WHY.** `vmm::init` maps every page of RAM `KERNEL_RWX` — it has to, since
/// it runs before `enable_paging()` and the kernel is executing out of that
/// memory. `enforce_wx` then tightened only the image, so on a 128 MiB board
/// ~121 MiB stayed writable AND executable in the kernel's own page table:
/// the heap, every frame `pmm` hands out, every task stack. Measured, not
/// estimated: disabling the sweep reports 60 megapages + 311 pages still
/// executable, first at 0x80000000.
///
/// The sweep itself needs a live page table, so what is testable here is the
/// decision it applies to each leaf — which is the part that must not widen a
/// mapping or drop a bit it was not asked to drop.
#[cfg(test)]
mod nx_outside_image {
    use super::wx::{self, RamExecReport};
    use azos_arch_api::{PagePerms, PAGE_SIZE};

    const MEGA: usize = 2 * 1024 * 1024;

    /// EXEC is the only permission that comes off. A sweep that also cleared,
    /// say, `dirty` would make every stripped page fault on its next write on
    /// a core with software-managed A/D — which is the configuration this
    /// kernel targets (`KERNEL_RW` pre-sets A+D for exactly that reason).
    #[test]
    fn stripping_exec_changes_exec_and_nothing_else() {
        let before = PagePerms::KERNEL_RWX;
        let after = wx::without_exec(before).expect("RWX is executable");
        assert_eq!(after, PagePerms { exec: false, ..before });
        assert_eq!(after, PagePerms::KERNEL_RW, "RWX minus X must BE the RW mapping");
        assert_eq!(before.read, after.read, "the sweep must not touch read");
        assert_eq!(before.write, after.write, "the sweep must not touch write");
        assert_eq!(before.user, after.user, "the sweep must not touch user");
        assert_eq!(before.cache, after.cache, "the sweep must not touch cache");
        assert_eq!(before.accessed, after.accessed, "the sweep must not touch accessed");
        assert_eq!(before.dirty, after.dirty, "the sweep must not touch dirty");
    }

    /// A mapping with nothing to strip returns `None`, so the caller counts
    /// mappings it CHANGED rather than addresses it visited. The difference
    /// matters: the second number reads as a measurement and is not one.
    #[test]
    fn a_non_executable_mapping_is_left_alone() {
        assert_eq!(wx::without_exec(PagePerms::KERNEL_RW), None);
        assert_eq!(wx::without_exec(PagePerms::KERNEL_RO), None);
    }

    /// Executable is executable whether or not it is also writable. The image
    /// half of W^X asks "W AND X"; out here every page is data, so the
    /// question is just "X at all" — a KERNEL_RX page in the heap would be
    /// W^X-clean and still has no business existing.
    #[test]
    fn read_execute_counts_as_executable_out_here() {
        assert!(wx::is_exec(PagePerms::KERNEL_RX));
        assert!(!wx::is_write_exec(PagePerms::KERNEL_RX), "and it is NOT a W^X violation");
        assert_eq!(wx::without_exec(PagePerms::KERNEL_RX), Some(PagePerms::KERNEL_RO));
    }

    /// Megapages and pages are counted apart, and the byte total is what gets
    /// printed. Summing the two entry counts would produce a number with no
    /// meaning — one L1 leaf covers 512 times the address space of one L0.
    #[test]
    fn the_report_totals_bytes_not_entries() {
        let mut r = RamExecReport::default();
        for i in 0..60 { r.record_mega(0x8000_0000 + i * MEGA); }
        for i in 0..311 { r.record_page(0x8600_0000 + i * PAGE_SIZE); }
        assert_eq!(r.megapages, 60);
        assert_eq!(r.pages, 311);
        // The figure the boot line prints, and the one measured by disabling
        // the sweep on a real 128 MiB boot.
        assert_eq!(r.bytes() >> 20, 121, "60 megapages + 311 pages is 121 MiB");
        assert!(!r.is_empty());
    }

    /// The first executable address is kept so the failure line names a page
    /// somebody can go look at, and a later find does not overwrite it.
    #[test]
    fn the_report_remembers_the_first_address_across_both_units() {
        let mut r = RamExecReport::default();
        r.record_mega(0x8000_0000);
        r.record_page(0x8010_0000);
        r.record_mega(0x8020_0000);
        assert_eq!(r.first, 0x8000_0000);

        // And a page seen before any megapage sets it just the same.
        let mut p = RamExecReport::default();
        p.record_page(0x8140_0000);
        p.record_mega(0x8000_0000);
        assert_eq!(p.first, 0x8140_0000, "first SEEN, not lowest");
    }

    /// An empty report is the success condition the boot line keys on, so it
    /// must not be confusable with "nothing was walked".
    #[test]
    fn an_empty_report_means_nothing_executable_was_found() {
        let r = RamExecReport::default();
        assert!(r.is_empty());
        assert_eq!(r.bytes(), 0);
    }
}

/// The COW refcount table (`cow_table.rs`), the real code.
///
/// **WHY A MODEL.** The table is now an array indexed by frame number. The
/// strongest test is still the boring one: run the same operations through the
/// real table and through an obviously correct `Vec`, and require identical
/// results at every step. Two frames sharing a counter, an off-by-one in the
/// index, or a wrong initial count each break the equality within a few
/// thousand steps.
///
/// **WHAT IT REPLACED.** A 512-entry table scanned from index 0. It cost a fork
/// of an M-page process M²/2 comparisons and refused any fork past 512 shared
/// pages, so `a_process_past_the_old_512_page_ceiling_can_fork` is the test that
/// could not have passed before.
#[cfg(test)]
mod cow_table_tests {
    use super::cow_table::{page_addref, page_decref, page_getref};
    use super::pmm;
    use azos_arch::mmu::PAGE_SIZE;
    use azos_common::error::KernelError;

    const BASE: usize = 0x8000_0000;
    /// Managed frames in the test window. Well past the old 512-entry cap.
    const FRAMES: usize = 4096;

    /// The window the table indexes by. Holds the crate-wide pmm lock for the
    /// whole test.
    fn window() -> std::sync::MutexGuard<'static, ()> {
        let g = super::PMM_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        pmm::init(BASE, FRAMES * PAGE_SIZE, BASE);
        g
    }

    fn frame(n: usize) -> usize { BASE + n * PAGE_SIZE }

    /// Drop every frame in `0..n` from the table, whatever its count.
    fn drain(n: usize) {
        for i in 0..n {
            while page_getref(frame(i)) != 0 {
                page_decref(frame(i));
            }
        }
    }

    /// The semantics as originally written, as a `Vec`.
    #[derive(Default)]
    struct Model(Vec<(usize, u16)>);
    impl Model {
        fn addref(&mut self, p: usize) {
            match self.0.iter_mut().find(|e| e.0 == p) {
                Some(e) => e.1 = e.1.saturating_add(1),
                None => self.0.push((p, 2)),
            }
        }
        fn decref(&mut self, p: usize) -> bool {
            match self.0.iter().position(|e| e.0 == p) {
                Some(i) if self.0[i].1 <= 1 => { self.0.remove(i); true }
                Some(i) => { self.0[i].1 -= 1; false }
                None => true, // untracked: the caller is the sole owner
            }
        }
        fn getref(&self, p: usize) -> u16 {
            self.0.iter().find(|e| e.0 == p).map_or(0, |e| e.1)
        }
    }

    #[test]
    fn matches_a_plain_vec_over_thousands_of_mixed_operations() {
        let _g = window();
        const PAGES: usize = 48;
        drain(PAGES);
        let mut m = Model::default();
        // xorshift: deterministic, so a failure names its step.
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        for step in 0..6000 {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            let p = frame((s >> 8) as usize % PAGES);
            match (s >> 40) % 3 {
                0 => { page_addref(p).unwrap(); m.addref(p); }
                1 => assert_eq!(page_decref(p), m.decref(p), "decref({p:#x}) at step {step}"),
                _ => {}
            }
            assert_eq!(page_getref(p), m.getref(p), "getref({p:#x}) at step {step}");
        }
        for i in 0..PAGES {
            assert_eq!(page_getref(frame(i)), m.getref(frame(i)), "final state of page {i}");
        }
        drain(PAGES);
    }

    /// A fork, a second fork, then both children exiting, in address order, the
    /// shape every real caller has. Nothing may be lost or miscounted.
    #[test]
    fn a_fork_shaped_walk_counts_every_page() {
        let _g = window();
        const N: usize = 200;
        drain(N);
        for _ in 0..3 {
            for i in 0..N { page_addref(frame(i)).unwrap(); }
        }
        // First fork takes a page to 2, later ones add one each: 2 + 1 + 1.
        for i in 0..N { assert_eq!(page_getref(frame(i)), 4, "page {i}"); }
        for round in 0..3 {
            for i in 0..N {
                assert!(!page_decref(frame(i)), "page {i} freed early in round {round}");
            }
        }
        // 4 -> 1 after three drops; the last holder's decref frees it.
        for i in 0..N { assert_eq!(page_getref(frame(i)), 1, "page {i}"); }
        for i in 0..N { assert!(page_decref(frame(i)), "page {i} not freed by its last holder"); }
        for i in 0..N { assert_eq!(page_getref(frame(i)), 0, "page {i} left a count behind"); }
    }

    /// **The test the old table could not pass.** It refused the 513th distinct
    /// shared page with `CapacityFull`, so `fork` of any process past ~2 MiB
    /// failed. Here a process of `FRAMES - 1` shared pages forks and every page
    /// is counted.
    #[test]
    fn a_process_past_the_old_512_page_ceiling_can_fork() {
        let _g = window();
        let n = FRAMES - 1;
        assert!(n > 512, "the test must exceed the old ceiling to mean anything");
        drain(n);
        for i in 0..n {
            assert_eq!(page_addref(frame(i)), Ok(()), "page {i} refused: a ceiling is back");
        }
        for i in 0..n { assert_eq!(page_getref(frame(i)), 2, "page {i}"); }
        for i in 0..n { assert!(!page_decref(frame(i)), "page {i}"); }
        for i in 0..n { assert!(page_decref(frame(i)), "page {i}"); }
        for i in 0..n { assert_eq!(page_getref(frame(i)), 0, "page {i}"); }
    }

    /// Two different frames must never share a counter, and the first and last
    /// frames of the window are both real.
    #[test]
    fn distinct_frames_have_distinct_counters_at_the_window_edges() {
        let _g = window();
        let (first, last) = (frame(0), frame(FRAMES - 1));
        drain(FRAMES);
        page_addref(first).unwrap();
        assert_eq!(page_getref(first), 2);
        assert_eq!(page_getref(last), 0, "the last frame aliased the first");
        assert_eq!(page_getref(frame(1)), 0, "an adjacent frame aliased");
        page_addref(last).unwrap();
        page_addref(last).unwrap();
        assert_eq!(page_getref(last), 3);
        assert_eq!(page_getref(first), 2, "counting the last frame moved the first");
        drain(FRAMES);
    }

    /// Anything that is not a managed, page-aligned frame is refused, and asking
    /// after one answers "untracked, caller owns it" without touching a counter.
    #[test]
    fn a_frame_outside_the_window_or_unaligned_is_refused() {
        let _g = window();
        drain(FRAMES);
        for bad in [BASE - PAGE_SIZE, frame(FRAMES), frame(FRAMES) + PAGE_SIZE, BASE + 1, BASE + PAGE_SIZE - 1, 0] {
            assert_eq!(page_addref(bad), Err(KernelError::InvalidArg), "{bad:#x} was accepted");
            assert_eq!(page_getref(bad), 0, "{bad:#x}");
            assert!(page_decref(bad), "{bad:#x}: not ours to count, so the caller is the sole owner");
        }
        // And the refused calls counted nothing anywhere.
        for i in [0, 1, FRAMES - 1] { assert_eq!(page_getref(frame(i)), 0, "frame {i}"); }
    }

    /// A count that reaches `u16::MAX` stays there rather than wrapping to 0
    /// (which would read as "untracked" and free a shared frame).
    #[test]
    fn a_count_saturates_and_never_wraps_to_untracked() {
        let _g = window();
        let p = frame(7);
        drain(8);
        for _ in 0..(u16::MAX as usize + 50) { page_addref(p).unwrap(); }
        assert_eq!(page_getref(p), u16::MAX, "saturation lost");
        assert!(!page_decref(p), "a saturated page is still shared");
        assert_eq!(page_getref(p), u16::MAX - 1);
        drain(8);
    }
}

/// The per-task frame budget (`budget.rs`, carved out of `scheduler.rs`'s
/// `mm_charge`/`mm_discharge`/`mm_reset_charge`).
///
/// **WHY THIS CLOSES THE OPEN FINDING.** Scan unit 3 finding 3 (owner decision
/// 102) shipped with the positive half proven in `tests/host/syscall-tests`
/// (`mmap_guards.rs`) and the refusal proven at the QEMU gate
/// (`mem-quota-canary`, `tools/ci_check.sh`) — but neither exercises the REAL
/// `mm_charge`/`mm_discharge` in `scheduler.rs`. `syscall-tests`' own shim says
/// so explicitly: it is "State, not behaviour... SEMANTICS are copied
/// deliberately", proving the WIRING in `handlers.rs`, not this decision. The
/// diagnosis that a per-test arena was missing (the mistake that cost three
/// withdrawn attempts on the write-guard finding) does not apply here: `mm_charge`
/// takes no allocator lock and touches no PMM arena at all, it is three
/// integers behind a task-table index. What was actually missing was a SEAM —
/// the arithmetic was inlined on `TASKS[idx]` inside a file that cannot be
/// `#[path]`-pulled. `budget.rs` is that seam, tested here as the real code
/// `tests/host/mm-tests` links (see its own header for what still has to happen in
/// `scheduler.rs` to make this the code that ships).
#[cfg(test)]
mod budget_tests {
    use super::budget::PageBudget;

    /// `pages == 0` must succeed and touch nothing — not even the peak. A
    /// caller (`sys_mmap` with a zero-length request) must not see a spurious
    /// high-water mark from a no-op call.
    #[test]
    fn charging_zero_pages_is_a_free_no_op() {
        let mut b = PageBudget::new();
        b.set_limit(4);
        assert!(b.charge(0));
        assert_eq!(b.used(), 0);
        assert_eq!(b.peak(), 0);
    }

    /// `limit == 0` is "no limit" — the state every task without a `mem_pages`
    /// row in its topology gets. A charge that would refuse under any nonzero
    /// limit must still succeed here.
    #[test]
    fn a_zero_limit_means_unlimited() {
        let mut b = PageBudget::new();
        assert!(b.charge(1_000_000));
        assert_eq!(b.used(), 1_000_000);
    }

    /// The positive half, reproduced at the host: a task that stays within its
    /// budget is charged exactly what it asked for, and the peak tracks the
    /// running total, not the last charge.
    #[test]
    fn charging_within_the_limit_succeeds_and_tracks_the_peak() {
        let mut b = PageBudget::new();
        b.set_limit(16);
        assert!(b.charge(10));
        assert_eq!(b.used(), 10);
        assert_eq!(b.peak(), 10);
        assert!(b.charge(6));
        assert_eq!(b.used(), 16);
        assert_eq!(b.peak(), 16);
    }

    /// **The runaway-`brk` proof, at the host.** A task that keeps charging
    /// one page at a time (`sys_brk_impl`'s shape) is granted pages up to
    /// EXACTLY the budget and refused — with NOTHING charged — the moment it
    /// would go over. This is the host-level twin of the QEMU
    /// `mem-quota-canary` row (`tools/ci_check.sh`, budget dropped to 16,
    /// `abitest` asks for 256 and is granted 16): same ceiling, same
    /// one-page-at-a-time shape, no QEMU boot needed to see it fail. A quota
    /// wired to refuse everything fails the first assertion; one wired to
    /// refuse nothing never reaches the last one.
    #[test]
    fn a_runaway_charge_one_page_at_a_time_is_refused_exactly_at_the_ceiling() {
        let mut b = PageBudget::new();
        b.set_limit(16);
        for i in 0..16 {
            assert!(b.charge(1), "page {i} of 16 must be granted");
        }
        assert_eq!(b.used(), 16, "the budget must bind exactly, not early");
        assert!(!b.charge(1), "the 17th page must be refused");
        assert_eq!(b.used(), 16, "a refused charge must charge NOTHING");
        // And the refusal is not a one-shot fluke: the task stays refused, it
        // does not silently get let through on a later attempt.
        assert!(!b.charge(1));
        assert_eq!(b.used(), 16);
    }

    /// `sys_mmap`'s shape: the whole request charged at once, because a
    /// caller that asked for 64 pages cannot use 40. A request that would
    /// exceed the budget must be refused WHOLESALE, not partially charged.
    #[test]
    fn a_whole_request_over_budget_is_refused_wholesale_not_partially_charged() {
        let mut b = PageBudget::new();
        b.set_limit(16);
        assert!(b.charge(10));
        assert!(!b.charge(10), "10 more would be 20, over a budget of 16");
        assert_eq!(b.used(), 10, "the refused 10-page request must not land any of its pages");
    }

    /// Over-discharge must floor at 0, not wrap to `u32::MAX` and disable the
    /// budget silently — the dangerous direction, since it refuses a task
    /// memory it is entitled to.
    #[test]
    fn discharging_more_than_used_floors_at_zero_instead_of_wrapping() {
        let mut b = PageBudget::new();
        b.charge(3);
        b.discharge(10);
        assert_eq!(b.used(), 0);
        // And the budget is still usable afterward — a wrap would have left
        // `used` near `u32::MAX`, refusing everything from here on.
        b.set_limit(4);
        assert!(b.charge(4));
    }

    /// `reset` (called on `exec_user` and on exit) must clear BOTH `used` and
    /// `peak` — the address space either one described is gone. Clearing only
    /// `used` would leave a stale peak attributed to whatever runs in that
    /// task slot next.
    #[test]
    fn reset_clears_both_used_and_the_peak() {
        let mut b = PageBudget::new();
        b.set_limit(0);
        b.charge(50);
        assert_eq!(b.peak(), 50);
        b.reset();
        assert_eq!(b.used(), 0);
        assert_eq!(b.peak(), 0, "a stale peak would misattribute the next task's cost");
    }

    /// **This workspace's overflow rule, held on the real code.** `panic =
    /// "abort"` + `overflow-checks = true` means a plain `+` here is a board
    /// reset, not a caught error (see `note_stalled_tick`,
    /// `crates/core/actuation/src/watchdog.rs`, for the established precedent).
    /// `charge` must saturate instead.
    ///
    /// Canary verified by hand (not left in the tree): replacing
    /// `self.used.saturating_add(pages)` in `budget.rs` with a plain `+`
    /// makes this test abort the whole `cargo test --release` process with
    /// "attempt to add with overflow" instead of failing this assertion —
    /// exactly the undiagnosed-abort class `mm-tests`' own `pmm::init` canary
    /// (see `init_refuses_a_mem_start_past_kernel_end_instead_of_underflowing`)
    /// exists to close off.
    #[test]
    fn charging_near_u32_max_saturates_instead_of_overflowing() {
        let mut b = PageBudget::new();
        b.set_limit(0); // unlimited: saturation, not the ceiling, is under test
        assert!(b.charge(u32::MAX - 1));
        assert!(b.charge(10), "would overflow u32 with a plain `+`");
        assert_eq!(b.used(), u32::MAX);
        assert_eq!(b.peak(), u32::MAX);
    }

    /// The discharge side of the same rule: `saturating_sub`, not `-`.
    #[test]
    fn discharging_past_zero_saturates_instead_of_underflowing() {
        let mut b = PageBudget::new();
        b.set_limit(0);
        assert!(b.charge(1));
        b.discharge(u32::MAX); // would underflow u32 with a plain `-`
        assert_eq!(b.used(), 0);
    }
}

/// The COW-break counter (`cow_table.rs`): visibility for the frames a COW
/// break adds to a task's footprint, WITHOUT charging them against the quota.
///
/// **WHY UNCHARGED.** See `crates/core/mm/src/cow_table.rs`'s note on
/// `note_cow_break`:
/// `handle_cow_fault` has four failure paths, three are the calling program's
/// own bug, and the store-page-fault arm kills the task on any of them because
/// there is no signal/upcall ABI to hand a refusal back. Charging (with
/// refusal) would add an indistinguishable fifth kill for a task that broke a
/// page it was entitled to. This counter is the alternative: it moves once,
/// never backward except by an explicit reset, and never refuses anything.
#[cfg(test)]
mod cow_break_tests {
    use super::cow_table::{cow_break_frames, note_cow_break, shim_set_cow_breaks};

    /// Every test in this module touches the same global counter, so they
    /// must not interleave — same rule as `PMM_SERIAL`, a separate lock
    /// because this counter shares no state with the PMM arena or `REFS`.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static COW_BREAK_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
        COW_BREAK_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn note_cow_break_increments_the_visible_count() {
        let _g = serial();
        shim_set_cow_breaks(0);
        note_cow_break();
        note_cow_break();
        note_cow_break();
        assert_eq!(cow_break_frames(), 3);
    }

    /// **The saturation canary.** A plain `AtomicU32::fetch_add` wraps on
    /// overflow — atomics are not covered by `overflow-checks`, unlike every
    /// plain arithmetic op in this workspace's release profile — so a naive
    /// implementation of this counter would silently read `0` ("no COW
    /// breaks") right when it should read "over four billion", the opposite
    /// of what a diagnostic counter must do under pressure.
    ///
    /// This test was RED against exactly that naive implementation before
    /// `note_cow_break` was written to load-saturate-store instead of
    /// `fetch_add`ing (see the RED transcript in the task report).
    #[test]
    fn a_saturated_count_never_wraps_to_zero() {
        let _g = serial();
        shim_set_cow_breaks(u32::MAX);
        note_cow_break();
        assert_eq!(cow_break_frames(), u32::MAX,
            "a wrapped counter reads as \"no COW breaks\" — the wrong direction for a diagnostic");
        shim_set_cow_breaks(0); // leave the shared counter clean for other tests
    }
}

/// Wave 14 (DEMANDPAGE): `region.rs`, the bookkeeping the demand-fault path
/// trusts to say whether an address is reserved and with what permission.
/// Mutation canaries (run by hand, see the front report): `joins` always
/// false turns the fold rows red; dropping the straddle check in
/// `remove_range` turns `a_cut_needs_a_slot` red (index out of bounds);
/// `find` answering the first region whatever `va` turns the lookup rows red.
#[cfg(test)]
mod region_tests {
    use super::region::{Region, RegionError, RegionSet};
    const P: usize = 4096;

    fn anon(a: usize, b: usize, w: bool) -> Region {
        Region::anon(a * P, b * P, w)
    }

    fn spans<const N: usize>(s: &RegionSet<N>) -> Vec<(usize, usize, bool)> {
        s.as_slice().iter().map(|r| (r.start / P, r.end / P, r.write)).collect()
    }

    #[test]
    fn lookup_answers_inside_and_only_inside() {
        let mut s = RegionSet::<4>::new();
        s.insert(anon(10, 20, true)).unwrap();
        s.insert(anon(30, 31, false)).unwrap();
        assert!(s.find(9 * P + P - 1).is_none());
        assert_eq!(s.find(10 * P).map(|r| r.write), Some(true));
        assert_eq!(s.find(20 * P - 1).map(|r| r.write), Some(true));
        assert!(s.find(20 * P).is_none(), "end is exclusive");
        assert_eq!(s.find(30 * P + 5).map(|r| r.write), Some(false));
        assert!(s.find(31 * P).is_none());
        assert_eq!(s.reserved_pages(), 11);
    }

    #[test]
    fn adjacent_compatible_ranges_fold() {
        let mut s = RegionSet::<2>::new();
        s.insert(anon(10, 11, true)).unwrap();
        s.insert(anon(11, 12, true)).unwrap();
        s.insert(anon(9, 10, true)).unwrap();
        assert_eq!(spans(&s), vec![(9, 12, true)]);
        // Filling the gap between two records folds all three into one.
        s.insert(anon(14, 15, true)).unwrap();
        s.insert(anon(12, 14, true)).unwrap();
        assert_eq!(spans(&s), vec![(9, 15, true)]);
        // Different permission: its own record.
        s.insert(anon(15, 16, false)).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s.insert(anon(20, 21, true)), Err(RegionError::Full));
        assert_eq!(s.len(), 2, "a refusal changes nothing");
    }

    #[test]
    fn overlap_and_bad_ranges_are_refused() {
        let mut s = RegionSet::<4>::new();
        s.insert(anon(10, 20, true)).unwrap();
        assert_eq!(s.insert(anon(19, 21, true)), Err(RegionError::Overlap));
        assert_eq!(s.insert(anon(5, 11, true)), Err(RegionError::Overlap));
        assert_eq!(s.insert(anon(12, 13, false)), Err(RegionError::Overlap));
        assert_eq!(s.insert(Region::anon(P, P, true)), Err(RegionError::Invalid));
        assert_eq!(s.insert(Region::anon(P + 1, 2 * P, true)), Err(RegionError::Invalid));
        assert_eq!(spans(&s), vec![(10, 20, true)]);
    }

    #[test]
    fn remove_range_trims_cuts_and_counts() {
        let mut s = RegionSet::<4>::new();
        s.insert(anon(10, 20, true)).unwrap();
        s.insert(anon(30, 40, false)).unwrap();
        assert_eq!(s.remove_range(12 * P, 14 * P), Ok(2));
        assert_eq!(spans(&s), vec![(10, 12, true), (14, 20, true), (30, 40, false)]);
        assert_eq!(s.remove_range(18 * P, 35 * P), Ok(2 + 5));
        assert_eq!(spans(&s), vec![(10, 12, true), (14, 18, true), (35, 40, false)]);
        assert_eq!(s.remove_range(0, 100 * P), Ok(2 + 4 + 5));
        assert!(s.is_empty());
        assert_eq!(s.remove_range(0, P), Ok(0));
    }

    #[test]
    fn a_cut_needs_a_slot() {
        let mut s = RegionSet::<2>::new();
        s.insert(anon(10, 20, true)).unwrap();
        s.insert(anon(30, 40, true)).unwrap();
        assert_eq!(s.remove_range(12 * P, 14 * P), Err(RegionError::Full));
        assert_eq!(spans(&s), vec![(10, 20, true), (30, 40, true)], "nothing changed");
        // Trimming an end needs no slot.
        assert_eq!(s.remove_range(10 * P, 12 * P), Ok(2));
        assert_eq!(s.remove_range(38 * P, 50 * P), Ok(2));
    }

    #[test]
    fn protect_splits_then_folds_back() {
        let mut s = RegionSet::<4>::new();
        s.insert(anon(10, 20, true)).unwrap();
        s.protect_range(12 * P, 14 * P, false).unwrap();
        assert_eq!(spans(&s), vec![(10, 12, true), (12, 14, false), (14, 20, true)]);
        assert_eq!(s.find(13 * P).map(|r| r.write), Some(false));
        s.protect_range(0, 100 * P, true).unwrap();
        assert_eq!(spans(&s), vec![(10, 20, true)], "same permission again: one record");
        // Only region pages change; a hole stays a hole.
        s.protect_range(5 * P, 11 * P, false).unwrap();
        assert_eq!(spans(&s), vec![(10, 11, false), (11, 20, true)]);
        assert_eq!(s.reserved_pages(), 10);
    }

    #[test]
    fn protect_refuses_when_its_cuts_do_not_fit() {
        let mut s = RegionSet::<2>::new();
        s.insert(anon(10, 20, true)).unwrap();
        assert_eq!(s.protect_range(12 * P, 14 * P, false), Err(RegionError::Full));
        assert_eq!(spans(&s), vec![(10, 20, true)]);
        s.protect_range(10 * P, 14 * P, false).unwrap();
        assert_eq!(spans(&s), vec![(10, 14, false), (14, 20, true)]);
    }

    #[test]
    fn a_copy_is_the_same_reservation() {
        let mut a = RegionSet::<4>::new();
        a.insert(anon(10, 20, true)).unwrap();
        a.insert(anon(30, 31, false)).unwrap();
        let mut b = RegionSet::<4>::new();
        b.copy_from(&a);
        assert_eq!(spans(&a), spans(&b));
        a.remove_range(10 * P, 20 * P).unwrap();
        assert_eq!(b.reserved_pages(), 11, "independent after the copy");
    }

    #[test]
    fn page_index_follows_the_cut() {
        let mut s = RegionSet::<4>::new();
        s.insert(anon(10, 20, true)).unwrap();
        s.remove_range(10 * P, 13 * P).unwrap();
        let r = *s.find(15 * P).unwrap();
        assert_eq!(r.page_index(15 * P), 5, "object offset survives the trim");
    }
}
