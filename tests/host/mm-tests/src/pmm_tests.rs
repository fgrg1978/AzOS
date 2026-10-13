// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the page allocator's API, `crates/core/mm/src/pmm.rs`, the
//! real file over a leaked host arena. (`buddy_tests.rs` has the engine under
//! it.) The allocator is a kernel singleton, so these hold `PMM_SERIAL`.
//!
//! The per-hart caches are off here: they are keyed by the hart, which a
//! host test does not have (`pmm::enable_cpu_caches` is a no-op off target).
//! Their logic is `buddy_tests.rs`'s `Pcp` rows; the wiring is the riscv64
//! boot's.

use super::{addr::PhysAddr, frame::*, pmm};
use azos_arch::mmu::PAGE_SIZE;
use azos_common::error::KernelError;

const MEGA: usize = 2 * 1024 * 1024;
/// Frames of the main arena: 4 MiB.
const PAGES: usize = 1024;
const SIZE: usize = PAGES * PAGE_SIZE;
/// Frames the descriptor array takes at its start: 32 B per frame.
const ARRAY: usize = PAGES * 32 / PAGE_SIZE;

fn serial() -> std::sync::MutexGuard<'static, ()> {
    super::PMM_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// A real, 2 MiB-aligned arena of `bytes`, leaked: the allocator zeroes and
/// writes descriptors through the physical addresses it is given, which on a
/// host must be memory this process owns.
fn leak_arena(bytes: usize) -> usize {
    let raw = vec![0u8; bytes + MEGA].leak();
    (raw.as_ptr() as usize + MEGA - 1) & !(MEGA - 1)
}

fn arena_base() -> usize {
    use std::sync::OnceLock;
    static BASE: OnceLock<usize> = OnceLock::new();
    *BASE.get_or_init(|| leak_arena(SIZE))
}

/// Reserve the first `n` pages (the kernel image); the descriptor array
/// follows them.
fn init(reserved_pages: usize) {
    let base = arena_base();
    assert!(pmm::init(base, SIZE, base + reserved_pages * PAGE_SIZE));
}

fn first_free(reserved_pages: usize) -> usize {
    arena_base() + (reserved_pages + ARRAY) * PAGE_SIZE
}

/// Take every page, then give back `holes` (arena page indexes).
fn drained_with_holes(holes: &[usize]) -> usize {
    init(0);
    let base = arena_base();
    while pmm::alloc_page().is_ok() {}
    assert_eq!(pmm::free_pages(), 0);
    for &h in holes {
        pmm::free_page(PhysAddr::new(base + h * PAGE_SIZE)).expect("a drained page frees");
    }
    base
}

/// The image and the descriptor array are reserved, and the accounting
/// closes exactly, not approximately.
#[test]
fn init_reserves_exactly_the_kernel_pages_and_the_descriptor_array() {
    let _g = serial();
    init(8);
    assert_eq!(pmm::total_pages(), PAGES);
    assert_eq!(pmm::used_pages(), 8 + ARRAY);
    assert_eq!(pmm::free_pages(), PAGES - 8 - ARRAY);
    assert_eq!(pmm::total_pages(), pmm::used_pages() + pmm::free_pages());
    assert_eq!(pmm::frame_state(arena_base()), Some(F_RESERVED), "the image");
    assert_eq!(pmm::frame_state(arena_base() + (8 + ARRAY - 1) * PAGE_SIZE), Some(F_RESERVED),
               "the array's last page");
    assert_eq!(pmm::frame_state(first_free(8)), Some(F_FREE));
}

/// **The array covers ALL the RAM it is told about, not Kconfig `RAM_SIZE`.**
/// A span past that ceiling is described in full, and its last frame is
/// reachable.
#[test]
fn the_descriptors_cover_all_the_ram_not_the_old_ceiling() {
    let _g = serial();
    let pages = (azos_limits::RAM_SIZE + 64) * 1024 * 1024 / PAGE_SIZE;
    let base = leak_arena(pages * PAGE_SIZE);
    assert!(pmm::init(base, pages * PAGE_SIZE, base));
    assert_eq!(pmm::total_pages(), pages, "every frame described");
    let array = table_bytes(pages) / PAGE_SIZE;
    assert_eq!(pmm::free_pages(), pages - array);
    let last = base + (pages - 1) * PAGE_SIZE;
    assert_eq!(pmm::frame_index(last), Some(pages - 1));
    // Drain without zeroing 300 MiB: the highest frame must come out.
    let mut top = 0;
    let mut n = 0;
    while let Some(p) = pmm::alloc(0, pmm::ANY_COLOUR, pmm::ANY_NODE) {
        top = top.max(p.phys());
        n += 1;
    }
    assert_eq!(n, pages - array);
    assert_eq!(top, last, "the last frame of RAM is allocatable");
    assert_eq!(pmm::free_pages(), 0);
}

/// **No page may be handed out twice.** Two owners writing one frame corrupt
/// something far from the cause.
#[test]
fn every_allocation_is_unique_and_in_range() {
    let _g = serial();
    init(4);
    let mut seen = std::collections::HashSet::new();
    while let Ok(p) = pmm::alloc_page() {
        let a = p.as_usize();
        assert!(seen.insert(a), "page {a:#x} handed out twice");
        assert!(a >= first_free(4), "allocated a reserved page {a:#x}");
        assert!(a < arena_base() + SIZE, "allocated past the arena: {a:#x}");
        assert_eq!(a % PAGE_SIZE, 0);
    }
    assert_eq!(seen.len(), PAGES - 4 - ARRAY);
}

#[test]
fn exhaustion_returns_an_error_rather_than_reusing() {
    let _g = serial();
    init(4);
    while pmm::alloc_page().is_ok() {}
    assert!(pmm::alloc_page().is_err());
    assert_eq!(pmm::free_pages(), 0);
    assert!(pmm::alloc(0, pmm::ANY_COLOUR, pmm::ANY_NODE).is_none());
}

#[test]
fn a_freed_page_is_reusable_and_the_count_returns() {
    let _g = serial();
    init(4);
    let before = pmm::free_pages();
    let p = pmm::alloc_page().expect("arena has free pages");
    assert_eq!(pmm::free_pages(), before - 1);
    assert_eq!(pmm::frame_state(p.as_usize()), Some(F_ALLOCATED));
    pmm::free_page(p).expect("a page just allocated must be freeable");
    assert_eq!(pmm::free_pages(), before, "free did not return the page");
    assert_eq!(pmm::frame_state(p.as_usize()), Some(F_FREE));
}

/// A range taken as one block must be all free pages of the arena.
#[test]
fn range_is_free_refuses_a_used_page_and_the_arena_edges() {
    let _g = serial();
    init(4);
    let base = arena_base();
    let f = 4 + ARRAY; // first free page index
    let n = PAGES - f;
    assert!(pmm::range_is_free(base + f * PAGE_SIZE, n * PAGE_SIZE), "the free tail");
    assert!(!pmm::range_is_free(base + (f - 1) * PAGE_SIZE, 2 * PAGE_SIZE), "starts on a reserved page");
    assert!(!pmm::range_is_free(base + f * PAGE_SIZE, (n + 1) * PAGE_SIZE), "one page past the arena");
    assert!(!pmm::range_is_free(base - PAGE_SIZE, PAGE_SIZE), "below the arena");
    pmm::reserve_range(base + 40 * PAGE_SIZE, PAGE_SIZE);
    assert!(!pmm::range_is_free(base + f * PAGE_SIZE, n * PAGE_SIZE), "a used page in the middle");
    assert!(pmm::range_is_free(base + 41 * PAGE_SIZE, 23 * PAGE_SIZE), "the run after it");
    assert!(pmm::range_is_free(base + PAGES * PAGE_SIZE, 0), "an empty range at the end");
}

/// Freeing outside the arena must be refused: accepting an address the
/// allocator does not own shows up later as a double allocation.
#[test]
fn freeing_outside_the_arena_is_refused() {
    let _g = serial();
    init(4);
    let base = arena_base();
    for a in [base - PAGE_SIZE, base + SIZE, base + SIZE + 0x10_0000] {
        assert_eq!(pmm::free_page(PhysAddr::new(a)), Err(KernelError::InvalidArg), "{a:#x}");
    }
    assert_eq!(pmm::free_page(PhysAddr::new(first_free(4) + 1)), Err(KernelError::NotAligned));
}

/// A page freed twice is refused the second time, before it can be on the
/// lists twice and handed to two owners.
#[test]
fn a_double_free_is_refused_and_changes_nothing() {
    let _g = serial();
    init(4);
    let p = pmm::alloc_page().unwrap();
    pmm::free_page(p).unwrap();
    let free = pmm::free_pages();
    assert_eq!(pmm::free_page(p), Err(KernelError::DoubleFree));
    assert_eq!(pmm::free_pages(), free);
    // A frame that was never allocated is free, so also a double free.
    assert_eq!(pmm::free_page(PhysAddr::new(first_free(4) + 100 * PAGE_SIZE)),
               Err(KernelError::DoubleFree));
    assert_eq!(pmm::free_pages(), free);
}

/// A pinned frame is not freed; a reserved one is (the DMA canary reserves
/// frames and frees them); the modifiers need an allocated frame.
#[test]
fn pinned_frames_are_not_freed_and_reserved_frames_are() {
    let _g = serial();
    init(4);
    let p = pmm::alloc_page().unwrap().as_usize();
    assert!(pmm::set_frame_modifier(p, F_PINNED, true));
    assert_eq!(pmm::frame_state(p), Some(F_ALLOCATED | F_PINNED));
    assert_eq!(pmm::free_page(PhysAddr::new(p)), Err(KernelError::InvalidArg));
    assert!(pmm::set_frame_modifier(p, F_PINNED, false));
    assert!(pmm::set_frame_modifier(p, F_COMPRESSED | F_SWAPPED, true));
    pmm::free_page(PhysAddr::new(p)).expect("modifiers other than pinned do not stop a free");
    assert_eq!(pmm::frame_state(p), Some(F_FREE));
    assert!(!pmm::set_frame_modifier(p, F_PINNED, true), "a free frame cannot be pinned");
    assert!(!pmm::set_frame_modifier(p, F_ALLOCATED, true), "not a modifier");

    let free = pmm::free_pages();
    let r = first_free(4) + 200 * PAGE_SIZE;
    pmm::reserve_range(r, PAGE_SIZE);
    assert_eq!(pmm::free_pages(), free - 1);
    pmm::free_page(PhysAddr::new(r)).expect("a reserved frame goes back to the lists");
    assert_eq!(pmm::free_pages(), free);
}

/// `reserve_range` marks every page the range touches, a partial final page
/// included.
#[test]
fn reserve_range_rounds_up_to_cover_a_partial_page() {
    let _g = serial();
    init(4);
    let before = pmm::free_pages();
    pmm::reserve_range(arena_base() + 100 * PAGE_SIZE, PAGE_SIZE + 1);
    assert_eq!(pmm::free_pages(), before - 2);
}

/// A page already in use inside the range is not counted again, and a range
/// running past the arena stops at its last page.
#[test]
fn reserve_range_counts_only_newly_reserved_pages() {
    let _g = serial();
    init(4);
    let base = arena_base();
    let before = pmm::free_pages();
    pmm::reserve_range(base + 400 * PAGE_SIZE, PAGE_SIZE);
    pmm::reserve_range(base + 390 * PAGE_SIZE, 31 * PAGE_SIZE);
    assert_eq!(pmm::free_pages(), before - 31, "pages 390..=420, page 400 once");
    pmm::reserve_range(base + (PAGES - 3) * PAGE_SIZE, 10 * PAGE_SIZE);
    assert_eq!(pmm::free_pages(), before - 34, "the last three only: the arena ends");
    assert!(!pmm::range_is_free(base + (PAGES - 1) * PAGE_SIZE, PAGE_SIZE), "the last page");
    // What is reserved is never handed out.
    while let Ok(p) = pmm::alloc_page() {
        let i = (p.as_usize() - base) / PAGE_SIZE;
        assert!(!(390..=420).contains(&i) && i < PAGES - 3, "page {i} was reserved");
    }
}

/// The first free page moves past what is taken.
#[test]
fn next_free_addr_is_the_first_free_frame() {
    let _g = serial();
    init(4);
    assert_eq!(pmm::next_free_addr(), first_free(4));
    pmm::reserve_range(first_free(4), 3 * PAGE_SIZE);
    assert_eq!(pmm::next_free_addr(), first_free(4) + 3 * PAGE_SIZE);
    let _ = drained_with_holes(&[]);
    assert_eq!(pmm::next_free_addr(), arena_base() + SIZE, "none free: the end of RAM");
}

/// **The zeroing guarantee must survive old content.** Only meaningful if the
/// page has carried non-zero bytes: poison, free, take it back.
#[test]
fn a_reallocated_page_is_zeroed_not_the_old_content() {
    let _g = serial();
    let p = drained_with_holes(&[20]) + 20 * PAGE_SIZE;
    unsafe { core::ptr::write_bytes(p as *mut u8, 0xAA, PAGE_SIZE) };
    // `drained_with_holes` freed page 20 after the drain zeroed it; re-poison
    // and cycle it once more.
    let again = pmm::alloc_page().expect("the one free page");
    assert_eq!(again.as_usize(), p);
    unsafe { core::ptr::write_bytes(p as *mut u8, 0xAA, PAGE_SIZE) };
    pmm::free_page(again).unwrap();
    let again = pmm::alloc_page().expect("and again");
    assert_eq!(again.as_usize(), p);
    let bytes = unsafe { core::slice::from_raw_parts(p as *const u8, PAGE_SIZE) };
    assert!(bytes.iter().all(|&b| b == 0), "the old 0xAA content survived the allocation");
}

/// `alloc_page_uninit` is `alloc_page` minus the zero-fill: the poison
/// survives (the inverse of the row above).
#[test]
fn alloc_page_uninit_does_not_zero_old_content() {
    let _g = serial();
    let p = drained_with_holes(&[20]) + 20 * PAGE_SIZE;
    unsafe { core::ptr::write_bytes(p as *mut u8, 0xAA, PAGE_SIZE) };
    let again = unsafe { pmm::alloc_page_uninit() }.expect("the one free page");
    assert_eq!(again.as_usize(), p);
    let bytes = unsafe { core::slice::from_raw_parts(p as *const u8, PAGE_SIZE) };
    assert!(bytes.iter().all(|&b| b == 0xAA), "alloc_page_uninit zeroed the page");
    assert_eq!(pmm::free_pages(), 0);
}

/// **DTB audit, consumer side.** A `mem_start` past `kernel_end` used to
/// underflow `kernel_end - mem_start` into a panic, which under the kernel's
/// abort profile is a board reset with nothing on the console. `init` must
/// return `false` and leave the all-zero state, not the previous one.
#[test]
fn init_refuses_a_mem_start_past_kernel_end_instead_of_underflowing() {
    let _g = serial();
    init(4);
    assert_eq!(pmm::total_pages(), PAGES);
    let base = arena_base();
    assert!(!pmm::init(base, SIZE, base - PAGE_SIZE));
    assert_eq!(pmm::total_pages(), 0, "refusal must reset the previous init");
    assert_eq!(pmm::free_pages(), 0);
    assert!(pmm::alloc_page().is_err());
    assert!(pmm::frame_index(base).is_none());
}

/// No frame to describe, or no room for the descriptors: refused too.
#[test]
fn init_refuses_an_empty_range_and_one_the_array_does_not_fit() {
    let _g = serial();
    let base = arena_base();
    assert!(!pmm::init(base, 0, base), "no frame");
    assert!(!pmm::init(base, PAGE_SIZE - 1, base), "less than one frame");
    assert!(!pmm::init(base, SIZE, base + SIZE), "the image fills the RAM");
    assert!(!pmm::init(base, SIZE, base + SIZE - ARRAY * PAGE_SIZE + PAGE_SIZE),
            "one page short for the array");
    assert!(pmm::init(base, SIZE, base + SIZE - ARRAY * PAGE_SIZE), "exactly the array fits");
    assert_eq!(pmm::free_pages(), 0);
    assert_eq!(pmm::total_pages(), PAGES);
}

/// `mem_start == kernel_end` is the legitimate zero-reservation case: the
/// guard is `>`, not `>=`.
#[test]
fn init_accepts_mem_start_exactly_equal_to_kernel_end() {
    let _g = serial();
    init(0);
    assert_eq!(pmm::total_pages(), PAGES);
    assert_eq!(pmm::free_pages(), PAGES - ARRAY, "only the array is reserved");
}

// ── `alloc` / `free` ──────────────────────────────────────────────────────

#[test]
fn alloc_and_free_take_naturally_aligned_blocks() {
    let _g = serial();
    init(4);
    let free = pmm::free_pages();
    for order in [0usize, 1, 3, 5, 8] {
        let p = pmm::alloc(order, pmm::ANY_COLOUR, pmm::ANY_NODE).expect("room");
        assert_eq!(p.0 % (1 << order), 0, "order {order}");
        assert_eq!(p.phys() % (PAGE_SIZE << order), 0, "physically aligned to its size");
        assert_eq!(pmm::free_pages(), free - (1 << order));
        for i in 0..1usize << order {
            assert_eq!(pmm::frame_state(p.phys() + i * PAGE_SIZE), Some(F_ALLOCATED));
        }
        pmm::free(p, order).unwrap();
        assert_eq!(pmm::free_pages(), free);
    }
    assert!(pmm::alloc(crate::buddy::MAX_ORDER + 1, pmm::ANY_COLOUR, pmm::ANY_NODE).is_none());
}

#[test]
fn free_refuses_a_misaligned_block_and_a_double_free_of_a_block() {
    let _g = serial();
    init(4);
    let p = pmm::alloc(3, pmm::ANY_COLOUR, pmm::ANY_NODE).unwrap();
    assert_eq!(pmm::free(Pfn(p.0 + 1), 3), Err(KernelError::NotAligned));
    assert_eq!(pmm::free(p, crate::buddy::MAX_ORDER + 1), Err(KernelError::InvalidArg));
    assert_eq!(pmm::frame_state(p.phys()), Some(F_ALLOCATED), "refusals changed nothing");
    pmm::free(p, 3).unwrap();
    assert_eq!(pmm::free(p, 3), Err(KernelError::DoubleFree));
    // A block can be given back a frame at a time, in any order.
    let q = pmm::alloc(2, pmm::ANY_COLOUR, pmm::ANY_NODE).unwrap();
    let free = pmm::free_pages();
    for i in [2usize, 0, 3, 1] {
        pmm::free(Pfn(q.0 + i), 0).unwrap();
    }
    assert_eq!(pmm::free_pages(), free + 4);
}

/// A reallocated frame starts unshared, whatever count it died with.
#[test]
fn a_reallocated_frame_starts_with_no_share_count() {
    let _g = serial();
    let p = drained_with_holes(&[20]) + 20 * PAGE_SIZE;
    crate::cow_table::shim_set_refcount(p, 5);
    let a = pmm::alloc_page().unwrap();
    assert_eq!(crate::cow_table::page_getref(a.as_usize()), 0);
}

// ── `alloc_contiguous` (RFC-0049 M0; the legacy virtio-mmio queue) ────────

/// A run is a buddy block of the order that holds it, trimmed: aligned to a
/// power of two, exactly `n` frames claimed, and giving the frames back one
/// at a time (as every caller does) rebuilds the free blocks it came from.
///
/// **Canary** (by hand): drop the tail release in `Buddy::alloc_run` and the
/// free count falls short by the surplus.
#[test]
fn a_run_is_aligned_exact_and_comes_back_a_page_at_a_time() {
    let _g = serial();
    init(4);
    let free = pmm::free_pages();
    let top = (0..=crate::buddy::MAX_ORDER).map(pmm::free_blocks).collect::<Vec<_>>();
    let p = pmm::alloc_contiguous(5).expect("room").as_usize();
    assert_eq!(p % (8 * PAGE_SIZE), 0, "a run of 5 is an order-3 block, aligned to 8 pages");
    assert_eq!(pmm::free_pages(), free - 5, "exactly the pages asked for");
    for i in 0..5 {
        assert_eq!(pmm::frame_state(p + i * PAGE_SIZE), Some(F_ALLOCATED));
    }
    for i in 5..8 {
        assert_eq!(pmm::frame_state(p + i * PAGE_SIZE), Some(F_FREE), "the surplus went back");
    }
    for i in [3usize, 0, 4, 1, 2] {
        pmm::free_page(PhysAddr::new(p + i * PAGE_SIZE)).unwrap();
    }
    assert_eq!(pmm::free_pages(), free);
    let back = (0..=crate::buddy::MAX_ORDER).map(pmm::free_blocks).collect::<Vec<_>>();
    assert_eq!(back, top, "the free blocks merged back to what they were");
}

#[test]
fn alloc_contiguous_refuses_what_does_not_exist_and_claims_nothing() {
    let _g = serial();
    init(4);
    let free = pmm::free_pages();
    assert!(pmm::alloc_contiguous(0).is_err(), "zero pages is an argument error");
    assert_eq!(pmm::alloc_contiguous(PAGES + 1), Err(KernelError::OutOfMemory));
    assert_eq!(pmm::alloc_contiguous((1 << crate::buddy::MAX_ORDER) + 1), Err(KernelError::OutOfMemory));
    assert_eq!(pmm::free_pages(), free);
}

/// With every other frame taken there is plenty free and no run of two.
#[test]
fn alloc_contiguous_refuses_isolated_pages_and_claims_nothing() {
    let _g = serial();
    let holes: Vec<usize> = (ARRAY..PAGES).step_by(2).collect();
    let _ = drained_with_holes(&holes);
    assert_eq!(pmm::free_pages(), holes.len());
    assert!(pmm::alloc_contiguous(2).is_err());
    assert_eq!(pmm::free_pages(), holes.len());
    assert!(pmm::alloc_page().is_ok(), "single frames are still there");
}

/// Every page of a recycled run comes back zeroed, not just the first.
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
    assert_eq!(q, p, "the block just freed is the one at the head of its list");
    let bytes = unsafe { core::slice::from_raw_parts(q as *const u8, 3 * PAGE_SIZE) };
    assert!(bytes.iter().all(|&b| b == 0), "a recycled run carries the old bytes");
}

/// **G24: 2 MiB for `mem="locked"`.** A 2 MiB block is order 9; its physical
/// base is a multiple of 2 MiB because frame numbers are absolute. The array
/// sits in the arena's first 2 MiB, so exactly one such block exists.
#[test]
fn a_two_mib_allocation_is_one_aligned_block() {
    let _g = serial();
    init(4);
    let order = 2 * 1024 * 1024 / PAGE_SIZE;
    let p = pmm::alloc_contiguous_aligned(order, MEGA).expect("the second megapage is free").as_usize();
    assert_eq!(p % MEGA, 0);
    assert_eq!(p, arena_base() + MEGA);
    assert_eq!(pmm::alloc_contiguous_aligned(order, MEGA), Err(KernelError::OutOfMemory),
               "the first megapage holds the image and the array");
    for i in 0..order {
        pmm::free_page(PhysAddr::new(p + i * PAGE_SIZE)).unwrap();
    }
    assert_eq!(pmm::alloc_contiguous_aligned(order, MEGA).unwrap().as_usize(), p, "and it merged back");
}

/// A run shorter than the alignment is rounded up to it: aligned, claims
/// only the pages asked for.
#[test]
fn alloc_contiguous_aligned_starts_on_the_alignment_and_claims_only_n() {
    let _g = serial();
    init(4);
    let free = pmm::free_pages();
    let align = 64 * PAGE_SIZE;
    let p = pmm::alloc_contiguous_aligned(4, align).expect("room").as_usize();
    assert_eq!(p % align, 0);
    assert_eq!(pmm::free_pages(), free - 4);
    assert!(pmm::alloc_contiguous_aligned(0, align).is_err());
    assert!(pmm::alloc_contiguous_aligned(1, 3 * PAGE_SIZE).is_err(), "not a power of two");
    assert!(pmm::alloc_contiguous_aligned(1, PAGE_SIZE / 2).is_err(), "below one page");
}

/// The boot DMA pool: taken as one run, given back page by page, the free
/// blocks as they were.
#[test]
fn the_dma_pool_reserves_a_run_and_releases_it_whole() {
    let _g = serial();
    init(4);
    let free = pmm::free_pages();
    let top = (0..=crate::buddy::MAX_ORDER).map(pmm::free_blocks).collect::<Vec<_>>();
    let base = pmm::reserve_dma_pool(100).expect("room").as_usize();
    assert_eq!(pmm::dma_pool(), (base, 100));
    assert_eq!(pmm::free_pages(), free - 100);
    assert_eq!(pmm::reserve_dma_pool(10), Err(KernelError::InvalidArg), "a second pool is refused");
    pmm::release_dma_pool();
    assert_eq!(pmm::dma_pool(), (0, 0));
    assert_eq!(pmm::free_pages(), free);
    let back = (0..=crate::buddy::MAX_ORDER).map(pmm::free_blocks).collect::<Vec<_>>();
    assert_eq!(back, top);
}

/// The kernel heap is one block: the first free frame is no use when a
/// reserved range (an image the loader put mid-RAM) cuts the free run after
/// it too short. `first_free_run` skips to the first run that holds the bytes.
#[test]
fn first_free_run_skips_gaps_too_small_for_the_block() {
    let _g = serial();
    init(4);
    let base = arena_base();
    let f = first_free(4);
    assert_eq!(pmm::first_free_run(PAGE_SIZE), Some(f), "one frame: the first free frame");
    assert_eq!(pmm::first_free_run(PAGES * PAGE_SIZE), None, "more than the arena holds");
    // A reserved page 10 frames in leaves a 10-frame gap before it.
    pmm::reserve_range(f + 10 * PAGE_SIZE, PAGE_SIZE);
    assert_eq!(pmm::first_free_run(10 * PAGE_SIZE), Some(f), "the gap holds exactly ten");
    assert_eq!(pmm::first_free_run(11 * PAGE_SIZE), Some(f + 11 * PAGE_SIZE), "eleven starts after the reservation");
    assert_eq!(pmm::first_free_run(10 * PAGE_SIZE + 1), Some(f + 11 * PAGE_SIZE), "a partial page needs its frame");
    // The run after it is what is left of the arena.
    let after = (base + SIZE - (f + 11 * PAGE_SIZE)) / PAGE_SIZE;
    assert_eq!(pmm::first_free_run(after * PAGE_SIZE), Some(f + 11 * PAGE_SIZE));
    assert_eq!(pmm::first_free_run((after + 1) * PAGE_SIZE), None);
    // next_free_addr is the first frame whatever the run.
    assert_eq!(pmm::next_free_addr(), f);
}
