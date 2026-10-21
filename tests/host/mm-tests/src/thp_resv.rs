// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the superpage reservations (Kconfig `MM_THP_RESV`), the real
//! `crates/core/mm/src/resv.rs`: reserve, fill, promote, break, and a cut of
//! the region (a permission change) breaking the reservations it touches.
//!
//! What is NOT here: the page-table half (`vmm::promote_user_block`,
//! `split_user_mega`, the fork split), which needs a live MMU and runs in the
//! boot gate; and the fault path in `pager.rs`. This file pins the state both
//! of them rest on: which frame belongs to whom, and when a block is complete.
//!
//! Canaries (discriminate / do not / did not compile):
//! * `claim` handing a frame out twice (drop the `is_handed` test): rows
//!   `a_frame_is_handed_out_once` and `a_stale_claimer_does_not_touch_a_remade_run` go red.
//! * `installed` completing on `handed` instead of the installed count:
//!   `a_block_with_a_frame_still_in_hand_is_not_complete` goes red.
//! * `unused` listing a handed frame: `break_returns_exactly_the_frames_never_handed_out`
//!   and `the_pmm_accounting_closes_after_a_break` go red.

use super::pmm;
use super::region::{Region, RegionSet};
use super::resv::{block_of, covers, index_of, Claim, Filled, ResvTable, BLOCK_PAGES, BLOCK_SIZE};
use azos_arch::mmu::PAGE_SIZE;

const ROOT: usize = 0x8000_1000;
const OTHER: usize = 0x8000_2000;
const VA: usize = 0x4000_0000;
const RUN: usize = 0x9000_0000;

fn table() -> ResvTable<4> {
    ResvTable::new()
}

fn claimed_pa(c: Claim) -> usize {
    match c {
        Claim::Frame { pa, .. } => pa,
        other => panic!("expected a frame, got {other:?}"),
    }
}

#[test]
fn a_block_is_a_level_one_leaf() {
    assert_eq!(BLOCK_SIZE, 2 * 1024 * 1024);
    assert_eq!(BLOCK_PAGES, 512);
    assert_eq!(block_of(VA + 5 * PAGE_SIZE + 17), VA);
    assert_eq!(index_of(VA + 5 * PAGE_SIZE + 17), 5);
    assert_eq!(index_of(VA + BLOCK_SIZE - 1), BLOCK_PAGES - 1);
    // A block is reservable only inside one record that holds it whole.
    assert!(covers(VA, VA + BLOCK_SIZE, VA));
    assert!(covers(VA - BLOCK_SIZE, VA + 2 * BLOCK_SIZE, VA));
    assert!(!covers(VA + PAGE_SIZE, VA + 2 * BLOCK_SIZE, VA), "starts inside the block");
    assert!(!covers(VA, VA + BLOCK_SIZE - PAGE_SIZE, VA), "ends inside the block");
}

#[test]
fn reserve_refuses_what_it_cannot_keep() {
    let mut t = table();
    assert_eq!(t.insert(ROOT, VA, RUN), Ok(()));
    assert!(t.find(ROOT, VA).is_some());
    assert!(t.find(OTHER, VA).is_none(), "another space has none");
    assert_eq!(t.insert(ROOT, VA, RUN + BLOCK_SIZE), Err(()), "one reservation per block");
    assert_eq!(t.insert(0, VA + BLOCK_SIZE, RUN), Err(()), "root 0 is the free-slot mark");
    assert_eq!(t.insert(ROOT, VA + PAGE_SIZE, RUN), Err(()), "block base unaligned");
    assert_eq!(t.insert(ROOT, VA + BLOCK_SIZE, RUN + PAGE_SIZE), Err(()), "run unaligned");
    for k in 1..4 {
        assert_eq!(t.insert(ROOT, VA + k * BLOCK_SIZE, RUN + k * BLOCK_SIZE), Ok(()));
    }
    assert_eq!(t.insert(OTHER, VA, RUN + 9 * BLOCK_SIZE), Err(()), "a full pool refuses");
    assert!(t.find(OTHER, VA).is_none());
}

#[test]
fn a_frame_is_handed_out_once() {
    let mut t = table();
    t.insert(ROOT, VA, RUN).unwrap();
    assert_eq!(t.claim(ROOT, VA, 7), Claim::Frame { run: RUN, pa: RUN + 7 * PAGE_SIZE });
    assert_eq!(t.claim(ROOT, VA, 7), Claim::Busy, "in hand: the second thread takes a plain page and races for the entry");
    assert_eq!(t.claim(ROOT, VA, 8), Claim::Frame { run: RUN, pa: RUN + 8 * PAGE_SIZE });
    assert_eq!(t.claim(OTHER, VA, 7), Claim::None, "no reservation for another space");
    assert_eq!(t.claim(ROOT, VA + BLOCK_SIZE, 7), Claim::None, "nor another block");
}

#[test]
fn a_frame_that_was_not_installed_goes_back_to_the_reservation() {
    let mut t = table();
    t.insert(ROOT, VA, RUN).unwrap();
    let Claim::Frame { run, .. } = t.claim(ROOT, VA, 3) else { panic!() };
    assert!(t.unclaim(ROOT, VA, run, 3));
    assert_eq!(t.claim(ROOT, VA, 3), Claim::Frame { run: RUN, pa: RUN + 3 * PAGE_SIZE }, "claimable again");
}

#[test]
fn fill_then_complete() {
    let mut t = table();
    t.insert(ROOT, VA, RUN).unwrap();
    for i in 0..BLOCK_PAGES {
        assert_eq!(claimed_pa(t.claim(ROOT, VA, i)), RUN + i * PAGE_SIZE);
        let f = t.installed(ROOT, VA, RUN, i);
        if i + 1 < BLOCK_PAGES {
            assert!(matches!(f, Filled::Partial), "page {i}");
        } else {
            let Filled::Complete(done) = f else { panic!("the last page completes the block") };
            assert_eq!(done.handed(), BLOCK_PAGES);
            assert_eq!(done.unused().count(), 0, "nothing left to give back at promotion");
        }
    }
    // Promoted: the entry is gone, the slot is free again.
    assert!(t.find(ROOT, VA).is_none());
    assert_eq!(t.claim(ROOT, VA, 0), Claim::None);
}

#[test]
fn a_block_with_a_frame_still_in_hand_is_not_complete() {
    let mut t = table();
    t.insert(ROOT, VA, RUN).unwrap();
    // Every frame handed out, one thread slow with its zero: promoting now
    // would map a frame that is not installed.
    for i in 0..BLOCK_PAGES {
        t.claim(ROOT, VA, i);
    }
    for i in 0..BLOCK_PAGES - 1 {
        assert!(matches!(t.installed(ROOT, VA, RUN, i), Filled::Partial), "page {i}");
    }
    assert!(matches!(t.installed(ROOT, VA, RUN, BLOCK_PAGES - 1), Filled::Complete(_)));
}

#[test]
fn a_block_filled_out_of_order_still_completes_once() {
    let mut t = table();
    t.insert(ROOT, VA, RUN).unwrap();
    let order: Vec<usize> = (0..BLOCK_PAGES).map(|k| (k * 211) % BLOCK_PAGES).collect(); // 211 is prime to 512
    let mut completed = 0;
    for &i in &order {
        t.claim(ROOT, VA, i);
        if matches!(t.installed(ROOT, VA, RUN, i), Filled::Complete(_)) {
            completed += 1;
        }
    }
    assert_eq!(completed, 1);
}

#[test]
fn an_installed_frame_is_not_handed_again() {
    let mut t = table();
    t.insert(ROOT, VA, RUN).unwrap();
    t.claim(ROOT, VA, 9);
    assert!(matches!(t.installed(ROOT, VA, RUN, 9), Filled::Partial));
    // The page was unmapped later by something other than a cut of the region:
    // its frame is an ordinary one now, maybe freed. The fault takes a plain page.
    assert_eq!(t.claim(ROOT, VA, 9), Claim::Installed);
    // A second install report of the same page does not count twice: the
    // block completes at its last page, not one early.
    assert!(matches!(t.installed(ROOT, VA, RUN, 9), Filled::Partial));
    // And one for a page nobody claimed counts for nothing.
    assert!(matches!(t.installed(ROOT, VA, RUN, 10), Filled::Gone));
    for i in (0..BLOCK_PAGES).filter(|&i| i != 9) {
        t.claim(ROOT, VA, i);
        let f = t.installed(ROOT, VA, RUN, i);
        assert_eq!(matches!(f, Filled::Complete(_)), i == BLOCK_PAGES - 1, "page {i}");
    }
}

#[test]
fn a_stale_claimer_does_not_touch_a_remade_run() {
    let mut t = table();
    t.insert(ROOT, VA, RUN).unwrap();
    let Claim::Frame { run: old, .. } = t.claim(ROOT, VA, 4) else { panic!() };
    // The reservation is broken while the frame is in hand, and made again
    // (a different run) before the thread reports back.
    t.take_overlapping(ROOT, VA, VA + BLOCK_SIZE).unwrap();
    t.insert(ROOT, VA, RUN + BLOCK_SIZE).unwrap();
    assert!(!t.unclaim(ROOT, VA, old, 4), "the thread must free its own frame");
    assert!(matches!(t.installed(ROOT, VA, old, 4), Filled::Gone));
    assert_eq!(t.find(ROOT, VA).unwrap().handed(), 0, "the new run was not disturbed");
}

#[test]
fn break_returns_exactly_the_frames_never_handed_out() {
    let mut t = table();
    t.insert(ROOT, VA, RUN).unwrap();
    for i in [0usize, 1, 2, 100, 511] {
        t.claim(ROOT, VA, i);
    }
    t.installed(ROOT, VA, RUN, 0);
    t.installed(ROOT, VA, RUN, 1);
    // 2, 100 and 511 are in hand (a thread zeroing them): not the break's to free.
    let broken = t.take_overlapping(ROOT, VA, VA + BLOCK_SIZE).unwrap();
    let unused: Vec<usize> = broken.unused().collect();
    assert_eq!(unused.len(), BLOCK_PAGES - 5);
    for i in [0usize, 1, 2, 100, 511] {
        assert!(!unused.contains(&(RUN + i * PAGE_SIZE)), "frame {i} is somebody's");
    }
    assert!(unused.contains(&(RUN + 3 * PAGE_SIZE)));
    assert!(t.take_overlapping(ROOT, VA, VA + BLOCK_SIZE).is_none(), "broken once");
}

#[test]
fn a_cut_breaks_every_block_it_touches_and_only_those() {
    let mut t = table();
    for k in 0..4 {
        t.insert(ROOT, VA + k * BLOCK_SIZE, RUN + k * BLOCK_SIZE).unwrap();
    }
    // munmap of the last page of block 0 and the first of block 1.
    let (s, e) = (VA + BLOCK_SIZE - PAGE_SIZE, VA + BLOCK_SIZE + PAGE_SIZE);
    let mut broken = Vec::new();
    while let Some(r) = t.take_overlapping(ROOT, s, e) {
        broken.push(r.va);
    }
    broken.sort();
    assert_eq!(broken, vec![VA, VA + BLOCK_SIZE]);
    assert!(t.find(ROOT, VA + 2 * BLOCK_SIZE).is_some());
    assert!(t.find(ROOT, VA + 3 * BLOCK_SIZE).is_some());
    // A range that ends exactly where a block starts touches nothing of it.
    assert!(t.take_overlapping(ROOT, VA + BLOCK_SIZE, VA + 2 * BLOCK_SIZE).is_none());
    // Another space's block at the same address is not ours to break.
    t.insert(OTHER, VA, RUN + 8 * BLOCK_SIZE).unwrap();
    assert!(t.take_overlapping(ROOT, VA, VA + BLOCK_SIZE).is_none(), "already broken");
    assert!(t.find(OTHER, VA).is_some());
}

#[test]
fn a_permission_change_splits_the_region_and_breaks_the_reservation() {
    // The pager's rule, with the real region records: a block is reservable
    // only inside one record, and mprotect of a part cuts the record.
    let mut set: RegionSet<8> = RegionSet::new();
    set.insert(Region::anon(VA, VA + 4 * BLOCK_SIZE, true)).unwrap();
    let mut t = table();
    for k in 0..4 {
        let b = VA + k * BLOCK_SIZE;
        let r = *set.find(b).unwrap();
        assert!(covers(r.start, r.end, b), "block {k} is reservable in one record");
        t.insert(ROOT, b, RUN + k * BLOCK_SIZE).unwrap();
    }
    // mprotect(PROT_READ) of two pages in the middle of block 1.
    let (s, e) = (VA + BLOCK_SIZE + 10 * PAGE_SIZE, VA + BLOCK_SIZE + 12 * PAGE_SIZE);
    set.protect_range(s, e, false).unwrap();
    let mut broken = Vec::new();
    while let Some(r) = t.take_overlapping(ROOT, s, e) {
        broken.push(r.va);
    }
    assert_eq!(broken, vec![VA + BLOCK_SIZE], "only block 1 is cut");
    // After the cut, no record holds block 1 whole: it is never reserved again,
    // and its pages are plain (4 KiB, mixed permissions) from now on.
    let r = *set.find(VA + BLOCK_SIZE).unwrap();
    assert!(!covers(r.start, r.end, VA + BLOCK_SIZE));
    let ro = *set.find(s).unwrap();
    assert!(!ro.write && !covers(ro.start, ro.end, VA + BLOCK_SIZE));
    // The blocks around it are still whole in their records and keep theirs.
    let r0 = *set.find(VA).unwrap();
    assert!(covers(r0.start, r0.end, VA));
    let r2 = *set.find(VA + 2 * BLOCK_SIZE).unwrap();
    assert!(covers(r2.start, r2.end, VA + 2 * BLOCK_SIZE));
    assert!(t.find(ROOT, VA).is_some() && t.find(ROOT, VA + 2 * BLOCK_SIZE).is_some());

    // mprotect of a whole block is uniform again, but still a cut of the
    // record: the pager breaks its reservation too (it never keeps one across
    // a permission change).
    let (s, e) = (VA + 2 * BLOCK_SIZE, VA + 3 * BLOCK_SIZE);
    set.protect_range(s, e, false).unwrap();
    assert_eq!(t.take_overlapping(ROOT, s, e).map(|r| r.va), Some(VA + 2 * BLOCK_SIZE));
}

#[test]
fn exit_and_fork_break_everything_of_one_space() {
    let mut t = table();
    t.insert(ROOT, VA, RUN).unwrap();
    t.insert(ROOT, VA + BLOCK_SIZE, RUN + BLOCK_SIZE).unwrap();
    t.insert(OTHER, VA, RUN + 2 * BLOCK_SIZE).unwrap();
    let mut n = 0;
    while t.take_root(ROOT).is_some() {
        n += 1;
    }
    assert_eq!(n, 2);
    assert!(t.find(OTHER, VA).is_some(), "the other space keeps its reservation");
    assert!(t.take_root(0).is_none());
}

#[test]
fn a_dry_allocator_reclaims_the_reservation_with_most_to_give() {
    let mut t = table();
    t.insert(ROOT, VA, RUN).unwrap();
    t.insert(OTHER, VA, RUN + BLOCK_SIZE).unwrap();
    for i in 0..300 {
        t.claim(ROOT, VA, i);
    }
    for i in 0..10 {
        t.claim(OTHER, VA, i);
    }
    let first = t.take_richest().unwrap();
    assert_eq!((first.root, first.unused().count()), (OTHER, BLOCK_PAGES - 10));
    let second = t.take_richest().unwrap();
    assert_eq!((second.root, second.unused().count()), (ROOT, BLOCK_PAGES - 300));
    assert!(t.take_richest().is_none());
}

// ── Against the real allocator ──────────────────────────────────────────────

const MEGA: usize = BLOCK_SIZE;
/// 8 MiB: block 0 holds the descriptor array, blocks 1..3 are free runs.
const ARENA: usize = 4 * MEGA;

fn arena_base() -> usize {
    use std::sync::OnceLock;
    static BASE: OnceLock<usize> = OnceLock::new();
    *BASE.get_or_init(|| {
        let raw = vec![0u8; ARENA + MEGA].leak();
        (raw.as_ptr() as usize + MEGA - 1) & !(MEGA - 1)
    })
}

fn serial() -> std::sync::MutexGuard<'static, ()> {
    super::PMM_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn fresh_pmm() {
    let base = arena_base();
    assert!(pmm::init(base, ARENA, base));
}

#[test]
fn the_pmm_gives_a_block_aligned_run_without_zeroing_it() {
    let _g = serial();
    fresh_pmm();
    let before = pmm::free_pages();
    // SAFETY: the test writes before it reads.
    let run = unsafe { pmm::alloc_contiguous_aligned_uninit(BLOCK_PAGES, BLOCK_SIZE) }.expect("a free block").as_usize();
    assert_eq!(run % BLOCK_SIZE, 0, "a level-1 leaf needs the run aligned to its size");
    assert_eq!(pmm::free_pages(), before - BLOCK_PAGES);
    // Dirty a frame, give the run back, take it again: uninit must not clean it.
    unsafe { core::ptr::write_bytes((run + 5 * PAGE_SIZE) as *mut u8, 0xA5, PAGE_SIZE) };
    for i in 0..BLOCK_PAGES {
        pmm::free_page(super::addr::PhysAddr::new(run + i * PAGE_SIZE)).unwrap();
    }
    assert_eq!(pmm::free_pages(), before);
    let again = unsafe { pmm::alloc_contiguous_aligned_uninit(BLOCK_PAGES, BLOCK_SIZE) }.unwrap().as_usize();
    let dirty = unsafe { *((again + 5 * PAGE_SIZE) as *const u8) } == 0xA5;
    let frame = super::addr::PhysAddr::new(again + 5 * PAGE_SIZE);
    pmm::zero_frame(frame);
    let clean = (0..PAGE_SIZE).all(|k| unsafe { *((again + 5 * PAGE_SIZE + k) as *const u8) } == 0);
    assert!(clean, "zero_frame is the one zero of a handed-out page");
    // The first form (alloc_contiguous_aligned) zeroes everything; the uninit one
    // is only cheaper if it does not. On this arena the same block comes back.
    assert!(dirty || again != run, "the uninit run keeps what RAM held (or is another block)");
    for i in 0..BLOCK_PAGES {
        pmm::free_page(super::addr::PhysAddr::new(again + i * PAGE_SIZE)).unwrap();
    }
    assert_eq!(pmm::free_pages(), before);
}

#[test]
fn the_pmm_accounting_closes_after_a_break() {
    let _g = serial();
    fresh_pmm();
    let before = pmm::free_pages();
    let run = unsafe { pmm::alloc_contiguous_aligned_uninit(BLOCK_PAGES, BLOCK_SIZE) }.unwrap().as_usize();
    let mut t = table();
    t.insert(ROOT, VA, run).unwrap();
    // 40 pages faulted in and installed, 2 in hand.
    let installed: Vec<usize> = (0..40).collect();
    for &i in &installed {
        let pa = claimed_pa(t.claim(ROOT, VA, i));
        pmm::zero_frame(super::addr::PhysAddr::new(pa));
        t.installed(ROOT, VA, run, i);
    }
    t.claim(ROOT, VA, 200);
    t.claim(ROOT, VA, 201);
    // munmap of the block: the reservation breaks, the sweep frees the installed pages.
    let broken = t.take_overlapping(ROOT, VA, VA + BLOCK_SIZE).unwrap();
    let mut given_back = 0;
    for pa in broken.unused() {
        pmm::free_page(super::addr::PhysAddr::new(pa)).unwrap();
        given_back += 1;
    }
    assert_eq!(given_back, BLOCK_PAGES - 42);
    assert_eq!(pmm::free_pages(), before - 42, "the 40 installed and the 2 in hand are still out");
    for &i in &installed {
        pmm::free_page(super::addr::PhysAddr::new(run + i * PAGE_SIZE)).unwrap(); // the sweep
    }
    // The two threads in hand find the entry gone and free their own.
    assert!(!t.unclaim(ROOT, VA, run, 200));
    pmm::free_page(super::addr::PhysAddr::new(run + 200 * PAGE_SIZE)).unwrap();
    assert!(!t.unclaim(ROOT, VA, run, 201));
    pmm::free_page(super::addr::PhysAddr::new(run + 201 * PAGE_SIZE)).unwrap();
    assert_eq!(pmm::free_pages(), before, "every frame of the run is back, none twice");
}

#[test]
fn a_filled_block_leaves_the_allocator_the_whole_run_to_the_page_table() {
    let _g = serial();
    fresh_pmm();
    let before = pmm::free_pages();
    let run = unsafe { pmm::alloc_contiguous_aligned_uninit(BLOCK_PAGES, BLOCK_SIZE) }.unwrap().as_usize();
    let mut t = table();
    t.insert(ROOT, VA, run).unwrap();
    for i in 0..BLOCK_PAGES {
        t.claim(ROOT, VA, i);
        if let Filled::Complete(done) = t.installed(ROOT, VA, run, i) {
            assert_eq!(done.unused().count(), 0);
        }
    }
    assert_eq!(pmm::free_pages(), before - BLOCK_PAGES, "promotion frees nothing but the table");
    // munmap of the promoted block: its 512 frames are freed one by one.
    for i in 0..BLOCK_PAGES {
        pmm::free_page(super::addr::PhysAddr::new(run + i * PAGE_SIZE)).unwrap();
    }
    assert_eq!(pmm::free_pages(), before);
    // And they merge back to a block: another run of the same size is there.
    let again = unsafe { pmm::alloc_contiguous_aligned_uninit(BLOCK_PAGES, BLOCK_SIZE) };
    assert!(again.is_ok(), "the freed frames merged into a block again");
}
