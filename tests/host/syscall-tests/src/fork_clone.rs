// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// A fork clones the parent's anonymous objects (`pager::fork_clone`): the
// child's slots are the parent's words, each resident frame shared once more
// and read-only on both sides, each compressed page the pool's entry shared,
// on the real `handlers.rs`, `pager.rs`, `anon_obj.rs`, `cow.rs` and `vmm.rs`
// over the shim arena.
//
// * `a_fork_shares_each_anonymous_frame_read_only_on_both_sides`: one more
//   reference per frame, no writable leaf left on either side, and a store by
//   either breaks the share. Canary `cow-shared-write-canary` (the clone keeps
//   the write permission): the parent's store reaches the child.
// * `a_child_that_exits_gives_its_share_back_and_the_parent_keeps_its_frames`
//   (fork, exit, wait): every frame the fork took comes back, and the parent's
//   next store takes its frame back with no copy (the share is down to one).
//   Canary `cow-reuse-canary`: the store copies.
// * `a_large_heap_fork_copies_no_frame`: a 64 MiB heap touched whole is
//   forked with no frame copied and no page shared twice (the walk passes the
//   anonymous mapping, the clone shares it). Same canary as the first row.
// * `a_sparse_mapping_is_cloned_page_by_page_across_its_leaf_tables`: pages
//   touched in three leaf tables of one mapping, each the parent's frame in the
//   child at its own address. Same canary.
// * `a_heap_page_is_the_childs_own_after_the_fork`: the `brk` heap is an
//   anonymous mapping and is cloned with it. Same canary.
// * `a_compressed_page_is_shared_with_the_child_not_restored`: the clone copies
//   the marker and the pool's entry is shared; neither side's restore touches
//   the other's page. Canary `fork-marker-canary` (the marker is not copied):
//   the child reads zeros. Needs the compressed pool (Kconfig MM_RECLAIM_COMPRESS).
//
// * `a_copy_on_write_break_waits_for_the_fork_to_end`: a sibling's break of a
//   page the clone shared waits while the fork holds the space, so a store
//   through a writable translation the shootdown has not reached yet stays in
//   the parent's frame. Canary `cow-break-during-fork-canary`: it breaks at once.
// * `a_frame_whose_parent_leaf_is_missing_refuses_the_fork`: the clone does
//   not share a frame the parent's leaf does not map (the parent's next fault
//   would install it writable). Canary `fork-leafless-frame-canary`.
//
// The host has no TLB: no row here sees the parent's shootdown after the
// clone; the QEMU fork rows run it.
//
// Included into `mod handlers` (see `lib.rs`), so `sys_*` resolve directly.

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;
use azos_mm::pager::{Ages, AnonReclaim, Victim};
use azos_mm::zpool::Reclaimee;

const ANON: u64 = u64::MAX;
const RW: u64 = 3;
const BRK: u64 = 0x10_0000;
/// A byte of the compressed row's page that differs from the others.
const MARK: usize = 2000;

fn space() -> usize {
    let old = azos_sched::current_user_pt();
    if old != 0 {
        azos_sched::shim_forget_space(old);
    }
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(1);
    azos_sched::shim_set_page_limit(0);
    azos_sched::shim_set_mem_locked(false);
    azos_sched::shim_set_sched_class(3);
    azos_sched::shim_set_brk(BRK);
    pt
}

fn map(pages: usize) -> usize {
    let r = sys_mmap(0, (pages * PAGE_SIZE) as u64, RW, 0, ANON, 0);
    assert!(r > 0, "mmap failed: {r}");
    r as usize
}

fn bytes<'a>(frame: usize) -> &'a mut [u8] {
    // SAFETY: a frame of the host arena, which the shim identity-maps.
    unsafe { core::slice::from_raw_parts_mut(azos_mm::addr::phys_to_virt(frame) as *mut u8, PAGE_SIZE) }
}

/// The frame of the page at `va` of `pt` as an access finds it: a first touch
/// faults it in through the space's pager (the kernel's copy does that for the
/// running task's root only), a store breaks copy-on-write.
fn touch(pt: usize, va: usize, write: bool) -> usize {
    if azos_mm::vmm::translate(pt, va).is_none() {
        assert!(azos_mm::vmm::handle_demand_fault(azos_sched::shim_space(pt), va).is_ok(), "the first touch");
    }
    azos_mm::vmm::translate_user(pt, va, write).expect("an allowed access") & !(PAGE_SIZE - 1)
}

/// Write `b` over the page at `va` of `pt` the way a store does; the frame written.
fn write(pt: usize, va: usize, b: u8) -> usize {
    let f = touch(pt, va, true);
    bytes(f).fill(b);
    f
}

/// What a load from `va` of `pt` reads (its first byte).
fn read(pt: usize, va: usize) -> u8 {
    bytes(touch(pt, va, false))[0]
}

/// The fork of the current space, as `sys_fork` runs it: the walk, then the
/// clone of the mappings into task 2's root. The child's root.
fn fork(pt: usize) -> usize {
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let (child, hold) =
        azos_mm::vmm::fork_cow_shared_held(azos_sched::shim_space(pt), shm_lo, shm_hi, false).expect("fork");
    azos_sched::shim_forget_space(child);
    azos_sched::shim_set_other_task(2, child, 0);
    assert!(fork_regions_to_child(2), "the clone was refused");
    drop(hold);
    child
}

/// The child ends as a task's space does: its records, then its tables.
fn exit(child: usize) {
    azos_sched::shim_end_space(child);
}

fn done(pt: usize) {
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(0);
}

#[test]
fn a_fork_shares_each_anonymous_frame_read_only_on_both_sides() {
    let _g = serial();
    let pt = space();
    let base = map(8);
    let f0 = write(pt, base, 0xA0);
    let f1 = write(pt, base + PAGE_SIZE, 0xA1);
    let child = fork(pt);
    for (va, f) in [(base, f0), (base + PAGE_SIZE, f1)] {
        assert_eq!(azos_mm::vmm::translate(child, va), Some(f), "the child maps the parent's frame");
        assert_eq!(azos_mm::cow::page_getref(f), 2, "one reference more, taken once");
        assert!(azos_mm::vmm::translate_user_writable_nofault(pt, va).is_none(), "the parent's leaf is read-only");
        assert!(azos_mm::vmm::translate_user_writable_nofault(child, va).is_none(), "the child's leaf is read-only");
    }
    assert_eq!(azos_mm::pager::space_pages(azos_sched::shim_space(child)), (8, 2));
    assert_eq!(azos_sched::shim_other_pages(), 6, "charged for the six it may still commit");
    // A store by either side breaks the share for it alone.
    let mine = write(pt, base, 0xB0);
    assert_ne!(mine, f0, "the parent's store took a frame of its own");
    assert_eq!(read(child, base), 0xA0, "the parent's store reached the child");
    let theirs = write(child, base + PAGE_SIZE, 0xC1);
    assert_ne!(theirs, f1);
    assert_eq!(read(pt, base + PAGE_SIZE), 0xA1, "the child's store reached the parent");
    // An untouched page is a zero page of each side's own.
    assert_eq!(read(child, base + 2 * PAGE_SIZE), 0);
    assert_ne!(azos_mm::vmm::translate(child, base + 2 * PAGE_SIZE), azos_mm::vmm::translate(pt, base + 2 * PAGE_SIZE));
    exit(child);
    done(pt);
}

#[test]
fn a_child_that_exits_gives_its_share_back_and_the_parent_keeps_its_frames() {
    let _g = serial();
    let pt = space();
    let base = map(16);
    let frames: Vec<usize> = (0..16).map(|i| write(pt, base + i * PAGE_SIZE, i as u8)).collect();
    let before = azos_mm::shim_pages_in_use();
    let child = fork(pt);
    assert!(azos_mm::shim_pages_in_use() > before, "the child's tables");
    exit(child);
    assert_eq!(azos_mm::shim_pages_in_use(), before, "every frame and table of the child is back");
    for &f in &frames {
        assert!(azos_mm::cow::page_getref(f) <= 1, "the parent holds its frames alone again");
    }
    // The parent's store finds the share down to one: its frame, no copy.
    for (i, &f) in frames.iter().enumerate() {
        assert_eq!(write(pt, base + i * PAGE_SIZE, 0xEE), f, "page {i} was copied");
    }
    assert_eq!(azos_mm::shim_pages_in_use(), before, "no frame taken by the stores");
    done(pt);
}

#[test]
fn a_large_heap_fork_copies_no_frame() {
    let _g = serial();
    let pt = space();
    let pages = azos_mm::pager::MAX_MAP_BYTES / PAGE_SIZE;
    // Not block-aligned here: the clone's spans start inside a leaf table.
    let base = map(pages);
    for i in 0..pages {
        assert!(azos_mm::vmm::translate_user(pt, base + i * PAGE_SIZE, true).is_some(), "page {i}");
    }
    let (first, last) = (base, base + (pages - 1) * PAGE_SIZE);
    let ff = write(pt, first, 0x5F);
    write(pt, last, 0x5E);
    let before = azos_mm::shim_pages_in_use();
    let child = fork(pt);
    // Tables and slot chunks only: the child's leaf table and slot chunk per
    // 2 MiB of heap, the parent's leaf table for a promoted block it splits
    // (Kconfig MM_THP_RESV), and the upper levels.
    let built = azos_mm::shim_pages_in_use() - before;
    assert!(built <= 3 * pages / 512 + 8, "the fork took {built} pages");
    assert_eq!(azos_mm::pager::space_pages(azos_sched::shim_space(child)), (pages, pages));
    assert_eq!(azos_sched::shim_other_pages(), 0, "every page is committed in the child");
    let mut shared = 0;
    azos_mm::vmm::for_each_leaf_in(child, base, base + pages * PAGE_SIZE, |va, f| {
        assert_eq!(azos_mm::vmm::translate(pt, va), Some(f));
        assert_eq!(azos_mm::cow::page_getref(f), 2, "shared once, not by the walk too");
        shared += 1;
    });
    assert_eq!(shared, pages);
    assert_ne!(write(pt, first, 0x60), ff, "the parent's store broke the share");
    assert_eq!(read(child, first), 0x5F, "the parent's store reached the child");
    write(child, last, 0x61);
    assert_eq!(read(pt, last), 0x5E, "the child's store reached the parent");
    exit(child);
    done(pt);
}

#[test]
fn a_sparse_mapping_is_cloned_page_by_page_across_its_leaf_tables() {
    let _g = serial();
    let pt = space();
    let base = map(1100);
    let touched = [0usize, 600, 1099];
    let frames: Vec<usize> = touched.iter().map(|&i| write(pt, base + i * PAGE_SIZE, i as u8)).collect();
    let child = fork(pt);
    assert_eq!(azos_mm::pager::space_pages(azos_sched::shim_space(child)), (1100, 3));
    let mut seen = Vec::new();
    azos_mm::vmm::for_each_leaf_in(child, base, base + 1100 * PAGE_SIZE, |va, f| seen.push(((va - base) / PAGE_SIZE, f)));
    let want: Vec<(usize, usize)> = touched.iter().copied().zip(frames.iter().copied()).collect();
    assert_eq!(seen, want, "the child's leaves are the touched pages, each on the parent's frame");
    for &i in &touched {
        write(pt, base + i * PAGE_SIZE, 0xFF);
        assert_eq!(read(child, base + i * PAGE_SIZE), i as u8, "page {i}: the parent's store reached the child");
    }
    exit(child);
    done(pt);
}

#[test]
fn a_heap_page_is_the_childs_own_after_the_fork() {
    let _g = serial();
    let pt = space();
    let pg = PAGE_SIZE as u64;
    assert_eq!(sys_brk(BRK + 4 * pg), (BRK + 4 * pg) as i64);
    let heap = BRK as usize;
    let hf = write(pt, heap, 0x48);
    let child = fork(pt);
    assert_eq!(azos_mm::vmm::translate(child, heap), Some(hf), "the heap page is shared");
    write(pt, heap, 0x49);
    assert_eq!(read(child, heap), 0x48, "the parent's heap store reached the child");
    write(child, heap + PAGE_SIZE, 0x4A);
    assert_eq!(read(pt, heap + PAGE_SIZE), 0, "the child's heap page is its own");
    exit(child);
    done(pt);
}

#[test]
fn a_compressed_page_is_shared_with_the_child_not_restored() {
    if !azos_mm::zpool::ENABLED {
        return;
    }
    let _g = serial();
    azos_crypto::entropy::mix(&[0x5d; 64], 512);
    let pt = space();
    let base = map(2);
    // Not one byte repeated: a blob of the pool's, not a same-filled entry.
    let f = write(pt, base, 0x5D);
    bytes(f)[MARK] = 0x01;
    let roots = [Some(azos_sched::shim_space(pt))];
    let mut ages = Ages::new();
    let mut reclaim = AnonReclaim::new(&roots, 0, &mut ages);
    let victim = Victim { space: pt, va: base };
    assert!(reclaim.unmap(victim));
    assert!(reclaim.store(victim).is_ok(), "the page is in the pool");
    reclaim.free(victim);
    let held = azos_mm::pager::zpool_stats();
    let child = fork(pt);
    assert!(azos_mm::vmm::translate(pt, base).is_none(), "the fork restored the parent's page");
    assert!(azos_mm::vmm::translate(child, base).is_none(), "the fork restored the child's page");
    let now = azos_mm::pager::zpool_stats();
    assert_eq!((now.entries, now.blobs), (held.entries + 1, held.blobs), "the pool's copy is shared, not stored again");
    assert_eq!(azos_mm::pager::space_pages(azos_sched::shim_space(child)), (2, 0));
    assert_eq!(azos_sched::shim_other_pages(), 1, "the compressed page is not charged");
    write(pt, base, 0x6D);
    assert_eq!(read(child, base), 0x5D, "the child reads the parent's page as it was");
    let cf = azos_mm::vmm::translate(child, base).expect("restored in the child");
    assert_eq!(bytes(cf)[MARK], 0x01, "the child's copy is whole");
    write(child, base, 0x7D);
    assert_eq!(read(pt, base), 0x6D);
    exit(child);
    done(pt);
}

/// Set when a break finds its space held by a fork.
static BREAK_HELD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn break_held() {
    BREAK_HELD.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[test]
fn a_copy_on_write_break_waits_for_the_fork_to_end() {
    let _g = serial();
    let pt = space();
    let base = map(2);
    let f = write(pt, base, 0x31);
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let (child, hold) =
        azos_mm::vmm::fork_cow_shared_held(azos_sched::shim_space(pt), shm_lo, shm_hi, false).expect("fork");
    azos_sched::shim_forget_space(child);
    azos_sched::shim_set_other_task(2, child, 0);
    assert!(fork_regions_to_child(2));
    BREAK_HELD.store(false, std::sync::atomic::Ordering::SeqCst);
    azos_mm::pager::shim_set_held_hook(Some(break_held));
    azos_sched::shim_serial_share(true);
    let (held, during, broke) = std::thread::scope(|sc| {
        let sibling = sc.spawn(|| azos_mm::cow::handle_cow_fault(pt, base).is_ok());
        while !BREAK_HELD.load(std::sync::atomic::Ordering::SeqCst) && !sibling.is_finished() {
            std::thread::yield_now();
        }
        let held = BREAK_HELD.load(std::sync::atomic::Ordering::SeqCst);
        let during = azos_mm::vmm::translate(pt, base);
        drop(hold);
        (held, during, sibling.join().unwrap())
    });
    azos_sched::shim_serial_share(false);
    azos_mm::pager::shim_set_held_hook(None);
    assert!(held, "the break went through while the fork held the space");
    assert_eq!(during, Some(f), "the parent left the frame the child keeps during the fork");
    assert!(broke, "the break after the fork's end");
    assert_ne!(azos_mm::vmm::translate(pt, base), Some(f), "the parent has a frame of its own after the fork");
    assert_eq!(azos_mm::vmm::translate(child, base), Some(f));
    exit(child);
    done(pt);
}

#[test]
fn a_frame_whose_parent_leaf_is_missing_refuses_the_fork() {
    let _g = serial();
    let pt = space();
    let base = map(2);
    let f = write(pt, base, 0x41);
    // The leaf goes, the slot keeps the frame.
    azos_mm::vmm::unmap(pt, base);
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let (child, hold) =
        azos_mm::vmm::fork_cow_shared_held(azos_sched::shim_space(pt), shm_lo, shm_hi, false).expect("fork");
    azos_sched::shim_forget_space(child);
    azos_sched::shim_set_other_task(2, child, 0);
    let cloned = fork_regions_to_child(2);
    drop(hold);
    assert!(!cloned, "the clone shared a frame its parent leaf does not map");
    assert!(azos_mm::cow::page_getref(f) <= 1, "the refusal kept a reference");
    azos_sched::shim_forget_space(child);
    azos_mm::vmm::destroy_user_pagetable_skip_range(child, shm_lo, shm_hi);
    done(pt);
}
