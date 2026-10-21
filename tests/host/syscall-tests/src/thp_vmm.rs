// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Kconfig MM_THP_RESV: host rows for the page-table half of the superpage
// reservations, on the real `pager.rs`, `vmm.rs`, `cow.rs` and `resv.rs`
// over the shim arena and the real Sv39 walker. (The bookkeeping alone is in
// `tests/host/mm-tests/src/thp_resv.rs`.)
//
// Built with MM_THP_RESV=y these rows pin the promotion and everything that
// has to settle a promoted block; with it n they pin that nothing is
// reserved or promoted. What each pins, and its canary:
//
// * The first fault of an untouched, wholly covered block takes an aligned
//   run and the pages come from it in order; the last fills it and the
//   level-0 table becomes ONE level-1 leaf. Canary: `promote_user_block`
//   skipping its entry check (`ARCH.pte_is_cow(e)`) does not show here (no
//   COW page in these rows); skipping the CAS leaves `leaf_level` at 0.
// * A promoted block is still a user leaf for `user_page`, `translate_user`
//   and the write checks. Canary: `user_page` without its `promoted_leaf`
//   arm answers `Other` and `fill_promotes...` / `mprotect...` go red.
// * `munmap` of the whole block frees its 512 frames, of a part splits it
//   first. Canary: `release_megas` removed: the frames leak and
//   `munmap_of_the_whole...` goes red.
// * `mprotect` of the whole block rewrites the leaf, of a part splits it.
// * A fork splits the parent's promoted blocks (the walk skips level-1
//   leaves). Canary: drop `fork_begin` from `cow::fork_cow_shared`: the child
//   gets a hole and `fork_splits...` goes red.
// * Promotion waits for every running fork walk of the space, not the first
//   to end (`a_block_filled_while_any_fork_walk_runs_is_not_promoted`).
// * A cut of the region (munmap, mprotect of a part) returns the run's unused
//   frames. Canary: drop `break_range` from `pager::protect_range`:
//   `mprotect_of_a_part_of_a_reservation...` goes red.
// * Break-before-make (`Mmu::block_change_needs_bbm`, the shim answers it on
//   demand): the shootdown of a promotion finds the slot PARKED (invalid, not
//   the old table, not the leaf), and the leaf lands after it; a split does
//   the same; a software walk that meets the park waits for the leaf. Without
//   the requirement the shootdown sees the leaf and nothing is ever parked.
//   Canaries: `promote_user_block` storing the leaf before the shootdown, or
//   skipping the park: `the_shootdown_of_a_promotion_finds_the_slot_parked`
//   goes red; `translate` reading the slot with `read_volatile` instead of
//   `l1_read`, or `l1_slot_is_empty` likewise: `a_walker_that_meets_the_park_waits_for_the_leaf`
//   goes red.
// * A hardware fault on a level-0 word a run break has parked waits for the
//   plain leaf and retries the access (`vmm::wait_out_parked_fault`).
//   Canary: drop the call from `vmm::handle_demand_fault`:
//   `a_fault_on_a_word_a_run_break_has_parked_waits_for_the_plain_leaf` goes red.
// * Teardown frees a promoted block's frames and a partly used block's run.
//   Canary: drop the promoted arm of `destroy_user_pagetable_skip_range`.
//
// Included into `mod handlers` (see `lib.rs`), so `sys_*` resolve directly.

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;

const ANON: u64 = u64::MAX;
const RW: u64 = 3;
const RO: u64 = 1;
const BRK: u64 = 0x10_0000;
const MEGA: usize = 2 * 1024 * 1024;
/// 6 MiB from `BRK` = [1 MiB, 7 MiB): the blocks [2, 4) and [4, 6) MiB lie
/// wholly inside one region, [0, 2) and [6, 8) do not.
const REGION_PAGES: usize = 3 * MEGA / PAGE_SIZE;
const BLOCK_A: usize = 0x20_0000;
const BLOCK_B: usize = 0x40_0000;
const PAGES: usize = MEGA / PAGE_SIZE;

fn on() -> bool {
    azos_mm::resv::ENABLED
}

fn space() -> usize {
    let old = azos_sched::current_user_pt();
    if old != 0 {
        azos_mm::pager::forget(old);
    }
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::pager::forget(pt);
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(1);
    azos_sched::shim_set_page_limit(0);
    azos_sched::shim_set_mem_locked(false);
    azos_sched::shim_set_sched_class(3);
    azos_sched::shim_set_brk(BRK);
    pt
}

fn region(prot: u64) -> usize {
    let r = sys_mmap(0, (REGION_PAGES * PAGE_SIZE) as u64, prot, 0, ANON, 0);
    assert_eq!(r, BRK as i64, "mmap failed: {r}");
    r as usize
}

fn touch(pt: usize, va: usize) {
    assert!(azos_mm::vmm::handle_demand_fault(pt, va).is_ok(), "fault at {va:#x}");
}

fn fill(pt: usize, block: usize, n: usize) {
    for i in 0..n {
        touch(pt, block + i * PAGE_SIZE);
    }
}

fn level(pt: usize, va: usize) -> Option<usize> {
    azos_mm::vmm::leaf_level(pt, va)
}

fn writable(pt: usize, va: usize) -> bool {
    azos_mm::vmm::user_write_would_be_permitted(pt, va)
}

fn used() -> usize {
    azos_mm::shim_pages_in_use()
}

fn pa(pt: usize, va: usize) -> usize {
    azos_mm::vmm::translate(pt, va).expect("mapped")
}

fn page_bytes(pa: usize) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut(azos_mm::addr::phys_to_virt(pa) as *mut u8, PAGE_SIZE) }
}

#[test]
fn the_first_fault_takes_an_aligned_run_and_the_pages_come_from_it_in_order() {
    let _g = serial();
    let pt = space();
    region(RW);
    let before = used();
    touch(pt, BLOCK_A + 5 * PAGE_SIZE);
    if !on() {
        assert!(used() - before < 8, "one page and its tables; no run");
        return;
    }
    // The run is out of the allocator whole; the page asked for is installed.
    assert!(used() - before >= PAGES, "512 frames reserved");
    let run = pa(pt, BLOCK_A + 5 * PAGE_SIZE) - 5 * PAGE_SIZE;
    assert_eq!(run % MEGA, 0, "a level-1 leaf needs the run aligned to its size");
    for k in [0usize, 1, 7, 300, 511] {
        touch(pt, BLOCK_A + k * PAGE_SIZE);
        assert_eq!(pa(pt, BLOCK_A + k * PAGE_SIZE), run + k * PAGE_SIZE, "page {k} is frame {k} of the run");
        assert!(page_bytes(run + k * PAGE_SIZE).iter().all(|&b| b == 0), "handed out zeroed");
    }
    assert_eq!(level(pt, BLOCK_A), Some(0), "still 4 KiB pages");
    // A second block has its own run.
    touch(pt, BLOCK_B);
    assert_eq!(pa(pt, BLOCK_B) % MEGA, 0);
    assert_ne!(pa(pt, BLOCK_B), run);
}

#[test]
fn a_block_outside_one_whole_record_is_not_reserved() {
    let _g = serial();
    let pt = space();
    region(RW);
    let before = used();
    // [0, 2) MiB starts below the region: its first page is the region's, the
    // block is not.
    touch(pt, BRK as usize);
    assert!(used() - before < 8, "a plain page");
    touch(pt, 0x60_0000 + PAGE_SIZE); // block [6, 8) MiB ends past the region
    assert!(used() - before < 16);
    assert_eq!(level(pt, BRK as usize), Some(0));
}

#[test]
fn filling_a_block_promotes_it_to_one_leaf_and_the_data_survives() {
    let _g = serial();
    let pt = space();
    region(RW);
    fill(pt, BLOCK_A, PAGES - 1);
    // Data written through the 4 KiB pages before the promotion.
    let p5 = pa(pt, BLOCK_A + 5 * PAGE_SIZE);
    page_bytes(p5)[17] = 0xAB;
    let before_last = used();
    let tables_before = azos_mm::vmm::table_frames(pt);
    touch(pt, BLOCK_A + (PAGES - 1) * PAGE_SIZE);
    if !on() {
        assert_eq!(level(pt, BLOCK_A), Some(0), "off: never a leaf");
        return;
    }
    assert_eq!(level(pt, BLOCK_A), Some(1));
    assert_eq!(level(pt, BLOCK_A + 300 * PAGE_SIZE), Some(1));
    assert_eq!(used() + 1, before_last, "the level-0 table is the only frame that came back");
    assert_eq!(azos_mm::vmm::table_frames(pt) + 1, tables_before);
    // Still a user page for every reader.
    assert_eq!(azos_mm::vmm::user_page(pt, BLOCK_A + 9 * PAGE_SIZE), azos_mm::vmm::UserPage::Leaf { exec: false });
    assert!(writable(pt, BLOCK_A + 9 * PAGE_SIZE));
    assert_eq!(azos_mm::vmm::translate_user(pt, BLOCK_A + 5 * PAGE_SIZE + 17, true), Some(p5 + 17));
    assert_eq!(page_bytes(p5)[17], 0xAB);
    assert_eq!(pa(pt, BLOCK_A + 5 * PAGE_SIZE), p5, "the same frames, not copies");
    // Both the pager's books and the charge are unchanged by the swap.
    assert_eq!(azos_mm::pager::space_pages(pt), (REGION_PAGES, PAGES));
    // The neighbour block is untouched and still 4 KiB.
    assert_eq!(level(pt, BLOCK_B), None);
}

#[test]
fn a_cut_region_is_never_promoted() {
    let _g = serial();
    let pt = space();
    region(RW);
    // mprotect two pages in the middle of block A before anything is touched:
    // the record is cut, the block is two permissions.
    assert_eq!(sys_mprotect((BLOCK_A + 10 * PAGE_SIZE) as u64, (2 * PAGE_SIZE) as u64, RO), 0);
    fill(pt, BLOCK_A, PAGES);
    assert_eq!(level(pt, BLOCK_A), Some(0));
    assert!(!writable(pt, BLOCK_A + 10 * PAGE_SIZE));
    assert!(writable(pt, BLOCK_A + 12 * PAGE_SIZE));
    // The block next to it is whole in its record and promotes.
    fill(pt, BLOCK_B, PAGES);
    assert_eq!(level(pt, BLOCK_B), if on() { Some(1) } else { Some(0) });
}

#[test]
fn munmap_of_a_part_of_a_reservation_returns_its_unused_frames() {
    let _g = serial();
    let pt = space();
    region(RW);
    let base_used = used();
    let base_tables = azos_mm::vmm::table_frames(pt);
    fill(pt, BLOCK_A, 3);
    assert_eq!(sys_munmap((BLOCK_A + PAGE_SIZE) as u64, PAGE_SIZE as u64), 0);
    // The cut broke the reservation: of the run only the two pages still
    // mapped stay out, and the one unmapped came back with the sweep.
    let tables = azos_mm::vmm::table_frames(pt) - base_tables;
    assert_eq!(used() - base_used, 2 + tables, "two mapped pages and the tables; everything else is back");
    // Pages faulted after the cut are plain: not promoted ever, any frame.
    touch(pt, BLOCK_A + 100 * PAGE_SIZE);
    assert_eq!(level(pt, BLOCK_A), Some(0));
}

#[test]
fn mprotect_of_a_part_of_a_reservation_returns_its_unused_frames() {
    let _g = serial();
    let pt = space();
    region(RW);
    let base_used = used();
    let base_tables = azos_mm::vmm::table_frames(pt);
    touch(pt, BLOCK_A);
    assert_eq!(sys_mprotect((BLOCK_A + 10 * PAGE_SIZE) as u64, (2 * PAGE_SIZE) as u64, RO), 0);
    let tables = azos_mm::vmm::table_frames(pt) - base_tables;
    assert_eq!(used() - base_used, 1 + tables, "the one page and the tables; the rest of the run is back");
}

#[test]
fn munmap_of_the_whole_promoted_block_frees_all_its_frames() {
    if !on() {
        return;
    }
    let _g = serial();
    let pt = space();
    region(RW);
    let base_used = used();
    fill(pt, BLOCK_A, PAGES);
    assert_eq!(level(pt, BLOCK_A), Some(1));
    assert_eq!(azos_sched::shim_user_pages(), REGION_PAGES as u32);
    assert_eq!(sys_munmap(BLOCK_A as u64, MEGA as u64), 0);
    assert_eq!(level(pt, BLOCK_A), None, "the leaf is gone");
    // Frames: only the tables the walk made remain (level 1; the level-0 table
    // went with the promotion).
    assert!(used() - base_used <= 2, "512 frames freed, got {} still out", used() - base_used);
    assert_eq!(azos_sched::shim_user_pages(), (REGION_PAGES - PAGES) as u32, "512 pages discharged");
    // The range is a hole now: a fault there is not resolved.
    assert!(azos_mm::vmm::handle_demand_fault(pt, BLOCK_A + PAGE_SIZE).is_err());
}

#[test]
fn munmap_of_part_of_a_promoted_block_splits_it_first() {
    if !on() {
        return;
    }
    let _g = serial();
    let pt = space();
    region(RW);
    fill(pt, BLOCK_A, PAGES);
    let run = pa(pt, BLOCK_A);
    let before = used();
    assert_eq!(sys_munmap((BLOCK_A + 7 * PAGE_SIZE) as u64, (2 * PAGE_SIZE) as u64), 0);
    assert_eq!(level(pt, BLOCK_A), Some(0), "4 KiB pages again");
    assert_eq!(azos_mm::vmm::user_page(pt, BLOCK_A + 7 * PAGE_SIZE), azos_mm::vmm::UserPage::Missing);
    assert_eq!(azos_mm::vmm::user_page(pt, BLOCK_A + 9 * PAGE_SIZE), azos_mm::vmm::UserPage::Leaf { exec: false });
    assert_eq!(pa(pt, BLOCK_A + 9 * PAGE_SIZE), run + 9 * PAGE_SIZE, "the others are the same frames");
    // A table came (the split), two frames went.
    assert_eq!(used() + 2, before + 1);
    assert_eq!(azos_sched::shim_user_pages(), (REGION_PAGES - 2) as u32);
}

#[test]
fn mprotect_rewrites_a_whole_promoted_block_and_splits_for_a_part() {
    if !on() {
        return;
    }
    let _g = serial();
    let pt = space();
    region(RW);
    fill(pt, BLOCK_A, PAGES);
    fill(pt, BLOCK_B, PAGES);
    assert!(writable(pt, BLOCK_A + 3 * PAGE_SIZE));
    // The whole block, read-only: the leaf stays one leaf.
    assert_eq!(sys_mprotect(BLOCK_A as u64, MEGA as u64, RO), 0);
    assert_eq!(level(pt, BLOCK_A), Some(1));
    assert!(!writable(pt, BLOCK_A + 3 * PAGE_SIZE));
    assert!(azos_mm::vmm::translate_user(pt, BLOCK_A + 3 * PAGE_SIZE, true).is_none(), "a store is refused");
    assert!(azos_mm::vmm::translate_user(pt, BLOCK_A + 3 * PAGE_SIZE, false).is_some());
    // And back.
    assert_eq!(sys_mprotect(BLOCK_A as u64, MEGA as u64, RW), 0);
    assert_eq!(level(pt, BLOCK_A), Some(1));
    assert!(writable(pt, BLOCK_A + 3 * PAGE_SIZE));
    // A part of the other block: split, and only those pages change.
    assert_eq!(sys_mprotect((BLOCK_B + 20 * PAGE_SIZE) as u64, (3 * PAGE_SIZE) as u64, RO), 0);
    assert_eq!(level(pt, BLOCK_B), Some(0));
    assert!(!writable(pt, BLOCK_B + 21 * PAGE_SIZE));
    assert!(writable(pt, BLOCK_B + 19 * PAGE_SIZE));
    assert!(writable(pt, BLOCK_B + 23 * PAGE_SIZE));
}

#[test]
fn a_protect_takes_write_from_a_promoted_block() {
    if !on() {
        return;
    }
    let _g = serial();
    let pt = space();
    region(RW);
    fill(pt, BLOCK_A, PAGES);
    let changed = azos_mm::vmm::set_user_range_write(pt, BLOCK_A, BLOCK_A + MEGA, false);
    assert!(changed >= 1);
    assert!(!writable(pt, BLOCK_A + PAGE_SIZE));
    assert_eq!(level(pt, BLOCK_A), Some(1));
    azos_mm::vmm::set_user_range_write(pt, BLOCK_A, BLOCK_A + MEGA, true);
    assert!(writable(pt, BLOCK_A + PAGE_SIZE));
}

#[test]
fn fork_splits_the_parents_promoted_blocks_and_the_child_gets_the_pages() {
    if !on() {
        return;
    }
    let _g = serial();
    let pt = space();
    region(RW);
    fill(pt, BLOCK_A, PAGES);
    // A block still being filled: its reservation is the fork's to break.
    fill(pt, BLOCK_B, 10);
    let p5 = pa(pt, BLOCK_A + 5 * PAGE_SIZE);
    page_bytes(p5)[3] = 0x77;
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let child = azos_mm::cow::fork_cow_shared(pt, shm_lo, shm_hi, false).expect("fork").0;
    assert_eq!(level(pt, BLOCK_A), Some(0), "the parent's block was split before the walk");
    assert_eq!(level(child, BLOCK_A), Some(0));
    for k in [0usize, 5, 300, 511] {
        assert_eq!(pa(child, BLOCK_A + k * PAGE_SIZE), pa(pt, BLOCK_A + k * PAGE_SIZE),
                   "page {k}: the child maps the parent's frame (copy-on-write)");
    }
    assert_eq!(page_bytes(pa(child, BLOCK_A + 5 * PAGE_SIZE))[3], 0x77);
    // Copy-on-write, not shared writable.
    assert!(azos_mm::vmm::translate_user(child, BLOCK_A + 5 * PAGE_SIZE, false).is_some());
    // The parent's half-filled block lost its reservation: a later fault is a
    // plain page from anywhere.
    touch(pt, BLOCK_B + 200 * PAGE_SIZE);
    assert_eq!(level(pt, BLOCK_B), Some(0));
}

#[test]
fn a_block_filled_while_any_fork_walk_runs_is_not_promoted() {
    if !on() {
        return;
    }
    let _g = serial();
    let pt = space();
    region(RW);
    // Two threads of the space fork at once: the first to finish must not let
    // promotion resume under the second's walk (a leaf the walk passes is a
    // hole in the child). Canary: `Space.forking` back to a bool: the block
    // is promoted after the first `fork_end`.
    assert!(azos_mm::pager::fork_begin(pt));
    assert!(azos_mm::pager::fork_begin(pt));
    azos_mm::pager::fork_end(pt);
    fill(pt, BLOCK_B, PAGES);
    assert_eq!(level(pt, BLOCK_B), Some(0), "a walk is still running");
    azos_mm::pager::fork_end(pt);
    // Nothing left to wait for: the next block fills and promotes.
    fill(pt, BLOCK_A, PAGES);
    assert_eq!(level(pt, BLOCK_A), Some(1));
}

#[test]
fn teardown_frees_a_promoted_block_and_the_run_of_a_half_filled_one() {
    if !on() {
        return;
    }
    let _g = serial();
    let before_space = used();
    let pt = space();
    region(RW);
    fill(pt, BLOCK_A, PAGES);
    fill(pt, BLOCK_B, 10);
    assert!(used() - before_space >= 2 * PAGES);
    azos_sched::set_current_user_pt(0);
    assert_eq!(azos_mm::vmm::destroy_user_pagetable_skip_range(pt, 0, 0), 0);
    assert_eq!(used(), before_space, "every frame is back: the leaf's 512, the other run's 502 and 10, the tables, the root");
}

#[test]
fn under_memory_pressure_a_reservation_is_given_up_for_a_plain_page() {
    if !on() {
        return;
    }
    let _g = serial();
    let pt = space();
    region(RW);
    touch(pt, BLOCK_A); // a run is out for block A, one page installed
    // Take every other frame.
    let mut held = Vec::new();
    while let Ok(p) = azos_mm::pmm::alloc_page() {
        held.push(p);
    }
    assert_eq!(azos_mm::pmm::free_pages(), 0);
    // A fault in a block with no reservation (block B: making one needs free
    // memory, there is none) still finds a frame: block A's run is reclaimed.
    assert!(azos_mm::vmm::handle_demand_fault(pt, 0x60_0000 + PAGE_SIZE).is_ok(), "reclaim found a frame");
    assert!(azos_mm::pmm::free_pages() > 0, "the run's unused frames are back");
    // Block A's installed page survives; its next faults are plain.
    assert!(azos_mm::vmm::user_page(pt, BLOCK_A) == azos_mm::vmm::UserPage::Leaf { exec: false });
    touch(pt, BLOCK_A + PAGE_SIZE);
    for p in held {
        let _ = azos_mm::pmm::free_page(p);
    }
}

// ── break-before-make ───────────────────────────────────────────────────

use azos_arch::mmu::Pte;
use azos_arch::{NEEDS_BBM, SHOOTDOWN_HOOK};
use azos_arch_api::PTE_BBM_PARK;
use core::sync::atomic::{AtomicUsize, Ordering};

static WATCH: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static SAW_PARK: AtomicUsize = AtomicUsize::new(0);
static SAW_LEAF: AtomicUsize = AtomicUsize::new(0);
static SAW_TABLE: AtomicUsize = AtomicUsize::new(0);
/// A virtual address a thread translates from inside the park window (0: none).
static PROBE: AtomicUsize = AtomicUsize::new(0);
static PROBER: std::sync::Mutex<Option<std::thread::JoinHandle<Option<usize>>>> = std::sync::Mutex::new(None);
static MAP_PROBER: std::sync::Mutex<Option<std::thread::JoinHandle<bool>>> = std::sync::Mutex::new(None);
static EMPTY_PROBER: std::sync::Mutex<Option<std::thread::JoinHandle<bool>>> = std::sync::Mutex::new(None);

/// The level-1 word that maps `va` under `root`, read by hand (never through a
/// reader that would wait for the park).
fn l1_word(root: usize, va: usize) -> u64 {
    let word = |table: usize, i: usize| unsafe {
        *(azos_mm::addr::phys_to_virt(table + i * 8) as *const u64)
    };
    let l2 = Pte(word(root, azos_arch::mmu::vpn2(va)));
    word(l2.phys_addr(), azos_arch::mmu::vpn1(va))
}

fn observe(root: usize, va: usize, _len: usize) {
    if root == 0 || WATCH.load(Ordering::SeqCst) != root {
        return;
    }
    CALLS.fetch_add(1, Ordering::SeqCst);
    let w = l1_word(root, va);
    if w == PTE_BBM_PARK {
        SAW_PARK.fetch_add(1, Ordering::SeqCst);
        let probe = PROBE.load(Ordering::SeqCst);
        if probe != 0 {
            // Three readers, each starting inside the window: a walk that
            // translates, the question "is this slot free?", and a mapper
            // that would build a table in a slot it finds empty.
            let started = std::sync::Arc::new(AtomicUsize::new(0));
            let (s1, s2, s3) = (started.clone(), started.clone(), started.clone());
            let t = std::thread::spawn(move || {
                s1.fetch_add(1, Ordering::SeqCst);
                azos_mm::vmm::translate(root, probe)
            });
            let e = std::thread::spawn(move || {
                s2.fetch_add(1, Ordering::SeqCst);
                azos_mm::vmm::l1_slot_is_empty(root, probe)
            });
            let m = std::thread::spawn(move || {
                s3.fetch_add(1, Ordering::SeqCst);
                azos_mm::vmm::map(root, probe & !(PAGE_SIZE - 1), 7 * PAGE_SIZE, azos_arch_api::PagePerms::USER_RW).is_err()
            });
            while started.load(Ordering::SeqCst) < 3 {
                std::thread::yield_now();
            }
            // Long enough for both to be inside their read, on the park.
            std::thread::sleep(std::time::Duration::from_millis(100));
            *PROBER.lock().unwrap() = Some(t);
            *EMPTY_PROBER.lock().unwrap() = Some(e);
            *MAP_PROBER.lock().unwrap() = Some(m);
        }
    } else if Pte(w).is_leaf() {
        SAW_LEAF.fetch_add(1, Ordering::SeqCst);
    } else {
        SAW_TABLE.fetch_add(1, Ordering::SeqCst);
    }
}

/// The shim answers "needs break-before-make" and reports each shootdown of
/// `root` to [`observe`] for as long as this lives.
struct Bbm;

impl Bbm {
    fn arm(root: usize, needs: bool) -> Bbm {
        for c in [&CALLS, &SAW_PARK, &SAW_LEAF, &SAW_TABLE, &PROBE] {
            c.store(0, Ordering::SeqCst);
        }
        WATCH.store(root, Ordering::SeqCst);
        NEEDS_BBM.store(needs, Ordering::SeqCst);
        *SHOOTDOWN_HOOK.lock().unwrap() = Some(observe);
        Bbm
    }
}

impl Drop for Bbm {
    fn drop(&mut self) {
        *SHOOTDOWN_HOOK.lock().unwrap() = None;
        NEEDS_BBM.store(false, Ordering::SeqCst);
        WATCH.store(0, Ordering::SeqCst);
        PROBE.store(0, Ordering::SeqCst);
    }
}

#[test]
fn the_park_word_is_invalid_and_is_not_empty_or_a_marker() {
    use azos_arch_api::Mmu;
    assert!(!azos_arch::ARCH.pte_is_valid(PTE_BBM_PARK));
    assert_ne!(PTE_BBM_PARK, azos_arch::ARCH.pte_empty());
    assert!(!azos_arch::ARCH.pte_is_demand(PTE_BBM_PARK));
}

/// The level-0 slot that maps `va` under `root`, by hand.
fn l0_slot(root: usize, va: usize) -> *mut u64 {
    let word = |table: usize, i: usize| unsafe {
        *(azos_mm::addr::phys_to_virt(table + i * 8) as *const u64)
    };
    let l2 = Pte(word(root, azos_arch::mmu::vpn2(va)));
    let l1 = Pte(word(l2.phys_addr(), azos_arch::mmu::vpn1(va)));
    azos_mm::addr::phys_to_virt(l1.phys_addr() + azos_arch::mmu::vpn0(va) * 8) as *mut u64
}

#[test]
fn a_fault_on_a_word_a_run_break_has_parked_waits_for_the_plain_leaf() {
    let _g = serial();
    let pt = space();
    region(RW);
    let va = BLOCK_A + 3 * PAGE_SIZE;
    touch(pt, va);
    if level(pt, va) != Some(0) {
        return;
    }
    let _b = Bbm::arm(pt, true);
    let slot = l0_slot(pt, va);
    let leaf = unsafe { *slot };
    assert!(Pte(leaf).is_valid());
    // The window of `break_contig_run` on another CPU: the word is parked,
    // and the plain leaf lands a moment later.
    unsafe { *slot = PTE_BBM_PARK };
    let addr = slot as usize;
    let maker = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        unsafe { core::ptr::write_volatile(addr as *mut u64, leaf) };
    });
    // The page stays mapped: the fault is waited out and the access retries,
    // not a kill (`NotMapped`) and not a second page.
    assert!(azos_mm::vmm::handle_demand_fault(pt, va).is_ok(), "a parked word is no fault to kill for");
    assert_eq!(unsafe { *slot }, leaf, "answered only once the leaf is back");
    maker.join().unwrap();
}

#[test]
fn the_shootdown_of_a_promotion_finds_the_slot_parked() {
    if !on() {
        return;
    }
    let _g = serial();
    let pt = space();
    region(RW);
    let _b = Bbm::arm(pt, true);
    fill(pt, BLOCK_A, PAGES - 1);
    assert_eq!(CALLS.load(Ordering::SeqCst), 0, "no shootdown before the block is whole");
    touch(pt, BLOCK_A + (PAGES - 1) * PAGE_SIZE);
    assert_eq!(level(pt, BLOCK_A), Some(1), "the block is promoted");
    assert_eq!(SAW_PARK.load(Ordering::SeqCst), 1, "invalid at the shootdown: broken before made");
    assert_eq!(SAW_LEAF.load(Ordering::SeqCst), 0, "the leaf is stored after it");
    assert_eq!(SAW_TABLE.load(Ordering::SeqCst), 0, "the old table is no longer reachable at it");
    assert_eq!(CALLS.load(Ordering::SeqCst), 1, "one flush: the break's; the finish does not repeat it");
    assert_ne!(l1_word(pt, BLOCK_A), PTE_BBM_PARK, "the park never outlives the call");
}

#[test]
fn without_the_requirement_the_promotion_is_one_swap_and_nothing_is_parked() {
    if !on() {
        return;
    }
    let _g = serial();
    let pt = space();
    region(RW);
    let _b = Bbm::arm(pt, false);
    fill(pt, BLOCK_A, PAGES);
    assert_eq!(level(pt, BLOCK_A), Some(1));
    assert_eq!(SAW_PARK.load(Ordering::SeqCst), 0);
    assert_eq!(SAW_LEAF.load(Ordering::SeqCst), 1, "the old translations are shot down after the swap");
    assert_eq!(CALLS.load(Ordering::SeqCst), 1);
}

#[test]
fn a_split_is_broken_before_made_too() {
    if !on() {
        return;
    }
    let _g = serial();
    let pt = space();
    region(RW);
    let _b = Bbm::arm(pt, true);
    fill(pt, BLOCK_A, PAGES);
    assert_eq!(level(pt, BLOCK_A), Some(1));
    let calls = CALLS.load(Ordering::SeqCst);
    // A part of the block goes away: the block is split first.
    assert_eq!(sys_munmap((BLOCK_A + PAGE_SIZE) as u64, PAGE_SIZE as u64), 0);
    assert_eq!(SAW_PARK.load(Ordering::SeqCst), 2, "the split parked the slot at its shootdown too");
    assert!(CALLS.load(Ordering::SeqCst) > calls);
    assert_eq!(level(pt, BLOCK_A), Some(0), "4 KiB pages again");
    assert_eq!(azos_mm::vmm::translate(pt, BLOCK_A + 2 * PAGE_SIZE).map(|p| p % PAGE_SIZE), Some(0));
    assert_eq!(azos_mm::vmm::translate(pt, BLOCK_A + PAGE_SIZE), None, "the page cut out is gone");
}

#[test]
fn a_walker_that_meets_the_park_waits_for_the_leaf() {
    if !on() {
        return;
    }
    let _g = serial();
    let pt = space();
    region(RW);
    let _b = Bbm::arm(pt, true);
    let probe = BLOCK_A + 5 * PAGE_SIZE + 0x123;
    fill(pt, BLOCK_A, PAGES - 1);
    let run = pa(pt, BLOCK_A) & !(MEGA - 1);
    PROBE.store(probe, Ordering::SeqCst);
    touch(pt, BLOCK_A + (PAGES - 1) * PAGE_SIZE);
    assert_eq!(SAW_PARK.load(Ordering::SeqCst), 1);
    let t = PROBER.lock().unwrap().take().expect("the walker thread ran inside the window");
    let e = EMPTY_PROBER.lock().unwrap().take().expect("the reader thread ran inside the window");
    // Not `None` (read as unmapped) and not a fresh table's frame: the block's.
    assert_eq!(t.join().unwrap(), Some(run + 5 * PAGE_SIZE + 0x123));
    assert!(!e.join().unwrap(), "a parked slot is taken, not free for a table or a mapping");
    let m = MAP_PROBER.lock().unwrap().take().expect("the mapper thread ran inside the window");
    assert!(m.join().unwrap(), "a mapper waits for the leaf and finds the page mapped; it builds no table over the run");
    assert_eq!(level(pt, BLOCK_A), Some(1), "still one leaf");
}
