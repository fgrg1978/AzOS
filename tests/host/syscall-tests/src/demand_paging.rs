// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Wave 14 (DEMANDPAGE): host rows for demand-paged `mmap`, against the real
// `handlers.rs`, `vmm.rs`, `pager.rs` and `region.rs` on the shim arena.
//
// What each row pins, and its canary:
//
// * The fault entry the trap branches call (`vmm::handle_demand_fault`)
//   commits a region page and nothing outside a region. Canary: feature
//   `demand-region-canary` (the fault path never asks the pagers) turns the
//   commit rows red; the "outside" rows stay green, which is the point of
//   having both.
// * A kernel copy into a reserved page commits it (`translate_user`), so a
//   `read()` into fresh `mmap` memory is not EFAULT. Same canary.
// * Reserve-time charging: `mmap` charges the whole range, a touch charges
//   nothing more, `munmap` gives back committed and uncommitted pages alike.
// * Pre-commit: `MAP_POPULATE`, a locked task and an RT-class task get every
//   page at map time.
//
// Included into `mod handlers` (see `lib.rs`), so `sys_*` resolve directly.

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;

const ANON: u64 = u64::MAX;
const RW: u64 = 3;
const RO: u64 = 1;
const BRK: u64 = 0x10_0000;
/// `Err(KernelError::NotMapped)`: "no region, no marker" — the answer that
/// makes the trap branch kill the task. (This crate does not depend on
/// `azos_common`, so the variant is matched by name.)
fn not_mapped<E: core::fmt::Debug>(r: Result<(), E>) -> bool {
    matches!(r, Err(e) if format!("{e:?}") == "NotMapped")
}

/// A fresh, empty address space with no budget, no lock, best-effort class.
/// The previous test's root leaves the region table first: roots here are
/// never torn down, and a table filled by dead roots would send every later
/// `mmap` down the eager path and make these rows test nothing.
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

fn map(pages: usize, prot: u64, flags: u64) -> usize {
    let r = sys_mmap(0, (pages * PAGE_SIZE) as u64, prot, flags, ANON, 0);
    assert!(r > 0, "mmap failed: {r}");
    r as usize
}

fn committed(pt: usize, va: usize) -> bool {
    matches!(azos_mm::vmm::user_page(pt, va), azos_mm::vmm::UserPage::Leaf { .. })
}

#[test]
fn mmap_reserves_and_commits_nothing() {
    let _g = serial();
    let pt = space();
    let before = azos_mm::shim_pages_in_use();
    let base = map(256, RW, 0); // 1 MiB
    assert_eq!(base, BRK as usize);
    assert_eq!(azos_mm::shim_pages_in_use(), before, "a reservation takes no frame and no table");
    assert_eq!(azos_mm::pager::space_pages(pt), (256, 0));
    assert_eq!(azos_sched::update_user_brk(0), BRK + 256 * PAGE_SIZE as u64, "the break moves past it");
    assert_eq!(azos_sched::shim_user_pages(), 256, "charged in full at reserve time");
    assert!(!committed(pt, base));
}

#[test]
fn the_fault_entry_commits_a_region_page_with_its_permissions() {
    let _g = serial();
    let pt = space();
    let rw = map(4, RW, 0);
    let ro = map(4, RO, 0);

    assert!(azos_mm::vmm::handle_demand_fault(pt, rw + PAGE_SIZE + 0x123).is_ok(), "first touch commits");
    assert_eq!(azos_mm::vmm::user_page(pt, rw + PAGE_SIZE), azos_mm::vmm::UserPage::Leaf { exec: false });
    assert!(azos_mm::vmm::user_write_would_be_permitted(pt, rw + PAGE_SIZE));
    assert!(!committed(pt, rw), "one page per fault");

    assert!(azos_mm::vmm::handle_demand_fault(pt, ro).is_ok());
    assert_eq!(azos_mm::vmm::user_page(pt, ro), azos_mm::vmm::UserPage::Leaf { exec: false });
    assert!(!azos_mm::vmm::user_write_would_be_permitted(pt, ro), "PROT_READ is never writable");
    // A second fault on the committed read-only page (a store to it) is not
    // resolved again: the trap branch kills, as for any read-only page.
    assert!(azos_mm::vmm::handle_demand_fault(pt, ro).is_err());

    assert_eq!(azos_mm::pager::space_pages(pt), (8, 2));
    assert_eq!(azos_sched::shim_user_pages(), 8, "a touch charges nothing more");
}

#[test]
fn a_fault_outside_every_region_is_not_resolved() {
    let _g = serial();
    let pt = space();
    let base = map(4, RW, 0);
    let end = base + 4 * PAGE_SIZE;
    assert!(not_mapped(azos_mm::vmm::handle_demand_fault(pt, end)));
    assert!(not_mapped(azos_mm::vmm::handle_demand_fault(pt, base - PAGE_SIZE)));
    assert!(azos_mm::vmm::handle_demand_fault(pt, 0x10).is_err(), "the null guard holds");
    assert!(!committed(pt, end));
}

#[test]
fn a_kernel_copy_into_fresh_mmap_memory_commits_it() {
    let _g = serial();
    let pt = space();
    let base = map(2, RW, 0);
    assert!(azos_mm::vmm::user_write_would_be_permitted(pt, base + 8), "a reserved RW page is writable");
    assert!(azos_mm::vmm::translate_user(pt, base + 8, true).is_some(), "copy_to_user must not see EFAULT");
    assert!(committed(pt, base));
    let ro = map(1, RO, 0);
    assert!(!azos_mm::vmm::user_write_would_be_permitted(pt, ro));
    assert!(azos_mm::vmm::translate_user(pt, ro, true).is_none(), "nor make a PROT_READ page writable");
    assert!(azos_mm::vmm::translate_user(pt, ro, false).is_some());
}

#[test]
fn a_kernel_copy_into_an_alloc_demand_buffer_commits_it() {
    let _g = serial();
    let pt = space();
    let base = sys_alloc_demand(PAGE_SIZE as u64);
    assert!(base > 0);
    assert!(azos_mm::vmm::translate_user(pt, base as usize, true).is_some());
}

#[test]
fn munmap_frees_committed_pages_and_discharges_the_whole_reservation() {
    let _g = serial();
    let pt = space();
    let base = map(16, RW, 0);
    for i in [0usize, 5, 15] {
        assert!(azos_mm::vmm::translate_user(pt, base + i * PAGE_SIZE, true).is_some());
    }
    let with_three = azos_mm::shim_pages_in_use();
    assert_eq!(sys_munmap(base as u64, (16 * PAGE_SIZE) as u64), 0);
    assert_eq!(azos_mm::shim_pages_in_use(), with_three - 3, "the three committed frames come back");
    assert_eq!(azos_sched::shim_user_pages(), 0, "and all sixteen reserved pages are discharged");
    assert_eq!(azos_mm::pager::space_pages(pt), (0, 0));
    assert!(not_mapped(azos_mm::vmm::handle_demand_fault(pt, base + PAGE_SIZE)), "an unmapped reservation faults like any hole");
}

#[test]
fn munmap_in_the_middle_splits_the_region() {
    let _g = serial();
    let pt = space();
    let base = map(8, RW, 0);
    assert!(azos_mm::vmm::translate_user(pt, base + 3 * PAGE_SIZE, true).is_some());
    assert_eq!(sys_munmap((base + 2 * PAGE_SIZE) as u64, (2 * PAGE_SIZE) as u64), 0);
    assert_eq!(azos_sched::shim_user_pages(), 6);
    assert_eq!(azos_mm::pager::space_pages(pt), (6, 0));
    assert!(azos_mm::vmm::handle_demand_fault(pt, base).is_ok());
    assert!(azos_mm::vmm::handle_demand_fault(pt, base + 2 * PAGE_SIZE).is_err());
    assert!(azos_mm::vmm::handle_demand_fault(pt, base + 4 * PAGE_SIZE).is_ok());
}

#[test]
fn mprotect_read_only_holds_for_pages_committed_later() {
    let _g = serial();
    let pt = space();
    let base = map(4, RW, 0);
    assert_eq!(sys_mprotect(base as u64, (4 * PAGE_SIZE) as u64, RO), 0);
    assert_eq!(azos_sched::shim_user_pages(), 4, "reserved pages are not 'missing': no second charge");
    assert!(!committed(pt, base + PAGE_SIZE), "nor committed by mprotect");
    assert!(azos_mm::vmm::translate_user(pt, base + PAGE_SIZE, true).is_none());
    assert!(azos_mm::vmm::translate_user(pt, base + PAGE_SIZE, false).is_some());
    assert!(!azos_mm::vmm::user_write_would_be_permitted(pt, base + PAGE_SIZE));
    assert_eq!(sys_mprotect(base as u64, (2 * PAGE_SIZE) as u64, RW), 0);
    assert!(azos_mm::vmm::translate_user(pt, base, true).is_some(), "and back to writable");
    assert!(!azos_mm::vmm::user_write_would_be_permitted(pt, base + 2 * PAGE_SIZE));
}

#[test]
fn mprotect_none_drops_the_reservation() {
    let _g = serial();
    let pt = space();
    let base = map(4, RW, 0);
    assert!(azos_mm::vmm::translate_user(pt, base, true).is_some());
    assert_eq!(sys_mprotect(base as u64, (4 * PAGE_SIZE) as u64, 0), 0);
    assert_eq!(azos_sched::shim_user_pages(), 0);
    assert_eq!(azos_mm::pager::space_pages(pt), (0, 0));
    assert!(azos_mm::vmm::handle_demand_fault(pt, base + PAGE_SIZE).is_err());
    // Below the break and empty again: mprotect maps it eagerly, as before.
    assert_eq!(sys_mprotect(base as u64, (4 * PAGE_SIZE) as u64, RW), 0);
    assert_eq!(azos_sched::shim_user_pages(), 4);
    assert!(committed(pt, base + 3 * PAGE_SIZE));
}

#[test]
fn populate_locked_and_rt_tasks_commit_at_map_time() {
    let _g = serial();
    for how in 0..4 {
        let pt = space();
        let flags = match how {
            0 => MMAP_MAP_POPULATE,
            1 => MMAP_MAP_LOCKED,
            2 => {
                azos_sched::shim_set_mem_locked(true);
                0
            }
            _ => {
                azos_sched::shim_set_sched_class(1); // HardRT
                0
            }
        };
        let before = azos_mm::shim_pages_in_use();
        let base = map(8, RW, flags);
        assert!(azos_mm::shim_pages_in_use() >= before + 8, "case {how}: every page now");
        assert!(committed(pt, base) && committed(pt, base + 7 * PAGE_SIZE), "case {how}");
        assert_eq!(azos_mm::pager::space_pages(pt), (0, 0), "case {how}: no region left to fault on");
        assert_eq!(azos_sched::shim_user_pages(), 8, "case {how}");
    }
    // Best-effort again: reserve.
    let pt = space();
    map(8, RW, 0);
    assert_eq!(azos_mm::pager::space_pages(pt), (8, 0));
}

#[test]
fn a_fork_child_inherits_the_reservation_and_is_charged_for_it() {
    let _g = serial();
    let pt = space();
    let base = map(8, RW, 0);
    assert!(azos_mm::vmm::translate_user(pt, base, true).is_some());
    assert!(azos_mm::vmm::translate_user(pt, base + PAGE_SIZE, true).is_some());

    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let child = azos_mm::vmm::fork_cow(pt, shm_lo, shm_hi).expect("fork");
    azos_mm::pager::forget(child);
    azos_sched::shim_set_other_task(2, child, 0);
    assert!(fork_regions_to_child(2));
    assert_eq!(azos_mm::pager::space_pages(child), (8, 2), "the records, and what the COW fork shares");
    assert_eq!(azos_sched::shim_other_pages(), 6, "charged for the six it may still commit");
    azos_mm::pager::forget(child);
    azos_mm::vmm::destroy_user_pagetable_skip_range(child, shm_lo, shm_hi);

    // A child whose budget cannot take it: the fork is refused, no records stay.
    let child = azos_mm::pmm::alloc_page().unwrap().as_usize();
    azos_mm::pager::forget(child);
    azos_sched::shim_set_other_task(3, child, 5);
    assert!(!fork_regions_to_child(3));
    assert_eq!(azos_mm::pager::space_pages(child), (0, 0));
}

/// **A page a sibling thread commits during a fork is the child's to pay
/// for (wave 14, FORKSPAWN).** The fork's copy-on-write walk runs first and
/// `fork_regions_to_child` after it, with only the layout lock held: another
/// thread of the parent can commit a region page in between. The child does
/// not have that page (the walk had passed it), but the parent's committed
/// counter, which the child took, did, so the child was charged one page
/// short and could commit it unpaid. The child now counts its own.
///
/// **Canary.** Feature `azos_mm/fork-commit-race-canary`: the child takes
/// the parent's counter and is charged 5.
#[test]
fn a_page_committed_during_the_fork_is_charged_to_the_child() {
    let _g = serial();
    let pt = space();
    let base = map(8, RW, 0);
    assert!(azos_mm::vmm::translate_user(pt, base, true).is_some());
    assert!(azos_mm::vmm::translate_user(pt, base + PAGE_SIZE, true).is_some());

    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let child = azos_mm::vmm::fork_cow(pt, shm_lo, shm_hi).expect("fork");
    // The sibling's commit, after the walk and before the regions are cloned.
    assert!(azos_mm::vmm::translate_user(pt, base + 2 * PAGE_SIZE, true).is_some());
    assert_eq!(azos_mm::pager::space_pages(pt), (8, 3));

    azos_mm::pager::forget(child);
    azos_sched::shim_set_other_task(2, child, 0);
    assert!(fork_regions_to_child(2));
    assert_eq!(azos_mm::pager::space_pages(child), (8, 2), "the child holds two of the eight");
    assert_eq!(azos_sched::shim_other_pages(), 6, "and may still commit six, all charged");
    assert!(!committed(child, base + 2 * PAGE_SIZE));
    azos_mm::pager::forget(child);
    azos_mm::vmm::destroy_user_pagetable_skip_range(child, shm_lo, shm_hi);
}

#[test]
fn a_reservation_refuses_an_occupied_range_as_the_eager_path_did() {
    let _g = serial();
    let pt = space();
    let page = azos_mm::pmm::alloc_page().unwrap().as_usize();
    let occupied = BRK as usize + 2 * PAGE_SIZE;
    azos_mm::vmm::map(pt, occupied, page, azos_arch_api::PagePerms::USER_RW).unwrap();
    assert_eq!(sys_mmap(0, (4 * PAGE_SIZE) as u64, RW, 0, ANON, 0), -1);
    assert_eq!(azos_sched::update_user_brk(0), BRK, "nothing moved");
    assert_eq!(azos_sched::shim_user_pages(), 0, "nothing charged");
    assert_eq!(azos_mm::pager::space_pages(pt), (0, 0));
}

#[test]
fn page_table_teardown_forgets_the_regions() {
    let _g = serial();
    let pt = space();
    map(4, RW, 0);
    assert_eq!(azos_mm::pager::space_pages(pt), (4, 0));
    azos_mm::vmm::destroy_user_pagetable(pt);
    assert_eq!(azos_mm::pager::space_pages(pt), (0, 0));
    azos_sched::set_current_user_pt(0);
}

#[test]
fn consecutive_maps_fold_into_one_record() {
    let _g = serial();
    let pt = space();
    for _ in 0..(2 * azos_mm::pager::REGIONS_PER_SPACE) {
        map(1, RW, 0);
    }
    // Twice as many maps as records, all reserved: they folded.
    let n = 2 * azos_mm::pager::REGIONS_PER_SPACE;
    assert_eq!(azos_mm::pager::space_pages(pt), (n, 0));
}
