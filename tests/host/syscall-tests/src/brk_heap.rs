// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host rows for the program break (`sys_brk`, the Linux personality's) as an
// anonymous mapping, against the real `handlers.rs`, `pager.rs`, `mapping.rs`
// and `anon_obj.rs` on the shim arena.
//
// What each row pins, and its canary (by hand; discriminates / does not / did
// not compile):
//
// * A growth reserves, folds into the heap's one mapping, takes no frame and is
//   charged once; a touch commits a page and charges nothing more. Canary:
//   `pager::reserve` not folding into the mapping beside it: the one-record
//   assertion goes red.
// * A growth the budget cannot hold whole is refused whole: the break stays,
//   nothing is charged or reserved (the per-page charge granted part of it).
//   Canary: `sys_brk` charging and reserving one page at a time up to the
//   limit: red at "the break stays".
// * A growth over something already mapped is refused and gives its charge
//   back. Canary: drop the `mm_discharge` of the refusal: red at "nothing
//   stays charged".
// * A task committed at map time (`mem = "locked"`) gets every page at once
//   and no mapping record. Canary: `sys_brk` ignoring `mmap_precommit`: red.
// * A query, a shrink and a break past the mmap floor answer the break as it
//   is.
// * A row's ceiling (`mem_pages_max`, `shim_set_page_ceiling` here): a growth
//   past the base is had up to the ceiling, the limit growing by the request,
//   and refused whole past it; a real-time task's never grows. Canary
//   `budget-ceiling-ignored-canary` (the ceiling holds nothing): red at "past
//   the ceiling"; by hand, `request_may_grow` answering `true`: red at "real
//   time never grows". The growth pool (`azos_mm::budget::set_growth_pool`):
//   a growth past what it holds is refused whole (canary
//   `budget-pool-ignored-canary`); a fork child starts from the base and its
//   growth past it is its own, from the pool.
// * With the pool on (`MM_RECLAIM_COMPRESS`, its gate row): a heap page the
//   reclaimer stores leaves a marker in its slot and an empty leaf, and its
//   next touch restores its bytes. Canary: `mm-pte-truth-canary` (the leaf
//   believed over the slot) makes it a zero page.
//
// Included into `mod handlers` (see `lib.rs`), so `sys_*` resolve directly.

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;

const BRK: u64 = 0x10_0000;
const PG: u64 = PAGE_SIZE as u64;

/// A fresh, empty Linux-personality address space at break `BRK`, no budget.
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

fn done(pt: usize) {
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(0);
}

fn leaf(pt: usize, va: u64) -> bool {
    matches!(azos_mm::vmm::user_page(pt, va as usize), azos_mm::vmm::UserPage::Leaf { .. })
}

#[test]
fn a_heap_growth_is_one_mapping_charged_once() {
    let _g = serial();
    let pt = space();
    let s = azos_sched::shim_space(pt);
    let frames = azos_mm::shim_pages_in_use();
    assert_eq!(sys_brk(0), BRK as i64, "a query answers the break");
    assert_eq!(sys_brk(BRK + 3 * PG + 5), (BRK + 4 * PG) as i64, "the break moves to a page boundary");
    assert_eq!(azos_sched::shim_user_pages(), 4, "the whole growth, charged once");
    assert_eq!(azos_mm::pager::space_pages(s), (4, 0), "reserved, nothing committed");
    assert_eq!(azos_mm::shim_pages_in_use(), frames, "no frame and no table for a reservation");
    assert_eq!(sys_brk(BRK + 8 * PG), (BRK + 8 * PG) as i64);
    assert_eq!(azos_mm::pager::shim_mappings(s), 1, "the growth folds into the heap's mapping");
    assert_eq!(azos_mm::pager::space_pages(s), (8, 0));
    assert_eq!(azos_sched::shim_user_pages(), 8);
    let va = BRK + 5 * PG;
    assert!(azos_mm::vmm::handle_demand_fault(s, va as usize + 0x10).is_ok(), "a touch commits");
    assert!(leaf(pt, va) && !leaf(pt, va + PG), "one page per touch");
    assert_eq!(azos_mm::pager::space_pages(s), (8, 1));
    assert_eq!(azos_sched::shim_user_pages(), 8, "and charges nothing more");
    let pa = azos_mm::vmm::translate_user(pt, (BRK + 7 * PG) as usize, true).expect("a kernel copy commits");
    // SAFETY: a frame of the host arena, which the shim identity-maps.
    let page = unsafe { core::slice::from_raw_parts(azos_mm::addr::phys_to_virt(pa & !(PAGE_SIZE - 1)) as *const u8, PAGE_SIZE) };
    assert!(page.iter().all(|&b| b == 0), "a zero page");
    done(pt);
}

#[test]
fn a_growth_past_the_budget_is_refused_whole() {
    let _g = serial();
    let pt = space();
    let s = azos_sched::shim_space(pt);
    azos_sched::shim_set_page_limit(6);
    assert_eq!(sys_brk(BRK + 4 * PG), (BRK + 4 * PG) as i64);
    assert_eq!(sys_brk(BRK + 8 * PG), (BRK + 4 * PG) as i64, "the break stays");
    assert_eq!(azos_sched::shim_user_pages(), 4, "nothing of the refused growth is charged");
    assert_eq!(azos_mm::pager::space_pages(s), (4, 0), "nor reserved");
    assert_eq!(sys_brk(BRK + 6 * PG), (BRK + 6 * PG) as i64, "a growth that fits is had");
    assert_eq!(azos_sched::shim_user_pages(), 6);
    done(pt);
}

#[test]
fn a_growth_over_a_mapped_page_is_refused() {
    let _g = serial();
    let pt = space();
    let s = azos_sched::shim_space(pt);
    let page = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    let rw = azos_arch_api::PagePerms { accessed: true, dirty: true, ..azos_arch_api::PagePerms::USER_RW };
    azos_mm::vmm::map(pt, (BRK + 2 * PG) as usize, page, rw).unwrap();
    assert_eq!(sys_brk(BRK + 4 * PG), BRK as i64, "the break stays");
    assert_eq!(azos_sched::shim_user_pages(), 0, "nothing stays charged");
    assert_eq!(azos_mm::pager::space_pages(s), (0, 0), "and nothing is reserved");
    assert_eq!(sys_brk(BRK + 2 * PG), (BRK + 2 * PG) as i64, "up to it is had");
    done(pt);
}

#[test]
fn a_locked_tasks_heap_is_committed_at_once() {
    let _g = serial();
    let pt = space();
    let s = azos_sched::shim_space(pt);
    azos_sched::shim_set_mem_locked(true);
    assert_eq!(sys_brk(BRK + 3 * PG), (BRK + 3 * PG) as i64);
    assert!((0..3).all(|i| leaf(pt, BRK + i * PG)), "every page is there");
    assert_eq!(azos_mm::pager::space_pages(s), (0, 0), "with no mapping to fault through");
    assert_eq!(azos_sched::shim_user_pages(), 3);
    azos_sched::shim_set_mem_locked(false);
    done(pt);
}

#[test]
fn a_shrink_or_a_break_past_the_floor_answers_the_break() {
    let _g = serial();
    let pt = space();
    assert_eq!(sys_brk(BRK + 2 * PG), (BRK + 2 * PG) as i64);
    assert_eq!(sys_brk(BRK), (BRK + 2 * PG) as i64, "a shrink is not done");
    let floor = azos_sched::user_mmap_area().0 as u64;
    assert_eq!(sys_brk(floor + PG), (BRK + 2 * PG) as i64, "the break stops below the mmap area");
    assert_eq!(sys_brk(u64::MAX), (BRK + 2 * PG) as i64, "no wrap at the top");
    assert_eq!(azos_sched::shim_user_pages(), 2);
    done(pt);
}

#[test]
fn a_heap_page_the_reclaimer_stores_comes_back_through_its_slot() {
    use azos_mm::pager::{Ages, AnonReclaim, Victim};
    use azos_mm::zpool::Reclaimee;
    if !azos_mm::zpool::ENABLED {
        return;
    }
    let _g = serial();
    azos_crypto::entropy::mix(&[0x5b; 64], 512);
    let pt = space();
    let s = azos_sched::shim_space(pt);
    assert_eq!(sys_brk(BRK + 2 * PG), (BRK + 2 * PG) as i64);
    let va = (BRK + PG) as usize;
    let f = azos_mm::vmm::translate_user(pt, va, true).expect("a kernel copy commits") & !(PAGE_SIZE - 1);
    // SAFETY: a frame of the host arena, which the shim identity-maps.
    unsafe { core::slice::from_raw_parts_mut(azos_mm::addr::phys_to_virt(f) as *mut u8, PAGE_SIZE) }.fill(0xB7);
    let roots = [Some(s)];
    let mut ages = Ages::new();
    let mut reclaim = AnonReclaim::new(&roots, 0, &mut ages);
    let victim = Victim { space: pt, va };
    assert!(reclaim.unmap(victim));
    assert!(reclaim.store(victim).is_ok(), "the heap page is in the pool");
    reclaim.free(victim);
    assert!(azos_mm::vmm::translate(pt, va).is_none(), "its leaf is empty");
    assert!(azos_mm::vmm::handle_demand_fault(s, va).is_ok());
    let back = azos_mm::vmm::translate(pt, va).expect("restored") & !(PAGE_SIZE - 1);
    // SAFETY: as above.
    let page = unsafe { core::slice::from_raw_parts(azos_mm::addr::phys_to_virt(back) as *const u8, PAGE_SIZE) };
    assert!(page.iter().all(|&b| b == 0xB7), "the stored page, not a zero one");
    done(pt);
}

#[test]
fn a_heap_grows_past_its_base_up_to_the_ceiling() {
    let _g = serial();
    let pt = space();
    azos_mm::budget::set_growth_pool(1 << 20);
    azos_sched::shim_set_page_limit(4);
    azos_sched::shim_set_page_ceiling(10);
    assert_eq!(sys_brk(BRK + 4 * PG), (BRK + 4 * PG) as i64, "within the base");
    assert_eq!(sys_brk(BRK + 7 * PG), (BRK + 7 * PG) as i64, "past the base, within the ceiling");
    assert_eq!(azos_sched::shim_page_limit_grown(), (7, 3), "the limit grew by the request");
    assert_eq!(sys_brk(BRK + 11 * PG), (BRK + 7 * PG) as i64, "past the ceiling: refused whole");
    assert_eq!(azos_sched::shim_user_pages(), 7, "nothing of it charged");
    assert_eq!(sys_brk(BRK + 10 * PG), (BRK + 10 * PG) as i64, "up to the ceiling");
    assert_eq!(azos_sched::shim_page_limit_grown(), (10, 6));
    done(pt);
}

#[test]
fn a_real_time_heap_does_not_grow() {
    let _g = serial();
    let pt = space();
    azos_mm::budget::set_growth_pool(1 << 20);
    azos_sched::shim_set_page_limit(4);
    azos_sched::shim_set_page_ceiling(10);
    azos_sched::shim_set_sched_class(1);
    assert_eq!(sys_brk(BRK + 6 * PG), BRK as i64, "real time never grows");
    assert_eq!(azos_sched::shim_user_pages(), 0);
    azos_sched::shim_set_sched_class(3);
    done(pt);
}

/// **A heap's growth is the growth pool's.** With 2 pages left in the pool, a
/// growth that needs 3 past the base is refused whole, one that needs 2 is
/// had, and the pool is then empty.
/// **Canary** `budget-pool-ignored-canary`: the 3-page growth is had.
#[test]
fn a_heap_grows_only_as_far_as_the_growth_pool() {
    let _g = serial();
    let pt = space();
    azos_mm::budget::set_growth_pool(2);
    azos_sched::shim_set_page_limit(4);
    azos_sched::shim_set_page_ceiling(10);
    assert_eq!(sys_brk(BRK + 4 * PG), (BRK + 4 * PG) as i64);
    assert_eq!(sys_brk(BRK + 7 * PG), (BRK + 4 * PG) as i64, "3 past the base, 2 in the pool");
    assert_eq!(sys_brk(BRK + 6 * PG), (BRK + 6 * PG) as i64);
    assert_eq!(azos_mm::budget::growth_pool(), 0);
    done(pt);
}

/// **A fork child starts from the row's base, and its growth is its own.**
/// The parent grew past its base; the child is given the base and the
/// ceiling, and what it inherits past the base is a growth of its own from
/// the pool, not the parent's limit handed on.
/// **Canary** (by hand): `fork_regions_to_child` charging the child within its
/// limit only (`mm_charge_request_tid(.., false)`): red at "the child grew".
#[test]
fn a_fork_childs_growth_past_its_base_is_its_own() {
    let _g = serial();
    let pt = space();
    azos_mm::budget::set_growth_pool(1 << 20);
    azos_sched::shim_set_page_limit(4);
    azos_sched::shim_set_page_ceiling(16);
    assert_eq!(sys_brk(BRK + 8 * PG), (BRK + 8 * PG) as i64, "the parent grows to 8");
    let pool = azos_mm::budget::growth_pool();
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let child = azos_mm::vmm::fork_cow(pt, shm_lo, shm_hi).expect("fork");
    azos_sched::shim_forget_space(child);
    azos_sched::shim_set_other_task(2, child, 4);
    azos_sched::shim_set_other_ceiling(16);
    assert!(fork_regions_to_child(2));
    assert_eq!(azos_sched::shim_other_limit_grown(), (8, 4), "the child grew from its base");
    assert_eq!(azos_mm::budget::growth_pool(), pool - 4, "from the pool");
    azos_sched::shim_forget_space(child);
    azos_mm::vmm::destroy_user_pagetable_skip_range(child, shm_lo, shm_hi);
    done(pt);
}
