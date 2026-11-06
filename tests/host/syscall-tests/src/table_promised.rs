// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host rows for the page tables of a reserved range: `mmap` charges the pages
// of a range whole, not the tables its first touches build, and a touch of a
// page the charge covers must not die for a table. The real `handlers.rs`,
// `vmm.rs` and `pager.rs` on the shim arena, with the shim's table hook
// charging the budget the way `scheduler/budget.rs` does.
//
// The slot chunk a page past the object's inline slots needs is charged within
// the limit: canary `slot-chunk-promised-canary` charges it past the limit and
// the refused touch goes through.
//
// Canary: `pager::fault_once` walking with `vmm::walk(.., true)` instead of
// `vmm::walk_level(.., promised)` hands a table to the budget as refusable: the first
// touch at the limit is refused and `a_touch_at_the_limit_gets_its_tables` fails.
//
// Included into `mod handlers` (see `lib.rs`), so `sys_*` resolve directly.

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;

const ANON: u64 = u64::MAX;
const RW: u64 = 3;
const BRK: u64 = 0x10_0000;
/// 2 MiB from 1 MiB: [1, 2) and [2, 3) MiB, two blocks, neither wholly inside
/// the region, so no superpage reservation takes the touch.
const REGION_PAGES: usize = 2 * 1024 * 1024 / PAGE_SIZE;

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

#[test]
fn a_touch_at_the_limit_gets_its_tables() {
    let _g = serial();
    let pt = space();
    azos_sched::shim_set_page_limit(REGION_PAGES as u32);
    azos_sched::shim_charge_tables(true);
    let base = sys_mmap(0, (REGION_PAGES * PAGE_SIZE) as u64, RW, 0, ANON, 0);
    assert_eq!(base, BRK as i64, "the range is the whole budget: {base}");
    assert_eq!(azos_sched::shim_user_pages() as usize, REGION_PAGES);

    let frames = azos_mm::shim_pages_in_use();
    // One page in each block: the first builds the level-1 and level-0 tables,
    // the second a level-0 table of its own.
    let a = BRK as usize;
    let b = 2 * 1024 * 1024 + PAGE_SIZE;
    // The page in the next block is past the object's inline slots: it needs
    // a chunk of slot words (`anon_obj.rs`), kernel memory the reservation did
    // not count, which the limit refuses: the touch is refused before a table
    // is built.
    let refused = azos_mm::vmm::handle_demand_fault(azos_sched::shim_space(pt), b);
    assert!(refused.is_err(), "a slot chunk was charged past the limit");
    assert_eq!(azos_mm::shim_pages_in_use(), frames, "nothing taken for the refused touch");
    // Room for the chunk (the limit again, the reservation charged again).
    azos_sched::shim_set_page_limit(REGION_PAGES as u32 + 1);
    assert!(azos_sched::mm_charge(REGION_PAGES as u32));
    let second = azos_mm::vmm::handle_demand_fault(azos_sched::shim_space(pt), b);
    let first = azos_mm::vmm::handle_demand_fault(azos_sched::shim_space(pt), a);
    azos_sched::shim_charge_tables(false);
    assert!(second.is_ok(), "the touch in the next block was refused: {second:?}");
    assert!(first.is_ok(), "the touch at the limit was refused: {first:?}");

    let built = azos_mm::shim_pages_in_use() - frames - 2;
    assert_eq!(built, 3 + 1, "three tables and a slot chunk for two touches");
    assert_eq!(azos_sched::shim_user_pages() as usize, REGION_PAGES + built, "each table and the chunk are charged, the tables past the limit");
    azos_sched::shim_set_page_limit(0);
}

#[test]
fn a_range_past_the_limit_is_still_refused_after_the_tables_took_theirs() {
    let _g = serial();
    let pt = space();
    azos_sched::shim_set_page_limit(REGION_PAGES as u32);
    azos_sched::shim_charge_tables(true);
    let base = sys_mmap(0, (REGION_PAGES * PAGE_SIZE) as u64, RW, 0, ANON, 0);
    assert_eq!(base, BRK as i64);
    assert!(azos_mm::vmm::handle_demand_fault(azos_sched::shim_space(pt), BRK as usize).is_ok());
    let more = sys_mmap(0, PAGE_SIZE as u64, RW, 0, ANON, 0);
    azos_sched::shim_charge_tables(false);
    assert_eq!(more, -1, "the limit is still the limit");
    azos_sched::shim_set_page_limit(0);
}
