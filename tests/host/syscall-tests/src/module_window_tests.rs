// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the module window (`crates/core/syscall/src/module_window.rs`):
// `SYS_MO_MAP` with `MAP_FIXED_NOREPLACE` places a Linux driver server's
// module memory at an exact address inside the Kconfig window, and nowhere
// else, on the real Sv39 walker (`shims/mm`).

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;

const ANON: u64 = u64::MAX;
const RW: u64 = 3;
const NOREPLACE: u64 = crate::module_window::MMAP_MAP_FIXED_NOREPLACE;

fn win() -> (usize, usize) {
    crate::module_window::window()
}

/// A fresh, empty user page table with a break, as `mmap_guards` makes one.
fn fresh() -> usize {
    let old = azos_sched::current_user_pt();
    if old != 0 {
        azos_mm::pager::forget(old);
    }
    azos_sched::shim_set_sched_class(3);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::pager::forget(pt);
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(1);
    azos_sched::shim_set_page_limit(0);
    azos_sched::shim_set_mem_locked(false);
    azos_sched::shim_set_brk(0x40_0000);
    pt
}

fn place(pt: usize, addr: usize, len: usize, prot: u64) -> i64 {
    crate::module_window::map_fixed(pt, addr as u64, len, prot, true)
}

/// The window the build checked: page-aligned, above the break's ceiling,
/// and within an aarch64 branch of the lowest user address.
#[test]
fn the_window_is_where_kconfig_puts_it() {
    let (lo, hi) = win();
    assert_eq!((lo, hi - lo), (azos_limits::LX_MODULE_WINDOW_BASE, azos_limits::LX_MODULE_WINDOW_SIZE));
    assert!(lo % PAGE_SIZE == 0 && hi > lo);
    assert!(hi - azos_mm::vmm::USER_GUARD_LIMIT <= 1 << 27);
}

/// Inside the window the pages land exactly at the address, committed and
/// read-write, and the break does not move.
#[test]
fn a_placement_inside_the_window_maps_exactly_there_and_leaves_the_break() {
    let _g = serial();
    let pt = fresh();
    let (lo, _) = win();
    let at = lo + 4 * PAGE_SIZE;
    assert_eq!(place(pt, at, 3 * PAGE_SIZE - 100, RW), at as i64);
    for k in 0..3 {
        assert!(azos_mm::vmm::translate_user(pt, at + k * PAGE_SIZE, true).is_some(), "page {k} not mapped writable");
    }
    assert!(azos_mm::vmm::translate_user(pt, at + 3 * PAGE_SIZE, false).is_none(), "one page too many");
    assert_eq!(azos_sched::update_user_brk(0), 0x40_0000, "the break moved");
    // The read-only form maps pages a store cannot use.
    let ro = lo + 16 * PAGE_SIZE;
    assert_eq!(place(pt, ro, PAGE_SIZE, 1), ro as i64);
    assert!(azos_mm::vmm::translate_user(pt, ro, false).is_some());
    assert!(azos_mm::vmm::translate_user(pt, ro, true).is_none(), "PROT_READ gave a writable page");
}

/// Never over a mapping: the overlapping request is `EEXIST` and maps
/// nothing; the page next to it is fine.
#[test]
fn a_placement_over_a_mapped_page_is_eexist_and_replaces_nothing() {
    let _g = serial();
    let pt = fresh();
    let (lo, _) = win();
    assert_eq!(place(pt, lo + PAGE_SIZE, PAGE_SIZE, RW), (lo + PAGE_SIZE) as i64);
    let first = azos_mm::vmm::translate_user(pt, lo + PAGE_SIZE, false);
    assert_eq!(place(pt, lo, 2 * PAGE_SIZE, RW), -17, "overlaps the mapped page");
    assert!(azos_mm::vmm::translate_user(pt, lo, false).is_none(), "the refused request mapped its first page");
    assert_eq!(azos_mm::vmm::translate_user(pt, lo + PAGE_SIZE, false), first, "the mapped page was replaced");
    assert_eq!(place(pt, lo, PAGE_SIZE, RW), lo as i64, "the page below is free");
}

/// Outside the window, straddling either edge, unaligned or `PROT_NONE`:
/// `EINVAL`, nothing mapped.
#[test]
fn a_placement_outside_the_window_or_malformed_is_einval() {
    let _g = serial();
    let pt = fresh();
    let (lo, hi) = win();
    for (at, len, prot, why) in [
        (lo - PAGE_SIZE, PAGE_SIZE, RW, "below the window"),
        (lo - PAGE_SIZE, 2 * PAGE_SIZE, RW, "straddles the base"),
        (hi - PAGE_SIZE, 2 * PAGE_SIZE, RW, "straddles the end"),
        (hi, PAGE_SIZE, RW, "at the end"),
        (0x40_0000, PAGE_SIZE, RW, "at the break"),
        (lo + 8, PAGE_SIZE, RW, "unaligned"),
        (lo, PAGE_SIZE, 0, "PROT_NONE"),
    ] {
        assert_eq!(place(pt, at, len, prot), -22, "{why}");
        assert!(azos_mm::vmm::translate_user(pt, at & !(PAGE_SIZE - 1), false).is_none(), "{why}: mapped");
    }
    assert_eq!(place(pt, hi - PAGE_SIZE, PAGE_SIZE, RW), (hi - PAGE_SIZE) as i64, "the last page is inside");
}

/// Without a module token the placement is `EPERM`. Through `sys_mmap` this
/// host build has no module loader, so no task holds a token.
#[test]
fn without_a_module_token_the_placement_is_eperm() {
    let _g = serial();
    let pt = fresh();
    let (lo, _) = win();
    assert_eq!(crate::module_window::map_fixed(pt, lo as u64, PAGE_SIZE, RW, false), -1);
    assert_eq!(sys_mmap(lo as u64, PAGE_SIZE as u64, RW, NOREPLACE, ANON, 0), -1);
    assert!(azos_mm::vmm::translate_user(pt, lo, false).is_none());
    assert_eq!(azos_sched::update_user_brk(0), 0x40_0000);
    // Without the flag the hint is unread and the break pays, as before.
    assert_eq!(sys_mmap(lo as u64, PAGE_SIZE as u64, RW, 0, ANON, 0), 0x40_0000);
}

/// Out of frame budget: `ENOMEM`, and the charge and the pages go back.
#[test]
fn a_placement_over_budget_is_enomem_and_maps_nothing() {
    let _g = serial();
    let pt = fresh();
    let (lo, _) = win();
    azos_sched::shim_set_page_limit(1);
    assert_eq!(place(pt, lo, 2 * PAGE_SIZE, RW), -12);
    assert!(azos_mm::vmm::translate_user(pt, lo, false).is_none());
    assert_eq!(place(pt, lo, PAGE_SIZE, RW), lo as i64, "the refused charge was given back");
    azos_sched::shim_set_page_limit(0);
}

/// A page the kernel maps for itself inside the window (riscv64 shares the
/// low gigabyte's tables with the kernel) is never handed out.
#[test]
fn a_placement_over_a_kernel_mapping_is_einval() {
    let _g = serial();
    let (_, hi) = win();
    azos_mm::vmm::init(azos_mm::shim_arena_base(), PAGE_SIZE).unwrap();
    azos_mm::vmm::map_mmio_region(hi - PAGE_SIZE, PAGE_SIZE).unwrap();
    let pt = fresh();
    azos_mm::vmm::copy_kernel_entries_to_user(pt);
    assert_eq!(place(pt, hi - 2 * PAGE_SIZE, 2 * PAGE_SIZE, RW), -22);
    assert!(azos_mm::vmm::translate_user(pt, hi - 2 * PAGE_SIZE, false).is_none());
}

/// The frames run out part-way: `ENOMEM`, every page mapped so far freed
/// and unmapped, and the whole charge given back.
#[test]
fn a_placement_that_runs_out_of_frames_unwinds_and_gives_the_charge_back() {
    let _g = serial();
    let pt = fresh();
    let (lo, _) = win();
    let mut ballast = Vec::new();
    while azos_mm::pmm::free_pages() > 100 {
        ballast.push(azos_mm::pmm::alloc_page().expect("drain"));
    }
    let before = azos_mm::shim_pages_in_use();
    assert_eq!(place(pt, lo, 200 * PAGE_SIZE, RW), -12);
    assert!(azos_mm::shim_pages_in_use() <= before + 8, "frames stranded");
    assert!(azos_mm::vmm::translate_user(pt, lo, false).is_none(), "the first page stayed mapped");
    assert_eq!(azos_sched::shim_user_pages(), 0, "the charge was kept");
    drop(ballast);
}
