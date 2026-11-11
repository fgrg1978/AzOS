// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Every frame-charge site the host shims can drive, with its discharge: the
// real `handlers.rs` (mmap, munmap, brk), `module_window.rs` and the page-table
// hook, over the shim's budget, which is the real `PageBudget`.
//
// One table, one rule: a site that charges is undone by the call that gives
// the memory back, and a site that fails (refused by the budget, refused for
// another reason after the charge) leaves the count where it found it. Each
// row names the site; the assertion message names the row.
//
// What the table CANNOT drive on the host (the charge or its undo sits in
// kernel glue with no shim): `scheduler/budget.rs::table_hook` (the real one:
// the shim's copy is what row `page tables` runs), `mm_charge_request_tid` for
// a fork child (the shim keeps one `OTHER` budget; `fork_clone.rs` covers the
// charge, not the undo on a failed spawn), `ipc/io_ring.rs` buffers (azos_ipc is
// not linked here), `memobj_cap.rs` (MemObj holders), `cap_store.rs` and
// `endpoint.rs` kernel-memory charges (KmemBudget; the ledger is in
// `mm-tests/src/budget_stress.rs`, the sites are in the kernel boot), the
// reclaimer's restore (`kernel/src/tasks/reclaim.rs`) and the `commit_now`
// frame-exhaustion rollback (needs an arena that fails mid-request).

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;

const ANON: u64 = u64::MAX;
const PG: usize = PAGE_SIZE;
const RW: u64 = 3;

fn space() -> usize {
    let old = azos_sched::current_user_pt();
    if old != 0 {
        azos_sched::shim_forget_space(old);
    }
    azos_sched::shim_set_sched_class(3);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(1);
    azos_sched::shim_set_page_limit(0);
    azos_sched::shim_set_mem_locked(false);
    azos_sched::shim_set_brk(0x40_0000);
    pt
}

fn used() -> u32 { azos_sched::shim_user_pages() }

type Row = (&'static str, fn(usize));

/// Reserve, then give back whole: the reservation is charged up front and
/// `munmap` returns it, touched or not.
fn mmap_munmap(pt: usize) {
    let s = azos_sched::shim_space(pt);
    let va = sys_mmap(0, (5 * PG) as u64, RW, 0, ANON, 0);
    assert!(va > 0);
    assert_eq!(used(), 5, "the whole reservation is charged");
    assert!(azos_mm::vmm::handle_demand_fault(s, va as usize + PG).is_ok());
    assert_eq!(used(), 5, "a touch charges nothing more");
    assert_eq!(sys_munmap(va as u64, (5 * PG) as u64), 0);
    assert_eq!(used(), 0, "munmap gives back the reserved and the touched");
}

/// A task committed at map time: every page is charged and committed at once.
fn mmap_committed_munmap(pt: usize) {
    let _ = pt;
    azos_sched::shim_set_mem_locked(true);
    let va = sys_mmap(0, (3 * PG) as u64, RW, 0, ANON, 0);
    assert!(va > 0);
    assert_eq!(used(), 3);
    assert_eq!(sys_munmap(va as u64, (3 * PG) as u64), 0);
    assert_eq!(used(), 0);
    azos_sched::shim_set_mem_locked(false);
}

/// A request the budget cannot hold is refused whole, in either mode.
fn mmap_refused_by_the_budget(pt: usize) {
    let _ = pt;
    for locked in [false, true] {
        azos_sched::shim_set_mem_locked(locked);
        azos_sched::shim_set_page_limit(4);
        assert_eq!(sys_mmap(0, (5 * PG) as u64, RW, 0, ANON, 0), -1, "locked {locked}");
        assert_eq!(used(), 0, "locked {locked}: a refusal charges nothing");
    }
    azos_sched::shim_set_mem_locked(false);
}

/// A hole cut from the middle of a mapping gives back exactly the hole.
fn munmap_a_hole_then_the_rest(pt: usize) {
    let _ = pt;
    let va = sys_mmap(0, (6 * PG) as u64, RW, 0, ANON, 0) as usize;
    assert!(va > 0);
    assert_eq!(sys_munmap((va + 2 * PG) as u64, (2 * PG) as u64), 0);
    assert_eq!(used(), 4, "the hole, and only the hole");
    assert_eq!(sys_munmap(va as u64, (2 * PG) as u64), 0);
    assert_eq!(sys_munmap((va + 4 * PG) as u64, (2 * PG) as u64), 0);
    assert_eq!(used(), 0, "the pieces add up to the whole");
}

/// PROT_NONE reserves nothing and charges nothing.
fn prot_none_charges_nothing(pt: usize) {
    let _ = pt;
    let va = sys_mmap(0, (4 * PG) as u64, 0, 0, ANON, 0);
    assert!(va > 0);
    assert_eq!(used(), 0);
    assert_eq!(sys_munmap(va as u64, (4 * PG) as u64), 0);
    assert_eq!(used(), 0, "and munmap of it gives nothing back");
}

/// The heap: a growth is charged whole; one that the budget or the map refuses
/// leaves the count; a shrink is not supported, so the break and the charge stay
/// until the address space goes (`reset_budget` at exec and exit).
fn brk_grow_refuse_shrink(pt: usize) {
    let _ = pt;
    let b = 0x40_0000u64;
    azos_sched::shim_set_page_limit(6);
    assert_eq!(sys_brk(b + (4 * PG) as u64), b as i64 + (4 * PG) as i64);
    assert_eq!(used(), 4);
    assert_eq!(sys_brk(b + (8 * PG) as u64), b as i64 + (4 * PG) as i64, "refused");
    assert_eq!(used(), 4, "the refused growth charged nothing");
    assert_eq!(sys_brk(b), b as i64 + (4 * PG) as i64, "a shrink is not supported");
    assert_eq!(used(), 4, "so nothing is given back before teardown");
    azos_sched::shim_set_page_limit(6);
    assert_eq!(used(), 0, "teardown (a new declaration resets it here) gives all back");
}

/// The module window: charged on a placement, refused outside the window or
/// over the budget without a charge, and given back by `munmap`.
fn module_window_place_refuse_unmap(pt: usize) {
    let (lo, _) = crate::module_window::window();
    azos_sched::shim_set_page_limit(4);
    let at = lo + 8 * PG;
    assert_eq!(crate::module_window::map_fixed(pt, at as u64, 3 * PG, RW, true), at as i64);
    assert_eq!(used(), 3);
    assert!(crate::module_window::map_fixed(pt, (lo - PG) as u64, PG, RW, true) < 0, "below the window");
    assert_eq!(used(), 3, "a placement outside the window charged nothing");
    assert!(crate::module_window::map_fixed(pt, at as u64, PG, RW, true) < 0, "over a mapped page");
    assert_eq!(used(), 3);
    assert!(crate::module_window::map_fixed(pt, (lo + 32 * PG) as u64, 2 * PG, RW, true) < 0, "3 + 2 is over 4");
    assert_eq!(used(), 3, "a refusal by the budget charged nothing");
    assert_eq!(sys_munmap(at as u64, (3 * PG) as u64), 0);
    assert_eq!(used(), 0, "munmap of a placement gives its pages back");
}

const ROWS: &[Row] = &[
    ("sys_mmap reserve / sys_munmap", mmap_munmap),
    ("sys_mmap committed / sys_munmap", mmap_committed_munmap),
    ("sys_mmap refused by the budget", mmap_refused_by_the_budget),
    ("sys_munmap a hole, then the rest", munmap_a_hole_then_the_rest),
    ("sys_mmap PROT_NONE", prot_none_charges_nothing),
    ("sys_brk grow / refuse / shrink", brk_grow_refuse_shrink),
    ("module window place / refuse / unmap", module_window_place_refuse_unmap),
];

/// **Every charge site the host can drive has its discharge, and every failure
/// leaves the count where it found it.** The table above, one row at a time on a
/// fresh address space and an empty budget; at the end of a row the count is 0.
/// **Canary** (by hand, per row): drop the `mm_discharge` after a refused
/// `commit_now` in `sys_mmap`, or the discharge in `sys_munmap`: the row named in
/// the message goes red.
#[test]
fn every_charge_site_the_host_can_drive_has_its_discharge() {
    let _g = serial();
    for (name, row) in ROWS {
        let pt = space();
        let before = used();
        assert_eq!(before, 0, "{name}: starts empty");
        row(pt);
        assert_eq!(used(), 0, "{name}: the count is back where it started");
        azos_sched::shim_set_page_limit(0);
        azos_sched::shim_set_mem_locked(false);
        azos_sched::shim_forget_space(pt);
        azos_sched::set_current_user_pt(0);
    }
}

/// A random walk over the same sites: the shim's count always equals the pages
/// the mappings the walk holds were charged, whatever the order of maps, holes
/// and refusals, and ends at 0 when they are all gone.
#[test]
fn a_walk_over_mmap_and_munmap_keeps_the_count_equal_to_the_pages_held() {
    let _g = serial();
    let pt = space();
    azos_sched::shim_set_page_limit(40);
    let mut held: Vec<(usize, usize)> = Vec::new(); // (va, pages)
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    for step in 0..600 {
        let total: usize = held.iter().map(|h| h.1).sum();
        if next() % 3 != 0 || held.is_empty() {
            let pages = 1 + (next() % 12) as usize;
            let r = sys_mmap(0, (pages * PG) as u64, RW, 0, ANON, 0);
            if total + pages <= 40 {
                assert!(r > 0, "step {step}: {pages} pages fit ({total} held of 40)");
                held.push((r as usize, pages));
            } else {
                assert_eq!(r, -1, "step {step}: {pages} pages do not fit ({total} held of 40)");
            }
        } else {
            let (va, pages) = held.swap_remove((next() % held.len() as u64) as usize);
            if pages > 1 && next() % 2 == 0 {
                // Cut the head off, keep the tail.
                let cut = 1 + (next() % (pages as u64 - 1)) as usize;
                assert_eq!(sys_munmap(va as u64, (cut * PG) as u64), 0);
                held.push((va + cut * PG, pages - cut));
            } else {
                assert_eq!(sys_munmap(va as u64, (pages * PG) as u64), 0);
            }
        }
        let total: usize = held.iter().map(|h| h.1).sum();
        assert_eq!(used() as usize, total, "step {step}");
    }
    for (va, pages) in held {
        assert_eq!(sys_munmap(va as u64, (pages * PG) as u64), 0);
    }
    assert_eq!(used(), 0);
    azos_sched::shim_set_page_limit(0);
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(0);
}
