// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The address space object's life (`crates/core/mm/src/aspace.rs`), against
// the real `aspace.rs`, `pager.rs` and `vmm.rs` on the shim arena, whose
// object cache hands a freed object out again first, as the kernel's does.
//
// * A space that ends takes its records with it, so the next space made from
//   the same object starts with none (the code half of `mm.tla`'s
//   `DestroyLeavesNothing`). Canary `as-stale-root-canary`: the end leaves the
//   records in the object, and the next space has the dead one's region.
// * A reference kept past its space's end (the reclaimer reads them from task
//   slots) reaches nothing, also once the object is another space. Canary
//   `as-stale-ref-canary`: the root is not compared, and the stale reference
//   sees the next space's region.
//
// Included into `mod handlers` (see `lib.rs`).

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;

const BASE: usize = 0x40_0000;

fn not_mapped<E: core::fmt::Debug>(r: Result<(), E>) -> bool {
    matches!(r, Err(e) if format!("{e:?}") == "NotMapped")
}

/// The object a reference names: the low bits of its key (`aspace::tag_of`).
fn object(r: azos_mm::aspace::SpaceRef) -> usize {
    r.key() & ((1 << 48) - 1)
}

/// A root no space has yet.
fn root() -> usize {
    azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize()
}

#[test]
fn a_space_made_from_a_reaped_object_starts_with_no_records() {
    let _g = serial();
    let pt = root();
    let a = azos_sched::shim_space(pt);
    azos_mm::pager::reserve(a, BASE, BASE + 8 * PAGE_SIZE, true).expect("reserve");
    assert_eq!(azos_mm::pager::space_pages(a), (8, 0));
    azos_sched::shim_end_space(pt);

    let b = azos_sched::shim_space(root());
    assert_eq!(object(b), object(a), "the cache hands the reaped object out first");
    assert_eq!(azos_mm::pager::space_pages(b), (0, 0), "the dead space's region came with the object");
    assert!(not_mapped(azos_mm::vmm::handle_demand_fault(b, BASE)), "a touch of the dead space's range is a hole");
    assert!(azos_mm::pager::reserve(b, BASE, BASE + PAGE_SIZE, true).is_ok(), "and the range is free");
    azos_sched::shim_end_space(b.root());
}

#[test]
fn a_reference_kept_past_its_space_reaches_nothing() {
    let _g = serial();
    let pt = root();
    // Another root for the next space, taken first so it is not the freed one
    // and the stale reference does not name the new space.
    let other = root();
    let a = azos_sched::shim_space(pt);
    azos_sched::shim_end_space(pt);
    assert_eq!(azos_mm::pager::space_pages(a), (0, 0));
    assert!(azos_mm::pager::reserve(a, BASE, BASE + PAGE_SIZE, true).is_err(), "an ended space takes no region");

    let b = azos_sched::shim_space(other);
    assert_eq!(object(b), object(a), "the object is the next space");
    azos_mm::pager::reserve(b, BASE, BASE + 4 * PAGE_SIZE, true).expect("reserve");
    assert_eq!(azos_mm::pager::space_pages(b), (4, 0));
    assert_eq!(azos_mm::pager::space_pages(a), (0, 0), "the stale reference reached the next space's records");
    assert!(!azos_mm::pager::contains(a, BASE));
    assert!(not_mapped(azos_mm::vmm::handle_demand_fault(a, BASE)), "a fault through it found a region");
    azos_sched::shim_end_space(other);
}

const ANON: u64 = u64::MAX;
const RW: u64 = 3;
const BRK: u64 = 0x10_0000;

/// The current task runs on the space of `pt` with one resident anonymous
/// page; its address.
fn resident_page_on(pt: usize) -> usize {
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(1);
    azos_sched::shim_set_page_limit(0);
    azos_sched::shim_set_mem_locked(false);
    azos_sched::shim_set_sched_class(3);
    azos_sched::shim_set_brk(BRK);
    let va = sys_mmap(0, PAGE_SIZE as u64, RW, 0, ANON, 0);
    assert_eq!(va, BRK as i64, "mmap failed: {va}");
    assert!(azos_mm::vmm::handle_demand_fault(azos_sched::shim_space(pt), va as usize).is_ok());
    va as usize
}

/// End the space of `pt` and make the next one over the same frame: the
/// page-table allocator hands the freed root out first, as the object cache
/// does its object, so the new space is the same object over the same root.
fn same_root_again(pt: usize) {
    azos_sched::set_current_user_pt(0);
    azos_sched::shim_end_space(pt);
    assert_eq!(root(), pt, "the freed root is the next page-table frame");
}

// The reclaimer reads a Domain's spaces once per pass. A space that ends in
// the pass and comes back as the same object over the same root (another
// process) is not the one it read: the stale reference takes none of its
// pages. Canary `as-gen-unchecked-canary`: only the root is compared, and the
// page of the new space is taken out under the old one's Domain.
#[test]
fn a_reference_kept_past_its_space_takes_nothing_from_a_space_on_the_same_root() {
    use azos_mm::pager::{Ages, AnonReclaim, Victim};
    use azos_mm::zpool::Reclaimee;
    let _g = serial();
    let pt = root();
    resident_page_on(pt);
    let a = azos_sched::shim_space(pt);
    same_root_again(pt);
    let va = resident_page_on(pt);
    let b = azos_sched::shim_space(pt);
    assert_eq!((b.root(), object(b)), (a.root(), object(a)), "same root, same object");
    assert_ne!(b, a, "but another space");

    assert_eq!(azos_mm::pager::space_pages(a), (0, 0), "the stale reference reached the next space's records");
    let victim = Victim { space: pt, va };
    let stale = [Some(a)];
    let mut ages = Ages::new();
    let mut reclaim = AnonReclaim::new(&stale, 0, &mut ages);
    assert!(!reclaim.unmap(victim), "the stale reference took a page of the next space");
    assert!(azos_mm::vmm::translate(pt, va).is_some(), "the page stayed mapped");

    let live = [Some(b)];
    let mut ages = Ages::new();
    let mut reclaim = AnonReclaim::new(&live, 0, &mut ages);
    assert!(reclaim.unmap(victim), "the live reference takes it");
    reclaim.keep(victim);
    azos_sched::set_current_user_pt(0);
    azos_sched::shim_end_space(pt);
}

// A store of the reclaimer can outlive its space: the page is out of the dead
// space's table and the store runs on. The next space, the same object over
// the same root, has a page of its own in the pool at the same address. The
// late store is the dead space's, under its own key, and leaves that page
// alone. Canary `as-key-no-gen-canary`: the key is the object alone, the late
// store replaces the new space's entry and the next touch finds the page lost.
// Needs the compressed pool (Kconfig MM_RECLAIM_COMPRESS: the gate's row runs
// it under that configuration); without it there is no store to race.
#[test]
fn a_store_that_outlives_its_space_leaves_the_next_space_page_alone() {
    use azos_mm::pager::{Ages, AnonReclaim, Victim};
    use azos_mm::zpool::Reclaimee;
    if !azos_mm::zpool::ENABLED {
        return;
    }
    let _g = serial();
    azos_crypto::entropy::mix(&[0x5a; 64], 512);
    let pt = root();
    let va = resident_page_on(pt);
    let a = azos_sched::shim_space(pt);
    let victim = Victim { space: pt, va };
    let dead = [Some(a)];
    let mut dead_ages = Ages::new();
    let mut late = AnonReclaim::new(&dead, 0, &mut dead_ages);
    assert!(late.unmap(victim), "the dead space's page is out: its store is in flight");
    same_root_again(pt);

    assert_eq!(resident_page_on(pt), va);
    let b = azos_sched::shim_space(pt);
    let frame = azos_mm::vmm::translate(pt, va).expect("mapped");
    // SAFETY: the new space's own frame, mapped by the host arena.
    unsafe { core::ptr::write_bytes(azos_mm::addr::phys_to_virt(frame) as *mut u8, 0xC3, PAGE_SIZE) };
    let live = [Some(b)];
    let mut ages = Ages::new();
    let mut reclaim = AnonReclaim::new(&live, 0, &mut ages);
    assert!(reclaim.unmap(victim));
    assert!(reclaim.store(victim).is_ok(), "the new space's page is in the pool");
    reclaim.free(victim);
    assert!(azos_mm::vmm::translate(pt, va).is_none(), "and out of its table");

    // The dead space's store ends now.
    assert!(late.store(victim).is_err(), "a store of an ended space is published");
    late.keep(victim);

    assert!(azos_mm::vmm::handle_demand_fault(b, va).is_ok(), "the new space's page was lost");
    let frame = azos_mm::vmm::translate(pt, va).expect("restored");
    // SAFETY: as above.
    let bytes = unsafe { core::slice::from_raw_parts(azos_mm::addr::phys_to_virt(frame) as *const u8, PAGE_SIZE) };
    assert!(bytes.iter().all(|&x| x == 0xC3), "the restored page is not the new space's");
    azos_sched::set_current_user_pt(0);
    azos_sched::shim_end_space(pt);
}
