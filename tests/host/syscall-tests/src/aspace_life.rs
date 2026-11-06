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
    assert_eq!(b.key(), a.key(), "the cache hands the reaped object out first");
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
    assert_eq!(b.key(), a.key(), "the object is the next space");
    azos_mm::pager::reserve(b, BASE, BASE + 4 * PAGE_SIZE, true).expect("reserve");
    assert_eq!(azos_mm::pager::space_pages(b), (4, 0));
    assert_eq!(azos_mm::pager::space_pages(a), (0, 0), "the stale reference reached the next space's records");
    assert!(!azos_mm::pager::contains(a, BASE));
    assert!(not_mapped(azos_mm::vmm::handle_demand_fault(a, BASE)), "a fault through it found a region");
    azos_sched::shim_end_space(other);
}
