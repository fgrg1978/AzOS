// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// A physical range lent to a task is a record of its address space
// (`pager::Backing::Phys`): placed in the mmap area, torn down by its record,
// never executable, never taken back by the task, and given to a fork's child
// only when it says so. On the real `phys_map.rs`, `handlers.rs`, `pager.rs`,
// `mapping.rs` and `vmm.rs` over the shim arena.
//
// * `a_space_that_ends_leaves_a_physical_range_to_its_owner`: the range's frame
//   is the owner's; the space's end clears the leaf and frees nothing. Canary
//   `mm-rmap-missing-canary` (the leaves stay, the sweep frees the frame).
// * `a_physical_range_is_never_made_executable`: the exec flip refuses it.
//   Canary `exec-shared-record-canary`.
// * `a_task_cannot_unmap_a_physical_range` and
//   `a_task_cannot_reprotect_a_physical_range`: `munmap` and `mprotect` refuse it
//   whole; only its owner ends it. Canary `phys-grant-ends-by-owner-canary`.
// * `a_fork_gives_the_child_only_the_ranges_that_say_so`: an inheriting range is
//   the child's too, the same frame with no reference counted; any other is
//   absent from the child. Canary `phys-inherit-ignored-canary` (the flag
//   is inverted).
// * `a_range_with_no_record_room_maps_nothing`: a map the space cannot record
//   makes no leaf. Canary `phys-leaves-unrecorded-canary`.
// * `a_threads_vdso_page_leaves_the_group_space_when_the_thread_ends`: the
//   per-task page is the pool slot's, which another task is given. Canary
//   `vdso-page-kept-canary`.
// * `the_exec_flip_refuses_a_root_with_no_address_space`: Canary
//   `exec-no-space-canary`.
//
// Included into `mod handlers` (see `lib.rs`), so `sys_*` resolve directly.

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;
use azos_arch_api::MemType;

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
    azos_sched::shim_set_brk(0x10_0000);
    pt
}

fn lend(pa: usize, write: bool, mem: MemType) -> Option<usize> {
    crate::phys_map::map_user(&crate::phys_map::Grant { pa, pages: 1, write, mem })
}

fn owner_page() -> usize {
    azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize()
}

#[test]
fn a_space_that_ends_leaves_a_physical_range_to_its_owner() {
    let _g = serial();
    let pt = space();
    let pa = owner_page();
    let va = lend(pa, true, MemType::WB).expect("lent");
    assert_eq!(azos_mm::vmm::translate(pt, va), Some(pa));
    azos_sched::shim_end_space(pt);
    let state = azos_mm::pmm::frame_state(pa).unwrap_or(0);
    assert!(state & azos_mm::frame::F_ALLOCATED != 0 && state & azos_mm::frame::F_FREE == 0, "the space's end freed the owner's frame");
    azos_sched::set_current_user_pt(0);
    let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(pa));
}

#[test]
fn a_physical_range_is_never_made_executable() {
    let _g = serial();
    let pt = space();
    let pa = owner_page();
    let va = lend(pa, true, MemType::WB).expect("lent");
    assert!(
        azos_mm::vmm::set_user_range_exec(pt, va, va + PAGE_SIZE).is_err(),
        "a physical range's frame was made executable"
    );
    let perms = azos_mm::vmm::translate_user(pt, va, true);
    assert_eq!(perms, Some(pa), "the leaf is still its owner's, writable");
    azos_sched::shim_end_space(pt);
    azos_sched::set_current_user_pt(0);
    let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(pa));
}

#[test]
fn a_task_cannot_unmap_a_physical_range() {
    let _g = serial();
    let pt = space();
    let pa = owner_page();
    let va = lend(pa, true, MemType::WB).expect("lent");
    assert_eq!(sys_munmap(va as u64, PAGE_SIZE as u64), azos_abi::error::Errno::EINVAL.to_syscall_ret(), "munmap took a physical range");
    assert_eq!(azos_mm::vmm::translate(pt, va), Some(pa), "the leaf went");
    assert!(azos_mm::pager::has_phys(azos_sched::shim_space(pt), va, va + PAGE_SIZE), "the record went");
    azos_sched::shim_end_space(pt);
    azos_sched::set_current_user_pt(0);
    let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(pa));
}

#[test]
fn a_task_cannot_reprotect_a_physical_range() {
    let _g = serial();
    let pt = space();
    let pa = owner_page();
    let va = lend(pa, true, MemType::WB).expect("lent");
    assert_eq!(sys_mprotect(va as u64, PAGE_SIZE as u64, 1), azos_abi::error::Errno::EINVAL.to_syscall_ret(), "mprotect changed a physical range");
    assert!(azos_mm::vmm::translate_user(pt, va, true).is_some(), "the range lost its write permission");
    azos_sched::shim_end_space(pt);
    azos_sched::set_current_user_pt(0);
    let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(pa));
}

#[test]
fn a_fork_gives_the_child_only_the_ranges_that_say_so() {
    let _g = serial();
    let pt = space();
    let space_ref = azos_sched::shim_space(pt);
    let (own, shared) = (owner_page(), owner_page());
    let va_own = lend(own, true, MemType::WB).expect("lent");
    // A range that says a fork shares it, recorded where the loader would.
    let va_shared = va_own - PAGE_SIZE;
    azos_mm::pager::reserve_phys(space_ref, va_shared, va_shared + PAGE_SIZE, false, shared, MemType::WB, true).expect("recorded");
    azos_mm::vmm::map_phys(pt, va_shared, shared, 1, false, MemType::WB).expect("mapped");

    let (child, hold) = azos_mm::vmm::fork_cow_shared_held(space_ref, false).expect("fork");
    azos_sched::shim_forget_space(child);
    azos_sched::shim_set_other_task(2, child, 0);
    assert!(fork_regions_to_child(2), "the clone was refused");
    drop(hold);

    assert_eq!(azos_mm::vmm::translate(child, va_shared), Some(shared), "the child lacks the range that says so");
    assert_eq!(azos_mm::vmm::translate(child, va_own), None, "the child holds a range that does not");
    assert_eq!(azos_mm::pager::shim_mappings(azos_sched::shim_space(child)), 1);
    assert!(azos_mm::cow::page_getref(shared) <= 1 && azos_mm::cow::page_getref(own) <= 1, "a range was counted as a shared frame");
    azos_sched::shim_end_space(child);
    assert_eq!(azos_mm::vmm::translate(pt, va_shared), Some(shared), "the child's end took the parent's leaf");
    assert!(azos_mm::pmm::frame_state(shared).unwrap_or(0) & azos_mm::frame::F_FREE == 0, "the child's end freed the range");
    azos_sched::shim_end_space(pt);
    azos_sched::set_current_user_pt(0);
    for pa in [own, shared] {
        let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(pa));
    }
}

#[test]
fn a_range_with_no_record_room_maps_nothing() {
    let _g = serial();
    let pt = space();
    let pa = owner_page();
    let mut held = Vec::new();
    while let Some(va) = lend(pa, false, MemType::WB) {
        held.push(va);
        assert!(held.len() <= azos_mm::pager::MAPPINGS_PER_SPACE, "the space recorded more ranges than it has records");
    }
    assert_eq!(held.len(), azos_mm::pager::MAPPINGS_PER_SPACE);
    let next = held.iter().copied().min().unwrap() - PAGE_SIZE;
    assert_eq!(azos_mm::vmm::translate(pt, next), None, "a range the space could not record got a leaf");
    azos_sched::shim_end_space(pt);
    azos_sched::set_current_user_pt(0);
    let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(pa));
}

#[test]
fn a_threads_vdso_page_leaves_the_group_space_when_the_thread_ends() {
    let _g = serial();
    let pt = space();
    let va = crate::vdso_notify::sys_vdso_task_map();
    assert!(va > 0, "the map returned {va}");
    let va = va as usize;
    let space_ref = azos_sched::shim_space(pt);
    assert!(azos_mm::pager::has_phys(space_ref, va, va + PAGE_SIZE), "the page is not a record of the space");

    // The thread ends while its group lives on; the slot goes to another task.
    crate::vdso_notify::release_task_page(1);
    azos_sched::set_current_task_tid(2);
    assert!(azos_mm::vdso::task_page_claim(0, 2).is_some(), "the slot's next owner claims the page");
    assert!(!azos_mm::pager::has_phys(space_ref, va, va + PAGE_SIZE), "the group still maps the slot's page");
    assert_eq!(azos_mm::vmm::translate(pt, va), None, "and reads the next owner's counters through it");
    azos_sched::shim_end_space(pt);
    azos_sched::set_current_user_pt(0);
}

#[test]
fn the_exec_flip_refuses_a_root_with_no_address_space() {
    let _g = serial();
    // A root nobody made a space for: no record says whose its pages are.
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    let pa = owner_page();
    azos_mm::vmm::map_phys(pt, 0x40_0000, pa, 1, true, MemType::WB).expect("mapped");
    assert!(
        azos_mm::vmm::set_user_range_exec(pt, 0x40_0000, 0x40_0000 + PAGE_SIZE).is_err(),
        "a page was made executable with no record to say it is private"
    );
    let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(pa));
}
