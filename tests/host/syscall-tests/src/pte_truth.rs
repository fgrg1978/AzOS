// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// A private anonymous page's state is its object's slot and its leaf a cache of
// it, on the real `handlers.rs`, `pager.rs`, `anon_obj.rs`, `slot.rs`, `cow.rs`
// and `vmm.rs` over the shim arena.
//
// * `a_stale_leaf_over_an_empty_slot_is_not_believed`: the fault decides from
//   the slot; a leaf no install made is replaced by a zero page. Canary
//   `mm-pte-truth-canary` (the leaf believed): the stale bytes are read.
// * `a_compressed_page_comes_back_from_its_slot`: a page the reclaimer stored
//   is restored from the marker in its slot, its leaf being empty. Same canary:
//   a zero page. Needs the compressed pool (Kconfig MM_RECLAIM_COMPRESS).
// * `a_copy_on_write_break_moves_the_slot_with_the_leaf`: after a fork, the
//   parent's write gives it a new frame and its slot follows, so the page is
//   still the reclaimer's to take. Canary by hand: `pager::cow_swap` leaving
//   the slot: the unmap is refused (the slot names the child's frame).
// * `a_page_committed_during_the_fork_is_a_zero_page_in_the_child`: the child's
//   slots are its own leaves, not the parent's slots. Canary by hand: the
//   child's frame slots copied from the parent's: the child maps the parent's
//   frame.
//
// Included into `mod handlers` (see `lib.rs`), so `sys_*` resolve directly.

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;
use azos_mm::pager::{Ages, AnonReclaim, Victim};
use azos_mm::zpool::Reclaimee;

const ANON: u64 = u64::MAX;
const RW: u64 = 3;
const BRK: u64 = 0x10_0000;

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

/// Write `b` over the page at `va` the way a store does: a fault (or a
/// copy-on-write break) first, then the frame the leaf maps.
fn write(pt: usize, va: usize, b: u8) -> usize {
    let f = azos_mm::vmm::translate_user(pt, va, true).expect("writable") & !(PAGE_SIZE - 1);
    bytes(f).fill(b);
    f
}

#[test]
fn a_stale_leaf_over_an_empty_slot_is_not_believed() {
    let _g = serial();
    let pt = space();
    let base = map(4);
    let stale = azos_mm::pmm::alloc_page().unwrap().as_usize();
    bytes(stale).fill(0xEE);
    // A leaf no install of the object made: a clear that was missed.
    azos_mm::vmm::map(pt, base, stale, azos_arch_api::PagePerms::USER_RW).unwrap();
    assert!(azos_mm::pager::resolve_fault(azos_sched::shim_space(pt), base).is_ok());
    let now = azos_mm::vmm::translate(pt, base).expect("mapped");
    assert_ne!(now, stale, "the leaf was believed over the empty slot");
    assert!(bytes(now).iter().all(|&b| b == 0), "a zero page, not the previous owner's bytes");
    assert_eq!(azos_mm::pager::space_pages(azos_sched::shim_space(pt)), (4, 1));
    let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(stale));
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(0);
}

#[test]
fn a_compressed_page_comes_back_from_its_slot() {
    if !azos_mm::zpool::ENABLED {
        return;
    }
    let _g = serial();
    azos_crypto::entropy::mix(&[0x3c; 64], 512);
    let pt = space();
    let base = map(2);
    write(pt, base, 0x5C);
    let roots = [Some(azos_sched::shim_space(pt))];
    let mut ages = Ages::new();
    let mut reclaim = AnonReclaim::new(&roots, 0, &mut ages);
    let victim = Victim { space: pt, va: base };
    assert!(reclaim.unmap(victim));
    assert!(reclaim.store(victim).is_ok(), "the page is in the pool");
    reclaim.free(victim);
    assert!(azos_mm::vmm::translate(pt, base).is_none(), "and its leaf is empty");
    assert!(azos_mm::vmm::handle_demand_fault(azos_sched::shim_space(pt), base).is_ok());
    let f = azos_mm::vmm::translate(pt, base).expect("restored");
    assert!(bytes(f).iter().all(|&b| b == 0x5C), "the stored page, not a zero one");
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(0);
}

#[test]
fn a_copy_on_write_break_moves_the_slot_with_the_leaf() {
    let _g = serial();
    let pt = space();
    let base = map(4);
    let shared = write(pt, base, 0x11);
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let child = azos_mm::vmm::fork_cow(pt, shm_lo, shm_hi).expect("fork");
    azos_sched::shim_forget_space(child);
    azos_sched::shim_set_other_task(2, child, 0);
    assert!(fork_regions_to_child(2));
    // The parent's store breaks the sharing: a frame of its own.
    let mine = write(pt, base, 0x22);
    assert_ne!(mine, shared);
    assert_eq!(azos_mm::vmm::translate(child, base), Some(shared), "the child keeps the shared frame");
    assert!(bytes(shared).iter().all(|&b| b == 0x11));
    // The parent's page is its own again, so the reclaimer may take it.
    let roots = [Some(azos_sched::shim_space(pt))];
    let mut ages = Ages::new();
    let mut reclaim = AnonReclaim::new(&roots, 0, &mut ages);
    let victim = Victim { space: pt, va: base };
    assert!(reclaim.unmap(victim), "the slot names the parent's frame, the one its leaf maps");
    reclaim.keep(victim);
    assert_eq!(azos_mm::vmm::translate(pt, base), Some(mine));
    azos_sched::shim_forget_space(child);
    azos_mm::vmm::destroy_user_pagetable_skip_range(child, shm_lo, shm_hi);
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(0);
}

#[test]
fn a_page_committed_during_the_fork_is_a_zero_page_in_the_child() {
    let _g = serial();
    let pt = space();
    let base = map(8);
    write(pt, base, 0x33);
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let child = azos_mm::vmm::fork_cow(pt, shm_lo, shm_hi).expect("fork");
    // A sibling's commit, after the walk and before the mappings are cloned.
    let late = write(pt, base + 2 * PAGE_SIZE, 0x44);
    azos_sched::shim_forget_space(child);
    azos_sched::shim_set_other_task(2, child, 0);
    assert!(fork_regions_to_child(2));
    let cs = azos_sched::shim_space(child);
    assert!(azos_mm::vmm::handle_demand_fault(cs, base + 2 * PAGE_SIZE).is_ok());
    let theirs = azos_mm::vmm::translate(child, base + 2 * PAGE_SIZE).expect("the child's page");
    assert_ne!(theirs, late, "the child maps the parent's private frame");
    assert!(bytes(theirs).iter().all(|&b| b == 0), "a zero page");
    assert!(bytes(late).iter().all(|&b| b == 0x44), "the parent's page is untouched");
    azos_sched::shim_forget_space(child);
    azos_mm::vmm::destroy_user_pagetable_skip_range(child, shm_lo, shm_hi);
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(0);
}

/// **A store whose range was unmapped and mapped again puts nothing back.**
/// The reclaimer has the page out; `munmap` and a new `mmap` of the same range
/// (the same object, its pages numbered by address) run before the store
/// fails. The put-back finds the slot is not its own: no leaf goes in for the
/// old frame, which is freed, and the new page is a zero page.
#[test]
fn a_failed_store_after_the_range_was_mapped_again_puts_nothing_back() {
    let _g = serial();
    let pt = space();
    // A Linux task's mmap honours a free hint: the range comes back.
    azos_sched::shim_set_linux(true);
    let base = map(2);
    write(pt, base, 0x66);
    let roots = [Some(azos_sched::shim_space(pt))];
    let mut ages = Ages::new();
    let mut reclaim = AnonReclaim::new(&roots, 0, &mut ages);
    let victim = Victim { space: pt, va: base };
    assert!(reclaim.unmap(victim));
    assert_eq!(sys_munmap(base as u64, (2 * PAGE_SIZE) as u64), 0);
    let used = azos_mm::shim_pages_in_use();
    assert_eq!(sys_mmap(base as u64, (2 * PAGE_SIZE) as u64, RW, 0, ANON, 0), base as i64, "the same range again");
    reclaim.keep(victim);
    assert!(azos_mm::vmm::translate(pt, base).is_none(), "no leaf for the old frame");
    assert_eq!(azos_mm::shim_pages_in_use() + 1, used, "the old frame is freed");
    assert!(azos_mm::vmm::handle_demand_fault(azos_sched::shim_space(pt), base).is_ok());
    let f = azos_mm::vmm::translate(pt, base).expect("the new page");
    assert!(bytes(f).iter().all(|&b| b == 0), "a zero page, not the old one");
    azos_sched::shim_set_linux(false);
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(0);
}


/// **No page of the parent leaves it while a fork copies it.** A sibling
/// commits a page after the fork's walk; the reclaimer must not store it before
/// the child's mappings are cloned, or the child would get a marker with no
/// entry in its share of the pool (the pool was shared before the store) and
/// die on its first touch. The fork's hold lasts until the clone.
/// **Canary** `fork-hold-canary`: the hold ends with the walk.
#[test]
fn the_reclaimer_takes_no_page_of_a_parent_until_its_fork_is_cloned() {
    let _g = serial();
    let pt = space();
    let base = map(4);
    write(pt, base, 0x10);
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let (child, _, hold) =
        azos_mm::vmm::fork_cow_shared_held(azos_sched::shim_space(pt), shm_lo, shm_hi, false).expect("fork");
    write(pt, base + PAGE_SIZE, 0x77);
    let roots = [Some(azos_sched::shim_space(pt))];
    let mut ages = Ages::new();
    let mut reclaim = AnonReclaim::new(&roots, 0, &mut ages);
    let victim = Victim { space: pt, va: base + PAGE_SIZE };
    assert!(!reclaim.unmap(victim), "the reclaimer took a page of a parent its fork is still copying");
    azos_sched::shim_forget_space(child);
    azos_sched::shim_set_other_task(2, child, 0);
    assert!(fork_regions_to_child(2));
    drop(hold);
    assert!(reclaim.unmap(victim), "the fork is over: the page may be taken");
    reclaim.keep(victim);
    azos_sched::shim_forget_space(child);
    azos_mm::vmm::destroy_user_pagetable_skip_range(child, shm_lo, shm_hi);
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(0);
}

/// **A page out at the fork's walk is the child's, whatever a sibling does
/// meanwhile.** The parent's page is compressed when the fork walks; a sibling
/// touches it before the child's mappings are cloned. The restore waits for the
/// fork to end, so the child gets the parent's marker (and its share of the
/// pool's copy) and reads the page, not a zero page. Needs the compressed pool
/// (Kconfig MM_RECLAIM_COMPRESS).
/// **Canary** `fork-hold-canary`: the sibling restores at once, the child's
/// slot stays empty and it reads zeros.
#[test]
fn a_page_compressed_at_the_fork_is_the_childs_though_a_sibling_restores_it() {
    if !azos_mm::zpool::ENABLED {
        return;
    }
    let _g = serial();
    azos_crypto::entropy::mix(&[0x4b; 64], 512);
    let pt = space();
    let base = map(2);
    write(pt, base, 0x5A);
    let roots = [Some(azos_sched::shim_space(pt))];
    let mut ages = Ages::new();
    let mut reclaim = AnonReclaim::new(&roots, 0, &mut ages);
    let victim = Victim { space: pt, va: base };
    assert!(reclaim.unmap(victim));
    assert!(reclaim.store(victim).is_ok());
    reclaim.free(victim);
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let (child, _, hold) =
        azos_mm::vmm::fork_cow_shared_held(azos_sched::shim_space(pt), shm_lo, shm_hi, false).expect("fork");
    let parent_space = azos_sched::shim_space(pt);
    azos_sched::shim_serial_share(true);
    std::thread::scope(|sc| {
        // The sibling's access retries until its page is there.
        let sibling = sc.spawn(|| {
            while azos_mm::vmm::translate(pt, base).is_none() {
                azos_mm::vmm::handle_demand_fault(parent_space, base)?;
                std::thread::yield_now();
            }
            Ok::<(), azos_common::error::KernelError>(())
        });
        std::thread::sleep(std::time::Duration::from_millis(150));
        let early = azos_mm::vmm::translate(pt, base).is_some();
        azos_sched::shim_forget_space(child);
        azos_sched::shim_set_other_task(2, child, 0);
        assert!(fork_regions_to_child(2));
        drop(hold);
        assert!(sibling.join().unwrap().is_ok());
        assert!(!early, "the sibling restored the page while the fork copied the markers");
    });
    azos_sched::shim_serial_share(false);
    let f = azos_mm::vmm::translate(pt, base).expect("restored in the parent");
    assert!(bytes(f).iter().all(|&b| b == 0x5A));
    assert!(azos_mm::vmm::handle_demand_fault(azos_sched::shim_space(child), base).is_ok());
    let cf = azos_mm::vmm::translate(child, base).expect("restored in the child");
    assert!(bytes(cf).iter().all(|&b| b == 0x5A), "the child reads the parent's page, not zeros");
    azos_sched::shim_forget_space(child);
    azos_mm::vmm::destroy_user_pagetable_skip_range(child, shm_lo, shm_hi);
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(0);
}
