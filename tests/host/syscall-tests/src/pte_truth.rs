// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// A private anonymous page's state is its object's slot and its leaf a cache of
// it, on the real `handlers.rs`, `pager.rs`, `anon_obj.rs`, `slot.rs`, `cow.rs`
// and `vmm.rs` over the shim arena.
//
// * `a_resident_slot_whose_leaf_was_cleared_is_installed_again`: the fault
//   decides from the slot; a cleared leaf is a cache word, the slot's frame
//   goes back in. Canary `mm-pte-truth-canary` (the leaf believed): a zero page.
// * `a_leaf_the_slot_does_not_name_is_left_alone`: neither believed nor
//   replaced, no frame taken or lost.
// * `a_compressed_page_comes_back_from_its_slot`: a page the reclaimer stored
//   is restored from the marker in its slot, its leaf being empty. Same canary:
//   a zero page. Needs the compressed pool (Kconfig MM_RECLAIM_COMPRESS).
// * `a_copy_on_write_break_moves_the_slot_with_the_leaf`: after a fork, the
//   parent's write gives it a new frame and its slot follows, so the page is
//   still the reclaimer's to take. Canary `cow-slot-canary` (`pager::cow_swap`
//   leaves the slot): the unmap is refused (the slot names the child's frame).
// * `a_page_committed_during_the_fork_is_a_zero_page_in_the_child`: the child's
//   slots are its own leaves, not the parent's slots. Canary
//   `fork-commit-race-canary` (the child's empty slots take the parent's frame
//   slots): the child maps the parent's frame.
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
fn a_resident_slot_whose_leaf_was_cleared_is_installed_again() {
    let _g = serial();
    let pt = space();
    let base = map(4);
    let f = write(pt, base, 0x3D);
    // The leaf goes, the slot still names the frame (a cleared cache word).
    azos_mm::vmm::unmap(pt, base);
    assert!(azos_mm::vmm::translate(pt, base).is_none());
    assert!(azos_mm::pager::resolve_fault(azos_sched::shim_space(pt), base).is_ok());
    assert_eq!(azos_mm::vmm::translate(pt, base), Some(f), "the slot's frame, installed again");
    assert!(bytes(f).iter().all(|&b| b == 0x3D), "the page, not a zero one");
    assert_eq!(azos_mm::pager::space_pages(azos_sched::shim_space(pt)), (4, 1), "committed once");
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(0);
}

#[test]
fn a_leaf_the_slot_does_not_name_is_left_alone() {
    let _g = serial();
    let pt = space();
    let base = map(4);
    let stale = azos_mm::pmm::alloc_page().unwrap().as_usize();
    bytes(stale).fill(0xEE);
    // A leaf no install of the object made: the fault neither takes it for
    // the page nor replaces it (its frame is nobody's it could free).
    azos_mm::vmm::map(pt, base, stale, azos_arch_api::PagePerms::USER_RW).unwrap();
    let used = azos_mm::shim_pages_in_use();
    assert!(azos_mm::pager::resolve_fault(azos_sched::shim_space(pt), base).is_ok());
    assert_eq!(azos_mm::vmm::translate(pt, base), Some(stale), "left as it was");
    assert_eq!(azos_mm::shim_pages_in_use(), used, "no frame taken, none lost");
    assert_eq!(azos_mm::pager::space_pages(azos_sched::shim_space(pt)), (4, 0), "nothing committed");
    azos_mm::vmm::unmap(pt, base);
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
    let (child, hold) =
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
    let (child, hold) =
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

/// **A `munmap` frees the slot chunks of the pages it leaves unmapped.** A
/// page past the object's inline slots takes a chunk of slot words on its
/// first touch; once no mapping of the object covers any page of the chunk,
/// the chunk goes back with the cut, though the object lives on.
/// **Canary** `slot-chunk-kept-canary`: the chunk stays until the object ends.
#[test]
fn a_munmap_frees_the_slot_chunks_of_the_pages_it_unmaps() {
    let _g = serial();
    let pt = space();
    let chunk = azos_mm::anon_obj::PER_CHUNK * PAGE_SIZE;
    let base = map(3 * chunk / PAGE_SIZE);
    let first_chunk = (base / chunk + 1) * chunk;
    write(pt, base, 0x01);
    let before = azos_mm::shim_pages_in_use();
    let tables = azos_mm::vmm::table_frames(pt);
    write(pt, first_chunk + PAGE_SIZE, 0x02);
    let built = azos_mm::vmm::table_frames(pt) - tables;
    // (With reservations on, the touch also took a run, which the cut gives back.)
    assert!(azos_mm::shim_pages_in_use() >= before + built + 2, "the page, its chunk and its tables");
    assert_eq!(sys_munmap(first_chunk as u64, chunk as u64), 0);
    assert_eq!(azos_mm::shim_pages_in_use(), before + built, "the page and its chunk are back, the tables stay");
    assert!(azos_mm::vmm::translate(pt, base).is_some(), "the object lives on");
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(0);
}

/// **A copy-on-write break through another task's root moves the slot too.**
/// A kernel write into a task that is not the running one (through
/// `translate_user` on its root) breaks the sharing there: the space is found
/// by its root (`aspace::with_root`), and its slot follows the leaf, so the
/// page is still the reclaimer's to take.
/// **Canary** `cow-slot-canary`: the slot stays on the shared frame.
#[test]
fn a_copy_on_write_break_through_another_tasks_root_moves_its_slot() {
    let _g = serial();
    let pt = space();
    let base = map(4);
    let shared = write(pt, base, 0x11);
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let child = azos_mm::vmm::fork_cow(pt, shm_lo, shm_hi).expect("fork");
    azos_sched::shim_forget_space(child);
    azos_sched::shim_set_other_task(2, child, 0);
    assert!(fork_regions_to_child(2));
    // The child runs; the kernel writes into the parent.
    azos_sched::set_current_user_pt(child);
    let mine = write(pt, base, 0x22);
    assert_ne!(mine, shared);
    let roots = [Some(azos_sched::shim_space(pt))];
    let mut ages = Ages::new();
    let mut reclaim = AnonReclaim::new(&roots, 0, &mut ages);
    let victim = Victim { space: pt, va: base };
    assert!(reclaim.unmap(victim), "the parent's slot names its new frame");
    reclaim.keep(victim);
    azos_sched::set_current_user_pt(pt);
    azos_sched::shim_forget_space(child);
    azos_mm::vmm::destroy_user_pagetable_skip_range(child, shm_lo, shm_hi);
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(0);
}

/// The fork the install hook starts in `a_restore_begun_before_the_fork_*`:
/// the parent's root, then the child's root and the fork's hold.
static HOOK_PARENT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static HOOK_FORK: std::sync::Mutex<Option<(usize, azos_mm::pager::ForkHold)>> = std::sync::Mutex::new(None);

fn fork_at_install() {
    let pt = HOOK_PARENT.load(std::sync::atomic::Ordering::SeqCst);
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let (child, hold) =
        azos_mm::vmm::fork_cow_shared_held(azos_sched::shim_space(pt), shm_lo, shm_hi, false).expect("fork");
    *HOOK_FORK.lock().unwrap() = Some((child, hold));
}

/// **A restore that was supplying when the fork began does not install during
/// it.** A sibling decides to restore a compressed page and decompresses it;
/// meanwhile the fork raises its hold and its walk passes the page (no leaf,
/// so the child gets none). The install then finds the hold and is refused;
/// it waits for the fork's end. The child's copy of the markers sees the page
/// out, and the child reads it, not a zero page. Needs the compressed pool.
/// **Canary** `fork-install-recheck-canary`: the install goes through during
/// the hold, the parent's slot is a frame when the markers are copied, and the
/// child reads zeros.
#[test]
fn a_restore_begun_before_the_fork_does_not_install_during_it() {
    if !azos_mm::zpool::ENABLED {
        return;
    }
    let _g = serial();
    azos_crypto::entropy::mix(&[0x2d; 64], 512);
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
    HOOK_PARENT.store(pt, std::sync::atomic::Ordering::SeqCst);
    azos_mm::pager::shim_set_install_hook(Some(fork_at_install));
    let parent_space = azos_sched::shim_space(pt);
    azos_sched::shim_serial_share(true);
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let child = std::thread::scope(|sc| {
        let sibling = sc.spawn(|| {
            while azos_mm::vmm::translate(pt, base).is_none() {
                azos_mm::vmm::handle_demand_fault(parent_space, base)?;
                std::thread::yield_now();
            }
            Ok::<(), azos_common::error::KernelError>(())
        });
        // The fork began at the sibling's install; it clones and ends here.
        let child = loop {
            if let Some((child, _)) = HOOK_FORK.lock().unwrap().as_ref() {
                break *child;
            }
            std::thread::yield_now();
        };
        azos_sched::shim_forget_space(child);
        azos_sched::shim_set_other_task(2, child, 0);
        assert!(fork_regions_to_child(2));
        drop(HOOK_FORK.lock().unwrap().take());
        assert!(sibling.join().unwrap().is_ok());
        child
    });
    azos_sched::shim_serial_share(false);
    azos_mm::pager::shim_set_install_hook(None);
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

/// **A kernel copy waits out a fork's hold.** A sibling's `read()` into a page
/// that is compressed while a fork holds the space: the copy's fault waits for
/// the fork's end, however long it runs, instead of answering EFAULT after
/// its tries. Needs the compressed pool.
/// **Canary** `fork-wait-counted-canary`: the waits count as tries and the
/// copy gives up.
#[test]
fn a_kernel_copy_waits_out_a_fork_hold() {
    if !azos_mm::zpool::ENABLED {
        return;
    }
    let _g = serial();
    azos_crypto::entropy::mix(&[0x6e; 64], 512);
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
    let (child, hold) =
        azos_mm::vmm::fork_cow_shared_held(azos_sched::shim_space(pt), shm_lo, shm_hi, false).expect("fork");
    azos_sched::shim_serial_share(true);
    let copied = std::thread::scope(|sc| {
        let sibling = sc.spawn(|| azos_mm::vmm::translate_user(pt, base, true));
        std::thread::sleep(std::time::Duration::from_millis(100));
        azos_sched::shim_forget_space(child);
        azos_sched::shim_set_other_task(2, child, 0);
        assert!(fork_regions_to_child(2));
        drop(hold);
        sibling.join().unwrap()
    });
    azos_sched::shim_serial_share(false);
    let f = copied.expect("the copy gave up on a page the fork kept out");
    assert!(bytes(f & !(PAGE_SIZE - 1)).iter().all(|&b| b == 0x5A));
    azos_sched::shim_forget_space(child);
    azos_mm::vmm::destroy_user_pagetable_skip_range(child, shm_lo, shm_hi);
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(0);
}

/// **A fault another install already resolved is spurious, not the task's.**
/// Two threads touch one fresh page; one installs it, the other's fault is
/// handled after: the page is mapped and allows the access, so that access
/// retries instead of the thread dying. A store to a read-only page is still
/// the task's fault.
/// **Canary** `spurious-fault-canary`: the second faulter is killed.
#[test]
fn a_fault_another_install_resolved_is_spurious() {
    use azos_mm::vmm::{handle_user_fault, UserFault};
    let _g = serial();
    let pt = space();
    let base = map(2);
    let s = azos_sched::shim_space(pt);
    assert_eq!(handle_user_fault(s, base, true), UserFault::Resolved, "the first faulter installs");
    assert_eq!(handle_user_fault(s, base, true), UserFault::Spurious, "the second one retries");
    assert_eq!(handle_user_fault(s, base, false), UserFault::Spurious);
    let ro = sys_mmap(0, PAGE_SIZE as u64, 1, 0, ANON, 0) as usize;
    assert_eq!(handle_user_fault(s, ro, false), UserFault::Resolved);
    assert_eq!(handle_user_fault(s, ro, true), UserFault::No, "a store to a read-only page is the task's");
    assert_eq!(handle_user_fault(s, base + 64 * PAGE_SIZE, false), UserFault::No, "and so is a hole");
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(0);
}
