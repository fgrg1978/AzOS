// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// `mprotect` against the anonymous-page reclaimer, on the real `pager.rs` and
// `vmm.rs` over the shim arena. A store in flight has the page's leaf swapped
// for an `InTransit` marker; `mprotect` rewrites leaves in place, so it must
// neither run through that window (its store would put a valid leaf back on a
// frame the reclaimer is about to free, and a failed store restores the old
// permission over the new one) nor let a store start while it runs.
//
// * `mprotect_waits_out_a_store_in_flight`: the permission change lands after
//   the failed store restored the page, so the page ends read-only.
//   Canary: take `azos_mm::pager::reclaim_pause` out of `sys_mprotect`: the
//   call returns while the store is in flight and the page ends writable.
// * `the_reclaimer_takes_nothing_while_mprotect_rewrites`: the pause refuses
//   `unmap`. Canary: `reclaim_hold` not counting the hold: the unmap succeeds.
//
// * `module_map_x_waits_out_a_store_in_flight`: the same for the Linux
//   personality's module map (`set_user_range_exec`): it waits, then maps the
//   restored page executable. Canary `exec-reclaim-canary`: it does not hold the
//   reclaimer off, refuses the marker at once and returns while the store runs.
//
// Included into `mod handlers` (see `lib.rs`), so `sys_*` resolve directly.

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;
use azos_mm::pager::{Ages, AnonReclaim, Victim};
use azos_mm::zpool::Reclaimee;
use std::sync::atomic::{AtomicBool, Ordering};

const ANON: u64 = u64::MAX;
const RW: u64 = 3;
const RO: u64 = 1;
const BRK: u64 = 0x10_0000;

/// A fresh space with one anonymous region of two pages whose first page is resident.
fn resident_page() -> (usize, usize) {
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
    let va = sys_mmap(0, (2 * PAGE_SIZE) as u64, RW, 0, ANON, 0);
    assert_eq!(va, BRK as i64, "mmap failed: {va}");
    assert!(azos_mm::vmm::handle_demand_fault(pt, va as usize).is_ok());
    assert!(azos_mm::vmm::user_write_would_be_permitted(pt, va as usize));
    (pt, va as usize)
}

#[test]
fn mprotect_waits_out_a_store_in_flight() {
    let _g = serial();
    let (pt, va) = resident_page();
    let frame = azos_mm::vmm::translate(pt, va).expect("mapped");
    let roots = [pt];
    let mut ages = Ages::new();
    let mut reclaim = AnonReclaim::new(&roots, 0, &mut ages);
    let victim = Victim { space: pt, va };
    assert!(reclaim.unmap(victim), "the page is taken out: a store is in flight");
    assert!(azos_mm::vmm::translate(pt, va).is_none(), "the leaf is the marker");

    let done = AtomicBool::new(false);
    // The call runs on a thread of its own, since it must block until the
    // store ends; this thread only waits and then ends the store.
    azos_sched::shim_serial_share(true);
    std::thread::scope(|sc| {
        let call = sc.spawn(|| {
            let r = sys_mprotect(va as u64, PAGE_SIZE as u64, RO);
            done.store(true, Ordering::SeqCst);
            r
        });
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(!done.load(Ordering::SeqCst), "mprotect ran while a store of its space was in flight");
        // The store fails: the page comes back as it was taken out.
        reclaim.keep(victim);
        assert_eq!(call.join().unwrap(), 0);
    });
    azos_sched::shim_serial_share(false);
    assert_eq!(azos_mm::vmm::translate(pt, va), Some(frame), "the same frame is still mapped");
    assert!(!azos_mm::vmm::user_write_would_be_permitted(pt, va), "the downgrade survived the failed store");
    azos_mm::pager::forget(pt);
    azos_sched::set_current_user_pt(0);
}

#[test]
fn the_reclaimer_takes_nothing_while_mprotect_rewrites() {
    let _g = serial();
    let (pt, va) = resident_page();
    let roots = [pt];
    let mut ages = Ages::new();
    let mut reclaim = AnonReclaim::new(&roots, 0, &mut ages);
    let victim = Victim { space: pt, va };
    let pause = azos_mm::pager::reclaim_pause(pt).expect("the space has regions");
    assert!(!reclaim.unmap(victim), "no page leaves a space while its leaves are rewritten");
    assert!(azos_mm::vmm::translate(pt, va).is_some(), "the page stayed mapped");
    drop(pause);
    assert!(reclaim.unmap(victim), "the pause ended: the page may be taken again");
    reclaim.keep(victim);
    azos_mm::pager::forget(pt);
    azos_sched::set_current_user_pt(0);
}

#[test]
fn module_map_x_waits_out_a_store_in_flight() {
    let _g = serial();
    let (pt, va) = resident_page();
    let frame = azos_mm::vmm::translate(pt, va).expect("mapped");
    let roots = [pt];
    let mut ages = Ages::new();
    let mut reclaim = AnonReclaim::new(&roots, 0, &mut ages);
    let victim = Victim { space: pt, va };
    assert!(reclaim.unmap(victim), "the page is taken out: a store is in flight");

    let done = AtomicBool::new(false);
    azos_sched::shim_serial_share(true);
    std::thread::scope(|sc| {
        let call = sc.spawn(|| {
            let r = azos_mm::vmm::set_user_range_exec(pt, va, va + PAGE_SIZE, 0, 0);
            done.store(true, Ordering::SeqCst);
            r
        });
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(!done.load(Ordering::SeqCst), "the module map ran while a store of its space was in flight");
        reclaim.keep(victim);
        assert_eq!(call.join().unwrap(), Ok(1), "the restored page is the one mapped executable");
    });
    azos_sched::shim_serial_share(false);
    assert_eq!(azos_mm::vmm::translate(pt, va), Some(frame), "the same frame is still mapped");
    assert!(!azos_mm::vmm::user_write_would_be_permitted(pt, va), "write was taken off with execute put on");
    azos_mm::pager::forget(pt);
    azos_sched::set_current_user_pt(0);
}
