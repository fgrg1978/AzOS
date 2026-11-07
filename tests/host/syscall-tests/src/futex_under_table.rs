// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for what a futex call does under the futex table's lock, which it
// holds with interrupts off and which an interrupt may take: it faults no page
// in, and it does not spin on the region table.
//
// * The look at a private word reads what is resident. A word on a page not
//   committed answers "not now" with nothing allocated; the settle, with no
//   lock held, commits it, and the look then reads it. Canary
//   `futex-look-faults-canary` (a look that faults the page in) commits under
//   the look.
// * A hart that holds the table never spins on the region table. The holder of
//   the region table, with interrupts on, takes an interrupt that wakes a
//   futex and spins on the table: with the table's holder spinning on the
//   region table, neither ever moves. Here two threads stand in for the harts,
//   and the region table's holder is parked by the word hook, where the
//   interrupt would land. Canary `memobj-word-spin-canary` deadlocks, which the
//   test reads as its bound passing.

use super::harness::serial;
use azos_ipc::memobj::{
    memobj_create_ref, memobj_note_mapping_ref, memobj_page_phys_ref, memobj_release_all, memobj_with_mapped_word,
    shim_set_word_hook, MapAccess, MemPerms,
};
use azos_arch_api::PagePerms;
use azos_sched::futex_table::{self as ft, FutexEnv, Key, WaitResult};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::SeqCst};
use std::time::{Duration, Instant};

const TID: u32 = 0x6E00_0001;
const VA: usize = 0x4000_0000;
const BRK: u64 = 0x10_0000;
const PAGE: usize = 4096;
const RW: u64 = 3;
const ANON: u64 = u64::MAX;

struct Env;
impl FutexEnv for Env {
    fn now(&self) -> u64 {
        0
    }
    fn block(&self, _deadline: u64) -> bool {
        false
    }
    fn wake(&self, _tid: u32, _deadline: u64) {}
}

fn committed(pt: usize, va: usize) -> bool {
    matches!(azos_mm::vmm::user_page(pt, va), azos_mm::vmm::UserPage::Leaf { .. })
}

#[test]
fn a_look_under_the_table_commits_nothing_and_the_settle_does() {
    let _g = serial();
    let pt = azos_mm::pmm::alloc_page().expect("a page-table root").as_usize();
    azos_sched::shim_forget_space(pt);
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(TID);
    azos_sched::shim_set_page_limit(0);
    azos_sched::shim_set_mem_locked(false);
    azos_sched::shim_set_sched_class(3);
    azos_sched::shim_set_brk(BRK);
    let va = sys_mmap(0, PAGE as u64, RW, 0, ANON, 0);
    assert!(va > 0, "mmap failed: {va}");
    let va = va as u64;

    let frames = azos_mm::shim_pages_in_use();
    assert_eq!(crate::vdso_notify::futex_look(va, false), None, "a word on a page not committed is not readable now");
    assert!(!committed(pt, va as usize), "the look under the table committed the page");
    assert_eq!(azos_mm::shim_pages_in_use(), frames, "the look under the table allocated");

    assert!(crate::vdso_notify::futex_settle(va), "with no lock held the page commits");
    assert!(committed(pt, va as usize));
    let (key, v) = crate::vdso_notify::futex_look(va, false).expect("resident now");
    assert_eq!(v, 0);
    assert!(matches!(key, Key::Private { .. }));

    // A word that is mapped nowhere: unreadable for good, the settle says so.
    assert_eq!(crate::vdso_notify::futex_look(0x7000_0000, false), None);
    assert!(!crate::vdso_notify::futex_settle(0x7000_0000));
    azos_sched::set_current_user_pt(0);
    azos_sched::shim_forget_space(pt);
}

/// 0 the holder of the region table is not there yet, 1 it is, 2 the table's
/// holder has its lock and goes for the region table.
static STAGE: AtomicU32 = AtomicU32::new(0);
static WOKE: AtomicBool = AtomicBool::new(false);
static OBJ: AtomicU32 = AtomicU32::new(0);

/// Inside the region table's hold: the interrupt, as soon as the other hart
/// holds the futex table.
fn interrupt_wakes_a_futex(_pa: usize) {
    STAGE.store(1, SeqCst);
    while STAGE.load(SeqCst) != 2 {
        std::thread::yield_now();
    }
    let key = Key::Shared { obj: OBJ.load(SeqCst), offset: 0 };
    let _ = ft::wake_key_checked(&Env, key, 1);
    WOKE.store(true, SeqCst);
}

#[test]
fn a_futex_look_never_spins_on_the_region_table() {
    let _g = serial();
    let pt = azos_mm::pmm::alloc_page().expect("a page-table root").as_usize();
    azos_sched::set_current_task_tid(TID);
    azos_sched::set_current_proc_tid(0);
    azos_sched::set_current_user_pt(pt);
    let r = memobj_create_ref(TID, 1, MemPerms::ReadWrite).expect("a region");
    let frame = memobj_page_phys_ref(r, 0).expect("live").expect("a frame");
    assert_eq!(memobj_note_mapping_ref(TID, r, pt, VA, 1, MapAccess::RW), Ok(true));
    azos_mm::vmm::map(pt, VA, frame, PagePerms::USER_RW).expect("map");
    OBJ.store(r, SeqCst);
    STAGE.store(0, SeqCst);
    WOKE.store(false, SeqCst);
    shim_set_word_hook(Some(interrupt_wakes_a_futex));

    let holder = std::thread::spawn(|| memobj_with_mapped_word(TID, VA, false, |_, _, _| ()));
    let t = Instant::now();
    while STAGE.load(SeqCst) != 1 && t.elapsed() < Duration::from_secs(10) {
        std::thread::yield_now();
    }
    assert_eq!(STAGE.load(SeqCst), 1, "the region table's holder never came");

    // The look of a requeue, under the table. It gets one try: the deadlock
    // needs nothing more, and the region table stays held until the wake.
    let looker = std::thread::spawn(|| {
        azos_sched::shim_serial_enter();
        let look = || {
            STAGE.store(2, SeqCst);
            crate::vdso_notify::futex_look(VA as u64, true)
        };
        let to = Key::Shared { obj: OBJ.load(SeqCst), offset: 8 };
        ft::requeue_key(&Env, &look, to, 0, 0, Some(0), false)
    });
    let t = Instant::now();
    while !WOKE.load(SeqCst) && t.elapsed() < Duration::from_secs(5) {
        std::thread::yield_now();
    }
    // Spinning threads cannot be joined: report, and leave them to the process.
    assert!(WOKE.load(SeqCst), "the look spins on the region table holding the futex table: deadlock");
    assert_eq!(looker.join().expect("looker"), Err(WaitResult::Fault), "busy reads as not now");
    azos_sched::shim_serial_enter();
    assert_eq!(holder.join().expect("holder"), Ok(Some(())));
    shim_set_word_hook(None);
    azos_mm::vmm::unmap(pt, VA);
    azos_sched::set_current_user_pt(0);
    memobj_release_all(TID);
}
