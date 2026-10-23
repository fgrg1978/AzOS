// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the user-memory access sections
// (`crates/core/mm/src/uaccess.rs`): a copy that has resolved a user page to
// its frame keeps that frame until the copy ends, whatever another thread of
// the process unmaps meanwhile.
//
// **The race.** `copy_to_user` and its siblings never touch the user's VA:
// they walk the page table in software and copy through the kernel's own map
// of the frame. A TLB shootdown does not stop that copy. Before the sections,
// a `munmap` by another thread cleared the leaf, shot the TLBs down and freed
// the frame while a copy that had read the leaf a moment earlier still wrote
// it, and the allocator could hand the frame to anyone in that window.
//
// **How it is made deterministic.** A host-only hook in the copy loop parks
// the copying thread right after it has resolved the frame and before it
// touches it. A second thread then runs the real
// `vmm::unmap_user_range_and_free` on the page. With the sections, that call
// cannot return while the copy is parked (it waits for the copy's section to
// end); without them it returns at once, the frame is free, the next
// `alloc_page` hands it out, and the parked copy writes into it (or, for a
// read, hands its new owner's bytes to the caller).
//
// Canary: `uaccess-race-canary` (the unmapper does not wait for readers):
// every test below fails (the unmap ones with the frame reissued under the
// copy, the fork one with the child seeing the parent's late write).

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;
use azos_arch_api::PagePerms;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::SeqCst};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The user page every test copies to or from.
const VA: usize = 0x40_0000;

/// How long the unmapping thread is given to return while the copy is parked.
/// The unmap of one page takes microseconds; a fraction of a second is three
/// orders of magnitude of margin for a loaded host.
const UNMAP_GRACE: Duration = Duration::from_millis(300);

/// Where the parked copy stands: 0 not there yet, 1 parked with its frame
/// resolved, 2 told to go on.
static STAGE: AtomicU32 = AtomicU32::new(0);

/// An empty user root: a frame of the arena, zeroed, with no region left
/// over from an earlier test whose root had the same address (`pager`).
fn fresh_root() -> usize {
    let pt = azos_mm::pmm::alloc_page().expect("arena").as_usize();
    unsafe { core::ptr::write_bytes(pt as *mut u8, 0, PAGE_SIZE) };
    azos_mm::pager::forget(pt);
    pt
}

/// The hook: park the copy between resolving its frame and touching it.
fn park(_pa: usize) {
    STAGE.store(1, SeqCst);
    let t = Instant::now();
    // Bounded: a broken test must fail, not hang the suite.
    while STAGE.load(SeqCst) != 2 && t.elapsed() < Duration::from_secs(10) {
        std::thread::yield_now();
    }
}

fn wait_for(cond: impl Fn() -> bool, limit: Duration) -> bool {
    let t = Instant::now();
    while !cond() {
        if t.elapsed() >= limit {
            return false;
        }
        std::thread::yield_now();
    }
    true
}

/// What one parked copy against one concurrent change of its leaf came to.
struct Outcome {
    /// The change (an unmap, a write-protect, a fork) returned while the copy
    /// was still parked on the frame.
    freed_under_copy: bool,
    /// ... and `alloc_page` then handed that very frame out again.
    reissued: bool,
    /// The copy's own answer.
    copied: bool,
    /// What the change answered (frames an unmap released).
    freed: u32,
    /// The frame the page was backed by.
    frame: usize,
}

/// Map one fresh frame at [`VA`], start `copy` on its own thread (the real
/// `azos_mm::uaccess` loop `copy_to_user`/`copy_from_user` run for a user
/// task, given the page table: the shim's "current task" belongs to the test
/// thread; it parks in the hook), run `change` on the page table from a third
/// thread, and see whether it got through while the copy held the frame.
/// `fill_reissued` runs on the frame if the allocator handed it out again in
/// that window, before the copy is let go.
fn race(copy: fn(usize) -> bool, change: fn(usize) -> u32, fill_reissued: fn(*mut u8)) -> Outcome {
    let pt = fresh_root();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(1);
    let frame = azos_mm::pmm::alloc_page().expect("arena").as_usize();
    // A known "user" content for the read direction.
    unsafe { core::ptr::write_bytes(frame as *mut u8, 0x11, PAGE_SIZE) };
    azos_mm::vmm::map(pt, VA, frame, PagePerms::USER_RW).expect("map");

    STAGE.store(0, SeqCst);
    azos_mm::uaccess::shim_set_hook(Some(park));
    let copier = std::thread::spawn(move || {
        azos_mm::uaccess::shim_set_cpu(1);
        copy(pt)
    });
    assert!(wait_for(|| STAGE.load(SeqCst) == 1, Duration::from_secs(10)), "the copy never reached its frame");

    let returned = Arc::new(AtomicBool::new(false));
    let r = returned.clone();
    let unmapper = std::thread::spawn(move || {
        azos_mm::uaccess::shim_set_cpu(2);
        let n = change(pt);
        r.store(true, SeqCst);
        n
    });
    let freed_under_copy = wait_for(|| returned.load(SeqCst), UNMAP_GRACE);

    // If the frame is free already, show what that means: the next
    // allocation gets it. Kept until the end so nothing else can take it.
    let mut held = Vec::new();
    let mut reissued = false;
    if freed_under_copy {
        for _ in 0..256 {
            let Ok(p) = azos_mm::pmm::alloc_page() else { break };
            held.push(p);
            if p.as_usize() == frame {
                reissued = true;
                fill_reissued(frame as *mut u8);
                break;
            }
        }
    }
    STAGE.store(2, SeqCst);
    let copied = copier.join().expect("copier");
    let freed = unmapper.join().expect("unmapper");
    azos_mm::uaccess::shim_set_hook(None);
    for p in held {
        let _ = azos_mm::pmm::free_page(p);
    }
    azos_sched::set_current_user_pt(0);
    Outcome { freed_under_copy, reissued, copied, freed, frame }
}

/// The unmap a sibling thread's `munmap` runs.
fn unmap(pt: usize) -> u32 {
    azos_mm::vmm::unmap_user_range_and_free(pt, VA, VA + PAGE_SIZE, 0, 0)
}

fn nothing(_: *mut u8) {}

/// The write direction: the kernel copies 4 KiB out to a user page another
/// thread unmaps.
///
/// **Divergence:** without the readers' wait (`uaccess-race-canary`, or the
/// code before the sections) the unmap returns while the copy is parked, the
/// frame is reissued and zeroed by its new owner, and the parked copy then
/// overwrites the new owner's page with 0xA5.
#[test]
fn copy_to_user_keeps_its_frame_until_the_copy_ends() {
    let _g = serial();
    fn copy(pt: usize) -> bool {
        let src = [0xA5u8; PAGE_SIZE];
        azos_mm::uaccess::copy_out(pt, VA, src.as_ptr(), PAGE_SIZE)
    }
    fn zero(p: *mut u8) {
        unsafe { core::ptr::write_bytes(p, 0, PAGE_SIZE) };
    }
    let o = race(copy, unmap, zero);
    let scribbled = o.reissued && unsafe { *(o.frame as *const u8) } == 0xA5;
    assert!(
        !o.freed_under_copy,
        "munmap freed the frame of a copy still in flight (reissued: {}, the new owner's page overwritten by the copy: {})",
        o.reissued, scribbled,
    );
    assert!(o.copied, "the copy resolved its page before the unmap: it must succeed");
    assert_eq!(o.freed, 1, "the unmap releases the frame, after the copy");
}

/// The read direction: the kernel copies 4 KiB in from a user page another
/// thread unmaps.
///
/// **Divergence:** without the readers' wait the frame is reissued under the
/// parked read, its new owner writes 0x5E into it, and the read hands those
/// bytes (another owner's data) to the caller.
#[test]
fn copy_from_user_keeps_its_frame_until_the_copy_ends() {
    let _g = serial();
    static LEAKED: AtomicBool = AtomicBool::new(false);
    fn copy(pt: usize) -> bool {
        let mut dst = [0u8; PAGE_SIZE];
        let ok = azos_mm::uaccess::copy_in(pt, dst.as_mut_ptr(), VA, PAGE_SIZE);
        LEAKED.store(dst.iter().any(|&b| b == 0x5E), SeqCst);
        ok
    }
    fn secret(p: *mut u8) {
        unsafe { core::ptr::write_bytes(p, 0x5E, PAGE_SIZE) };
    }
    LEAKED.store(false, SeqCst);
    let o = race(copy, unmap, secret);
    assert!(
        !o.freed_under_copy,
        "munmap freed the frame of a read still in flight (reissued: {}, the new owner's bytes read back: {})",
        o.reissued,
        LEAKED.load(SeqCst),
    );
    assert!(o.copied);
    assert!(!LEAKED.load(SeqCst));
    assert_eq!(o.freed, 1);
}

/// `mprotect(PROT_READ)` by a sibling while the kernel writes the page.
///
/// **Divergence:** without the wait, `mprotect` returns while the parked write
/// is still to come, so a store lands in a page the process was told is
/// read-only (as a ring-3 store through a stale TLB entry would, which the
/// shootdown exists to rule out).
#[test]
fn a_write_protect_waits_for_a_write_in_flight() {
    let _g = serial();
    fn copy(pt: usize) -> bool {
        let src = [0xA5u8; PAGE_SIZE];
        azos_mm::uaccess::copy_out(pt, VA, src.as_ptr(), PAGE_SIZE)
    }
    fn protect(pt: usize) -> u32 {
        azos_mm::vmm::protect_user_range(pt, VA, VA + PAGE_SIZE, false) as u32
    }
    let o = race(copy, protect, nothing);
    assert!(!o.freed_under_copy, "mprotect returned while a write into the page was still in flight");
    assert!(o.copied);
    assert_eq!(o.freed, 1, "one leaf lost its write permission");
}

/// A fork while the kernel writes the parent's page: the child must not get
/// a share of the frame with a write still to land in it.
///
/// **Divergence:** without the wait, `fork_cow` returns (the frame now shared
/// copy-on-write with the child) and the parked write then lands in the
/// shared frame, so the child sees bytes its parent wrote after the fork.
#[test]
fn a_fork_waits_for_a_write_in_flight() {
    let _g = serial();
    static CHILD: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    fn copy(pt: usize) -> bool {
        let src = [0xA5u8; PAGE_SIZE];
        azos_mm::uaccess::copy_out(pt, VA, src.as_ptr(), PAGE_SIZE)
    }
    fn fork(pt: usize) -> u32 {
        let child = azos_mm::vmm::fork_cow(pt, 0, 0).expect("fork");
        CHILD.store(child, SeqCst);
        0
    }
    let o = race(copy, fork, nothing);
    let child = CHILD.load(SeqCst);
    let child_sees = azos_mm::vmm::translate_user(child, VA, false)
        .is_some_and(|pa| unsafe { *(pa as *const u8) } == 0xA5);
    assert!(
        !o.freed_under_copy,
        "fork returned while a write into the parent's page was in flight (the child sees it: {child_sees})"
    );
    assert!(o.copied);
}

/// The scalar path (`copy_small`: an argument, a futex word) under the same
/// race as the page copy above.
///
/// **Divergence:** as `copy_to_user_keeps_its_frame_until_the_copy_ends`,
/// for the eight bytes the parked scalar store then writes into the reissued
/// frame.
#[test]
fn a_scalar_copy_keeps_its_frame_until_it_ends() {
    let _g = serial();
    fn copy(pt: usize) -> bool {
        let v = 0xA5A5_A5A5_A5A5_A5A5u64;
        azos_mm::uaccess::copy_out(pt, VA, &v as *const u64 as *const u8, 8)
    }
    fn zero(p: *mut u8) {
        unsafe { core::ptr::write_bytes(p, 0, PAGE_SIZE) };
    }
    let o = race(copy, unmap, zero);
    let scribbled = o.reissued && unsafe { *(o.frame as *const u8) } == 0xA5;
    assert!(
        !o.freed_under_copy,
        "munmap freed the frame of a scalar store still in flight (reissued: {}, overwritten: {})",
        o.reissued, scribbled,
    );
    assert!(o.copied);
    assert_eq!(o.freed, 1);
}
