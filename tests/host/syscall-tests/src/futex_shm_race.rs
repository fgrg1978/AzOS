// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the futex calls' access to a word of a shm region (front
// futex-shm-word): the frame the word lives in keeps its owner until the
// access ends, whatever another thread unmaps or releases meanwhile.
//
// **The race.** A futex word of a shm region is read (and, by the Linux PI
// calls, swapped) through the kernel's map of its frame, never through the
// user's VA, so no PTE and no TLB shootdown stops the access. The futex paths
// used to take the frame from `memobj_resolve_mapped` under the region table
// lock and use it after the lock was dropped: `vdso_notify::futex_word` kept
// the address for the wait's look at the word, `linux.rs` `futex_word` for
// FUTEX_WAIT/REQUEUE and `ShmPiWord` for the PI read and swap. Between the
// two, a sibling thread's unmap and release (or a revoke of the capability)
// gave the last reference back, the frame went to the PMM, and the next
// allocation handed it to someone else: the wait then compared the new
// owner's bytes with its `expected` (an equality oracle on a foreign page)
// and the PI swap wrote a TID into it.
//
// **How it is made deterministic.** A host-only hook in
// `memobj_with_mapped_word` parks the access right after the word's frame is
// found and before it is touched. A second thread then runs the real
// `memobj_take_mapping_ref` + `memobj_release_ref` of the region's last
// reference. With the access under the table lock, that release cannot return
// while the access is parked; without it (`memobj-word-unlocked-canary`, the
// shape of the old paths) it returns at once, the frame is free, `alloc_page`
// hands it out, and the parked access reads (or writes) the new owner's page.
//
// The wait runs the real `vdso_notify::sys_futex_wait` (key, then the look at
// the word, here from the sched shim's `wait_key`); the swap runs the helper
// `ShmPiWord` calls (linux.rs is not built in this crate).

use super::harness::serial;
use azos_ipc::memobj::{
    memobj_create_ref, memobj_note_mapping_ref, memobj_page_phys_ref, memobj_release_ref, memobj_take_mapping_ref,
    memobj_with_mapped_word, shim_set_word_hook, MapAccess, MemPerms,
};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::SeqCst};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The process that maps the region.
const TID: u32 = 0x6C00_0001;
/// Where it maps it; the futex word is the first of the page.
const VA: usize = 0x4000_0000;
/// The word's value while the region is the process's.
const MINE: u32 = 5;
/// What a new owner of the frame writes into it: the value the wait expects,
/// so a look at the reissued frame "matches".
const THEIRS: u32 = 7;

/// How long the releasing thread is given to return while the access is
/// parked. A release of one page takes microseconds.
const RELEASE_GRACE: Duration = Duration::from_millis(300);

/// 0 not there yet, 1 parked with its frame found, 2 told to go on.
static STAGE: AtomicU32 = AtomicU32::new(0);

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

/// What one parked access against one concurrent release came to.
struct Outcome<T> {
    /// The release returned while the access was still parked on the frame.
    freed_under_access: bool,
    /// ... and `alloc_page` then handed that very frame out again (its new
    /// owner wrote [`THEIRS`] into the word).
    reissued: bool,
    /// The access's own answer.
    answer: T,
    /// The word in the frame afterwards.
    word_after: u32,
}

/// Map a fresh one-page region holding [`MINE`] at [`VA`] for [`TID`], start
/// `access` on its own thread (it parks in the hook), release the region from
/// a third thread, and see whether the release got through while the access
/// held the frame.
fn race<T: Send + 'static>(access: fn() -> T) -> Outcome<T> {
    azos_sched::set_current_task_tid(TID);
    azos_sched::set_current_proc_tid(0);
    azos_sched::set_current_user_pt(0);
    let r = memobj_create_ref(TID, 1, MemPerms::ReadWrite).expect("a region");
    let frame = memobj_page_phys_ref(r, 0).expect("live").expect("a frame");
    let word = azos_mm::addr::phys_to_virt(frame) as *mut u32;
    unsafe { word.write_volatile(MINE) };
    assert_eq!(memobj_note_mapping_ref(TID, r, 0x1000, VA, 1, MapAccess::RW), Ok(true));

    STAGE.store(0, SeqCst);
    shim_set_word_hook(Some(park));
    // The access runs the syscall as the current task: the shim's state is
    // lent to its thread for the call (the test thread touches none of it
    // until the join takes it back).
    let accessor = std::thread::spawn(move || {
        azos_sched::shim_serial_enter();
        access()
    });
    assert!(wait_for(|| STAGE.load(SeqCst) == 1, Duration::from_secs(10)), "the access never reached its frame");

    let returned = Arc::new(AtomicBool::new(false));
    let done = returned.clone();
    let releaser = std::thread::spawn(move || {
        // A sibling's munmap, then the last reference (a close, a revoke).
        let taken = memobj_take_mapping_ref(TID, r);
        let released = memobj_release_ref(TID, r);
        done.store(true, SeqCst);
        (taken, released)
    });
    let freed_under_access = wait_for(|| returned.load(SeqCst), RELEASE_GRACE);

    // If the frame is free already, show what that means: the next
    // allocation gets it and its owner writes its own word.
    let mut held = Vec::new();
    let mut reissued = false;
    if freed_under_access {
        for _ in 0..256 {
            let Ok(p) = azos_mm::pmm::alloc_page() else { break };
            held.push(p);
            if p.as_usize() == frame {
                reissued = true;
                unsafe { word.write_volatile(THEIRS) };
                break;
            }
        }
    }
    STAGE.store(2, SeqCst);
    let answer = accessor.join().expect("accessor");
    azos_sched::shim_serial_enter();
    let (taken, released) = releaser.join().expect("releaser");
    shim_set_word_hook(None);
    let word_after = unsafe { word.read_volatile() };
    for p in held {
        let _ = azos_mm::pmm::free_page(p);
    }
    assert_eq!(taken, Ok(Some((VA, 1))), "the mapping was taken");
    assert_eq!(released, Ok(()), "the last reference was given back");
    Outcome { freed_under_access, reissued, answer, word_after }
}

/// The native wait: `SYS_FUTEX_WAIT` on the shm word, expecting [`THEIRS`].
/// Its own word holds [`MINE`], so the answer is `-EAGAIN`.
///
/// **Divergence:** with the word used outside the table lock
/// (`memobj-word-unlocked-canary`, or the code before this front) the release
/// returns while the look is parked, the frame is reissued with [`THEIRS`] in
/// it, and the wait reads the new owner's word: it "matches" and answers 0, as
/// if it had slept and been woken, on a value of a page it never mapped.
#[test]
fn a_futex_wait_keeps_its_shm_frame_until_its_look_ends() {
    let _g = serial();
    fn wait() -> i64 {
        crate::vdso_notify::sys_futex_wait(VA as u64, THEIRS as u64, 0)
    }
    let o = race(wait);
    assert!(
        !o.freed_under_access,
        "the region's last release freed the frame of a futex word still being read (reissued: {}, the wait answered {})",
        o.reissued, o.answer,
    );
    assert_eq!(o.answer, -11, "the wait reads its own word ({MINE}), not {THEIRS}: -EAGAIN");
}

/// The Linux PI calls' swap of a shm word (`ShmPiWord::cmpxchg`, which runs
/// this helper): `0 -> TID`'s shape, here [`MINE`] -> 9.
///
/// **Divergence:** with the word used outside the table lock the frame is
/// reissued under the parked swap and the swap stores into the new owner's
/// page.
#[test]
fn a_pi_swap_keeps_its_shm_frame_until_the_swap_ends() {
    let _g = serial();
    fn swap() -> Option<u32> {
        memobj_with_mapped_word(TID, VA, true, |w| match w.compare_exchange(THEIRS, 9, SeqCst, SeqCst) {
            Ok(v) | Err(v) => v,
        })
    }
    let o = race(swap);
    assert!(
        !o.freed_under_access,
        "the region's last release freed the frame of a PI word still being swapped (reissued: {}, the new owner's word is now {})",
        o.reissued, o.word_after,
    );
    assert_eq!(o.answer, Some(MINE), "the swap saw its own word, which did not hold {THEIRS}");
}
