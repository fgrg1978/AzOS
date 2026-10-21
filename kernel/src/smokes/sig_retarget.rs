// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `signal_retarget_on_thread_detach` (wave 15, FX5): a process-directed
//! signal pending on a thread that is not its process's leader goes back to
//! the process when the thread's signal state is detached (its exit; Linux
//! keeps it in the shared pending set), and a thread-directed one ends with
//! the thread.
//!
//! Deterministic, with no userspace: the ktest's own task is the leader and
//! blocks the signal, a parked kernel task is the other member (a
//! `ktest_group` group), so `post` can only land on the member; the test
//! then calls `signal::detach` on it directly. The userspace row (LXHELLO
//! `stage_sig_retarget`) cannot reach this path since a futex wait ends with
//! EINTR on a deliverable signal (N9): its thread runs the handler first.
//!
//! Canary `canary=sig-exit-drop`: `detach` drops the process's signal with
//! the thread, `not ok`.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use azos_sched::scheduler::signal::{self as sig, Posted};

/// Fair band: the member only waits for the go.
const MEMBER_PRIO: u32 = 20;
const SIGUSR1: u32 = 10;
const SIGUSR2: u32 = 12;

const fn bit(s: u32) -> u64 {
    1u64 << (s - 1)
}

static MEMBER_TID: AtomicU32 = AtomicU32::new(0);
static GO: AtomicBool = AtomicBool::new(false);
static MEMBER_DONE: AtomicBool = AtomicBool::new(false);

fn sleep_ms(ms: u64) {
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    let due = azos_drv_sys::timebase::now() + ms * per_ms;
    azos_sched::task_block(azos_sched::WaitReason::Timer(due));
}

/// Parks until the go (a post wakes its timer wait early; it waits again).
fn member(_: usize) {
    MEMBER_TID.store(azos_sched::scheduler::current_task_tid(), Ordering::Release);
    for _ in 0..10_000 {
        if GO.load(Ordering::Acquire) {
            break;
        }
        sleep_ms(1);
    }
    MEMBER_DONE.store(true, Ordering::Release);
}

fn retarget(lead: u32, t: u32) -> Result<(), &'static str> {
    if !sig::attach(lead, bit(SIGUSR1), 0) || !sig::attach(t, 0, 0) {
        return Err("attach refused a live task");
    }
    if !azos_sched::group::ktest_group(lead, t) {
        return Err("the two tasks could not be made one process");
    }
    if sig::post(lead, SIGUSR1, 0) != Posted::Pending {
        return Err("the process-directed post was not left pending");
    }
    if sig::pending_of(t) & bit(SIGUSR1) == 0 || sig::pending_of(lead) & bit(SIGUSR1) != 0 {
        return Err("the post did not land on the member (the leader blocks it)");
    }
    sig::detach(t);
    if sig::pending_of(lead) & bit(SIGUSR1) == 0 {
        return Err("the member's detach dropped the process's pending signal");
    }
    // A thread-directed signal ends with its thread.
    if !sig::attach(t, 0, 0) {
        return Err("attach refused the member again");
    }
    if sig::post_thread(t, SIGUSR2, 0) != Posted::Pending {
        return Err("the thread-directed post was not left pending");
    }
    sig::detach(t);
    if sig::pending_of(lead) & bit(SIGUSR2) != 0 {
        return Err("a thread-directed signal moved to the process at the thread's detach");
    }
    Ok(())
}

azos_ktest::ktest_late! {
    fn signal_retarget_on_thread_detach() {
        MEMBER_TID.store(0, Ordering::Release);
        MEMBER_DONE.store(false, Ordering::Release);
        GO.store(false, Ordering::Release);
        let lead = azos_sched::scheduler::current_task_tid();
        azos_sched::task_create_affinity("fx5-sig-member", member, 0, MEMBER_PRIO, -1);
        crate::ktest::wait("the member task never started", || MEMBER_TID.load(Ordering::Acquire) != 0)?;
        let t = MEMBER_TID.load(Ordering::Acquire);
        let r = retarget(lead, t);
        // Undone whatever failed: no group and no signal state outlive the
        // test (a group changes every later lookup of the two slots).
        sig::detach(t);
        azos_sched::group::ktest_ungroup(lead, t);
        sig::detach(lead);
        GO.store(true, Ordering::Release);
        crate::ktest::wait("the member task never ended", || MEMBER_DONE.load(Ordering::Acquire))?;
        r
    }
}
