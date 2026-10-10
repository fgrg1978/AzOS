// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The direct handoff (wave 15 N13, Kconfig IPC_DIRECT_HANDOFF), every ISA.
//!
//! * `ipc_handoff_refuses_less_urgent_peer`: a caller asks for a handoff to
//!   a peer blocked on exactly the event, but less urgent than itself. The
//!   scheduler's switch refuses with `LowerPriority` before any wake, and
//!   the peer stays blocked (the caller's normal path would wake it and
//!   the more urgent task keeps running). Driven through
//!   `handoff_try_for_test`, the production staging and switch without the
//!   Kconfig gate, so the default kernel (symbol n) judges it too.
//!   Canary `canary=handoff-any-prio`: the check is skipped, the peer is
//!   woken (claimed or enqueued) and the answer is not `LowerPriority`:
//!   `not ok`.

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

use azos_sched::WaitReason;
use azos_sync::handoff::{HandoffReason, HandoffRefused};

/// Lower number = more urgent; both fair-band priorities.
const CALLER_PRIO: u32 = 14;
const PEER_PRIO: u32 = 20;
/// The caller's block reason should the switch (wrongly) be taken.
const HANDLE: u64 = 0x13_0000_0001;
const NOT_YET: i32 = i32::MIN;

static PEER_TID: AtomicU32 = AtomicU32::new(0);
static PEER_WOKES: AtomicU32 = AtomicU32::new(0);
static PEER_RELEASE: AtomicBool = AtomicBool::new(false);
static PEER_DONE: AtomicBool = AtomicBool::new(false);
static RESULT: AtomicI32 = AtomicI32::new(NOT_YET);

fn sleep_ms(ms: u64) {
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    let due = azos_drv_sys::timebase::now() + ms * per_ms;
    azos_sched::task_block(WaitReason::Timer(due));
}

/// Blocks as a server waiting in accept; counts every wake before release.
fn peer(_: usize) {
    let me = azos_sched::current_task_tid();
    PEER_TID.store(me, Ordering::Release);
    while !PEER_RELEASE.load(Ordering::Acquire) {
        azos_sched::task_block(WaitReason::FastIpcServer(me));
        if !PEER_RELEASE.load(Ordering::Acquire) {
            PEER_WOKES.fetch_add(1, Ordering::Relaxed);
        }
    }
    PEER_DONE.store(true, Ordering::Release);
}

fn caller(_: usize) {
    let p = PEER_TID.load(Ordering::Acquire);
    let r = azos_sched::scheduler::handoff_try_for_test(
        p,
        WaitReason::FastIpcServer(p),
        WaitReason::FastIpcClient(HANDLE),
        HandoffReason::IpcCall,
    );
    RESULT.store(
        match r {
            Ok(()) => -1,
            Err(e) => e.index() as i32,
        },
        Ordering::Release,
    );
}

azos_ktest::ktest_late! {
    fn ipc_handoff_refuses_less_urgent_peer() {
        azos_sched::task_create_affinity("n13-peer", peer, 0, PEER_PRIO, -1);
        crate::ktest::wait("the peer never started", || PEER_TID.load(Ordering::Acquire) != 0)?;
        // Let it reach its block.
        sleep_ms(10);
        azos_sched::task_create_affinity("n13-call", caller, 0, CALLER_PRIO, -1);
        crate::ktest::wait("the caller never came back from the handoff",
            || RESULT.load(Ordering::Acquire) != NOT_YET)?;
        let r = RESULT.load(Ordering::Acquire);
        if r == HandoffRefused::Disabled.index() as i32 {
            return Err("the switch is compiled out (no sched-ipc-affinity) or refused its preconditions");
        }
        if r != HandoffRefused::LowerPriority.index() as i32 {
            return Err("the handoff did not refuse a less urgent peer");
        }
        sleep_ms(10);
        if PEER_WOKES.load(Ordering::Relaxed) != 0 {
            return Err("the refused handoff woke the peer");
        }
        // Release the peer the ordinary way.
        PEER_RELEASE.store(true, Ordering::Release);
        let p = PEER_TID.load(Ordering::Acquire);
        azos_sched::scheduler::wake_task_by_tid(p, &|w| *w == WaitReason::FastIpcServer(p));
        crate::ktest::wait("the peer never ran to its end", || PEER_DONE.load(Ordering::Acquire))?;
        Ok(())
    }
}
