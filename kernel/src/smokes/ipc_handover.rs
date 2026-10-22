// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Live update, Level 1 hooks, every ISA.
//!
//! * `ipc_handover_under_load_loses_no_call`: clients call an echo endpoint
//!   in a loop while its server is replaced by a successor with the
//!   endpoint-level handover the supervisor's swap verb drives (open the
//!   swap, the successor's grant, begin, wait for the old server's calls in
//!   service, re-present halfway, rebind). Every call is answered with its
//!   own reply, none ends `-EPEERDIED`, none is lost, none is answered
//!   twice (the replies the two servers delivered add up to the calls made:
//!   a re-presented call's first reply is refused, not delivered), and both
//!   servers served some (the swap happened under load).
//!
//! The servers are kernel tasks (the fast calls go through
//! `syscall_dispatch_out`, the arms ring 3 reaches). The supervisor's own
//! orchestration (`drv_supervisor::swap`: the spawn from the signed row, the
//! successor joining the old server's domain, the retirement of the old task) needs a
//! supervised ring-3 image and is not run here.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use azos_abi::syscall_nr::{SYS_IPC_FAST_ACCEPT, SYS_IPC_FAST_CALL_EP, SYS_IPC_FAST_REPLY};
use azos_ipc::cap::CapPerms;
use azos_syscall::SyscallOut;

const PRIO: u32 = 12;
const EP: &[u8] = b"lu.echo";
const CLIENTS: usize = 6;
const CALLS: usize = 40;
/// Attempts per call: a call resolved to the old server that reaches the
/// queue after the flip is refused (an endpoint that changed server) and
/// made again; it is counted in `RETRIED`, and must never be answered twice.
const TRIES: usize = 5;

static TID_A: AtomicU32 = AtomicU32::new(0);
static TID_B: AtomicU32 = AtomicU32::new(0);
static A_READY: AtomicBool = AtomicBool::new(false);
static B_READY: AtomicBool = AtomicBool::new(false);
static STOP: AtomicBool = AtomicBool::new(false);
/// Replies each server delivered (`SYS_IPC_FAST_REPLY` returned 0).
static SERVED_A: AtomicUsize = AtomicUsize::new(0);
static SERVED_B: AtomicUsize = AtomicUsize::new(0);
static OK: AtomicUsize = AtomicUsize::new(0);
static LOST: AtomicUsize = AtomicUsize::new(0);
static RETRIED: AtomicUsize = AtomicUsize::new(0);

fn dispatch(num: u64, a: [u64; 6], out: &mut SyscallOut) -> i64 {
    let regs = azos_sched::UserRegs::default();
    azos_syscall::syscall_dispatch_out(num, a[0], a[1], a[2], a[3], a[4], a[5], 0, 0, &regs, out)
}

fn sleep_ms(ms: u64) {
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    let due = azos_drv_sys::timebase::now() + ms * per_ms;
    azos_sched::task_block(azos_sched::WaitReason::Timer(due));
}

/// Accept, work for `work_ms`, reply `w0 + 1`, until stopped. Counts the
/// replies delivered: one refused (a call re-presented to the successor
/// while this server worked on it) is not an answer.
fn serve_loop(served: &AtomicUsize, work_ms: u64) {
    let mut out = SyscallOut::new();
    while !STOP.load(Ordering::Acquire) {
        let h = dispatch(SYS_IPC_FAST_ACCEPT, [0; 6], &mut out);
        if h < 0 {
            continue; // nothing delivered (a handover, or the accept's turns ran out)
        }
        let w0 = out.regs[1];
        if work_ms != 0 {
            sleep_ms(work_ms);
        }
        if dispatch(SYS_IPC_FAST_REPLY, [h as u64, w0 + 1, 0, 0, 0, 0], &mut out) == 0 {
            served.fetch_add(1, Ordering::AcqRel);
        }
    }
}

fn old_server(_: usize) {
    let me = azos_sched::current_task_tid();
    if azos_ipc::endpoint::endpoint_named_cap(me, CapPerms::READ, EP).is_none() {
        return;
    }
    TID_A.store(me, Ordering::Release);
    A_READY.store(true, Ordering::Release);
    serve_loop(&SERVED_A, 3);
}

fn new_server(_: usize) {
    let me = azos_sched::current_task_tid();
    // The successor's grant: holds the capability, claims nothing.
    if azos_ipc::endpoint::endpoint_named_cap(me, CapPerms::READ, EP).is_none() {
        return;
    }
    TID_B.store(me, Ordering::Release);
    B_READY.store(true, Ordering::Release);
    serve_loop(&SERVED_B, 0);
}

fn client(k: usize) {
    let me = azos_sched::current_task_tid();
    let Some(cap) = azos_ipc::endpoint::endpoint_named_cap(me, CapPerms::WRITE, EP).map(|c| c.raw().0 as u64) else {
        LOST.fetch_add(CALLS, Ordering::AcqRel);
        return;
    };
    let mut out = SyscallOut::new();
    for n in 0..CALLS {
        let w = 0x1000 + (k * CALLS + n) as u64;
        let mut done = false;
        for t in 0..TRIES {
            let rc = dispatch(SYS_IPC_FAST_CALL_EP, [cap, w, 0, 0, 0, 0], &mut out);
            if rc == (w + 1) as i64 {
                OK.fetch_add(1, Ordering::AcqRel);
                done = true;
                break;
            }
            // Only a refusal at the flip is made again; PEER_DIED is a loss.
            if rc == azos_abi::error::Errno::EPEERDIED.to_syscall_ret() {
                break;
            }
            if t + 1 < TRIES {
                RETRIED.fetch_add(1, Ordering::AcqRel);
                sleep_ms(1);
            }
        }
        if !done {
            LOST.fetch_add(1, Ordering::AcqRel);
        }
    }
}

azos_ktest::ktest_late! {
    fn ipc_handover_under_load_loses_no_call() {
        use azos_ipc::endpoint::{
            endpoint_handover_begin_all, endpoint_handover_in_service, endpoint_handover_represent_all,
            endpoint_rebind_all, endpoint_swap_cancel, endpoint_swap_open,
        };
        azos_sched::task_create_affinity("lu-old", old_server, 0, PRIO, -1);
        crate::ktest::wait("the old server never claimed the endpoint", || A_READY.load(Ordering::Acquire))?;
        for k in 0..CLIENTS {
            azos_sched::task_create_affinity("lu-cli", client, k, PRIO, -1);
        }
        crate::ktest::wait("the old server served nothing", || SERVED_A.load(Ordering::Acquire) >= 5)?;
        let old = TID_A.load(Ordering::Acquire);

        // The swap, as the supervisor drives it.
        if endpoint_swap_open(old) != 1 {
            return Err("the swap did not open on the old server's named endpoint");
        }
        azos_sched::task_create_affinity("lu-new", new_server, 0, PRIO, -1);
        crate::ktest::wait("the successor never took its grant", || B_READY.load(Ordering::Acquire))?;
        let new = TID_B.load(Ordering::Acquire);
        let owner_ok = azos_ipc::endpoint::endpoint_ref_by_name(EP)
            .and_then(|r| azos_ipc::endpoint::endpoint_owner_ref(r).ok()) == Some(old);
        if !owner_ok {
            return Err("the successor's grant claimed the endpoint");
        }
        if endpoint_handover_begin_all(old, new).is_err() {
            let _ = endpoint_swap_cancel(old);
            return Err("the handover was refused");
        }
        let t0 = azos_drv_sys::timebase::now();
        let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
        let mut represented = false;
        while endpoint_handover_in_service(old) != 0 {
            let waited = azos_drv_sys::timebase::now().saturating_sub(t0) / per_ms;
            if !represented && waited > 500 {
                represented = true;
                let _ = endpoint_handover_represent_all(old);
            }
            if waited > 2000 {
                let _ = endpoint_swap_cancel(old);
                return Err("the old server's calls in service never finished");
            }
            sleep_ms(1);
        }
        if endpoint_rebind_all(old, new).is_err() {
            let _ = endpoint_swap_cancel(old);
            return Err("the rebind was refused");
        }
        azos_sched::wake_fast_ipc_server(new);

        crate::ktest::wait("not every call came back",
            || OK.load(Ordering::Acquire) + LOST.load(Ordering::Acquire) == CLIENTS * CALLS)?;
        // A server counts its reply after the reply woke the client: wait for
        // the counts to catch up with the answers before reading them.
        let served = || SERVED_A.load(Ordering::Acquire) + SERVED_B.load(Ordering::Acquire);
        let _ = crate::ktest::wait("the servers' counts never caught up", || served() >= OK.load(Ordering::Acquire));
        STOP.store(true, Ordering::Release);
        azos_sched::scheduler::task_stop(old, true, 9);
        azos_sched::scheduler::task_stop(new, true, 9);
        if LOST.load(Ordering::Acquire) != 0 {
            return Err("a call was lost or ended -EPEERDIED across the handover");
        }
        if OK.load(Ordering::Acquire) != CLIENTS * CALLS {
            return Err("a call was not answered with its own reply");
        }
        azos_drv_sys::kprintln!(
            "# ipc_handover_under_load_loses_no_call: {} served by the old server, {} by the successor, {} retried",
            SERVED_A.load(Ordering::Acquire), SERVED_B.load(Ordering::Acquire), RETRIED.load(Ordering::Acquire)
        );
        if served() > CLIENTS * CALLS {
            return Err("the servers delivered more replies than calls were made: a call was answered twice");
        }
        if served() < CLIENTS * CALLS {
            return Err("a reply the client took was not counted as delivered by either server");
        }
        if SERVED_A.load(Ordering::Acquire) == 0 || SERVED_B.load(Ordering::Acquire) == 0 {
            return Err("the swap did not happen under load: one of the servers served nothing");
        }
        Ok(())
    }
}
