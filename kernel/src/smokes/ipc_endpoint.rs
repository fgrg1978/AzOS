// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The endpoint object (wave 15 N5, Kconfig IPC_ENDPOINT_QUEUES), every ISA.
//! Kernel tasks make the fast calls through `syscall_dispatch_out`, the arms
//! ring 3 reaches.
//!
//! * `ipc_server_death_completes_call_peer_died`: a server accepts a call
//!   and dies without answering; the caller's call returns `-EPEERDIED`.
//!   Canary `canary=ipc-no-peer-died`: the death leaves the accepted call in
//!   service, nobody completes it, the caller never returns, and the wait
//!   times out: `not ok`.
//! * `ipc_endpoint_destroy_completes_call_revoked`: the owner destroys its
//!   endpoint with a call in service and one queued; both return
//!   `-EREVOKED`.
//! * `ipc_endpoint_many_callers_queue`: callers queue on one endpoint while
//!   its server sleeps, then all are answered, each with its own reply.
//! * `ipc_endpoint_slot_reused_after_grace`: a destroyed endpoint's slot is
//!   held out of the pool until a grace period has passed (`call_rcu`).
//!   Canary `canary=rcu-free-no-grace`: the slot is back at once, `not ok`.

use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicUsize, Ordering};

use azos_abi::error::Errno;
use azos_abi::syscall_nr::{SYS_IPC_FAST_ACCEPT, SYS_IPC_FAST_CALL_EP, SYS_IPC_FAST_REPLY};
use azos_ipc::cap::CapPerms;
use azos_syscall::SyscallOut;

const PRIO: u32 = 12;
const NOT_YET: i64 = i64::MIN;

fn dispatch(num: u64, a: [u64; 6], out: &mut SyscallOut) -> i64 {
    let regs = azos_sched::UserRegs::default();
    azos_syscall::syscall_dispatch_out(num, a[0], a[1], a[2], a[3], a[4], a[5], 0, 0, &regs, out)
}

fn sleep_ms(ms: u64) {
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    let due = azos_drv_sys::timebase::now() + ms * per_ms;
    azos_sched::task_block(azos_sched::WaitReason::Timer(due));
}

/// The client's capability on endpoint `name` (WRITE), as a raw handle.
fn client_cap(name: &[u8]) -> Option<u64> {
    let me = azos_sched::current_task_tid();
    azos_ipc::endpoint::endpoint_named_cap(me, CapPerms::WRITE, name).map(|c| c.raw().0 as u64)
}

/// Claim endpoint `name` as its server (READ).
fn serve(name: &[u8]) -> bool {
    let me = azos_sched::current_task_tid();
    azos_ipc::endpoint::endpoint_named_cap(me, CapPerms::READ, name).is_some()
}

// ── PeerDied ────────────────────────────────────────────────────────────────

const DIE_EP: &[u8] = b"n5.die";
static DIE_READY: AtomicBool = AtomicBool::new(false);
static DIE_ACCEPTED: AtomicBool = AtomicBool::new(false);
static DIE_RC: AtomicI64 = AtomicI64::new(NOT_YET);

fn die_server(_: usize) {
    if !serve(DIE_EP) {
        return;
    }
    DIE_READY.store(true, Ordering::Release);
    let mut out = SyscallOut::new();
    // Take the call, then return without answering: the task exits with
    // the call in service.
    let h = dispatch(SYS_IPC_FAST_ACCEPT, [0; 6], &mut out);
    DIE_ACCEPTED.store(h >= 0, Ordering::Release);
}

fn die_client(_: usize) {
    let Some(cap) = client_cap(DIE_EP) else {
        DIE_RC.store(-12345, Ordering::Release);
        return;
    };
    let mut out = SyscallOut::new();
    let rc = dispatch(SYS_IPC_FAST_CALL_EP, [cap, 0xD1E, 0, 0, 0, 0], &mut out);
    DIE_RC.store(rc, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn ipc_server_death_completes_call_peer_died() {
        if !azos_limits::IPC_ENDPOINT_QUEUES {
            return Err("Kconfig IPC_ENDPOINT_QUEUES is off in this ktest kernel");
        }
        azos_sched::task_create_affinity("n5-die-srv", die_server, 0, PRIO, -1);
        crate::ktest::wait("the server never claimed its endpoint", || DIE_READY.load(Ordering::Acquire))?;
        azos_sched::task_create_affinity("n5-die-cli", die_client, 0, PRIO, -1);
        crate::ktest::wait("the caller was never completed (no PeerDied)",
            || DIE_RC.load(Ordering::Acquire) != NOT_YET)?;
        if !DIE_ACCEPTED.load(Ordering::Acquire) {
            return Err("the server never took the call");
        }
        if DIE_RC.load(Ordering::Acquire) != Errno::EPEERDIED.to_syscall_ret() {
            return Err("the call returned something other than -EPEERDIED");
        }
        Ok(())
    }
}

// ── Revoked ─────────────────────────────────────────────────────────────────

const REV_EP: &[u8] = b"n5.rev";
static REV_READY: AtomicBool = AtomicBool::new(false);
static REV_ACCEPTED: AtomicBool = AtomicBool::new(false);
static REV_GO: AtomicBool = AtomicBool::new(false);
static REV_DESTROYED: AtomicBool = AtomicBool::new(false);
static REV_RC: [AtomicI64; 2] = [const { AtomicI64::new(NOT_YET) }; 2];

fn rev_server(_: usize) {
    if !serve(REV_EP) {
        return;
    }
    REV_READY.store(true, Ordering::Release);
    let mut out = SyscallOut::new();
    let h = dispatch(SYS_IPC_FAST_ACCEPT, [0; 6], &mut out);
    REV_ACCEPTED.store(h >= 0, Ordering::Release);
    // Wait for the second call to be queued, then destroy the endpoint with
    // one call in service and one queued.
    while !REV_GO.load(Ordering::Acquire) {
        sleep_ms(5);
    }
    sleep_ms(20);
    let me = azos_sched::current_task_tid();
    if let Some(r) = azos_ipc::endpoint::endpoint_ref_by_name(REV_EP) {
        REV_DESTROYED.store(azos_ipc::endpoint::destroy_ref_as(r, me).is_ok(), Ordering::Release);
    }
    // The in-service call is over: answering it is refused.
    let late = dispatch(SYS_IPC_FAST_REPLY, [h as u64, 1, 0, 0, 0, 0], &mut out);
    if late == 0 {
        REV_DESTROYED.store(false, Ordering::Release);
    }
}

fn rev_client(k: usize) {
    let Some(cap) = client_cap(REV_EP) else {
        REV_RC[k].store(-12345, Ordering::Release);
        return;
    };
    if k == 1 {
        REV_GO.store(true, Ordering::Release);
    }
    let mut out = SyscallOut::new();
    let rc = dispatch(SYS_IPC_FAST_CALL_EP, [cap, 0x5EF + k as u64, 0, 0, 0, 0], &mut out);
    REV_RC[k].store(rc, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn ipc_endpoint_destroy_completes_call_revoked() {
        if !azos_limits::IPC_ENDPOINT_QUEUES {
            return Err("Kconfig IPC_ENDPOINT_QUEUES is off in this ktest kernel");
        }
        azos_sched::task_create_affinity("n5-rev-srv", rev_server, 0, PRIO, -1);
        crate::ktest::wait("the server never claimed its endpoint", || REV_READY.load(Ordering::Acquire))?;
        azos_sched::task_create_affinity("n5-rev-cli0", rev_client, 0, PRIO, -1);
        crate::ktest::wait("the server never took the first call", || REV_ACCEPTED.load(Ordering::Acquire))?;
        azos_sched::task_create_affinity("n5-rev-cli1", rev_client, 1, PRIO, -1);
        crate::ktest::wait("a caller was never completed (no Revoked)", || {
            REV_RC.iter().all(|r| r.load(Ordering::Acquire) != NOT_YET)
        })?;
        if !REV_DESTROYED.load(Ordering::Acquire) {
            return Err("the owner could not destroy its endpoint, or answered a revoked call");
        }
        let want = Errno::EREVOKED.to_syscall_ret();
        if REV_RC.iter().any(|r| r.load(Ordering::Acquire) != want) {
            return Err("a call returned something other than -EREVOKED");
        }
        Ok(())
    }
}

// ── Many callers on one endpoint ────────────────────────────────────────────

const MANY_EP: &[u8] = b"n5.many";
/// Callers at once: bounded by the ktest kernel's task slots, not by the
/// fast call (the host suite queues 150, past the old table's 64 slots).
const MANY: usize = 12;
static MANY_READY: AtomicBool = AtomicBool::new(false);
static MANY_QUEUED: AtomicUsize = AtomicUsize::new(0);
static MANY_OK: AtomicUsize = AtomicUsize::new(0);
static MANY_SEEN_QUEUED: AtomicU32 = AtomicU32::new(0);

fn many_server(_: usize) {
    if !serve(MANY_EP) {
        return;
    }
    MANY_READY.store(true, Ordering::Release);
    // Let every caller queue before serving any.
    let deadline_ms = 2000u64;
    let mut waited = 0;
    while MANY_QUEUED.load(Ordering::Acquire) < MANY && waited < deadline_ms {
        sleep_ms(10);
        waited += 10;
    }
    sleep_ms(30);
    MANY_SEEN_QUEUED.store(azos_ipc::fastcall::census().0, Ordering::Release);
    let mut out = SyscallOut::new();
    for _ in 0..MANY {
        let h = dispatch(SYS_IPC_FAST_ACCEPT, [0; 6], &mut out);
        if h < 0 {
            return;
        }
        let w0 = out.regs[1];
        dispatch(SYS_IPC_FAST_REPLY, [h as u64, w0 + 1, 0, 0, 0, 0], &mut out);
    }
}

fn many_client(k: usize) {
    let Some(cap) = client_cap(MANY_EP) else { return };
    let mut out = SyscallOut::new();
    MANY_QUEUED.fetch_add(1, Ordering::AcqRel);
    let w = 0x1000 + k as u64;
    let rc = dispatch(SYS_IPC_FAST_CALL_EP, [cap, w, 0, 0, 0, 0], &mut out);
    if rc == (w + 1) as i64 {
        MANY_OK.fetch_add(1, Ordering::AcqRel);
    }
}

azos_ktest::ktest_late! {
    fn ipc_endpoint_many_callers_queue() {
        if !azos_limits::IPC_ENDPOINT_QUEUES {
            return Err("Kconfig IPC_ENDPOINT_QUEUES is off in this ktest kernel");
        }
        azos_sched::task_create_affinity("n5-many-srv", many_server, 0, PRIO, -1);
        crate::ktest::wait("the server never claimed its endpoint", || MANY_READY.load(Ordering::Acquire))?;
        for k in 0..MANY {
            azos_sched::task_create_affinity("n5-many-cli", many_client, k, PRIO, -1);
        }
        crate::ktest::wait("not every caller was answered", || MANY_OK.load(Ordering::Acquire) == MANY)?;
        if (MANY_SEEN_QUEUED.load(Ordering::Acquire) as usize) < MANY / 2 {
            return Err("the callers never queued together on the endpoint");
        }
        Ok(())
    }
}

// ── Grace period before a slot is reused ────────────────────────────────────

azos_ktest::ktest_late! {
    fn ipc_endpoint_slot_reused_after_grace() {
        if !azos_sync::qsbr::ON {
            return Err("RCU_QSBR is off in this ktest kernel");
        }
        let me = azos_sched::current_task_tid();
        let r = azos_ipc::endpoint::endpoint_create(me).ok_or("no endpoint slot free")?;
        let i = azos_ipc::objref::ENDPOINT.idx(r) as usize;
        azos_ipc::endpoint::destroy_ref_as(r, me).map_err(|_| "the owner could not destroy it")?;
        if !azos_ipc::endpoint::slot_held(i) {
            return Err("the slot was back in the pool before a grace period");
        }
        crate::ktest::wait("the slot never came back after the grace period",
            || !azos_ipc::endpoint::slot_held(i))?;
        Ok(())
    }
}
