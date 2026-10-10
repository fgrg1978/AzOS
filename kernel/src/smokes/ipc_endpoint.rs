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
//! * `ipc_reply_warrant_moves_to_worker_and_is_send_once` (wave 15 N11): a
//!   server accepts a call and moves its reply warrant to a worker task; the
//!   server can no longer answer, the worker answers, the caller gets the
//!   worker's words, and a second reply on the warrant is refused.
//!   Canary `canary=ipc-reply-twice`: the second reply is delivered, `not ok`.

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
        // Both implementations: the old table holds this many in its slots.
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

// ── Notices on event ports (wave 15 N5b, Kconfig IPC_PORT_NOTICES) ──────────
//
// * `ipc_no_senders_on_last_revoke`: two send capabilities (WRITE, no READ)
//   to an endpoint; revoking the first posts nothing, revoking the last
//   posts one `PORT_EVENT_NO_SENDERS` (code ENOSENDERS) to the port the
//   server bound the endpoint to, and only one.
// * `ipc_no_senders_once_after_staggered_exits`: two client tasks each hold
//   one; the first exits and nothing arrives (the count is 1), the second
//   exits and the notice arrives, once. Canary `canary=ipc-no-senders-wipe`:
//   an exit's table wipe does not count its send capabilities out, the count
//   never falls and the waits time out: `not ok`.
// * `ipc_no_senders_grant_revoke_race`: two CPUs grant and revoke send
//   capabilities in a loop while a third is held: no notice and an exact
//   count after the race; revoking the held one posts one notice.
// * `port_source_gone_wakes_the_waiter`: a task waits on a port bound to a
//   channel and then to an endpoint; destroying each wakes it with
//   `PORT_EVENT_SOURCE_GONE` (code EREVOKED). Canary `canary=port-no-vanish`:
//   the source stays bound and silent, the wait times out: `not ok`.

use azos_abi::syscall_nr::{
    PORT_EVENT_NO_SENDERS, PORT_EVENT_SOURCE_GONE, PORT_SRC_CHANNEL, PORT_SRC_ENDPOINT, SYS_PORT_BIND_TYPED,
    SYS_PORT_POLL_TYPED, SYS_PORT_WAIT_UNTIL_TYPED,
};
use azos_ipc::cap::targets::Endpoint as EpTarget;

type Verdict = Result<(), &'static str>;

/// A decoded 16-byte port event: (key, source type, code).
type Ev = (u64, u8, u16);

fn decode(b: &[u8; 16]) -> Ev {
    let key = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let c = azos_abi::syscall_nr::PORT_EVENT_CODE_OFFSET;
    (key, b[8], u16::from_le_bytes([b[c], b[c + 1]]))
}

/// One event from `port`, without blocking.
fn poll(port: u64) -> Option<Ev> {
    let mut buf = [0u8; 16];
    let mut out = SyscallOut::new();
    (dispatch(SYS_PORT_POLL_TYPED, [port, buf.as_mut_ptr() as u64, 0, 0, 0, 0], &mut out) == 16)
        .then(|| decode(&buf))
}

/// Wait up to `ms` for an event on `port`: `None` when the time passed.
fn wait_event(port: u64, ms: u64) -> Option<Ev> {
    let now = azos_abi::time::ticks_to_ns(azos_drv_sys::timebase::now(), azos_drv_sys::timebase::TIMER_FREQ);
    let mut buf = [0u8; 16];
    let mut out = SyscallOut::new();
    let rc = dispatch(SYS_PORT_WAIT_UNTIL_TYPED, [port, buf.as_mut_ptr() as u64, now + ms * 1_000_000, 0, 0, 0], &mut out);
    (rc == 16).then(|| decode(&buf))
}

fn bind(port: u64, ty: u64, src: u64, key: u64) -> i64 {
    let mut out = SyscallOut::new();
    dispatch(SYS_PORT_BIND_TYPED, [port, ty, src, key, 0, 0], &mut out)
}

/// A new port in the current task's table, as a raw handle.
fn new_port() -> Result<u64, &'static str> {
    let me = azos_sched::current_task_tid();
    azos_ipc::port::port_create_cap(me).map(|c| c.raw().0 as u64).ok_or("no port slot free")
}

/// An anonymous endpoint served by the current task, and its server
/// capability (`RW`: its receive right, not a sender).
fn new_endpoint() -> Result<(u32, u64), &'static str> {
    let me = azos_sched::current_task_tid();
    let r = azos_ipc::endpoint::endpoint_create(me).ok_or("no endpoint slot free")?;
    let c = azos_ipc::objref::grant_packed::<EpTarget>(me, CapPerms::RW, r).ok_or("no server capability")?;
    Ok((r, c.raw().0 as u64))
}

/// A send capability to `r` in the current task's table.
fn sender(r: u32) -> Option<azos_ipc::cap::Cap<EpTarget>> {
    azos_ipc::objref::grant_packed::<EpTarget>(azos_sched::current_task_tid(), CapPerms::WRITE, r)
}

fn no_senders(e: Option<Ev>, key: u64) -> bool {
    e == Some((key, PORT_EVENT_NO_SENDERS, Errno::ENOSENDERS as u16))
}

/// Each scenario runs in its own kernel task (a task's table and port
/// waits); its verdict comes back here.
static VERDICT: [azos_sync::SpinLock<Option<Verdict>>; 4] = [const { azos_sync::SpinLock::new(None) }; 4];

fn report(k: usize, v: Verdict) {
    *VERDICT[k].lock() = Some(v);
}

fn verdict_of(k: usize, name: &str, entry: fn(usize)) -> Verdict {
    if !azos_limits::IPC_PORT_NOTICES {
        return Err("Kconfig IPC_PORT_NOTICES is off in this ktest kernel");
    }
    azos_sched::task_create_affinity(name, entry, k, PRIO, -1);
    crate::ktest::wait("the scenario task never reported", || VERDICT[k].lock().is_some())?;
    VERDICT[k].lock().take().unwrap_or(Err("no verdict"))
}

// ── 1. The last sender revoked ──────────────────────────────────────────────

const KEY_REVOKE: u64 = 0x5E_0001;

fn sc_revoke() -> Verdict {
    let me = azos_sched::current_task_tid();
    let (r, srv) = new_endpoint()?;
    let a = sender(r).ok_or("no first send capability")?;
    let b = sender(r).ok_or("no second send capability")?;
    if azos_ipc::endpoint::senders_of(r) != Some(2) {
        return Err("two send capabilities did not count as two (the server's RW counted?)");
    }
    let port = new_port()?;
    if bind(port, PORT_SRC_ENDPOINT, srv, KEY_REVOKE) != 0 {
        return Err("the server could not bind its endpoint to its port");
    }
    if poll(port).is_some() {
        return Err("a notice arrived at bind with two senders left");
    }
    azos_ipc::cap_store::revoke(me, a);
    if poll(port).is_some() {
        return Err("a notice arrived with one sender left");
    }
    azos_ipc::cap_store::revoke(me, b);
    if !no_senders(poll(port), KEY_REVOKE) {
        return Err("no NoSenders notice (key, type 5, ENOSENDERS) after the last send capability was revoked");
    }
    if poll(port).is_some() {
        return Err("the notice arrived twice");
    }
    if azos_ipc::endpoint::senders_of(r) != Some(0) {
        return Err("the count is not 0 after both revokes");
    }
    Ok(())
}

fn revoke_task(k: usize) {
    report(k, sc_revoke());
}

azos_ktest::ktest_late! {
    fn ipc_no_senders_on_last_revoke() {
        verdict_of(0, "n5b-revoke", revoke_task)
    }
}

// ── 2. Senders exit one after the other ─────────────────────────────────────

const KEY_EXIT: u64 = 0x5E_0002;
static EXIT_REF: AtomicU32 = AtomicU32::new(0);
static EXIT_GRANTED: AtomicUsize = AtomicUsize::new(0);
static EXIT_GO: [AtomicBool; 2] = [const { AtomicBool::new(false) }; 2];

fn exit_client(k: usize) {
    let r = EXIT_REF.load(Ordering::Acquire);
    if sender(r).is_none() {
        return;
    }
    EXIT_GRANTED.fetch_add(1, Ordering::AcqRel);
    while !EXIT_GO[k].load(Ordering::Acquire) {
        sleep_ms(5);
    }
    // Returns: the task exits holding its send capability, and its table is
    // wiped (`cap_store::reset`).
}

/// Poll `cond` every 10 ms for up to `ms`.
fn within(ms: u64, mut cond: impl FnMut() -> bool) -> bool {
    let mut waited = 0;
    while !cond() {
        if waited >= ms {
            return false;
        }
        sleep_ms(10);
        waited += 10;
    }
    true
}

fn sc_exits() -> Verdict {
    let (r, srv) = new_endpoint()?;
    let port = new_port()?;
    EXIT_REF.store(r, Ordering::Release);
    for k in 0..2 {
        azos_sched::task_create_affinity("n5b-exit-cli", exit_client, k, PRIO, -1);
    }
    if !within(2000, || EXIT_GRANTED.load(Ordering::Acquire) == 2) {
        return Err("the clients never took their send capabilities");
    }
    if bind(port, PORT_SRC_ENDPOINT, srv, KEY_EXIT) != 0 {
        return Err("the server could not bind its endpoint to its port");
    }
    if poll(port).is_some() {
        return Err("a notice arrived at bind with two senders left");
    }
    EXIT_GO[0].store(true, Ordering::Release);
    if !within(2000, || azos_ipc::endpoint::senders_of(r) == Some(1)) {
        return Err("the first client's exit did not count its send capability out");
    }
    if wait_event(port, 100).is_some() {
        return Err("a notice arrived after the first exit, with one sender left");
    }
    EXIT_GO[1].store(true, Ordering::Release);
    if !no_senders(wait_event(port, 3000), KEY_EXIT) {
        return Err("no NoSenders notice after the last sender exited");
    }
    if poll(port).is_some() {
        return Err("the notice arrived twice");
    }
    Ok(())
}

fn exits_task(k: usize) {
    report(k, sc_exits());
}

azos_ktest::ktest_late! {
    fn ipc_no_senders_once_after_staggered_exits() {
        verdict_of(1, "n5b-exits", exits_task)
    }
}

// ── 3. Grants and revokes race on two CPUs ──────────────────────────────────

const KEY_RACE: u64 = 0x5E_0003;
/// Grant/revoke pairs each racer makes.
const RACE_ROUNDS: usize = 2000;
static RACE_REF: AtomicU32 = AtomicU32::new(0);
static RACE_DONE: AtomicUsize = AtomicUsize::new(0);
static RACE_FAILED: AtomicBool = AtomicBool::new(false);

fn racer(_: usize) {
    let me = azos_sched::current_task_tid();
    let r = RACE_REF.load(Ordering::Acquire);
    for _ in 0..RACE_ROUNDS {
        match sender(r) {
            Some(c) => azos_ipc::cap_store::revoke(me, c),
            None => RACE_FAILED.store(true, Ordering::Release),
        }
    }
    RACE_DONE.fetch_add(1, Ordering::AcqRel);
}

fn sc_race() -> Verdict {
    let me = azos_sched::current_task_tid();
    let (r, srv) = new_endpoint()?;
    let anchor = sender(r).ok_or("no held send capability")?;
    let port = new_port()?;
    if bind(port, PORT_SRC_ENDPOINT, srv, KEY_RACE) != 0 {
        return Err("the server could not bind its endpoint to its port");
    }
    RACE_REF.store(r, Ordering::Release);
    // On two CPUs of their own when the boot has them; with fewer (the
    // `-smp 1` hold rows) unpinned, racing by preemption only.
    let (ca, cb) = if azos_percpu::nr_cpu_ids() >= 3 { (1, 2) } else { (-1, -1) };
    azos_sched::task_create_affinity("n5b-race-a", racer, 0, PRIO, ca);
    azos_sched::task_create_affinity("n5b-race-b", racer, 1, PRIO, cb);
    if !within(20_000, || RACE_DONE.load(Ordering::Acquire) == 2) {
        return Err("the racers never finished");
    }
    if RACE_FAILED.load(Ordering::Acquire) {
        return Err("a racer's grant was refused");
    }
    if poll(port).is_some() {
        return Err("a notice arrived while a send capability was held");
    }
    if azos_ipc::endpoint::senders_of(r) != Some(1) {
        return Err("the count drifted under the race (not 1 with the held capability)");
    }
    azos_ipc::cap_store::revoke(me, anchor);
    if !no_senders(poll(port), KEY_RACE) {
        return Err("no NoSenders notice after the held capability was revoked");
    }
    if poll(port).is_some() {
        return Err("the notice arrived twice");
    }
    Ok(())
}

fn race_task(k: usize) {
    report(k, sc_race());
}

azos_ktest::ktest_late! {
    fn ipc_no_senders_grant_revoke_race() {
        verdict_of(2, "n5b-race", race_task)
    }
}

// ── 4. A gone source wakes its waiter ───────────────────────────────────────

const KEY_CHAN: u64 = 0x5E_0004;
const KEY_EP: u64 = 0x5E_0005;
static GONE_CHAN: AtomicU32 = AtomicU32::new(0);
static GONE_EP: AtomicU32 = AtomicU32::new(0);
static GONE_STAGE: AtomicUsize = AtomicUsize::new(0);

fn gone_event(e: Option<Ev>, key: u64) -> bool {
    e == Some((key, PORT_EVENT_SOURCE_GONE, Errno::EREVOKED as u16))
}

fn sc_gone() -> Verdict {
    let me = azos_sched::current_task_tid();
    let port = new_port()?;
    let ch = azos_ipc::channel::channel_create_cap(me).map_err(|_| "no channel slot free")?;
    let ch_ref = azos_ipc::cap_store::get(me, ch, CapPerms::READ).map_err(|_| "the channel capability did not resolve")?;
    if bind(port, PORT_SRC_CHANNEL, ch.raw().0 as u64, KEY_CHAN) != 0 {
        return Err("the channel could not be bound");
    }
    GONE_CHAN.store(ch_ref, Ordering::Release);
    GONE_STAGE.store(1, Ordering::Release);
    // The test body destroys the channel now.
    if !gone_event(wait_event(port, 3000), KEY_CHAN) {
        return Err("the waiter was not woken with SOURCE_GONE (EREVOKED) when its channel was destroyed");
    }
    let (r, srv) = new_endpoint()?;
    if bind(port, PORT_SRC_ENDPOINT, srv, KEY_EP) != 0 {
        return Err("the endpoint could not be bound");
    }
    // No sender exists: the bind reports it at once (level at bind).
    if !no_senders(poll(port), KEY_EP) {
        return Err("binding an endpoint with no sender did not report it");
    }
    GONE_EP.store(r, Ordering::Release);
    GONE_STAGE.store(2, Ordering::Release);
    if !gone_event(wait_event(port, 3000), KEY_EP) {
        return Err("the waiter was not woken with SOURCE_GONE (EREVOKED) when its endpoint was destroyed");
    }
    if poll(port).is_some() {
        return Err("a gone source reported twice");
    }
    Ok(())
}

fn gone_task(k: usize) {
    report(k, sc_gone());
}

azos_ktest::ktest_late! {
    fn port_source_gone_wakes_the_waiter() {
        if !azos_limits::IPC_PORT_NOTICES {
            return Err("Kconfig IPC_PORT_NOTICES is off in this ktest kernel");
        }
        azos_sched::task_create_affinity("n5b-gone", gone_task, 3, PRIO, -1);
        crate::ktest::wait("the waiter never bound its channel",
            || GONE_STAGE.load(Ordering::Acquire) >= 1 || VERDICT[3].lock().is_some())?;
        if GONE_STAGE.load(Ordering::Acquire) >= 1 {
            let _ = azos_ipc::channel::channel_destroy_ref(GONE_CHAN.load(Ordering::Acquire));
        }
        crate::ktest::wait("the waiter never bound its endpoint",
            || GONE_STAGE.load(Ordering::Acquire) >= 2 || VERDICT[3].lock().is_some())?;
        if GONE_STAGE.load(Ordering::Acquire) >= 2 {
            let _ = azos_ipc::endpoint::destroy_ref(GONE_EP.load(Ordering::Acquire));
        }
        crate::ktest::wait("the waiter never reported", || VERDICT[3].lock().is_some())?;
        VERDICT[3].lock().take().unwrap_or(Err("no verdict"))
    }
}

// ── Reply warrant (wave 15 N11) ─────────────────────────────────────────────

const WAR_EP: &[u8] = b"n11.war";
static WAR_READY: AtomicBool = AtomicBool::new(false);
static WAR_WORKER: AtomicU32 = AtomicU32::new(0);
/// The accepted call's handle, handed to the worker (0: not yet).
static WAR_HANDLE: AtomicI64 = AtomicI64::new(0);
/// 1 ok; negative: which step failed.
static WAR_SERVER: AtomicI64 = AtomicI64::new(NOT_YET);
static WAR_WORKER_RC: AtomicI64 = AtomicI64::new(NOT_YET);
static WAR_RC: AtomicI64 = AtomicI64::new(NOT_YET);

fn war_server(_: usize) {
    if !serve(WAR_EP) {
        WAR_SERVER.store(-1, Ordering::Release);
        return;
    }
    WAR_READY.store(true, Ordering::Release);
    let me = azos_sched::current_task_tid();
    let mut out = SyscallOut::new();
    let h = dispatch(SYS_IPC_FAST_ACCEPT, [0; 6], &mut out);
    if h < 0 {
        WAR_SERVER.store(-2, Ordering::Release);
        return;
    }
    let worker = WAR_WORKER.load(Ordering::Acquire);
    if azos_ipc::fastcall::delegate(h as u64, me, worker) != azos_ipc::fastcall::Delegated::Moved {
        WAR_SERVER.store(-3, Ordering::Release);
        return;
    }
    // Given away: the server's own answer is refused.
    if azos_ipc::fastcall::reply_warrant(h as u64, me, [1, 0, 0, 0]) != azos_ipc::FastIpcReply::Refused {
        WAR_SERVER.store(-4, Ordering::Release);
        return;
    }
    WAR_SERVER.store(1, Ordering::Release);
    WAR_HANDLE.store(h, Ordering::Release);
    // Stay alive until the worker has answered: a server's exit drains its
    // endpoint, and the drain ends every call in service there PEER_DIED,
    // a delegated one too (`ep_queue::release_holder` covers only the
    // calls on endpoints the holder does not serve). The worker is meant
    // to be a thread of the server's domain, which outlives neither.
    let mut waited = 0;
    while WAR_WORKER_RC.load(Ordering::Acquire) == NOT_YET && waited < 3000 {
        sleep_ms(5);
        waited += 5;
    }
}

fn war_worker(_: usize) {
    WAR_WORKER.store(azos_sched::current_task_tid(), Ordering::Release);
    let me = azos_sched::current_task_tid();
    let mut waited = 0;
    while WAR_HANDLE.load(Ordering::Acquire) == 0 && waited < 3000 {
        sleep_ms(5);
        waited += 5;
    }
    let h = WAR_HANDLE.load(Ordering::Acquire) as u64;
    if h == 0 {
        WAR_WORKER_RC.store(-1, Ordering::Release);
        return;
    }
    // What the reply arm does on delivery: wake the caller, then give back
    // the donation the caller lent to the server.
    match azos_ipc::fastcall::reply_warrant(h, me, [0x0A11, 0, 0, 0]) {
        azos_ipc::FastIpcReply::Woke { caller_tid, donee, .. } => {
            azos_sched::wait::wake_fast_ipc_client_tid(caller_tid, h);
            if donee != azos_ipc::fast_ipc::NO_DONEE {
                azos_sched::return_donation(donee);
            }
        }
        _ => {
            WAR_WORKER_RC.store(-2, Ordering::Release);
            return;
        }
    }
    // Send-once: the second answer is refused (canary: delivered).
    let again = azos_ipc::fastcall::reply_warrant(h, me, [0xBAD, 0, 0, 0]);
    WAR_WORKER_RC.store(if again == azos_ipc::FastIpcReply::Refused { 1 } else { -3 }, Ordering::Release);
}

fn war_client(_: usize) {
    let Some(cap) = client_cap(WAR_EP) else {
        WAR_RC.store(-12345, Ordering::Release);
        return;
    };
    let mut out = SyscallOut::new();
    let rc = dispatch(SYS_IPC_FAST_CALL_EP, [cap, 0x11, 0, 0, 0, 0], &mut out);
    WAR_RC.store(rc, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn ipc_reply_warrant_moves_to_worker_and_is_send_once() {
        if !azos_limits::IPC_ENDPOINT_QUEUES {
            return Err("Kconfig IPC_ENDPOINT_QUEUES is off in this ktest kernel");
        }
        azos_sched::task_create_affinity("n11-war-wrk", war_worker, 0, PRIO, -1);
        crate::ktest::wait("the worker never started", || WAR_WORKER.load(Ordering::Acquire) != 0)?;
        azos_sched::task_create_affinity("n11-war-srv", war_server, 0, PRIO, -1);
        crate::ktest::wait("the server never claimed its endpoint", || WAR_READY.load(Ordering::Acquire))?;
        azos_sched::task_create_affinity("n11-war-cli", war_client, 0, PRIO, -1);
        crate::ktest::wait("the caller was never answered", || WAR_RC.load(Ordering::Acquire) != NOT_YET)?;
        crate::ktest::wait("the worker never finished", || WAR_WORKER_RC.load(Ordering::Acquire) != NOT_YET)?;
        match WAR_SERVER.load(Ordering::Acquire) {
            1 => {}
            -3 => return Err("the server could not move its reply warrant"),
            -4 => return Err("the server still answered after giving its warrant away"),
            _ => return Err("the server never took the call"),
        }
        if WAR_RC.load(Ordering::Acquire) != 0x0A11 {
            return Err("the caller did not get the worker's answer");
        }
        match WAR_WORKER_RC.load(Ordering::Acquire) {
            1 => Ok(()),
            -3 => Err("a second reply on one warrant was delivered"),
            _ => Err("the worker could not answer on the warrant"),
        }
    }
}
