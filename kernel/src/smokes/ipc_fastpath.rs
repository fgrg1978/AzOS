// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The IPC fast path (Kconfig IPC_FASTPATH, Chain E stage a), every ISA.
//! Kernel tasks make the calls through `azos_syscall::fastpath::entry`, the
//! function each ISA's trap entry calls, over a register file of their own,
//! and fall back to `syscall_dispatch_out` as the entries do.
//!
//! * `ipc_fastpath_taken_when_parked`: a client and its server on one hart
//!   exchange `ROUNDS` calls; every answer is right, and the per-task hit
//!   counters show the calls and the replies went through the fast path (all
//!   but the first exchange, whose server may not be parked yet). The server's
//!   first call is taken by its ordinary accept, from the deposit.
//!   Canary `canary=ipc-force-slow`: the fast path is off for the boot, the
//!   answers are still right, the counters do not move: `not ok`.
//! * `ipc_fastpath_not_taken_when_calls_queued`: two callers call a server
//!   that is asleep, not in its accept (not parked: the calls queue), and
//!   its reply finds the second call queued (the fast reply would jump it):
//!   every answer is right and no counter moves. With the fast path compiled
//!   out (no IPC_FASTPATH) both are Ok at once.
//! * `ipc_resolve_cache_follows_revoke_and_reown` (Kconfig
//!   IPC_RESOLVE_CACHE): a destination the resolve cache holds follows its
//!   endpoint to a new owner, and a call through a revoked capability is
//!   refused after a cached hit; on either path (see its section below).
//! * Resume points (Kconfig IPC_FASTPATH_RESUME, Chain E commit 9; see their
//!   section below): `ipc_fastpath_resumes_at_the_point` (the fast path's
//!   claim finishes a parked peer's syscall and starts it at its resume
//!   point, both ways), and three ways a task parked with a point is woken
//!   by something else and resumes where it blocked, its point spent:
//!   `ipc_fastpath_resume_point_kill` (a server killed),
//!   `ipc_fastpath_resume_point_drain` (a caller completed -EPEERDIED by its
//!   server's death), `ipc_fastpath_resume_point_ordinary_call` (a server
//!   woken by an ordinary call).
//! * The wait graph's call edge (Kconfig WAIT_GRAPH; see its section below):
//!   `ipc_fastpath_boosting_call_is_slow_and_boosts` (a call that must boost
//!   its server keeps the ordinary path, and boosts),
//!   `ipc_fastpath_call_edge_is_in_the_graph` (a fast-blocked caller's edge
//!   is the one a deadlock walk follows).

use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicUsize, Ordering};

use azos_abi::syscall_nr::{SYS_IPC_FAST_ACCEPT, SYS_IPC_FAST_CALL_EP, SYS_IPC_FAST_REPLY, SYS_IPC_FAST_REPLY_ACCEPT};
use azos_ipc::cap::CapPerms;
use azos_syscall::fastpath::{self, FastResume, IpcRegs};
use azos_syscall::SyscallOut;

const PRIO: u32 = 12;
/// Exchanges in the first test.
const ROUNDS: u64 = 16;

/// `a0..a6` of a kernel task's call, and whether the call leaves a resume
/// point (the trampoline below, through these registers: see "Resume
/// points").
#[repr(C)]
struct Regs([u64; 7], bool);

impl IpcRegs for Regs {
    fn arg(&self, n: usize) -> u64 {
        self.0[n]
    }
    fn set_out(&mut self, n: usize, v: u64) {
        self.0[1 + n] = v;
    }
    fn resume_point(&self) -> FastResume {
        let pc = Self::resume_pc();
        if !self.1 || pc == 0 {
            return FastResume::NONE;
        }
        FastResume { sp: self as *const Regs as usize, pc }
    }
    /// The trampoline, while the boot leaves resume points (not under the
    /// runtime canary `ipc-resume-off`).
    fn resume_pc() -> usize {
        if fastpath::resume_stub() == 0 {
            return 0;
        }
        ipc_ktest_resume_tramp as *const () as usize
    }
    unsafe fn finish_at(at: usize, a0: i64, out: Option<&[u64; 6]>) {
        // SAFETY: the caller's contract: `at` is the `Regs` of a claimed
        // task's call (see `resume_point`), on its stack, which no CPU runs.
        let r = unsafe { &mut *(at as *mut Regs) };
        r.0[0] = a0 as u64;
        if let Some(out) = out {
            r.0[1..].copy_from_slice(out);
        }
    }
}

/// `num` with arguments `a`, as a trap entry makes it: the fast path when it
/// takes the call, the ordinary dispatch otherwise. `(a0, a0..a6)`.
fn call(num: u64, a: [u64; 6]) -> (i64, [u64; 7]) {
    call_regs(num, a, false)
}

/// [`call`], leaving a resume point when `point`.
fn call_regs(num: u64, a: [u64; 6], point: bool) -> (i64, [u64; 7]) {
    let mut r = Regs([a[0], a[1], a[2], a[3], a[4], a[5], 0], point);
    if fastpath::wants(num) {
        if let Some(rc) = fastpath::entry(num, &mut r) {
            return (rc, r.0);
        }
    }
    let regs = azos_sched::UserRegs::default();
    let mut out = SyscallOut::new();
    let rc = azos_syscall::syscall_dispatch_out(num, a[0], a[1], a[2], a[3], a[4], a[5], 0, 0, &regs, &mut out);
    if out.written {
        for (k, v) in out.regs.iter().enumerate() {
            r.0[1 + k] = *v;
        }
    }
    (rc, r.0)
}

fn sleep_ms(ms: u64) {
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    let due = azos_drv_sys::timebase::now() + ms * per_ms;
    azos_sched::task_block(azos_sched::WaitReason::Timer(due));
}

fn my_slot() -> usize {
    azos_sched::current_task_slot().map_or(usize::MAX, |(i, _)| i)
}

/// Endpoint `name` as its client (WRITE), as a raw handle.
fn client_cap(name: &[u8]) -> Option<u64> {
    let me = azos_sched::current_task_tid();
    azos_ipc::endpoint::endpoint_named_cap(me, CapPerms::WRITE, name).map(|c| c.raw().0 as u64)
}

/// Claim endpoint `name` as its server (READ).
fn serve(name: &[u8]) -> bool {
    let me = azos_sched::current_task_tid();
    azos_ipc::endpoint::endpoint_named_cap(me, CapPerms::READ, name).is_some()
}

// ── Taken ───────────────────────────────────────────────────────────────────

const HIT_EP: &[u8] = b"fp.hit";
static HIT_READY: AtomicBool = AtomicBool::new(false);
static HIT_DONE: AtomicBool = AtomicBool::new(false);
static HIT_RIGHT: AtomicU32 = AtomicU32::new(0);
static HIT_CALLS: AtomicU32 = AtomicU32::new(0);
static HIT_REPLIES: AtomicU32 = AtomicU32::new(0);
static HIT_SERVED: AtomicBool = AtomicBool::new(false);

fn hit_server(_: usize) {
    if !serve(HIT_EP) {
        HIT_SERVED.store(true, Ordering::Release);
        return;
    }
    let before = fastpath::hits_of(my_slot()).1;
    HIT_READY.store(true, Ordering::Release);
    // The first call through the ordinary accept (parked in it, the fast
    // call deposits), every next one through the fast reply-and-accept.
    let (mut h, mut r) = call(SYS_IPC_FAST_ACCEPT, [0; 6]);
    for _ in 1..ROUNDS {
        if h < 0 {
            break;
        }
        (h, r) = call(SYS_IPC_FAST_REPLY_ACCEPT, [h as u64, 0, r[2] + 1, 0, 0, 0]);
    }
    if h >= 0 {
        call(SYS_IPC_FAST_REPLY, [h as u64, r[2] + 1, 0, 0, 0, 0]);
    }
    HIT_REPLIES.store(fastpath::hits_of(my_slot()).1.wrapping_sub(before), Ordering::Release);
    HIT_SERVED.store(true, Ordering::Release);
}

fn hit_client(_: usize) {
    let Some(cap) = client_cap(HIT_EP) else {
        HIT_DONE.store(true, Ordering::Release);
        return;
    };
    let before = fastpath::hits_of(my_slot()).0;
    // Let the server park in its accept.
    sleep_ms(20);
    for k in 0..ROUNDS {
        let w = 0x500 + k;
        let (rc, _) = call(SYS_IPC_FAST_CALL_EP, [cap, w, 0, 0, 0, 0]);
        if rc == (w + 1) as i64 {
            HIT_RIGHT.fetch_add(1, Ordering::AcqRel);
        }
    }
    HIT_CALLS.store(fastpath::hits_of(my_slot()).0.wrapping_sub(before), Ordering::Release);
    HIT_DONE.store(true, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn ipc_fastpath_taken_when_parked() {
        if !fastpath::ENABLED {
            return Ok(());
        }
        // One hart: each side is parked when the other reaches it.
        azos_sched::task_create_affinity("fp-hit-srv", hit_server, 0, PRIO, 0);
        crate::ktest::wait("the server never claimed its endpoint", || HIT_READY.load(Ordering::Acquire))?;
        azos_sched::task_create_affinity("fp-hit-cli", hit_client, 0, PRIO, 0);
        crate::ktest::wait("the client did not finish its calls",
            || HIT_DONE.load(Ordering::Acquire) && HIT_SERVED.load(Ordering::Acquire))?;
        if HIT_RIGHT.load(Ordering::Acquire) as u64 != ROUNDS {
            return Err("a call came back with a wrong answer");
        }
        if (HIT_CALLS.load(Ordering::Acquire) as u64) < ROUNDS - 1 {
            return Err("the calls to a parked server did not take the fast path");
        }
        if (HIT_REPLIES.load(Ordering::Acquire) as u64) < ROUNDS - 2 {
            return Err("the replies to a parked client did not take the fast path");
        }
        Ok(())
    }
}

// ── Not taken ───────────────────────────────────────────────────────────────

const Q_EP: &[u8] = b"fp.queued";
static Q_READY: AtomicBool = AtomicBool::new(false);
static Q_SERVED: AtomicBool = AtomicBool::new(false);
static Q_QUEUED: AtomicUsize = AtomicUsize::new(0);
static Q_RIGHT: AtomicU32 = AtomicU32::new(0);
static Q_CALL_HITS: AtomicU32 = AtomicU32::new(0);
static Q_REPLY_HITS: AtomicI64 = AtomicI64::new(-1);
static Q_DONE: AtomicUsize = AtomicUsize::new(0);

fn q_server(_: usize) {
    if !serve(Q_EP) {
        Q_SERVED.store(true, Ordering::Release);
        return;
    }
    let before = fastpath::hits_of(my_slot()).1;
    Q_READY.store(true, Ordering::Release);
    // Asleep, not in the accept: the calls cannot find it parked and queue.
    let mut waited = 0;
    while (Q_QUEUED.load(Ordering::Acquire) < 2 || azos_ipc::fastcall::census().0 < 2) && waited < 2000 {
        sleep_ms(10);
        waited += 10;
    }
    let (h, r) = call(SYS_IPC_FAST_ACCEPT, [0; 6]);
    if h >= 0 {
        // The second call is queued: the fast reply must not jump it.
        let (h2, r2) = call(SYS_IPC_FAST_REPLY_ACCEPT, [h as u64, 0, r[2] + 1, 0, 0, 0]);
        if h2 >= 0 {
            call(SYS_IPC_FAST_REPLY, [h2 as u64, r2[2] + 1, 0, 0, 0, 0]);
        }
    }
    Q_REPLY_HITS.store(i64::from(fastpath::hits_of(my_slot()).1.wrapping_sub(before)), Ordering::Release);
    Q_SERVED.store(true, Ordering::Release);
}

fn q_client(k: usize) {
    let Some(cap) = client_cap(Q_EP) else {
        Q_DONE.fetch_add(1, Ordering::AcqRel);
        return;
    };
    let before = fastpath::hits_of(my_slot()).0;
    Q_QUEUED.fetch_add(1, Ordering::AcqRel);
    let w = 0x700 + k as u64;
    let (rc, _) = call(SYS_IPC_FAST_CALL_EP, [cap, w, 0, 0, 0, 0]);
    if rc == (w + 1) as i64 {
        Q_RIGHT.fetch_add(1, Ordering::AcqRel);
    }
    Q_CALL_HITS.fetch_add(fastpath::hits_of(my_slot()).0.wrapping_sub(before), Ordering::AcqRel);
    Q_DONE.fetch_add(1, Ordering::AcqRel);
}

azos_ktest::ktest_late! {
    fn ipc_fastpath_not_taken_when_calls_queued() {
        if !fastpath::ENABLED {
            return Ok(());
        }
        azos_sched::task_create_affinity("fp-q-srv", q_server, 0, PRIO, -1);
        crate::ktest::wait("the server never claimed its endpoint", || Q_READY.load(Ordering::Acquire))?;
        for k in 0..2 {
            azos_sched::task_create_affinity("fp-q-cli", q_client, k, PRIO, -1);
        }
        crate::ktest::wait("a caller was not answered",
            || Q_DONE.load(Ordering::Acquire) == 2 && Q_SERVED.load(Ordering::Acquire))?;
        if Q_RIGHT.load(Ordering::Acquire) != 2 {
            return Err("a call came back with a wrong answer");
        }
        if Q_CALL_HITS.load(Ordering::Acquire) != 0 {
            return Err("a call to a server that was not parked took the fast path");
        }
        if Q_REPLY_HITS.load(Ordering::Acquire) != 0 {
            return Err("a reply with a call still queued took the fast path");
        }
        Ok(())
    }
}

// ── The resolve cache ───────────────────────────────────────────────────────
//
// `ipc_resolve_cache_follows_revoke_and_reown` (Kconfig IPC_RESOLVE_CACHE,
// Chain E commit 5): a client calls server A twice (a miss that keeps the
// destination, then a hit); A answers a stop word, hands its endpoint on as
// a supervised driver's exit does (`endpoint_orphan_all`) and ends; server B
// claims it, and the client's next calls, through the same capability and
// the destination the cache still holds for A, must reach B. Then, after a
// cached hit to B, the client's capability is revoked and its call must be
// refused. Behaviour only, so it holds on the ordinary path as well
// (`canary=ipc-force-slow`): the resolve cache serves the call arm too. Host tests in `azos_ipc::endpoint` (keying, every miss, the
// canaries) and `syscall-tests` (`cap_denial_record`: the refusal is
// recorded once).

const RC_EP: &[u8] = b"fp.rcache";
/// The word that ends a server: answered with itself.
const RC_STOP: u64 = 0x5709;
static RC_A_READY: AtomicBool = AtomicBool::new(false);
static RC_A_GONE: AtomicBool = AtomicBool::new(false);
static RC_B_READY: AtomicBool = AtomicBool::new(false);
static RC_B_GONE: AtomicBool = AtomicBool::new(false);
static RC_DONE: AtomicBool = AtomicBool::new(false);
/// The client's verdict: 0 passed, else the step that failed (`RC_WHY`).
static RC_FAIL: AtomicUsize = AtomicUsize::new(usize::MAX);
const RC_WHY: [&str; 10] = [
    "",
    "the client got no capability to the endpoint",
    "a call to the first server came back with a wrong answer",
    "the resolve cache did not keep the client's destination",
    "the first server did not answer its stop word",
    "the first server did not hand its endpoint on",
    "a call after the endpoint changed owner did not reach the new owner",
    "a call through a revoked capability was not refused",
    "the client got no second capability to stop the new owner",
    "the new owner did not answer its stop word",
];

/// Serve `RC_EP` (claimed), answering `w + add`, until `RC_STOP`.
fn rc_serve(add: u64) {
    let (mut h, mut r) = call(SYS_IPC_FAST_ACCEPT, [0; 6]);
    while h >= 0 {
        if r[2] == RC_STOP {
            call(SYS_IPC_FAST_REPLY, [h as u64, RC_STOP, 0, 0, 0, 0]);
            return;
        }
        (h, r) = call(SYS_IPC_FAST_REPLY_ACCEPT, [h as u64, 0, r[2] + add, 0, 0, 0]);
    }
}

fn rc_server_a(_: usize) {
    if serve(RC_EP) {
        RC_A_READY.store(true, Ordering::Release);
        rc_serve(1);
        // Kept for a successor, as a supervised driver's exit keeps it.
        azos_ipc::endpoint::endpoint_orphan_all(azos_sched::current_task_tid());
    }
    RC_A_GONE.store(true, Ordering::Release);
}

fn rc_server_b(_: usize) {
    if serve(RC_EP) {
        RC_B_READY.store(true, Ordering::Release);
        rc_serve(2);
    }
    RC_B_GONE.store(true, Ordering::Release);
}

/// `w` to `cap` answered `w + add`?
fn rc_calls(cap: u64, base: u64, add: u64) -> bool {
    (0..2).all(|k| call(SYS_IPC_FAST_CALL_EP, [cap, base + k, 0, 0, 0, 0]).0 == (base + k + add) as i64)
}

/// The client's steps; `Err(k)` names the one that failed.
fn rc_steps() -> Result<(), usize> {
    use azos_ipc::endpoint::resolve_cache;
    let cap = client_cap(RC_EP).ok_or(1usize)?;
    let me = azos_sched::current_task_tid();
    let kept = || !resolve_cache::ENABLED || resolve_cache::cached(my_slot()) == Some((me, cap as u32));
    // Let the server park in its accept.
    sleep_ms(20);
    if !rc_calls(cap, 0x900, 1) {
        return Err(2);
    }
    if !kept() {
        return Err(3);
    }
    if call(SYS_IPC_FAST_CALL_EP, [cap, RC_STOP, 0, 0, 0, 0]).0 != RC_STOP as i64 {
        return Err(4);
    }
    // The test body starts B once A is gone.
    let mut waited = 0;
    while !RC_B_READY.load(Ordering::Acquire) && waited < 2000 {
        sleep_ms(10);
        waited += 10;
    }
    if !RC_B_READY.load(Ordering::Acquire) {
        return Err(5);
    }
    sleep_ms(20);
    if !rc_calls(cap, 0xA00, 2) || !kept() {
        return Err(6);
    }
    let held: azos_ipc::cap::Cap<azos_ipc::cap::targets::Endpoint> =
        azos_ipc::cap::Cap::from_raw(azos_abi::cap::CapHandle(cap as u32));
    azos_ipc::cap_store::revoke(me, held);
    if call(SYS_IPC_FAST_CALL_EP, [cap, 0xB00, 0, 0, 0, 0]).0 != -1 {
        return Err(7);
    }
    let stop = client_cap(RC_EP).ok_or(8usize)?;
    if call(SYS_IPC_FAST_CALL_EP, [stop, RC_STOP, 0, 0, 0, 0]).0 != RC_STOP as i64 {
        return Err(9);
    }
    Ok(())
}

fn rc_client(_: usize) {
    RC_FAIL.store(rc_steps().err().unwrap_or(0), Ordering::Release);
    RC_DONE.store(true, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn ipc_resolve_cache_follows_revoke_and_reown() {
        azos_sched::task_create_affinity("rc-srv-a", rc_server_a, 0, PRIO, 0);
        crate::ktest::wait("the first server never claimed its endpoint", || RC_A_READY.load(Ordering::Acquire))?;
        azos_sched::task_create_affinity("rc-cli", rc_client, 0, PRIO, 0);
        crate::ktest::wait("the first server did not stop", || RC_A_GONE.load(Ordering::Acquire))?;
        azos_sched::task_create_affinity("rc-srv-b", rc_server_b, 0, PRIO, 0);
        crate::ktest::wait("the client did not finish its calls", || RC_DONE.load(Ordering::Acquire))?;
        match RC_FAIL.load(Ordering::Acquire) {
            0 => {}
            k => return Err(RC_WHY.get(k).copied().unwrap_or("the client failed")),
        }
        crate::ktest::wait("the new owner did not stop", || RC_B_GONE.load(Ordering::Acquire))?;
        Ok(())
    }
}

// ── Resume points ───────────────────────────────────────────────────────────
//
// Kconfig IPC_FASTPATH_RESUME (Chain E commit 9; `azos_syscall::fastpath`,
// "Resume points"). A kernel task's call through `call_regs(.., true)` leaves
// a resume point in its own `Regs`: the claim that takes it writes the call's
// result there and starts the task at `ipc_ktest_resume_tramp` (below), on a
// stack under those `Regs`, which calls `ipc_ktest_resumed`; that finishes
// what the task's call would have returned to with the continuation it named
// (`rcall`), and ends the task. Resumed where it blocked instead, the call
// returns and `rcall` runs the same continuation. The continuation is told
// which way it came (`at`), and each test reads it and whether the task's
// point was spent (`ipc_fast_resume_held`).
//
// * `ipc_fastpath_resumes_at_the_point`: a server parked in its accept and a
//   caller exchange two calls on one hart: the caller's first call leaves a
//   point, the server's fast reply finishes it there; the server's reply
//   and accept leaves one, the caller's second (fast) call finishes it there.
//   Canaries `canary=ipc-resume-off` (no point is left) and
//   `canary=ipc-force-slow`: every answer right, nothing started at a point.
// * `ipc_fastpath_resume_point_kill`: a server parked with a point is
//   killed (`task_stop`, forced): it resumes where it blocked, its point
//   spent, and its call ends.
// * `ipc_fastpath_resume_point_drain`: a caller parked with a point, whose
//   server ends without answering: the drain wakes it, it resumes where it
//   blocked, its point spent, and its call returns -EPEERDIED.
// * `ipc_fastpath_resume_point_ordinary_call`: a server parked with a point
//   is woken by an ordinary call (the arm's own code, not the fast path): it
//   resumes where it blocked, its point spent, and its accept returns that
//   call.
//
// Canary `canary=ipc-resume-stale` (a task resumed where it blocked keeps its
// point) turns the last three red; `ipc-resume-off` and `ipc-force-slow` turn
// them red too (no task is parked with a point: the precondition fails).

/// What a task does once its call returns: `(arg, a0, a0..a6, at its
/// resume point)`.
type Cont = fn(usize, i64, [u64; 7], bool);

/// Per task slot: the continuation of the task's pending `rcall`, and its
/// argument.
static CONT: [AtomicUsize; azos_limits::MAX_TASKS] = [const { AtomicUsize::new(0) }; azos_limits::MAX_TASKS];
static CONT_ARG: [AtomicUsize; azos_limits::MAX_TASKS] = [const { AtomicUsize::new(0) }; azos_limits::MAX_TASKS];

/// `num` with arguments `a`, leaving a resume point: `cont(arg, ..)` runs
/// with the result whichever way the call ends.
fn rcall(num: u64, a: [u64; 6], cont: Cont, arg: usize) {
    let slot = my_slot();
    if let (Some(c), Some(x)) = (CONT.get(slot), CONT_ARG.get(slot)) {
        c.store(cont as usize, Ordering::Release);
        x.store(arg, Ordering::Release);
    }
    let (rc, r) = call_regs(num, a, true);
    cont(arg, rc, r, false);
}

// The trampoline a resume point starts at: `sp` is the call's `Regs`, which
// becomes the argument; the stack goes on below them, 16-aligned.
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".global ipc_ktest_resume_tramp",
    ".balign 4",
    "ipc_ktest_resume_tramp:",
    "    mv   a0, sp",
    "    andi sp, sp, -16",
    "    call ipc_ktest_resumed",
    "    unimp",
);
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".globl ipc_ktest_resume_tramp",
    ".balign 4",
    "ipc_ktest_resume_tramp:",
    "    mov  x0, sp",
    "    and  x9, x0, #~15",
    "    mov  sp, x9",
    "    bl   ipc_ktest_resumed",
    "    brk  #0",
);
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl ipc_ktest_resume_tramp",
    "ipc_ktest_resume_tramp:",
    "    mov  rdi, rsp",
    "    and  rsp, -16",
    "    call ipc_ktest_resumed",
    "    ud2",
);

#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("ipc_ktest_resume_tramp: no trampoline for this ISA");

unsafe extern "C" {
    fn ipc_ktest_resume_tramp();
}

/// A kernel task started at its resume point: what its call's return would
/// have led to. The step the switch's own return makes (a Zombie to reap),
/// interrupts on as the call's hand-off leaves them, then the continuation,
/// then the end of the task (its frames above are abandoned).
#[unsafe(no_mangle)]
extern "C" fn ipc_ktest_resumed(regs: *const Regs) -> ! {
    azos_sched::scheduler::azos_ipc_fast_resumed();
    {
        use azos_arch::Interrupts as _;
        azos_arch::ARCH.enable_all();
    }
    // SAFETY: the `Regs` the claim wrote, in this task's abandoned frames,
    // above this stack.
    let r = unsafe { (*regs).0 };
    let slot = my_slot();
    let cont = CONT.get(slot).map_or(0, |c| c.load(Ordering::Acquire));
    let arg = CONT_ARG.get(slot).map_or(0, |x| x.load(Ordering::Acquire));
    if cont != 0 {
        // SAFETY: stored by `rcall` from a `Cont`.
        let cont: Cont = unsafe { core::mem::transmute::<usize, Cont>(cont) };
        cont(arg, r[0] as i64, r, true);
    }
    azos_sched::task_exit()
}

/// Does the task in slot `slot` hold a resume point?
fn held(slot: usize) -> bool {
    azos_sched::scheduler::ipc_fast_resume_held(slot)
}

// ── Taken at the point ──────────────────────────────────────────────────────

const RP_EP: &[u8] = b"fp.resume";
static RP_READY: AtomicBool = AtomicBool::new(false);
static RP_SRV_DONE: AtomicBool = AtomicBool::new(false);
static RP_CLI_DONE: AtomicBool = AtomicBool::new(false);
static RP_CAP: AtomicUsize = AtomicUsize::new(0);
static RP_RIGHT: AtomicU32 = AtomicU32::new(0);
static RP_SRV_AT: AtomicU32 = AtomicU32::new(0);
static RP_CLI_AT: AtomicU32 = AtomicU32::new(0);
static RP_SRV_WORD: AtomicUsize = AtomicUsize::new(0);

fn rp_server(_: usize) {
    if !serve(RP_EP) {
        RP_SRV_DONE.store(true, Ordering::Release);
        return;
    }
    RP_READY.store(true, Ordering::Release);
    // The first call through the ordinary accept, parked.
    let (h, r) = call(SYS_IPC_FAST_ACCEPT, [0; 6]);
    if h < 0 {
        RP_SRV_DONE.store(true, Ordering::Release);
        return;
    }
    // Its answer and the wait for the next one, leaving a point.
    rcall(SYS_IPC_FAST_REPLY_ACCEPT, [h as u64, 0, r[2] + 1, 0, 0, 0], rp_server_next, 0);
}

fn rp_server_next(_: usize, h: i64, r: [u64; 7], at: bool) {
    if at {
        RP_SRV_AT.fetch_add(1, Ordering::AcqRel);
    }
    RP_SRV_WORD.store(r[2] as usize, Ordering::Release);
    if h >= 0 {
        // An ordinary reply: the caller, parked without a point, resumes
        // where it blocked.
        call(SYS_IPC_FAST_REPLY, [h as u64, r[2] + 1, 0, 0, 0, 0]);
    }
    RP_SRV_DONE.store(true, Ordering::Release);
}

fn rp_client(_: usize) {
    let Some(cap) = client_cap(RP_EP) else {
        RP_CLI_DONE.store(true, Ordering::Release);
        return;
    };
    RP_CAP.store(cap as usize, Ordering::Release);
    // Let the server park in its accept.
    sleep_ms(20);
    rcall(SYS_IPC_FAST_CALL_EP, [cap, 0x600, 0, 0, 0, 0], rp_client_next, 0);
}

fn rp_client_next(_: usize, rc: i64, _: [u64; 7], at: bool) {
    if at {
        RP_CLI_AT.fetch_add(1, Ordering::AcqRel);
    }
    if rc == 0x601 {
        RP_RIGHT.fetch_add(1, Ordering::AcqRel);
    }
    // The server is parked with a point: this call finishes its accept.
    let cap = RP_CAP.load(Ordering::Acquire) as u64;
    if call(SYS_IPC_FAST_CALL_EP, [cap, 0x602, 0, 0, 0, 0]).0 == 0x603 {
        RP_RIGHT.fetch_add(1, Ordering::AcqRel);
    }
    RP_CLI_DONE.store(true, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn ipc_fastpath_resumes_at_the_point() {
        if !fastpath::RESUME {
            return Ok(());
        }
        azos_sched::task_create_affinity("fp-rp-srv", rp_server, 0, PRIO, 0);
        crate::ktest::wait("the server never claimed its endpoint", || RP_READY.load(Ordering::Acquire))?;
        azos_sched::task_create_affinity("fp-rp-cli", rp_client, 0, PRIO, 0);
        crate::ktest::wait("the calls were not answered",
            || RP_CLI_DONE.load(Ordering::Acquire) && RP_SRV_DONE.load(Ordering::Acquire))?;
        if RP_RIGHT.load(Ordering::Acquire) != 2 || RP_SRV_WORD.load(Ordering::Acquire) != 0x602 {
            return Err("a call or an accept came back with a wrong answer");
        }
        if RP_CLI_AT.load(Ordering::Acquire) != 1 {
            return Err("the fast reply did not finish the caller's call at its resume point");
        }
        if RP_SRV_AT.load(Ordering::Acquire) != 1 {
            return Err("the fast call did not finish the server's accept at its resume point");
        }
        Ok(())
    }
}

// ── Woken by something else ─────────────────────────────────────────────────

/// One scenario's state (`PK[k]`, `k` the task argument).
struct Pk {
    ready: AtomicBool,
    srv_slot: AtomicUsize,
    srv_tid: AtomicU32,
    cli_slot: AtomicUsize,
    cli_done: AtomicBool,
    cli_rc: AtomicI64,
    /// DRAIN: the caller held a resume point when its server ended, and
    /// the server is ending.
    pre: AtomicBool,
    srv_done: AtomicBool,
    /// The parked side's call returned, where (`at`), with what, and
    /// whether its point was still held then.
    done: AtomicBool,
    at: AtomicBool,
    rc: AtomicI64,
    word: AtomicUsize,
    held: AtomicBool,
}

const NOT_YET: i64 = i64::MIN;

static PK: [Pk; 3] = [const {
    Pk {
        ready: AtomicBool::new(false),
        srv_slot: AtomicUsize::new(usize::MAX),
        srv_tid: AtomicU32::new(0),
        cli_slot: AtomicUsize::new(usize::MAX),
        cli_done: AtomicBool::new(false),
        cli_rc: AtomicI64::new(NOT_YET),
        pre: AtomicBool::new(false),
        srv_done: AtomicBool::new(false),
        done: AtomicBool::new(false),
        at: AtomicBool::new(false),
        rc: AtomicI64::new(NOT_YET),
        word: AtomicUsize::new(0),
        held: AtomicBool::new(false),
    }
}; 3];

/// The scenarios, `PK`'s index.
const KILL: usize = 0;
const DRAIN: usize = 1;
const ORDINARY: usize = 2;
const PK_EP: [&[u8]; 3] = [b"fp.rp.kill", b"fp.rp.drain", b"fp.rp.call"];

/// The parked side's continuation: where it came back, and its point.
fn pk_back(k: usize, rc: i64, r: [u64; 7], at: bool) {
    let p = &PK[k];
    p.at.store(at, Ordering::Release);
    p.rc.store(rc, Ordering::Release);
    p.word.store(r[2] as usize, Ordering::Release);
    p.held.store(held(my_slot()), Ordering::Release);
    if k == ORDINARY && rc >= 0 {
        call(SYS_IPC_FAST_REPLY, [rc as u64, r[2] + 1, 0, 0, 0, 0]);
    }
    p.done.store(true, Ordering::Release);
}

/// KILL and ORDINARY: a server that answers one call and parks for the
/// next with a point. DRAIN: a server that takes one call and ends.
fn pk_server(k: usize) {
    let p = &PK[k];
    if !serve(PK_EP[k]) {
        p.done.store(true, Ordering::Release);
        return;
    }
    p.srv_slot.store(my_slot(), Ordering::Release);
    p.srv_tid.store(azos_sched::current_task_tid(), Ordering::Release);
    p.ready.store(true, Ordering::Release);
    let (h, r) = call(SYS_IPC_FAST_ACCEPT, [0; 6]);
    if h < 0 {
        p.done.store(true, Ordering::Release);
        return;
    }
    if k == DRAIN {
        // Until the caller is parked with its point, then end unanswered.
        let pre = azos_syscall::sleep::wait_until_ms(PARK_MS, 5, || held(p.cli_slot.load(Ordering::Acquire)));
        p.pre.store(pre, Ordering::Release);
        p.srv_done.store(true, Ordering::Release);
        return;
    }
    rcall(SYS_IPC_FAST_REPLY_ACCEPT, [h as u64, 0, r[2] + 1, 0, 0, 0], pk_back, k);
}

/// The first caller: one call, leaving a point only for DRAIN.
fn pk_client(k: usize) {
    let p = &PK[k];
    p.cli_slot.store(my_slot(), Ordering::Release);
    let Some(cap) = client_cap(PK_EP[k]) else {
        p.cli_done.store(true, Ordering::Release);
        return;
    };
    // Let the server park in its accept.
    sleep_ms(20);
    if k == DRAIN {
        rcall(SYS_IPC_FAST_CALL_EP, [cap, 0x800, 0, 0, 0, 0], pk_back, k);
    } else {
        p.cli_rc.store(call(SYS_IPC_FAST_CALL_EP, [cap, 0x800, 0, 0, 0, 0]).0, Ordering::Release);
    }
    p.cli_done.store(true, Ordering::Release);
}

/// ORDINARY's second caller: the arm's own code, not the fast path.
fn pk_ordinary_client(k: usize) {
    let p = &PK[k];
    let Some(cap) = client_cap(PK_EP[k]) else {
        p.cli_rc.store(-12345, Ordering::Release);
        return;
    };
    let regs = azos_sched::UserRegs::default();
    let mut out = SyscallOut::new();
    let rc = azos_syscall::syscall_dispatch_out(SYS_IPC_FAST_CALL_EP, cap, 0x900, 0, 0, 0, 0, 0, 0, &regs, &mut out);
    p.cli_rc.store(rc, Ordering::Release);
}

/// Start scenario `k` up to its parked side holding a point.
fn pk_park(k: usize) -> Result<(), &'static str> {
    let p = &PK[k];
    azos_sched::task_create_affinity("fp-pk-srv", pk_server, k, PRIO, 0);
    crate::ktest::wait("the server never claimed its endpoint", || p.ready.load(Ordering::Acquire))?;
    azos_sched::task_create_affinity("fp-pk-cli", pk_client, k, PRIO, 0);
    if k == DRAIN {
        return Ok(());
    }
    crate::ktest::wait("the first call was not answered", || p.cli_done.load(Ordering::Acquire))?;
    if p.cli_rc.load(Ordering::Acquire) != 0x801 {
        return Err("the first call came back with a wrong answer");
    }
    // The server parks as it answers: a short bound, so a canary that keeps
    // it from leaving a point fails here and not at the late timeout.
    if !azos_syscall::sleep::wait_until_ms(PARK_MS, 5, || held(p.srv_slot.load(Ordering::Acquire))) {
        return Err("the server never parked with a resume point");
    }
    Ok(())
}

/// How long a scenario waits for its side to park with a point.
const PARK_MS: u64 = 2000;

/// The parked side came back where it blocked, its point spent.
fn pk_back_where_it_blocked(k: usize) -> Result<(), &'static str> {
    let p = &PK[k];
    crate::ktest::wait("the parked task never came back", || p.done.load(Ordering::Acquire))?;
    if p.at.load(Ordering::Acquire) {
        return Err("a wake that is not the fast path's started the task at its resume point");
    }
    if p.held.load(Ordering::Acquire) {
        return Err("the task resumed where it blocked and kept its resume point");
    }
    Ok(())
}

azos_ktest::ktest_late! {
    fn ipc_fastpath_resume_point_kill() {
        if !fastpath::RESUME {
            return Ok(());
        }
        pk_park(KILL)?;
        let p = &PK[KILL];
        if !azos_sched::scheduler::task_stop(p.srv_tid.load(Ordering::Acquire), true, 9) {
            return Err("the parked server could not be stopped");
        }
        pk_back_where_it_blocked(KILL)?;
        if p.rc.load(Ordering::Acquire) >= 0 {
            return Err("the killed server's accept returned a call");
        }
        Ok(())
    }
}

azos_ktest::ktest_late! {
    fn ipc_fastpath_resume_point_drain() {
        if !fastpath::RESUME {
            return Ok(());
        }
        pk_park(DRAIN)?;
        crate::ktest::wait("the server never ended", || PK[DRAIN].srv_done.load(Ordering::Acquire))?;
        if !PK[DRAIN].pre.load(Ordering::Acquire) {
            return Err("the caller never parked with a resume point");
        }
        pk_back_where_it_blocked(DRAIN)?;
        if PK[DRAIN].rc.load(Ordering::Acquire) != azos_abi::error::Errno::EPEERDIED.to_syscall_ret() {
            return Err("the drained call returned something other than -EPEERDIED");
        }
        Ok(())
    }
}

azos_ktest::ktest_late! {
    fn ipc_fastpath_resume_point_ordinary_call() {
        if !fastpath::RESUME {
            return Ok(());
        }
        pk_park(ORDINARY)?;
        let p = &PK[ORDINARY];
        p.cli_rc.store(NOT_YET, Ordering::Release);
        azos_sched::task_create_affinity("fp-pk-ord", pk_ordinary_client, ORDINARY, PRIO, 0);
        pk_back_where_it_blocked(ORDINARY)?;
        if p.rc.load(Ordering::Acquire) < 0 || p.word.load(Ordering::Acquire) != 0x900 {
            return Err("the server's accept did not return the ordinary call");
        }
        crate::ktest::wait("the ordinary call was not answered", || p.cli_rc.load(Ordering::Acquire) != NOT_YET)?;
        if p.cli_rc.load(Ordering::Acquire) != 0x901 {
            return Err("the ordinary call came back with a wrong answer");
        }
        Ok(())
    }
}

// ── The wait graph's call edge (Kconfig WAIT_GRAPH) ─────────────────────────
//
// With WAIT_GRAPH a call lends its priority through a wait-graph edge; the
// fast call records that edge exactly as the ordinary call does, and only a
// lazy one (`waitgraph::block_on_quiet`), so a call the graph must act on
// keeps the ordinary path. Both tests are Ok at once without the wait graph
// or the fast path.
//
// * `ipc_fastpath_boosting_call_is_slow_and_boosts`: an RT caller calls a
//   low-priority server parked in its accept, on one hart (every other
//   precondition of the fast path holds): the call takes the ordinary path,
//   its edge boosts the server while it serves, the server's fast reply and
//   accept takes the ordinary path too (the edge is not lazy), and the
//   server is back at its own priority after it. Canary
//   `canary=ipc-call-no-edge` (no call takes an edge: the call is fast and
//   nothing is boosted), and by hand `block_on_quiet` ignoring its predicate
//   (every edge lazy: the same).
// * `ipc_fastpath_call_edge_is_in_the_graph`: a caller that owns a kernel
//   mutex's wait object calls its server through the fast path; while it
//   waits, fast-blocked, its edge names the server's call node and the
//   server's block on that object is refused as a cycle (`EDEADLK`): the
//   walk follows the fast call's edge. Canaries `canary=ipc-call-no-edge`
//   (the fast call takes no edge: the cycle is not seen) and
//   `canary=ipc-force-slow` (no fast call: red by its precondition).

use azos_sync::waitgraph::{self, EdgeKind, PiWaiters, SchedPi as _, UnblockReason, WaitError};

/// Is this a kernel whose fast path records the wait graph's call edge?
fn graph_fast_path() -> bool {
    fastpath::ENABLED && waitgraph::ENABLED && azos_ipc::fastcall::CALL_EDGE
}

const WB_EP: &[u8] = b"fp.wg.boost";
/// A low-priority server (past RT_PRIORITY_THRESHOLD) and an RT caller.
const WB_SERVER_PRIO: u32 = azos_sched::task::RT_PRIORITY_THRESHOLD + 8;
const WB_CLIENT_PRIO: u32 = 4;
const WB_STOP: u64 = 0x5709;
static WB_READY: AtomicBool = AtomicBool::new(false);
static WB_SRV_TID: AtomicU32 = AtomicU32::new(0);
static WB_SERVING: AtomicU32 = AtomicU32::new(u32::MAX);
static WB_REPLY_HITS: AtomicI64 = AtomicI64::new(-1);
static WB_SRV_DONE: AtomicBool = AtomicBool::new(false);
static WB_RC: AtomicI64 = AtomicI64::new(NOT_YET);
static WB_CALL_HITS: AtomicI64 = AtomicI64::new(-1);
static WB_AFTER: AtomicU32 = AtomicU32::new(u32::MAX);
static WB_CLI_DONE: AtomicBool = AtomicBool::new(false);

fn wb_server(_: usize) {
    if !serve(WB_EP) {
        WB_SRV_DONE.store(true, Ordering::Release);
        return;
    }
    let me = azos_sched::current_task_tid();
    WB_SRV_TID.store(me, Ordering::Release);
    let before = fastpath::hits_of(my_slot()).1;
    WB_READY.store(true, Ordering::Release);
    let (mut h, mut r) = call(SYS_IPC_FAST_ACCEPT, [0; 6]);
    let mut first = true;
    while h >= 0 {
        if first {
            // Serving the RT caller's call: its edge holds the boost.
            WB_SERVING.store(azos_sched::task_priority(me).unwrap_or(u32::MAX), Ordering::Release);
            first = false;
        }
        if r[2] == WB_STOP {
            call(SYS_IPC_FAST_REPLY, [h as u64, WB_STOP, 0, 0, 0, 0]);
            break;
        }
        (h, r) = call(SYS_IPC_FAST_REPLY_ACCEPT, [h as u64, 0, r[2] + 1, 0, 0, 0]);
    }
    WB_REPLY_HITS.store(i64::from(fastpath::hits_of(my_slot()).1.wrapping_sub(before)), Ordering::Release);
    WB_SRV_DONE.store(true, Ordering::Release);
}

fn wb_client(_: usize) {
    let Some(cap) = client_cap(WB_EP) else {
        WB_CLI_DONE.store(true, Ordering::Release);
        return;
    };
    // Let the server park in its accept.
    sleep_ms(20);
    let before = fastpath::hits_of(my_slot()).0;
    let (rc, _) = call(SYS_IPC_FAST_CALL_EP, [cap, 0x7A, 0, 0, 0, 0]);
    WB_CALL_HITS.store(i64::from(fastpath::hits_of(my_slot()).0.wrapping_sub(before)), Ordering::Release);
    WB_RC.store(rc, Ordering::Release);
    // Let the server park again after its reply, then read its priority.
    sleep_ms(20);
    WB_AFTER.store(azos_sched::task_priority(WB_SRV_TID.load(Ordering::Acquire)).unwrap_or(u32::MAX), Ordering::Release);
    call(SYS_IPC_FAST_CALL_EP, [cap, WB_STOP, 0, 0, 0, 0]);
    WB_CLI_DONE.store(true, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn ipc_fastpath_boosting_call_is_slow_and_boosts() {
        if !graph_fast_path() {
            return Ok(());
        }
        azos_sched::task_create_affinity("fp-wb-srv", wb_server, 0, WB_SERVER_PRIO, 0);
        crate::ktest::wait("the server never claimed its endpoint", || WB_READY.load(Ordering::Acquire))?;
        azos_sched::task_create_affinity("fp-wb-cli", wb_client, 0, WB_CLIENT_PRIO, 0);
        crate::ktest::wait("the calls were not answered",
            || WB_CLI_DONE.load(Ordering::Acquire) && WB_SRV_DONE.load(Ordering::Acquire))?;
        if WB_RC.load(Ordering::Acquire) != 0x7B {
            return Err("the call returned something other than the server's answer");
        }
        if WB_CALL_HITS.load(Ordering::Acquire) != 0 {
            return Err("a call that must boost its server took the fast path");
        }
        if WB_SERVING.load(Ordering::Acquire) > WB_CLIENT_PRIO {
            return Err("no boost: the server served below its RT caller's priority");
        }
        if WB_REPLY_HITS.load(Ordering::Acquire) != 0 {
            return Err("a reply to a call that boosted its server took the fast path");
        }
        if WB_AFTER.load(Ordering::Acquire) != WB_SERVER_PRIO {
            return Err("not restored: the server kept the boost after its reply");
        }
        Ok(())
    }
}

const WE_EP: &[u8] = b"fp.wg.edge";
/// A kernel mutex's wait object, owned by the caller while it calls.
static WE_OBJ: PiWaiters = PiWaiters::new(EdgeKind::Mutex);
static WE_READY: AtomicBool = AtomicBool::new(false);
static WE_CLI_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);
/// The server's finding: 1 the cycle refused, 2 no edge, 3 the cycle
/// accepted, 4 another refusal.
static WE_SEEN: AtomicU32 = AtomicU32::new(0);
static WE_SRV_DONE: AtomicBool = AtomicBool::new(false);
static WE_RC: AtomicI64 = AtomicI64::new(NOT_YET);
static WE_HITS: AtomicI64 = AtomicI64::new(-1);
static WE_CLI_DONE: AtomicBool = AtomicBool::new(false);

fn we_server(_: usize) {
    if !serve(WE_EP) {
        WE_SRV_DONE.store(true, Ordering::Release);
        return;
    }
    WE_READY.store(true, Ordering::Release);
    let (h, r) = call(SYS_IPC_FAST_ACCEPT, [0; 6]);
    if h >= 0 {
        let me = my_slot() as waitgraph::TaskId;
        let cli = WE_CLI_SLOT.load(Ordering::Acquire) as waitgraph::TaskId;
        // The caller waits on this server's call: its edge must be there,
        // and blocking on what the caller owns closes a cycle through it.
        let seen = if azos_sched::classes::PI.blocked_on(cli).is_none() {
            2
        } else {
            match waitgraph::block_on(me, &WE_OBJ) {
                Err(WaitError::Deadlock) => 1,
                Ok(()) => {
                    waitgraph::unblock(me, &WE_OBJ, UnblockReason::ObjectGone);
                    3
                }
                Err(_) => 4,
            }
        };
        WE_SEEN.store(seen, Ordering::Release);
        call(SYS_IPC_FAST_REPLY, [h as u64, r[2] + 1, 0, 0, 0, 0]);
    }
    WE_SRV_DONE.store(true, Ordering::Release);
}

fn we_client(_: usize) {
    let slot = my_slot();
    WE_CLI_SLOT.store(slot, Ordering::Release);
    let Some(cap) = client_cap(WE_EP) else {
        WE_CLI_DONE.store(true, Ordering::Release);
        return;
    };
    // Let the server park in its accept.
    sleep_ms(20);
    WE_OBJ.set_owner(Some(slot as waitgraph::TaskId));
    let before = fastpath::hits_of(slot).0;
    let (rc, _) = call(SYS_IPC_FAST_CALL_EP, [cap, 0x7C, 0, 0, 0, 0]);
    WE_HITS.store(i64::from(fastpath::hits_of(slot).0.wrapping_sub(before)), Ordering::Release);
    WE_OBJ.set_owner(None);
    WE_RC.store(rc, Ordering::Release);
    WE_CLI_DONE.store(true, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn ipc_fastpath_call_edge_is_in_the_graph() {
        if !graph_fast_path() {
            return Ok(());
        }
        // One hart: the server is parked when the caller calls.
        azos_sched::task_create_affinity("fp-we-srv", we_server, 0, PRIO, 0);
        crate::ktest::wait("the server never claimed its endpoint", || WE_READY.load(Ordering::Acquire))?;
        azos_sched::task_create_affinity("fp-we-cli", we_client, 0, PRIO, 0);
        crate::ktest::wait("the call was not answered",
            || WE_CLI_DONE.load(Ordering::Acquire) && WE_SRV_DONE.load(Ordering::Acquire))?;
        if WE_RC.load(Ordering::Acquire) != 0x7D {
            return Err("the call returned something other than the server's answer");
        }
        if WE_HITS.load(Ordering::Acquire) != 1 {
            return Err("the call to a parked server did not take the fast path");
        }
        match WE_SEEN.load(Ordering::Acquire) {
            1 => Ok(()),
            2 => Err("the fast-blocked caller had no wait-graph edge"),
            3 => Err("a cycle through the fast call's edge was not refused"),
            _ => Err("the server's block was refused for another reason"),
        }
    }
}
