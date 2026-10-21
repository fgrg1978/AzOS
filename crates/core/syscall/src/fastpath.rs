// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The IPC fast path (Kconfig `IPC_FASTPATH`, Chain E stage a).
//!
//! A fast call (`SYS_IPC_FAST_CALL_EP`) or reply-and-accept
//! (`SYS_IPC_FAST_REPLY_ACCEPT`) whose peer is parked in the matching
//! wait is finished here, from the trap entry, after the syscall filter and
//! before the syscall table. The kernel's shared trap layer
//! (`kernel/src/trap/kernel.rs`: the lean entry's IPC branch and `dispatch`)
//! calls [`entry`] on every ISA, with the trap frame behind [`IpcRegs`] (one
//! impl per ISA: riscv64 `EcallRegs`, aarch64 `SvcRegs`, x86_64
//! `SyscallRegs`); `None` sends the call on to the table exactly as before,
//! with nothing done.
//!
//! # What is skipped, and why that is safe
//!
//! The ordinary call queues its record on the endpoint, wakes the server,
//! and the server's accept takes the record off the queue; the ordinary
//! reply publishes the answer, looks for a next call, and the client's
//! collect retry loop finds the answer. Here, with the peer known to be
//! parked in exactly that wait:
//!
//! * the call writes its record straight to ACCEPTED (what the accept would
//!   leave) and deposits its handle in the server's per-task-slot word, under
//!   the endpoint's lock and only after the server is claimed, so a claim that
//!   fails leaves nothing written and the server cannot run before the
//!   deposit is visible to it. The server's accept, wherever it resumes, takes
//!   the deposit before it looks at the queues: no queue, no ready mask, no
//!   `take_ep`. The record's tags are the same as the ordinary path's, so a
//!   server's death or the endpoint's destruction completes the call exactly
//!   as it completes an accepted one;
//! * the reply is the ordinary reply's record work, taken only when the
//!   server has no other call queued (so the ordinary path would also block it
//!   for the next one) and the client is claimed under the same lock hold;
//! * both then hand off through the scheduler's own direct switch
//!   (`ipc_fast_handoff`: the wake's bookkeeping, `ipc_direct::allowed`, the
//!   state-word CASes, `wait_reason`, `context_saving`, the K-C24 rescue,
//!   `set_current_task`, `tp`, `CURRENT_TID/PRIO`, `asid::prepare_switch`,
//!   `qsbr::switch`, lockdep, the histogram and every observability hook of
//!   that switch), so nothing the switch does is skipped;
//! * a resumed side that does not find what it was woken for (a drained
//!   endpoint, a spurious wake, a slow-path wake) goes on in the ordinary
//!   code at the same point the ordinary path would be.
//!
//! Preconditions (otherwise the ordinary path, unchanged): four words and no
//! capability to move (`a5 == 0`); the destination resolves (a refusal is
//! answered `-1` here, as the arm answers it, so the denial is recorded
//! once; a call refused after that goes on in the arm's own code from the
//! resolved destination, not from the top); the server is not the caller,
//! not exiting, and needs no priority
//! donation (with the wait graph's call edge, Kconfig WAIT_GRAPH: the
//! caller's edge to the server is lazy, see below); the peer is parked (`Blocked` on exactly the reason the ordinary
//! wake would match, no stamp, saved); no call is queued on the endpoint or
//! for the server anywhere; the caller's record is free; preemption is enabled
//! and no forced stop is pending for the current task; the runtime canary
//! `ipc-force-slow` is not armed.
//!
//! With Kconfig WAIT_GRAPH a call lends its priority through a wait-graph
//! edge, not a counted donation. The fast call records the caller's edge
//! exactly as the ordinary call does, before the call is published
//! (`blocked_on`, the lazy flag, the fence: `waitgraph::block_on_quiet`), and
//! only when the edge stays lazy: the caller is not more urgent than the
//! server, carries no boost, and the server is blocked on nothing (no chain
//! to carry, no cycle to check), so the graph lock is not taken (but, as by
//! the ordinary call, to set a server slot's call node owner, once per
//! slot). Any other call (one that boosts, a chain) takes the ordinary
//! path, which lends through the lock. The runtime canary
//! `ipc-call-no-edge` leaves the fast call without an edge as it leaves the
//! ordinary one. The record
//! keeps the edge's token, so the reply, the drain, the collect and the
//! abandon retire it as they retire an ordinary call's; the fast reply
//! answers only a call whose edge is still lazy (one a walk materialized
//! boosts its server, and its reply takes the ordinary path) and retires it
//! before the caller runs.
//!
//! Compiled out ([`ENABLED`] false): without the endpoint queues, with
//! `pifast-donation-canary` (the donation rule is what condition 8 checks),
//! `kheap-census` (the dispatch's per-syscall census) and `ipc-trace` (the
//! arms' trace lines), and without `sched-ipc-affinity`.
//!
//! # Resume points (Kconfig IPC_FASTPATH_RESUME, Chain E commit 9)
//!
//! A side that blocks in the hand-off returns, when it runs again, through
//! the hand-off, this module, the ISA's dispatch and trap handler to the
//! syscall exit: five epilogues and the exit's checks, on every resume, for
//! a syscall whose answer the peer that woke it already holds. So a side
//! that blocks in the hand-off leaves a resume point
//! ([`IpcRegs::resume_point`]: its trap frame and its ISA's resume stub,
//! which leaves through the syscall exit its entry took). The fast path that
//! claims it next, on the other side, finishes its syscall for it under the
//! endpoint lock, as seL4's fast path does: the call or the answer goes
//! straight into the peer's registers ([`IpcRegs::finish_at`], with the
//! exit's own frame step) instead of through the deposit or the record
//! (`ep_queue`'s `Claim::hand_call` / `hand_reply`), and the peer's saved
//! context is pointed at the stub (the scheduler's `ipc_fast_start_at`), so
//! whichever switch runs it next starts it at its exit. What the unwound
//! resume did, and where it is now:
//!
//! * `finish_switch` (the reap of a Zombie the switch left, `ctx-probe`'s
//!   check): the stub's call of the scheduler's `azos_ipc_fast_exit`, when
//!   the switch left a Zombie (always, in a build with `ctx-probe`);
//! * the hand-off's `restore(irq)` (and `block_current`'s, when the hand-off
//!   enqueued its peer and slept in the scheduler): nothing; the exit
//!   restores the frame's interrupt state, which is ring 3's;
//! * the census steps of that return path (`switch-census`'s
//!   `after_switch`, `ipc-census`'s `BLOCK_SLEPT`): resume points are
//!   compiled out with either;
//! * the spend of the point (the scheduler's, on the hand-off's return):
//!   the claim took it;
//! * the server's take of the deposit / the caller's collect and the record's
//!   free, and the register writes: the hand-over, under the lock, which
//!   leaves the record exactly as the take or the collect would (a call
//!   with a donation is answered through the record, its collect returns it);
//! * the dispatch's return and the handler's: nothing (they pass the result);
//! * the syscall's exit work: the result and the pc step (riscv64) by
//!   [`IpcRegs::finish_at`]; the exit tracepoint, a Linux task's signal work
//!   and an exec hand-off are each a reason not to finish the syscall at the
//!   claim (tracing on, signal work pending, the task's exec slot set: it
//!   then resumes where it blocked); lockdep's no-lock check:
//!   `azos_ipc_fast_exit`, always, in a build with lockdep; `swcensus`'s
//!   exit step: compiled out with it (above); QSBR's exception boundary: nothing without RCU_NOCBS_CPUS
//!   ([`RESUME`] is false with it); the `lat-trace` exit hook: the ISA leaves
//!   no point under `lat-trace`;
//! * the exit itself: the same instructions, entered from the stub, with no
//!   address-space write (the switch made it).
//!
//! Neither path checks a pending kill or `need_resched` at a syscall's
//! exit: a forced stop ends a task at its killable waits and at the timer
//! tick from user mode, and the reschedule is the interrupt return's. Every
//! other resume of a task that left a point (a drain, a kill, an ordinary
//! call or reply, the scheduler) finds its context as it saved it, returns
//! where it blocked and spends the point, as before.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use azos_abi::syscall_nr::{SYS_IPC_FAST_CALL_EP, SYS_IPC_FAST_REPLY_ACCEPT};
use azos_arch::Interrupts as _;
use azos_ipc::fastcall::{self, Collected, NO_DONEE};
pub use azos_sched::scheduler::FastResume;
use azos_sched::scheduler::{
    ipc_fast_claim, ipc_fast_handoff, ipc_fast_parked, ipc_fast_start_at, ipc_fast_take_resume,
};
use azos_sched::WaitReason;

use crate::dispatch::{SyscallOut, NO_CAP_MOVED};

/// The registers of the trapping task, as the fast path reads and writes
/// them. Each ISA's entry implements it over its trap frame.
pub trait IpcRegs {
    /// Argument register `n` (0..=5): riscv64 a0..a5, aarch64 x0..x5,
    /// x86_64 rdi, rsi, rdx, r10, r8, r9.
    fn arg(&self, n: usize) -> u64;
    /// Extra return register `n` (0..=5), the ones [`SyscallOut`] fills:
    /// riscv64 a1..a6, aarch64 x1..x6, x86_64 rdx, rsi, rdi, r8, r9, r10.
    fn set_out(&mut self, n: usize, v: u64);
    /// This call's resume point (see "Resume points"): `pc` is
    /// [`Self::resume_pc`], `sp` what [`Self::finish_at`] writes through.
    /// [`FastResume::NONE`] (the default): the call leaves none.
    #[inline(always)]
    fn resume_point(&self) -> FastResume {
        FastResume::NONE
    }
    /// The `pc` of every resume point registers of this kind leave (0, the
    /// default: none), so a claim finishes only a peer whose frame is of its
    /// own kind.
    #[inline(always)]
    fn resume_pc() -> usize
    where
        Self: Sized,
    {
        0
    }
    /// Finish a peer's syscall at its resume point's `at` (its `sp`): `a0`
    /// its result and, with `out`, its six extra return registers, then the
    /// frame step its syscall exit makes. The default does nothing (no
    /// resume points).
    ///
    /// # Safety
    /// `at` is the `sp` of a resume point with `pc == Self::resume_pc()`,
    /// taken from a task the caller has claimed and not yet dispatched.
    #[inline(always)]
    unsafe fn finish_at(at: usize, a0: i64, out: Option<&[u64; 6]>)
    where
        Self: Sized,
    {
        let _ = (at, a0, out);
    }
}

/// Whether the fast path is compiled in (see the module doc).
pub const ENABLED: bool = fastcall::FAST_PATH
    && azos_sched::scheduler::IPC_FAST
    && !cfg!(feature = "pifast-donation-canary")
    && !cfg!(feature = "kheap-census")
    && !cfg!(feature = "ipc-trace");

/// Cleared by the runtime canary `ipc-force-slow` (boot only).
static ON: AtomicBool = AtomicBool::new(true);

/// Whether a side that blocks here leaves a resume point (Kconfig
/// IPC_FASTPATH_RESUME, see "Resume points"): not with RCU_NOCBS_CPUS, whose
/// exception boundary (an RT CPU's user mode) the trap handler keeps per
/// entry.
pub const RESUME: bool =
    ENABLED && azos_sched::scheduler::IPC_FAST_RESUME && azos_sync::qsbr::NOCBS_CPUS == 0;

/// The ISA's resume stub ([`set_resume_stub`], at boot): what every resume
/// point of the trap entry's registers starts at. 0 until then, and for the
/// boot with the runtime canary `ipc-resume-off`: no point is left. A load
/// the point needs anyway (the stub's address), so the canary is free.
static STUB: AtomicUsize = AtomicUsize::new(0);

/// Per caller task slot: calls the fast path finished (each one a server
/// claimed and handed the CPU or enqueued). Per slot, not one counter, so a
/// test reads its own task's and not the rest of the machine's. Counted in
/// ktest builds only, the ones whose tests read them ([`hits_of`]).
#[cfg(feature = "ktest")]
static CALL_HITS: [core::sync::atomic::AtomicU32; azos_limits::MAX_TASKS] = [const { core::sync::atomic::AtomicU32::new(0) }; azos_limits::MAX_TASKS];
/// Per replying task slot: replies the fast path finished (ktest builds).
#[cfg(feature = "ktest")]
static REPLY_HITS: [core::sync::atomic::AtomicU32; azos_limits::MAX_TASKS] = [const { core::sync::atomic::AtomicU32::new(0) }; azos_limits::MAX_TASKS];

/// Arm the runtime canary `ipc-force-slow`: every call takes the ordinary
/// path for the rest of the boot.
pub fn force_slow() {
    ON.store(false, Ordering::Relaxed);
}

/// Give the trap entry's resume stub (the kernel, at boot, unless the
/// runtime canary `ipc-resume-off` is armed: then no side leaves a resume
/// point, and every resume returns where it blocked).
pub fn set_resume_stub(pc: usize) {
    if RESUME {
        STUB.store(pc, Ordering::Relaxed);
    }
}

/// The trap entry's resume stub, or 0 (see [`set_resume_stub`]): the ISAs'
/// [`IpcRegs::resume_pc`].
#[inline(always)]
pub fn resume_stub() -> usize {
    STUB.load(Ordering::Relaxed)
}

/// `(calls, replies)` the fast path finished for the task in slot `slot`
/// since boot (the slot's tasks together: read it before and after). ktest
/// builds only.
#[cfg(feature = "ktest")]
pub fn hits_of(slot: usize) -> (u32, u32) {
    match (CALL_HITS.get(slot), REPLY_HITS.get(slot)) {
        (Some(c), Some(r)) => (c.load(Ordering::Relaxed), r.load(Ordering::Relaxed)),
        _ => (0, 0),
    }
}

/// Bump `counter`'s word for task slot `slot` (in range: the scheduler's).
#[cfg(feature = "ktest")]
#[inline(always)]
fn hit(counter: &[core::sync::atomic::AtomicU32; azos_limits::MAX_TASKS], slot: usize) {
    if let Some(c) = counter.get(slot) {
        c.fetch_add(1, Ordering::Relaxed);
    }
}

/// Is `num` one of the two calls the fast path may take, with the fast path
/// on? The entry's test, inline before [`entry`] is called at all, so the
/// canary `ipc-force-slow` costs the ordinary path no call.
#[inline(always)]
pub fn wants(num: u64) -> bool {
    ENABLED
        && (num == SYS_IPC_FAST_CALL_EP || num == SYS_IPC_FAST_REPLY_ACCEPT)
        && ON.load(Ordering::Relaxed)
}

/// Finish `num` (one [`wants`] accepted) for the current task, whose
/// registers `regs` are: `Some(a0)` with the extra return registers written,
/// or `None` with nothing done, for the ordinary dispatch. The syscall filter
/// has passed the call (or audited and recorded it), and the task is native.
#[inline(never)]
pub fn entry<R: IpcRegs>(num: u64, regs: &mut R) -> Option<i64> {
    if num == SYS_IPC_FAST_CALL_EP {
        call(regs)
    } else {
        reply_accept(regs)
    }
}

/// The current task's slot and TID, when nothing keeps it from blocking: no
/// forced stop pending (the ordinary path's retry turns are the killable
/// ones), and preemption enabled (re-checked with interrupts off).
#[inline(always)]
fn current() -> Option<(usize, u32)> {
    if azos_sched::wait::current_task_killed() {
        return None;
    }
    azos_sched::current_task_slot()
}

/// What a claim does to the claimed peer's provenance scope
/// (`azos_ipc::endpoint::label`). A register-only call has no label word, so
/// the label is derived from the tasks, and it has to be in place under the
/// endpoint lock, before the peer can run again: the claim may start it on
/// another hart at once, and a peer that ran first would act on a request
/// without its label (or read an answer without absorbing it).
#[derive(Clone, Copy)]
enum Carry {
    /// A call claims the server: its scope is the caller's, as an accept
    /// would have entered it.
    Enter(u32),
    /// A reply claims the caller: it absorbs the label of the answer.
    Absorb(u32),
}

/// The claim of a peer parked on exactly this reason, made under the
/// endpoint lock (`azos_ipc::fastcall::Claim`).
/// With Kconfig IPC_FASTPATH_RESUME and `HAND` (the peer was seen holding a
/// resume point: [`azos_sched::scheduler::ipc_fast_marked`], read before the
/// lock), the claim also takes the claimed peer's resume point (one left by
/// registers of this same kind `R`, whose syscall may end without its exit
/// work) and, asked under the lock, hands the call or the answer straight
/// into that peer's registers ([`IpcRegs::finish_at`]): its resume's own
/// work, done for it (see "Resume points"). Without `HAND` it is the claim
/// it always was, so a peer without a point costs the fast path one load:
/// the point a hint saw and the claim does not find (the peer resumed and
/// parked again without one) is simply not used, and a point the hint
/// missed is spent by its own task, which resumes where it blocked.
struct Parked<R, const HAND: bool> {
    reason: WaitReason,
    carry: Carry,
    point: FastResume,
    handed: bool,
    regs: core::marker::PhantomData<R>,
}

impl<R: IpcRegs, const HAND: bool> Parked<R, HAND> {
    #[inline(always)]
    fn new(reason: WaitReason, carry: Carry) -> Self {
        Self { reason, carry, point: FastResume::NONE, handed: false, regs: core::marker::PhantomData }
    }

    /// The peer in slot `slot` was handed its call or answer: start it at
    /// its resume point.
    #[inline(always)]
    fn start(&self, slot: usize) {
        if RESUME && HAND && self.handed {
            ipc_fast_start_at(slot, self.point);
        }
    }

    /// Write the peer's result at its point (see [`IpcRegs::finish_at`]).
    #[inline(always)]
    fn hand(&mut self, a0: i64, out: &[u64; 6]) -> bool {
        if !RESUME || !HAND || self.point.pc == 0 {
            return false;
        }
        // SAFETY: `point.pc == R::resume_pc()`, the point of the peer this
        // claim just took; it runs nowhere until it is dispatched.
        unsafe { R::finish_at(self.point.sp, a0, Some(out)) };
        self.handed = true;
        true
    }
}

impl<R: IpcRegs, const HAND: bool> fastcall::Claim for &mut Parked<R, HAND> {
    #[inline(always)]
    fn claim(&mut self, slot: usize) -> bool {
        let Some(saved) = ipc_fast_claim(slot, self.reason) else {
            return false;
        };
        if azos_ipc::endpoint::label::ENABLED {
            match self.carry {
                Carry::Enter(l) => azos_ipc::endpoint::label::enter_slot(slot, l),
                Carry::Absorb(l) => azos_ipc::endpoint::label::absorb_slot(slot, l),
            }
        }
        // A peer whose registers are still being saved (it was woken, ran
        // and parked again since the hint): its saved context is its hart's
        // to write, so it keeps its point and resumes where it blocked.
        if RESUME && HAND && saved {
            let point = ipc_fast_take_resume(slot);
            if point.pc != 0 && point.pc == R::resume_pc() && exit_is_plain() {
                self.point = point;
            }
        }
        true
    }

    /// The server's accept, resumed: `a0` the handle, then the caller and
    /// the words, as [`reply_accept`] writes what its take of the deposit
    /// finds (the same record: this call's, ACCEPTED in the server's service).
    #[inline(always)]
    fn hand_call(&mut self, handle: u64, caller: u32, words: &[u64; fastcall::WORDS]) -> bool {
        self.hand(handle as i64, &[caller as u64, words[0], words[1], words[2], words[3], NO_CAP_MOVED])
    }

    /// The caller's call, resumed: what [`call_parked`] writes for the
    /// answer its collect finds (a call without a donation).
    #[inline(always)]
    fn hand_reply(&mut self, words: &[u64; fastcall::WORDS]) -> bool {
        self.hand(words[0] as i64, &[words[1], words[2], words[3], 0, 0, NO_CAP_MOVED])
    }
}

#[cfg(feature = "ipc-census")]
#[inline(always)]
fn census_turn() {
    crate::dispatch::fast_call_stats::bump(&crate::dispatch::fast_call_stats::TURNS);
}

#[cfg(not(feature = "ipc-census"))]
#[inline(always)]
fn census_turn() {}

/// `SYS_IPC_FAST_CALL_EP`: `a0` the endpoint capability, `a1..a4` the words,
/// `a5` a capability to move (the fast path takes none). Once the
/// destination is resolved the call is always finished here: by the fast
/// path, or by the arm's own code from the resolved destination on
/// ([`call_ordinary`]), so a miss does not resolve it (nor record a denial)
/// twice.
#[inline(always)]
fn call<R: IpcRegs>(regs: &mut R) -> Option<i64> {
    if regs.arg(5) != 0 {
        return None;
    }
    let (caller_idx, caller_tid) = current()?;
    // The arm's own refusal, answered here so the denial is recorded once.
    let Some((dest, hint)) = crate::dispatch::resolve_endpoint_dest_slot(caller_idx, caller_tid, regs.arg(0)) else {
        return Some(crate::dispatch::E_PERM);
    };
    let words = [regs.arg(1), regs.arg(2), regs.arg(3), regs.arg(4)];
    // An interface the kernel hosts has no server task to hand off to: it is
    // answered from the registers on this stack (`khost`).
    if let Some(key) = azos_ipc::endpoint::host_key(dest.owner) {
        let Some(who) = u32::try_from(regs.arg(0)).ok().and_then(|h| crate::khost::admit(caller_tid, h, words[0])) else {
            return Some(crate::dispatch::E_PERM);
        };
        let r = crate::khost::serve_regs(key, &who, words);
        regs.set_out(0, r[1]);
        regs.set_out(1, r[2]);
        regs.set_out(2, r[3]);
        regs.set_out(3, 0);
        regs.set_out(4, 0);
        regs.set_out(5, NO_CAP_MOVED);
        return Some(r[0] as i64);
    }
    // A service on another node (the RPC server accepts a v1 call as well as a
    // v2 one): a real-time caller is refused here as it is on the v2 call.
    if let Err(e) = crate::ipc_deadline::check_proxy(
        azos_ipc::endpoint::is_proxy(&dest),
        || azos_sched::current_sched_params().1,
        caller_tid,
    ) {
        return Some(e);
    }
    match call_parked(caller_idx, caller_tid, dest, hint, words, regs) {
        Some(r) => Some(r),
        None => Some(call_ordinary(caller_idx, caller_tid, dest, words, regs)),
    }
}

/// [`call`] to a server parked in its accept: `None`, with nothing done,
/// when a precondition fails. `hint`: the server's slot as the resolve cache
/// last saw it, used when it still holds the server (else the lookup).
#[inline(always)]
fn call_parked<R: IpcRegs>(
    caller_idx: usize, caller_tid: u32, dest: azos_ipc::endpoint::Dest, hint: usize, words: [u64; 4], regs: &mut R,
) -> Option<i64> {
    let server = dest.owner;
    if server == caller_tid {
        return None;
    }
    let server_idx = if azos_sched::scheduler::slot_holds(hint, server) {
        hint
    } else {
        azos_sched::idx_for_tid(server)?
    };
    let parked = WaitReason::FastIpcServer(server);
    // With the wait graph's call edge the donation is the edge, decided in
    // `fastcall::fast_call` (quiet or the ordinary path).
    if azos_sched::scheduler::slot_is_exiting(server_idx)
        || (!fastcall::CALL_EDGE && azos_sched::scheduler::call_needs_donation_from(caller_idx, server_idx, server))
        || !ipc_fast_parked(server_idx, server, parked)
    {
        return None;
    }
    // Interrupts off from the claim to the switch, as `ipc_wake_then_block`:
    // a tick in between would run the scheduler with the claimed server in
    // no queue.
    let irq = azos_arch::ARCH.disable_all();
    let cpu = azos_sched::smp::current_cpu_id();
    // The server works in the scope of this request (`Carry`).
    let carry = Carry::Enter(azos_ipc::endpoint::label::outgoing(caller_tid, 0));
    let claimed = if azos_sync::preempt::disabled() {
        None
    } else if RESUME && azos_sched::scheduler::ipc_fast_marked(server_idx) {
        let mut claim = Parked::<R, true>::new(parked, carry);
        let h = fastcall::fast_call(caller_idx, caller_tid, dest, server_idx, words, &mut claim);
        claim.start(server_idx);
        h
    } else {
        fastcall::fast_call(caller_idx, caller_tid, dest, server_idx, words, &mut Parked::<R, false>::new(parked, carry))
    };
    let Some(handle) = claimed else {
        azos_arch::ARCH.restore(irq);
        return None;
    };
    #[cfg(feature = "ktest")]
    hit(&CALL_HITS, caller_idx);
    census_turn();
    park(regs, caller_idx);
    ipc_fast_handoff(cpu, server_idx, WaitReason::FastIpcClient(handle), irq);
    // Running again: the answer is normally in the record.
    match fastcall::collect(handle, caller_tid) {
        Collected::Reply(reply, donee) => {
            if donee != NO_DONEE {
                azos_sched::return_donation(donee);
            }
            regs.set_out(0, reply[1]);
            regs.set_out(1, reply[2]);
            regs.set_out(2, reply[3]);
            regs.set_out(3, 0);
            regs.set_out(4, 0);
            regs.set_out(5, NO_CAP_MOVED);
            Some(reply[0] as i64)
        }
        // Completed without an answer (the server died, the endpoint was
        // destroyed): the code is the call's answer, as in the arm.
        Collected::Done(code, donee) => {
            if donee != NO_DONEE {
                azos_sched::return_donation(donee);
            }
            Some(code)
        }
        // Woken without an answer: the arm's retry loop, from turn 0's
        // collect on.
        Collected::Nothing => Some(call_wait(handle, caller_tid, server, regs)),
    }
}

/// [`call`] that the fast path could not take after resolving its
/// destination: the arm's code from there on (queue, hand-off, wait).
#[inline(never)]
fn call_ordinary<R: IpcRegs>(
    caller_idx: usize, caller_tid: u32, dest: azos_ipc::endpoint::Dest, words: [u64; 4], regs: &mut R,
) -> i64 {
    let mut out = SyscallOut::new();
    let r = crate::dispatch::fast_ipc_call_to(caller_idx, caller_tid, dest, words, 0, &mut out);
    copy_out(&out, regs);
    r
}

/// [`call`] resumed without its answer: the ordinary wait, turn 0's
/// hand-off already made.
#[inline(never)]
fn call_wait<R: IpcRegs>(handle: u64, caller_tid: u32, server: u32, regs: &mut R) -> i64 {
    let mut out = SyscallOut::new();
    let r = crate::dispatch::fast_ipc_call_wait(handle, caller_tid, server, 0, false, &mut out, true);
    copy_out(&out, regs);
    r
}

/// `SYS_IPC_FAST_REPLY_ACCEPT`: `a0` the handle answered, `a2..a5` the
/// answer's words (`a1` unused, as in the arm).
#[inline(always)]
fn reply_accept<R: IpcRegs>(regs: &mut R) -> Option<i64> {
    let (server_idx, server_tid) = current()?;
    let handle = regs.arg(0);
    let words = [regs.arg(2), regs.arg(3), regs.arg(4), regs.arg(5)];
    let parked = WaitReason::FastIpcClient(handle);
    let irq = azos_arch::ARCH.disable_all();
    let cpu = azos_sched::smp::current_cpu_id();
    // The caller absorbs the label of this answer: the server's scope, read
    // now, while it still has the request's (`Carry`).
    let carry = Carry::Absorb(azos_ipc::endpoint::label::outgoing(server_tid, 0));
    let answered = if azos_sync::preempt::disabled() {
        None
    } else if RESUME && fastcall::handle_slot(handle).is_some_and(azos_sched::scheduler::ipc_fast_marked) {
        let mut claim = Parked::<R, true>::new(parked, carry);
        let got = fastcall::fast_reply(handle, server_tid, server_idx, words, &mut claim);
        if let Some((client_idx, _)) = got {
            claim.start(client_idx);
        }
        got
    } else {
        fastcall::fast_reply(handle, server_tid, server_idx, words, &mut Parked::<R, false>::new(parked, carry))
    };
    let Some((client_idx, _)) = answered else {
        azos_arch::ARCH.restore(irq);
        return None;
    };
    // Out of the request it answered; the next one's label is entered by the
    // call that claims this server, before it can run.
    azos_ipc::endpoint::label::enter_slot(server_idx, 0);
    #[cfg(feature = "ktest")]
    hit(&REPLY_HITS, server_idx);
    census_turn();
    park(regs, server_idx);
    ipc_fast_handoff(cpu, client_idx, WaitReason::FastIpcServer(server_tid), irq);
    // Running again: normally a fast call deposited the next request.
    if let Some((rec, h)) = fastcall::take_deposit(server_idx, server_tid) {
        regs.set_out(0, fastcall::deposit_caller(rec) as u64);
        regs.set_out(1, fastcall::deposit_word(rec, 0));
        regs.set_out(2, fastcall::deposit_word(rec, 1));
        regs.set_out(3, fastcall::deposit_word(rec, 2));
        regs.set_out(4, fastcall::deposit_word(rec, 3));
        regs.set_out(5, NO_CAP_MOVED);
        return Some(h as i64);
    }
    Some(accept_wait(server_idx, server_tid, regs))
}

/// The current task, in slot `slot`, leaves its resume point for the
/// hand-off it is about to make (see "Resume points").
#[inline(always)]
fn park<R: IpcRegs>(regs: &R, slot: usize) {
    if RESUME {
        let point = regs.resume_point();
        if point.pc != 0 {
            azos_sched::scheduler::ipc_fast_leave(slot, point);
        }
    }
}

/// May a syscall end at its resume point now, without its exit work: no
/// exit tracepoint to record, no Linux signal work pending anywhere?
#[inline(always)]
fn exit_is_plain() -> bool {
    !azos_trace::syscall_on() && !(azos_limits::LINUX_ABI && azos_sched::scheduler::signal::work_pending())
}

/// [`reply_accept`] resumed without a deposit (woken by an ordinary call, or
/// spuriously): the ordinary accept, polling first.
#[inline(never)]
fn accept_wait<R: IpcRegs>(server_idx: usize, server_tid: u32, regs: &mut R) -> i64 {
    let mut out = SyscallOut::new();
    let r = crate::dispatch::fast_ipc_accept_into_waking(&mut out, server_idx, server_tid, None, None, NO_DONEE);
    copy_out(&out, regs);
    r
}

/// The ISA entries' copy-back of [`SyscallOut`], for the two resumes that
/// went through the ordinary code.
#[inline(always)]
fn copy_out<R: IpcRegs>(out: &SyscallOut, regs: &mut R) {
    if out.written {
        for (k, &v) in out.regs.iter().enumerate() {
            regs.set_out(k, v);
        }
    }
}
