// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Syscall dispatch — called from trap handler on ecall.
///
/// Registers: a7 = syscall number, a0..a5 = arguments, a0 = return value.
///
/// Security layers (AQ6 + AQ11):
///   1. Syscall filter: per-task whitelist rejects unauthorized syscalls.
///   2. Handle checks: (future) validate resource handles per-task.

use crate::numbers::*;
use crate::handlers::*;
use crate::ipc_handlers::*;
use crate::syscall_table::{syscall_table, SysCtx, SyscallFn};

/// Error code for denied syscall (capability violation — the seccomp filter
/// itself no longer returns this: see [`crate::handlers::seccomp_deny_kill`],
/// V1.8).
const E_PERM: i64 = -1;

/// Extra return registers a syscall arm may hand back to ring 3, on top of
/// the `i64` that lands in `a0`.
///
/// **WHY this exists (CARRIL 4).** `SYS_IPC_FAST_ACCEPT` has to give the
/// server a caller TID *and* four request words. One `i64` cannot carry
/// forty bytes, and fast IPC exists precisely so that ≤32 bytes travel in
/// registers without the kernel touching user memory — routing them through
/// a user pointer and `copy_to_user` would pay a per-page permission walk and
/// a copy on the one path this kernel optimises, forever, to avoid a one-time
/// six-line change in the trap handler.
///
/// The trap handler cannot simply be handed `&mut` to its register file: the
/// `reg_snapshot` it already passes as `regs` is a **copy** on its own stack
/// (it must be, because `frame.regs[10]` is overwritten with the return value
/// before a forked child ever reads it). So the out-registers travel back in
/// this struct and the handler copies them into the real `TrapFrame`.
///
/// **`written` is not decoration.** `a1`..`a5` are argument registers, and
/// every existing `libsys` wrapper passes its arguments as `in("a1")`,
/// `in("a2")`… — operands rustc is entitled to assume the `asm!` block leaves
/// untouched. Clobbering them on *every* syscall would be undefined behaviour
/// in ring 3 across the whole tree. Only an arm that explicitly opts in via
/// [`SyscallOut::set`] gets its registers copied back, and only wrappers
/// written for that arm may declare them `lateout`.
#[derive(Clone, Copy)]
pub struct SyscallOut {
    /// Values destined for `a1`..`a6`, in that order.
    pub regs: [u64; SYSCALL_OUT_REGS],
    /// True when an arm filled `regs` and the trap handler must copy them
    /// into the trap frame. False for every other syscall.
    pub written: bool,
}

/// What `a6` carries when no capability moved with the message.
///
/// Zero is not an accident of initialisation here: a capability handle is
/// generation-tagged and never zero, so ring 3 can read `a6 == 0` as "none"
/// without a separate flag.
pub const NO_CAP_MOVED: u64 = 0;

/// How many extra return registers [`SyscallOut`] carries: `a1`..`a6`.
///
/// **Was 5 until RFC-0040 gap 2 stage 4 (2026-09-20).** `SYS_IPC_FAST_ACCEPT`
/// already filled all five with `[caller_tid, w0, w1, w2, w3]` and returned the
/// exchange handle in `a0`, so a capability moved along with the message had
/// **nowhere to come back**. The sixth register is where the receiver learns
/// the handle the moved capability took in its own table; `0` means none rode.
///
/// `a7` (`regs[17]`) carries the syscall number and is never written back.
pub const SYSCALL_OUT_REGS: usize = 6;

impl SyscallOut {
    /// An empty set — nothing to copy back.
    pub const fn new() -> Self {
        Self { regs: [0; SYSCALL_OUT_REGS], written: false }
    }

    /// Opt this syscall into the copy-back and fill `a1`..`a6`.
    #[inline]
    pub fn set(&mut self, values: [u64; SYSCALL_OUT_REGS]) {
        self.regs = values;
        self.written = true;
    }

    /// [`set`](Self::set) for the arms that move no capability: fills `a1`..`a5`
    /// and puts [`NO_CAP_MOVED`] in `a6`.
    ///
    /// It exists so that adding the sixth register did not put a bare `0` at
    /// the end of three unrelated call sites, where it would read as a spare
    /// message word rather than as "no capability rode along". Every arm that
    /// does not transfer a capability must go through here, so the arms that
    /// DO are the only ones naming `a6` at all.
    #[inline]
    pub fn set_no_cap(&mut self, values: [u64; SYSCALL_OUT_REGS - 1]) {
        let mut regs = [NO_CAP_MOVED; SYSCALL_OUT_REGS];
        regs[..SYSCALL_OUT_REGS - 1].copy_from_slice(&values);
        self.regs = regs;
        self.written = true;
    }
}

impl Default for SyscallOut {
    fn default() -> Self { Self::new() }
}

/// Backwards-compatible entry point: dispatches and **discards** any extra
/// return registers.
///
/// **Callers that keep using this see no request payload from
/// `SYS_IPC_FAST_ACCEPT`.** The delivery added in CARRIL 4 is inert until the
/// trap handler switches to [`syscall_dispatch_out`] and copies
/// [`SyscallOut::regs`] into the live `TrapFrame` — see the doc on
/// `SyscallOut`. This shim exists so the kernel's synthetic boot-time call
/// (`kernel/src/main.rs`, the `sys_drv_invoke` smoke) needs no change at all;
/// it is not a second supported ABI.
#[allow(clippy::too_many_arguments)]
pub fn syscall_dispatch(
    num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
    sepc: u64, user_sp: u64, regs: &azos_sched::UserRegs,
) -> i64 {
    let mut out = SyscallOut::new();
    syscall_dispatch_out(num, a0, a1, a2, a3, a4, a5, sepc, user_sp, regs, &mut out)
}

/// Exit-path counters for `SYS_IPC_FAST_CALL`.
///
/// **WHY counters and not traces.** A traced run prints through the UART, which
/// costs ~160 us per 64 bytes under QEMU — enough to change the very timing
/// that produces the race. Counters are a `fetch_add` on a path that already
/// takes a lock, and they answer the only question that matters here: *which*
/// exit produced the spurious `-1`.
///
/// Read together they discriminate three hypotheses for the -1 that `vsbench`
/// measures at 0-1.2% of round trips:
///   * `exhausted` high, `ready_turn` ~0  -> genuinely many spurious wakes; the
///     `MAX_SPURIOUS_WAKES` bound is simply too low.
///   * `ready_turn` high                  -> `fast_ipc_wait_state` says the
///     reply is there while `fast_ipc_collect` cannot find it. Those two use
///     *different keys* -- collect scans by `caller_tid`, wait_state
///     classifies by `handle` -- so this would be a real inconsistency, not a
///     slow reply.
///   * `no_slot` high                     -> slot exhaustion, i.e. slots are
///     leaking from abandoned exchanges.
#[cfg(feature = "ipc-census")]
pub mod fast_call_stats {
    use core::sync::atomic::{AtomicU32, Ordering};

    pub static TURNS: AtomicU32 = AtomicU32::new(0);
    pub static READY_TURN: AtomicU32 = AtomicU32::new(0);
    pub static WAITING_TURN: AtomicU32 = AtomicU32::new(0);
    /// `Waiting` seen on the **first** turn: `task_block` returned immediately
    /// because a wake stamp was already latched when the call started. That
    /// stamp cannot belong to this exchange -- the slot was claimed
    /// microseconds ago and the server has not replied -- so it is a leftover
    /// from the previous round trip. If this dominates `WAITING_TURN`, the bug
    /// is a stamp that outlives its exchange, not a slow server.
    pub static WAITING_TURN0: AtomicU32 = AtomicU32::new(0);
    pub static GONE: AtomicU32 = AtomicU32::new(0);
    pub static EXHAUSTED: AtomicU32 = AtomicU32::new(0);
    pub static NO_SLOT: AtomicU32 = AtomicU32::new(0);

    #[inline(always)]
    pub fn bump(c: &AtomicU32) { c.fetch_add(1, Ordering::Relaxed); }

    /// `(turns, ready_turn, waiting_turn, gone, exhausted, no_slot, waiting_turn0)`
    pub fn read() -> (u32, u32, u32, u32, u32, u32, u32) {
        (TURNS.load(Ordering::Relaxed), READY_TURN.load(Ordering::Relaxed),
         WAITING_TURN.load(Ordering::Relaxed), GONE.load(Ordering::Relaxed),
         EXHAUSTED.load(Ordering::Relaxed), NO_SLOT.load(Ordering::Relaxed),
         WAITING_TURN0.load(Ordering::Relaxed))
    }
}

/// No-op shim so the call sites stay identical in both builds.
#[cfg(feature = "ipc-census")]
macro_rules! fc_stat { ($c:ident) => { crate::dispatch::fast_call_stats::bump(&crate::dispatch::fast_call_stats::$c) }; }
#[cfg(not(feature = "ipc-census"))]
macro_rules! fc_stat { ($c:ident) => { () }; }


/// Fast-IPC path trace, compiled out unless `--features ipc-trace`.
///
/// **WHY it is off by default and must stay that way.** Each line is a UART
/// write, and a UART write costs ~160 us per 64 bytes under QEMU (measured by
/// `userspace/bench/latbench`). Turning this on does not observe the fast path — it
/// replaces its timing entirely, which for a race is the difference between
/// seeing the bug and hiding it. Use it to answer "where does the exchange
/// stop", never "how long does the exchange take".
macro_rules! ipc_trace {
    ($($arg:tt)*) => {
        #[cfg(feature = "ipc-trace")]
        { azos_drv_sys::kprintln!($($arg)*); }
    };
}

/// Main syscall dispatch.  Arguments are raw register values (u64).
/// Returns the result that will be written back into a0.
///
/// `sepc`/`user_sp` are the trap frame's own PC/SP at ecall time — kernel-
/// internal trap metadata, not part of the user-facing syscall ABI (a0-a5
/// are the only user-supplied arguments). K-A15: passed through as plain
/// parameters (hart-local, on this call's own stack) so `SYS_FORK` can hand
/// them to `sys_fork_impl` without going through shared mutable state that
/// a concurrent syscall on another hart could clobber first.
///
/// `out` is the write-back channel for arms that must return more than one
/// register — today `SYS_IPC_FAST_ACCEPT` and `SYS_IPC_FAST_REPLY_ACCEPT`.
/// See [`SyscallOut`]. The trap
/// handler must copy `out.regs` into `frame.regs[11..16]` when `out.written`
/// is set, and must not touch them otherwise.
/// The destination of a `SYS_IPC_FAST_CALL_EP`, or `None` if the caller may
/// not send to it.
///
/// A thin shell over `azos_ipc::endpoint::endpoint_dest_for`, which is
/// where the rule and its tests live — `tests/host/syscall-tests` does not compile
/// this file, so a check written here would be the one part of gap 2 with
/// nothing exercising it. All this adds is the width guard: a handle is 32
/// bits, and a wider `a0` must be refused rather than truncated onto a
/// capability the caller does hold.
fn resolve_endpoint_dest(caller_tid: u32, cap_raw: u64) -> Option<u32> {
    // A handle is 32 bits. A wider `a0` is refused rather than truncated onto
    // a capability the caller does hold.
    let raw = u32::try_from(cap_raw).ok()?;
    crate::handlers::endpoint_dest_recording(caller_tid, raw)
}

/// The destination of a `SYS_IPC_FAST_CALL` (108), or `None` if the caller
/// may not send to it.
///
/// A thin shell over `azos_ipc::fast_ipc_tid_dest_for`, same reason as
/// `resolve_endpoint_dest` above: `tests/host/syscall-tests` does not compile
/// this file, so the rule lives in `crates/core/ipc` where `ipc-fast-tests`
/// exercises it, and this adds only the width guard — a TID is 32 bits, and a
/// wider `a0` is refused rather than truncated onto whatever the low bits
/// happen to be.
fn resolve_raw_tid_dest(a0: u64) -> Option<u32> {
    let raw = u32::try_from(a0).ok()?;
    azos_ipc::fast_ipc_tid_dest_for(raw)
}

/// Whether the fast-IPC call lends the caller's priority to the server
/// (wave 11 PIFAST) — see the call arm. `pifast-donation-canary` never
/// donates, so `pifast-smoke`'s loaded phase must fail its bound.
const FAST_CALL_DONATES: bool = !cfg!(feature = "pifast-donation-canary");

/// Body of the fast-IPC CALL arm, shared by `SYS_IPC_FAST_CALL_EP` (582) and,
/// where it is compiled in, `SYS_IPC_FAST_CALL` (108).
///
/// **Extracted so 108 can be compiled out.** The two numbers differ only in
/// how `a0` names the destination — a capability the caller holds, or a raw
/// TID, now checked against the caller's own parent (RFC-0040 gap 2, the
/// CALL direction) — and everything after that is the same exchange. A board
/// kernel matches 582 alone (see the arms), so 108 falls through to the
/// default arm and is refused like any unclaimed number.
#[allow(clippy::too_many_arguments)]
fn fast_ipc_call_arm(
    num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
    out: &mut SyscallOut,
) -> i64 {

            let caller_tid = azos_sched::current_task_tid();
            let server_tid = if num == SYS_IPC_FAST_CALL_EP {
                match resolve_endpoint_dest(caller_tid, a0) {
                    Some(t) => t,
                    // One code for "no such capability", "no WRITE on it",
                    // "contained" and "nobody serves that endpoint": telling
                    // them apart would report on capabilities the caller does
                    // not hold.
                    None => return E_PERM,
                }
            } else {
                match resolve_raw_tid_dest(a0) {
                    Some(t) => t,
                    // Same one-code convention as the EP arm above: "not my
                    // parent" and "no parent recorded" collapse into the same
                    // E_PERM — see `fast_ipc_tid_dest_for`.
                    None => return E_PERM,
                }
            };
            let words = [a1 as u64, a2 as u64, a3 as u64, a4 as u64];

            // RFC-0040 gap 2 stage 4 — the capability MOVE.
            //
            // **`a5` is the handle to move, `0` for none.** It was a
            // `lateout`-only register until this change, which is the
            // `drv_heartbeat` shape; it is safe here only because every ring-3
            // image is rebuilt in one pass and `build/image_hashes.rs` binds
            // each profile to its bytes, so a caller built before this cannot
            // exec at all. `SYS_IPC_FAST_CALL` (108) is excluded on purpose:
            // even now that its destination is checked (`resolve_raw_tid_dest`
            // — the caller's own parent, nothing wider), the ABI never gave it
            // an `a5` register for a move, and there is no reason to wire one
            // for a primitive `legacy-tid-ipc` keeps alive only for
            // `userspace/tests/ipctest`.
            //
            // **Why the move runs BEFORE `fast_ipc_call` and not after.** The
            // slot becomes `Pending` inside that call, and a server woken on it
            // can accept immediately — on another hart, before this one gets
            // its next instruction. A move done afterwards would race an accept
            // that already reported `moved_cap = 0`. So the capability is moved
            // first and the resulting handle is handed to `alloc_slot`, which
            // publishes the two together.
            let moving = num == SYS_IPC_FAST_CALL_EP && a5 != 0;
            let moved_cap = if moving {
                let raw = match u32::try_from(a5) {
                    Ok(r) => r,
                    // A wider `a5` is refused, never truncated onto a
                    // capability the caller does hold — same rule as `a0`.
                    Err(_) => return E_PERM,
                };
                match azos_ipc::cap_store::move_cap(
                    caller_tid,
                    server_tid,
                    azos_abi::cap::CapHandle(raw),
                    // Rights are KEPT. Lowering needs a second field this ABI
                    // has no register for; `move_cap` takes `Some(..)` for it
                    // and no caller passes one yet.
                    None,
                ) {
                    Ok(h) => h.0,
                    // One code, as `resolve_endpoint_dest` gives one: which of
                    // stale / no-rights / receiver-full it was would report on
                    // the server's table to a caller that does not hold it.
                    Err(_) => return E_PERM,
                }
            } else {
                0
            };

            ipc_trace!("[IPC] CALL  tid={} -> srv={} w0={:#x} cap={:#x}",
                caller_tid, server_tid, words[0], moved_cap);
            // Wave 11 PIFAST (RFC-0052 §4.7): the caller lends the server its
            // priority for the span of the call, before the slot is published
            // and recorded in it (`fast_ipc_call_donating`). Without it a
            // server below the caller is woken behind any task in between on
            // its hart and the caller waits for that task: measured by
            // `pifast-smoke`, up to a 2 ms hog burst per inverted call.
            // Returned exactly once: by the server after it wakes this caller
            // (`fast_ipc_reply_words`, `fast_ipc_reply_accept` with work
            // pending), by this caller when it collects after a hand-off or
            // leaves without a reply, or by the exit sweep when it dies
            // blocked. A call refused for want of a slot returns it inside.
            match azos_ipc::fast_ipc::fast_ipc_call_donating(
                caller_tid, server_tid, words, moved_cap, FAST_CALL_DONATES,
            ) {
                // `handle`, not a slot index: the generation-tagged exchange
                // id (same encoding as the server's FAST_ACCEPT handle). The
                // client blocks on it, so a wake can only match THIS
                // exchange — the client-side ABA closure.
                Some(handle) => {
                    ipc_trace!("[IPC] CALL  tid={} handle={:#x} claimed", caller_tid, handle);
                    // The server is woken on turn 0 of the loop below, by
                    // `fast_ipc_call_handoff`, which wakes it and blocks this
                    // caller in one step so it can switch straight to a server
                    // blocked in FAST_ACCEPT on this hart (and otherwise does
                    // the wake-then-block this arm always did).


                    // **WHY blocking once is not enough (K-C10).** The fix for
                    // the lost-wakeup race stamps `wake_pending` on a task that
                    // has not reached `task_block` yet, and `block_current`
                    // consumes that stamp by returning *immediately*. So this
                    // path can now come back from `task_block` with no reply
                    // waiting — a legitimate spurious wake, not an error. The
                    // old code read that as failure and answered -1, turning
                    // the cure into a different bug.
                    //
                    // Retrying needs to tell two indistinguishable situations
                    // apart, which is why `fast_ipc_wait_state` exists:
                    //   `Waiting` — the slot is still ours and unanswered, so
                    //               going back to sleep is correct;
                    //   `Gone`    — the server died and `fast_ipc_release_all`
                    //               reclaimed the slot, so sleeping again would
                    //               be sleeping forever;
                    //   `Ready`   — the reply is there; collect it.
                    // Guessing either way is worse than the -1 this replaces.
                    //
                    // The bound is a backstop, not the mechanism: each spurious
                    // wake consumes one stamp and stamps are not latched, so a
                    // correct system converges in one or two turns. Looping
                    // unbounded inside a syscall would hand ring 3 a way to pin
                    // a hart if that assumption ever broke.
                    const MAX_SPURIOUS_WAKES: u32 = 8;
                    let mut result = -1i64;
                    // Per-call breakdown, printed only when this call fails.
                    // The global counters say what happens on average; they
                    // cannot say whether ONE failing call saw eight `Waiting`
                    // turns in a row (a burst of stamps) or a mix. That is the
                    // difference between "stamps pile up" and "something else
                    // entirely", and no aggregate can tell them apart.
                    #[cfg(feature = "ipc-census")]
                    let (mut c_wait, mut c_ready) = (0u32, 0u32);
                    // Snapshot the scheduler's wake accounting so the failure
                    // report can show the DELTA over this one call. The global
                    // totals cannot answer "who woke this client eight times";
                    // the delta can, because during one call almost nothing
                    // else is running.
                    #[cfg(feature = "ipc-census")]
                    let wc0 = azos_sched::wake_counters();
                    // Elapsed CLINT time across the whole retry loop. This is
                    // the clincher for "did it ever actually sleep": eight real
                    // blocks with eight real wakes cannot happen in a handful
                    // of ticks, but eight `task_block` calls that return
                    // without ever descheduling can.
                    #[cfg(feature = "ipc-census")]
                    let t0 = azos_drv_sys::timebase::now();
                    for _turn in 0..MAX_SPURIOUS_WAKES {
                        fc_stat!(TURNS);
                        ipc_trace!("[IPC] CALL  tid={} handle={:#x} blocking (turn {})",
                            caller_tid, handle, _turn);
                        if _turn == 0 {
                            azos_sched::scheduler::fast_ipc_call_handoff(server_tid, handle);
                        } else {
                            azos_sched::task_block(
                                azos_sched::WaitReason::FastIpcClient(handle)
                            );
                        }
                        ipc_trace!("[IPC] CALL  tid={} handle={:#x} woke (turn {})",
                            caller_tid, handle, _turn);
                        match azos_ipc::fast_ipc::fast_ipc_collect_donated(handle, caller_tid) {
                            // Full reply delivery: a0 = reply[0] (the return
                            // value, as always), a1..a3 = reply[1..3] via
                            // `SyscallOut` — same register-delivery contract
                            // as FAST_ACCEPT, and the same rule: `out` is
                            // written on SUCCESS ONLY. The -1 exhaustion path
                            // must leave a1..a5 untouched or ring 3 inherits
                            // a previous exchange's payload. libsys's wrapper
                            // declares a1..a5 `lateout` — the shared syscallN
                            // helpers (in("aN")) must never carry this call.
                            Some((reply, donee)) => {
                                // A reply that handed off to us left the
                                // donation for us to return (the server is
                                // asleep by now): see
                                // `fast_ipc_reply_then_accept`.
                                if donee != azos_ipc::fast_ipc::NO_DONEE {
                                    azos_sched::return_donation(donee);
                                }
                                out.set([reply[1], reply[2], reply[3], 0, 0,
                                         NO_CAP_MOVED]);
                                result = reply[0] as i64;
                                break;
                            }
                            None => match azos_ipc::fast_ipc_wait_state(handle, caller_tid) {
                                azos_ipc::FastIpcWait::Waiting => {
                                    fc_stat!(WAITING_TURN);
                                    #[cfg(feature = "ipc-census")]
                                    {
                                        c_wait += 1;
                                        if _turn == 0 { fc_stat!(WAITING_TURN0); }
                                    }
                                    continue
                                }
                                // `Ready` here means the reply landed between
                                // the collect and this probe; one more turn
                                // picks it up without blocking, because the
                                // reply's own wake stamped us.
                                azos_ipc::FastIpcWait::Ready   => {
                                    fc_stat!(READY_TURN);
                                    #[cfg(feature = "ipc-census")]
                                    { c_ready += 1; }
                                    continue
                                }
                                azos_ipc::FastIpcWait::Gone    => {
                                    fc_stat!(GONE);
                                    ipc_trace!("[IPC] CALL  tid={} handle={:#x} GONE (server died?)",
                                        caller_tid, handle);
                                    break;
                                }
                            },
                        }
                    }
                    // Report at the moment of failure, not from a periodic
                    // task: the census printer is a task, and a task can be
                    // descheduled, parked, or simply never sampled while the
                    // interesting microsecond passes. This fires only on the
                    // spurious -1 -- 0 to 6 times in 500 round trips -- so the
                    // UART cost it adds is charged to a path that already
                    // failed, never to a measured one.
                    if result < 0 {
                        // Leaving without a reply (exhausted, or the slot gone
                        // with a dead server): take the donation back if the
                        // exchange still carries it. A reply that landed first
                        // already returned it, and the exit sweep of a dead
                        // server leaves nothing to take.
                        let d = azos_ipc::fast_ipc::fast_ipc_withdraw_donation(handle, caller_tid);
                        if d != azos_ipc::fast_ipc::NO_DONEE {
                            azos_sched::return_donation(d);
                        }
                        fc_stat!(EXHAUSTED);
                        // U04-3: a capability moved to the server at the top
                        // of this call is stranded there if the retry loop
                        // exhausts with the slot still `Waiting` — the server
                        // never answered, so nobody is left to give it back
                        // otherwise (contrast the `None` arm below, which
                        // already does this for the "never happened" case).
                        // `fast_ipc_wait_state` cannot tell a slot the server
                        // has not looked at yet from one it has just accepted
                        // and is about to act on — the residual this doesn't
                        // close: a move-back racing the server's own use of
                        // the capability in that narrower window. `Gone` means
                        // the server already died and its own exit path
                        // reclaimed the slot; nothing to move back.
                        if moved_cap != 0
                            && azos_ipc::fast_ipc_wait_state(handle, caller_tid)
                                == azos_ipc::FastIpcWait::Waiting
                        {
                            let back = azos_ipc::cap_store::move_cap(
                                server_tid,
                                caller_tid,
                                azos_abi::cap::CapHandle(moved_cap),
                                None,
                            );
                            if back.is_err() {
                                azos_drv_sys::kerr!(
                                    "[SAFETY_CAP_STRANDED] tid={} srv={} cap={:#x} lost on exhaustion",
                                    caller_tid, server_tid, moved_cap);
                            }
                        }
                        #[cfg(feature = "ipc-census")]
                        {
                            let (t, r, w, g, e, ns, w0) = fast_call_stats::read();
                            // Slots still standing in this caller's name. The
                            // -1 path itself manufactures orphans: the client
                            // gives up, the server replies anyway, and the slot
                            // sits `Replied` (code 3) owned by a caller that is
                            // no longer waiting for it. More than one here
                            // means the failures are self-amplifying.
                            let mut slots = [(0u8, 0u8, 0u32, 0u32); 16];
                            let ns_slots = azos_ipc::fast_ipc_slot_ids(&mut slots);
                            let mut mine = 0u32;
                            let mut mine_replied = 0u32;
                            for e2 in slots.iter().take(ns_slots) {
                                if e2.2 == caller_tid {
                                    mine += 1;
                                    if e2.1 == 3 { mine_replied += 1; }
                                }
                            }
                            let wc1 = azos_sched::wake_counters();
                            let us = azos_sched::unswitched::read();
                            let bs = azos_sched::unswitched::block_split();
                            // `blk_q` = tasks that are `Blocked` and yet still
                            // sitting in a per-CPU ready queue. Such a task is
                            // dispatched by `cpu_dequeue_locked` directly, with
                            // no waker involved -- which is the only way this
                            // client can come back eight times while the wake
                            // counters stay at zero.
                            let (_rdy, _blk, _run, _pc, ready_unq, blk_q, _rsn) =
                                azos_sched::task_census();
                            let dt = azos_drv_sys::timebase::now().wrapping_sub(t0);
                            azos_drv_sys::kprintln!(
                                "[FASTCALL-FAIL] canary={:#x} tid={} THIS_CALL wait={} ready={} ticks={} | slots_mine={} orphans={} live={} | WAKE-DELTA disp={} stamp={} mism={} absent={} enqref={} late={} | UNSWITCHED-blocked aps={} q={} self={} (ok aps={} q={} self={}) | BLOCK skipped={} slept={} | LOST ready_unq={} blocked_queued={} | TOTAL turns={} ready={} waiting={} w0={} gone={} exh={} noslot={}",
                                azos_sched::unswitched::CANARY,
                                caller_tid, c_wait, c_ready, dt, mine, mine_replied, ns_slots,
                                wc1.0.wrapping_sub(wc0.0), wc1.1.wrapping_sub(wc0.1),
                                wc1.2.wrapping_sub(wc0.2), wc1.3.wrapping_sub(wc0.3),
                                wc1.4.wrapping_sub(wc0.4), wc1.5.wrapping_sub(wc0.5),
                                us.0, us.1, us.2, us.3, us.4, us.5, bs.0, bs.1, ready_unq, blk_q,
                                t, r, w, w0, g, e, ns);
                        }
                    }
                    ipc_trace!("[IPC] CALL  tid={} handle={:#x} -> rc={}",
                        caller_tid, handle, result);
                    result
                }
                None => {
                    // The exchange never happened, but the capability already
                    // moved — it was moved first on purpose, so that no accept
                    // could ever see the slot without it. Give it back, or the
                    // server keeps authority for a message it will never
                    // receive.
                    //
                    // This move back cannot fail for space: the caller is in
                    // its own trap and has granted nothing since, so the slot
                    // it just gave up is still free. It can fail if the SERVER
                    // died in between and its table was wiped, and then the
                    // capability is gone — which is the same outcome as the
                    // server having received and dropped it, and strictly
                    // better than leaving it live in a dead task's table.
                    if moved_cap != 0 {
                        let back = azos_ipc::cap_store::move_cap(
                            server_tid,
                            caller_tid,
                            azos_abi::cap::CapHandle(moved_cap),
                            None,
                        );
                        if back.is_err() {
                            azos_drv_sys::kerr!(
                                "[SAFETY_CAP_STRANDED] tid={} srv={} cap={:#x} lost on a refused call",
                                caller_tid, server_tid, moved_cap);
                        }
                    }
                    ipc_trace!("[IPC] CALL  tid={} -> srv={} NO SLOT (or bad tid)",
                        caller_tid, server_tid);
                    fc_stat!(NO_SLOT);
                    #[cfg(feature = "ipc-census")]
                    {
                        let (t, r, w, g, e, ns, w0) = fast_call_stats::read();
                        azos_drv_sys::kprintln!(
                            "[FASTCALL-NOSLOT] tid={} srv={} turns={} ready={} waiting={} waiting_turn0={} gone={} exhausted={} no_slot={}",
                            caller_tid, server_tid, t, r, w, w0, g, e, ns);
                    }
                    -1 // no free slots — fall back to channel IPC
                }
            }
        
}

/// What [`syscall_entry_fast`] decided for one syscall number.
pub enum SyscallEntry {
    /// Answered already (one of the three register-only calls); the value is
    /// the syscall's return value.
    Done(i64),
    /// The filter passed it (or audited it) and it is a native call: finish
    /// it with [`syscall_dispatch_checked`].
    Native,
    /// RFC-0047: a Linux task's number; finish it with
    /// [`syscall_dispatch_checked`], which hands it to the personality.
    Linux,
}

/// The syscall filter verdict, then the three calls that need nothing but the
/// number. Everything a syscall entry must do before it looks at arguments.
///
/// Split out of [`syscall_dispatch_out`] (SYSFLOOR) so a trap entry can run
/// it BEFORE it builds the argument list, the `SyscallOut` and (aarch64) the
/// `UserRegs` snapshot that `getpid` never reads: the filter is still the
/// first thing every syscall meets, and `Done` is only ever returned after it.
#[inline(always)]
pub fn syscall_entry_fast(num: u64) -> SyscallEntry {
    // AQ11: Syscall filter. Checked on the task slot in place
    // (`current_syscall_verdict`), so no copy of the filter is made per syscall,
    // and on the full number: one past `u16::MAX` is refused, never compared by
    // its low 16 bits.
    match azos_sched::scheduler::current_syscall_verdict(num) {
        azos_sched::filter::FilterVerdict::Allow => {}
        // An image profile in audit mode (`ImageProfile::audit` in
        // `crates/core/sched/src/seccomp.rs`): the unlisted call goes through and is
        // recorded, bounded per task on a budget apart from the capability
        // denials. `Audit` is
        // only returned for `num <= u16::MAX`, so the narrowing below is exact.
        azos_sched::filter::FilterVerdict::Audit => {
            crate::handlers::record_seccomp_audit(num as u16);
        }
        // RFC-0047: a Linux task's number is a Linux number. The personality
        // checks the filter itself, on each native call it reaches. The guard
        // is a constant: without `LINUX_ABI` this arm is not compiled and the
        // match keeps its three-way shape (`Linux` is never answered then).
        azos_sched::filter::FilterVerdict::Linux if azos_limits::LINUX_ABI => {
            return SyscallEntry::Linux;
        }
        // V1.8 (owner decision, 2026-09-26): kill, not `-1` — see
        // `handlers::seccomp_deny_kill`'s doc for why the logic lives there.
        // `seccomp_deny_kill` must NOT be `#[cold]`: that attribute on the
        // callee reshaped THIS function's register allocation and block layout
        // — measured +18 instr riscv64 / +8 aarch64 on `syscall-floor`
        // (2026-09-26, bisected: the arm's divergence and the 584 arm cost 0).
        azos_sched::filter::FilterVerdict::Deny => seccomp_deny_kill(num),
        // Never answered without the personality; refused like `Deny` if it
        // ever were.
        azos_sched::filter::FilterVerdict::Linux => seccomp_deny_kill(num),
    }

    // ── Fast path ──────────────────────────────────────────────────────
    //
    // **Why this exists.** The `match` below has ~100 arms, and LLVM reserves
    // in the function prologue the UNION of the locals of all of them. The
    // disassembly leaves no doubt:
    //
    //     addi sp, sp, -0x3c0     ← 960 bytes of frame
    //     sd ra, s0 … s11         ← 13 registers saved
    //
    // **Every** syscall paid that, `getpid` included — a call that needs not
    // one byte of stack: 26 memory accesses and a stack adjustment before even
    // looking at which syscall it is. The cheapest paid for the dearest arm.
    //
    // These three touch neither `out`, nor `regs`, nor capabilities, and copy
    // nothing to user memory, so they are answered here and the fat frame
    // stays in `dispatch_slow`.
    //
    // (Wave 10: the `match` is now `SYSCALL_TABLE`, one small function per
    // arm, so no frame is fat any more; what these three still skip is
    // `dispatch_slow`'s context stores and the indirect call. Kept: removing
    // them was not measured.)
    //
    // **The syscall filter has already been checked above**, so this skips no
    // security gate — only the prologue.
    match num {
        SYS_GETPID => SyscallEntry::Done(sys_getpid()),
        SYS_YIELD  => SyscallEntry::Done(sys_yield()),
        SYS_TEST   => SyscallEntry::Done(sys_test()),
        _ => SyscallEntry::Native,
    }
}

/// Second half of a syscall whose [`syscall_entry_fast`] verdict was not
/// `Done`: the filter has run; this only routes.
#[allow(clippy::too_many_arguments)]
#[inline]
pub fn syscall_dispatch_checked(
    entry: SyscallEntry,
    num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
    sepc: u64, user_sp: u64, regs: &azos_sched::UserRegs,
    out: &mut SyscallOut,
) -> i64 {
    #[cfg(feature = "kheap-census")]
    crate::kheap_census::enter(num);
    let r = match entry {
        SyscallEntry::Done(r) => r,
        SyscallEntry::Linux if azos_limits::LINUX_ABI => {
            crate::linux::entry(num, a0, a1, a2, a3, a4, a5, sepc, user_sp, regs, out)
        }
        _ => dispatch_slow(num, a0, a1, a2, a3, a4, a5, sepc, user_sp, regs, out),
    };
    #[cfg(feature = "kheap-census")]
    crate::kheap_census::leave();
    r
}

#[allow(clippy::too_many_arguments)]
pub fn syscall_dispatch_out(
    num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
    sepc: u64, user_sp: u64, regs: &azos_sched::UserRegs,
    out: &mut SyscallOut,
) -> i64 {
    let entry = syscall_entry_fast(num);
    syscall_dispatch_checked(entry, num, a0, a1, a2, a3, a4, a5, sepc, user_sp, regs, out)
}

/// RFC-0047: everything `syscall_dispatch_out` does after the filter check,
/// for a native call that reached the Linux personality's entry because its
/// filter word was 0 (no task current, or a word not published). Not on the
/// native path.
#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_native_checked(
    num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
    sepc: u64, user_sp: u64, regs: &azos_sched::UserRegs,
    out: &mut SyscallOut,
) -> i64 {
    match num {
        SYS_GETPID => return sys_getpid(),
        SYS_YIELD  => return sys_yield(),
        SYS_TEST   => return sys_test(),
        _ => {}
    }
    dispatch_slow(num, a0, a1, a2, a3, a4, a5, sepc, user_sp, regs, out)
}

/// Body of the `SYS_IPC_FAST_ACCEPT` arm, shared with
/// `SYS_IPC_FAST_REPLY_ACCEPT`. The ABI, and why the request travels in
/// registers, are at the arm.
fn fast_ipc_accept_into(out: &mut SyscallOut) -> i64 {
    fast_ipc_accept_into_waking(
        out, azos_sched::current_task_tid(), None, None, azos_ipc::fast_ipc::NO_DONEE,
    )
}

/// A request `fast_ipc_accept` hands back: `(handle, caller_tid, words, moved_cap)`.
type AcceptedReq = (u64, u32, [u64; 4], u32);

/// [`fast_ipc_accept_into`] with a client wake still owed: `Some((caller_tid,
/// handle))` when `SYS_IPC_FAST_REPLY_ACCEPT` delivered a reply and deferred
/// its wake to here. The wake happens on EVERY path out, exactly once — at
/// once when a request is already waiting (nothing to hand off to), or folded
/// into turn 0's block through `fast_ipc_reply_handoff` so the server can
/// switch straight to that client. Deferring it past one `fast_ipc_accept`
/// only delays a client that is blocked (or stamped) on its reply.
///
/// `polled`: `Some(first)` when the caller already made the first accept
/// attempt itself (`fast_ipc_reply_then_accept`, in the reply's own lock
/// hold), `None` to make it here.
fn fast_ipc_accept_into_waking(
    out: &mut SyscallOut,
    server_tid: u32,
    polled: Option<Option<AcceptedReq>>,
    mut wake: Option<(u32, u64)>,
    // A donation the reply took and the server owes (wave 11 PIFAST): set
    // only together with a polled next request (`fast_ipc_reply_then_accept`
    // leaves it in the slot for the client otherwise), so only the no-block
    // arm below ever sees it.
    undonate: u32,
) -> i64 {
    ipc_trace!("[IPC] ACCEPT srv={} polling", server_tid);
    // Check if a call is already waiting.
    let first = match polled {
        Some(first) => first,
        None => azos_ipc::fast_ipc_accept(server_tid),
    };
    match first {
        // `handle` is the 63-bit generation-tagged handle (57 gen +
        // 6 idx), NOT a bare slot index — it goes back to ring 3
        // verbatim for the subsequent FAST_REPLY. Masking or
        // "cleaning" it here would strip the generation and reopen
        // the slot-ABA this handle exists to close.
        Some((handle, caller_tid, words, moved_cap)) => {
            ipc_trace!("[IPC] ACCEPT srv={} handle={:#x} from tid={} w0={:#x} (no block)",
                server_tid, handle, caller_tid, words[0]);
            // `moved_cap` is a RECORD: the move happened in the caller's trap,
            // before this slot was `Pending`. Reporting it here cannot fail,
            // which is why an accept never fails for a capability.
            out.set([caller_tid as u64, words[0], words[1], words[2], words[3],
                     moved_cap as u64]);
            if let Some((client, h)) = wake {
                azos_sched::wait::wake_fast_ipc_client_tid(client, h);
            }
            // Wave 11 PIFAST: the reply's donation, returned after the wake.
            if undonate != azos_ipc::fast_ipc::NO_DONEE {
                azos_sched::return_donation(undonate);
            }
            handle as i64
        }
        None => {
            // Same spurious-wake problem as FAST_CALL, and for the same
            // reason: `wake_pending` makes `task_block` return without the
            // awaited event. Blocking exactly once and answering -1 turned
            // every stamped server into a failed accept, which is how a
            // server loop stops serving while every one of its clients waits
            // on it.
            //
            // **The two arms are NOT symmetric.** FAST_CALL owns a
            // slot, so `fast_ipc_wait_state` can tell "spurious wake,
            // keep sleeping" from "server died, give up". An accepting
            // server owns nothing: there is no slot to probe, and
            // "woken spuriously" and "genuinely nothing pending" are
            // the same observation from here. So the bounded retry is
            // not a refinement of a better test — it is the only test
            // available, and running out of turns yields -1 exactly as
            // an empty queue would.
            const MAX_SPURIOUS_WAKES: u32 = 8;
            let mut result = -1i64;
            for _turn in 0..MAX_SPURIOUS_WAKES {
                fc_stat!(TURNS);
                ipc_trace!("[IPC] ACCEPT srv={} blocking (turn {})", server_tid, _turn);
                match wake.take() {
                    Some((client, h)) => azos_sched::scheduler::fast_ipc_reply_handoff(
                        client, h, server_tid,
                    ),
                    None => azos_sched::task_block(
                        azos_sched::WaitReason::FastIpcServer(server_tid)
                    ),
                }
                if let Some((handle, caller_tid, words, moved_cap)) =
                    azos_ipc::fast_ipc_accept(server_tid)
                {
                    ipc_trace!("[IPC] ACCEPT srv={} handle={:#x} from tid={} w0={:#x} (after block)",
                        server_tid, handle, caller_tid, words[0]);
                    // Same delivery as the no-block path above (and
                    // the same generation-tagged handle — see there).
                    // Both success paths must fill `out`, and the -1
                    // exhaustion path below must not: leaving stale
                    // values in a1..a5 on a failed accept would hand
                    // ring 3 the previous exchange's payload.
                    out.set([caller_tid as u64,
                             words[0], words[1], words[2], words[3],
                             moved_cap as u64]);
                    result = handle as i64;
                    break;
                }
            }
            if result < 0 {
                ipc_trace!("[IPC] ACCEPT srv={} EXHAUSTED {} turns -> -1",
                    server_tid, MAX_SPURIOUS_WAKES);
            }
            result
        }
    }
}

/// Body of the `SYS_IPC_FAST_REPLY` arm, shared with
/// `SYS_IPC_FAST_REPLY_ACCEPT`: 0 delivered, -2 stale, -1 refused. Why the
/// replier's identity comes from the scheduler is at the arm.
fn fast_ipc_reply_words(handle: u64, words: [u64; 4]) -> i64 {
    // `handle` is the opaque handle from FAST_ACCEPT, **not** a slot index.
    // It carries a generation tag in its upper bits and must be passed
    // through untouched — no mask, no sign extension. A handle whose
    // bit 63 is set is rejected outright rather than truncated, so a
    // server that stored a negative return value and replayed it
    // cannot land on a live slot.
    let replier_tid = azos_sched::current_task_tid();
    let privileged = azos_sched::current_user_pt() == 0;
    ipc_trace!("[IPC] REPLY srv={} handle={:#x} w0={:#x}", replier_tid, handle, words[0]);
    match azos_ipc::fast_ipc_reply(handle, replier_tid, privileged, words) {
        // `_slot_idx`: only the ipc-trace build reads it, and the
        // warning gate compiles without that feature.
        azos_ipc::FastIpcReply::Woke { caller_tid, slot_idx: _slot_idx, donee } => {
            // **WHY the wake is addressed by TID (K-C10).** The
            // sweep-keyed `wake_fast_ipc_client` matches on
            // `WaitReason::FastIpcClient(handle)`, which only exists
            // once the client is already `Blocked`. `SYS_IPC_FAST_CALL`
            // claims its slot, wakes the server and only *then* blocks,
            // so on SMP this reply can land in the gap — `try_wake_task`
            // sees a task that is not `Blocked` yet, returns early, and
            // the client sleeps forever holding its slot. The TID-keyed
            // variant stamps the wake in that case, which
            // `block_current` consumes before committing to `Blocked`.
            //
            // The handle passed through is the server's own `a0`,
            // verbatim — client and server handles of one exchange
            // are the same value (the generation only advances on
            // free), so this matches exactly the WaitReason the
            // client blocked on.
            azos_sched::wait::wake_fast_ipc_client_tid(
                caller_tid, handle);
            // The answer ends the call: the server gives back the caller's
            // priority (wave 11 PIFAST) — AFTER the wake. Returned before it,
            // a preemption in between leaves the reply deposited, the client
            // asleep and the server back at its own priority behind whatever
            // sits between them.
            if donee != azos_ipc::fast_ipc::NO_DONEE {
                azos_sched::return_donation(donee);
            }
            ipc_trace!("[IPC] REPLY srv={} slot={} woke client tid={}",
                replier_tid, _slot_idx, caller_tid);
            0
        }
        // Distinct code on purpose: `Stale` is reachable **only** by
        // the slot's current legitimate owner, so it leaks nothing, and
        // it is the one answer that tells a server "your handle died,
        // the exchange is gone" rather than "something was wrong".
        // Collapsing it into -1 would lose that and nothing else.
        azos_ipc::FastIpcReply::Stale => {
            ipc_trace!("[IPC] REPLY srv={} handle={:#x} STALE (generation retired)",
                replier_tid, handle);
            -2
        }
        azos_ipc::FastIpcReply::Refused => {
            ipc_trace!("[IPC] REPLY srv={} handle={:#x} REFUSED (not owner / not accepted)",
                replier_tid, handle);
            -1
        }
    }
}

/// Body of the `SYS_IPC_FAST_REPLY_ACCEPT` arm: 0-or-handle as the accept
/// answers, -2 stale, -3 any other refusal of the reply. The ABI and the
/// fail-fast rule are at the arm.
///
/// Stays in this file, beside [`fast_ipc_accept_into_waking`] and
/// [`fast_ipc_reply_words`], because it hands the accept its [`SyscallOut`];
/// neither is visible to `handlers.rs`.
fn fast_ipc_reply_accept(handle: u64, words: [u64; 4], out: &mut SyscallOut) -> i64 {
    // The reply and the first accept attempt share ONE hold of
    // `FAST_IPC` (`fast_ipc_reply_then_accept`); the replier's
    // identity and privilege are derived exactly as
    // `fast_ipc_reply_words` derives them. The delivered reply's
    // client wake rides on the accept: at once when a request is
    // already waiting, or folded into turn 0's block so this hart can
    // switch straight to the client (`fast_ipc_reply_handoff`).
    let server_tid = azos_sched::current_task_tid();
    let privileged = azos_sched::current_user_pt() == 0;
    let (reply, next) = azos_ipc::fast_ipc::fast_ipc_reply_then_accept(
        handle, server_tid, privileged, words, server_tid,
    );
    match reply {
        azos_ipc::FastIpcReply::Woke { caller_tid, donee, .. } => {
            // `donee` is set only when a next request was already taken (no
            // hand-off; returned after the wake); otherwise the client returns
            // it. See `fast_ipc_reply_then_accept`.
            fast_ipc_accept_into_waking(out, server_tid, Some(next), Some((caller_tid, handle)), donee)
        }
        azos_ipc::FastIpcReply::Stale => -2,
        azos_ipc::FastIpcReply::Refused => -3,
    }
}

/// One entry of [`SYSCALL_TABLE`].
type Handler = SyscallFn<azos_sched::UserRegs, SyscallOut>;

/// Entries in [`SYSCALL_TABLE`]: every number the ABI assigns is below
/// `SYS_NR_RESERVED_UPPER` (`tests/host/abi-tests` holds every arm below it).
const SYSCALL_TABLE_LEN: usize = SYS_NR_RESERVED_UPPER as usize;

/// Everything that is not the fast path: one handler per syscall number,
/// indexed by it (see `crate::syscall_table` for why a table and not a
/// `match`, and how the arms below become its entries). The arms read as the
/// `match num` they used to be: first match wins, `_` answers every number
/// nothing else claims.
static SYSCALL_TABLE: [Handler; SYSCALL_TABLE_LEN] = syscall_table!(
    SYSCALL_TABLE_LEN, azos_sched::UserRegs, SyscallOut;
    |num, a0, a1, a2, a3, a4, a5, sepc, user_sp, regs, out| {
        // Console
        SYS_TEST    => sys_test(),
        SYS_PUTCHAR => sys_putchar(a0),
        SYS_GETCHAR => sys_getchar(),

        // Process
        SYS_EXIT    => sys_exit(a0),
        SYS_GETPID  => sys_getpid(),
        SYS_YIELD   => sys_yield(),
        SYS_FORK    => { let t = azos_sched::prof::t(); let r = sys_fork(sepc, user_sp, regs); azos_sched::prof::add(23, t); r },
        SYS_EXEC     => sys_exec(a0, a1),
        SYS_EXECPATH => sys_execpath(a0),
        SYS_SPAWN    => crate::spawn::sys_spawn(a0),
        SYS_WAIT     => sys_wait(),
        SYS_WAIT_STATUS => sys_wait_status(a0),
        SYS_WAITPID  => { let t = azos_sched::prof::t(); let r = sys_waitpid(a0, a1); azos_sched::prof::add(17, t); r },
        SYS_EXIT_STATS => sys_exit_stats(a0),
        // Wave 13: threads (`crate::threads`).
        SYS_THREAD_CREATE => crate::threads::sys_thread_create(a0, a1, a2, a3, a4, regs),
        SYS_THREAD_EXIT   => crate::threads::sys_thread_exit(a0),
        SYS_FUTEX_WAIT    => crate::threads::sys_futex_wait(a0, a1, a2),
        SYS_FUTEX_WAKE    => crate::threads::sys_futex_wake(a0, a1),
        // Wave 13 (orphans): the caller's child-subreaper mark.
        SYS_TASK_SUBREAPER => match a0 {
            SUBREAPER_GET => azos_sched::scheduler::task_subreaper(None) as i64,
            SUBREAPER_SET => azos_sched::scheduler::task_subreaper(Some(true)) as i64,
            SUBREAPER_CLEAR => azos_sched::scheduler::task_subreaper(Some(false)) as i64,
            _ => azos_abi::error::Errno::EINVAL.to_syscall_ret(),
        },
        // The user shell (RFC-0055): pipes, spawn with a request block, the
        // console wait, a stop request to a descendant.
        SYS_PIPE_TYPED   => crate::ushell::sys_pipe_typed(a0, a1),
        SYS_SPAWN_EX     => crate::ushell::sys_spawn_ex(a0, a1),
        SYS_CONSOLE_WAIT => crate::ushell::sys_console_wait(a0, a1, a2, a3),
        SYS_TASK_KILL    => crate::ushell::sys_task_kill(a0, a1, a2, a3),
        // RFC-0055 S5: the power family, `Cap<Power>` in `a0`.
        SYS_POWER_TYPED  => crate::power::sys_power_typed(a0, a1, a2),
        // Wave 12: the other privileged families (`crate::families`).
        SYS_FLIGHT_TYPED   => crate::families::sys_flight_typed(a0, a1, a2),
        SYS_BEHAVIOR_TYPED => crate::families::sys_behavior_typed(a0, a1, a2),
        SYS_CONFIG_TYPED   => crate::families::sys_config_typed(a0, a1, a2, a3, a4, a5),
        SYS_OTA_TYPED      => crate::families::sys_ota_typed(a0, a1, a2),
        // Wave 15 (TRACE): the kernel tracer's control, `Cap<Trace>` in `a0`.
        SYS_TRACE_CTL_TYPED => crate::trace_ctl::sys_trace_ctl_typed(a0, a1, a2),
        // RFC-0053 L0b: the module loader's kernel half. Unassigned (the `_`
        // arm, -ENOSYS) in a kernel built without `lx-loader`.
        #[cfg(feature = "lx-loader")]
        SYS_MODULE_VERIFY => crate::module_ops::sys_module_verify(a0, a1, a2, a3),
        #[cfg(feature = "lx-loader")]
        SYS_MODULE_MAP_X => crate::module_ops::sys_module_map_x(a0, a1, a2),
        SYS_SLEEP    => crate::sleep::sys_sleep(a0),
        SYS_SLEEP_UNTIL => crate::sleep::sys_sleep_until(a0),

        // File I/O. `SYS_OPEN` (20), `SYS_READ` (22) and `SYS_LSEEK` (24) are
        // retired (owner decision 96): a file is opened and read through
        // `Cap<File>` (563/564), and seek has no typed form yet. The handlers
        // `sys_open`/`sys_read`/`sys_lseek` stay — the typed arms and the host
        // suites reach the descriptor seam through them — they are simply not
        // reachable from ring 3 by a number any more.
        //
        // `SYS_CLOSE` closes a DESCRIPTOR and refuses a capability handle;
        // `SYS_WRITE` is the console, untyped on purpose.
        SYS_CLOSE   => sys_close(a0),
        SYS_WRITE   => sys_write(a0, a1, a2),

        // Filesystem
        SYS_MKDIR   => sys_mkdir(a0),
        SYS_UNLINK  => sys_unlink(a0),
        SYS_READDIR => sys_readdir(a0, a1, a2, a3, a4, a5),
        SYS_MOUNT   => sys_mount(a0, a1, a2),
        SYS_UMOUNT  => sys_umount(a0),
        SYS_SYNC    => sys_sync(),
        SYS_STAT    => sys_stat(a0, a1),
        SYS_RMDIR   => sys_rmdir(a0),
        SYS_RENAME  => sys_rename(a0, a1),
        SYS_TRUNCATE => sys_truncate(a0, a1),
        SYS_FSYNC_TYPED => sys_fsync_typed(a0),
        SYS_STATFS  => sys_statfs(a0, a1, a2),

        // System info
        SYS_MEMINFO  => sys_meminfo(),
        SYS_TASKINFO => sys_taskinfo(a0, a1),
        SYS_UPTIME   => sys_uptime(),

        // System control
        SYS_SHUTDOWN => sys_shutdown(),
        SYS_REBOOT   => sys_reboot(),

        // Disk
        SYS_DISK_INFO  => sys_disk_info(),
        SYS_DISK_READ  => sys_disk_read(a0, a1, a2, a3),
        SYS_DISK_WRITE => sys_disk_write(a0, a1, a2, a3),
        SYS_DISK_SIZE  => sys_disk_size(a0),

        // Service manager
        SYS_SERVICE_REGISTER  => sys_service_register(a0, a1, a2),
        SYS_SERVICE_DISCOVER  => sys_service_discover(a0),
        SYS_SERVICE_HEARTBEAT => sys_service_heartbeat(a0),
        SYS_SERVICE_STOP      => sys_service_stop_handler(a0),
        SYS_SERVICE_UNREGISTER | SYS_SERVICE_LIST |
        SYS_SERVICE_INFO | SYS_SERVICE_START => sys_stub(),

        // E11.AQ3 — userspace driver framework.
        SYS_DRIVER_POLL_EVENT => sys_driver_poll_event(a0, a1),
        SYS_DRIVER_FETCH_REQ  => sys_driver_fetch_request(a0, a1),
        SYS_DRIVER_REPLY      => sys_driver_reply(a0, a1),
        SYS_DRIVER_REPLY_FETCH => sys_driver_reply_fetch(a0, a1, a2),
        SYS_DRIVER_REPLY_WAIT => sys_driver_reply_wait(a0, a1, a2, a3),
        SYS_DRIVER_STATS      => sys_driver_stats(a0),

        // GPIO
        SYS_GPIO_INFO  => sys_gpio_info(),

        // PWM
        SYS_PWM_INFO     => sys_pwm_info(),

        // I2C
        SYS_I2C_SCAN  => sys_i2c_scan(a0),
        SYS_I2C_INFO  => sys_i2c_info(),

        // Motor
        SYS_MOTOR_CREATE => sys_motor_create(a0, a1, a2, a3),
        SYS_MOTOR_INFO   => sys_motor_info(),

        // Memory management
        SYS_BRK    => sys_brk(a0),
        SYS_MMAP   => sys_mmap(a0, a1, a2, a3, a4, a5),
        SYS_MUNMAP => sys_munmap(a0, a1),
        // E11/AQ9: explicit COW fork (equivalent to SYS_FORK today).
        SYS_FORK_COW    => sys_fork_cow(sepc, user_sp, regs),
        // E11/AQ10: reserve a virtual range without physical backing.
        SYS_ALLOC_DEMAND => sys_alloc_demand(a0),

        // ADC
        SYS_ADC_READ => sys_adc_read(a0),

        // Buzzer
        SYS_BUZZER_TONE => sys_buzzer_tone(a0, a1),
        SYS_BUZZER_OFF  => sys_buzzer_off(),

        // M02: Fast-path IPC — register-passing, ≤32 bytes, zero-copy.

        // SYS_IPC_FAST_CALL: client side.
        // a0 = server_tid, a1..a4 = data words (up to 4 × u64 = 32 bytes).
        // Blocks until server replies.  Returns: d0 in a0 on wake (words in caller context).
        // Both call forms share this arm. Only the DESTINATION differs: 108
        // takes `a0` as a raw TID, checked against the caller's own parent
        // (RFC-0040 gap 2, `resolve_raw_tid_dest`); 582 resolves `a0` as a
        // `Cap<Endpoint>` in the caller's own table (`resolve_endpoint_dest`).
        // Everything after — the slot, the wake, the spurious-wake retry, the census —
        // is one body on purpose: two copies of this logic would drift, and
        // the retry loop below is exactly the kind of code that drifts
        // silently.
        #[cfg(feature = "legacy-tid-ipc")]
        SYS_IPC_FAST_CALL =>
            fast_ipc_call_arm(num, a0, a1, a2, a3, a4, a5, out),
        SYS_IPC_FAST_CALL_EP =>
            fast_ipc_call_arm(num, a0, a1, a2, a3, a4, a5, out),

        // SYS_IPC_FAST_ACCEPT: server side.
        // Blocks until a client calls FAST_CALL targeting this TID.
        //
        // ABI: a0 = slot index (the handle for the subsequent FAST_REPLY), or
        // -1 if nothing pending. On success ONLY, a1 = caller TID and
        // a2..a5 = the four request words, delivered through `SyscallOut`.
        //
        // **WHY the delivery is here and not in a user buffer (CARRIL 4).**
        // Until this change the arm read `(slot_idx, caller_tid, words)` out
        // of `fast_ipc_accept` and threw two thirds of it away, while the
        // comment that stood here claimed "returns caller_tid in a0; data
        // words in a1..a4 (written via TrapFrame by waker)". No waker wrote
        // anything: no code in the tree touched the server's frame. A ring-3
        // server learned *that* it had been called and could answer, but
        // never *what* was asked — which is not an RPC transport, and is why
        // the whole path had never carried a real request.
        //
        // The alternative considered was a user pointer plus `copy_to_user`.
        // It needs no trap-handler change, but it charges this path a
        // per-page VALID+USER+WRITE walk and a 40-byte copy on every accept,
        // permanently — on the one path whose entire reason to exist is
        // moving ≤32 bytes in registers without touching user memory. The
        // register route costs five stores into a struct the handler already
        // has in hand.
        //
        // **This is inert until the trap handler copies `out` back.** See
        // `syscall_dispatch` (the shim) — it discards `out`, so a caller that
        // has not migrated to `syscall_dispatch_out` still sees exactly the
        // old, payload-less behaviour. `libsys::fast_ipc_accept_req` detects
        // that case explicitly instead of reporting stale registers as data.
        SYS_IPC_FAST_ACCEPT => fast_ipc_accept_into(out),

        // SYS_IPC_FAST_REPLY: server side.
        // a0 = slot_idx (from FAST_ACCEPT return value).
        // a1..a4 = reply data words.
        // Wakes the client. Returns 0 on success.
        //
        // **WHY the replier's identity is taken from the scheduler and never
        // from a register (IPC-1).** `fast_ipc_reply` used to authorize
        // nothing: `Slot::server_tid` was written by `alloc_slot` and read only
        // to find pending work, never to decide who may answer — a field
        // written and never read, the same signature that produced the
        // `HANDLES`, `port`, `io_ring` and `shm` holes. `slot_idx` arrives raw
        // in `a0` and the space is 0..63, so any ring-3 task could sweep it and
        // hand every blocked client a reply of its choosing, impersonating any
        // IPC server on the board. Passing `current_task_tid()` here — never an
        // argument register — is what makes the check unforgeable.
        SYS_IPC_FAST_REPLY => fast_ipc_reply_words(a0, [a1, a2, a3, a4]),

        // SYS_IPC_FAST_REPLY_ACCEPT (RFC-0041 §C): the reply above and the
        // accept above it, in one trap. a0 = handle, a2..a5 = reply words. a1
        // is not read: libsys preloads the accept's not-written sentinel there,
        // so `FastRequest::delivered` keeps its meaning on this path.
        //
        // **Fail-fast (owner decision 2026-09-15).** The accept already fills
        // all of a1..a5 (`SYSCALL_OUT_REGS`), so no register is left to report
        // the reply's outcome next to an accepted request. A reply that is not
        // delivered therefore accepts nothing and returns at once: -2 stale,
        // -3 any other refusal. The server still holds its answer, knows it
        // went nowhere, and pays one more trap on a path only a server bug or
        // a dead exchange reaches. The reply's own -1 cannot pass through,
        // because -1 already means what the accept means by it: the reply was
        // delivered and nothing arrived within the eight wakes.
        SYS_IPC_FAST_REPLY_ACCEPT => fast_ipc_reply_accept(a0, [a2, a3, a4, a5], out),

        // M04: Lease-based IPC — zero-copy large transfer via time-bounded SHM grant.

        // 111 (`SYS_IPC_LEASE_GRANT`, a raw region id) is retired: the grant
        // is SYS_IPC_LEASE_GRANT_TYPED (603) below, which takes a `Cap<Shm>`.

        // SYS_IPC_LEASE_ACCEPT: lessee accepts a pending lease from lessor_tid.
        // a0=lessor_tid. Blocks until a lease from THAT lessor arrives.
        // Returns lease_id (shm_id can be queried separately), or -1 when no
        // lease from `a0` arrived within the bounded wait, when that lessor
        // exited while the caller waited, when the wait could not be
        // registered, or when `a0` does not fit a TID. A pending lease from
        // any other lessor is neither taken nor returned: it stays pending for
        // an accept naming its lessor.
        SYS_IPC_LEASE_ACCEPT => sys_ipc_lease_accept(a0),
        // SYS_IPC_LEASE_ACCEPT_MAP (613): the same accept, then the leased
        // region mapped into the caller for the life of the lease; a1 = where
        // the mapping's address goes.
        SYS_IPC_LEASE_ACCEPT_MAP => sys_ipc_lease_accept_map(a0, a1),

        // SYS_IPC_LEASE_RETURN: lessee returns the lease buffer to lessor.
        // a0=lease_id. Wakes the lessor: `lease_return` calls
        // `wq_wake_by_tid(lessor)` itself, the wake `lease_wait_return` waits
        // for, so this arm adds none. It used to add
        // `wake_fast_ipc_server(lessor)`, which no lease wait matches and which
        // dispatched a lessor blocked serving fast IPC (removed, owner decision
        // 2026-09-14).
        //
        // **WHY the caller's identity is taken from the scheduler (IPC-6).**
        // Both this arm and LEASE_FREE below passed `a0` straight through to
        // functions that received no caller at all, so they could not authorize
        // even in principle. `MAX_LEASES` is small and dense — nothing to guess.
        // A stranger calling RETURN wakes the *lessor* into believing its buffer
        // is back while the real lessee still has it mapped: a data race over
        // shared memory, driven from ring 3, not a mere annoyance. A stranger
        // calling FREE destroys a hand-off in flight between two other tasks.
        SYS_IPC_LEASE_RETURN => sys_ipc_lease_return(a0),

        // SYS_IPC_LEASE_FREE: lessor frees the lease entry after reclaiming buffer.
        // a0=lease_id. See LEASE_RETURN above for why the caller is checked.
        SYS_IPC_LEASE_FREE => sys_ipc_lease_free(a0),

        // SYS_IPC_LEASE_WAIT (wave 9): a0 = Cap<Lease> (READ). The lessor blocks
        // until returned (0) or expired (1), donating to the lessee meanwhile.
        SYS_IPC_LEASE_WAIT => sys_ipc_lease_wait(a0),

        // SYS_IPC_LEASE_GRANT_TYPED (603): lessor grants the region its
        // `Cap<Shm>` names. a0 = Cap<Shm> (READ), a1 = lessee_tid, a2 =
        // expire_ticks (0 = no expiry). Returns the lease id and, for a ring-3
        // lessor, mints the `Cap<Lease>` SYS_IPC_LEASE_WAIT takes; -EQUOTA past
        // MAX_LEASES_PER_LESSOR (8) occupied entries; the capability's
        // -ECAPSTALE/-ECAPKIND/-ECAPPERMS; -1 on any other refusal.
        SYS_IPC_LEASE_GRANT_TYPED => sys_ipc_lease_grant_typed(a0, a1, a2),

        // Network
        SYS_NET_INFO   => sys_net_info(),
        SYS_NET_GETIP  => sys_net_getip(),
        SYS_NET_SETIP  => sys_net_setip(a0, a1, a2),
        SYS_NET_PING   => sys_net_ping(a0),
        SYS_NET_GETMAC => sys_net_getmac(),
        SYS_NET_STATS  => sys_net_stats(),
        // F05: DNS resolver — a0 = hostname_ptr, a1 = hostname_len, a2 = result_ip_ptr
        SYS_DNS_RESOLVE => sys_dns_resolve(a0, a1, a2),
        // F05.2: NTP — a0 unused for SYNC; OFFSET returns Unix seconds
        // M24: same fix as SYS_DNS_RESOLVE above — yields between polls
        // instead of busy-spinning `net_poll()` from ring 3.
        SYS_NTP_SYNC   => azos_net::ntp::ntp_sync_with_yield(azos_sched::task_yield) as i64,
        SYS_NTP_OFFSET => azos_net::ntp::ntp_offset() as i64,
        SYS_MCAST_JOIN => sys_stub(),
        // SYS_SHUTDOWN (270) and SYS_REBOOT (271) handled above
        SYS_MCAST_LEAVE ..= SYS_SECURE_RECV => sys_stub(),  // 272..=276

        SYS_FDT_INFO   ..= SYS_FDT_DUMP      => sys_stub(),

        // ── F06: Driver server syscalls ─────────────────────────────────────
        // F06.1: SYS_DRV_REGISTER — a0=name_ptr, a1=name_len → drv_id or -1
        SYS_DRV_REGISTER => sys_drv_register(a0, a1),

        // F06.1: SYS_DRV_UNREGISTER — a0=drv_id (mark as Stopped)
        SYS_DRV_UNREGISTER => sys_stub(),

        // 302 (SYS_DRV_MMAP) is retired (RFC-0043): ring 3 maps MMIO only
        // through SYS_MMIO_MAP.

        // F06.2: SYS_DRV_MUNMAP — a0=va (stub: full unmap not yet supported)
        SYS_DRV_MUNMAP => sys_stub(),

        // F06.3: SYS_DRV_IRQ_WAIT — a0=irq_num → blocks until IRQ fires.
        // Returns 0 when woken, or -EAGAIN (-11) when the kernel declined to
        // block at all (K-C29). See `handlers::irq_wait_ret`.
        //
        // Wave 9 (IRQ4): for the owner of a wake-task binding of the line
        // (`SYS_IRQ_BIND` type 0) the binding's pending bit IS such a record,
        // and `sys_drv_irq_wait` re-tests it (`handlers::irq_wait_bound_ret`).
        // What follows still holds for every other caller.
        //
        // **WHY this arm cannot use a re-check loop like the ones below.**
        // Every other blocking arm re-polls the thing it waited for
        // (`lease_accept`, `port_wait_end`, `fast_ipc_collect`),
        // so a return that was not the awaited event is indistinguishable
        // from "nothing there yet" and answering -1 is honest. This arm has
        // no such probe: nothing in the tree records that IRQ `n` fired for
        // task `t`. `wake_by_irq` sweeps tasks already blocked on
        // `WaitReason::Irq(n)` and consumes the fact in the act of waking
        // them, and `irq_bind`'s `IrqTarget::WakeTask` arm is deliberately an
        // empty branch that defers to that sweep. A task that was never
        // parked therefore cannot ask whether its interrupt arrived, so the
        // refusal has to be reported rather than re-tested — which is the
        // ABI-visible alternative the K-C29 comment in
        // `scheduler.rs::block_current` calls for.
        //
        // Ring 3 sees -11 only on the refusal path. A genuine wake is still
        // 0, so a driver written against the old contract keeps working; it
        // just now has a code to retry on instead of a false success.
        SYS_DRV_IRQ_WAIT => sys_drv_irq_wait(a0),

        // F06.3: SYS_DRV_IRQ_ACK — a0=irq_num → acknowledge PLIC
        //
        // Requires `Cap<Irq>` for the line, as SYS_IRQ_BIND does.
        SYS_DRV_IRQ_ACK => sys_drv_irq_ack(a0),

        // F06.4: SYS_DRV_DMA_ALLOC — a0=size_bytes → phys addr or -1
        // Allocates one physically contiguous page (4 KiB minimum unit).
        // Drivers requesting larger DMA buffers should call multiple times.
        // Kernel callers only (see `sys_drv_dma_free`).
        SYS_DRV_DMA_ALLOC => sys_drv_dma_alloc(a0),

        // F06.4: SYS_DRV_DMA_FREE — a0=phys_addr
        // Kernel callers only: an unowned free was a ring-3 escape primitive.
        SYS_DRV_DMA_FREE => sys_drv_dma_free(a0),

        // F06.4: SYS_DRV_DMA_SYNC — a0=phys_addr, a1=size (cache flush — no-op on QEMU)
        SYS_DRV_DMA_SYNC => sys_drv_dma_sync(),

        // F06.5: SYS_DRV_HEARTBEAT — a0=drv_id → 0
        //
        // U07-5: only the driver's own task (or the kernel) may refresh it.
        SYS_DRV_HEARTBEAT => sys_drv_heartbeat(a0),

        // F06.6: SYS_DRV_GET_DEVICE — a0=drv_id, a1=out_ptr, a2=out_len → bytes written or -1
        SYS_DRV_GET_DEVICE => sys_drv_get_device(a0, a1, a2),
        // 325 is NOT a stub any more — this arm must stay ABOVE the range
        // below, which still collapses the rest of the robot block. See
        // `sys_robot_estop`: the call was declared in the ABI, exposed by
        // `libsys`, and swallowed here, so ring 3's only "stop everything"
        // returned -1.
        SYS_ROBOT_ESTOP => sys_robot_estop(),
        SYS_ROBOT_INIT ..= SYS_SENSOR_ADD     => sys_stub(),
        SYS_PLATFORM_INFO ..= SYS_PLATFORM_TYPE => sys_stub(),

        // Sockets (Phase 9)
        SYS_SOCKET   => sys_socket(a0, a1, a2),
        SYS_BIND     => sys_bind(a0, a1, a2),
        SYS_LISTEN   => sys_listen_syscall(a0, a1),
        SYS_ACCEPT   => sys_accept(a0, a1, a2),
        SYS_CONNECT  => sys_connect_syscall(a0, a1, a2),
        SYS_SEND     => sys_send_syscall(a0, a1, a2, a3),
        SYS_RECV     => sys_recv_syscall(a0, a1, a2, a3),
        // a3 = sockaddr pointer, not `flags`: see `sys_sendto_syscall`.
        SYS_SENDTO   => sys_sendto_syscall(a0, a1, a2, a3),
        SYS_RECVFROM => sys_recvfrom_syscall(a0, a1, a2, a3),
        SYS_SOCK_SHUTDOWN => sys_sock_close(a0),
        SYS_GETSOCKNAME | SYS_GETPEERNAME => sys_stub(),

        // Security (AQ11): activate syscall filter (one-way)
        SYS_SECCOMP => azos_sched::seccomp::activate_profile(a0),

        // AZOS Phase 1 W3 — Cap<T> typed IPC (RFC-0003).
        SYS_CHAN_WRITE_TYPED => sys_chan_write_typed(a0, a1, a2),
        SYS_CHAN_READ_TYPED  => sys_chan_read_typed(a0, a1, a2),

        // AZOS Phase 1 W5 — Cap<Port> typed port API.
        SYS_PORT_CREATE_TYPED  => sys_port_create_typed(),
        // RFC-0040 gap 2 stage 4. Mints into the caller and takes nothing, so
        // there is no capability to resolve and no argument to validate.
        SYS_ENDPOINT_CREATE_TYPED => sys_endpoint_create_typed(),
        SYS_PORT_POLL_TYPED    => sys_port_poll_typed(a0, a1),
        SYS_PORT_DESTROY_TYPED => sys_port_destroy_typed(a0),

        // RFC-0040 gap 1: the typed forms of the untyped channel create, shared
        // memory map, port bind and port wait (573-575, 577). 566 closes a
        // channel.
        SYS_CHAN_CREATE_TYPED  => sys_chan_create_typed(),
        SYS_SHM_MAP_TYPED      => sys_shm_map_typed(a0),
        SYS_PORT_BIND_TYPED    => sys_port_bind_typed(a0, a1, a2, a3),
        SYS_PORT_WAIT_TYPED    => sys_port_wait_typed(a0, a1),
        // Wave 11 (PORTWAIT): the multi-source wait with a deadline.
        SYS_PORT_WAIT_UNTIL_TYPED => sys_port_wait_until_typed(a0, a1, a2),

        // AZOS Phase 1 W5 batch 2 — Cap<Shm> typed shared-memory API.
        SYS_SHM_CREATE_TYPED   => sys_shm_create_typed(a0, a1),
        SYS_SHM_ACQUIRE_TYPED  => sys_shm_acquire_typed(a0, a1),
        SYS_SHM_RELEASE_TYPED  => sys_shm_release_typed(a0),

        // AZOS Phase 1 W5 batch 3 — Cap<IoRing> typed io_ring API.
        SYS_IORING_CREATE_TYPED  => sys_ioring_create_typed(a0),
        SYS_IORING_SUBMIT_TYPED  => sys_ioring_submit_typed(a0),
        SYS_IORING_DESTROY_TYPED => sys_ioring_destroy_typed(a0),

        // AZOS Phase 1 W5 batch 5.1 — Cap<Gpio> typed hardware API.
        SYS_GPIO_READ_TYPED      => sys_gpio_read_typed(a0),
        SYS_GPIO_WRITE_TYPED     => sys_gpio_write_typed(a0, a1),
        SYS_GPIO_SET_DIR_TYPED   => sys_gpio_set_dir_typed(a0, a1),

        // AZOS Phase 1 W5 batch 5.2 — Cap<I2c> typed hardware API.
        SYS_I2C_READ_TYPED       => sys_i2c_read_typed(a0, a1, a2, a3),
        SYS_I2C_WRITE_TYPED      => sys_i2c_write_typed(a0, a1, a2),
        SYS_I2C_DETECT_TYPED     => sys_i2c_detect_typed(a0),

        // AZOS Phase 1 W5 batch 5.3 — Cap<Pwm> typed hardware API.
        SYS_PWM_ENABLE_TYPED        => sys_pwm_enable_typed(a0),
        SYS_PWM_DISABLE_TYPED       => sys_pwm_disable_typed(a0),
        SYS_PWM_SET_PERIOD_TYPED    => sys_pwm_set_period_typed(a0, a1),
        SYS_PWM_SET_DUTY_TYPED      => sys_pwm_set_duty_typed(a0, a1),
        SYS_PWM_SET_DUTY_PCT_TYPED  => sys_pwm_set_duty_pct_typed(a0, a1),

        // AZOS Phase 1 W5 batch 5.4 — Cap<Motor> typed hardware API
        // (opens the cap-typed extension range 550..=579).
        SYS_MOTOR_SET_TARGET_TYPED  => sys_motor_set_target_typed(a0, a1, a2),
        SYS_MOTOR_TICK_TYPED        => sys_motor_tick_typed(a0, a1, a2, a3, a4),
        SYS_MOTOR_ENABLE_TYPED      => sys_motor_enable_typed(a0, a1),
        SYS_MOTOR_ENABLED_TYPED     => sys_motor_enabled_typed(a0),
        SYS_MOTOR_SET_GAINS_TYPED   => sys_motor_set_gains_typed(a0, a1, a2, a3),
        SYS_MOTOR_RESET_TYPED       => sys_motor_reset_typed(a0),
        // The only typed motor call that ACTUATES (560). 550-555 write PID
        // state; this one drives a wheel, like the untyped 232 it mirrors.
        SYS_MOTOR_SPEED_TYPED       => sys_motor_speed_typed(a0, a1),
        // The typed forms of 231 and 233 (RFC-0040 gap 1): the wheel comes
        // from the capability. 576 sets a direction like 231; 578 writes the
        // encoder ticks through a pointer and returns 0 or -errno.
        SYS_MOTOR_DIRECTION_TYPED   => sys_motor_direction_typed(a0, a1),
        SYS_MOTOR_ANGLE_TYPED       => sys_motor_angle_typed(a0, a1),
        // (direction, speed) in one call — U11-12, W2-B4. Same cap
        // resolution as 560/576, handler in its own file (motor_cmd.rs).
        SYS_MOTOR_MOVE_TYPED        => crate::motor_cmd::sys_motor_move_typed(a0, a1, a2),
        SYS_SENSOR_READ_TYPED       => sys_sensor_read_typed(a0, a1, a2),
        // Wave 11: 561's read behind a header carrying the acquisition time.
        SYS_SENSOR_READ_TS          => sys_sensor_read_ts(a0, a1, a2),
        // U06-9: the ring-3 door onto the reserved-sector brain-link PSK.
        // Handler in its own file (`link_key.rs`), same reason as 584's
        // `motor_cmd`: this crate's `dispatch.rs`/`handlers.rs` are owned by
        // another front this wave.
        SYS_LINK_KEY_READ_TYPED     => crate::link_key::sys_link_key_read_typed(a0, a1, a2),
        // Wave 9 (P9): ring-3 read of the kernel entropy pool. Own file, same
        // reason as 591's `link_key`.
        SYS_ENTROPY_READ_TYPED      => crate::entropy::sys_entropy_read_typed(a0, a1, a2),
        // Wave 6 (front V): the caller's own vDSO page and the sensors it
        // publishes there. Handlers in `vdso_notify.rs`, same reason as above.
        SYS_VDSO_TASK_MAP           => crate::vdso_notify::sys_vdso_task_map(),
        SYS_VDSO_SENSOR_BIND        => crate::vdso_notify::sys_vdso_sensor_bind(a0),
        // Futex-shaped notify/wait on a word in a mapped shm region.
        SYS_NOTIFY_WAIT             => crate::vdso_notify::sys_notify_wait(a0, a1, a2),
        SYS_NOTIFY_WAKE             => crate::vdso_notify::sys_notify_wake(a0, a1),
        SYS_NOTIFY_ROBUST           => crate::vdso_notify::sys_notify_robust(a0, a1),

        // Cap<File> (563-566). These are now the ONLY way ring 3 opens or
        // reads a file: the untyped 20 and 22 were retired once these had
        // taken over. SYS_CLOSE_TYPED picks what to release from the handle's
        // own kind.
        SYS_FILE_OPEN_TYPED         => sys_file_open_typed(a0, a1),
        // RFC-0055: a `Cap<Pipe>` end goes to the pipe arms, chosen by the
        // handle's kind bits; every other handle takes the file path as before.
        SYS_FILE_READ_TYPED         => if crate::ushell::is_pipe_handle(a0) {
            crate::ushell::sys_pipe_read(a0, a1, a2)
        } else {
            sys_file_read_typed(a0, a1, a2)
        },
        SYS_FILE_WRITE_TYPED        => if crate::ushell::is_pipe_handle(a0) {
            crate::ushell::sys_pipe_write(a0, a1, a2)
        } else {
            sys_file_write_typed(a0, a1, a2)
        },
        SYS_CLOSE_TYPED             => if crate::ushell::is_pipe_handle(a0) {
            crate::ushell::sys_pipe_close(a0)
        } else {
            sys_close_typed(a0)
        },

        // Cap<Socket> (567-570), one-to-one with the untyped socket calls.
        // Close goes through SYS_CLOSE_TYPED above.
        SYS_SOCKET_TYPED            => sys_socket_typed(a0, a1, a2),
        SYS_CONNECT_TYPED           => sys_connect_typed(a0, a1, a2),
        SYS_SEND_TYPED              => sys_send_typed(a0, a1, a2),
        SYS_RECV_TYPED              => sys_recv_typed(a0, a1, a2),
        // Multicast on a Cap<Socket> (571-572). The memberships go back with
        // the socket on every close path, in `crates/net/net/src/socket.rs`.
        SYS_MCAST_JOIN_TYPED        => sys_mcast_join_typed(a0, a1),
        SYS_MCAST_LEAVE_TYPED       => sys_mcast_leave_typed(a0, a1),

        // Cap<DriverRegistry> (556-557). The kind is read from the cap, so
        // unlike SYS_DRIVER_REGISTER (520) there is no kind argument to
        // disagree with the capability.
        // The read half of the capability model (558). Without it the typed
        // arms above this line had no possible ring-3 caller.
        SYS_CAP_LOOKUP              => sys_cap_lookup(a0, a1),

        SYS_DRIVER_REGISTER_TYPED   => sys_driver_register_typed(a0, a1, a2, a3),
        SYS_DRIVER_UNREGISTER_TYPED => sys_driver_unregister_typed(a0),

        // RFC-0002 Driver registry bridge — userspace invokes a
        // driver by (kind, op). Six args; uses a5 (previously a5).
        SYS_DRV_INVOKE           => sys_drv_invoke(a0, a1, a2, a3, a4, a5),

        // MMIO mapping (F00.2), see crate::mmio.
        SYS_MMIO_MAP => crate::mmio::sys_mmio_map(a0, a1),

        // IRQ binding (F00.3): a0 = irq_number, a1 = target_type, a2 = target_id, a3 = user_key
        // target_type: 0=wake_task (default via scheduler), 1=queue_to_port
        // Requires `Cap<Irq>` for the line.
        SYS_IRQ_BIND => sys_irq_bind(a0, a1, a2, a3),

        // Trace (AQ8)
        // a0 = entries to print, 0 for the default (50).
        SYS_TRACE_DUMP => sys_trace_dump(a0),

        _ => -1,
    }
);

/// Everything that is not the fast path: [`SYSCALL_TABLE`]'s entry for `num`,
/// or -1 (what `_` answers) for a number past the table.
///
/// `#[inline(never)]` is structural, not a performance hint: if this merges
/// into `syscall_dispatch_out`, the fast path's `getpid` pays the context this
/// builds on the stack, and nothing fails to say so.
#[inline(never)]
pub(crate) fn dispatch_slow(
    num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
    sepc: u64, user_sp: u64, regs: &azos_sched::UserRegs,
    out: &mut SyscallOut,
) -> i64 {
    let mut ctx = SysCtx { sepc, user_sp, regs, out };
    // `num` is ring 3's a7/x8: the index is masked after the bounds check so
    // a mispredicted check cannot load a "handler" from past the table and
    // call it speculatively (Spectre v1; `CONFIG_MITIGATION_SPECTRE_V1_INDEX`).
    match azos_limits::nospec::get(&SYSCALL_TABLE, num as usize) {
        Some(handler) => handler(num, a0, a1, a2, a3, a4, a5, &mut ctx),
        None => -1,
    }
}
