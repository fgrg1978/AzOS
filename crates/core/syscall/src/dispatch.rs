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
pub(crate) const E_PERM: i64 = -1;

pub use crate::syscall_out::{SyscallOut, NO_CAP_MOVED, SYSCALL_OUT_REGS};

/// Backwards-compatible entry point: dispatches and **discards** any extra
/// return registers.
///
/// **Callers that keep using this see no request payload from
/// `SYS_IPC_FAST_ACCEPT`.** The delivery added in CARRIL 4 is inert until the
/// trap handler switches to [`syscall_dispatch_out`] and copies
/// [`SyscallOut::regs`] into the live `TrapFrame` — see the doc on
/// `SyscallOut`. This shim exists so a kernel-context caller (a boot-time
/// synthetic call) needs no change; it is not a second supported ABI.
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
/// parameters (hart-local, on this call's own stack) so `SYS_FOREIGN_FORK` can hand
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
///
/// `caller_idx` is the caller's task slot: the resolution goes through that
/// slot's resolve cache (`crate::handlers::endpoint_dest_at`, Kconfig
/// `IPC_RESOLVE_CACHE`).
#[inline(always)]
pub(crate) fn resolve_endpoint_dest(caller_idx: usize, caller_tid: u32, cap_raw: u64) -> Option<azos_ipc::endpoint::Dest> {
    // A handle is 32 bits. A wider `a0` is refused rather than truncated onto
    // a capability the caller does hold.
    let raw = u32::try_from(cap_raw).ok()?;
    crate::handlers::endpoint_dest_at(caller_idx, caller_tid, raw)
}

/// [`resolve_endpoint_dest`] with the serving task's slot as an unchecked
/// hint (`usize::MAX`: none), for the IPC fast path.
#[inline(always)]
pub(crate) fn resolve_endpoint_dest_slot(
    caller_idx: usize, caller_tid: u32, cap_raw: u64,
) -> Option<(azos_ipc::endpoint::Dest, usize)> {
    let raw = u32::try_from(cap_raw).ok()?;
    crate::handlers::endpoint_dest_slot_at(caller_idx, caller_tid, raw)
}

/// Whether the fast-IPC call lends the caller's priority to the server
/// (wave 11 PIFAST) — see the call arm. `pifast-donation-canary` never
/// donates, so `pifast-smoke`'s loaded phase must fail its bound.
const FAST_CALL_DONATES: bool = !cfg!(feature = "pifast-donation-canary");

/// Body of the fast-IPC CALL arm, `SYS_IPC_FAST_CALL_EP`: `a0` names
/// the destination by a capability the caller holds. The raw-TID form (108)
/// is retired (wave 15 N5).
#[allow(clippy::too_many_arguments)]
fn fast_ipc_call_arm(
    a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
    out: &mut SyscallOut,
) -> i64 {

            // The caller's task slot and TID in one read: the slot names its
            // call record.
            let (caller_idx, caller_tid) = azos_sched::current_task_slot().unwrap_or((usize::MAX, 0));
            let dest = match resolve_endpoint_dest(caller_idx, caller_tid, a0) {
                Some(d) => d,
                // One code for "no such capability", "no WRITE on it",
                // "contained" and "nobody serves that endpoint": telling
                // them apart would report on capabilities the caller does
                // not hold.
                None => return E_PERM,
            };
            // An interface the kernel hosts answers here, in the registers:
            // the request's four words in, the reply's four words out.
            if let Some(key) = azos_ipc::endpoint::host_key(dest.owner) {
                return fast_ipc_call_kernel_hosted(key, caller_tid, a0, [a1, a2, a3, a4], a5, out);
            }
            // A service on another node: refused to a real-time caller (the v2
            // call and the lean entry apply the same rule).
            if let Err(e) = crate::ipc_deadline::check_proxy(
                azos_ipc::endpoint::is_proxy(&dest),
                || azos_sched::current_sched_params().1,
                caller_tid,
            ) {
                return e;
            }
            fast_ipc_call_to(caller_idx, caller_tid, dest, [a1, a2, a3, a4], a5, out)
}

/// The register form of a call to an endpoint the kernel hosts
/// (`crate::khost::serve_regs`). It moves no capability (`a5` must be 0:
/// `E_PERM`, as for any refused destination). The reply's four words come
/// back in `a0..a3`; word 0 is the interface's status, small and
/// non-negative, so it cannot be mistaken for the call's own failure.
#[inline(always)]
fn fast_ipc_call_kernel_hosted(
    key: u16, caller_tid: u32, ep_raw: u64, words: [u64; 4], a5: u64, out: &mut SyscallOut,
) -> i64 {
    if a5 != 0 {
        return E_PERM;
    }
    let Some(who) = u32::try_from(ep_raw).ok().and_then(|h| crate::khost::admit(caller_tid, h, words[0])) else {
        return E_PERM;
    };
    let r = crate::khost::serve_regs(key, &who, words);
    out.set_no_cap([r[1], r[2], r[3], 0, 0]);
    r[0] as i64
}

/// [`fast_ipc_call_arm`] from the resolved destination on: the call of the
/// task in slot `caller_idx` (`caller_tid`) to `dest` with `words`, moving the
/// capability `a5` (0: none). Also the IPC fast path's ordinary half, for a
/// call it resolved and then could not take (`crate::fastpath`): the
/// destination is not resolved (nor a denial recorded) twice.
#[inline(always)]
pub(crate) fn fast_ipc_call_to(
    caller_idx: usize, caller_tid: u32, dest: azos_ipc::endpoint::Dest, words: [u64; 4], a5: u64,
    out: &mut SyscallOut,
) -> i64 {
            let server_tid = dest.owner;

            // The capability MOVE.
            //
            // **`a5` is the handle to move, `0` for none.** It was a
            // `lateout`-only register until this change, which is the
            // `drv_heartbeat` shape; it is safe here only because every ring-3
            // image is rebuilt in one pass and `$AZOS_OUT/build/image_hashes.rs` binds
            // each profile to its bytes, so a caller built before this cannot
            // exec at all.
            //
            // **Why the move runs BEFORE `fast_ipc_call` and not after.** The
            // slot becomes `Pending` inside that call, and a server woken on it
            // can accept immediately — on another hart, before this one gets
            // its next instruction. A move done afterwards would race an accept
            // that already reported `moved_cap = 0`. So the capability is moved
            // first and the resulting handle is handed to `alloc_slot`, which
            // publishes the two together.
            //
            // **`FAST_CALL_CAP_SHARE` (bit 32 of `a5`) shares instead:** the
            // receiver gets a derived copy and the caller keeps its handle (and,
            // for a `Cap<Shm>`, its mapping). Undone on a refused call by
            // revoking the copy, not by moving it back.
            let share = a5 & azos_abi::syscall_nr::FAST_CALL_CAP_SHARE != 0;
            let a5 = a5 & !azos_abi::syscall_nr::FAST_CALL_CAP_SHARE;
            let moving = a5 != 0;
            let moved_cap = if moving {
                let raw = match u32::try_from(a5) {
                    Ok(r) => r,
                    // A wider `a5` is refused, never truncated onto a
                    // capability the caller does hold — same rule as `a0`.
                    Err(_) => return E_PERM,
                };
                let handle = azos_abi::cap::CapHandle(raw);
                // Rights are KEPT. Lowering needs a second field this ABI has
                // no register for.
                let moved = if share {
                    let mut out = [azos_abi::cap::CapHandle(0); 1];
                    azos_ipc::cap_store::move_caps(
                        caller_tid, server_tid, &[azos_ipc::cap_store::CapXfer::new(handle, true)], false, &mut out,
                    )
                    .map(|_| out[0])
                } else {
                    azos_ipc::cap_store::move_cap(caller_tid, server_tid, handle, None)
                };
                match moved {
                    Ok(h) => {
                        crate::ipc_handlers::reap_moved_windows();
                        h.0
                    }
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
            // Wave 11 PIFAST: the caller lends the server its
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
            match azos_ipc::fastcall::call(
                caller_idx, caller_tid, dest, words, moved_cap, FAST_CALL_DONATES,
            ) {
                // `handle`, not a slot index: the generation-tagged exchange
                // id (same encoding as the server's FAST_ACCEPT handle). The
                // client blocks on it, so a wake can only match THIS
                // exchange — the client-side ABA closure.
                Some(handle) => {
                    ipc_trace!("[IPC] CALL  tid={} handle={:#x} claimed", caller_tid, handle);
                    fast_ipc_call_wait(handle, caller_tid, server_tid, moved_cap, share, out, false)
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
                    if moved_cap != 0 && !undo_cap(share, server_tid, caller_tid, moved_cap) {
                        azos_drv_sys::kerr!(
                            "[SAFETY_CAP_STRANDED] tid={} srv={} cap={:#x} lost on a refused call",
                            caller_tid, server_tid, moved_cap);
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

/// Take back the capability a refused fast call moved (or shared) to the
/// server: a MOVE goes back to the caller, a SHARE's copy is destroyed (the
/// caller kept its own). `false` when it could not be.
fn undo_cap(share: bool, server_tid: u32, caller_tid: u32, moved_cap: u32) -> bool {
    let h = azos_abi::cap::CapHandle(moved_cap);
    if share {
        azos_ipc::cap_store::delete_moved(server_tid, h)
    } else {
        azos_ipc::cap_store::move_cap(server_tid, caller_tid, h, None).is_ok()
    }
}

/// The fast call's wait for its answer, from the hand-off that wakes the
/// server to the collect, with the bounded retry over spurious wakes and the
/// withdrawal when no answer comes. `blocked`: turn 0's hand-off was already
/// made by the fast path (`crate::fastpath`), which resumes here when the
/// answer it found on waking was not there yet.
#[inline(always)]
pub(crate) fn fast_ipc_call_wait(
    handle: u64, caller_tid: u32, server_tid: u32, moved_cap: u32, share: bool, out: &mut SyscallOut, blocked: bool,
) -> i64 {
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
    const MAX_SPURIOUS_WAKES: u32 = azos_limits::IPC_CALL_WAKE_RETRIES as u32;
    let mut result = -1i64;
    // Completed with a code (`Collected::Done`): nothing is
    // left to withdraw.
    let mut completed = false;
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
            // The fast path (`crate::fastpath`) made this hand-off already.
            if !blocked {
                azos_sched::scheduler::fast_ipc_call_handoff(server_tid, handle);
            }
        } else {
            // Killable (plan item 7): a forced kill spends
            // the remaining turns without blocking.
            azos_sched::task_block_unless_killed(
                azos_sched::WaitReason::FastIpcClient(handle)
            );
        }
        ipc_trace!("[IPC] CALL  tid={} handle={:#x} woke (turn {})",
            caller_tid, handle, _turn);
        match azos_ipc::fastcall::collect(handle, caller_tid) {
            // Full reply delivery: a0 = reply[0] (the return
            // value, as always), a1..a3 = reply[1..3] via
            // `SyscallOut` — same register-delivery contract
            // as FAST_ACCEPT, and the same rule: `out` is
            // written on SUCCESS ONLY. The -1 exhaustion path
            // must leave a1..a5 untouched or ring 3 inherits
            // a previous exchange's payload. libsys's wrapper
            // declares a1..a5 `lateout` — the shared syscallN
            // helpers (in("aN")) must never carry this call.
            azos_ipc::fastcall::Collected::Reply(reply, donee) => {
                // A reply that handed off to us left the
                // donation for us to return (the server is
                // asleep by now): see
                // `fast_ipc_reply_then_accept`.
                if donee != azos_ipc::fastcall::NO_DONEE {
                    azos_sched::return_donation(donee);
                }
                out.set([reply[1], reply[2], reply[3], 0, 0,
                         NO_CAP_MOVED]);
                result = reply[0] as i64;
                break;
            }
            // Completed without an answer (wave 15 N5): the
            // server died (-EPEERDIED) or the endpoint was
            // destroyed (-EREVOKED) with this call queued or
            // in service. The code is the call's answer.
            azos_ipc::fastcall::Collected::Done(code, donee) => {
                if donee != azos_ipc::fastcall::NO_DONEE {
                    azos_sched::return_donation(donee);
                }
                result = code;
                completed = true;
                break;
            }
            azos_ipc::fastcall::Collected::Nothing => match azos_ipc::fastcall::wait_state(handle, caller_tid) {
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
    if result < 0 && !completed {
        // Leaving without a reply (exhausted, or the slot gone
        // with a dead server): withdraw the call, and take the
        // donation back if it still carries it. A reply that
        // landed first already returned it, and the exit
        // sweep of a dead server leaves nothing to take.
        let a = azos_ipc::fastcall::abandon(handle, caller_tid);
        if a.donee != azos_ipc::fastcall::NO_DONEE {
            azos_sched::return_donation(a.donee);
        }
        fc_stat!(EXHAUSTED);
        // U04-3: a capability moved to the server at the top
        // of this call is stranded there if the retry loop
        // exhausts with the request unanswered — nobody is
        // left to give it back otherwise (contrast the `None`
        // arm below, which does this for the "never happened"
        // case). With the per-endpoint queues `was_queued` is
        // exact: the request was withdrawn before any server
        // took it. The old table can only say "not answered",
        // which includes a server that has just accepted and
        // is about to act on the capability: the residual it
        // leaves.
        if moved_cap != 0 && a.was_queued && !undo_cap(share, server_tid, caller_tid, moved_cap) {
            azos_drv_sys::kerr!(
                "[SAFETY_CAP_STRANDED] tid={} srv={} cap={:#x} lost on exhaustion",
                caller_tid, server_tid, moved_cap);
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
            let ns_slots = azos_ipc::fastcall::slot_ids(&mut slots);
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
                "[FASTCALL-FAIL] canary={:#x} tid={} THIS_CALL wait={} ready={} ticks={} | slots_mine={} orphans={} live={} | WAKE-DELTA disp={} stamp={} mism={} absent={} enqref={} late={} | UNSWITCHED-blocked q={} self={} (ok q={} self={}) | BLOCK skipped={} slept={} | LOST ready_unq={} blocked_queued={} | TOTAL turns={} ready={} waiting={} w0={} gone={} exh={} noslot={}",
                azos_sched::unswitched::CANARY,
                caller_tid, c_wait, c_ready, dt, mine, mine_replied, ns_slots,
                wc1.0.wrapping_sub(wc0.0), wc1.1.wrapping_sub(wc0.1),
                wc1.2.wrapping_sub(wc0.2), wc1.3.wrapping_sub(wc0.3),
                wc1.4.wrapping_sub(wc0.4), wc1.5.wrapping_sub(wc0.5),
                us.0, us.1, us.2, us.3, bs.0, bs.1, ready_unq, blk_q,
                t, r, w, w0, g, e, ns);
        }
    }
    ipc_trace!("[IPC] CALL  tid={} handle={:#x} -> rc={}",
        caller_tid, handle, result);
    result
}

/// What [`syscall_entry_fast`] decided for one syscall number.
pub enum SyscallEntry {
    /// Answered already (one of the two register-only calls); the value is
    /// the syscall's return value.
    Done(i64),
    /// The filter passed it (or audited it) and it is a native call: finish
    /// it with [`syscall_dispatch_checked`].
    Native,
    /// A Linux task's number; finish it with
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
    if let SyscallEntry::Linux = syscall_verdict(num) {
        return SyscallEntry::Linux;
    }
    syscall_register_only(num)
}

/// [`syscall_entry_fast`]'s first half: the syscall filter verdict on `num`
/// for the current task, and nothing else. `Native` when the filter passed it
/// (an audited call recorded), `Linux` for a Linux task's number (with
/// `LINUX_ABI`); a denied call never returns (`seccomp_deny_kill`). Never
/// `Done`. Alone for an entry that knows `num` is none of the three
/// register-only calls: the lean native entries' IPC branch (Chain E cut 7,
/// `SYS_IPC_FAST_CALL_EP` / `SYS_IPC_FAST_REPLY_ACCEPT`).
#[inline(always)]
pub fn syscall_verdict(num: u64) -> SyscallEntry {
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
        // A Linux task's number is a Linux number. The personality
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
    SyscallEntry::Native
}

/// [`syscall_entry_fast`]'s second half, once the filter passed a native
/// number: the two calls answered from the number alone. Public for the
/// trap layer (`kernel/src/trap`), which counts the entry between the verdict
/// and this.
#[inline(always)]
pub fn syscall_register_only(num: u64) -> SyscallEntry {
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
    // These two touch neither `out`, nor `regs`, nor capabilities, and copy
    // nothing to user memory, so they are answered here and the fat frame
    // stays in `dispatch_slow`.
    //
    // (Wave 10: the `match` is now `SYSCALL_TABLE`, one small function per
    // arm, so no frame is fat any more; what these two still skip is
    // `dispatch_slow`'s context stores and the indirect call. Kept: removing
    // them was not measured.)
    //
    // **The syscall filter has already been checked above**, so this skips no
    // security gate — only the prologue.
    match num {
        SYS_GETPID => SyscallEntry::Done(sys_getpid()),
        SYS_YIELD  => SyscallEntry::Done(sys_yield()),
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
            // A thread that registered a runtime entry has its foreign trap
            // reflected at the return to user mode (`azos_sched::foreign`);
            // anything else is a Linux task of the in-kernel personality.
            if azos_sched::foreign::any_registered() && azos_sched::foreign::request_reflect(num, a0) {
                0
            } else {
                crate::linux::entry(num, a0, a1, a2, a3, a4, a5, sepc, user_sp, regs, out)
            }
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

/// Everything `syscall_dispatch_out` does after the filter check,
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
        _ => {}
    }
    dispatch_slow(num, a0, a1, a2, a3, a4, a5, sepc, user_sp, regs, out)
}

/// Body of the `SYS_IPC_FAST_ACCEPT` arm, shared with
/// `SYS_IPC_FAST_REPLY_ACCEPT`. The ABI, and why the request travels in
/// registers, are at the arm.
fn fast_ipc_accept_into(out: &mut SyscallOut) -> i64 {
    let (server_idx, server_tid) = azos_sched::current_task_slot().unwrap_or((usize::MAX, 0));
    fast_ipc_accept_into_waking(
        out, server_idx, server_tid, None, None, azos_ipc::fastcall::NO_DONEE,
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
#[inline(always)]
pub(crate) fn fast_ipc_accept_into_waking(
    out: &mut SyscallOut,
    server_idx: usize,
    server_tid: u32,
    polled: Option<Option<AcceptedReq>>,
    wake: Option<(u32, u64)>,
    undonate: u32,
) -> i64 {
    fast_ipc_accept_into_waking_as::<true>(out, server_idx, server_tid, polled, wake, undonate)
}

/// One accept attempt: the v1 accept (`V1`, which refuses a v2 call; wave
/// 15 N11c) or the v2 one (`SYS_IPC_ACCEPT_V2`, which takes every call).
#[inline(always)]
fn accept_as<const V1: bool>(server_idx: usize, server_tid: u32) -> Option<AcceptedReq> {
    if V1 {
        azos_ipc::fastcall::accept(server_idx, server_tid)
    } else {
        azos_ipc::fastcall::accept_v2(server_idx, server_tid)
    }
}

/// [`fast_ipc_accept_into_waking`] for the v1 accept (`V1`) or the v2 one
/// (`SYS_IPC_ACCEPT_V2`, `polled` and `wake` always `None`).
pub(crate) fn fast_ipc_accept_into_waking_as<const V1: bool>(
    out: &mut SyscallOut,
    server_idx: usize,
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
        None => accept_as::<V1>(server_idx, server_tid),
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
            if V1 {
                // The v2 accept enters the scope of its payload's label itself.
                azos_ipc::endpoint::label::accepted(server_tid, caller_tid);
            }
            if let Some((client, h)) = wake {
                azos_sched::wait::wake_fast_ipc_client_tid(client, h);
            }
            // Wave 11 PIFAST: the reply's donation, returned after the wake.
            if undonate != azos_ipc::fastcall::NO_DONEE {
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
            const MAX_SPURIOUS_WAKES: u32 = azos_limits::IPC_CALL_WAKE_RETRIES as u32;
            let mut result = -1i64;
            for _turn in 0..MAX_SPURIOUS_WAKES {
                fc_stat!(TURNS);
                ipc_trace!("[IPC] ACCEPT srv={} blocking (turn {})", server_tid, _turn);
                match wake.take() {
                    Some((client, h)) => azos_sched::scheduler::fast_ipc_reply_handoff(
                        client, h, server_tid,
                    ),
                    // Killable (plan item 7): an idle server killed in its
                    // accept spends the remaining turns without blocking.
                    None => azos_sched::task_block_unless_killed(
                        azos_sched::WaitReason::FastIpcServer(server_tid)
                    ),
                }
                // A call the fast path accepted for us while we were parked
                // (`crate::fastpath`): deposited, not queued, so it is taken
                // here before the queues are looked at.
                if let Some(handle) = fast_ipc_take_deposit(out, server_idx, server_tid) {
                    result = handle as i64;
                    break;
                }
                if let Some((handle, caller_tid, words, moved_cap)) =
                    accept_as::<V1>(server_idx, server_tid)
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
                    if V1 {
                        azos_ipc::endpoint::label::accepted(server_tid, caller_tid);
                    }
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

/// Take the call the fast path deposited for the server in slot
/// `server_idx` (`azos_ipc::fastcall::take_deposit`), delivering it in
/// `out` exactly as an accept delivers a queued call. Its handle, or `None`
/// (always, without Kconfig IPC_FASTPATH).
#[inline(always)]
fn fast_ipc_take_deposit(out: &mut SyscallOut, server_idx: usize, server_tid: u32) -> Option<u64> {
    use azos_ipc::fastcall::{deposit_caller, deposit_word};
    let (rec, handle) = azos_ipc::fastcall::take_deposit(server_idx, server_tid)?;
    // The caller's label was put in this server's scope when the call
    // claimed it (`fastpath::Parked::claim`), before the server could run.
    // A deposited call moved no capability (the fast path takes none).
    out.set([deposit_caller(rec) as u64, deposit_word(rec, 0), deposit_word(rec, 1),
             deposit_word(rec, 2), deposit_word(rec, 3), NO_CAP_MOVED]);
    Some(handle)
}

/// The label of the reply `replier` is about to make to the exchange
/// `handle` names goes into its caller's scope (`label::answering`), before
/// the reply is published. Nothing when the replier holds no such unanswered
/// call: the reply is then refused, and no task is named.
#[inline(always)]
fn label_answer(handle: u64, replier: u32) {
    if azos_ipc::endpoint::label::ENABLED {
        if let Some((caller, _)) = azos_ipc::fastcall::warrant_peer(handle, replier) {
            azos_ipc::endpoint::label::answering(replier, caller);
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
    label_answer(handle, replier_tid);
    match azos_ipc::fastcall::reply(handle, replier_tid, privileged, words) {
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
            azos_ipc::endpoint::label::enter(replier_tid, 0);
            azos_sched::wait::wake_fast_ipc_client_tid(
                caller_tid, handle);
            // The answer ends the call: the server gives back the caller's
            // priority (wave 11 PIFAST) — AFTER the wake. Returned before it,
            // a preemption in between leaves the reply deposited, the client
            // asleep and the server back at its own priority behind whatever
            // sits between them.
            if donee != azos_ipc::fastcall::NO_DONEE {
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
            // The server keeps its scope: a reply to an exchange that is gone
            // answers nothing, and must not be a way to leave the request it
            // is still working on.
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
    let (server_idx, server_tid) = azos_sched::current_task_slot().unwrap_or((usize::MAX, 0));
    let privileged = azos_sched::current_user_pt() == 0;
    label_answer(handle, server_tid);
    let (reply, next) = azos_ipc::fastcall::reply_then_accept(
        handle, server_tid, privileged, words, server_idx,
    );
    match reply {
        azos_ipc::FastIpcReply::Woke { caller_tid, donee, .. } => {
            // Out of the answered request, whatever the next accept finds.
            azos_ipc::endpoint::label::enter(server_tid, 0);
            // `donee` is set only when a next request was already taken (no
            // hand-off; returned after the wake); otherwise the client returns
            // it. See `fast_ipc_reply_then_accept`.
            fast_ipc_accept_into_waking(out, server_idx, server_tid, Some(next), Some((caller_tid, handle)), donee)
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
        // Process
        SYS_EXIT    => sys_exit(a0),
        SYS_GETPID  => sys_getpid(),
        SYS_YIELD   => sys_yield(),
        // Wave 13: threads (`crate::threads`).
        SYS_THREAD_CREATE => crate::threads::sys_thread_create(a0, a1, a2, a3, a4, regs),
        SYS_THREAD_EXIT   => crate::threads::sys_thread_exit(a0),
        SYS_FUTEX_WAIT    => crate::vdso_notify::sys_futex_wait(a0, a1, a2),
        SYS_FUTEX_WAKE    => crate::vdso_notify::sys_futex_wake(a0, a1),
        // The user shell: pipes, spawn with a request block, the
        // console wait, a stop request to a descendant.
        SYS_SPAWN_EX     => crate::ushell::sys_spawn_ex(a0, a1),
        SYS_ALERT    => crate::ushell::sys_task_kill(a0, a1, a2, a3),
        // D6: the operations on a handle (`crate::invoke`).
        SYS_INVOKE => crate::invoke::sys_invoke(a0, a1, a2, a3, a4, a5, out),
        // Wave 15 N11b: ABI v2 of the call (`crate::ipc_v2`). The v1 arms
        // above are untouched.
        SYS_IPC_CALL_V2 => crate::ipc_v2::sys_ipc_call_v2(a0, a1),
        SYS_IPC_ACCEPT_V2 => crate::ipc_v2::sys_ipc_accept_v2(a0),
        SYS_IPC_REPLY_V2 => crate::ipc_v2::sys_ipc_reply_v2(a0, a1),
        SYS_IPC_REPLY_DELEGATE => crate::ipc_v2::sys_ipc_reply_delegate(a0, a1),
        SYS_CAP_INFO => crate::caps::sys_cap_info(a0, a1, a2, a3, out),
        SYS_CAP_CLOSE => crate::caps::sys_cap_close(a0),
        SYS_CAP_DERIVE => crate::caps::sys_cap_derive(a0, a1, a2, a3),
        SYS_CAP_REVOKE => crate::caps::sys_cap_revoke(a0),
        // N6b: a task's dispatch class; RT and DL need a time warrant.
        SYS_SCHEDCTL => crate::schedctl::sys_schedctl(a0, a1, a2, a3, a4, a5),
        // D6: the foreign-ABI family (`crate::foreign`).
        SYS_FOREIGN_ENTRY => crate::foreign::sys_foreign_entry(a0, a1),
        SYS_FOREIGN_RESUME => crate::foreign::sys_foreign_resume(a0),
        SYS_FOREIGN_FORK => crate::foreign::sys_foreign_fork(sepc, user_sp, regs),
        SYS_SLEEP_UNTIL => crate::sleep::sys_sleep_until(a0, a1),

        // File I/O. A file is opened with `NODE_OPENAT` beneath a `Cap<Dir>`
        // and read through `Cap<File>`; the old numbered open, read and seek
        // calls are retired, and
        // seek has no typed form yet. The handlers `sys_read`/`sys_lseek`
        // stay — the typed arms and the host suites reach the descriptor seam
        // through them — they are simply not reachable from ring 3 by a number
        // any more. There is no `sys_open`: an open names a directory.

        // M02: Fast-path IPC — register-passing, ≤32 bytes, zero-copy.

        // SYS_IPC_FAST_CALL_EP: client side. a0 = a `Cap<Endpoint>`, a1..a4 =
        // data words (up to 4 × u64 = 32 bytes), a5 = a capability to move.
        // Blocks until the server replies. The raw-TID form (108) is retired
        // (wave 15 N5): the endpoint is the only address.
        SYS_IPC_FAST_CALL_EP =>
            fast_ipc_call_arm(a0, a1, a2, a3, a4, a5, out),

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

        // SYS_IPC_FAST_REPLY_ACCEPT: the reply above and the
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

        // ── F06: Driver server syscalls ─────────────────────────────────────
        // 302 (SYS_DRV_MMAP) is retired: ring 3 maps MMIO only
        // through DOMAIN_MMIO_MAP.


        // AZOS Phase 1 W5 — Cap<Port> typed port API.

        // Shared memory map, the multi-source port wait.
        SYS_MO_MAP => crate::memory::sys_mo_map(a0, a1, a2, a3, a4),
        // The multi-source wait, with a deadline.
        SYS_PORT_WAIT          => sys_port_wait(a0, a1, a2),

        // AZOS Phase 1 W5 batch 2 — Cap<Shm> typed shared-memory API.
        SYS_MO_CREATE   => sys_shm_create_typed(a0, a1),
        SYS_MO_UNMAP => crate::memory::sys_mo_unmap(a0, a1, a2),

        // AZOS Phase 1 W5 batch 3 — Cap<IoRing> typed io_ring API.
        SYS_RING_SETUP  => sys_ioring_create_typed(a0),
        SYS_RING_ENTER  => sys_ioring_submit_typed(a0),


        // Cap<DriverRegistry> (556-557). The kind is read from the cap, so
        // unlike SYS_DRIVER_REGISTER there is no kind argument to
        // disagree with the capability.
        // The read half of the capability model (558). Without it the typed
        // arms above this line had no possible ring-3 caller.




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
