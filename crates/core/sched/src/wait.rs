// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! IO-wait and wake primitives (AQ0).
//!
//! Provides `task_block(reason)` to put the current task to sleep and
//! `wake_*()` functions to unblock tasks when their wait condition is met.

use crate::task::{WaitReason, MAX_TASKS};
use crate::smp::current_cpu_id;
use crate::scheduler;

/// Block the current task until `reason` is satisfied.
///
/// The task is removed from the ready queue and marked `Blocked`.
/// Another task is scheduled immediately. This function "returns"
/// when the task is woken up by a matching `wake_*()` call.
pub fn task_block(reason: WaitReason) {
    let cpu = current_cpu_id();
    scheduler::block_current(cpu, reason);
}

/// Why a [`task_block_outcome`] call came back.
///
/// `block_current` has always been able to return **without having slept**,
/// and there are now two distinct ways it does so. They mean opposite things
/// to a caller and this enum is what lets one tell them apart:
///
///   * [`BlockOutcome::Returned`] — the task either really slept and was
///     woken, or consumed a `wake_pending` stamp (K-C9) that a waker left in
///     the window before it committed to `Blocked`. Both are "the wait
///     happened"; a caller that re-tests its condition and finds it unmet is
///     seeing an ordinary spurious wake and should go round again.
///   * [`BlockOutcome::Refused`] — K-C29: preemption was disabled on this
///     hart, so `block_current` declined to park the task at all. **No time
///     passed and no event occurred.** A caller must not report its awaited
///     event on this path.
///
/// A caller with a condition it can re-test does not need this — it should
/// loop on the condition, which is correct under both outcomes. This exists
/// for the callers that have nothing to re-test, where the only honest answer
/// is to pass the refusal out to ring 3.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockOutcome {
    /// The block was performed (slept and woken, or a stamp was consumed).
    Returned,
    /// K-C29 refused to block: a critical section was open on this hart.
    Refused,
}

/// [`task_block`], but reporting whether the block actually happened.
///
/// # Why the check can be made here, before the call
///
/// The predicate is [`azos_sync::preempt_core::voluntary_admission`] over
/// this hart's depth — literally the decision `block_current` is about to make
/// a few instructions later. Reading it here gives the same answer it will
/// give there, because:
///
///   * The depth is **per-hart**, and the only way to raise it is to hold a
///     `PreemptGuard`. Between this read and `block_current`'s own check, this
///     task executes a call and a `current_cpu_id()` — it takes no guard.
///   * An interrupt landing in that window may take a guard, but an ISR
///     cannot return to us still holding one: the guard is an RAII value on
///     the ISR's own stack and is dropped before it returns.
///   * Another hart cannot touch this hart's slot at all.
///
/// So this is an exact predicate, not an estimate. If a future change ever
/// lets a guard outlive the code that took it, this stops being exact and the
/// outcome must instead be reported out of `block_current` itself.
///
/// The block is attempted **unconditionally**, refusal or not: `block_current`
/// owns the K-C29 audit bookkeeping (the `BLOCK_WHILE_ATOMIC` counter, the
/// last-offender record, the rate-limited console line). Short-circuiting here
/// would report the refusal to this one caller and hide it from the audit.
pub fn task_block_outcome(reason: WaitReason) -> BlockOutcome {
    let admission = azos_sync::preempt_core::voluntary_admission(
        azos_sync::preempt::depth(),
    );
    task_block(reason);
    match admission {
        azos_sync::preempt_core::VoluntaryAdmission::Proceed => BlockOutcome::Returned,
        azos_sync::preempt_core::VoluntaryAdmission::RefuseAtomic => BlockOutcome::Refused,
    }
}

/// [`task_block_outcome`] for a wait a task makes in a syscall of its own:
/// with a forced stop (`SYS_TASK_KILL` force) pending for the caller it does
/// not block at all and answers [`BlockOutcome::Refused`], which every caller
/// already turns into "withdraw and return". The syscall then returns, and
/// the task ends at its next syscall (its filter is empty) or tick.
///
/// **Why (plan item 7).** Every per-client release runs from the exit hook,
/// so a killed task that stays blocked releases nothing: its leases, ports,
/// shared memory, fast-IPC slots stay booked for the life of the board.
/// `task_stop` wakes a forced target out of any wait; without this check the
/// woken task blocks again (a `notify_wait` with no deadline, a port wait, a
/// fast-IPC accept) and nothing ever wakes it a second time.
///
/// One relaxed load when no forced stop is pending anywhere.
pub fn task_block_killable(reason: WaitReason) -> BlockOutcome {
    #[cfg(not(feature = "kill-reblock-canary"))]
    if current_task_killed() {
        return BlockOutcome::Refused;
    }
    task_block_outcome(reason)
}

/// [`task_block`] for a wait in a task's own syscall whose caller has no
/// use for the outcome (a bounded retry loop that re-tests its condition):
/// with a forced stop pending it does not block, so the loop spends its
/// remaining turns at once and returns. One relaxed load more than
/// [`task_block`] when no forced stop is pending anywhere.
pub fn task_block_unless_killed(reason: WaitReason) {
    #[cfg(not(feature = "kill-reblock-canary"))]
    if current_task_killed() {
        return;
    }
    task_block(reason);
}

/// Is a forced stop pending for the calling task? For a wait that does not
/// block through [`task_block_killable`] (a sleep that spins out a refused
/// block) and must end early instead.
pub fn current_task_killed() -> bool {
    scheduler::forced_stop_pending() && scheduler::current_forced_exit().is_some()
}

/// Wake all tasks blocked on a specific IRQ.
pub fn wake_by_irq(irq: u32) {
    wake_matching(|r| matches!(r, WaitReason::Irq(i) if *i == irq));
}

/// Wake all tasks blocked on a specific channel.
pub fn wake_by_channel(handle: u32) {
    wake_matching(|r| matches!(r, WaitReason::Channel(h) if *h == handle));
}

/// Wake all tasks blocked on a specific ring buffer.
pub fn wake_by_ring(ring_id: u32) {
    wake_matching(|r| matches!(r, WaitReason::Ring(id) if *id == ring_id));
}

/// Wake all tasks blocked on a specific port.
pub fn wake_by_port(port_id: u32) {
    wake_matching(|r| matches!(r, WaitReason::Port(id) if *id == port_id));
}

/// Wake all tasks whose timer deadline has expired.
///
/// With `sched-timer-heap` only the due sleepers are visited
/// (`scheduler::timer_sleepers`); without it, every slot is.
pub fn wake_expired_timers(now_ticks: u64) {
    #[cfg(feature = "sched-timer-heap")]
    scheduler::wake_expired_timers_heap(now_ticks);
    #[cfg(not(feature = "sched-timer-heap"))]
    wake_matching(|r| matches!(r, WaitReason::Timer(deadline) if now_ticks >= *deadline));
}

// ── K-C10: the wake decision, isolated as pure logic ────────────────────────

/// What a TID-directed wake must do with one task-pool slot.
///
/// This is the whole of K-C10's policy, split out from
/// `scheduler::wake_task_by_tid` so it can be exercised on the host — the
/// scheduler itself cannot be (static `TASKS`, RISC-V CSRs, assembly context
/// switch). See `tests/host/sched-wake-tests/`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WakeAction {
    /// Not the addressee. Keep scanning; touch nothing.
    Skip,
    /// Addressee found, but it has **not** committed to `Blocked` yet.
    /// Stamp `wake_pending` (K-C9) so its imminent `block_current()` consumes
    /// the wake instead of sleeping through it. Stop scanning.
    StampPending,
    /// Addressee found and `Blocked`, but on a reason the caller did not
    /// expect. Genuine mismatch: stop scanning, and leave `wake_pending`
    /// alone — this is not our task.
    Mismatch,
    /// Addressee found, `Blocked`, reason matches: transition Blocked → Ready
    /// and enqueue it. Stop scanning.
    Dispatch,
}

/// Decide what to do with one task-pool slot on behalf of a TID-directed wake.
///
/// `reason_matches` is the caller's `WaitReason` predicate evaluated against
/// the slot; it is only meaningful when `is_blocked` is true (a task that has
/// not blocked yet has `wait_reason == WaitReason::None`, which no targeted
/// predicate accepts — that is precisely why selection must be by TID).
///
/// # Truth table (the complete contract; `-` = input not consulted)
///
/// | addressee | blocked | reason matches | prev `wake_pending` | action        | `wake_pending` after |
/// |-----------|---------|----------------|---------------------|---------------|----------------------|
/// | no        | -       | -              | -                   | `Skip`        | unchanged            |
/// | yes       | no      | -              | false               | `StampPending`| **true**             |
/// | yes       | no      | -              | true                | `StampPending`| true (idempotent)    |
/// | yes       | yes     | no             | false               | `Mismatch`    | false (untouched)    |
/// | yes       | yes     | yes            | false               | `Dispatch`    | false                |
///
/// **`Blocked` with the wake stamp already set does not occur under
/// `saved = true`**, which is why those two rows are absent rather than
/// merely uninteresting. Since K-C19 this is enforced by construction, not by
/// call-site discipline: state and stamp share one atomic word
/// (`task::sched_word`), committing to `Blocked` is a CAS that requires the
/// stamp clear, and stamping is a CAS that requires `state != Blocked`.
/// `sched-wake-tests` asserts exactly that. **K-C24 made the state
/// representable** for an UNSAVED target (`wake_transition`'s `!saved` arm
/// stamps a committed-but-still-executing task); a stamp that then survives
/// the switch-away sweep parks as `Blocked + stamp + saved`, and the K-C25
/// reaper (`sched_word::reap_orphaned_stamp`, driven from the timer tick) is
/// that state's designated consumer — see the measured wedge documented
/// there.
///
/// Two rows deserve comment:
///
/// * **`Mismatch` never stamps.** Stamping there would make a task blocked on
///   something unrelated (a `Timer`, say) skip its *next* block. Between
///   becoming wake-able and calling `task_block()`, our addressees run a
///   straight-line stretch of their own syscall: they can be preempted to
///   `Ready`, but cannot become `Blocked` on a different reason. So
///   `Blocked` + non-matching reason means the TID no longer designates the
///   task we mean (exit + TID reuse, stale slot index, confused replier).
///   Same rule, same reasoning, as `scheduler::wq_wake_by_tid`.
/// * **`StampPending` ignores the previous value.** The stamp is an
///   idempotent bit (a CAS that ORs it in), not a counter: two wakes landing
///   in the window skip one block, not two. That is correct for every caller
///   here, because each has exactly one thing to wait for. If K-C10 ever has
///   to count wakes, this is the function that changes first.
///
/// `Mismatch` does not touch the word at all, so a stamp left by an earlier
/// wake survives it — deliberately: clearing it would re-open the lost-wakeup
/// window this finding closes. (`Dispatch` cannot meet a stamp: Blocked with
/// the stamp set is unrepresentable, per the invariant above.)
#[inline]
pub const fn wake_action(is_addressee: bool, is_blocked: bool, reason_matches: bool) -> WakeAction {
    if !is_addressee { return WakeAction::Skip; }
    if !is_blocked { return WakeAction::StampPending; }
    if !reason_matches { return WakeAction::Mismatch; }
    WakeAction::Dispatch
}

// ── K-C10: targeted wakes go through scheduler::wake_task_by_tid ────────────
//
// The TID-directed wakes below each address ONE task that is known by TID at
// the call site. Routing them through `wake_matching` (i.e. `try_wake_task`) lost the
// wake whenever the addressee had made itself wake-able but had not yet
// reached `task_block()` — a real SMP window, because the waker runs on
// another hart. `scheduler::wake_task_by_tid` selects by TID, so it can stamp
// `wake_pending` (K-C9) in that window and `block_current()` consumes it.
//
// Do NOT "unify" the broadcast wakes above into this: they have no addressee
// TID, and a not-yet-blocked task has `wait_reason == None`, so a sweep-based
// waker cannot tell the addressee from any other task about to sleep. See the
// `wake_task_by_tid` doc comment for the full argument.

/// Wake the server task blocked waiting for a fast IPC call (by server TID).
///
/// K-C10: converted to the TID-directed path. `WaitReason::FastIpcServer(t)`
/// carries the server's own TID, so TID and predicate agree by construction.
///
/// Fast IPC only (`SYS_IPC_FAST_CALL`). No lease path calls it: a lessor
/// waits in `lease_wait_return` on the WaitQueue and is woken by
/// `wq_wake_by_tid`, and a lessee waits on `LeaseAccept` and is woken by
/// [`wake_lease_acceptor`]. A lease wake through here would dispatch a task
/// blocked as a fast-IPC server on the same TID.
pub fn wake_fast_ipc_server(server_tid: u32) {
    // IPC hand-off: the caller blocks on the reply right after this.
    scheduler::wake_task_by_tid_ipc(
        server_tid,
        &|r| matches!(r, WaitReason::FastIpcServer(tid) if *tid == server_tid),
    );
}

/// Wake a lessee blocked in `SYS_IPC_LEASE_ACCEPT` on a lease from `lessor`
/// (by lessee TID).
///
/// Called after a successful grant (`lease_grant_as`) and, when a lessor
/// exits, for every accept registered as waiting on it (`lease_release_all`,
/// which marks the registration first, so the woken lessee's next poll ends
/// its wait instead of blocking again). The predicate accepts
/// `WaitReason::LeaseAccept(lessee, lessor)` and nothing else, so:
///
///   * a lessee blocked accepting from `lessor` is dispatched;
///   * a task with the same TID blocked on `FastIpcServer(lessee)` (a fast-IPC
///     server) or on an accept naming another lessor is a `Mismatch`: left
///     asleep, not stamped. Before this function the grant woke lessees
///     through `wake_fast_ipc_server`, which dispatched the former;
///   * a lessee that has not blocked yet is stamped `wake_pending`
///     ([`wake_action`] consults no predicate for an unblocked addressee), so
///     a grant landing between the accept's poll and its `task_block` is
///     consumed by that block instead of being lost.
///
/// `LeaseAccept`'s first field is the blocking task's own TID, which is the
/// selector invariant `scheduler::wake_task_by_tid` depends on; the lessor is
/// a cross-check, as the handle is in [`wake_fast_ipc_client_tid`].
pub fn wake_lease_acceptor(lessee: u32, lessor: u32) {
    scheduler::wake_task_by_tid(
        lessee,
        &|r| matches!(r, WaitReason::LeaseAccept(t, l) if *t == lessee && *l == lessor),
    );
}

/// Wake the client task blocked waiting for a fast IPC reply, addressed by
/// the client's TID (K-C10 — preferred over [`wake_fast_ipc_client`]).
///
/// `fast_ipc_reply()` returns the `caller_tid` that owns the exchange, so the
/// addressee is known at the call site and this can close the window where the
/// client has reserved its slot and woken the server but has not yet executed
/// `task_block(WaitReason::FastIpcClient(handle))`.
///
/// The predicate matches on the generation-tagged `handle` (client and server
/// handles for one exchange are the same value — the generation only advances
/// on free): if the client is already blocked it must be blocked on *this*
/// exchange, and a mismatch means the TID no longer designates that client
/// (exit + TID reuse, or a stale handle) — in which case `wake_task_by_tid`
/// deliberately leaves the wake stamp untouched.
pub fn wake_fast_ipc_client_tid(caller_tid: u32, handle: u64) {
    // IPC hand-off: the replying server goes back to accept.
    scheduler::wake_task_by_tid_ipc(
        caller_tid,
        &|r| matches!(r, WaitReason::FastIpcClient(h) if *h == handle),
    );
}

/// Wake one registered waiter of an event port, addressed by its TID
/// (RFC-0040 gap 1). `crates/core/ipc/src/port.rs` wakes through this, not through
/// the broadcast [`wake_by_port`].
///
/// `SYS_PORT_WAIT` registers the task as a waiter of the port's packed
/// `(index, generation)` reference in the same `PORTS` hold as its empty poll
/// (`port::port_wait_begin`), then blocks on `WaitReason::Port(port_ref)`.
/// Queueing an event on the port, or destroying or releasing it, detaches the
/// registered waiters under `PORTS` and calls this for each after releasing
/// it. The addressee is known, so a waiter that registered but has not
/// committed to `Blocked` yet is stamped (K-C9) and its block consumes the
/// stamp: the lost wakeup a sweep cannot close (see [`wake_action`]).
///
/// The predicate matches the exact reference: a task with this TID blocked on
/// another port, or on another incarnation of the same index, is a
/// `Mismatch`, left asleep and unstamped.
///
/// IRQ context: `irq_bind::irq_dispatch` reaches this from the PLIC handler
/// (through `port_queue_event_bound`). `wake_task_by_tid` is a scan of
/// `TASK_VALID`/`tid`, CAS transitions on the task's state word and the
/// SIE-masked `cpu_enqueue_locked`: the primitives `try_wake_task` already
/// runs from that handler for [`wake_by_irq`], plus the stamp CAS.
pub fn wake_port_waiter(tid: u32, port_ref: u32) {
    scheduler::wake_task_by_tid(
        tid,
        &|r| matches!(r, WaitReason::Port(p) if *p == port_ref),
    );
}

/// Wake one registered waiter of an event port that blocks with a deadline,
/// addressed by its TID (wave 11, PORTWAIT).
///
/// A port wait with a deadline (`SYS_PORT_WAIT_UNTIL_TYPED`, 604), or on a
/// port with an armed timer source, blocks on `WaitReason::Timer(until)` so
/// the timer interrupt ends its sleep; an event on the port wakes it here. The
/// shape of `vdso_notify`'s timed notify wake: TID-directed, so a waiter that
/// registered but has not blocked yet is stamped (K-C9) and its block returns
/// at once. The predicate matches any `Timer` reason: the addressee's port
/// registration is what names the wait, and a task blocks in one syscall at a
/// time. A wake that lands after the waiter deregistered and entered another
/// timed sleep is a spurious wake there, which every `Timer` sleeper re-tests
/// against the clock.
pub fn wake_port_timed_waiter(tid: u32) {
    scheduler::wake_task_by_tid(
        tid,
        &|r| matches!(r, WaitReason::Timer(_)),
    );
}

/// Wake the owner of a wake-task IRQ binding registered in
/// `SYS_DRV_IRQ_WAIT` (`irq_bind::irq_wait_begin`), by TID: the delivery's
/// wake (`irq_bind::irq_dispatch`, IRQ context). Same shape and same reason
/// as [`wake_port_waiter`]: the owner registered before it blocked, so a
/// delivery landing between the registration and its commit to `Blocked`
/// stamps it (K-C9) and its block consumes the stamp, where the
/// [`wake_by_irq`] sweep sees a `Running` task and wakes nothing. The
/// predicate is the exact line; a task with this TID blocked on anything
/// else is a `Mismatch`, left asleep and unstamped.
pub fn wake_irq_waiter(tid: u32, irq: u32) {
    scheduler::wake_task_by_tid(
        tid,
        &|r| matches!(r, WaitReason::Irq(i) if *i == irq),
    );
}

/// Wake the client task blocked waiting for a fast IPC reply (by exchange
/// handle, sweep-based).
///
/// K-C10: **superseded by [`wake_fast_ipc_client_tid`]** for the reply path;
/// still the right shape for `fast_ipc_release_all`'s orphan wake, whose
/// addressee is unknown (the dying server never learns the client's TID).
/// The handle match means a re-let seat's new client can never be woken by a
/// dead exchange's orphan sweep. A sweep still cannot address a client that
/// has not reached `task_block()` yet — acceptable for the orphan path,
/// whose client has been blocked for the whole exchange by construction.
pub fn wake_fast_ipc_client(handle: u64) {
    wake_matching(|r| matches!(r, WaitReason::FastIpcClient(h) if *h == handle));
}

/// Internal: scan all tasks and wake those matching the predicate.
fn wake_matching(pred: impl Fn(&WaitReason) -> bool) {
    for i in 0..MAX_TASKS {
        scheduler::try_wake_task(i, &pred);
    }
}
