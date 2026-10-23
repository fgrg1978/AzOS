// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! I-13 transactional control ticks. `txn_try_rollback` is called by an
//! ISA's trap entry on the fault class it decodes as recoverable (riscv64's
//! `arch_exception`, aarch64's `arch_page_fault`), so it is `#[inline]` across
//! the crate boundary (`lto = false`). The decision itself is `txn_rule.rs`.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

pub use crate::txn_rule::MAX_TXN_RESTARTS;
use crate::txn_rule::{may_roll_back, Fault};

// ── I-13: transactional control ticks ─────────────────────────────
// A recoverable fault inside an *armed* control tick is rolled back — the
// trap handler restarts `rt_motor_task` at its entry (a known PC + a valid
// saved SP) after a motor safe-stop, instead of taking the fatal path that
// halts the kernel. Restarting at a function ENTRY (not mid-tick) is safe
// without hand-rolled setjmp/longjmp: the prologue rebuilds the frame and the
// task never returns. Which faults are recoverable is the ISA's decode, in
// its trap entry (`kernel/src/entry/<isa>/trap.rs`): a conservative whitelist
// that does NOT include ecall or page faults (those keep their handlers):
// riscv64's misaligned load/store, aarch64's EL1 Alignment fault (a data
// abort, decoded ahead of the page-fault policy). x86_64 has none to take:
// ring 0 never raises #AC.
//
// The checkpoint belongs to the task that armed it, not to a CPU: a CPU runs
// other tasks while the control task waits for its next tick, and a fault of
// any of them must not be restarted on the control task's stack.

/// The armed task (0: none), and where it restarts.
static ARMED_TID: AtomicU32 = AtomicU32::new(0);
static TXN_SP: AtomicUsize = AtomicUsize::new(0);
static TXN_PC: AtomicUsize = AtomicUsize::new(0);
/// Lifetime count of transactional rollbacks (observability).
static TXN_ABORTS: AtomicU32 = AtomicU32::new(0);
/// A rollback happened and its restart has not reported it yet: set in trap
/// context, taken by the restarted task's `txn_arm`, which writes the record
/// (the trap writes none: it runs on any CPU, with the logger's locks in
/// whatever state the fault left them).
static TXN_RESTART_PENDING: AtomicBool = AtomicBool::new(false);
/// Restarts the restarted task reported, and how many of those records the
/// flight recorder admitted (none while it is inactive: no volume).
static TXN_REPORTED: AtomicU32 = AtomicU32::new(0);
static TXN_RECORDED: AtomicU32 = AtomicU32::new(0);

/// Consecutive transactional restarts with no completed control tick in
/// between. A *deterministic* recoverable fault would otherwise restart the
/// control task forever — the task re-arms at its entry before the fault
/// recurs, so disarming on rollback does NOT break the loop. This counter does:
/// once it reaches `MAX_TXN_RESTARTS`, `txn_try_rollback` declines and the
/// fault falls through to the fatal path, surfacing the real bug instead of
/// silently looping. A completed tick clears it (`txn_note_tick_complete`), so
/// genuine one-off transients never accumulate toward the budget.
static TXN_RESTART_STREAK: AtomicU32 = AtomicU32::new(0);

/// Arm the calling task's transactional checkpoint: a recoverable fault of
/// this task until the next rollback restarts it at `(sp, pc)`. When this
/// entry is such a restart, report it first: a console line and a
/// `SAFETY_TXN_ROLLBACK` record (task context, no lock held).
pub(crate) fn txn_arm(sp: usize, pc: usize) {
    if !azos_limits::CONTROL_TXN_TICKS {
        return;
    }
    if TXN_RESTART_PENDING.swap(false, Ordering::Acquire) {
        let aborts = TXN_ABORTS.load(Ordering::Relaxed);
        azos_drv_sys::kwarn!(
            "[TXN] control task restarted at its entry after a rolled-back fault ({} so far)", aborts);
        let admitted = azos_actuation::logger::log_safety_violation_admitted(
            azos_actuation::logger::SAFETY_TXN_ROLLBACK, 0, aborts);
        TXN_REPORTED.fetch_add(1, Ordering::Relaxed);
        if admitted {
            TXN_RECORDED.fetch_add(1, Ordering::Release);
        }
    }
    TXN_SP.store(sp, Ordering::Relaxed);
    TXN_PC.store(pc, Ordering::Relaxed);
    // After the restart point: a fault that sees the task armed sees where.
    ARMED_TID.store(azos_sched::current_task_tid(), Ordering::Release);
}

/// What I-13 did so far: `(rollbacks, restarts reported, records admitted)`.
pub fn txn_counts() -> (u32, u32, u32) {
    (TXN_ABORTS.load(Ordering::Acquire), TXN_REPORTED.load(Ordering::Acquire),
     TXN_RECORDED.load(Ordering::Acquire))
}

/// Trap-handler hook: `recoverable` is the ISA's decode of the exception (a
/// whitelisted fault, taken in kernel mode). If it hit the armed task, and
/// the restart budget lasts, safe-stop the motors, disarm, and return the
/// `(sp, pc)` the caller writes into the trap frame to restart the control
/// task at its entry. `None`: not ours, the caller's policy applies.
///
/// LOAD-BEARING PRECONDITION (certification review): the restart resets SP to
/// the stack top and re-enters at the task entry, so **the abandoned stack's
/// destructors never run** — any RAII guard / blocking lock held at fault time
/// leaks. The control tick *does* hold SpinLocks (`motor_pid::TICK_STATE`,
/// `PID_CONTROLLERS`) across its computation, so a whitelisted fault taken
/// inside such a region would deadlock the next acquire. This is safe **only**
/// because the whitelist is misaligned-load/store-only AND the tick body
/// touches exclusively aligned, typed data (no raw unaligned access) — so no
/// whitelisted fault is reachable inside a locked region. Broadening the
/// whitelist (illegal-instr, page faults) OR adding a raw unaligned access to
/// the tick re-opens this; both require re-auditing the lock discipline here.
#[inline]
pub fn txn_try_rollback(recoverable: bool) -> Option<(usize, usize)> {
    if !azos_limits::CONTROL_TXN_TICKS || !recoverable {
        return None; // const-eliminated when off → trap handler unchanged
    }
    let fault = Fault {
        recoverable,
        armed_tid: ARMED_TID.load(Ordering::Acquire),
        current_tid: azos_sched::current_task_tid(),
        streak: TXN_RESTART_STREAK.load(Ordering::Relaxed),
    };
    if !may_roll_back(fault) {
        return None;
    }
    ARMED_TID.store(0, Ordering::Relaxed);
    TXN_RESTART_STREAK.fetch_add(1, Ordering::Relaxed);
    TXN_ABORTS.fetch_add(1, Ordering::Release);
    TXN_RESTART_PENDING.store(true, Ordering::Release);
    // Request (0, 0) so the command `rt_motor_task` reads no longer holds
    // whatever the rolled-back task last asked for. This does NOT mean no
    // half-applied duty survives: the stop takes effect on rt_motor's NEXT
    // tick (≤1 ms) — a duty already written to the PWM peripheral by an
    // EARLIER, already-applied command stays on the wire until that tick
    // runs. "No half-applied command survives" describes the command, not
    // the actuator.
    // The stop latch, never a publish: this runs in trap context on any CPU,
    // and the channel (a `Log` of one slot) has one writer handle.
    azos_robot::motor_cmd_zero();
    // Restart the control task at its entry with a CLEAN stack top (reset SP),
    // NOT the mid-function SP that was live at fault time. The entry prologue
    // then runs exactly once per restart, so the stack does not descend a
    // frame on every rollback (the bug a post-prologue capture introduced).
    Some((TXN_SP.load(Ordering::Relaxed), TXN_PC.load(Ordering::Relaxed)))
}

/// Clear the transactional restart streak — called at the end of every
/// completed control tick. A completed tick proves forward progress, so the
/// abort budget (`MAX_TXN_RESTARTS`) only ever counts restarts that made *no*
/// progress (a deterministic fault), never lifetime one-off transients.
#[inline]
pub(crate) fn txn_note_tick_complete() {
    if !azos_limits::CONTROL_TXN_TICKS {
        return;
    }
    // Read-mostly: the no-fault steady state has streak == 0, so the common
    // path is a single relaxed *load* with no store — the hot tick is left
    // effectively unchanged (no cache-line dirtying). Only a tick that follows
    // a rollback writes.
    if TXN_RESTART_STREAK.load(Ordering::Relaxed) != 0 {
        TXN_RESTART_STREAK.store(0, Ordering::Relaxed);
    }
}

/// ktest only (`kernel/src/entry/aarch64/ext/txn_align.rs`): the fault the
/// control task takes on its next iteration, at the point of its loop that
/// holds no lock (the precondition `txn_try_rollback` documents).
#[cfg(feature = "ktest")]
static INJECT: azos_sync::SpinLock<Option<fn()>> = azos_sync::SpinLock::new(None);
#[cfg(feature = "ktest")]
static INJECT_ARMED: AtomicBool = AtomicBool::new(false);

/// ktest only: make the control task call `fault` once, on its next iteration.
#[cfg(feature = "ktest")]
pub fn txn_inject_once(fault: fn()) {
    *INJECT.lock() = Some(fault);
    INJECT_ARMED.store(true, Ordering::Release);
}

/// ktest only: the control task's side of [`txn_inject_once`]. The lock is
/// released before the call: the fault must not be taken inside a locked
/// region.
#[cfg(feature = "ktest")]
pub(crate) fn txn_take_injected() {
    if INJECT_ARMED.swap(false, Ordering::Acquire) {
        let fault = INJECT.lock().take();
        if let Some(fault) = fault {
            fault();
        }
    }
}
