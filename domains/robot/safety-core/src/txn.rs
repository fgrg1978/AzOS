// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! I-13 transactional control ticks (RFC-0029). `txn_try_rollback` is called
//! by the kernel's `handle_exception` on every synchronous exception, so it is
//! `#[inline]` across the crate boundary (`lto = false`).

use core::sync::atomic::Ordering;
// `TrapFrame` and the `TRAP_*` cause constants are RISC-V-specific (see
// `crates/core/arch-riscv64/src/trap.rs`) — aarch64 has its own exception-frame
// shape (`ESR_EL1`/`ELR_EL1`/GPR block, see `crates/core/arch-aarch64`'s vector
// table), not yet plumbed through `arch-api`. `txn_try_rollback`'s whole job
// is rewriting a RISC-V trap frame's saved PC/SP, so it and its
// `trap::TRAP_*`-reading helper stay RISC-V-only below; `txn_arm` and
// `txn_note_tick_complete` (called from `rt_motor.rs` on every ISA) touch
// neither type and are unaffected.
#[cfg(target_arch = "riscv64")]
use azos_arch::trap::{self, TrapFrame};

// ── I-13: transactional control ticks (RFC-0029) ─────────────────────────────
// A recoverable fault inside an *armed* control tick is rolled back — the
// trap handler restarts `rt_motor_task` at its entry (a known PC + a valid
// saved SP) after a motor safe-stop, instead of taking the fatal path that
// halts the kernel. Restarting at a function ENTRY (not mid-tick) is safe
// without hand-rolled setjmp/longjmp: the prologue rebuilds the frame and the
// task never returns. `is_recoverable` is a conservative whitelist — it does
// NOT include ecall or page-fault causes (those keep their existing handlers).
const MAX_TXN_HARTS: usize = 8;
struct TxnSlot {
    armed: core::sync::atomic::AtomicBool,
    sp:    core::sync::atomic::AtomicUsize,
    pc:    core::sync::atomic::AtomicUsize,
}
impl TxnSlot {
    const fn new() -> Self {
        Self {
            armed: core::sync::atomic::AtomicBool::new(false),
            sp:    core::sync::atomic::AtomicUsize::new(0),
            pc:    core::sync::atomic::AtomicUsize::new(0),
        }
    }
}
static TXN: [TxnSlot; MAX_TXN_HARTS] = [const { TxnSlot::new() }; MAX_TXN_HARTS];
/// Lifetime count of transactional rollbacks (observability).
#[cfg(target_arch = "riscv64")]
static TXN_ABORTS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Consecutive transactional restarts with no completed control tick in
/// between. A *deterministic* recoverable fault would otherwise restart the
/// control task forever — the task re-arms at its entry before the fault
/// recurs, so disarming on rollback does NOT break the loop. This counter does:
/// once it reaches `MAX_TXN_RESTARTS`, `txn_try_rollback` declines and the
/// fault falls through to the fatal path, surfacing the real bug instead of
/// silently looping. A completed tick clears it (`txn_note_tick_complete`), so
/// genuine one-off transients never accumulate toward the budget.
static TXN_RESTART_STREAK: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
/// Max consecutive restarts (no tick completed) before escalating to fatal.
#[cfg(target_arch = "riscv64")]
const MAX_TXN_RESTARTS: u32 = 8;

/// Arm the per-hart transactional checkpoint: a recoverable fault until the
/// next disarm restarts at `(sp, pc)`.
pub(crate) fn txn_arm(sp: usize, pc: usize) {
    if !azos_limits::CONTROL_TXN_TICKS {
        return;
    }
    let h = azos_arch::cpu::hart_id() as usize;
    if h < MAX_TXN_HARTS {
        TXN[h].sp.store(sp, Ordering::Relaxed);
        TXN[h].pc.store(pc, Ordering::Relaxed);
        TXN[h].armed.store(true, Ordering::Relaxed);
    }
}

/// Conservative whitelist of faults a transactional tick may roll back:
/// **misaligned load/store only** — a plausibly transient "bad external data
/// alignment in the control loop" (e.g. an unaligned field from a sensor
/// frame). Illegal-instruction is deliberately **excluded**: it is almost
/// always a genuine defect (corrupt code, a bad function pointer), not a
/// recoverable transient, so it must surface via the fatal path rather than be
/// silently rolled back (RFC-0029 kill criterion: "false rollbacks mask real
/// bugs"). Page faults (demand paging) and ecall keep their own handlers.
#[cfg(target_arch = "riscv64")]
fn txn_is_recoverable(cause: usize) -> bool {
    matches!(
        cause,
        trap::TRAP_LOAD_MISALIGNED | trap::TRAP_STORE_MISALIGNED
    )
}

/// Trap-handler hook: if a recoverable fault hit an armed tick on this hart,
/// safe-stop the motors and rewrite the trap frame to restart the control
/// task at its entry. Returns true if it handled (rolled back) the fault.
///
/// LOAD-BEARING PRECONDITION (RFC-0017 cert review): the restart resets SP to
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
///
/// aarch64: not compiled here at all — nothing in `crates/` calls it, only
/// `kernel/src/trap/exception.rs`'s RISC-V `handle_exception`. An aarch64 kernel
/// entry needs its own rollback hook against its own exception-frame type
/// before this can be called there; see this file's module-level `use`
/// comment for why `TrapFrame` itself doesn't exist on this ISA yet.
#[cfg(target_arch = "riscv64")]
#[inline]
pub fn txn_try_rollback(frame: &mut TrapFrame, cause: usize) -> bool {
    if !azos_limits::CONTROL_TXN_TICKS {
        return false; // const-eliminated when off → trap handler unchanged
    }
    if !txn_is_recoverable(cause) {
        return false;
    }
    let h = azos_arch::cpu::hart_id() as usize;
    if h >= MAX_TXN_HARTS || !TXN[h].armed.load(Ordering::Relaxed) {
        return false;
    }
    // Abort budget: a deterministic fault re-arms at entry and recurs, so the
    // disarm below cannot break the loop on its own. If we have restarted
    // MAX_TXN_RESTARTS times without a single completed tick, treat the fault
    // as a real (non-transient) bug and decline — the caller falls through to
    // the fatal path, surfacing it instead of looping forever.
    if TXN_RESTART_STREAK.load(Ordering::Relaxed) >= MAX_TXN_RESTARTS {
        return false;
    }
    TXN[h].armed.store(false, Ordering::Relaxed);
    TXN_RESTART_STREAK.fetch_add(1, Ordering::Relaxed);
    TXN_ABORTS.fetch_add(1, Ordering::Relaxed);
    // Publish a (0, 0) MotorCmd so the CHANNEL no longer holds whatever the
    // rolled-back task last asked for. This does NOT mean no half-applied
    // duty survives: `motor_cmd_publish` only updates the channel
    // `rt_motor_task` reads on its NEXT tick (≤1 ms) — a duty already
    // written to the PWM peripheral by an EARLIER, already-applied command
    // stays on the wire until that tick runs. "No half-applied command
    // survives" describes the channel, not the actuator.
    // (Channel is a SeqLock — re-entrant publish from trap context never
    // blocks; worst case a concurrent reader retries one snapshot.)
    azos_robot::motor_cmd_publish(0, 0);
    // Restart the control task at its entry with a CLEAN stack top (reset SP),
    // NOT the mid-function SP that was live at fault time. The entry prologue
    // then runs exactly once per restart, so the stack does not descend a
    // frame on every rollback (the bug a post-prologue capture introduced).
    frame.regs[2] = TXN[h].sp.load(Ordering::Relaxed) as _;
    frame.sepc    = TXN[h].pc.load(Ordering::Relaxed) as _;
    true
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
