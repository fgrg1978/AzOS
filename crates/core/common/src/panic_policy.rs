// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel panic policy by profile (RFC-0052 §5): which panics may be
//! *contained* — the culprit task is parked and the machine keeps running —
//! and which must take the reset path.
//!
//! # Two policies, chosen at build time
//!
//! * [`Policy::Reset`] — every panic takes the reset path: actuators to the
//!   safe state (lock-free), the global panic flag, the crash record, then halt
//!   or reboot. The ground-robot behaviour, and the only one before RT7.
//! * [`Policy::Contain`] — "warn, don't kill" (flying profile, armed ESCs): a
//!   kernel panic in a non-safety kernel task whose context passes the
//!   containment predicate parks that task only. The global panic flag is not
//!   set, the actuator stop does not run, the other harts keep going, and the
//!   flight controller reacts to the containment with its own `Land` then
//!   `Disarm` (`azos_safety_core::flight_ctrl`). Anything that fails the
//!   predicate takes the reset path, exactly as under `Reset`.
//!
//! The kernel reads the choice from Kconfig `PANIC_POLICY_CONTAIN`; this
//! module only decides, so the decision is a pure function of captured state
//! and `tests/host/panic-policy-tests` pins it.
//!
//! # The containment predicate
//!
//! Evaluated at the top of the panic handler, before it masks interrupts
//! (masking destroys check 3's evidence). Contain iff ALL hold:
//!
//! 1. not in an interrupt handler (`isr_depth == 0`);
//! 2. no `SpinLock` is held by this hart (`preempt::depth() == 0`: every
//!    guard raises the depth), so abandoning the task leaks no lock;
//! 3. interrupts were enabled on entry (not inside an IRQ-save section or a
//!    trap handler that runs with them masked);
//! 4. the culprit holds no `PiMutex` (`pi_mutex::held_by`);
//! 5. this is not a second panic on this hart (a panic while handling one);
//! 6. no hart has taken the reset path already (the global flag is clear);
//! 7. the culprit is a kernel task that is neither an idle task, nor a ring-3
//!    task inside a system call, nor a registered safety task (the control
//!    loops: when one of them faults there is nothing left in the kernel to
//!    keep flying, and the external ESC/FC failsafe is the backstop — the
//!    reset path stops feeding the watchdog).
//!
//! The order of the checks is the order of [`Reason`]: the first failing
//! check names the reason the reset path prints.

use core::sync::atomic::{AtomicU32, Ordering};

/// The build-time panic policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Every panic takes the reset path (ground profile; the default).
    Reset,
    /// Contain what the predicate allows; reset the rest (flying profile).
    Contain,
}

/// What kind of task was running when the panic hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Culprit {
    /// No task is current on this hart (boot code, before the scheduler).
    NoTask,
    /// A per-hart idle task: parking it would leave the hart nothing to run.
    Idle,
    /// A ring-3 task, inside the kernel on its behalf (a system call).
    User,
    /// A registered safety task (rt-motor, flight-ctrl).
    Safety,
    /// Any other kernel task: the only containable kind.
    Kernel,
}

/// Everything the predicate reads, captured before interrupts are masked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PanicContext {
    /// This hart's interrupt-handler depth (`isr_depth`).
    pub in_isr: bool,
    /// This hart's preemption-disable depth: one per held `SpinLock` guard.
    pub preempt_depth: u32,
    /// Interrupts were enabled when the panic handler was entered.
    pub irqs_were_enabled: bool,
    /// `PiMutex` acquisitions the culprit has not released.
    pub pi_held: u32,
    /// This hart was already inside the panic handler.
    pub second_panic: bool,
    /// Some hart already took the reset path (the global panic flag).
    pub already_panicked: bool,
    /// The running task.
    pub culprit: Culprit,
}

/// Why a panic takes the reset path. `as_str` is what the panic handler
/// prints (`[PANIC] policy=... verdict=reset reason=<as_str>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The build's policy is `Reset`.
    PolicyReset,
    /// A panic while this hart was handling one.
    SecondPanic,
    /// Another hart already took the reset path.
    AlreadyPanicked,
    /// Check 1.
    InIsr,
    /// Check 2.
    SpinLockHeld,
    /// Check 3.
    IrqsOff,
    /// Check 4.
    PiMutexHeld,
    /// Check 7: no task.
    NoTask,
    /// Check 7: an idle task.
    IdleTask,
    /// Check 7: a ring-3 task in a system call.
    UserTask,
    /// Check 7: a safety task (the control loop itself).
    SafetyTask,
}

impl Reason {
    /// The token the panic handler prints; the gate rows anchor on it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Reason::PolicyReset => "policy-reset",
            Reason::SecondPanic => "second-panic",
            Reason::AlreadyPanicked => "already-panicked",
            Reason::InIsr => "in-isr",
            Reason::SpinLockHeld => "spinlock-held",
            Reason::IrqsOff => "irqs-off",
            Reason::PiMutexHeld => "pimutex-held",
            Reason::NoTask => "no-task",
            Reason::IdleTask => "idle-task",
            Reason::UserTask => "user-task",
            Reason::SafetyTask => "safety-task",
        }
    }
}

/// The policy's verdict for one panic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Park the culprit; the machine keeps running.
    Contain,
    /// Take the reset path, for this reason.
    Reset(Reason),
}

/// The decision. Pure: the same context always gives the same verdict.
/// Under `Reset` the verdict is the reset path whatever the context; under
/// `Contain` the first failing check names the reason.
pub const fn decide(policy: Policy, ctx: &PanicContext) -> Verdict {
    if let Policy::Reset = policy {
        return Verdict::Reset(Reason::PolicyReset);
    }
    if ctx.second_panic {
        return Verdict::Reset(Reason::SecondPanic);
    }
    if ctx.already_panicked {
        return Verdict::Reset(Reason::AlreadyPanicked);
    }
    if ctx.in_isr {
        return Verdict::Reset(Reason::InIsr);
    }
    if ctx.preempt_depth != 0 {
        return Verdict::Reset(Reason::SpinLockHeld);
    }
    if !ctx.irqs_were_enabled {
        return Verdict::Reset(Reason::IrqsOff);
    }
    if ctx.pi_held != 0 {
        return Verdict::Reset(Reason::PiMutexHeld);
    }
    match ctx.culprit {
        Culprit::NoTask => Verdict::Reset(Reason::NoTask),
        Culprit::Idle => Verdict::Reset(Reason::IdleTask),
        Culprit::User => Verdict::Reset(Reason::UserTask),
        Culprit::Safety => Verdict::Reset(Reason::SafetyTask),
        Culprit::Kernel => Verdict::Contain,
    }
}

/// The exit status a contained task's parent sees: 128 + SIGABRT (6), the
/// same 128+signal convention ring-3 faults use.
pub const CONTAINED_EXIT_STATUS: i32 = 128 + 6;

// ── Safety-task registry ────────────────────────────────────────────────────

/// Capacity of the safety-task registry. Two are registered today
/// (rt-motor and flight-ctrl); a full registry refuses the next one, and
/// [`register_safety_task`] says so.
pub const MAX_SAFETY_TASKS: usize = 8;

/// TIDs of the safety tasks; 0 = empty slot (TID 0 is "no task").
static SAFETY_TIDS: [AtomicU32; MAX_SAFETY_TASKS] = [const { AtomicU32::new(0) }; MAX_SAFETY_TASKS];

/// Register `tid` as a safety task: a panic in it is never contained.
/// Returns false if `tid` is 0 or the registry is full.
pub fn register_safety_task(tid: u32) -> bool {
    if tid == 0 {
        return false;
    }
    for slot in SAFETY_TIDS.iter() {
        if slot.load(Ordering::Acquire) == tid {
            return true;
        }
        if slot.compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return true;
        }
    }
    false
}

/// Is `tid` a registered safety task?
pub fn is_safety_task(tid: u32) -> bool {
    tid != 0 && SAFETY_TIDS.iter().any(|s| s.load(Ordering::Acquire) == tid)
}

// ── Isolation record (the scoped quarantine) ────────────────────────────────

/// Panics contained since boot. Counted separately from the crash counter
/// (`wdt::crash_counter_*`, boot-loop detection), which only the reset path
/// raises.
static CONTAINED: AtomicU32 = AtomicU32::new(0);
/// TID of the last task parked by a contained panic (0 = none yet).
static LAST_CONTAINED_TID: AtomicU32 = AtomicU32::new(0);

/// Record one contained panic of `tid`; returns the new count. Published
/// before the culprit is parked, so a reader that sees the new count may
/// still see the culprit for a moment, never the other way round.
pub fn note_contained(tid: u32) -> u32 {
    LAST_CONTAINED_TID.store(tid, Ordering::Release);
    CONTAINED.fetch_add(1, Ordering::AcqRel).saturating_add(1)
}

/// Panics contained since boot. The flight controller polls it every tick
/// and starts its `Land` → `Disarm` sequence when it grows.
#[inline]
pub fn contained_count() -> u32 {
    CONTAINED.load(Ordering::Acquire)
}

/// TID of the last task parked by a contained panic (0 = none yet).
#[inline]
pub fn last_contained_tid() -> u32 {
    LAST_CONTAINED_TID.load(Ordering::Acquire)
}
