// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Direct handoff (wave 15 N13): the ONE helper that switches from the
//! current task straight to a named peer without a pick. Nothing else in the
//! kernel switches directly.
//!
//! The scheduler side ([`DirectSwitch`]) lives in crates/core/sched
//! (`scheduler::SchedHandoff`, registered at boot); callers are IPC `call` /
//! `reply_recv` (N5, N11, through `scheduler::ipc_wake_then_block`) and, as a
//! measured experiment, futex wake (N9).
//!
//! Kconfig `IPC_DIRECT_HANDOFF`, **default n until it wins**: n makes
//! [`switch_to_direct`] a compile-time `Err(Disabled)` that inlines to
//! nothing, so the fast-call lane does not move. It is turned on only if it
//! beats N5's fast-call instruction count (precedent: a direct handoff cost
//! +52 instructions and saved none, reverted).
//!
//! # Preconditions (checked by the implementation, refusal = normal path)
//!
//! * The caller is the current task, in task context, preemption on, **no
//!   SpinLock held** (the endpoint or bucket lock is dropped first; the
//!   target's wake state was settled under it).
//! * `target` is blocked waiting for exactly this event (a server in
//!   `recv` on the endpoint, a caller in `reply` wait, a futex waiter) and
//!   was claimed by the caller under that lock, so no one else wakes it.
//! * `target` may run on this CPU (affinity) and is **not less urgent**
//!   than the caller (`waitgraph::PiAttr` of both, effective): a handoff
//!   never runs a lower-priority task ahead of a runnable more urgent one.
//! * The caller itself is about to block (call, reply_recv) or yield its
//!   remaining slice to the target (futex wake experiment).
//!
//! On `Ok(())` the call returns when the caller runs again. On `Err` the
//! caller wakes `target` the normal way and blocks/schedules as before;
//! every refusal is counted per reason for vsbench.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::waitgraph::TaskId;

/// Kconfig `IPC_DIRECT_HANDOFF`.
pub const ENABLED: bool = azos_limits::IPC_DIRECT_HANDOFF;

/// Who asks for the handoff (accounting and per-reason enable).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum HandoffReason {
    /// A client's `call` to a server blocked in `recv`.
    IpcCall = 1,
    /// A server's `reply_recv` to the caller blocked in reply wait.
    IpcReplyRecv = 2,
    /// Futex wake of one waiter (experiment, N9 x N13).
    FutexWake = 3,
}

/// Why a handoff did not happen; the caller takes the normal path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandoffRefused {
    /// Kconfig `IPC_DIRECT_HANDOFF` is n, or no implementation registered.
    Disabled,
    /// `target` is not blocked waiting for this event.
    PeerNotWaiting,
    /// `target` is less urgent than the caller.
    LowerPriority,
    /// `target` cannot run on this CPU (affinity, cluster).
    OtherCpu,
    /// Something more urgent than `target` is runnable here.
    Preempted,
}

/// The scheduler's switch. **Implemented by N13 in crates/core/sched.**
///
/// Takes the run-queue lock of this CPU, re-checks the preconditions under
/// it, marks the caller blocked (or runnable for `FutexWake`), makes
/// `target` current without a pick, accounts the switch to both SCs, and
/// switches. Cost goal: fewer instructions than wake + block + pick on the
/// fast-call lane (N5's number).
pub trait DirectSwitch: Sync {
    fn switch_to_direct(&self, target: TaskId, reason: HandoffReason) -> Result<(), HandoffRefused>;
}

/// Number of [`HandoffReason`] values (index = `reason as usize - 1`).
pub const REASONS: usize = 3;
/// Number of [`HandoffRefused`] values (index = [`HandoffRefused::index`]).
pub const REFUSALS: usize = 5;

impl HandoffRefused {
    /// Dense index for the per-reason counters.
    #[inline(always)]
    pub const fn index(self) -> usize {
        match self {
            HandoffRefused::Disabled => 0,
            HandoffRefused::PeerNotWaiting => 1,
            HandoffRefused::LowerPriority => 2,
            HandoffRefused::OtherCpu => 3,
            HandoffRefused::Preempted => 4,
        }
    }
}

/// The registered implementation. Written once, before [`READY`] is
/// published with `Release`; read only after an `Acquire` load saw it.
struct Slot(core::cell::UnsafeCell<Option<&'static dyn DirectSwitch>>);
// SAFETY: one write (in `register`, before `READY` is set), then reads only.
unsafe impl Sync for Slot {}
static IMP: Slot = Slot(core::cell::UnsafeCell::new(None));
static READY: AtomicBool = AtomicBool::new(false);

const Z: AtomicU32 = AtomicU32::new(0);
const ZROW: [AtomicU32; REFUSALS] = [Z; REFUSALS];
/// Handoffs taken, per reason.
static TAKEN: [AtomicU32; REASONS] = [Z; REASONS];
/// Refusals, per reason and per refusal (vsbench reads them through [`stats`]).
static REFUSED: [[AtomicU32; REFUSALS]; REASONS] = [ZROW; REASONS];

/// `(taken, refused[refusal])` for `reason`. Monotonic, Relaxed.
pub fn stats(reason: HandoffReason) -> (u32, [u32; REFUSALS]) {
    let r = reason as usize - 1;
    let mut out = [0u32; REFUSALS];
    for (o, c) in out.iter_mut().zip(REFUSED[r].iter()) {
        *o = c.load(Ordering::Relaxed);
    }
    (TAKEN[r].load(Ordering::Relaxed), out)
}

/// Install the scheduler's implementation once at boot. Task context.
/// With `IPC_DIRECT_HANDOFF` n this stores nothing (the implementation and
/// its vtable are then unreferenced and the linker drops them). A second
/// registration panics. `#[inline(always)]` so the n fold reaches the
/// caller and the fat pointer to the implementation is never built.
#[inline(always)]
pub fn register(imp: &'static dyn DirectSwitch) {
    if !ENABLED {
        return;
    }
    install(imp);
}

/// The body of [`register`], without the Kconfig gate (host tests reach the
/// counting path through it with the symbol n).
#[doc(hidden)]
pub fn install(imp: &'static dyn DirectSwitch) {
    assert!(!READY.load(Ordering::Acquire), "handoff: second DirectSwitch registration");
    // SAFETY: the only write; no reader looks before `READY` is published.
    unsafe { *IMP.0.get() = Some(imp) };
    READY.store(true, Ordering::Release);
}

/// Switch from the current task straight to `target` (contract in the
/// module doc). With `IPC_DIRECT_HANDOFF` n: `Err(Disabled)`, no code.
#[inline(always)]
pub fn switch_to_direct(target: TaskId, reason: HandoffReason) -> Result<(), HandoffRefused> {
    if !ENABLED {
        return Err(HandoffRefused::Disabled);
    }
    switch_slow(target, reason)
}

/// The registered implementation's switch, counted. `#[doc(hidden)] pub` so
/// the host tests can drive it with the symbol n.
#[doc(hidden)]
#[inline(never)]
pub fn switch_slow(target: TaskId, reason: HandoffReason) -> Result<(), HandoffRefused> {
    let r = reason as usize - 1;
    let res = if READY.load(Ordering::Acquire) {
        // SAFETY: `READY` (Acquire) orders this read after the one write.
        match unsafe { *IMP.0.get() } {
            Some(imp) => imp.switch_to_direct(target, reason),
            None => Err(HandoffRefused::Disabled),
        }
    } else {
        Err(HandoffRefused::Disabled)
    };
    match res {
        Ok(()) => {
            TAKEN[r].fetch_add(1, Ordering::Relaxed);
        }
        Err(e) => {
            REFUSED[r][e.index()].fetch_add(1, Ordering::Relaxed);
        }
    }
    res
}
