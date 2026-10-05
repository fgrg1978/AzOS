// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pure decision logic for preemption control — no arch, no atomics, no state.
//!
//! # Why this module exists separately
//!
//! `preempt.rs` cannot be compiled for the developer host: it reads `tp` and
//! `sstatus` through inline asm. Everything *interesting* about preemption
//! control, though, is a decision — "does this tick switch or defer?", "does
//! dropping this guard fire a deferred reschedule?" — and a decision is pure
//! arithmetic over `depth`, `need_resched` and `irqs_enabled`, taken as
//! separate inputs at separate times: see `enable` and `should_fire` below,
//! and why they are two functions and not one.
//!
//! So the arithmetic lives here, host-testable, and `preempt.rs` is reduced to
//! the plumbing that reads the CSRs and moves the atomics. **`preempt.rs`
//! calls every function in this module.** A pure module the production path
//! does not use would prove nothing about the kernel; see `tests/host/sync-tests`
//! for the suite that drives these, and `preempt.rs` for the call sites.
//!
//! # Saturation, not wrapping
//!
//! Both `disable` and `enable` saturate at the ends of the range. A wrapping
//! `depth` is not a cosmetic bug in this kernel: `u32::MAX + 1 == 0` silently
//! *re-enables* preemption inside a critical section, and `0 - 1 == u32::MAX`
//! silently disables it forever. `overflow-checks = true` does not help — an
//! atomic RMW is not a checked arithmetic operation — so the saturation has to
//! be written, and tested, by hand.

/// One more level of nesting. Saturates: see the module docs.
#[inline(always)]
pub fn disable(depth: u32) -> u32 {
    depth.saturating_add(1)
}

/// What decrementing the depth alone determines.
///
/// Deliberately says nothing about firing. `enable` used to decide `fire`
/// itself, from a `need_resched`/`irqs_enabled` pair the *caller* had read
/// before calling it — which is precisely the lost-wakeup bug this shape
/// fixes. Between "caller reads need_resched" and "caller calls `enable`"
/// there is a window in which a same-hart tick can land, see the pre-decrement
/// depth, defer, and set `need_resched` — a debt the caller's already-stale
/// copy will never see. Splitting `enable` (depth only) from `should_fire`
/// (need_resched/irqs only) forces the caller to read those two *after* the
/// depth has committed to its new value, closing the window: by the time
/// `should_fire`'s inputs are read, a tick that lands either sees the new
/// depth (0, so it takes the ordinary `Switch` path itself) or landed before
/// the decrement and its `need_resched = true` is still there to be read.
/// See `PreemptGuard::drop` in `preempt.rs` for the call sequence, and
/// `tests/host/sync-tests` for the race pinned against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnableOutcome {
    /// An outer guard is still held. Preemption stays off; nothing to decide.
    StillDisabled,
    /// This was the outermost guard. The caller must now read
    /// `need_resched`/`irqs_enabled` — freshly, not from before this call —
    /// and pass them to `should_fire`.
    Enabled,
    /// `enable` was called at depth 0 — an unbalanced release. The depth is
    /// left at 0 rather than wrapping to `u32::MAX`.
    Underflow,
}

/// One fewer level of nesting. Pure arithmetic on `depth` alone — see the
/// `EnableOutcome` docs for why `need_resched`/`irqs_enabled` are not
/// parameters here.
#[inline(always)]
pub fn enable(depth: u32) -> (u32, EnableOutcome) {
    match depth {
        0 => (0, EnableOutcome::Underflow),
        1 => (0, EnableOutcome::Enabled),
        d => (d - 1, EnableOutcome::StillDisabled),
    }
}

/// Whether an outermost-guard drop (`enable` returned `Enabled`) should fire
/// its deferred reschedule right now.
///
/// Both inputs MUST be read after the depth has already committed to 0 — see
/// the `EnableOutcome` docs. This function itself doesn't enforce that (it
/// cannot: it has no access to when its arguments were read), which is why
/// `preempt.rs` reads them in the specific place it does, right after the
/// `fetch_update` that runs `enable`, and why that ordering carries a
/// `compiler_fence` rather than being left to chance.
///
///   * `need_resched` alone is not enough. A tick that arrived while
///     preemption was off is owed, but it may only be paid where entering the
///     scheduler is legal.
///   * `irqs_enabled` is that legality test. Every `do_schedule` caller and
///     every ISR in this kernel runs with `sstatus.SIE == 0`, so a guard
///     dropped inside the scheduler or inside an interrupt handler reports
///     `false` and cannot re-enter the scheduler.
///   * When this returns `false` but `need_resched` was true, the caller MUST
///     leave `need_resched` set. The debt survives to the next drop that
///     happens somewhere legal. Clearing it there would silently swallow the
///     tick — which is exactly the defect the deleted `PREEMPT_COUNT` stub
///     had.
#[inline(always)]
pub fn should_fire(need_resched: bool, irqs_enabled: bool) -> bool {
    need_resched && irqs_enabled
}

/// What a timer tick / reschedule IPI should do with the current task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickDispatch {
    /// Normal: run the scheduler.
    Switch,
    /// Preemption is disabled on this hart. Record the debt and return.
    Defer,
}

/// Involuntary preemption admission. `Defer` iff a critical section is open.
///
/// Note what this does *not* decide: the tick's bookkeeping (runtime
/// accounting, APS class credit, deadline replenish, the monotonic tick
/// counter) is not preemption and must run either way. `Defer` covers only
/// the context switch.
#[inline(always)]
pub fn tick_dispatch(depth: u32) -> TickDispatch {
    if depth > 0 { TickDispatch::Defer } else { TickDispatch::Switch }
}

/// What a *voluntary* scheduler entry (`task_yield`, `block_current`) should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoluntaryAdmission {
    /// No critical section open — the caller may switch.
    Proceed,
    /// A critical section is open. The caller must return WITHOUT switching,
    /// and without deferring either.
    ///
    /// Deferring is wrong here and the difference matters. A tick can be paid
    /// later because the tick wants *someone else* to run. A voluntary yield
    /// or block while holding a spinlock is a request to stop running the one
    /// task that can release the lock: honouring it converts a
    /// priority-dependent hang into a certain one. Keeping the holder on the
    /// hart is what makes progress.
    RefuseAtomic,
}

/// Voluntary-entry admission. `RefuseAtomic` iff a critical section is open.
#[inline(always)]
pub fn voluntary_admission(depth: u32) -> VoluntaryAdmission {
    if depth > 0 { VoluntaryAdmission::RefuseAtomic } else { VoluntaryAdmission::Proceed }
}
