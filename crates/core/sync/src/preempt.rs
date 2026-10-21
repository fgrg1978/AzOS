// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-hart preemption control (K-C29 step 1).
//!
//! # What this is for
//!
//! `SpinLock::lock()` used not to inhibit preemption. The timer tick could
//! evict a lock holder, and a higher-priority task on the same hart would then
//! spin on that lock forever, because strict-priority dispatch never picks the
//! holder again. That is K-C29, and this module is the mechanism half of the
//! fix: a per-hart nesting counter that the scheduler consults before
//! switching.
//!
//! **This used to end "and it is the cause of K-C26". That claim is
//! withdrawn** — it was inference, and the experiment that tests it directly
//! says otherwise. On 2026-09-08, 20 runs of the `userspace: IPC` scenario
//! with `depth()` forced to return 0 — the counter still maintained, nothing
//! consulting it, which is precisely the pre-K-C29 scheduler behaviour — did
//! not wedge once, all 20 completing the full 1600-exchange phase A. If
//! K-C29 were what keeps K-C26 away, disabling it should have brought K-C26
//! back; it did not.
//!
//! That does not make K-C29 imaginary: the priority inversion it describes is
//! real, reachable by inspection, and the fix is cheap. It makes the *causal
//! link to K-C26* unsupported. K-C27 (yield-polling daemons fixed at the
//! workload) and K-C28 (the `sepc`/`sstatus` window) are the untested
//! candidates; see the K-C26 block in `tools/ci_check.sh`.
//!
//! **Step 2 has landed, and the paragraph that stood here said it had not.**
//! It read "Nothing takes a guard yet. Making `SpinLockGuard` carry a
//! `PreemptGuard` is step 2 and is deliberately not done here", and concluded
//! that `depth()` is 0 on every hart so every branch keyed on it is not-taken.
//! That is false: `SpinLock::lock` takes `critical_section()` BEFORE its spin
//! (`spinlock.rs`) and `SpinLockGuard` carries the `PreemptGuard`, so `depth()`
//! is non-zero for the life of every held `SpinLock` in the kernel.
//!
//! Left uncorrected it is worse than untidy. A reader deciding whether some
//! path may yield would conclude preemption is never off, and that is exactly
//! the reasoning that picks the wrong locking primitive — it nearly did on
//! 2026-09-07, when a sleeping lock was chosen for the I2C bus lock because its
//! acquire path yields, under the belief that no `SpinLockGuard` was live
//! above it.
//!
//! **The consequence this comment must carry instead:** preemption is now off
//! for the duration of every `SpinLock` critical section, so the length of
//! those sections is a real-time property. See `crates/core/ipc/src/cap_store.rs`'s
//! `with_table`, which four `*_cap` modules use with a driver call inside the
//! closure.
//!
//! # Why the sync crate cannot just call the scheduler
//!
//! `crates/core/sched` depends on `crates/core/sync`, so the dependency cannot run the
//! other way. The deferred reschedule therefore goes through a function
//! pointer registered at boot — the same shape `waitqueue::wq_set_callbacks`
//! already uses, and for the same reason.
//! Before registration, dropping the outermost guard simply does not
//! reschedule, which is correct: with no scheduler there is nothing to
//! reschedule to.
//!
//! # Relationship to the deleted `PREEMPT_COUNT` stub
//!
//! `crates/core/sched/src/scheduler.rs` used to carry a dead `PREEMPT_COUNT`
//! (zero callers) with three defects this module does not reproduce:
//!
//!   1. Its check in `schedule()` returned *before* the tick bookkeeping, so a
//!      lock holder vanished from `total_runtime`,
//!      from deadline replenish, and from `DEADLINE_TICK_COUNTER`. Here the
//!      admission check happens *after* all of it — see the call sites in
//!      `schedule()`.
//!   2. It had no need-resched memory: a tick that arrived while preemption
//!      was disabled was dropped on the floor. Here it is recorded and paid.
//!   3. Its `preempt_enable()` called `schedule()` unconditionally, from any
//!      context including an ISR. Here firing is gated on `sstatus.SIE`.
//!
//! It also indexed `[AtomicI32; MAX_CPUS]` with `hart.min(MAX_CPUS - 1)`, and
//! `MAX_CPUS` is 4 while `MAX_HARTS` is 8 — so harts 3 through 7 shared one
//! depth counter. A lock taken on hart 5 disabled preemption on hart 3. This
//! module has one slot per hart and no clamp.

use core::marker::PhantomData;
use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU32, Ordering};

use crate::preempt_core::{self, EnableOutcome};

// NOTE (K-C29 lost-wakeup fix): `PreemptGuard::drop` used to read
// `need_resched`/`irqs_enabled` BEFORE decrementing depth, decide from that
// stale pair, and only then commit the decrement. A tick landing between the
// read and the decrement — `tick_dispatch` sees the still-current depth of 1,
// defers, and sets `need_resched = true` — left that debt unseen: the drop
// decided with the value it read before the tick ever happened, decremented
// to 0, and returned without firing. Bounded at one tick period (the next
// tick's own `Switch` arm pays it), so never a hang, but a task made runnable
// right then waited a full tick with nothing recording it. See `drop` below
// for the fix and `preempt_core::EnableOutcome` for why the interface changed
// to force the read order.

/// One slot per hart.
///
/// **`align(64)` is load-bearing, not tidiness.** This counter is touched on
/// the kernel's hottest path — every lock acquire and release, every timer
/// tick. Slots of four harts inside one 64-byte cache line would make every
/// hart's own store pay a coherence miss as the line ping-pongs between L1s.
/// Padding each slot to its own line makes the only case that exists (a hart
/// touching only its own slot, see [`critical_section`]'s argument) a
/// private-line hit.
#[repr(align(64))]
struct PreemptSlot {
    /// Nesting depth. `> 0` means preemption is disabled on this hart.
    ///
    /// Written only by a Relaxed load and a Relaxed store, never an RMW (see
    /// [`critical_section`] for why that is sound). Still an atomic rather
    /// than a plain `u32` in an `UnsafeCell`: the store and load are the
    /// same single `sw`/`lw`, `str`/`ldr`, `mov` either way, and the atomic
    /// keeps any reader — an interrupt on this hart today, a cross-hart
    /// diagnostic some day — free of a data race by construction.
    depth: AtomicU32,
    /// A preemption was owed while `depth > 0` and has not been paid yet.
    need_resched: AtomicBool,
}

impl PreemptSlot {
    const fn new() -> Self {
        Self { depth: AtomicU32::new(0), need_resched: AtomicBool::new(false) }
    }
}

/// Number of per-hart slots: the CPU ceiling, Kconfig `NR_CPUS`, the same
/// constant `kernel/src/main.rs`'s `MAX_HARTS` and `boot.S`'s range check
/// take, so the two cannot drift (they used to be two hand-written 8s tied by
/// an assert). Static, not in a per-CPU area: every spinlock takes a
/// `PreemptGuard`, from the first `kprintln!` on, long before the frame
/// allocator exists. 8 bytes per CPU of the ceiling.
pub const SLOTS: usize = azos_limits::NR_CPUS;

static PREEMPT: [PreemptSlot; SLOTS] = [const { PreemptSlot::new() }; SLOTS];

/// Times `enable` ran at depth 0 — an unbalanced release. **Must stay zero.**
static UNDERFLOW: AtomicU32 = AtomicU32::new(0);

/// Times `hart_id()` was outside `0..SLOTS`. **Must stay zero**; boot.S
/// range-checks harts against `MAX_HARTS`, so this is unreachable on a
/// correctly-built kernel.
static HART_OOR: AtomicU32 = AtomicU32::new(0);

/// Ticks that found preemption disabled and recorded a debt instead of
/// switching. Bumped by [`set_need_resched`], which — in production — has
/// exactly one caller: `crates/core/sched`'s `tick_admit()`, on its `Defer` arm,
/// immediately after it calls this function.
///
/// Lives here rather than in `crates/core/sched`'s own `preempt_audit` module for
/// a concrete reason, not a stylistic one: `tests/host/sync-tests` needs to drive
/// and assert on this counter, and `crates/core/sched` does not compile for the
/// host (static `TASKS`/`PER_CPU`, CSR reads, an assembly context switch —
/// see that crate's test-suite doc). A counter that only existed in `sched`
/// could never appear in a host test at all. `crates/core/sched`'s `preempt_audit`
/// module reads this one through [`deferred`] rather than keeping its own
/// copy.
///
/// **Expected to grow.** Unlike `UNDERFLOW`/`HART_OOR` this is not a
/// must-stay-zero invariant — see [`FIRED`] for what the pair does and does
/// not tell you together.
static DEFERRED: AtomicU32 = AtomicU32::new(0);

/// Times a deferred reschedule was actually paid: incremented exactly where
/// `PreemptGuard::drop` *decides* to run the resched callback — i.e. where
/// `preempt_core::should_fire` returns `true` — regardless of whether a
/// callback happens to be registered yet. This is the only place `fired` can
/// be counted at all: the decision and the callback invocation both happen
/// inside this crate's `Drop` impl, which `crates/core/sched` cannot reach into
/// (it depends on `crates/core/sync`, not the other way — see the module docs).
///
/// # `deferred - fired` is not "the outstanding debt count" — read this before wiring an alarm on it
///
/// It is tempting to treat a growing gap between [`deferred`] and [`fired`]
/// as *the* signature of a stranded debt (a guard dropped with interrupts
/// off, per the NOTE above `impl Drop for PreemptGuard`). The gap grows for
/// three reasons, and only one of them is that bug:
///
///   1. **A critical section spanning more than one tick.** Every tick that
///      lands while `depth > 0` calls `set_need_resched()` and bumps
///      `DEFERRED`, but `need_resched` is a **boolean**, not a counter — the
///      first such tick sets it, every later one while it is already set is a
///      no-op on the flag. One guard drop then pays all of them with a
///      single `FIRED` bump. Three deferred ticks inside one lock, one fire:
///      gap of 2, and nothing is wrong.
///   2. **`clear_need_resched()`.** The scheduler's `Switch` arm calls this
///      when a *later* tick finds `depth == 0` and reschedules on its own —
///      the debt is discharged without ever going through
///      `PreemptGuard::drop`, so that `DEFERRED` is never matched by a
///      `FIRED`. This is a permanent, legitimate contribution to the gap, not
///      a transient one that later closes.
///   3. **`force_zero_depth()` at task exit.** Also clears `need_resched`
///      without firing. Correlated with `preempt_audit::EXIT_WHILE_ATOMIC`,
///      so unlike the first two this source is at least attributable from
///      the census — but it is a third distinct source of the same kind, not
///      the bug either.
///
/// So `deferred - fired` is a lower bound on tick-defer *traffic*, not a
/// count of debts still owed: a gap of zero is not the expected steady
/// state, and a nonzero — even growing — gap is not by itself evidence of an
/// interrupts-off drop. What the pair *does* guarantee, unconditionally:
/// **`deferred >= fired` always**, so the subtraction never goes negative.
/// A fire requires `need_resched == true`, and the only function that ever
/// sets it is `set_need_resched()`, which bumps `DEFERRED` before it can
/// return — same hart, program order — so a `FIRED` is always causally
/// preceded by a `DEFERRED` count that has already committed. Both counters
/// saturate rather than wrap (see [`bump`]), so `u32` subtraction cannot
/// underflow either, even under a bug this reasoning failed to anticipate.
/// (Reading the pair cross-hart through [`deferred`]/[`fired`] uses
/// `Relaxed` loads with no fence linking them, so a momentarily stale
/// snapshot — e.g. printed from a hart other than the one that just fired —
/// is possible in principle; it self-heals on the next read and is not the
/// failure mode this pair exists to catch.)
static FIRED: AtomicU32 = AtomicU32::new(0);

/// Saturating bump, so a diagnostic counter can never wrap back through zero
/// and read as "clean" on a board that is anything but.
#[inline(always)]
fn bump(c: &AtomicU32) {
    let _ = c.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_add(1)));
}

/// This hart's slot, or `None` if the hart id is out of range.
///
/// # The out-of-range policy — why `None` is unreachable on BOTH ISAs now
///
/// boot.S range-checks harts against `MAX_HARTS = 8` and `SLOTS == MAX_HARTS`,
/// so `None` is unreachable on riscv64, where `hart_id()` reads `tp`, the
/// same value `boot.S` range-checked. If it *were* reached, everything here
/// degrades to a no-op: `depth()` reads 0, guards do nothing, and the hart
/// behaves exactly as it does today with no preemption control at all —
/// the right failure mode *while nothing carries a guard*, but wrong once
/// something does.
///
/// **This paragraph used to say "Step 2 must revisit this" — Step 2 has
/// landed** (`SpinLockGuard` carries a `PreemptGuard`; see the module doc's
/// own correction), so a silent no-op here means a hart whose lock holders
/// are freely preempted, i.e. K-C29 unfixed on exactly one hart — worse
/// than a loud stop. On aarch64 this used to be reachable in principle: this
/// crate's `hart_id()` decoded `MPIDR_EL1` directly (`Aff0 | Aff1<<8 |
/// Aff2<<16`), a value that only stays inside `0..SLOTS` on a flat topology
/// (`Aff1 == 0`, true on QEMU virt's `-smp N`, false on any clustered SoC) —
/// U10-4 (audit). `crates/core/arch-aarch64::cpu::hart_id()` now reads
/// `TPIDR_EL1` instead — the SAME logical, contiguous `0..num_cpus` id
/// `boot.S` publishes and range-checks against `MAX_HARTS` before this
/// crate ever sees it (see that crate's own doc for the full history) — so
/// `None` is unreachable on aarch64 too, for the same reason it already was
/// on riscv64: one hart-identity source, one range check, both ISAs. The
/// alternative that must NOT be chosen is `hart % SLOTS`: that reintroduces
/// the counter-merging the deleted stub had.
#[inline(always)]
fn slot() -> Option<&'static PreemptSlot> {
    let hart = azos_arch::Cpu::hart_id(&azos_arch::ARCH);
    match PREEMPT.get(hart) {
        Some(s) => Some(s),
        None => { bump(&HART_OOR); None }
    }
}

/// Are S-mode interrupts enabled on this hart right now?
///
/// # LOAD-BEARING INVARIANT — this predicate is what makes firing safe
///
/// A dropped `PreemptGuard` may call back into the scheduler. That is only
/// legal from task context. This kernel establishes exactly the invariant that
/// makes the test sound:
///
///   * `task_yield()` clears `SSTATUS_SIE` before `do_schedule()` and restores
///     it after (`scheduler.rs`).
///   * `block_current()` does the same, for the K-A12 reentrancy hazard.
///   * `task_exit_with_code()` does the same before its `do_schedule()`.
///   * `schedule()` is called from the timer ISR, where the hardware has
///     already cleared `SIE` on trap entry.
///
/// So SIE is 0 inside every scheduler entry and inside every interrupt
/// handler. A guard dropped in either place reports `false`, does not fire,
/// and cannot re-enter the scheduler. The debt stays recorded in
/// `need_resched` and is paid by the next drop that happens with SIE set —
/// i.e. in ordinary task context.
///
/// If a future change ever runs `do_schedule` with SIE set, this predicate
/// stops being a safety property and the reentrancy it guards against comes
/// back.
#[inline(always)]
pub fn irqs_enabled() -> bool {
    // `interrupts_enabled()`, not a hand-read of `sstatus.SIE`: on aarch64
    // the same question is `DAIF.I` being CLEAR, so the bit test here would
    // not merely need renaming, it would need inverting. That is exactly the
    // kind of port bug a predicate named "enabled" hides.
    use azos_arch::Interrupts;
    azos_arch::ARCH.interrupts_enabled()
}

azos_common::ro_hook! {
    /// Deferred-reschedule callback, registered at boot.
    static RESCHED_FN: fn();
}

/// Register the deferred-reschedule callback. Call once, during boot.
///
/// The kernel registers `azos_sched::task_yield`. It is invoked only from
/// the drop of an outermost `PreemptGuard`, with interrupts enabled, after
/// `need_resched` has already been cleared.
pub fn set_resched_callback(f: fn()) {
    RESCHED_FN.set(f);
}

#[inline]
fn resched_callback() -> Option<fn()> {
    RESCHED_FN.get()
}

/// RAII token: preemption is disabled on this hart for as long as it lives.
///
/// `!Send` and `!Sync` via the `*mut ()` marker. The depth it increments is a
/// property of the *hart*, so a guard released on a different hart than the
/// one that took it would decrement a counter it never incremented. `!Send`
/// makes handing one to another thread of control a compile error rather than
/// a runtime counter corruption. There is deliberately no way to construct one
/// except `critical_section()`, and no public raw enable/disable pair: the only
/// way to leave the counter unbalanced is `mem::forget`, which leaks
/// preemption-off rather than underflowing it.
pub struct PreemptGuard {
    _not_send: PhantomData<*mut ()>,
    /// Where this guard was taken: the end site the masked-window tracer
    /// records if dropping it is what re-enables preemption.
    #[cfg(feature = "lat-trace")]
    site: &'static core::panic::Location<'static>,
}

/// Open a critical section: preemption is disabled on this hart until the
/// returned guard is dropped. Nests.
#[inline]
#[must_use = "preemption is re-enabled the instant the guard is dropped"]
#[cfg_attr(feature = "lat-trace", track_caller)]
pub fn critical_section() -> PreemptGuard {
    // Interrupts masked from the hart read to the store. This is what keeps
    // the increment on the slot of the hart the task runs on (see below).
    use azos_arch::Interrupts;
    let irq = azos_arch::ARCH.disable_all();
    if let Some(s) = slot() {
        // A load and a store, not an RMW (Chain E commit 7): the LR/SC
        // `fetch_update` loop this replaces was the cost of every lock
        // acquire. `preempt_core::disable` still saturates, so a wrapping
        // increment cannot silently re-enable preemption.
        //
        // # Why the increment runs with interrupts masked
        //
        // Nothing but its own hart ever writes a slot: `PREEMPT` is private
        // and every path to it goes through `slot()`, which indexes it by
        // this hart's id. What can run on THIS hart between the load and the
        // store is an interrupt, which ends in one of two ways:
        //
        //   * An interrupt that returns to the task. Every handler is
        //     depth-balanced (each guard it takes it drops before returning;
        //     `force_zero_depth` is task exit only), so the slot holds `d`
        //     again when the interrupted store runs, and `d + 1` is right.
        //   * An interrupt whose exit switches the task away (the tick found
        //     the slot at 0, so `tick_admit` let it). Every switch happens at
        //     depth 0, so the slot is 0 when the task is resumed. That is
        //     right ONLY IF the task resumes on the same hart. It need not:
        //     an idle CPU pulls a queued task from a busy one
        //     (`SCHED_BALANCE`, `fairq::balance_idle`), and the task then
        //     stores `d + 1` into the slot of the hart it LEFT, a slot its
        //     owner is writing with the same load/store at the same time. The
        //     hart it left keeps a depth of 1 that nothing will drop (its
        //     ticks are deferred for good, it can neither yield nor block:
        //     `block_current` refuses and the caller spins), the hart it
        //     resumed on sees the matching drop at depth 0 (`UNDERFLOW`), and
        //     the task runs the rest of its critical section preemptible.
        //     Seen on x86_64 as a thread group whose exit starved for 20 s
        //     behind a hart that never rescheduled, and as boots that hung in
        //     `K-C29 block_current refused`.
        //
        // With interrupts masked no switch can fall between the hart read
        // and the store, and the load/store pair stays cheap (no RMW). The
        // drop needs no mask: it starts at depth >= 1, so the tick defers
        // and the task cannot leave the hart before its store.
        let d = s.depth.load(Ordering::Relaxed);
        #[cfg(test)]
        window_hook::fire();
        s.depth.store(preempt_core::disable(d), Ordering::Relaxed);
        // Masked-window tracer: the 0 -> 1 transition opens a window.
        #[cfg(feature = "lat-trace")]
        if d == 0 {
            azos_arch::lat_hook::preempt_off(core::panic::Location::caller());
        }
    }
    azos_arch::ARCH.restore(irq);
    // Linux's `barrier()`. The slot is only ever read or written by its own
    // hart, so no *hardware* fence is needed — there is no cross-hart
    // publication here to order. What must not happen is the compiler hoisting
    // a load from the critical section above the store that disables
    // preemption. Data ordering between harts remains the lock's own
    // Acquire/Release, which this does not touch.
    compiler_fence(Ordering::SeqCst);
    PreemptGuard {
        _not_send: PhantomData,
        #[cfg(feature = "lat-trace")]
        site: core::panic::Location::caller(),
    }
}

impl Drop for PreemptGuard {
    #[inline]
    fn drop(&mut self) {
        compiler_fence(Ordering::SeqCst);
        let Some(s) = slot() else { return };

        // Decrement FIRST, decide SECOND — this order is the K-C29 lost-wakeup
        // fix (see the module-level NOTE above `impl Drop`). Load / decide /
        // store through `preempt_core::enable`, never a bare subtract. A
        // wrapping decrement at depth 0 would put `u32::MAX` in the slot for a
        // few instructions; an interrupt landing in that window reads
        // `disabled() == true` on a hart that is not in a critical section.
        // `enable` returns 0 for that case, so the wrap value never exists in
        // memory.
        //
        // A load and a store, not an RMW, by the argument in
        // `critical_section()`. On this side it is shorter still: the slot
        // holds `d >= 1` until the store, so the tick defers and only a
        // depth-balanced interrupt can land between the two. One that sets
        // `need_resched` there is seen by the read below, which follows the
        // store.
        let d = s.depth.load(Ordering::Relaxed);
        let (new, outcome) = preempt_core::enable(d);
        #[cfg(test)]
        window_hook::fire();
        s.depth.store(new, Ordering::Relaxed);

        match outcome {
            EnableOutcome::Underflow => bump(&UNDERFLOW),
            EnableOutcome::Enabled => {
                // Masked-window tracer: the 1 -> 0 transition closes the
                // window, before any deferred reschedule below is paid.
                #[cfg(feature = "lat-trace")]
                azos_arch::lat_hook::preempt_on(self.site);
                // The depth has already committed to 0 above. ONLY NOW do we
                // read the inputs to the firing decision — this ordering,
                // relative to the store above, is the entire fix.
                //
                // A same-hart interrupt does not care about the Rust memory
                // model; it cares about emitted instruction order at this
                // hart's PC. Relaxed atomics to two different locations
                // (`depth` and `need_resched`) give the compiler no reason NOT
                // to hoist the `need_resched` load above the depth store if it
                // can prove no data dependency forces otherwise — which would
                // silently reinstate the exact bug this restructuring exists
                // to remove. The fence pins the
                // reads after the decrement in the emitted code, the same way
                // `critical_section()`'s fence pins the increment before the
                // critical section it opens.
                compiler_fence(Ordering::SeqCst);

                // `irqs_enabled()` before `need_resched`: the former is the
                // only production call that lands inside this post-decrement
                // window and is observable from outside this function (it
                // reads a real CSR), so it is the one `tests/host/sync-tests`
                // hooks to inject "a tick sets need_resched right here"
                // without any real concurrency. Reading it first makes that
                // injected write visible to the very next line.
                let irqs = irqs_enabled();
                let need = s.need_resched.load(Ordering::Relaxed);

                if preempt_core::should_fire(need, irqs) {
                    // Cleared BEFORE the callback. The callback re-enters the
                    // scheduler, which may take another guard and drop it;
                    // leaving the flag set until after would let that inner
                    // drop fire a second, duplicate reschedule for a debt
                    // already being paid.
                    s.need_resched.store(false, Ordering::Relaxed);
                    // The debt is being paid right here — this is the ONLY
                    // place in the kernel `FIRED` is bumped, and it counts
                    // the decision, not the callback: it must not be gated on
                    // `resched_callback()` returning `Some`, since "no
                    // scheduler registered yet" (module docs, top of file) is
                    // a legitimate state in which the debt is still resolved,
                    // just with nothing to hand it to.
                    bump(&FIRED);
                    if let Some(f) = resched_callback() { f(); }
                }
                // Else: the debt (if `need` was set) is deliberately left in
                // `need_resched` — it survives for a legal drop later.
            }
            EnableOutcome::StillDisabled => {}
        }
    }
}

/// Host-test injection point between the load and the store of the depth,
/// on both sides (`tests/host/sync-tests`, which compiles this file as a
/// module of its own crate, so `cfg(test)` is never on in a kernel). A host
/// thread cannot deliver an interrupt to itself, so a test arms a one-shot
/// function here to stand for "an interrupt landed between the two".
#[cfg(test)]
pub(crate) mod window_hook {
    use std::cell::Cell;
    thread_local! {
        static HOOK: Cell<Option<fn()>> = const { Cell::new(None) };
    }
    /// Run `f` at the next load-to-store window on this thread, once.
    pub fn arm(f: fn()) { HOOK.with(|c| c.set(Some(f))); }
    /// Disarm without firing (the tests' shared reset).
    pub fn clear() { HOOK.with(|c| c.set(None)); }
    /// Taken before it runs, so a guard the hook itself takes does not
    /// re-fire it.
    pub(super) fn fire() {
        if let Some(f) = HOOK.with(|c| c.take()) { f(); }
    }
}

/// In-kernel test probe: a timer interrupt that takes a guard on top of one
/// the interrupted code holds (ktest `preempt_count_survives_irq_nesting`).
/// Called from `azos_sched::wake_expired_timers`, which every ISA's timer
/// interrupt runs. Armed for one hart; on the others it is one load.
#[cfg(feature = "ktest")]
pub mod ktest_probe {
    use super::{critical_section, depth};
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    static HART: AtomicUsize = AtomicUsize::new(usize::MAX);
    static LEAK: AtomicU32 = AtomicU32::new(0);
    static HITS: AtomicU32 = AtomicU32::new(0);
    static MAX_SEEN: AtomicU32 = AtomicU32::new(0);

    /// Arm on `hart`. `leak` (the test's canary) makes every probe until
    /// `disarm` keep its guard, an interrupt handler that is not
    /// depth-balanced. Every one, not the first: a leak that lands inside a
    /// load-to-store window is overwritten by the interrupted store.
    pub fn arm(hart: usize, leak: bool) {
        HITS.store(0, Ordering::Relaxed);
        MAX_SEEN.store(0, Ordering::Relaxed);
        LEAK.store(leak as u32, Ordering::Relaxed);
        HART.store(hart, Ordering::Release);
    }

    /// Disarm; `(interrupts that took a guard, deepest depth one saw)`.
    pub fn disarm() -> (u32, u32) {
        HART.store(usize::MAX, Ordering::Release);
        (HITS.load(Ordering::Relaxed), MAX_SEEN.load(Ordering::Relaxed))
    }

    /// Interrupts that took a guard since `arm`.
    pub fn hits() -> u32 {
        HITS.load(Ordering::Relaxed)
    }

    /// The timer interrupt's half.
    pub fn from_tick() {
        if HART.load(Ordering::Acquire) != azos_arch::Cpu::hart_id(&azos_arch::ARCH) {
            return;
        }
        let g = critical_section();
        MAX_SEEN.fetch_max(depth(), Ordering::Relaxed);
        HITS.fetch_add(1, Ordering::Relaxed);
        if LEAK.load(Ordering::Relaxed) != 0 {
            core::mem::forget(g);
        }
    }
}

// ── Scheduler-facing API ──────────────────────────────────────────────────
//
// These are the only things `crates/core/sched` needs. None of them can disable
// preemption; the counter can only be raised by holding a guard.

/// This hart's current nesting depth. 0 means preemption is enabled.
#[inline(always)]
pub fn depth() -> u32 {
    match slot() {
        Some(s) => s.depth.load(Ordering::Relaxed),
        None => 0,
    }
}

/// Is preemption disabled on this hart?
#[inline(always)]
pub fn disabled() -> bool {
    depth() > 0
}

/// May the running context block (wait for another task)? Not while it holds
/// a SpinLock, which raises the depth (`cap_store::with_table`'s closure is
/// one), and not with interrupts masked. The kernel's calls to a task-served
/// endpoint (`azos_syscall::kcall`) refuse when this is false instead of
/// sleeping with a lock held, which would stall every CPU that wants it for
/// as long as the server takes.
#[inline(always)]
pub fn may_block() -> bool {
    depth() == 0 && irqs_enabled()
}

/// Record that a preemption was owed on this hart while it was disabled.
/// Called by the scheduler tick when `tick_dispatch` says `Defer`.
///
/// Bumps [`DEFERRED`] unconditionally (not only on the false-to-true edge):
/// see that counter's doc for why counting every deferred tick, not just the
/// first one per debt, is deliberate.
#[inline]
pub fn set_need_resched() {
    if let Some(s) = slot() {
        s.need_resched.store(true, Ordering::Relaxed);
        bump(&DEFERRED);
    }
}

/// Clear the owed preemption. Called by the scheduler when it actually enters
/// `do_schedule` — a later tick served the debt, so nothing is owed any more.
///
/// Read-mostly on purpose. This runs on **every** timer tick that reaches the
/// scheduler, and in the overwhelmingly common case the flag is already clear.
/// An unconditional store would dirty this hart's slot line on every tick for
/// no state change; the load leaves it clean.
#[inline]
pub fn clear_need_resched() {
    if let Some(s) = slot() {
        if s.need_resched.load(Ordering::Relaxed) {
            s.need_resched.store(false, Ordering::Relaxed);
        }
    }
}

/// Is a preemption owed on this hart?
#[inline]
pub fn need_resched() -> bool {
    match slot() {
        Some(s) => s.need_resched.load(Ordering::Relaxed),
        None => false,
    }
}

/// Force this hart's depth to 0, discarding any open critical sections.
///
/// The only legitimate caller is task exit. Exit cannot be refused and cannot
/// be deferred: the task is not coming back to drop its guards, and refusing
/// to switch away from a Zombie strands the hart. Any outstanding guard's
/// `Drop` will then count an `UNDERFLOW`, which is the intended signal — the
/// counter says "a task exited holding a lock", which is a bug in that task,
/// not in this mechanism.
///
/// It can only *enable* preemption, so it can never be the cause of a hang.
#[inline]
#[cfg_attr(feature = "lat-trace", track_caller)]
pub fn force_zero_depth() {
    use azos_arch::Interrupts;
    // Masked: a task migrated between the hart read and the stores would zero
    // the depth of a hart that holds a real critical section.
    let irq = azos_arch::ARCH.disable_all();
    force_zero_depth_masked();
    azos_arch::ARCH.restore(irq);
}

#[inline]
#[cfg_attr(feature = "lat-trace", track_caller)]
fn force_zero_depth_masked() {
    if let Some(s) = slot() {
        #[cfg(feature = "lat-trace")]
        if s.depth.load(Ordering::Relaxed) != 0 {
            azos_arch::lat_hook::preempt_on(core::panic::Location::caller());
        }
        s.depth.store(0, Ordering::Relaxed);
        s.need_resched.store(false, Ordering::Relaxed);
    }
}

/// `(underflow, hart_out_of_range)`. Both **must stay zero**. Kept separate
/// from [`deferred`]/[`fired`]: those two are expected to grow, and mixing an
/// expected-to-grow counter into this tuple would wreck the one thing it is
/// for — eyeballing it for all-zeroes.
pub fn audit_counters() -> (u32, u32) {
    (UNDERFLOW.load(Ordering::Relaxed), HART_OOR.load(Ordering::Relaxed))
}

/// Ticks deferred because preemption was disabled. See [`FIRED`]'s doc for
/// what this pairs with, what growth means, and — importantly — what it does
/// not mean by itself.
pub fn deferred() -> u32 {
    DEFERRED.load(Ordering::Relaxed)
}

/// Deferred reschedules actually paid (a guard drop ran, or would have run,
/// the resched callback). See [`FIRED`]'s doc.
pub fn fired() -> u32 {
    FIRED.load(Ordering::Relaxed)
}
