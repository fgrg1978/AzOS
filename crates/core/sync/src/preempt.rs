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
//! 2026-09-07, when a `PiMutex` was chosen for the I2C bus lock because its
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
//! and `pi_mutex::pi_set_callbacks` already use, and for the same reason.
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
//!      lock holder vanished from `total_runtime`, from `aps_state::account`,
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
use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU32, AtomicUsize, Ordering};

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
/// the kernel's hottest path — every lock acquire and release in step 2, every
/// timer tick already. Four harts issuing `amoadd.w` against addresses inside
/// one 64-byte cache line serialise on the coherence protocol: the line
/// ping-pongs between L1s and each hart's own uncontended increment pays a
/// remote-miss. Padding each slot to its own line makes the common case
/// (a hart touching only its own slot) a private-line hit.
#[repr(align(64))]
struct PreemptSlot {
    /// Nesting depth. `> 0` means preemption is disabled on this hart.
    ///
    /// `AtomicU32`, not `AtomicU8`: the workspace target is
    /// `riscv64imac-unknown-none-elf` with `+zaamo,+zalrsc` (see
    /// `.cargo/config.toml`) and *no* `Zabha`. Without `Zabha` there is no
    /// byte-granular AMO, so a `u8` RMW lowers to a word-wide `lr.w`/`sc.w`
    /// loop with shift-and-mask — strictly more instructions, on this path,
    /// to save three bytes of a 64-byte-padded slot.
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

/// Deferred-reschedule callback, registered at boot. `fn()`, stored
/// pointer-sized, exactly like `PI_YIELD_FN` / `WQ_BLOCK_FN`.
static RESCHED_FN: AtomicUsize = AtomicUsize::new(0);

/// Register the deferred-reschedule callback. Call once, during boot.
///
/// The kernel registers `azos_sched::task_yield`. It is invoked only from
/// the drop of an outermost `PreemptGuard`, with interrupts enabled, after
/// `need_resched` has already been cleared.
pub fn set_resched_callback(f: fn()) {
    RESCHED_FN.store(f as usize, Ordering::Release);
}

#[inline]
fn resched_callback() -> Option<fn()> {
    let p = RESCHED_FN.load(Ordering::Acquire);
    if p == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, fn()>(p) }) }
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
    if let Some(s) = slot() {
        // `fetch_update` rather than `fetch_add`: it routes through
        // `preempt_core::disable`, which saturates. A wrapping increment would
        // silently re-enable preemption inside a critical section, and an
        // atomic RMW is not covered by `overflow-checks`.
        let _prev = s.depth.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |d| {
            Some(preempt_core::disable(d))
        });
        // Masked-window tracer: the 0 -> 1 transition opens a window.
        #[cfg(feature = "lat-trace")]
        if _prev == Ok(0) {
            azos_arch::lat_hook::preempt_off(core::panic::Location::caller());
        }
    }
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
        // store through `preempt_core::enable`, never a bare `fetch_sub`. A
        // `fetch_sub` at depth 0 materialises `u32::MAX` in the slot for a few
        // instructions; an interrupt landing in that window reads
        // `disabled() == true` on a hart that is not in a critical section.
        // `enable` returns 0 for that case, so the wrap value never exists in
        // memory.
        let mut outcome = EnableOutcome::StillDisabled;
        let _ = s.depth.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |d| {
            let (new, o) = preempt_core::enable(d);
            outcome = o;
            Some(new)
        });

        match outcome {
            EnableOutcome::Underflow => bump(&UNDERFLOW),
            EnableOutcome::Enabled => {
                // Masked-window tracer: the 1 -> 0 transition closes the
                // window, before any deferred reschedule below is paid.
                #[cfg(feature = "lat-trace")]
                azos_arch::lat_hook::preempt_on(self.site);
                // The depth has already committed to 0 above. ONLY NOW do we
                // read the inputs to the firing decision — this ordering,
                // relative to the `fetch_update` above, is the entire fix.
                //
                // A same-hart interrupt does not care about the Rust memory
                // model; it cares about emitted instruction order at this
                // hart's PC. Relaxed atomics to two different locations
                // (`depth` and `need_resched`) give the compiler no reason NOT
                // to hoist the `need_resched` load above the `fetch_update`'s
                // LR/SC loop if it can prove no data dependency forces
                // otherwise — which would silently reinstate the exact bug
                // this restructuring exists to remove. The fence pins the
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
