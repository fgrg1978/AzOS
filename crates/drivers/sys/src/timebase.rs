// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The monotonic clock, under a name that is not a RISC-V device.
//!
//! # Why this module exists
//!
//! 129 call sites across the tree read the clock as `clint::get_time()`. The
//! CLINT is a RISC-V interrupt controller, and on aarch64 there is no such
//! device — so every one of those sites was a blocker for building this kernel
//! on a second ISA, for no reason but the name.
//!
//! The name was never accurate even here: the read is `rdtime`, an unprivileged
//! CSR read, not an access to the CLINT's MMIO at all.
//!
//! # Why it is here and not in `arch`
//!
//! Owner decision 2026-09-20 put the primitive in `arch-api`'s `Cpu` trait,
//! and [`now`] delegates straight to it — the implementation IS arch's, on both
//! ISAs.
//!
//! What stays here is the **test seam**. Four test crates
//! (`behavior-tests`, `fs-tests`, `syscall-tests`, `topology-tests`) shim
//! `azos_drv_sys` and pin this clock so the flight recorder's records
//! decode reproducibly — a wall-clock stamp would make the bytes a test
//! asserts on different every run. Pointing the call sites at
//! `azos_arch::ARCH.now_ticks()` directly would have needed three NEW arch
//! shim crates and scattered that one override across four more places.
//!
//! So: the primitive is arch's, the seam stays where the tests already reach
//! it, and the call sites stop naming a device that only one ISA has.
//!
//! # What this is not
//!
//! Monotonic ticks since reset, never wall-clock. Nothing steers it — no NTP,
//! no RTC — and comparing readings across a reboot is meaningless. Units are
//! platform-defined (`TIMER_FREQ` converts; a raw tick count is a per-board
//! number, not a duration).

use azos_arch::Cpu as _;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::timer_arm;

/// When a busy CPU may stop its tick: the pure decisions (Kconfig
/// NOHZ_FULL). A child of this file so the host suite pulls it by path.
#[path = "nohz.rs"]
pub mod nohz;

/// Read the monotonic tick counter.
#[inline(always)]
pub fn now() -> u64 {
    azos_arch::ARCH.now_ticks()
}

/// Ticks per second of the counter [`now`] reads.
///
/// A **per-board** number, not a per-ISA one: 10 MHz is QEMU's `virt`, and the
/// VF2 and K1 differ. A raw tick count is therefore never a duration — divide
/// by this, always.
///
/// Kconfig `TIMER_FREQ`, the one place the tree reads it (the board
/// descriptions in `azos_drv_base::platform::hw` carry the same value).
///
/// [`now`] counts at this rate on every ISA: aarch64 and x86_64 scale their
/// counters to it, whatever `CNTFRQ_EL0` or the TSC runs at.
pub const TIMER_FREQ: u64 = azos_limits::TIMER_FREQ as u64;

/// Ticks per second of [`now`]. The rate the vDSO page publishes
/// (`ArchEntry::timebase_hz`).
#[inline(always)]
pub fn freq() -> u64 {
    TIMER_FREQ
}

/// The rate of the raw hardware counter, for what reads it unscaled: the
/// tracer's stamps, a device clocked by it. `CNTFRQ_EL0` on aarch64.
#[inline(always)]
pub fn counter_freq() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        azos_arch::cpu::timer_freq_hw()
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        TIMER_FREQ
    }
}

// ── Scheduler tick rate ────────────────────────────────────────────────────
//
// This has **no ISA content whatsoever**: a `u32` between 10 and 10_000 that
// says how often the kernel wants to be interrupted.
//
// It stays in `azos_drv_sys` rather than moving to `azos_sched`, which
// is where it conceptually belongs, because `set_next_tick` reads it to
// compute the next deadline and `drivers` does not depend on `sched` (the edge
// runs the other way). Moving it would invert that for a single integer.

static SCHED_HZ: AtomicU32 = AtomicU32::new(100);

/// Set the scheduler tick rate in Hz (10..=10_000). Out-of-range is ignored —
/// a tick rate of 0 would divide by zero in `set_next_tick`, and one of
/// 10^9 would spend the whole CPU in the timer ISR.
#[inline(always)]
pub fn sched_hz_set(hz: u64) {
    if (10..=10_000).contains(&hz) {
        SCHED_HZ.store(hz as u32, Ordering::Relaxed);
    }
}

/// Get the scheduler tick rate in Hz.
#[inline(always)]
pub fn sched_hz_get() -> u64 {
    SCHED_HZ.load(Ordering::Relaxed) as u64
}

// ── Scheduling the next tick ───────────────────────────────────────────────
//
// **Moved here from `clint`, not copied.** The arithmetic below — "now plus
// one tick period", "the earlier of that and the nearest sleeping deadline" —
// is scheduling policy with no ISA content at all. What IS per-ISA is the last
// line of each: programming the hardware, which on RISC-V means choosing
// between the `stimecmp` CSR and an SBI ecall (inside `set_timer_deadline`) and on
// aarch64 means writing `CNTV_CVAL_EL0`.
//
// Keeping the policy in a module named after a RISC-V interrupt controller is
// what made these two functions read as ISA-specific when only one line of
// each is.

// ── The comparator's one writer (wave 11 ONESHOT) ──────────
//
// Every write of this hart's timer comparator goes through [`program`], which
// records the instant in [`PROGRAMMED`] (one word per hart, written only by
// that hart). The record is what lets a task that blocks on a timer deadline
// move the comparator only when its deadline is EARLIER than what is already
// programmed ([`arm_if_earlier`]) — before this, the comparator was moved only
// by the timer interrupt and on the idle boundary, so a deadline on a hart
// that stayed busy was seen at the next scheduler tick, up to one period late.
//
// The invariant is that a record is never BELOW the comparator it describes: a
// low record would make `arm_if_earlier` skip a write it needed. So the write
// comes first and the record second, with interrupts masked across both (a
// timer interrupt in between would program and record its own value, and ours
// would then overwrite only the record). A record above the comparator costs at
// most one redundant write. Every caller passes its `hart` for the hardware's
// sake (unused by both mechanisms); the record is indexed by the calling hart's
// own id (`tp` / `TPIDR_EL1`, the read `current_cpu_id()` makes), never by that
// argument — boot passes a hart id that need not be the scheduler's index.

/// Records this many harts; a hart beyond it is programmed but never recorded,
/// so [`arm_if_earlier`] leaves it alone (its record reads [`timer_arm::NOT_ARMED`]).
const ARM_HARTS: usize = 16;

/// The comparator value each hart last programmed, in [`now`]'s units.
/// [`timer_arm::NOT_ARMED`] until the hart's first tick is armed.
static PROGRAMMED: [AtomicU64; ARM_HARTS] = [const { AtomicU64::new(timer_arm::NOT_ARMED) }; ARM_HARTS];

/// Write the calling hart's timer comparator with the contract's one deadline
/// write (`ARCH.set_timer_deadline`): the `stimecmp` CSR or SBI `set_timer` on
/// riscv64 (chosen at boot), `CNTV_CVAL_EL0` write + enable on aarch64, the TSC
/// deadline on x86_64. The comparator is per CPU, so `_hart` is unused.
///
/// Called only by [`program`] and [`arm_if_earlier`]: a write from anywhere
/// else leaves the hart's record of its comparator wrong, and a task blocking
/// on a timer deadline then skips a write it needed.
#[inline(always)]
fn set_timer(_hart: u32, time: u64) {
    use azos_arch::Interrupts;
    azos_arch::ARCH.set_timer_deadline(time);
}

/// Program the calling hart's comparator for `next` and record it. A value
/// equal to the record is not written again (the block-then-idle sequence
/// computes the same instant twice). `stopped` says whether `next` is a
/// busy hart's stopped tick ([`tick_stopped`]); every other caller passes
/// `false`, so any ordinary re-arm ends the stop.
#[inline]
fn program(next: u64, stopped: bool) {
    use azos_arch::Interrupts;
    // Masked BEFORE the hart is read: the comparator written below is the
    // executing hart's, and the records are indexed by the id, so a tick
    // between the two (a task context) would record this hart's write under
    // another hart's slot.
    let prev = azos_arch::ARCH.disable_all();
    let cpu = azos_arch::ARCH.hart_id();
    if let Some(flag) = STOPPED.get(cpu) {
        flag.store(stopped, Ordering::Relaxed);
    }
    match PROGRAMMED.get(cpu) {
        Some(slot) => {
            if slot.load(Ordering::Relaxed) != next {
                set_timer(cpu as u32, next);
                slot.store(next, Ordering::Relaxed);
            }
        }
        None => set_timer(cpu as u32, next),
    }
    azos_arch::ARCH.restore(prev);
}

/// A task on this hart is about to block until `deadline`: program the
/// comparator for it if it is earlier than what the hart has programmed.
/// Returns whether it wrote. On the common path (the deadline is not earlier)
/// this is a load and a compare: no CSR, SBI call or system-register write.
///
/// The common path reads the record without masking interrupts: every caller
/// is a committed timer sleeper (or the tick handler's nearest sleeper), so an
/// interrupt that programs the comparator after this read programs at most
/// this deadline (each writer takes the nearest sleeper into account). The
/// write path re-checks and writes under one interrupt mask, so an interrupt
/// cannot program an earlier instant between the check and the write that
/// this would then overwrite.
///
/// Every caller runs with interrupts already masked (the block commit and the
/// dispatch in the scheduler, the tick handlers), which is what keeps the hart
/// read first the hart of the comparator written last; a caller with them on
/// would have to mask around the call.
#[inline]
pub fn arm_if_earlier(deadline: u64) -> bool {
    use azos_arch::Interrupts;
    // percpu-hint: contract: every caller runs with interrupts masked (the dispatch, the tick handlers, the wake commit), so the hart cannot change; the record read is not a hint
    let cpu = azos_arch::ARCH.hart_id();
    let Some(slot) = PROGRAMMED.get(cpu) else { return false };
    if !timer_arm::earlier_than_programmed(slot.load(Ordering::Relaxed), deadline) {
        return false;
    }
    let prev = azos_arch::ARCH.disable_all();
    let wrote = timer_arm::earlier_than_programmed(slot.load(Ordering::Relaxed), deadline);
    if wrote {
        set_timer(cpu as u32, deadline);
        slot.store(deadline, Ordering::Relaxed);
    }
    azos_arch::ARCH.restore(prev);
    wrote
}

/// Program the calling hart's comparator for an absolute instant, recorded.
/// For the aarch64 tick handler, which arms the next tick before the end of
/// interrupt and the nearest sleeper (through [`arm_if_earlier`]) after its
/// wake sweep.
#[inline]
pub fn program_at(_hart: u32, next: u64) {
    if stop_wanted() {
        program(now().saturating_add(stop_bound()), true);
    } else {
        program(next, false);
    }
}

/// What the calling hart last programmed ([`timer_arm::NOT_ARMED`] if
/// never, or if the hart is beyond the recorded range).
pub fn programmed() -> u64 {
    // percpu-hint: read for a decision its callers take masked (dispatch, tick, idle)
    PROGRAMMED.get(azos_arch::ARCH.hart_id())
        .map_or(timer_arm::NOT_ARMED, |s| s.load(Ordering::Relaxed))
}

// ── A busy hart's stopped tick (Kconfig NOHZ_FULL) ─────────────────────────
//
// The scheduler tells this file, through a hook it registers once the
// topology's `isolcpus` is known, that the calling hart runs one real-time
// task alone and nothing needs its periodic tick. The three places that
// re-arm the tick of a busy hart ([`set_next_tick_smart`], the riscv64
// handler's; [`program_at`], aarch64's and x86_64's) then program the later
// instant [`stop_bound`] gives, and record that the tick is stopped. Every
// other programming of the comparator clears the record: a stop lasts until
// the next ordinary re-arm, which the scheduler's enqueue and switch paths
// ([`tick_restart`], `set_next_tick_tickless`) and the stopped tick's own
// interrupt all are.

azos_common::ro_hook! {
    /// `fn() -> bool`: may the calling hart's periodic tick stop now? Called
    /// from the tick handler, interrupts off, on the hart in question. Registered
    /// once ([`set_tick_stop_hook`]); unset = never.
    static TICK_STOP_HOOK: fn() -> bool;
}

/// Per hart: the comparator holds a stopped tick's instant, not a periodic
/// one. Written only by that hart ([`program`]).
static STOPPED: [AtomicBool; ARM_HARTS] = [const { AtomicBool::new(false) }; ARM_HARTS];

/// Register the tick-stop hook (once, when the scheduler learns which CPUs
/// are isolated; Kconfig NOHZ_FULL).
pub fn set_tick_stop_hook(f: fn() -> bool) {
    TICK_STOP_HOOK.set(f);
}

/// Does the calling hart's comparator hold a stopped tick? One relaxed load.
#[inline(always)]
pub fn tick_stopped() -> bool {
    // percpu-hint: its callers are masked (tick_restart masks, the dispatch and the tick handlers run with interrupts off)
    STOPPED.get(azos_arch::ARCH.hart_id()).is_some_and(|f| f.load(Ordering::Relaxed))
}

/// Does the hook say the calling hart's tick may stop? Note the hook advances
/// the scheduler's per-CPU count of ticks that saw the same lone task, so
/// this is called once per re-arm.
#[inline]
fn stop_wanted() -> bool {
    // A hart past the records ([`ARM_HARTS`]) has no flag to say it stopped,
    // so nothing would restore its tick: it never stops.
    // percpu-hint: only called by the callers of program(), which are masked (tick handlers, dispatch) or hold the mask (tick_restart)
    if !azos_limits::NOHZ_FULL || azos_arch::ARCH.hart_id() >= ARM_HARTS {
        return false;
    }
    match TICK_STOP_HOOK.get() {
        Some(f) => f(),
        None => false,
    }
}

/// How far out a stopped tick sleeps, in counter ticks ([`nohz::stop_bound`]):
/// `NOHZ_FULL_RESIDUAL_MS`, cut to the watchdog keepalive on hart 0 while one
/// is armed and to [`IDLE_POLL_US`] while the idle-poll hook (or a stranded
/// console) asks, as an idle hart's sleep is.
#[inline]
fn stop_bound() -> u64 {
    // percpu-hint: only called by the callers of program(), which are masked (tick handlers, dispatch)
    let keepalive = if azos_arch::ARCH.hart_id() == 0 { idle_keepalive_ticks() } else { None };
    let poll = if idle_poll_wanted() {
        Some(TIMER_FREQ.saturating_mul(IDLE_POLL_US) / 1_000_000)
    } else {
        None
    };
    nohz::stop_bound(
        TIMER_FREQ.saturating_mul(azos_limits::NOHZ_FULL_RESIDUAL_MS as u64) / 1_000,
        keepalive,
        poll,
    )
}

/// A task became ready on the calling hart, or its doorbell rang: end a
/// stopped tick. The
/// comparator moves to the earlier of what it holds (the nearest timer
/// deadline or enforcement instant, kept by [`arm_if_earlier`]) and one tick
/// period out. Nothing when the tick is running; no scheduler state is read,
/// so it is safe under the queue's caller.
#[inline]
pub fn tick_restart() {
    // Masked: the flag, the record and the write are this hart's, and a task
    // context (a wake on the CPU it runs on) can be moved between them.
    use azos_arch::Interrupts;
    let prev = azos_arch::ARCH.disable_all();
    if tick_stopped() {
        let period_end = now().saturating_add(TIMER_FREQ / sched_hz_get());
        let held = programmed();
        program(if held != timer_arm::NOT_ARMED && held < period_end { held } else { period_end }, false);
    }
    azos_arch::ARCH.restore(prev);
}

/// Schedule the next periodic tick at the configured rate (default 100 Hz).
pub fn set_next_tick(_hart: u32) {
    program(now() + TIMER_FREQ / sched_hz_get(), false);
}

/// M03: Tickless timer — schedule the timer at the earliest useful deadline.
///
/// `nearest_deadline` is the earliest pending `WaitReason::Timer(t)` deadline
/// from the scheduler (pass `azos_sched::nearest_timer_deadline()`).
/// If `None`, falls back to the standard periodic tick.
///
/// Programs the hardware timer at `min(nearest_deadline, next_periodic_tick)`
/// so sleeping tasks wake at exactly the right time while preemption still
/// fires.
///
/// On a CPU the scheduler says may stop its tick ([`set_tick_stop_hook`]) the
/// periodic clamp is replaced by [`stop_bound`]: the same call, the same
/// nearest-deadline fold, a later cap.
pub fn set_next_tick_smart(_hart: u32, nearest_deadline: Option<u64>) {
    if stop_wanted() {
        program(timer_arm::next_event(
            now(), nearest_deadline, timer_arm::Cap::IdleKeepalive,
            TIMER_FREQ / sched_hz_get(), stop_bound(), 0,
        ), true);
    } else {
        program(timer_arm::next_event(
            now(), nearest_deadline, timer_arm::Cap::Busy,
            TIMER_FREQ / sched_hz_get(), 0, 0,
        ), false);
    }
}

// ── M04: true tickless — the owner decision of 2026-09-25 ──────────────────
//
// `set_next_tick_smart` above is the M03 "tickless" scheduler's actual
// behaviour: `now() + TIMER_FREQ / sched_hz_get()` is computed and folded
// into the `min` UNCONDITIONALLY, so an idle hart is reprogrammed for "one
// ordinary tick period from now" forever — the periodic clamp this module's
// own doc calls out as never dropped. That is the gap the owner decision
// names FALSE: an idle hart never actually sleeps past one tick.
//
// [`set_next_tick_tickless`] is the fix. It is a distinct function, not a
// rewrite of `set_next_tick_smart` in place, because `set_next_tick_smart`'s
// signature is called from `kernel/src/entry/riscv64/irq.rs` (riscv64's timer ISR,
// outside this wave's file ownership) and changing that call site is not
// this wave's to make. The real caller for the new behaviour is
// `crates/core/sched/src/scheduler.rs`'s `do_schedule()`, at the two places a
// hart's dispatch enters or leaves the idle task — see that function's own
// comments for why THAT is the correct hook and not the ISR: the idle
// task's own loop (`wfi(); task_yield();`) runs `do_schedule()` on every
// wakeup regardless of what triggered it (tick or IPI), so re-arming there
// with a freshly-computed `nearest_timer_deadline()` is strictly more
// current than anything the ISR could compute before that same tick's own
// wake/reap sweep has even run — and it is reached whether the hart went
// idle from a tick, a yield, or a block.

/// Hart 0's idle keepalive (owner decision, wave 13 round 50).
///
/// Hart 0 alone feeds the hardware watchdog, from its timer interrupt
/// (`azos_actuation::watchdog::feed_from_timer_tick`, gated
/// `hart_id() == 0`), so an idle hart 0 must still take a timer interrupt
/// often enough to feed it — **but only while a watchdog is armed**
/// ([`crate::wdt::armed_timeout_ms`]). The period is the armed timeout over
/// [`timer_arm::KEEPALIVES_PER_TIMEOUT`] (4): 125 ms for the 500 ms default
/// `watchdog_ms`, so three consecutive keepalives can be lost or late before
/// the watchdog fires. With none armed (QEMU, K1: no watchdog node) an idle
/// hart 0 is as tickless as the others.
///
/// What the old fixed 100 ms keepalive also carried, and where it went:
///
/// * the vDSO timing page: refreshed when an idle hart wakes (the idle loop),
///   and by every timer interrupt as before;
/// * the deadlines only the tick observes (the K-C25 reaper of
///   orphaned wake stamps, a stranded console residual): the kernel registers
///   [`set_idle_poll_hook`]; while it answers `true` an idle hart arms at most
///   [`IDLE_POLL_US`] out, the old keepalive's bound.
#[inline]
fn idle_keepalive_ticks() -> Option<u64> {
    timer_arm::keepalive_us(crate::wdt::armed_timeout_ms())
        .map(|us| TIMER_FREQ.saturating_mul(us) / 1_000_000)
}

/// While the idle-poll hook answers `true`, an idle hart sleeps at most this
/// long (the bound the old fixed keepalive gave).
pub const IDLE_POLL_US: u64 = 100_000;

azos_common::ro_hook! {
    /// `fn() -> bool`: is some deadline pending that only a timer interrupt will
    /// observe? Registered once by the kernel at boot ([`set_idle_poll_hook`]);
    /// unset = never.
    static IDLE_POLL_HOOK: fn() -> bool;
}

/// Register the idle-poll hook (see [`IDLE_POLL_US`]).
pub fn set_idle_poll_hook(f: fn() -> bool) {
    IDLE_POLL_HOOK.set(f);
}

#[inline]
fn idle_poll_wanted() -> bool {
    if crate::uart::console_stranded() {
        return true;
    }
    match IDLE_POLL_HOOK.get() {
        Some(f) => f(),
        None => false,
    }
}

/// Hart 0's idle keepalive period in microseconds, `None` with no watchdog
/// armed (for the boot log).
pub fn idle_keepalive_us() -> Option<u64> {
    timer_arm::keepalive_us(crate::wdt::armed_timeout_ms())
}

/// Ceiling on how long a genuinely idle NON-hart-0 hart may go without its
/// own timer firing, when nothing is sleeping and nothing is ready to run on
/// it. The real wake path for such a hart is the cross-hart IPI/SGI
/// (`cpu_enqueue_locked` → `Interrupts::send_ipi`, K-C15) — this ceiling is a
/// self-heal bound against a missed or lost doorbell, not the intended wake
/// mechanism, so it is set far outside any latency budget this kernel
/// measures (vsbench's worst-case `ipc-rt` lane is single-digit
/// ms): a hart can never go PERMANENTLY silent from this path, whatever else
/// is wrong, but it also never fires "for no reason" at any rate a
/// benchmark would notice.
const IDLE_HART_CEILING_US: u64 = 60_000_000;

/// M04: true tickless — schedule the timer for a hart whose idle/busy state
/// is already known to the caller.
///
/// `nearest_deadline` is `azos_sched::nearest_timer_deadline()`, as for
/// [`set_next_tick_smart`]. `hart_idle` is the caller's own "no runnable
/// task" test — see `crates/core/sched/src/scheduler.rs::do_schedule()`'s two
/// call sites for the exact test used (the task the scheduler just picked,
/// or the task it just switched away from, has `IDLE_PRIORITY`) and why
/// nothing coarser (a ready-queue peek alone) is needed: `do_schedule()`
/// already proves "nothing higher-priority was ready" by construction
/// whenever its own pick IS the idle task.
///
/// - Not idle: identical to [`set_next_tick_smart`] — the periodic quantum
///   clamp `min`-ed with the nearest sleep deadline. Unchanged behaviour,
///   for RR/quantum preemption once a real task is dispatched.
/// - Idle, hart 0, a watchdog armed: clamped to the keepalive derived from
///   its timeout (`idle_keepalive_ticks`), `min`-ed with the nearest sleep
///   deadline, so the feed still gets a timer interrupt.
/// - Idle, any hart, the idle-poll hook (or a stranded console) asking:
///   clamped to [`IDLE_POLL_US`].
/// - Idle otherwise (hart 0 included when no watchdog is armed): no periodic
///   clamp — armed at the nearest sleep deadline if one exists, else
///   [`IDLE_HART_CEILING_US`] out. A wake arrives by IPI or device interrupt.
///
/// `saturating_mul`/`saturating_add` throughout: this runs with
/// `overflow-checks = true` in the same build as the timer ISR, and a
/// panicking arithmetic overflow here is a board reset, not a bug report.
///
/// Returns the absolute deadline actually programmed (`now()`'s units) for
/// the caller's own measurement.
pub fn set_next_tick_tickless(hart: u32, nearest_deadline: Option<u64>, hart_idle: bool) -> u64 {
    let keepalive = if hart_idle && hart == 0 { idle_keepalive_ticks() } else { None };
    let poll = hart_idle && keepalive.is_none() && idle_poll_wanted();
    let cap = if !hart_idle {
        timer_arm::Cap::Busy
    } else if keepalive.is_some() || poll {
        timer_arm::Cap::IdleKeepalive
    } else {
        timer_arm::Cap::IdleCeiling
    };
    let keepalive = match keepalive {
        Some(k) => k,
        None => TIMER_FREQ.saturating_mul(IDLE_POLL_US) / 1_000_000,
    };
    let next = timer_arm::next_event(
        now(), nearest_deadline, cap,
        TIMER_FREQ / sched_hz_get(),
        keepalive,
        TIMER_FREQ.saturating_mul(IDLE_HART_CEILING_US) / 1_000_000,
    );
    program(next, false);
    next
}
