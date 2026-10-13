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
use core::sync::atomic::{AtomicU64, Ordering};

use crate::timer_arm;

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
/// Re-exported here rather than left in `clint` for the same reason as [`now`]:
/// 82 call sites read it as `clint::TIMER_FREQ`, and the CLINT is a device only
/// one ISA has. The value still comes from the board's own timer, whatever
/// programs it.
pub use azos_drv_irqchip::clint::TIMER_FREQ;

// ── Scheduler tick rate ────────────────────────────────────────────────────
//
// This has **no ISA content whatsoever**: a `u32` between 10 and 10_000 that
// says how often the kernel wants to be interrupted. It sat in `clint` — a
// RISC-V interrupt-controller module — purely because that is where the code
// that consumes it lives.
//
// It stays in `azos_drv_sys` rather than moving to `azos_sched`, which
// is where it conceptually belongs, because `clint::set_next_tick` reads it to
// compute the next deadline and `drivers` does not depend on `sched` (the edge
// runs the other way). Moving it would invert that for a single integer.

/// Set the scheduler tick rate in Hz (10..=10_000). Out-of-range is ignored —
/// a tick rate of 0 would divide by zero in `set_next_tick`, and one of
/// 10^9 would spend the whole CPU in the timer ISR.
#[inline(always)]
pub fn sched_hz_set(hz: u64) {
    azos_drv_irqchip::clint::sched_hz_set(hz);
}

/// Get the scheduler tick rate in Hz.
#[inline(always)]
pub fn sched_hz_get() -> u64 {
    azos_drv_irqchip::clint::sched_hz_get()
}

// ── Scheduling the next tick ───────────────────────────────────────────────
//
// **Moved here from `clint`, not copied.** The arithmetic below — "now plus
// one tick period", "the earlier of that and the nearest sleeping deadline" —
// is scheduling policy with no ISA content at all. What IS per-ISA is the last
// line of each: programming the hardware, which on RISC-V means choosing
// between the `stimecmp` CSR and an SBI ecall (`clint::set_timer`) and on
// aarch64 means writing `CNTV_CVAL_EL0`.
//
// Keeping the policy in a module named after a RISC-V interrupt controller is
// what made these two functions read as ISA-specific when only one line of
// each is.

// ── The comparator's one writer (wave 11 ONESHOT, RFC-0052 §4.5) ──────────
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

/// Program the calling hart's comparator for `next` and record it. A value
/// equal to the record is not written again (the block-then-idle sequence
/// computes the same instant twice).
#[inline]
fn program(next: u64) {
    use azos_arch::Interrupts;
    let cpu = azos_arch::ARCH.hart_id();
    let prev = azos_arch::ARCH.disable_all();
    match PROGRAMMED.get(cpu) {
        Some(slot) => {
            if slot.load(Ordering::Relaxed) != next {
                azos_drv_irqchip::clint::set_timer(cpu as u32, next);
                slot.store(next, Ordering::Relaxed);
            }
        }
        None => azos_drv_irqchip::clint::set_timer(cpu as u32, next),
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
#[inline]
pub fn arm_if_earlier(deadline: u64) -> bool {
    use azos_arch::Interrupts;
    let cpu = azos_arch::ARCH.hart_id();
    let Some(slot) = PROGRAMMED.get(cpu) else { return false };
    if !timer_arm::earlier_than_programmed(slot.load(Ordering::Relaxed), deadline) {
        return false;
    }
    let prev = azos_arch::ARCH.disable_all();
    let wrote = timer_arm::earlier_than_programmed(slot.load(Ordering::Relaxed), deadline);
    if wrote {
        azos_drv_irqchip::clint::set_timer(cpu as u32, deadline);
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
    program(next);
}

/// What the calling hart last programmed ([`timer_arm::NOT_ARMED`] if
/// never, or if the hart is beyond the recorded range).
pub fn programmed() -> u64 {
    PROGRAMMED.get(azos_arch::ARCH.hart_id())
        .map_or(timer_arm::NOT_ARMED, |s| s.load(Ordering::Relaxed))
}

/// Schedule the next periodic tick at the configured rate (default 100 Hz).
pub fn set_next_tick(_hart: u32) {
    program(now() + TIMER_FREQ / sched_hz_get());
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
pub fn set_next_tick_smart(_hart: u32, nearest_deadline: Option<u64>) {
    program(timer_arm::next_event(
        now(), nearest_deadline, timer_arm::Cap::Busy,
        TIMER_FREQ / sched_hz_get(), 0, 0,
    ));
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
// signature is called from `kernel/src/trap/interrupt.rs` (riscv64's timer ISR,
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
/// * the deadlines only the tick observes (lease expiry, the K-C25 reaper of
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

/// `fn() -> bool`: is some deadline pending that only a timer interrupt will
/// observe? Registered once by the kernel at boot ([`set_idle_poll_hook`]);
/// null = never.
static IDLE_POLL_HOOK: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Register the idle-poll hook (see [`IDLE_POLL_US`]).
pub fn set_idle_poll_hook(f: fn() -> bool) {
    IDLE_POLL_HOOK.store(f as *mut (), Ordering::Release);
}

#[inline]
fn idle_poll_wanted() -> bool {
    if crate::uart::console_stranded() {
        return true;
    }
    let p = IDLE_POLL_HOOK.load(Ordering::Acquire);
    if p.is_null() {
        return false;
    }
    // SAFETY: only `set_idle_poll_hook` stores here, always a `fn() -> bool`.
    let f: fn() -> bool = unsafe { core::mem::transmute(p) };
    f()
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
    program(next);
    next
}
