// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 scheduler self-tests that run on every boot of that ISA: Phase 3
//! (two preempted tasks on one hart, x20/FP across a switch) and Phase 4 (the
//! cross-core migration probe).

use crate::*;

// ═════════════════════════════════════════════════════════════════════
// Phase 3 (context switch + scheduler on aarch64) — two kernel tasks,
// preempted by the real timer-driven scheduler (`crates/core/sched`, the SAME
// scheduler riscv64 uses — see `entry/aarch64/asm/context_switch.S` and
// `entry::aarch64::aarch64_trap_resched`). Neither task ever calls
// `task_yield()` or blocks on anything: the ONLY way either one stops
// running mid-loop is a tick reaching `aarch64_trap_resched` and
// `schedule()` deciding to time-slice it out. That is the whole point —
// a cooperative fallback would prove nothing about the scheduler.
// ═════════════════════════════════════════════════════════════════════

/// Kernel-task loop iterations to run before a task reports done. Small
/// and fast on purpose: this milestone only needs to OBSERVE preemption,
/// not stress it, and the gate boots this row with a bounded QEMU run.
#[cfg(target_arch = "aarch64")]
pub(crate) const PHASE3_TARGET_ITERS: u64 = 60;

/// The one hart phase 3's two tasks share — the boot hart, the only one every
/// `-smp` value has.
#[cfg(target_arch = "aarch64")]
pub(crate) const PHASE3_HART: i8 = 0;

/// Busy-work length per iteration, in `subs`/`b.ne` pairs (2 instructions
/// each) — real spinning, not a `wfi`, so the tick can land at any point
/// inside it. At the 100 Hz tick this kernel arms (`AARCH64_SCHED_HZ` in
/// `kernel_main`, ~10 ms/period) and QEMU TCG's emulation rate, this is
/// long enough that most iterations span at least one tick boundary —
/// verified empirically for this task's own canary run, not assumed.
#[cfg(target_arch = "aarch64")]
const PHASE3_SPIN_COUNT: u64 = 600_000;

/// Distinct 64-bit patterns for task A/B's x20 canary — chosen so a value
/// that leaked from the OTHER task (or survived from neither) reads back
/// as neither pattern, never a plausible "looks right by luck" collision.
#[cfg(target_arch = "aarch64")]
const PHASE3_PATTERN_A: u64 = 0xA5A5_0000_0000_A001;
#[cfg(target_arch = "aarch64")]
const PHASE3_PATTERN_B: u64 = 0xB5B5_0000_0000_B002;

#[cfg(target_arch = "aarch64")]
static PHASE3_ITERS_A: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
static PHASE3_ITERS_B: AtomicU64 = AtomicU64::new(0);

/// Set if A ever read back an `x20` other than [`PHASE3_PATTERN_A`] from
/// [`phase3_spin_with_x20`]. **This does NOT test `context_switch.S`.**
/// Every preemption this phase is taken as a timer IRQ, and
/// `entry/aarch64/asm/trap_entry.S`'s `_trap_common`/`trap_return` already
/// save/restore every GPR around every trap that reaches Rust — by the
/// time `context_switch.S` ever touches `x20`, the value already came from
/// a `TrapFrame`. What this DOES prove is that a preemption never corrupts
/// a task's `x20`, end to end. The canary that actually exercises
/// `context_switch.S`'s own AAPCS64 x19-x28 save/restore is
/// [`phase3_probe_x20_across_yield`], below; both must pass for
/// `fp_a_ok`/`fp_b_ok` in `phase3_task_done` (names kept from when this
/// probe used `d8`).
#[cfg(target_arch = "aarch64")]
static PHASE3_FP_MISMATCH_A: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "aarch64")]
static PHASE3_FP_MISMATCH_B: AtomicBool = AtomicBool::new(false);

/// Set if A's `x20` did not survive [`phase3_probe_x20_across_yield`] — the
/// canary that actually reaches `context_switch.S`'s own callee-saved GPR
/// save/restore. `task_yield()` puts a task through `do_schedule()` ->
/// `context_switch()` with NO `TrapFrame` in front of it (no IRQ, no ESR,
/// no vector) — the only thing that could preserve `x20` across it is
/// `context_switch.S` itself. See [`PHASE3_FP_MISMATCH_A`]'s doc comment
/// for why the spin-loop canary alone cannot make this claim.
#[cfg(target_arch = "aarch64")]
static PHASE3_YIELD_FP_MISMATCH_A: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "aarch64")]
static PHASE3_YIELD_FP_MISMATCH_B: AtomicBool = AtomicBool::new(false);

/// Interleaving proof (not just "both counters eventually reached N" —
/// that would also be true of A running to completion, then B, with no
/// preemption at all if nothing else dispatched them). Each task samples
/// the OTHER's counter after every one of its own increments; if it ever
/// observes a nonzero value there BEFORE IT ITSELF is done, the two were
/// genuinely interleaved rather than run sequentially.
#[cfg(target_arch = "aarch64")]
static PHASE3_A_SAW_B_PROGRESS: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "aarch64")]
static PHASE3_B_SAW_A_PROGRESS: AtomicBool = AtomicBool::new(false);

/// First task to finish just records the fact; the second one prints the
/// verdict, so exactly one of the two writes the marker line (no extra
/// synchronization needed — an `AtomicU32::fetch_add` is enough to tell
/// "am I first or second" apart without a lock).
#[cfg(target_arch = "aarch64")]
static PHASE3_FINISHERS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Real, uninterruptible busy-work: `pattern` goes into `x20`, then a tight
/// `subs`/`b.ne` loop spins `spins` times, then `x20` is read back — all in
/// ONE inline-asm block (mirrors `entry::aarch64::fp_survives_interrupt_probe`'s
/// own reasoning) so nothing the COMPILER does can touch the physical `x20`
/// in between; only real hardware — an interrupt landing mid-spin, and
/// whatever `context_switch.S` does or fails to do with `x20` across it —
/// can change what comes back.
///
/// `x20`, not `d8` as before: the aarch64 kernel is soft-float (built for
/// `aarch64-unknown-none-softfloat`) and kernel tasks may not hold FP/SIMD
/// state at all, exactly like Linux kernel threads. The property kept is
/// the one that still applies — a callee-saved register survives
/// preemption and `context_switch`.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
fn phase3_spin_with_x20(pattern: u64, spins: u64) -> u64 {
    let readback: u64;
    unsafe {
        core::arch::asm!(
            "mov x20, {pattern}",
            "mov {ctr}, {spins}",
            "20:",
            "subs {ctr}, {ctr}, #1",
            "b.ne 20b",
            "mov {out}, x20",
            pattern = in(reg) pattern,
            spins = in(reg) spins,
            ctr = out(reg) _,
            out = out(reg) readback,
            out("x20") _,
            options(nomem, nostack),
        );
    }
    readback
}

/// `extern "C"` trampoline so [`phase3_probe_x20_across_yield`] can `bl` into
/// `azos_sched::task_yield()` from inside a raw `asm!` block. Needed
/// because `sym` in `asm!` wants an item with a definite, ABI-checkable
/// call convention, and `task_yield`'s own signature is plain Rust
/// (`pub fn task_yield()`) — this wrapper is the same shape as
/// `entry::aarch64::aarch64_trap_resched`, just facing Rust-called-from-asm
/// instead of asm-called-from-Rust.
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
extern "C" fn phase3_yield_shim() {
    azos_sched::task_yield();
}

/// The canary that actually exercises `context_switch.S`'s own x19-x28
/// save/restore (see [`PHASE3_FP_MISMATCH_A`]'s doc comment for why
/// [`phase3_spin_with_x20`] cannot make this claim). `pattern` goes into
/// `x20`, then `bl`s straight into [`phase3_yield_shim`] -> `task_yield()`
/// -> `do_schedule()` -> `context_switch()`, with NO trap frame anywhere in
/// that call chain, then reads `x20` back — all as ONE inline-asm block
/// (same "nothing the compiler does in between" reasoning as
/// `phase3_spin_with_x20` and `entry::aarch64::fp_survives_interrupt_probe`).
/// `clobber_abi("C")` tells the compiler this `bl` is a real AAPCS64 call:
/// every CALLER-saved register may come back changed, but `x20` (callee-
/// saved) must not — exactly the property this is checking `context_switch.S`
/// upholds.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
fn phase3_probe_x20_across_yield(pattern: u64) -> u64 {
    let readback: u64;
    unsafe {
        core::arch::asm!(
            "mov x20, x9",
            "bl {yield_fn}",
            "mov x10, x20",
            in("x9") pattern,
            yield_fn = sym phase3_yield_shim,
            lateout("x10") readback,
            out("x20") _,
            clobber_abi("C"),
        );
    }
    readback
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn phase3_task_a(_arg: usize) {
    for i in 0..PHASE3_TARGET_ITERS {
        let readback = phase3_spin_with_x20(PHASE3_PATTERN_A, PHASE3_SPIN_COUNT);
        if readback != PHASE3_PATTERN_A {
            PHASE3_FP_MISMATCH_A.store(true, Ordering::Relaxed);
        }
        PHASE3_ITERS_A.fetch_add(1, Ordering::Relaxed);
        if i + 1 < PHASE3_TARGET_ITERS && PHASE3_ITERS_B.load(Ordering::Relaxed) > 0 {
            PHASE3_A_SAW_B_PROGRESS.store(true, Ordering::Relaxed);
        }
    }
    // Runs once, after the round-robin proof above is already complete, so
    // this deliberate extra `task_yield()` cannot be mistaken for part of
    // the "neither task ever yields" preemption proof.
    let yield_readback = phase3_probe_x20_across_yield(PHASE3_PATTERN_A);
    if yield_readback != PHASE3_PATTERN_A {
        PHASE3_YIELD_FP_MISMATCH_A.store(true, Ordering::Relaxed);
    }
    phase3_task_done("A");
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn phase3_task_b(_arg: usize) {
    for i in 0..PHASE3_TARGET_ITERS {
        let readback = phase3_spin_with_x20(PHASE3_PATTERN_B, PHASE3_SPIN_COUNT);
        if readback != PHASE3_PATTERN_B {
            PHASE3_FP_MISMATCH_B.store(true, Ordering::Relaxed);
        }
        PHASE3_ITERS_B.fetch_add(1, Ordering::Relaxed);
        if i + 1 < PHASE3_TARGET_ITERS && PHASE3_ITERS_A.load(Ordering::Relaxed) > 0 {
            PHASE3_B_SAW_A_PROGRESS.store(true, Ordering::Relaxed);
        }
    }
    let yield_readback = phase3_probe_x20_across_yield(PHASE3_PATTERN_B);
    if yield_readback != PHASE3_PATTERN_B {
        PHASE3_YIELD_FP_MISMATCH_B.store(true, Ordering::Relaxed);
    }
    phase3_task_done("B");
}

/// Common tail for both tasks. The SECOND task to arrive here (the one
/// that finds `PHASE3_FINISHERS` already at 1) prints the verdict and
/// reads every marker back rather than asserting: `FAILED:` on any
/// violation (the gate's existing grep already fails a row on that
/// prefix), a plain pass line otherwise. Both tasks then return, which
/// hands them to `task_exit()` — the kernel idles in `azos_sched`'s
/// own WFI loop afterward, same as riscv64 once every task exits.
#[cfg(target_arch = "aarch64")]
fn phase3_task_done(name: &str) {
    if PHASE3_FINISHERS.fetch_add(1, Ordering::AcqRel) == 0 {
        // First finisher: nothing to report yet, the other task may still
        // be mid-run.
        let _ = name;
        return;
    }

    let iters_a = PHASE3_ITERS_A.load(Ordering::Relaxed);
    let iters_b = PHASE3_ITERS_B.load(Ordering::Relaxed);
    let preempts = entry::aarch64::PREEMPT_COUNT.load(Ordering::Relaxed);
    // Both canaries must pass — the spin-loop one (every preemption is
    // survivable end to end) AND the yield one (`context_switch.S`'s own
    // x19-x28 save/restore specifically). See `PHASE3_FP_MISMATCH_A`'s doc
    // comment for why the first alone cannot make this claim.
    let fp_a_ok = !PHASE3_FP_MISMATCH_A.load(Ordering::Relaxed)
        && !PHASE3_YIELD_FP_MISMATCH_A.load(Ordering::Relaxed);
    let fp_b_ok = !PHASE3_FP_MISMATCH_B.load(Ordering::Relaxed)
        && !PHASE3_YIELD_FP_MISMATCH_B.load(Ordering::Relaxed);
    let interleaved = PHASE3_A_SAW_B_PROGRESS.load(Ordering::Relaxed)
        && PHASE3_B_SAW_A_PROGRESS.load(Ordering::Relaxed);

    kprintln!();
    if iters_a < PHASE3_TARGET_ITERS || iters_b < PHASE3_TARGET_ITERS {
        kprintln!("[SCHED] FAILED: task A ran {} times, task B ran {} times (need >= {} each)",
            iters_a, iters_b, PHASE3_TARGET_ITERS);
    } else if preempts == 0 {
        kprintln!("[SCHED] FAILED: task A and B both completed but PREEMPT_COUNT is 0 — \
                   the timer never asked for a reschedule");
    } else if !interleaved {
        kprintln!("[SCHED] FAILED: task A and B did not interleave — one ran to completion \
                   before the other made any progress (A_saw_B={} B_saw_A={})",
            PHASE3_A_SAW_B_PROGRESS.load(Ordering::Relaxed),
            PHASE3_B_SAW_A_PROGRESS.load(Ordering::Relaxed));
    } else if !fp_a_ok || !fp_b_ok {
        kprintln!("[SCHED] FAILED: x20 did not survive a context switch (task A ok={} task B ok={})",
            fp_a_ok, fp_b_ok);
    } else {
        kprintln!("[SCHED] task A ran {} times, task B ran {} times, interleaved", iters_a, iters_b);
        kprintln!("[SCHED] preemptions observed: {}", preempts);
        kprintln!("[SCHED] x20 survived every context switch on both tasks (task A, task B)");
    }
}

// ═════════════════════════════════════════════════════════════════════
//  Phase 4 (SMP): idle-per-hart task, the cross-core migration probe, and
//  the secondary hart's own Rust entry point. `phase3_task_a`/`b` above are
//  UNCHANGED — they still prove single-hart preemption; these are new,
//  additive tasks for the SMP-specific markers this phase's brief asks for.
// ═════════════════════════════════════════════════════════════════════

/// Iterations the migration probe blocks-and-wakes for. Small: this only
/// needs to give `find_best_cpu` a handful of chances to place the task, not
/// stress the scheduler, and the gate boots this row with a bounded QEMU run.
#[cfg(target_arch = "aarch64")]
const SMP_MIGRATE_PROBE_ITERS: u32 = 10;

/// Bitmask of every `current_cpu_id()` [`aarch64_migrate_probe_task`] ever
/// observed itself running on, bit N = core N. Published once, after the
/// loop finishes, read back nowhere else in this kernel — the task prints
/// its own verdict (see its own doc comment for why: unlike the online/SGI
/// markers, there is no separate reader to hand this to before the task
/// exits).
#[cfg(target_arch = "aarch64")]
static SMP_MIGRATE_CPU_MASK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Task 7 of this phase's brief: prove (or honestly disprove) that a task
/// can be picked up by another core over its lifetime.
///
/// `phase3_task_a`/`b` cannot answer this — they never yield or block, so
/// they are dispatched once and stay on whichever core's ready queue holds
/// them (this scheduler has no runtime work-stealing; see
/// `crates/core/sched::scheduler::rebalance_from_offline_cpus`'s own doc for the
/// confirmation nothing has been added). `crates/core/sched::scheduler::
/// wake_target_cpu` — the ONLY placement decision that runs on every wake
/// for an unpinned task — reruns `find_best_cpu` fresh each time, so a task
/// that blocks and is woken repeatedly gives the scheduler a genuine,
/// repeated opportunity to place it on a different core. Whether it
/// actually DOES, on a `-smp 2` boot with only a handful of other tasks
/// (two idle, two spinners), is an empirical question this task answers by
/// printing what it observes — not by asserting a specific outcome.
#[cfg(target_arch = "aarch64")]
pub(crate) fn aarch64_migrate_probe_task(_arg: usize) {
    use azos_arch::{Cpu, ARCH};

    let mut mask: u32 = 0;
    for _ in 0..SMP_MIGRATE_PROBE_ITERS {
        let cpu = azos_sched::smp::current_cpu_id();
        if cpu < 32 {
            mask |= 1 << cpu;
        }
        let hz = azos_arch::timer::freq_hz();
        // ~50 ms of real time per wake — long enough that the timer tick
        // (100 Hz, ~10 ms period) reliably fires the `wake_expired_timers`
        // sweep that wakes this task (`entry::aarch64::handle_irq`'s timer
        // arm) well before the next iteration, short enough that 10
        // iterations fit comfortably inside the gate's bounded QEMU run.
        let delay_ticks = if hz == 0 { 1 } else { core::cmp::max(1, hz / 20) };
        let deadline = ARCH.now_ticks().wrapping_add(delay_ticks);
        azos_sched::task_block(azos_sched::WaitReason::Timer(deadline));
    }

    SMP_MIGRATE_CPU_MASK.store(mask, Ordering::Release);
    let distinct = mask.count_ones();
    if distinct > 1 {
        // MARKER, asserted by the gate.
        kprintln!("[SMP] smp-migrate-probe ran on {} distinct core(s) over its lifetime \
                   (mask={:#010b}) — a task migrated between cores", distinct, mask);
    } else {
        kprintln!("[SMP] smp-migrate-probe ran on {} core (mask={:#010b}) — no migration \
                   observed this run", distinct, mask);
    }
}
