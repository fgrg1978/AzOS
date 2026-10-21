// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `current_cpu_id()` cross-check at boot (cargo feature `cpuid-probe`, gate
//! only; the counters live in `azos_sched::cpuid_probe`).
//!
//! The 2026-09-25 observation this answers: a `fork` the boot hart issued at
//! the end of `kernel_main` printed `rc=0`. The probe checks the property that
//! reading would need to have failed — `current_cpu_id()` on that hart, at
//! that position, while the secondaries run tasks — and keeps checking every
//! `current_cpu_id()` call on every hart afterwards.
//!
//! The iteration and reporting counts are instrument settings of a probe no
//! product build compiles, not tunables, so they are not Kconfig symbols.

use azos_drv_sys::kprintln;

/// Boot-hart reads of `current_cpu_id()` + `current_user_pt()` at the old
/// position (about 60 instructions each: 12 M under `-icount`).
const HAMMER_ITERS: u32 = 200_000;
/// Totals are printed this many times, one second apart: long enough for a
/// disk workload (the gate's `ipctest`) to run to its verdict in between.
const REPORTS: u32 = 120;
/// Canary attempts per report tick.
#[cfg(feature = "cpuid-probe-canary")]
const CANARY_TRIES: u32 = 20_000;

fn ticks_per_second() -> u64 {
    #[cfg(target_arch = "aarch64")]
    return azos_arch::cpu::timer_freq_hw();
    #[cfg(not(target_arch = "aarch64"))]
    return azos_drv_sys::timebase::TIMER_FREQ;
}

fn print_totals(tag: &str) {
    let (reads, bad, first, foreign) = azos_sched::cpuid_probe::snapshot();
    match first {
        Some((reg, hw)) => kprintln!(
            "[CPUID] {}: reads={} mismatches={} first=reg:{}/hw:{} foreign={}",
            tag, reads, bad, reg, hw, foreign),
        None => kprintln!(
            "[CPUID] {}: reads={} mismatches={} first=none foreign={}",
            tag, reads, bad, foreign),
    }
}

/// Arm the check and start the reporter. Boot hart, before any secondary is
/// woken (its trap vector is installed by then).
pub(crate) fn arm(num_cpus: usize) {
    azos_sched::cpuid_probe::arm();
    azos_sched::task_create("cpuid-report", report_task, num_cpus, azos_sched::DEFAULT_PRIORITY);
}

/// One canary attempt (see `azos_sched::cpuid_probe::poison_and_fork`);
/// prints and returns true when some hart's slot held a user page table.
#[cfg(feature = "cpuid-probe-canary")]
fn canary_fork(num_cpus: usize, from: &str) -> bool {
    match azos_sched::cpuid_probe::poison_and_fork(num_cpus) {
        Some((c, upt, rc)) => {
            kprintln!("[CPUID] canary ({}): id register := {}: user_pt={:#x}, fork rc={}",
                from, c, upt, rc);
            print_totals("canary");
            true
        }
        None => false,
    }
}

fn report_task(num_cpus: usize) {
    let hz = ticks_per_second();
    #[cfg(feature = "cpuid-probe-canary")]
    let mut forked = false;
    for n in 1..=REPORTS {
        let dl = azos_drv_sys::timebase::now() + hz;
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
        // A user task is current on another hart only part of the time: try
        // a burst of attempts per second until one lands.
        #[cfg(feature = "cpuid-probe-canary")]
        for _ in 0..CANARY_TRIES {
            if forked {
                break;
            }
            forked = canary_fork(num_cpus, "task");
        }
        #[cfg(not(feature = "cpuid-probe-canary"))]
        let _ = num_cpus;
        if n == REPORTS {
            print_totals("final");
        } else {
            print_totals("totals");
        }
    }
}

/// The old fork-probe position: after `arch_wake_secondaries`, just before
/// `arch_enter_scheduler`.
pub(crate) fn at_old_fork_probe_position(boot_id: usize, num_cpus: usize) {
    let (wrong, pt) = azos_sched::cpuid_probe::boot_hart_hammer(boot_id, HAMMER_ITERS);
    kprintln!(
        "[CPUID] boot hart {} at the old fork-probe position: {} reads, wrong id {}, user_pt!=0 {}",
        boot_id, HAMMER_ITERS, wrong, pt);
    print_totals("boot");

    // Canary: the id register lies here, on this hart. Usually no slot holds
    // a user page table yet at this point (autorun has not loaded one), so
    // the fork half of the canary is retried from the report task.
    #[cfg(feature = "cpuid-probe-canary")]
    if !canary_fork(num_cpus, "boot") {
        print_totals("canary");
    }
    #[cfg(not(feature = "cpuid-probe-canary"))]
    let _ = num_cpus;
}
