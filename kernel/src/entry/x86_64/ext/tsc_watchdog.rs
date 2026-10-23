// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The clocksource's boot record and the `tsc-watchdog` task (Kconfig
//! `X86_TSC_CLOCK`, `X86_TSC_WATCHDOG`; the counters and the comparison are
//! `azos_arch::timer`'s).
//!
//! While the TSC is the clock and the board has a reference (the HPET, else
//! the ACPI PM timer), the task compares the two every
//! `X86_TSC_WATCHDOG_MS` and demotes the TSC on a drift beyond the bound:
//! the clock goes on on the reference, ring 3 reads it through the syscall
//! (the vDSO flag is cleared), a `[TIMER]` line says so and a `clocksource`
//! decision record is written. While the reference is the clock and wraps
//! (a 24-bit PM timer, a 32-bit HPET), the same task reads it each interval
//! so its count is extended past every wrap. Neither: no task.
//!
//! Runtime canary `x86-tsc-skew`: the TSC is made to run four times the
//! bound fast, so the task must demote it.

use azos_arch::irq::encode::ClockPlan;
use azos_arch::timer::{self, Clocksource, Watch};
use azos_decision::{Rule, Verdict};
use azos_drv_sys::kprintln;

/// The `clocksource` record's `reason`.
const NOT_INVARIANT: u64 = 1;
const RAN_FAST: u64 = 2;
const RAN_SLOW: u64 = 3;
const KEPT_ALONE: u64 = 4;

fn record(verdict: Verdict, clock: Clocksource, reason: u64, drift_ppm: u64, limit_ppm: u64) {
    azos_decision::record(Rule::Clocksource, verdict, clock as u32, [reason, drift_ppm, limit_ppm]);
}

/// The boot's clocksource line and record, then the task on the lowest CPU
/// outside the real-time ones (as the thermal task is placed).
/// `arch_enter_scheduler`, after the topology published its real-time CPUs
/// and the decision sink was installed.
pub(crate) fn start() {
    let clock = timer::clock();
    let reference = timer::reference();
    let invariant = timer::clock_plan() == ClockPlan::Stated;
    match (clock, reference) {
        (Clocksource::Tsc, None) if !invariant => {
            azos_drv_sys::kwarn!("[TIMER] clock: TSC, not invariant, and no HPET or PM timer to replace or watch it");
            record(Verdict::Admit, clock, KEPT_ALONE, 0, 0);
        }
        (Clocksource::Tsc, _) => {}
        (c, _) => {
            kprintln!("[TIMER] clock: {} (the TSC is not invariant; Kconfig X86_TSC_CLOCK)", c.name());
            record(Verdict::Refuse, c, NOT_INVARIANT, 0, 0);
        }
    }
    let watching = clock == Clocksource::Tsc && azos_limits::X86_TSC_WATCHDOG && reference.is_some();
    if !watching && !timer::reference_wraps() {
        return;
    }
    let isolated = azos_topology::get().map_or(0, |t| t.sched_config().isolcpus as usize);
    let rt = azos_sync::qsbr::NOCBS_CPUS | isolated;
    let Some(cpu) = azos_sync::qsbr_core::callback_cpu(azos_percpu::nr_cpu_ids(), rt, azos_percpu::cpu_possible) else {
        azos_drv_sys::kwarn!("[TIMER] every CPU is real-time (RCU_NOCBS_CPUS {:#x}, isolcpus {:#x}): no tsc-watchdog task, the {} is not {}",
            azos_sync::qsbr::NOCBS_CPUS, isolated,
            if watching { "TSC" } else { "reference" }, if watching { "watched" } else { "extended past its wraps" });
        return;
    };
    let prio = azos_limits::X86_TSC_WATCHDOG_PRIORITY as u32;
    azos_sched::task_create_affinity("tsc-watchdog", task, 0, prio, cpu as i8);
    if watching {
        kprintln!("[TIMER] watchdog: TSC against the {} every {} ms, bound {} ppm (prio {}, CPU {})",
            reference.map_or("-", Clocksource::name), azos_limits::X86_TSC_WATCHDOG_MS, timer::watch_bound_ppm(), prio, cpu);
    }
}

fn task(_: usize) {
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    let inject = if canary!("x86-tsc-skew") { 4 * timer::watch_bound_ppm() } else { 0 };
    let mut w = timer::Watchdog::new();
    // The clock when the TSC was demoted: the next wake says how far the new
    // clock went in one interval, so a demotion is seen to keep time going.
    let mut demoted_at = None;
    loop {
        let end = azos_drv_sys::timebase::now() + azos_limits::X86_TSC_WATCHDOG_MS as u64 * per_ms;
        while azos_drv_sys::timebase::now() < end {
            azos_sched::task_block(azos_sched::WaitReason::Timer(end));
        }
        if timer::clock() != Clocksource::Tsc {
            if let Some(at) = demoted_at.take() {
                kprintln!("[TIMER] the {} clock runs: {} ms over one {} ms interval",
                    timer::clock().name(), (azos_drv_sys::timebase::now() - at) / per_ms, azos_limits::X86_TSC_WATCHDOG_MS);
            }
            // The reference is the clock: the reads above extended its count.
            if !timer::reference_wraps() {
                return;
            }
            continue;
        }
        if let Watch::Skewed(ppm) = timer::watch(&mut w, inject) {
            if demote(ppm) {
                demoted_at = Some(azos_drv_sys::timebase::now());
            }
        }
    }
}

fn demote(ppm: i64) -> bool {
    let Some(clock) = timer::demote() else {
        return false;
    };
    azos_mm::vdso::vdso_clear_flags(azos_mm::vdso::VDSO_FLAG_RDTIME_NATIVE);
    let bound = timer::watch_bound_ppm();
    azos_drv_sys::kwarn!("[TIMER] TSC demoted: it ran {:+} ppm from the {} (bound {} ppm); the clock is the {} from now on",
        ppm, clock.name(), bound, clock.name());
    record(Verdict::Refuse, clock, if ppm > 0 { RAN_FAST } else { RAN_SLOW }, ppm.unsigned_abs(), bound);
    true
}
