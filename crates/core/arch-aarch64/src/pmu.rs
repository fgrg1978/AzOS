// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The PMUv3 cycle counter (`PMCCNTR_EL0`), Kconfig `A64_PMU`.
//!
//! Its users: `azos_drv_sys::wcet::read_cycles` (every WCET and jitter
//! figure, `domains/robot/bench`, the `ifconfig` receive cost) and the
//! tracer's cycle timestamps (`KTRACE_TS_CYCLES`). The probe is
//! `ID_AA64DFR0_EL1.PMUVer` ([`crate::features::IdRegs::pmuv3`]); a core
//! without PMUv3 takes an UNDEFINED exception on any PMCR_EL0 or PMCCNTR_EL0
//! access, so nothing here runs unless [`select`] kept the extension.
//!
//! Every PE has its own counter: the boot CPU enables its own from
//! `cpu_features`, each secondary from `secondary_irq_init`
//! ([`cycles_enable`], idempotent). It counts at EL0 and EL1 (PMCCFILTR_EL0
//! = 0), every cycle (PMCR_EL0.D clear), and, as on most cores, not while
//! the PE sleeps in WFI.

use azos_arch_api::isa::{aarch64 as policy, ExtPolicy};
use core::sync::atomic::{AtomicBool, Ordering};

/// The probe's verdict (`probe` only; `n`/`require` never read it).
static PMU_ON: AtomicBool = AtomicBool::new(false);

/// `PMCR_EL0.E`: all counters enabled.
pub const PMCR_E: u64 = 1 << 0;
/// `PMCR_EL0.D`: the cycle counter counts every 64th cycle.
pub const PMCR_D: u64 = 1 << 3;
/// `PMCNTENSET_EL0.C`: enable the cycle counter.
pub const PMCNTENSET_C: u64 = 1 << 31;

/// The cycle counter in use on this boot: a constant under `n`/`require`.
#[inline(always)]
pub fn pmu_on() -> bool {
    match policy::PMU {
        ExtPolicy::Never => false,
        ExtPolicy::Require => true,
        ExtPolicy::Probe => PMU_ON.load(Ordering::Relaxed),
    }
}

/// Boot, the boot CPU, before [`cycles_enable`]: `present` is the ID
/// register's answer. Returns what the counter paths use.
pub fn select(present: bool) -> bool {
    PMU_ON.store(policy::PMU.gate(present), Ordering::Relaxed);
    pmu_on()
}

/// `PMCR_EL0` with the counters on and the cycle counter undivided; every
/// other bit (event counter count `N`, `LC`, ...) as read.
pub const fn pmcr_enabled(pmcr: u64) -> u64 {
    (pmcr | PMCR_E) & !PMCR_D
}

/// Start THIS PE's cycle counter, when [`select`] kept the extension.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn cycles_enable() {
    if !pmu_on() {
        return;
    }
    // SAFETY: only reached when PMUVer says PMUv3, so PMCR_EL0,
    // PMCNTENSET_EL0 and PMCCFILTR_EL0 exist at EL1; none touches memory.
    unsafe {
        core::arch::asm!(
            "msr PMCR_EL0, {pmcr}",
            "msr PMCCFILTR_EL0, xzr",
            "msr PMCNTENSET_EL0, {c}",
            "isb",
            pmcr = in(reg) pmcr_enabled(read_pmcr()),
            c = in(reg) PMCNTENSET_C,
            options(nostack, nomem, preserves_flags),
        );
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn read_pmcr() -> u64 {
    let v: u64;
    // SAFETY: as `cycles_enable`.
    unsafe { core::arch::asm!("mrs {}, PMCR_EL0", out(reg) v, options(nostack, nomem, preserves_flags)) };
    v
}

/// The cycle counter, or 0 when it is not in use.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline(always)]
pub fn read_cycles() -> u64 {
    if !pmu_on() {
        return 0;
    }
    let v: u64;
    // SAFETY: PMUv3 is present (`pmu_on`); the counter is read-only here.
    unsafe { core::arch::asm!("mrs {}, PMCCNTR_EL0", out(reg) v, options(nostack, nomem, preserves_flags)) };
    v
}

/// Anywhere that is not bare-metal aarch64: no counter, no instruction.
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub fn cycles_enable() {}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
#[inline(always)]
pub fn read_cycles() -> u64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The PMCR_EL0 value: E set, D clear, the event-counter count `N`
    /// [15:11], `LC` and every other bit untouched.
    #[test]
    fn the_pmcr_value_sets_e_clears_d_and_keeps_the_rest() {
        assert_eq!(pmcr_enabled(0), PMCR_E);
        assert_eq!(pmcr_enabled(PMCR_D), PMCR_E, "a divided counter is made undivided");
        let n6_lc = (6 << 11) | (1 << 6) | (0x41 << 24);
        assert_eq!(pmcr_enabled(n6_lc), n6_lc | PMCR_E);
        assert_eq!(pmcr_enabled(!0) & PMCR_D, 0);
        assert_eq!(pmcr_enabled(!0) & !PMCR_D, !PMCR_D);
        assert_eq!(PMCNTENSET_C, 0x8000_0000, "the cycle counter is PMCNTENSET_EL0 bit 31");
    }

    /// `select` keeps the extension only when the probe found it (under the
    /// default `probe` policy these tests build with).
    #[test]
    fn select_follows_the_probe_under_probe_policy() {
        if !matches!(policy::PMU, ExtPolicy::Probe) {
            return;
        }
        assert!(select(true) && pmu_on());
        assert!(!select(false) && !pmu_on());
        assert_eq!(read_cycles(), 0, "no counter off bare metal");
    }
}
