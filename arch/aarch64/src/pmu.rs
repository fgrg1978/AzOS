// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The PMUv3 counters behind [`azos_arch_api::Pmu`], Kconfig `A64_PMU`.
//!
//! Cycles are `PMCCNTR_EL0`; instructions are event counter 0 counting
//! INST_RETIRED (0x08); [`Pmu::event`](azos_arch_api::Pmu::event) uses event
//! counter 1. Their users: `azos_drv_sys::wcet::read_cycles` (every WCET and
//! jitter figure, `crates/domains/robot/bench`, the `ifconfig` receive cost), the
//! lock hold times of lockdep, the tracer's cycle timestamps
//! (`KTRACE_TS_CYCLES`) and, in ring 3, vsbench's cycle lanes (Kconfig
//! `PMU_USER`: `PMUSERENR_EL0` with CR and ER, never EN, so ring 3 can read
//! the counters but not write any PMU register).
//!
//! The probe is `ID_AA64DFR0_EL1.PMUVer`
//! ([`crate::cpu::features::IdRegs::pmuv3`]); a core without PMUv3 takes an
//! UNDEFINED exception on any PMCR_EL0 or PMCCNTR_EL0 access, so nothing here
//! runs unless [`select`] kept the extension. A counter that does not move
//! once enabled (a hypervisor that ignores the enable) is dropped by
//! [`verify`] and reads 0.
//!
//! Every PE has its own counters: the boot CPU enables its own from
//! `cpu_features`, each secondary from `secondary_irq_init`
//! ([`start_this_cpu`], idempotent). They count at EL0 and EL1
//! (PMCCFILTR_EL0 = 0), every cycle (PMCR_EL0.D clear), and, as on most
//! cores, not while the PE sleeps in WFI. The event counters are 32 bits
//! wide, 64 with PMCR_EL0.LP (PMUVer 6 and later).
//!
//! Overflow sampling (the profiler, Kconfig `PROFILER_PMU`) uses the last
//! event counter (`api::a64_sample_counter`: `N - 1` when `N >= 3`), counting
//! CPU_CYCLES from `api::sample_init`; its `PMINTENSET_EL1` bit raises the
//! PMU's PPI on the wrap, `PMOVSSET_EL0` says which counter wrapped and
//! `PMOVSCLR_EL0` drops the (level) line. The PPI is the DTB `pmu` node's
//! ([`set_irq`]); without one (a board whose PMU interrupt is not a GIC PPI,
//! the Raspberry Pi 3's local interrupt controller) nothing is armed. The
//! counter is reached through `PMSELR_EL0` (its number is not an immediate),
//! from EL1 with interrupts masked: ring 3's `PMUSERENR_EL0.ER` lets it write
//! `PMSELR_EL0`, but it never runs in between.

use azos_arch_api::isa::{aarch64 as policy, ExtPolicy};
// The cross-ISA helpers, under the ISA's own module (`azos_arch::pmu`).
pub use azos_arch_api::pmu::{advanced, delta, mask, rate_per_us, PmuCaps, Source};
use azos_arch_api::pmu as api;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

/// The probe's verdict (`probe` only; `n`/`require` never read it).
static PMU_ON: AtomicBool = AtomicBool::new(false);
/// PMUv3 is implemented, used or not: `PMUSERENR_EL0` exists.
static PRESENT: AtomicBool = AtomicBool::new(false);
/// `PMCR_EL0.N`: event counters this PE has.
static EVENT_N: AtomicU8 = AtomicU8::new(0);
/// `ID_AA64DFR0_EL1.PMUVer`.
static PMUVER: AtomicU8 = AtomicU8::new(0);
/// The cycle and instruction counters moved after the enable ([`verify`]).
static CYC_OK: AtomicBool = AtomicBool::new(false);
static INS_OK: AtomicBool = AtomicBool::new(false);
/// Ring 3 may read them (Kconfig `PMU_USER`, with the counter live).
static USER_C: AtomicBool = AtomicBool::new(false);
static USER_I: AtomicBool = AtomicBool::new(false);

/// The event each CPU's counter 1 counts (`u64::MAX`: none programmed).
const NO_EVENT: u64 = u64::MAX;
static EVENT_SEL: [AtomicU64; azos_limits::NR_CPUS] = [const { AtomicU64::new(NO_EVENT) }; azos_limits::NR_CPUS];

/// The PMU's overflow interrupt, a GIC PPI INTID (0: none; [`set_irq`]).
static IRQ: AtomicU32 = AtomicU32::new(0);

/// The PMU overflow interrupt from the DTB (`pmu` node, a PPI), set by the
/// boot CPU's interrupt-controller bring-up; every PE enables the same PPI.
pub fn set_irq(intid: u32) {
    IRQ.store(intid, Ordering::Relaxed);
}

/// The PMU overflow interrupt's INTID, 0 when none is wired.
#[inline(always)]
pub fn irq() -> u32 {
    IRQ.load(Ordering::Relaxed)
}

/// The sampling counter, when this boot has one.
fn sample_counter() -> Option<u8> {
    if pmu_on() { api::a64_sample_counter(event_counters()) } else { None }
}

/// The PMU in use on this boot: a constant under `n`/`require`.
#[inline(always)]
pub fn pmu_on() -> bool {
    match policy::PMU {
        ExtPolicy::Never => false,
        ExtPolicy::Require => true,
        ExtPolicy::Probe => PMU_ON.load(Ordering::Relaxed),
    }
}

/// Boot, the boot CPU, before [`start_this_cpu`]: `present` is
/// `IdRegs::pmuv3()` and `pmuver` the raw `ID_AA64DFR0_EL1.PMUVer`. Returns
/// what the counter paths use.
pub fn select(present: bool, pmuver: u8) -> bool {
    PMU_ON.store(policy::PMU.gate(present), Ordering::Relaxed);
    PRESENT.store(present, Ordering::Relaxed);
    PMUVER.store(pmuver, Ordering::Relaxed);
    pmu_on()
}

/// Event counters usable: instructions need one, [`Pmu::event`] a second.
fn event_counters() -> u8 {
    EVENT_N.load(Ordering::Relaxed)
}

/// Start THIS PE's counters, when [`select`] kept the extension: PMCR_EL0
/// (counters on, cycle counter undivided, 64-bit event counters where
/// PMUv3p5 has them), the cycle counter, INST_RETIRED on event counter 0 and
/// the ring-3 read access.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn start_this_cpu() {
    if !pmu_on() {
        // A PMU this kernel does not use is still one ring 3 could reach:
        // PMUSERENR_EL0 resets to UNKNOWN (EN would let EL0 write PMCR_EL0),
        // so it is closed here (both flags are false: no access).
        if PRESENT.load(Ordering::Relaxed) {
            write_user_access();
        }
        return;
    }
    // PMCR_EL0.N is read once here, on every PE, before any event counter is touched.
    let pmcr = read_pmcr();
    EVENT_N.store(api::a64_pmcr_n(pmcr), Ordering::Relaxed);
    let n = api::a64_pmcr_n(pmcr);
    // SAFETY: only reached when PMUVer says PMUv3, so PMCR_EL0,
    // PMCNTENSET_EL0, PMCCFILTR_EL0 and (for the first `N`) the event
    // counters exist at EL1; none touches memory.
    unsafe {
        core::arch::asm!(
            "msr PMCR_EL0, {pmcr}",
            "msr PMCCFILTR_EL0, xzr",
            pmcr = in(reg) api::a64_pmcr(pmcr, PMUVER.load(Ordering::Relaxed)),
            options(nostack, nomem, preserves_flags),
        );
        if n >= 1 {
            core::arch::asm!(
                "msr PMEVTYPER0_EL0, {ev}",
                "msr PMEVCNTR0_EL0, xzr",
                ev = in(reg) api::A64_EV_INST_RETIRED,
                options(nostack, nomem, preserves_flags),
            );
        }
        core::arch::asm!(
            "msr PMCNTENSET_EL0, {en}",
            "isb",
            en = in(reg) api::a64_cnten(n),
            options(nostack, nomem, preserves_flags),
        );
    }
    write_user_access();
}

/// `PMUSERENR_EL0` from the live counters and Kconfig `PMU_USER`: read access
/// only (`api::a64_pmuserenr` never sets EN, which would let a task stop or
/// retarget the counters wcet and lockdep trust).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn write_user_access() {
    let v = api::a64_pmuserenr(USER_C.load(Ordering::Relaxed), USER_I.load(Ordering::Relaxed));
    // SAFETY: PMUv3 is present (`pmu_on`); PMUSERENR_EL0 only gates EL0 access,
    // and only reads of the counters are opened.
    unsafe { core::arch::asm!("msr PMUSERENR_EL0, {v}", "isb", v = in(reg) v, options(nostack, nomem, preserves_flags)) };
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn read_pmcr() -> u64 {
    let v: u64;
    // SAFETY: as `start_this_cpu`.
    unsafe { core::arch::asm!("mrs {}, PMCR_EL0", out(reg) v, options(nostack, nomem, preserves_flags)) };
    v
}

/// The cycle counter, or 0 when it is not in use.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline(always)]
fn read_cycles() -> u64 {
    if !CYC_OK.load(Ordering::Relaxed) {
        return 0;
    }
    let v: u64;
    // SAFETY: PMUv3 is present and the counter moved at the boot (`CYC_OK`).
    unsafe { core::arch::asm!("mrs {}, PMCCNTR_EL0", out(reg) v, options(nostack, nomem, preserves_flags)) };
    v
}

/// Event counter 0 (INST_RETIRED), or 0 when it is not in use.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline(always)]
fn read_instructions() -> u64 {
    if !INS_OK.load(Ordering::Relaxed) {
        return 0;
    }
    let v: u64;
    // SAFETY: as `read_cycles`; event counter 0 exists (`N >= 1`, `INS_OK`).
    unsafe { core::arch::asm!("mrs {}, PMEVCNTR0_EL0", out(reg) v, options(nostack, nomem, preserves_flags)) };
    v
}

/// The cycle counter and event counter 0 (0 when `n` says there is none).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn sample(n: u8) -> (u64, u64) {
    let (c, i): (u64, u64);
    // SAFETY: only reached after `start_this_cpu` enabled the counters;
    // event counter 0 exists when `n >= 1`.
    unsafe {
        core::arch::asm!("mrs {}, PMCCNTR_EL0", out(reg) c, options(nostack, nomem, preserves_flags));
        if n >= 1 {
            core::arch::asm!("mrs {}, PMEVCNTR0_EL0", out(reg) i, options(nostack, nomem, preserves_flags));
        } else {
            i = 0;
        }
    }
    (c, i)
}

/// Boot CPU, after [`start_this_cpu`]: run a short loop, and keep only the
/// counters that moved. Sets the ring-3 access for the ones that did, on
/// this PE (a secondary's [`start_this_cpu`] reads the flags). Returns the
/// final capabilities, for the boot line.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn verify() -> PmuCaps {
    if !pmu_on() {
        return caps();
    }
    let n = event_counters();
    let (c0, i0) = sample(n);
    for _ in 0..4096 {
        core::hint::spin_loop();
    }
    let (c1, i1) = sample(n);
    let user = azos_limits::PMU_USER;
    let cyc = api::advanced(64, c0, c1);
    let ins = n >= 1 && api::advanced(event_bits(), i0, i1);
    CYC_OK.store(cyc, Ordering::Relaxed);
    INS_OK.store(ins, Ordering::Relaxed);
    USER_C.store(user && cyc, Ordering::Relaxed);
    USER_I.store(user && ins, Ordering::Relaxed);
    write_user_access();
    caps()
}

/// Width of an event counter on this boot.
fn event_bits() -> u8 {
    api::a64_event_bits(PMUVER.load(Ordering::Relaxed))
}

/// The event selector of "mispredicted branches" for [`Pmu::event`](azos_arch_api::Pmu::event)
/// on this ISA: the boot self-test counts it over a short loop
/// (`boot::seams::pmu_report`).
pub fn branch_miss_event() -> u64 {
    api::A64_EV_BR_MIS_PRED
}

/// The capabilities as the boot left them.
pub fn caps() -> PmuCaps {
    let src = |ok: &AtomicBool| if ok.load(Ordering::Relaxed) { Source::Pmu } else { Source::None };
    PmuCaps {
        cycles: src(&CYC_OK),
        instructions: src(&INS_OK),
        cycle_bits: 64,
        instr_bits: event_bits(),
        events: if event_counters() >= 2 && pmu_on() { 1 } else { 0 },
        event_bits: event_bits(),
        user_cycles: USER_C.load(Ordering::Relaxed),
        user_instructions: USER_I.load(Ordering::Relaxed),
        sample_bits: if sample_counter().is_some() { event_bits() } else { 0 },
    }
}

/// Anywhere that is not bare-metal aarch64: no counter, no instruction.
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub fn start_this_cpu() {}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub fn verify() -> PmuCaps {
    caps()
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl azos_arch_api::Pmu for crate::api_impl::Aarch64 {
    fn caps(&self) -> PmuCaps {
        caps()
    }

    #[inline(always)]
    fn cycles(&self) -> u64 {
        read_cycles()
    }

    #[inline(always)]
    fn instructions(&self) -> u64 {
        read_instructions()
    }

    /// Event counter 1, programmed to `sel` (an architected or
    /// implementation-defined event number, `PMEVTYPER1_EL0.evtCount`) on the
    /// first ask and after any change; counted from that call.
    fn event(&self, sel: u64) -> Option<u64> {
        use azos_arch_api::Cpu as _;
        if !pmu_on() || event_counters() < 2 {
            return None;
        }
        let cur = EVENT_SEL.get(self.hart_id())?;
        let v: u64;
        // SAFETY: PMUv3 with N >= 2 (checked); counter 1 was enabled by
        // `start_this_cpu` (PMCNTENSET_EL0 bit 1); no memory is touched.
        unsafe {
            if cur.load(Ordering::Relaxed) != sel {
                core::arch::asm!(
                    "msr PMEVTYPER1_EL0, {ev}",
                    "msr PMEVCNTR1_EL0, xzr",
                    "isb",
                    ev = in(reg) sel & 0xFFFF,
                    options(nostack, nomem, preserves_flags),
                );
                cur.store(sel, Ordering::Relaxed);
            }
            core::arch::asm!("mrs {}, PMEVCNTR1_EL0", out(reg) v, options(nostack, nomem, preserves_flags));
        }
        Some(v)
    }

    /// The last event counter, CPU_CYCLES from the period's initial value,
    /// its overflow interrupt and the counter enabled.
    fn sample_arm(&self, period: u64) -> bool {
        let Some(n) = sample_counter() else { return false };
        if irq() == 0 || !api::sample_period_fits(event_bits(), period) {
            return false;
        }
        let bit = 1u64 << n;
        // SAFETY: PMUv3 with counter `n` (`a64_sample_counter` keeps it below
        // N); PMSELR_EL0 selects it for the two indirect writes, with
        // interrupts masked (the trait's contract) so nothing reselects in
        // between; no memory.
        unsafe {
            core::arch::asm!(
                "msr PMCNTENCLR_EL0, {bit}",
                "msr PMSELR_EL0, {n}",
                "isb",
                "msr PMXEVTYPER_EL0, {ev}",
                "msr PMXEVCNTR_EL0, {init}",
                "msr PMOVSCLR_EL0, {bit}",
                "msr PMINTENSET_EL1, {bit}",
                "msr PMCNTENSET_EL0, {bit}",
                "isb",
                bit = in(reg) bit,
                n = in(reg) n as u64,
                ev = in(reg) api::A64_EV_CPU_CYCLES,
                init = in(reg) api::sample_init(event_bits(), period),
                options(nostack, nomem, preserves_flags),
            );
        }
        true
    }

    /// The PMU PPI: the counter's `PMOVSSET_EL0` bit, cleared (the line
    /// drops), then the counter reloaded, or its interrupt and count stopped.
    fn sample_ack(&self, rearm: Option<u64>) -> bool {
        let Some(n) = sample_counter() else { return false };
        let bit = 1u64 << n;
        let ovs: u64;
        // SAFETY: as `sample_arm`.
        unsafe {
            core::arch::asm!("mrs {}, PMOVSSET_EL0", out(reg) ovs, options(nostack, nomem, preserves_flags));
            core::arch::asm!("msr PMOVSCLR_EL0, {}", "isb", in(reg) bit, options(nostack, nomem, preserves_flags));
        }
        let overflowed = ovs & bit != 0;
        match rearm {
            // SAFETY: as `sample_arm`.
            Some(period) if overflowed => unsafe {
                core::arch::asm!(
                    "msr PMSELR_EL0, {n}",
                    "isb",
                    "msr PMXEVCNTR_EL0, {init}",
                    n = in(reg) n as u64,
                    init = in(reg) api::sample_init(event_bits(), period),
                    options(nostack, nomem, preserves_flags),
                );
            },
            Some(_) => {}
            // SAFETY: as `sample_arm`.
            None => unsafe {
                core::arch::asm!(
                    "msr PMINTENCLR_EL1, {bit}",
                    "msr PMCNTENCLR_EL0, {bit}",
                    "isb",
                    bit = in(reg) bit,
                    options(nostack, nomem, preserves_flags),
                );
            },
        }
        overflowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `select` keeps the extension only when the probe found it (under the
    /// default `probe` policy these tests build with), and a host build has
    /// no counter to read: the capabilities say none.
    #[test]
    fn select_follows_the_probe_under_probe_policy() {
        if !matches!(policy::PMU, ExtPolicy::Probe) {
            return;
        }
        assert!(select(true, 6) && pmu_on());
        assert!(!select(false, 0) && !pmu_on());
        assert_eq!(caps(), PmuCaps { instr_bits: 32, event_bits: 32, ..PmuCaps::NONE });
        assert_eq!(verify(), caps(), "nothing runs off bare metal");
    }
}
