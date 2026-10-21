// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The x86_64 counters behind [`azos_arch_api::Pmu`], Kconfig `X86_PMU`.
//!
//! Intel (CPUID leaf 0xA, version 2 or later): the fixed counters, INST_RETIRED
//! for instructions and CPU_CLK_UNHALTED for cycles, and programmable counter 0
//! for `Pmu::event`. AMD (`0x80000001` ECX\[23\] PerfCtrExtCore, else the
//! legacy four on bare metal): counter 0 counts cycles (0x76), counter 1
//! instructions (0xC0), counter 2 serves `Pmu::event`. The plan is
//! `azos_arch_api::pmu::x86_plan` (pure, tested with fake CPUID tables); this
//! file reads CPUID once and programs the MSRs the plan names, so a CPU or an
//! emulator without a PMU (QEMU TCG) is never asked for one. A counter that
//! does not move after the enable (a hypervisor that ignores the MSR write)
//! is dropped by [`verify`].
//!
//! Without a cycle counter `Pmu::cycles` is the time-stamp counter, as
//! `wcet::read_cycles` always was on this ISA (the rate is measured against
//! the timebase at boot); `Pmu::instructions` is 0.
//!
//! Counters are read with `rdpmc`. Ring 3 may use it with `CR4.PCE`, which
//! Kconfig `PMU_USER` sets on every CPU for a live counter and which opens
//! every counter to `rdpmc`, not only those two. The vDSO hwcap
//! `PMU_FIXED` bit tells ring 3 which `rdpmc` indices the plan uses.

use azos_arch_api::isa::{x86_64 as policy, ExtPolicy};
// The cross-ISA helpers, under the ISA's own module (`azos_arch::pmu`).
pub use azos_arch_api::pmu::{advanced, delta, mask, rate_per_us, PmuCaps, Source};
use azos_arch_api::pmu::{self as api, X86Plan};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

const NONE: u32 = u32::MAX;

/// The `rdpmc` index of each counter in use (`NONE`: not in use).
static CYC_IDX: AtomicU32 = AtomicU32::new(NONE);
static INS_IDX: AtomicU32 = AtomicU32::new(NONE);
static EVT_IDX: AtomicU32 = AtomicU32::new(NONE);
/// Widths (cycle | instruction << 8 | event << 16), and the fixed and
/// programmable counters the plan enables.
static BITS: AtomicU32 = AtomicU32::new(0x40_40_40);
static FIXED_MASK: AtomicU8 = AtomicU8::new(0);
static PMC_MASK: AtomicU8 = AtomicU8::new(0);
static GLOBAL: AtomicBool = AtomicBool::new(false);
/// Intel (fixed counters) vs AMD (core counters 0 and 1).
static FIXED: AtomicBool = AtomicBool::new(false);
/// The AMD register map (`counters == 0`: Intel or none).
static AMD_EVTSEL0: AtomicU32 = AtomicU32::new(0);
static AMD_CTR0: AtomicU32 = AtomicU32::new(0);
static AMD_STRIDE: AtomicU32 = AtomicU32::new(1);
static AMD_COUNTERS: AtomicU8 = AtomicU8::new(0);
/// The counters moved after the enable ([`verify`]).
static CYC_OK: AtomicBool = AtomicBool::new(false);
static INS_OK: AtomicBool = AtomicBool::new(false);
/// Ring 3 may read them (Kconfig `PMU_USER`, with the counter live).
static USER_C: AtomicBool = AtomicBool::new(false);
static USER_I: AtomicBool = AtomicBool::new(false);

/// The event each CPU's programmable counter counts (`u64::MAX`: none).
const NO_EVENT: u64 = u64::MAX;
static EVENT_SEL: [AtomicU64; azos_limits::NR_CPUS] = [const { AtomicU64::new(NO_EVENT) }; azos_limits::NR_CPUS];

fn idx(v: Option<u32>) -> u32 {
    v.unwrap_or(NONE)
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn amd() -> api::AmdPmu {
    api::AmdPmu {
        counters: AMD_COUNTERS.load(Ordering::Relaxed),
        evtsel0: AMD_EVTSEL0.load(Ordering::Relaxed),
        ctr0: AMD_CTR0.load(Ordering::Relaxed),
        stride: AMD_STRIDE.load(Ordering::Relaxed),
        global_ctl: GLOBAL.load(Ordering::Relaxed),
    }
}

/// Keep `plan` as this boot's counters (unless Kconfig says `n`). Boot CPU,
/// before [`start_this_cpu`]. Returns whether the plan has both the cycle
/// and the instruction counter (the `[ISA]` line's `pmu` row).
pub fn adopt(plan: X86Plan) -> bool {
    if matches!(policy::PMU, ExtPolicy::Never) {
        return false;
    }
    CYC_IDX.store(idx(plan.cycle_idx), Ordering::Relaxed);
    INS_IDX.store(idx(plan.instr_idx), Ordering::Relaxed);
    EVT_IDX.store(idx(plan.event_idx), Ordering::Relaxed);
    BITS.store(plan.cycle_bits as u32 | (plan.instr_bits as u32) << 8 | (plan.event_bits as u32) << 16, Ordering::Relaxed);
    FIXED_MASK.store(plan.fixed_mask, Ordering::Relaxed);
    PMC_MASK.store(plan.pmc_mask, Ordering::Relaxed);
    GLOBAL.store(plan.global, Ordering::Relaxed);
    FIXED.store(plan.fixed, Ordering::Relaxed);
    if let Some(a) = plan.amd {
        AMD_EVTSEL0.store(a.evtsel0, Ordering::Relaxed);
        AMD_CTR0.store(a.ctr0, Ordering::Relaxed);
        AMD_STRIDE.store(a.stride, Ordering::Relaxed);
        AMD_COUNTERS.store(a.counters, Ordering::Relaxed);
    }
    plan.cycle_idx.is_some() && plan.instr_idx.is_some()
}

/// Boot CPU: the plan from this CPU's CPUID ([`adopt`]). `hypervisor`,
/// `vendor` and the leaves are read here, nothing else.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn select() -> bool {
    if matches!(policy::PMU, ExtPolicy::Never) {
        return false;
    }
    adopt(api::x86_plan(crate::platform_impl::cpuid))
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn select() -> bool {
    false
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[inline(always)]
fn rdpmc(index: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: `index` names a counter the plan found and `start_this_cpu`
    // enabled (CPL0 may always `rdpmc`); no memory is touched.
    unsafe {
        core::arch::asm!("rdpmc", in("ecx") index, out("eax") lo, out("edx") hi,
                         options(nomem, nostack, preserves_flags));
    }
    (hi as u64) << 32 | lo as u64
}

/// Program THIS CPU's counters from the plan and open `rdpmc` to ring 3 for
/// the live ones. Boot CPU from `cpu_features`, each secondary from
/// `secondary_irq_init`. Only MSRs the plan names are written.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn start_this_cpu() {
    use crate::cpu::{rdmsr, wrmsr};
    let (cyc, ins) = (CYC_IDX.load(Ordering::Relaxed), INS_IDX.load(Ordering::Relaxed));
    let (fixed, pmc) = (FIXED_MASK.load(Ordering::Relaxed), PMC_MASK.load(Ordering::Relaxed));
    if cyc == NONE && ins == NONE && EVT_IDX.load(Ordering::Relaxed) == NONE {
        return;
    }
    if FIXED.load(Ordering::Relaxed) {
        if fixed != 0 {
            for n in 0..3u32 {
                if fixed & (1 << n) != 0 {
                    wrmsr(api::X86_MSR_FIXED_CTR0 + n, 0);
                }
            }
            wrmsr(api::X86_MSR_FIXED_CTR_CTRL, api::x86_fixed_ctrl(rdmsr(api::X86_MSR_FIXED_CTR_CTRL), fixed));
        }
        if GLOBAL.load(Ordering::Relaxed) {
            wrmsr(api::X86_MSR_PERF_GLOBAL_CTRL, api::x86_global_ctrl(rdmsr(api::X86_MSR_PERF_GLOBAL_CTRL), fixed, pmc));
        }
    } else {
        let a = amd();
        for (n, ev) in [(0u8, api::AMD_EV_CYCLES), (1, api::AMD_EV_INSTR)] {
            if n < a.counters && cyc != NONE {
                wrmsr(a.evtsel(n), 0);
                wrmsr(a.ctr(n), 0);
                wrmsr(a.evtsel(n), api::x86_evtsel(ev));
            }
        }
        if a.global_ctl {
            wrmsr(api::AMD_MSR_PERF_GLOBAL_CTL, rdmsr(api::AMD_MSR_PERF_GLOBAL_CTL) | pmc as u64);
        }
    }
    write_user_access();
}

/// `CR4.PCE` from the live counters and Kconfig `PMU_USER`.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn write_user_access() {
    let want = USER_C.load(Ordering::Relaxed) || USER_I.load(Ordering::Relaxed);
    let mut cr4: u64;
    // SAFETY: CPL0; CR4.PCE only gates `rdpmc` at CPL > 0, and the read-modify-write
    // keeps every other bit.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        if want {
            cr4 |= api::X86_CR4_PCE;
        } else {
            cr4 &= !api::X86_CR4_PCE;
        }
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn start_this_cpu() {}

/// Boot CPU, after [`start_this_cpu`]: a short loop, keeping the counters
/// that moved; opens `rdpmc` to ring 3 for those when Kconfig `PMU_USER`
/// allows. Returns the final capabilities for the boot line.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn verify() -> PmuCaps {
    let (cyc, ins) = (CYC_IDX.load(Ordering::Relaxed), INS_IDX.load(Ordering::Relaxed));
    let read = |i: u32| if i == NONE { 0 } else { rdpmc(i) };
    let (c0, i0) = (read(cyc), read(ins));
    for _ in 0..4096 {
        core::hint::spin_loop();
    }
    let (c1, i1) = (read(cyc), read(ins));
    let bits = BITS.load(Ordering::Relaxed);
    let c_ok = cyc != NONE && api::advanced((bits & 0xFF) as u8, c0, c1);
    let i_ok = ins != NONE && api::advanced(((bits >> 8) & 0xFF) as u8, i0, i1);
    CYC_OK.store(c_ok, Ordering::Relaxed);
    INS_OK.store(i_ok, Ordering::Relaxed);
    USER_C.store(azos_limits::PMU_USER && c_ok, Ordering::Relaxed);
    USER_I.store(azos_limits::PMU_USER && i_ok, Ordering::Relaxed);
    write_user_access();
    caps()
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn verify() -> PmuCaps {
    caps()
}

/// The capabilities as the boot left them. Without a live cycle counter the
/// cycles are the time-stamp counter.
pub fn caps() -> PmuCaps {
    let bits = BITS.load(Ordering::Relaxed);
    let live = |ok: &AtomicBool| ok.load(Ordering::Relaxed);
    PmuCaps {
        cycles: if live(&CYC_OK) { Source::Pmu } else if cfg!(target_arch = "x86_64") { Source::Timebase } else { Source::None },
        instructions: if live(&INS_OK) { Source::Pmu } else { Source::None },
        cycle_bits: if live(&CYC_OK) { (bits & 0xFF) as u8 } else { 64 },
        instr_bits: ((bits >> 8) & 0xFF) as u8,
        events: if EVT_IDX.load(Ordering::Relaxed) != NONE && (live(&CYC_OK) || live(&INS_OK)) { 1 } else { 0 },
        event_bits: ((bits >> 16) & 0xFF) as u8,
        user_cycles: live(&USER_C),
        user_instructions: live(&USER_I),
    }
}

/// The event selector of "mispredicted branches" for [`Pmu::event`](azos_arch_api::Pmu::event)
/// on this ISA: the boot self-test counts it over a short loop
/// (`boot::seams::pmu_report`).
pub fn branch_miss_event() -> u64 {
    if FIXED.load(Ordering::Relaxed) { api::INTEL_EV_BR_MISS } else { api::AMD_EV_BR_MISS }
}

/// `rdpmc` indices ring 3 uses, published by the vDSO hwcap `PMU_FIXED` bit:
/// whether they are the Intel fixed counters.
pub fn user_fixed_indices() -> bool {
    FIXED.load(Ordering::Relaxed)
}

impl azos_arch_api::Pmu for crate::X86_64 {
    fn caps(&self) -> PmuCaps {
        caps()
    }

    #[inline(always)]
    fn cycles(&self) -> u64 {
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            if CYC_OK.load(Ordering::Relaxed) {
                return rdpmc(CYC_IDX.load(Ordering::Relaxed));
            }
            crate::cpu::rdtsc()
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
        {
            0
        }
    }

    #[inline(always)]
    fn instructions(&self) -> u64 {
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            if INS_OK.load(Ordering::Relaxed) {
                return rdpmc(INS_IDX.load(Ordering::Relaxed));
            }
        }
        0
    }

    /// The programmable counter (Intel `IA32_PMC0`, AMD core counter 2),
    /// programmed to `sel` (the event-select register's event / unit mask
    /// image) on the first ask and after any change; counted from that call.
    fn event(&self, sel: u64) -> Option<u64> {
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            use azos_arch_api::{Cpu as _, Interrupts as _};
            let index = EVT_IDX.load(Ordering::Relaxed);
            if index == NONE || !(CYC_OK.load(Ordering::Relaxed) || INS_OK.load(Ordering::Relaxed)) {
                return None;
            }
            // The hart's own event-select image, its MSRs and `rdpmc` must be
            // the same CPU's: masked from the hart id to the read, or a
            // migration between them programs one CPU and reads another.
            let irq = self.disable_all();
            let read = EVENT_SEL.get(self.hart_id()).map(|cur| {
                if cur.load(Ordering::Relaxed) != sel {
                    let (evtsel, ctr) = if FIXED.load(Ordering::Relaxed) {
                        (api::X86_MSR_PERFEVTSEL0, api::X86_MSR_PMC0)
                    } else {
                        let a = amd();
                        (a.evtsel(index as u8), a.ctr(index as u8))
                    };
                    // Stop, zero, start: the count is since this call.
                    crate::cpu::wrmsr(evtsel, 0);
                    crate::cpu::wrmsr(ctr, 0);
                    crate::cpu::wrmsr(evtsel, api::x86_evtsel(sel));
                    cur.store(sel, Ordering::Relaxed);
                }
                rdpmc(index)
            });
            self.restore(irq);
            read
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
        {
            let _ = (sel, &EVENT_SEL);
            None
        }
    }
}
