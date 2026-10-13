// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The hardware half of the speculation mitigations (Kconfig `X86_MIT_*`,
//! [`crate::mitigations`] for the decision): [`select`] reads CPUID and the
//! MSRs behind its bits and decides on the boot CPU; [`apply_this_cpu`]
//! writes the per-CPU controls, on the boot CPU and on every secondary
//! (`x86_64_secondary_entry`), the way `splitlock` does.
//!
//! Every MSR here is read or written only behind the bit that says it
//! exists ([`needs_arch_caps`], [`needs_mcu_opt_ctrl`], the plan's own
//! fields), so an emulator or a CPU without one never sees a #GP.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use crate::features::read_cpuid;
use crate::hw::{rdmsr, wrmsr};
use crate::mitigations::{
    decide, needs_arch_caps, needs_mcu_opt_ctrl, needs_ucode_rev, Plan, Policies, Probe, Report,
    DE_CFG_ZEN2_FP_BACKUP_FIX, EFER_AIBRS, MCU_OPT_GDS_MITG_DIS, MSR_AMD64_DE_CFG, MSR_AMD64_PATCH_LEVEL,
    MSR_IA32_ARCH_CAPABILITIES, MSR_IA32_MCU_OPT_CTRL, MSR_IA32_SPEC_CTRL,
};

/// IA32_EFER.
const MSR_EFER: u32 = 0xC000_0080;

/// 1 while ring-3 returns execute `verw` (read by `trap_entry.S`, which
/// tests it on every return to ring 3).
#[unsafe(no_mangle)]
pub static X86_VERW_ON_EXIT: AtomicU8 = AtomicU8::new(0);

static SPEC_CTRL_BITS: AtomicU64 = AtomicU64::new(0);
static EFER_AIBRS_ON: AtomicBool = AtomicBool::new(false);
static DE_CFG_ZENBLEED_ON: AtomicBool = AtomicBool::new(false);
static GDS_ENABLE: AtomicBool = AtomicBool::new(false);

/// Read the boot CPU's facts: CPUID, then the MSRs behind its bits.
pub fn probe() -> Probe {
    let leaves = read_cpuid();
    let arch_caps = needs_arch_caps(&leaves).then(|| rdmsr(MSR_IA32_ARCH_CAPABILITIES));
    let mcu_opt_ctrl = match arch_caps {
        Some(c) if needs_mcu_opt_ctrl(c) => rdmsr(MSR_IA32_MCU_OPT_CTRL),
        _ => 0,
    };
    let ident = crate::features::decode_ident(&leaves);
    let ucode_rev = if needs_ucode_rev(&ident) { rdmsr(MSR_AMD64_PATCH_LEVEL) as u32 } else { 0 };
    Probe::new(&leaves, arch_caps, mcu_opt_ctrl, ucode_rev)
}

/// Decide for the boot CPU and record what every CPU is to do: the `verw`
/// flag takes effect at once, the MSR writes in [`apply_this_cpu`] and the
/// thunk's patch in [`patch_thunk`]. Boot CPU, once, before any other CPU runs.
pub fn select(pol: &Policies) -> (Probe, Report, Plan) {
    let pr = probe();
    let (report, plan) = decide(&pr, pol);
    SPEC_CTRL_BITS.store(plan.spec_ctrl, Ordering::Relaxed);
    EFER_AIBRS_ON.store(plan.efer_aibrs, Ordering::Relaxed);
    DE_CFG_ZENBLEED_ON.store(plan.de_cfg_zenbleed, Ordering::Relaxed);
    GDS_ENABLE.store(plan.gds_enable, Ordering::Relaxed);
    X86_VERW_ON_EXIT.store(plan.verw_on_exit as u8, Ordering::Release);
    (pr, report, plan)
}

/// Patch the indirect-branch thunk to the plan's mode (boot CPU, once,
/// before the kernel's tables make the text read-only); whether the bytes
/// read back. Only a kernel built with the thunk (Kconfig `X86_MIT_SPECTRE_V2`
/// = probe) reaches it.
///
/// # Safety
/// As [`crate::retpoline::set_mode`].
pub unsafe fn patch_thunk(plan: &Plan) -> bool {
    // SAFETY: the caller's contract.
    unsafe { crate::retpoline::set_mode(plan.thunk) }
}

/// Write this CPU's controls (the boot CPU after [`select`], each secondary
/// before it takes work). Nothing is touched for a verdict that asked for
/// nothing.
pub fn apply_this_cpu() {
    let bits = SPEC_CTRL_BITS.load(Ordering::Relaxed);
    if bits != 0 {
        wrmsr(MSR_IA32_SPEC_CTRL, rdmsr(MSR_IA32_SPEC_CTRL) | bits);
    }
    if EFER_AIBRS_ON.load(Ordering::Relaxed) {
        wrmsr(MSR_EFER, rdmsr(MSR_EFER) | EFER_AIBRS);
    }
    if DE_CFG_ZENBLEED_ON.load(Ordering::Relaxed) {
        wrmsr(MSR_AMD64_DE_CFG, rdmsr(MSR_AMD64_DE_CFG) | DE_CFG_ZEN2_FP_BACKUP_FIX);
    }
    if GDS_ENABLE.load(Ordering::Relaxed) {
        wrmsr(MSR_IA32_MCU_OPT_CTRL, rdmsr(MSR_IA32_MCU_OPT_CTRL) & !MCU_OPT_GDS_MITG_DIS);
    }
}

/// What this CPU's controls read back as: `(IA32_SPEC_CTRL, EFER)`, 0 where
/// the plan wrote nothing. For the boot line.
pub fn readback_this_cpu() -> (u64, u64) {
    let sc = if SPEC_CTRL_BITS.load(Ordering::Relaxed) != 0 { rdmsr(MSR_IA32_SPEC_CTRL) } else { 0 };
    let efer = if EFER_AIBRS_ON.load(Ordering::Relaxed) { rdmsr(MSR_EFER) } else { 0 };
    (sc, efer)
}
