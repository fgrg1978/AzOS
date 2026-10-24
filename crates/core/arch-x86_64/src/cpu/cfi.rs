// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Hardware control-flow integrity on x86_64: CET indirect-branch tracking
//! for the kernel's own code (Kconfig `X86_CET_IBT`; plan item I4).
//!
//! The compiler half is `-Z cf-protection=branch` (tools/build/kconfig_to_cargo.py,
//! `cfi_rustflags`): an `endbr64` at every function entry, a multi-byte NOP on
//! a CPU without CET. The hand-written entry points carry theirs too
//! (kernel/src/entry/x86_64/asm: every vector stub, `syscall_entry`, the
//! secondary and Limine entries, `context_switch`; `tests/host/cfi-tests`
//! scans for a missing one). This half turns the check on: with
//! `IA32_S_CET.ENDBR_EN` set, an indirect `call` or `jmp` in ring 0 whose
//! target is not an `endbr64` raises #CP (vector 21, error code 3).
//!
//! * `NO_TRACK_EN`: a `notrack jmp` through a jump table skips the check.
//!   The compiler emits those whenever it builds a jump table with branch
//!   protection on (verified on the pinned nightly), and the kernel keeps
//!   its jump tables: Kconfig `X86_MIT_SPECTRE_V2 = probe` already forbids
//!   them (retpoline) and a build without it takes them. The table sits in
//!   read-only memory, which is what makes the untracked jump safe.
//! * `context_switch` resumes a task through a `ret`, not a `jmp`: the
//!   resume address is no landing pad.
//! * No shadow stack (`X86_CET_SHSTK`): not enabled, see
//!   config/kernel/Kconfig.hardening, "Hardware control-flow integrity".
//! * Ring 3 gets nothing from this: `IA32_U_CET` is per process (an XSAVES
//!   supervisor/user component), so the vDSO's `HWCAP_X86_CET_IBT`, which
//!   reads `CR4.CET`, says the kernel enforces on itself.
//!
//! Every CPU runs [`enable_ibt_this_cpu`] once, after `CR0.WP` is set
//! (`CR4.CET` raises #GP without it): the boot CPU from `cpu_features`'
//! `post_heap` step, each secondary in `x86_64_secondary_entry`, next to
//! `mmu::cpu::enable_access_protection`.

/// `IA32_S_CET`: the supervisor CET controls (SDM Vol. 4).
pub const IA32_S_CET: u32 = 0x6A2;
/// `IA32_S_CET.ENDBR_EN` (bit 2): indirect-branch tracking for ring 0.
pub const S_CET_ENDBR_EN: u64 = 1 << 2;
/// `IA32_S_CET.NO_TRACK_EN` (bit 4): `notrack` indirect branches skip the check.
pub const S_CET_NO_TRACK_EN: u64 = 1 << 4;
/// `CR4.CET` (bit 23): the CET master enable (shadow stack and IBT).
pub const CR4_CET: u64 = 1 << 23;

/// What this kernel writes to `IA32_S_CET`: tracking on, `notrack` honoured.
/// The shadow-stack bits (SH_STK_EN, WR_SHSTK_EN) stay clear.
pub const S_CET_KERNEL: u64 = S_CET_ENDBR_EN | S_CET_NO_TRACK_EN;

/// Turn kernel IBT on for this CPU when `allowed` (the Kconfig policy applied
/// to what CPUID.(7,0):EDX[20] said: `X86_CET_IBT.gate(features.cet_ibt)`).
/// Returns whether it is on. `CR4.CET` first, then the MSR, the order Linux
/// uses; the next indirect branch on this CPU is already checked.
#[cfg(target_arch = "x86_64")]
pub fn enable_ibt_this_cpu(allowed: bool) -> bool {
    if !allowed {
        return false;
    }
    let cr4: u64;
    // SAFETY: CPL 0 reads and writes of CR4; the caller ran
    // `mmu::cpu::setup_paging_regs` (CR0.WP set), and `allowed` means CPUID
    // reported IBT, so CR4.CET and IA32_S_CET exist.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov cr4, {}", in(reg) cr4 | CR4_CET, options(nostack, preserves_flags));
    }
    super::wrmsr(IA32_S_CET, super::rdmsr(IA32_S_CET) | S_CET_KERNEL);
    super::rdmsr(IA32_S_CET) & S_CET_ENDBR_EN != 0
}

/// Off x86_64 there is no CET.
#[cfg(not(target_arch = "x86_64"))]
pub fn enable_ibt_this_cpu(_allowed: bool) -> bool {
    false
}
