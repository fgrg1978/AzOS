// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! NEON / SIMD context save + restore for aarch64.
//!
//! Analog of `arch-x86_64::xsave` for the ARMv8 FP/SIMD register
//! file. Any kernel that lets multiple tasks use NEON (which
//! includes our `Vector::dot_f32` impl + any LLVM auto-
//! vectorisation under the hard-float target) MUST save Q0-Q31
//! + FPSR + FPCR across context switches, otherwise switching
//! between two NEON-using tasks corrupts the vector register
//! file of whichever task wasn't running.
//!
//! Scope:
//!   - 528-byte `FpState` struct (32 × 16 B for Q0..Q31 + 4 B
//!     FPSR + 4 B FPCR + 8 B padding for 16-byte alignment).
//!   - `save_fp_state` / `restore_fp_state` — eight stp/ldp
//!     instructions plus the two status-reg MSR reads.
//!
//! Lazy FP (CPACR_EL1.FPEN trap on first EL0 FP use, save on
//! switch-out only if used) is built on these two helpers in
//! `kernel/src/entry/aarch64/fp_lazy.rs`; `context_switch.S`
//! carries its own copy of the save sequence (same layout).
//!
//! Out of scope:
//!   - SVE state (Z0..Z31, P0..P15, FFR) — vector-length-
//!     dependent, needs `STR Zn` family. Lands when we have
//!     real SVE hardware to test on.

#![allow(dead_code)]

use core::mem::{size_of, align_of};

/// FPU/SIMD state snapshot. Layout:
///   [0]    Q0..Q31    32 × 16 B = 512 B
///   [512]  FPSR       4 B (status)
///   [516]  FPCR       4 B (control)
///   [520]  padding    8 B (16-byte alignment)
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug)]
pub struct FpState(pub [u8; 528]);

impl FpState {
    pub const fn zero() -> Self {
        FpState([0u8; 528])
    }
}

/// Manual, not derived: `impl Default for [T; N]` in `core` only goes up to
/// N = 32 (pre-const-generics compatibility shim), and 528 is well past
/// that. `TrapFrame` (kernel/src/entry/aarch64.rs) embeds an `FpState` and
/// derives `Default`, so this impl is load-bearing for that derive, not
/// decoration.
impl Default for FpState {
    fn default() -> Self {
        Self::zero()
    }
}

/// Save the current NEON + FPSR + FPCR state into `area`.
///
/// Uses 16 `stp` instructions (each stores 2 × Q-reg = 32 B)
/// plus two `mrs` reads — together that's 32 Q-regs + the
/// two status registers, written contiguously.
///
/// # Safety
/// `area` must be writable; the 16-byte alignment from
/// `repr(align(16))` covers `stp` alignment requirements.
#[cfg(target_arch = "aarch64")]
#[inline(never)] // its own symbol: `tools/aarch64_fp_free_check.sh` allows it by name
pub unsafe fn save_fp_state(area: &mut FpState) {
    unsafe {
        core::arch::asm!(
            // The kernel is built soft-float (no FP/SIMD in the target), so
            // the assembler must be told these instructions are intended.
            ".arch_extension fp",
            ".arch_extension simd",
            "stp q0,  q1,  [{p}, #0  * 16]",
            "stp q2,  q3,  [{p}, #2  * 16]",
            "stp q4,  q5,  [{p}, #4  * 16]",
            "stp q6,  q7,  [{p}, #6  * 16]",
            "stp q8,  q9,  [{p}, #8  * 16]",
            "stp q10, q11, [{p}, #10 * 16]",
            "stp q12, q13, [{p}, #12 * 16]",
            "stp q14, q15, [{p}, #14 * 16]",
            "stp q16, q17, [{p}, #16 * 16]",
            "stp q18, q19, [{p}, #18 * 16]",
            "stp q20, q21, [{p}, #20 * 16]",
            "stp q22, q23, [{p}, #22 * 16]",
            "stp q24, q25, [{p}, #24 * 16]",
            "stp q26, q27, [{p}, #26 * 16]",
            "stp q28, q29, [{p}, #28 * 16]",
            "stp q30, q31, [{p}, #30 * 16]",
            "mrs {t1}, FPSR",
            "mrs {t2}, FPCR",
            "str {t1:w}, [{p}, #512]",
            "str {t2:w}, [{p}, #516]",
            p  = in(reg) area.0.as_mut_ptr(),
            t1 = out(reg) _,
            t2 = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
}

/// Restore NEON + FPSR + FPCR from a previous [`save_fp_state`]
/// snapshot. Zero-initialised `area` is valid — gives clean
/// vector regs.
///
/// # Safety
/// `area` must be 16-byte aligned (`repr(align(16))` ensures
/// it) and hold a valid snapshot.
#[cfg(target_arch = "aarch64")]
#[inline(never)] // its own symbol: `tools/aarch64_fp_free_check.sh` allows it by name
pub unsafe fn restore_fp_state(area: &FpState) {
    unsafe {
        core::arch::asm!(
            ".arch_extension fp",
            ".arch_extension simd",
            "ldr {t1:w}, [{p}, #512]",
            "ldr {t2:w}, [{p}, #516]",
            "msr FPSR, {t1}",
            "msr FPCR, {t2}",
            "ldp q0,  q1,  [{p}, #0  * 16]",
            "ldp q2,  q3,  [{p}, #2  * 16]",
            "ldp q4,  q5,  [{p}, #4  * 16]",
            "ldp q6,  q7,  [{p}, #6  * 16]",
            "ldp q8,  q9,  [{p}, #8  * 16]",
            "ldp q10, q11, [{p}, #10 * 16]",
            "ldp q12, q13, [{p}, #12 * 16]",
            "ldp q14, q15, [{p}, #14 * 16]",
            "ldp q16, q17, [{p}, #16 * 16]",
            "ldp q18, q19, [{p}, #18 * 16]",
            "ldp q20, q21, [{p}, #20 * 16]",
            "ldp q22, q23, [{p}, #22 * 16]",
            "ldp q24, q25, [{p}, #24 * 16]",
            "ldp q26, q27, [{p}, #26 * 16]",
            "ldp q28, q29, [{p}, #28 * 16]",
            "ldp q30, q31, [{p}, #30 * 16]",
            p  = in(reg) area.0.as_ptr(),
            t1 = out(reg) _,
            t2 = out(reg) _,
            options(nostack, preserves_flags, readonly),
        );
    }
}

// ── Host-build stubs ────────────────────────────────────────

#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn save_fp_state(_area: &mut FpState) {}
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn restore_fp_state(_area: &FpState) {}

// ── Compile-time sanity ─────────────────────────────────────

const _: () = {
    if size_of::<FpState>() != 528 {
        panic!("FpState must be 528 bytes (32 × Q16 + FPSR + FPCR + pad)");
    }
    if align_of::<FpState>() != 16 {
        panic!("FpState must be 16-byte aligned for stp/ldp");
    }
};
