// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 FP/SIMD state — SKELETON. **Eager, never lazy** (Kconfig
//! `FP_XSAVE_EAGER`): every context switch saves the outgoing task's
//! XSAVE area and restores the incoming one. Lazy switching (CR0.TS and a
//! #NM trap on first use) leaks the previous task's registers through
//! speculation (LazyFP, CVE-2018-3665); Linux made eager the default in
//! 4.6 and removed the lazy mode in 4.14.
//!
//! aarch64 switches lazily (`kernel/src/entry/aarch64/fp_lazy.rs`,
//! `CPACR_EL1.FPEN` trap on first use): that is a per-ISA choice, so the
//! shared scheduler must not assume either. An x86_64 port calls these from
//! `context_switch.S` / the switch path, and never arms a first-use trap.

/// Save the current FP/SIMD state into `area` (XSAVES, else XSAVEOPT, else
/// XSAVE with the XCR0 mask; FXSAVE without XSAVE).
///
/// # Safety
/// `area` must be a 64-byte-aligned XSAVE area of the size CPUID.(0xD,0)
/// reports for the enabled XCR0 components.
pub unsafe fn save_eager(_area: *mut u8) {
    todo!("x86_64: fpu::save_eager: XSAVES / XSAVEOPT / XSAVE on every switch")
}

/// Restore `area` (XRSTORS / XRSTOR / FXRSTOR).
///
/// # Safety
/// `area` must hold a state [`save_eager`] wrote, or the XSAVE init state.
pub unsafe fn restore_eager(_area: *const u8) {
    todo!("x86_64: fpu::restore_eager: XRSTORS / XRSTOR on every switch")
}
