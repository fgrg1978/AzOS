// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cross-arch `vector::*` surface for RISC-V.
//!
//! Mirrors [`arch-aarch64::vector`] and [`arch-x86_64::vector`] so
//! kernel call sites can write `azos_arch::vector::dot_f32_best`
//! and get the right impl on every ISA without `cfg(target_arch)`
//! soup in the caller (Item 2 Stage 3 batch 4).
//!
//! The RISC-V-specific kernels (`dot_f32_rvv`, `matmul_f32_rvv`,
//! the bench harness) stay in [`crate::rvv`] — this module is just
//! the portable face of the same code, doing the V-extension
//! detection internally instead of pushing it onto callers.

#[cfg(target_arch = "riscv64")]
use crate::rvv;

/// Scalar f32 dot product. Same impl as [`rvv::dot_f32_scalar`];
/// re-exposed here so the cross-arch surface is complete.
#[inline]
pub fn dot_f32_scalar(a: &[f32], b: &[f32]) -> f32 {
    rvv::dot_f32_scalar(a, b)
}

/// Best available f32 dot product for the current build. With the
/// `rvv` feature on and the V extension compiled in, dispatches to
/// [`rvv::dot_f32_rvv`]; otherwise falls back to the scalar form.
///
/// Kconfig `RV_V`: n compiles the vector kernels out; probe and require
/// compile them in and take them only when the boot found V
/// ([`rvv::usable`]).
#[inline]
pub fn dot_f32_best(a: &[f32], b: &[f32]) -> f32 {
    #[cfg(all(target_arch = "riscv64", feature = "rvv"))]
    if rvv::usable() {
        return rvv::dot_f32_rvv(a, b);
    }
    rvv::dot_f32_scalar(a, b)
}

/// Human-readable name of the kernel currently selected by
/// [`dot_f32_best`]. Mirror of `arch-aarch64::vector::active_backend`
/// / `arch-x86_64::vector::active_backend`. Procfs / boot banner
/// can print this without caring about the ISA.
pub fn active_backend() -> &'static str {
    #[cfg(all(target_arch = "riscv64", feature = "rvv"))]
    if rvv::usable() {
        return "RVV";
    }
    "scalar"
}
