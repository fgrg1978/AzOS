// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_arch`, used only so `tests/host/gguf-tests` can
//! compile `crates/core/ml/src/ggml_nano.rs`'s `dot()` dispatcher, which calls
//! `azos_arch::vector::dot_f32_best`.
//!
//! **Why this is a reimplementation, not a `#[path]` pull, unlike every
//! other shim in this tree.** The real function lives in
//! `crates/core/arch-riscv64/src/vector.rs`, which is `cfg(target_arch =
//! "riscv64")`-gated at its own top (`use crate::rvv;`) — on a host build
//! that `use` simply does not compile in, so a naive `#[path]` pull leaves
//! `rvv::dot_f32_scalar` unresolved. Its scalar fallback body
//! (`crate::rvv::dot_f32_scalar`, `crates/core/arch-riscv64/src/rvv.rs`) IS pure
//! arithmetic, but that file also contains `rdcycle()`, which is
//! unconditional inline RISC-V `asm!` with no `cfg` guard at all — the
//! whole file fails to assemble on a non-riscv64 host regardless of which
//! function a caller wants.
//!
//! So this reimplements the three-line scalar algorithm instead of pulling
//! it. Verified byte-for-byte against `crates/core/arch-riscv64/src/rvv.rs::
//! dot_f32_scalar` by inspection (both: `let n = a.len().min(b.len()); let
//! mut acc = 0.0f32; for i in 0..n { acc += a[i] * b[i]; } acc`) — if that
//! function ever changes, this copy must change with it; nothing enforces
//! that automatically, which is the one respect in which this shim is
//! weaker than the `#[path]`-based ones elsewhere in the tree (`mm-tests`,
//! `sched-wake-tests`). The RVV-accelerated path (`rvv::dot_f32_rvv`,
//! feature-gated, never compiled on host either way) is out of scope: no
//! host test can exercise a V-extension kernel.
pub mod vector {
    /// Mirrors `crates/core/arch-riscv64/src/vector.rs::dot_f32_best`'s
    /// non-`rvv` branch, which is the only branch any host build reaches.
    pub fn dot_f32_best(a: &[f32], b: &[f32]) -> f32 {
        dot_f32_scalar(a, b)
    }

    /// See module doc: hand-verified copy of
    /// `crates/core/arch-riscv64/src/rvv.rs::dot_f32_scalar`.
    pub fn dot_f32_scalar(a: &[f32], b: &[f32]) -> f32 {
        let n = a.len().min(b.len());
        let mut acc = 0.0f32;
        for i in 0..n {
            acc += a[i] * b[i];
        }
        acc
    }
}
