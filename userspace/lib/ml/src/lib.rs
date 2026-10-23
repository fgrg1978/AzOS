// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
#![forbid(unsafe_code)]
//! ML runtime for AzOS — the GGUF engine and the signed model bundle.
//!
//! ## Modules
//!
//! - `gguf`      — minimal GGUF v1–v3 parser, no_std / no alloc (Phase C)
//! - `quant`     — F32 / Q8_0 / Q4_0 dequantisation (Phase C)
//! - `ggml_nano` — linear-layer engine + `gguf_mlp_infer` (Phase C)
//! - `bundle`    — the signed `.MBL` model bundle the inference service reads
//!
//! The behavior loop's 4→8→3 obstacle-avoidance MLP is a GGUF file
//! (`tools/make_gguf.py`) wrapped in a bundle (`tools/make_mbl.py`); its
//! analytically derived weights are documented there. The network takes
//! `[dist_front, dist_right, velocity, battery]` (normalised 0..1) and answers
//! three raw logits, `[go_forward, turn_right, stop]`.
//!
//! # Dot products
//!
//! Every linear layer sums with the plain sequential loop in [`dot`]: no
//! SIMD, no kernel crate. The ring-3 inference service is the only runtime
//! user, and passes its own (vector) kernel where the hart has one.

// ── Phase C submodules ────────────────────────────────────────────────────────
pub mod gguf;
pub mod quant;
pub mod ggml_nano;
// ── Signed model bundle (.MBL): per-backend variants and a signed cost table ─
pub mod bundle;

/// Human-readable class names for the 3 output neurons of the behavior MLP.
pub const CLASS_NAMES: [&str; 3] = ["go_forward", "turn_right", "stop"];

/// Dot product: the sequential loop, left to right. `ggml_nano`'s default.
#[inline(always)]
pub(crate) fn dot(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    let mut acc: f32 = 0.0;
    for i in 0..n {
        acc += a[i] * b[i];
    }
    acc
}
