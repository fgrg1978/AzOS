// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ggml-nano — minimal tensor engine for embedded MLP inference.
//!
//! Implements the two operations needed for a small policy network:
//!
//! 1. **`linear_layer`** — matrix-vector multiply + bias + optional ReLU.
//!    Processes one output row at a time to keep stack usage bounded.
//!    Supports F32, Q8_0 and Q4_0 weight matrices (dequantised on the fly).
//!
//! 2. **`gguf_mlp_infer`** — run a 2-layer MLP stored in a GGUF file.
//!    Expected tensor names: `"w1"`, `"b1"`, `"w2"`, `"b2"`.
//!
//! No heap allocation; all temporaries are bounded stack arrays.
//!
//! # Feature gate
//!
//! When built with `--features rvv`, dot products call `dot_f32_rvv`
//! (RVV 1.0 SIMD), otherwise `dot_f32_scalar`.

use crate::quant::{dequant_q8_0, dequant_q4_0, dequant_f32};
use crate::gguf::{GgufFile, GgmlType};

/// Maximum layer width (neurons) supported with stack-only temporaries.
pub const MAX_WIDTH: usize = 256;

// ── linear_layer ──────────────────────────────────────────────────────────────

/// Dense linear layer: `out[i] = act(bias[i] + dot(W[i], x))`.
///
/// `w_data` — raw weight bytes (F32 / Q8_0 / Q4_0).
/// `w_type` — quantisation type of `w_data`.
/// `b_data` — F32 little-endian bias vector (`out_sz × 4` bytes).
/// `activation` — 0 = linear, 1 = ReLU.
pub fn linear_layer(
    w_data: &[u8], w_type: GgmlType,
    b_data: &[u8],
    x:      &[f32],
    out:    &mut [f32],
    activation: u8,
) {
    let out_sz = out.len();
    let in_sz  = x.len();
    if in_sz > MAX_WIDTH || out_sz > MAX_WIDTH { return; }

    // Bytes per row of the weight matrix.
    let row_bytes = match w_type {
        GgmlType::F32  => in_sz * 4,
        GgmlType::Q8_0 => ((in_sz + 31) / 32) * 34,
        GgmlType::Q4_0 => ((in_sz + 31) / 32) * 18,
        _              => return,
    };

    let mut row_buf = [0.0f32; MAX_WIDTH];
    let row_buf = &mut row_buf[..in_sz];

    for i in 0..out_sz {
        let start = i * row_bytes;
        let end   = start + row_bytes;
        if end > w_data.len() { break; }

        match w_type {
            GgmlType::F32  => dequant_f32 (&w_data[start..end], row_buf),
            GgmlType::Q8_0 => dequant_q8_0(&w_data[start..end], row_buf),
            GgmlType::Q4_0 => dequant_q4_0(&w_data[start..end], row_buf),
            _              => {}
        }

        let bias = if b_data.len() >= (i + 1) * 4 {
            f32::from_le_bytes([b_data[i*4], b_data[i*4+1], b_data[i*4+2], b_data[i*4+3]])
        } else { 0.0 };

        let val = bias + dot(row_buf, x);
        out[i] = if activation == 1 && val < 0.0 { 0.0 } else { val };
    }
}

// ── gguf_mlp_infer ────────────────────────────────────────────────────────────

/// Run a 2-layer MLP loaded from a GGUF file.
///
/// Looks up tensors `"w1"`, `"b1"`, `"w2"`, `"b2"` by name.
/// `input.len()` must equal `dims[0]` of `"w1"`.
/// `output.len()` must equal `dims[1]` of `"w2"`.
///
/// Returns `false` if any tensor is missing or dimensions are inconsistent.
///
/// **U11-9 fix (2026-09-26).** Before this fix, none of the three "must"s in
/// this doc comment were checked: `linear_layer` computes its per-row byte
/// stride from `x.len()` (the CALLER's slice length), not from the tensor's
/// own `dims[0]`, so a `POLICY.GGF` whose `w1`/`w2` dims disagree with
/// `input.len()`/`output.len()`/each other did not refuse — it silently
/// dequantised the wrong byte ranges and returned logits computed from
/// misaligned weights. `dequant_q8_0`/`dequant_q4_0`/`dequant_f32` are all
/// bounds-safe on their own (they only ever write `out.len()` elements and
/// only read while a full block remains in `data`), so this was never a
/// memory-safety bug — it was a *silent wrong answer*, which for a policy
/// network driving motors is not a better failure mode than a panic.
pub fn gguf_mlp_infer(gguf: &GgufFile, input: &[f32], output: &mut [f32]) -> bool {
    let in_sz  = input.len();
    let out_sz = output.len();
    if in_sz > MAX_WIDTH || out_sz > MAX_WIDTH { return false; }

    // Fetch tensors.
    let Some((w1d, w1t, _)) = gguf.tensor_data(b"w1") else { return false; };
    let Some((b1d, _,   _)) = gguf.tensor_data(b"b1") else { return false; };
    let Some((w2d, w2t, _)) = gguf.tensor_data(b"w2") else { return false; };
    let Some((b2d, _,   _)) = gguf.tensor_data(b"b2") else { return false; };

    // Hidden size = dims[1] of w1 (rows = output neurons of layer 1).
    let Some(w1i) = gguf.tensor_info(b"w1") else { return false; };
    let Some(w2i) = gguf.tensor_info(b"w2") else { return false; };
    let hid_sz = w1i.dims[1] as usize;
    if hid_sz > MAX_WIDTH { return false; }

    // U11-9: every dimension `linear_layer` is about to ASSUME must match
    // what the file actually declares, checked before either call —
    // `w1.dims[0]` is the caller's `input.len()`, `w2.dims[0]` is the
    // hidden width `w1.dims[1]` just computed (the two layers must agree on
    // it independently of what either weight matrix's byte length implies),
    // and `w2.dims[1]` is the caller's `output.len()`.
    if w1i.dims[0] as usize != in_sz { return false; }
    if w2i.dims[0] as usize != hid_sz { return false; }
    if w2i.dims[1] as usize != out_sz { return false; }

    // Layer 1: input → hidden (ReLU)
    let mut hidden = [0.0f32; MAX_WIDTH];
    linear_layer(w1d, w1t, b1d, input, &mut hidden[..hid_sz], 1 /*relu*/);

    // Layer 2: hidden → output (linear)
    linear_layer(w2d, w2t, b2d, &hidden[..hid_sz], output, 0 /*linear*/);

    true
}

/// Argmax over a slice — returns the index of the largest value.
pub fn argmax(v: &[f32]) -> usize {
    let mut best = 0;
    for i in 1..v.len() { if v[i] > v[best] { best = i; } }
    best
}

// ── Dot-product dispatcher ────────────────────────────────────────────────────

/// The crate's dot product (`crate::dot`): RVV SIMD when available.
#[inline(always)]
fn dot(a: &[f32], b: &[f32]) -> f32 {
    crate::dot(a, b)
}
