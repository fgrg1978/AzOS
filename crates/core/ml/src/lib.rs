// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
//! ML runtime for AzOS — Phases 12/15 (RMLP) + Phase C (ggml-nano/GGUF).
//!
//! ## Modules
//!
//! - `(root)` — 4→8→3 MLP with RMLP dynamic loading (Phases 12/15)
//! - `gguf`      — minimal GGUF v1–v3 parser, no_std / no alloc (Phase C)
//! - `quant`     — F32 / Q8_0 / Q4_0 dequantisation (Phase C)
//! - `ggml_nano` — linear-layer engine + `gguf_mlp_infer` (Phase C)
//!
//! # Original MLP doc (Phase 12/15)
//!
//! Implements a 4→8→3 MLP (multi-layer perceptron) with analytically-derived
//! weights for embedded neural-network inference on RISC-V.
//!
//! # Network layout
//!
//! ```text
//! Input (4):  [dist_front, dist_right, velocity, battery]  — normalised 0..1
//! Hidden (8): ReLU activation
//! Output (3): [go_forward, turn_right, stop]               — raw logits
//! ```
//!
//! # Weight design (Phase 14 — analytically verified)
//!
//! Hidden neurons act as interpretable feature detectors:
//! - h0 = ReLU(dist_front − 0.5)   → clearway signal
//! - h1 = ReLU(−dist_front + 0.3)  → obstacle signal
//! - h2 = ReLU(dist_right − 0.2)   → right-clear (aux, not used in W2)
//! - h3 = ReLU(−dist_right + 0.25) → right-wall signal
//! - h4 = ReLU(dist_front − 0.3)   → moderate clearway (aux)
//! - h5-h7: unused (zero weights)
//!
//! Output neurons: go_forward = 2·h0, turn_right = 3·h3, stop = 3·h1
//!
//! Verified scenarios:
//! - [0.8, 0.3, *, *] → logits [0.600, 0.000, 0.000] → go_forward  ✓
//! - [0.6, 0.1, *, *] → logits [0.200, 0.450, 0.000] → turn_right  ✓
//! - [0.1, 0.5, *, *] → logits [0.000, 0.000, 0.600] → stop        ✓
//!
//! # Dynamic model loading (Phase 15)
//!
//! Call `model_load_bytes(data)` with the contents of a `.rmlp` file read
//! from FAT32.  After a successful load, `mlp_infer` transparently uses the
//! dynamic weights instead of the compile-time constants.
//!
//! RMLP file format (292 bytes):
//! ```text
//! [4]  magic   : b"RMLP"
//! [4]  version : u32le = 1
//! [4]  in_sz   : u32le = 4
//! [4]  hid_sz  : u32le = 8
//! [4]  out_sz  : u32le = 3
//! [4]  reserved: u32le = 0
//! [128] W1: [f32le; 32]
//! [32]  B1: [f32le;  8]
//! [96]  W2: [f32le; 24]
//! [12]  B2: [f32le;  3]
//! ```
//!
//! # Feature gate
//!
//! `rvv` — use `dot_f32_rvv` (RVV 1.0 SIMD) for the linear layers;
//!          otherwise falls back to `dot_f32_scalar`.

// ── Phase C submodules ────────────────────────────────────────────────────────
pub mod gguf;
pub mod quant;
pub mod ggml_nano;
// ── Phase F08: Convolutional operators ──────────────────────────────────────
pub mod conv;
// ── Phase F08.8: INT8 quantized inference ──────────────────────────────────
pub mod int8;
// ── Phase F15: Zero-copy inference pipeline ─────────────────────────────────
pub mod pipeline;

use core::sync::atomic::{AtomicBool, Ordering};

// ── Network dimensions ────────────────────────────────────────────────────────

const IN:  usize = 4;   // input features
const HID: usize = 8;   // hidden neurons
const OUT: usize = 3;   // output classes

// ── Compile-time weights (4→8→3 analytically-derived MLP) ────────────────────
//
// Used when no .rmlp file has been loaded from FAT32.
// See module-level docs for the derivation and verification.

/// Layer 1 weight matrix  [HID × IN].
const W1: [f32; HID * IN] = [
//   dist_fwd  dist_rgt   vel     batt
     1.0,      0.0,       0.0,    0.0,   // h0 = ReLU(x0 - 0.5): clearway
    -1.0,      0.0,       0.0,    0.0,   // h1 = ReLU(-x0 + 0.3): obstacle
     0.0,      1.0,       0.0,    0.0,   // h2 = ReLU(x1 - 0.2): right-clear (aux)
     0.0,     -1.0,       0.0,    0.0,   // h3 = ReLU(-x1 + 0.25): right-wall
     1.0,      0.0,       0.0,    0.0,   // h4 = ReLU(x0 - 0.3): mod. clearway (aux)
     0.0,      0.0,       0.0,    0.0,   // h5 (unused)
     0.0,      0.0,       0.0,    0.0,   // h6 (unused)
     0.0,      0.0,       0.0,    0.0,   // h7 (unused)
];

/// Layer 1 bias vector  [HID].
const B1: [f32; HID] = [-0.5, 0.3, -0.2, 0.25, -0.3, 0.0, 0.0, 0.0];

/// Layer 2 weight matrix  [OUT × HID].
const W2: [f32; OUT * HID] = [
//   h0    h1    h2    h3    h4    h5    h6    h7
     2.0,  0.0,  0.0,  0.0,  0.0,  0.0,  0.0,  0.0,  // go_forward = 2·h0
     0.0,  0.0,  0.0,  3.0,  0.0,  0.0,  0.0,  0.0,  // turn_right = 3·h3
     0.0,  3.0,  0.0,  0.0,  0.0,  0.0,  0.0,  0.0,  // stop       = 3·h1
];

/// Layer 2 bias vector  [OUT].
const B2: [f32; OUT] = [0.0, 0.0, 0.0];

// ── Dynamic weights (loaded from FAT32 at runtime — Phase 15) ────────────────

/// Weights loaded from a `.rmlp` file.
///
/// Stored in a static, protected by `DWEIGHTS_VALID` (Release/Acquire).
/// Written once (during boot or `model load` shell command), then read-only.
#[derive(Clone, Copy)]
pub struct DynWeights {
    pub w1: [f32; HID * IN],
    pub b1: [f32; HID],
    pub w2: [f32; OUT * HID],
    pub b2: [f32; OUT],
}

static mut DWEIGHTS_STORAGE: DynWeights = DynWeights {
    w1: [0.0f32; HID * IN],
    b1: [0.0f32; HID],
    w2: [0.0f32; OUT * HID],
    b2: [0.0f32; OUT],
};

/// Set to `true` (Release) after `DWEIGHTS_STORAGE` is fully written.
/// Readers use Acquire to guarantee they see the complete write.
static DWEIGHTS_VALID: AtomicBool = AtomicBool::new(false);

// ── RMLP file constants ───────────────────────────────────────────────────────

const RMLP_MAGIC:   &[u8; 4] = b"RMLP";
const RMLP_VERSION: u32       = 1;
const RMLP_HDR:     usize     = 24;
const RMLP_DATA:    usize     = (HID * IN + HID + OUT * HID + OUT) * 4; // 268 B
const RMLP_TOTAL:   usize     = RMLP_HDR + RMLP_DATA;                   // 292 B

// ── Public API ────────────────────────────────────────────────────────────────

/// Human-readable class names for the 3 output neurons.
pub const CLASS_NAMES: [&str; OUT] = ["go_forward", "turn_right", "stop"];

/// Demo input: robot with clear path ahead → predicts go_forward.
pub const DEMO_INPUT: [f32; IN] = [0.8, 0.3, 0.5, 0.9];

/// Run the 4→8→3 MLP and return raw logits `[OUT]`.
///
/// If a model was loaded via `model_load_bytes`, uses the dynamic weights;
/// otherwise uses the compile-time constants.
///
/// When built with `--features rvv`, dot products use `dot_f32_rvv`.
pub fn mlp_infer(input: &[f32; IN]) -> [f32; OUT] {
    if DWEIGHTS_VALID.load(Ordering::Acquire) {
        let w = unsafe { &*(&raw const DWEIGHTS_STORAGE) };
        mlp_forward(&w.w1, &w.b1, &w.w2, &w.b2, input)
    } else {
        mlp_forward(&W1, &B1, &W2, &B2, input)
    }
}

/// Argmax over 3 logits — returns the index of the largest value.
pub fn argmax3(v: &[f32; OUT]) -> usize {
    let mut best = 0usize;
    for i in 1..OUT {
        if v[i] > v[best] { best = i; }
    }
    best
}

/// Load weights from a `.rmlp` file byte slice.
///
/// Returns `true` on success.  On success, subsequent calls to `mlp_infer`
/// will use the new weights transparently.  Returns `false` if the data is
/// too short, has a wrong magic/version, or has incompatible dimensions.
///
/// Thread-safety: uses Release ordering on `DWEIGHTS_VALID`.  Safe to call
/// from a single writer (boot task or shell) while readers use Acquire.
pub fn model_load_bytes(data: &[u8]) -> bool {
    if data.len() < RMLP_TOTAL                        { return false; }
    if &data[0..4] != RMLP_MAGIC                      { return false; }
    if u32_le(&data[4..8])   != RMLP_VERSION          { return false; }
    if u32_le(&data[8..12])  as usize != IN           { return false; }
    if u32_le(&data[12..16]) as usize != HID          { return false; }
    if u32_le(&data[16..20]) as usize != OUT          { return false; }

    let mut w = DynWeights {
        w1: [0.0; HID * IN],
        b1: [0.0; HID],
        w2: [0.0; OUT * HID],
        b2: [0.0; OUT],
    };
    let mut off = RMLP_HDR;
    for i in 0..HID * IN  { w.w1[i] = f32_le(&data[off + i * 4..]); }
    off += HID * IN  * 4;
    for i in 0..HID        { w.b1[i] = f32_le(&data[off + i * 4..]); }
    off += HID * 4;
    for i in 0..OUT * HID  { w.w2[i] = f32_le(&data[off + i * 4..]); }
    off += OUT * HID * 4;
    for i in 0..OUT        { w.b2[i] = f32_le(&data[off + i * 4..]); }

    // Write then publish.
    unsafe { *(&raw mut DWEIGHTS_STORAGE) = w; }
    DWEIGHTS_VALID.store(true, Ordering::Release);
    true
}

/// Returns `true` if dynamic weights are active (a `.rmlp` was loaded).
pub fn model_is_loaded() -> bool {
    DWEIGHTS_VALID.load(Ordering::Acquire)
}

/// Expected size of a valid `.rmlp` file in bytes.
pub const RMLP_FILE_SIZE: usize = RMLP_TOTAL;

// ── Internal computation ──────────────────────────────────────────────────────

/// Core MLP forward pass (weights passed by reference).
fn mlp_forward(w1: &[f32], b1: &[f32], w2: &[f32], b2: &[f32],
               input: &[f32; IN]) -> [f32; OUT] {
    // Layer 1: linear + ReLU
    let mut h = [0.0f32; HID];
    for j in 0..HID {
        let row = &w1[j * IN..(j + 1) * IN];
        h[j] = b1[j] + dot(row, input.as_ref());
        if h[j] < 0.0 { h[j] = 0.0; }
    }
    // Layer 2: linear (raw logits)
    let mut out = [0.0f32; OUT];
    for j in 0..OUT {
        let row = &w2[j * HID..(j + 1) * HID];
        out[j] = b2[j] + dot(row, h.as_ref());
    }
    out
}

/// Dot product dispatcher: uses `dot_f32_rvv` when the `rvv` feature is active.
/// Shared by `conv` and `ggml_nano`.
#[cfg(feature = "arch")]
#[inline(always)]
pub(crate) fn dot(a: &[f32], b: &[f32]) -> f32 {
    azos_arch::vector::dot_f32_best(a, b)
}

/// Without `arch`: the sequential loop, in the order `dot_f32_scalar` sums.
#[cfg(not(feature = "arch"))]
#[inline(always)]
pub(crate) fn dot(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    let mut acc: f32 = 0.0;
    for i in 0..n {
        acc += a[i] * b[i];
    }
    acc
}

// ── RMLP parsing helpers ──────────────────────────────────────────────────────

#[inline(always)]
fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[inline(always)]
fn f32_le(b: &[u8]) -> f32 {
    f32::from_bits(u32_le(b))
}
