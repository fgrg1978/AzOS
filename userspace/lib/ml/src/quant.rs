// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Dequantization helpers for GGML quantisation formats.
//!
//! Supports the formats used by small on-device models:
//! - **F32**  — copy as-is (little-endian bytes → f32)
//! - **Q8_0** — 34-byte blocks: 2-byte f16 scale + 32 × i8
//! - **Q4_0** — 18-byte blocks: 2-byte f16 scale + 16 bytes of packed 4-bit values
//!
//! All functions write into a caller-supplied `&mut [f32]` slice and clamp to
//! its length.
//!
//! That sentence used to end "so no bounds check is needed at call sites", and
//! it was wrong for `dequant_q4_0` with an odd-length slice: the guard counted
//! the slot it started at while the body wrote two, so the last iteration wrote
//! one past the end. Rust's bounds check caught it — as an abort. The clamp is
//! the contract, and `an_odd_output_length_is_not_written_past` in
//! `tests/host/gguf-tests` is what holds it, because a comment held it before and
//! the function had no test at all.

/// Convert a 16-bit half-precision float (IEEE 754-2008) to `f32`.
///
/// Infinities and NaN are mapped to 0.0 for safety in embedded inference.
#[inline(always)]
pub fn f16_to_f32(h: u16) -> f32 {
    let sign = ((h as u32) >> 15) & 1;
    let exp  = ((h as u32) >> 10) & 0x1F;
    let mant =  (h as u32)        & 0x3FF;
    match exp {
        0 => {
            // Subnormal / zero
            let f = (mant as f32) * (1.0f32 / (1u32 << 24) as f32);
            if sign != 0 { -f } else { f }
        }
        31 => 0.0f32, // Inf / NaN → 0 (safe for inference)
        _ => {
            let bits = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
            f32::from_bits(bits)
        }
    }
}

/// Dequantize a **Q8_0** byte slice into `f32` values.
///
/// Each block is 34 bytes: `[f16 scale (2 B)][i8 × 32 (32 B)]`.
/// `out.len()` elements are written; excess data is ignored.
pub fn dequant_q8_0(data: &[u8], out: &mut [f32]) {
    const BSIZ: usize = 34; // 2 + 32
    let n    = out.len();
    let mut elem = 0usize;
    let mut off  = 0usize;
    while elem < n && off + BSIZ <= data.len() {
        let scale = f16_to_f32(u16::from_le_bytes([data[off], data[off + 1]]));
        off += 2;
        for i in 0..32 {
            if elem >= n { break; }
            out[elem] = (data[off + i] as i8) as f32 * scale;
            elem += 1;
        }
        off += 32;
    }
}

/// Dequantize a **Q4_0** byte slice into `f32` values.
///
/// Each block is 18 bytes: `[f16 scale (2 B)][nibbles × 16 (16 B)]`.
/// Each nibble is an unsigned 4-bit value in range 0..15, shifted by −8 → −8..7.
pub fn dequant_q4_0(data: &[u8], out: &mut [f32]) {
    const BSIZ: usize = 18; // 2 + 16
    let n    = out.len();
    let mut elem = 0usize;
    let mut off  = 0usize;
    while elem < n && off + BSIZ <= data.len() {
        let scale = f16_to_f32(u16::from_le_bytes([data[off], data[off + 1]]));
        off += 2;
        for i in 0..16 {
            // `elem + 2`, not `elem + 1`: the body below writes TWO slots, so
            // the guard has to count the slots it is about to write, not the
            // one it starts at. With `n` odd the old test read `n > n` on the
            // last iteration — false, so it did not break — and then wrote
            // `out[n]`. The bounds check caught it, which under
            // `panic = "abort"` is a board reset; and the kernel feeds this
            // path a file off the data partition at every boot
            // (`/fat/POLICY.GGF`, `kernel/src/main.rs`), so an odd `dims[1]`
            // on a Q4_0 tensor was a boot loop anyone with write access to
            // that partition could arrange.
            if elem + 2 > n { break; }
            let byte = data[off + i];
            out[elem]     = ((byte & 0xF) as i32 - 8) as f32 * scale;
            out[elem + 1] = (((byte >> 4) & 0xF) as i32 - 8) as f32 * scale;
            elem += 2;
        }
        off += 16;
    }
}

/// Copy a **F32** tensor (little-endian bytes) into `out`.
pub fn dequant_f32(data: &[u8], out: &mut [f32]) {
    let n = out.len().min(data.len() / 4);
    for i in 0..n {
        out[i] = f32::from_le_bytes([data[i*4], data[i*4+1], data[i*4+2], data[i*4+3]]);
    }
}
