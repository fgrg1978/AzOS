// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! INT8 quantized inference path (F08.8).
//!
//! Provides integer-only inference for CNN layers, avoiding the F32
//! dequantize → compute → requantize overhead. All operations use i32
//! accumulators with per-tensor scale/zero-point quantization (TFLite-style).
//!
//! Quantization scheme: `real_value = scale * (quantized_value - zero_point)`

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum tensor elements for stack-only temporaries.
pub const INT8_MAX_ELEMENTS: usize = 16384; // 128×128 or 96×96×~1.8

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Quantization parameters for a tensor.
#[derive(Clone, Copy)]
pub struct QuantParams {
    /// Scale factor: real = scale * (q - zero_point).
    pub scale: f32,
    /// Zero point offset.
    pub zero_point: i8,
}

impl QuantParams {
    pub const fn new(scale: f32, zero_point: i8) -> Self {
        Self { scale, zero_point }
    }

    /// Quantize a single f32 value to i8.
    pub fn quantize(&self, val: f32) -> i8 {
        let q = (val / self.scale) + self.zero_point as f32;
        q.clamp(-128.0, 127.0) as i8
    }

    /// Dequantize a single i8 value to f32.
    pub fn dequantize(&self, q: i8) -> f32 {
        self.scale * (q as f32 - self.zero_point as f32)
    }
}

// ---------------------------------------------------------------------------
// Quantize / Dequantize arrays
// ---------------------------------------------------------------------------

/// Quantize f32 array to i8 with given parameters.
pub fn quantize_tensor(src: &[f32], dst: &mut [i8], params: &QuantParams) {
    let n = src.len().min(dst.len());
    let inv_scale = 1.0 / params.scale;
    let zp = params.zero_point as f32;
    for i in 0..n {
        let q = src[i] * inv_scale + zp;
        dst[i] = q.clamp(-128.0, 127.0) as i8;
    }
}

/// Dequantize i8 array to f32.
pub fn dequantize_tensor(src: &[i8], dst: &mut [f32], params: &QuantParams) {
    let n = src.len().min(dst.len());
    for i in 0..n {
        dst[i] = params.scale * (src[i] as f32 - params.zero_point as f32);
    }
}

/// Compute quantization parameters from an f32 tensor (min/max calibration).
pub fn calibrate_params(data: &[f32]) -> QuantParams {
    if data.is_empty() {
        return QuantParams::new(1.0, 0);
    }
    let mut min_val = data[0];
    let mut max_val = data[0];
    for &v in data {
        if v < min_val { min_val = v; }
        if v > max_val { max_val = v; }
    }

    // Ensure range includes zero for ReLU outputs
    if min_val > 0.0 { min_val = 0.0; }
    if max_val < 0.0 { max_val = 0.0; }

    /// Minimum scale to avoid division by zero.
    const MIN_SCALE: f32 = 1e-8;

    let scale = ((max_val - min_val) / 255.0).max(MIN_SCALE);
    let zero_point = (-128.0f32 - min_val / scale).clamp(-128.0, 127.0) as i8;

    QuantParams { scale, zero_point }
}

// ---------------------------------------------------------------------------
// INT8 Conv2D (quantized)
// ---------------------------------------------------------------------------

/// INT8 2D convolution (quantized weights and input).
///
/// All arithmetic in i32 accumulators. Output requantized to i8.
///
/// - `input`: quantized input tensor [C_in × H × W] as i8
/// - `kernel`: quantized weight tensor [C_out × C_in × kH × kW] as i8
/// - `bias_i32`: pre-computed bias in i32 (= bias_f32 / (input_scale * weight_scale))
/// - `output`: quantized output tensor [C_out × H_out × W_out] as i8
pub fn conv2d_int8(
    input: &[i8],
    in_c: usize, in_h: usize, in_w: usize,
    kernel: &[i8],
    out_c: usize, k_h: usize, k_w: usize,
    bias_i32: &[i32],
    stride: usize, pad: usize,
    input_zp: i8, kernel_zp: i8,
    output_params: &QuantParams,
    output: &mut [i8],
) {
    // Guard against `k > in + 2*pad` underflow (usize) → abort on a crafted
    // model; conv2d (f32) has these guards, conv2d_int8 was missing them.
    let padded_h = in_h.saturating_add(pad.saturating_mul(2));
    let padded_w = in_w.saturating_add(pad.saturating_mul(2));
    if stride == 0 || k_h > padded_h || k_w > padded_w { return; }
    let out_h = (padded_h - k_h) / stride + 1;
    let out_w = (padded_w - k_w) / stride + 1;
    let patch_size = in_c * k_h * k_w;

    for oc in 0..out_c {
        let k_off = oc * patch_size;
        let bias = if oc < bias_i32.len() { bias_i32[oc] } else { 0 };

        for oh in 0..out_h {
            for ow in 0..out_w {
                let mut acc: i32 = bias;

                // Dot product in i32
                for c in 0..in_c {
                    for kh in 0..k_h {
                        for kw in 0..k_w {
                            let ih = (oh * stride + kh) as isize - pad as isize;
                            let iw = (ow * stride + kw) as isize - pad as isize;

                            let input_val = if ih >= 0 && (ih as usize) < in_h
                                && iw >= 0 && (iw as usize) < in_w
                            {
                                input[c * in_h * in_w + ih as usize * in_w + iw as usize] as i32
                                    - input_zp as i32
                            } else {
                                0 // zero-padding (already offset by -zp since pad=0 maps to 0-zp)
                            };

                            let k_idx = k_off + c * k_h * k_w + kh * k_w + kw;
                            let kernel_val = kernel[k_idx] as i32 - kernel_zp as i32;

                            acc += input_val * kernel_val;
                        }
                    }
                }

                // Requantize to output i8 (integer-only, fused ReLU).
                //
                // Behaviour-preserving cleanup (RFC-0032): the old code computed
                // `acc as f32 * scale` and then `quantize()` divided by the same
                // `scale` — `scale` cancels, so the requant was really
                // `relu(acc) + zero_point`, paid for with a redundant per-output
                // float multiply + float DIVIDE (the divide dominated requant
                // cost). This computes the identical result in integers, no FP.
                //
                // CORRECTNESS LIMITATION (unchanged, flagged for a future API
                // change): a correct per-layer requant needs the combined
                // multiplier M = input_scale * weight_scale / output_scale with
                // a fixed-point multiply+shift (TFLite/gemmlowp style). This
                // signature lacks the input/weight scales, so no true rescale is
                // performed and outputs saturate for large accumulators. Fixing
                // that means threading M into the signature — out of scope here.
                let relu = if acc < 0 { 0 } else { acc };
                let q = (relu + output_params.zero_point as i32).clamp(-128, 127);
                let out_idx = oc * out_h * out_w + oh * out_w + ow;
                output[out_idx] = q as i8;
            }
        }
    }
}

/// INT8 fully-connected (linear) layer.
///
/// `input`: [in_features] i8
/// `weights`: [out_features × in_features] i8 (row-major)
/// `bias_i32`: [out_features] i32
/// `output`: [out_features] i8
pub fn linear_int8(
    input: &[i8], in_features: usize,
    weights: &[i8], out_features: usize,
    bias_i32: &[i32],
    input_zp: i8, weight_zp: i8,
    output_params: &QuantParams,
    relu: bool,
    output: &mut [i8],
) {
    for o in 0..out_features {
        let mut acc: i32 = if o < bias_i32.len() { bias_i32[o] } else { 0 };

        for i in 0..in_features {
            let x = input[i] as i32 - input_zp as i32;
            let w = weights[o * in_features + i] as i32 - weight_zp as i32;
            acc += x * w;
        }

        let real_val = acc as f32 * output_params.scale;
        let val = if relu && real_val < 0.0 { 0.0 } else { real_val };
        output[o] = output_params.quantize(val);
    }
}
