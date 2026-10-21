// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Convolutional operators for on-device CNN inference (F08).
//!
//! Implements Conv2D, depthwise separable conv, max/avg pooling, and fused
//! BatchNorm. All operations are stack-only with bounded temporaries.
//!
//! Uses the existing dot-product infrastructure (scalar or RVV SIMD).

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum spatial dimension (width or height) for input feature maps.
pub const MAX_SPATIAL: usize = 96;

/// Maximum number of channels in any layer.
pub const MAX_CHANNELS: usize = 64;

/// Maximum kernel spatial size (e.g. 3×3 = 9).
const MAX_KERNEL_AREA: usize = 9;

/// Maximum im2col patch size = MAX_KERNEL_AREA × MAX_CHANNELS.
const MAX_PATCH_SIZE: usize = MAX_KERNEL_AREA * MAX_CHANNELS;

/// Activation function: none (linear).
pub const ACT_LINEAR: u8 = 0;
/// Activation function: ReLU.
pub const ACT_RELU: u8 = 1;
/// Activation function: ReLU6 (clamped to [0, 6]).
pub const ACT_RELU6: u8 = 2;

// ---------------------------------------------------------------------------
// Conv2D (standard)
// ---------------------------------------------------------------------------

/// Standard 2D convolution.
///
/// - `input`:  `[C_in][H][W]` flattened in CHW order
/// - `kernel`: `[C_out][C_in][kH][kW]` flattened
/// - `bias`:   `[C_out]` or empty for no bias
/// - `output`: `[C_out][H_out][W_out]` flattened
///
/// Stride and padding applied symmetrically. Output size:
/// `H_out = (H + 2*pad - kH) / stride + 1`
pub fn conv2d(
    input: &[f32],
    in_c: usize, in_h: usize, in_w: usize,
    kernel: &[f32],
    out_c: usize, k_h: usize, k_w: usize,
    bias: &[f32],
    stride: usize, pad: usize,
    activation: u8,
    output: &mut [f32],
) {
    if stride == 0 || in_c > MAX_CHANNELS || out_c > MAX_CHANNELS { return; }
    if in_h > MAX_SPATIAL || in_w > MAX_SPATIAL { return; }
    if k_h * k_w > MAX_KERNEL_AREA { return; }

    let padded_h = in_h.saturating_add(pad.saturating_mul(2));
    let padded_w = in_w.saturating_add(pad.saturating_mul(2));
    if k_h > padded_h || k_w > padded_w { return; }

    let out_h = (padded_h - k_h) / stride + 1;
    let out_w = (padded_w - k_w) / stride + 1;
    let patch_size = in_c * k_h * k_w;

    if patch_size > MAX_PATCH_SIZE { return; }

    let mut patch = [0.0f32; MAX_PATCH_SIZE];

    for oc in 0..out_c {
        let kernel_offset = oc * patch_size;
        let b = if oc < bias.len() { bias[oc] } else { 0.0 };

        for oh in 0..out_h {
            for ow in 0..out_w {
                // Extract im2col patch
                im2col_patch(
                    input, in_c, in_h, in_w,
                    k_h, k_w, stride, pad,
                    oh, ow,
                    &mut patch[..patch_size],
                );

                // Dot product: kernel[oc] · patch + bias
                let val = b + dot(&kernel[kernel_offset..kernel_offset + patch_size],
                                  &patch[..patch_size]);
                let out_idx = oc * out_h * out_w + oh * out_w + ow;
                output[out_idx] = apply_activation(val, activation);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Depthwise Conv2D (for MobileNet-style separable conv)
// ---------------------------------------------------------------------------

/// Depthwise 2D convolution: one filter per input channel.
///
/// - `input`:  `[C][H][W]` flattened
/// - `kernel`: `[C][kH][kW]` flattened (one filter per channel)
/// - `bias`:   `[C]` or empty
/// - `output`: `[C][H_out][W_out]` flattened
pub fn depthwise_conv2d(
    input: &[f32],
    channels: usize, in_h: usize, in_w: usize,
    kernel: &[f32],
    k_h: usize, k_w: usize,
    bias: &[f32],
    stride: usize, pad: usize,
    activation: u8,
    output: &mut [f32],
) {
    if stride == 0 || channels > MAX_CHANNELS { return; }
    if in_h > MAX_SPATIAL || in_w > MAX_SPATIAL { return; }

    let padded_h = in_h.saturating_add(pad.saturating_mul(2));
    let padded_w = in_w.saturating_add(pad.saturating_mul(2));
    if k_h > padded_h || k_w > padded_w { return; }

    let out_h = (padded_h - k_h) / stride + 1;
    let out_w = (padded_w - k_w) / stride + 1;
    let k_area = k_h * k_w;

    for c in 0..channels {
        let k_off = c * k_area;
        let b = if c < bias.len() { bias[c] } else { 0.0 };

        for oh in 0..out_h {
            for ow in 0..out_w {
                let mut sum = b;
                for kh in 0..k_h {
                    for kw in 0..k_w {
                        let ih_s = (oh * stride + kh) as isize - pad as isize;
                        let iw_s = (ow * stride + kw) as isize - pad as isize;
                        if ih_s >= 0 && (ih_s as usize) < in_h
                            && iw_s >= 0 && (iw_s as usize) < in_w
                        {
                            let ih = ih_s as usize;
                            let iw = iw_s as usize;
                            sum += input[c * in_h * in_w + ih * in_w + iw]
                                * kernel[k_off + kh * k_w + kw];
                        }
                    }
                }
                output[c * out_h * out_w + oh * out_w + ow] = apply_activation(sum, activation);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pooling
// ---------------------------------------------------------------------------

/// Max pooling 2D.
///
/// - `input`:  `[C][H][W]` flattened
/// - `output`: `[C][H/pool][W/pool]` flattened
pub fn max_pool2d(
    input: &[f32],
    channels: usize, in_h: usize, in_w: usize,
    pool: usize,
    output: &mut [f32],
) {
    if pool == 0 { return; }
    let out_h = in_h / pool;
    let out_w = in_w / pool;

    for c in 0..channels {
        for oh in 0..out_h {
            for ow in 0..out_w {
                let mut max_val = f32::NEG_INFINITY;
                for ph in 0..pool {
                    for pw in 0..pool {
                        let ih = oh * pool + ph;
                        let iw = ow * pool + pw;
                        let val = input[c * in_h * in_w + ih * in_w + iw];
                        if val > max_val { max_val = val; }
                    }
                }
                output[c * out_h * out_w + oh * out_w + ow] = max_val;
            }
        }
    }
}

/// Average pooling 2D.
pub fn avg_pool2d(
    input: &[f32],
    channels: usize, in_h: usize, in_w: usize,
    pool: usize,
    output: &mut [f32],
) {
    if pool == 0 { return; }
    let out_h = in_h / pool;
    let out_w = in_w / pool;
    let pool_area_inv = 1.0 / (pool * pool) as f32;

    for c in 0..channels {
        for oh in 0..out_h {
            for ow in 0..out_w {
                let mut sum = 0.0f32;
                for ph in 0..pool {
                    for pw in 0..pool {
                        let ih = oh * pool + ph;
                        let iw = ow * pool + pw;
                        sum += input[c * in_h * in_w + ih * in_w + iw];
                    }
                }
                output[c * out_h * out_w + oh * out_w + ow] = sum * pool_area_inv;
            }
        }
    }
}

/// Global average pooling: reduce each channel to a single value.
///
/// - `input`:  `[C][H][W]` flattened
/// - `output`: `[C]`
pub fn global_avg_pool(
    input: &[f32],
    channels: usize, in_h: usize, in_w: usize,
    output: &mut [f32],
) {
    let spatial = in_h * in_w;
    if spatial == 0 { return; }
    let inv = 1.0 / spatial as f32;
    for c in 0..channels {
        let offset = c * spatial;
        let mut sum = 0.0f32;
        for i in 0..spatial {
            sum += input[offset + i];
        }
        output[c] = sum * inv;
    }
}

// ---------------------------------------------------------------------------
// BatchNorm (fused with conv — apply as scale + shift)
// ---------------------------------------------------------------------------

/// Fused BatchNorm: `output[c] = gamma[c] * input[c] + beta[c]` per channel.
///
/// Typically folded into conv weights offline, but can run standalone.
pub fn batchnorm_scale(
    data: &mut [f32],
    channels: usize, spatial: usize,
    gamma: &[f32], beta: &[f32],
) {
    for c in 0..channels {
        let g = if c < gamma.len() { gamma[c] } else { 1.0 };
        let b = if c < beta.len()  { beta[c]  } else { 0.0 };
        let offset = c * spatial;
        for i in 0..spatial {
            data[offset + i] = data[offset + i] * g + b;
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Extract im2col patch for one output position.
fn im2col_patch(
    input: &[f32], in_c: usize, in_h: usize, in_w: usize,
    k_h: usize, k_w: usize, stride: usize, pad: usize,
    out_y: usize, out_x: usize,
    patch: &mut [f32],
) {
    let mut idx = 0;
    for c in 0..in_c {
        for kh in 0..k_h {
            for kw in 0..k_w {
                let ih = (out_y * stride + kh) as isize - pad as isize;
                let iw = (out_x * stride + kw) as isize - pad as isize;
                patch[idx] = if ih >= 0 && ih < in_h as isize
                    && iw >= 0 && iw < in_w as isize
                {
                    input[c * in_h * in_w + ih as usize * in_w + iw as usize]
                } else {
                    0.0 // zero-padding
                };
                idx += 1;
            }
        }
    }
}

/// The crate's dot product (`crate::dot`): RVV SIMD when available.
#[inline(always)]
fn dot(a: &[f32], b: &[f32]) -> f32 {
    crate::dot(a, b)
}

/// Apply activation function.
#[inline(always)]
fn apply_activation(val: f32, act: u8) -> f32 {
    match act {
        ACT_RELU  => if val > 0.0 { val } else { 0.0 },
        ACT_RELU6 => {
            let v = if val > 0.0 { val } else { 0.0 };
            if v > 6.0 { 6.0 } else { v }
        }
        _ => val, // ACT_LINEAR
    }
}
