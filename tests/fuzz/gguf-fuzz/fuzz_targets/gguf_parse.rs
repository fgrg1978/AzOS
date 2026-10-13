// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! libFuzzer target: `GgufFile::parse` on an arbitrary POLICY.GGF, then every
//! accessor MLSRV calls on what it returns, then the MLP itself.
//!
//! MLSRV hands the file's bytes to `parse` and, on success, to
//! `gguf_mlp_infer` with a 4-wide input and a 3-wide output
//! (`userspace/services/mlsrv/src/main.rs`). Both shapes are driven here, plus the
//! shapes the file itself declares, so a file that names its own
//! dimensions reaches `linear_layer`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use azos_gguf_tests::ggml_nano::{argmax, gguf_mlp_infer};
use azos_gguf_tests::gguf::GgufFile;

const NAMES: [&[u8]; 4] = [b"w1", b"b1", b"w2", b"b2"];

fuzz_target!(|data: &[u8]| {
    let Some(g) = GgufFile::parse(data) else { return };
    for name in NAMES {
        if let Some((bytes, ty, n)) = g.tensor_data(name) {
            // What `tensor_data` hands out must be what it claims to be.
            assert_eq!(bytes.len(), ty.byte_size(n));
        }
        if let Some(info) = g.tensor_info(name) {
            let _ = info.n_elements();
            let _ = info.name_bytes();
        }
    }
    // MLSRV's own call: 4 inputs, 3 logits.
    let mut logits = [0.0f32; 3];
    if gguf_mlp_infer(&g, &[0.8, 0.3, 0.5, 0.9], &mut logits) {
        let _ = argmax(&logits);
    }
    // The file's own declared shape, capped so the buffers stay small.
    if let (Some(w1), Some(w2)) = (g.tensor_info(b"w1"), g.tensor_info(b"w2")) {
        let i = (w1.dims[0] as usize).min(256);
        let o = (w2.dims[1] as usize).min(256);
        let input = vec![0.5f32; i];
        let mut out = vec![0.0f32; o];
        if gguf_mlp_infer(&g, &input, &mut out) && !out.is_empty() {
            let _ = argmax(&out);
        }
    }
});
