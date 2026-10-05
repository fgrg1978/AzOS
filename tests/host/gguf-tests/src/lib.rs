// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the GGUF parser.
//!
//! Pulls `crates/core/ml/src/gguf.rs` directly via `#[path]` so we test
//! the same source the kernel uses, without dragging in
//! `azos_arch` (which the full `ml` crate depends on and which
//! is riscv-only).

#[path = "../../../../crates/core/ml/src/gguf.rs"]
pub mod gguf;

// `quant.rs` has no `use` at all, so it comes in the same way. It had NO test
// anywhere in the tree before 2026-09-19, which is how an off-by-one that
// wrote past the end of the caller's slice survived: the only thing asserting
// the bound was a sentence in the module doc.
#[path = "../../../../crates/core/ml/src/quant.rs"]
pub mod quant;

// U11-9 (audit 2026-09-25): `gguf_mlp_infer` never checked its tensors'
// declared `dims` against the caller's `input`/`output` lengths before this
// fix landed in `ggml_nano.rs` itself. Pulled in here, against a
// `azos_arch` shim (see `shims/arch`), so the fix is proven against the
// real function, not a copy of it.
#[path = "../../../../crates/core/ml/src/ggml_nano.rs"]
pub mod ggml_nano;

/// `ggml_nano.rs` calls its crate's `dot` (`crates/core/ml/src/lib.rs`), which
/// this crate stands in for: the same dispatch, onto the shim.
pub(crate) fn dot(a: &[f32], b: &[f32]) -> f32 {
    azos_arch::vector::dot_f32_best(a, b)
}

#[cfg(test)]
mod tests {
    use super::gguf::{GgmlType, GgufFile, MAX_TENSORS};

    // ── GGUF KV type constants — duplicated here so the tests
    // don't depend on private items of gguf.rs.
    const GGUF_TYPE_UINT32: u32 = 4;
    const GGUF_TYPE_STRING: u32 = 8;

    // ── Builder helpers ────────────────────────────────────────

    /// 24-byte header: magic + version + n_tensors + n_kv.
    fn header(version: u32, n_tensors: u64, n_kv: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        out.extend_from_slice(b"GGUF");
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&n_tensors.to_le_bytes());
        out.extend_from_slice(&n_kv.to_le_bytes());
        out
    }

    fn push_string(buf: &mut Vec<u8>, s: &[u8]) {
        buf.extend_from_slice(&(s.len() as u64).to_le_bytes());
        buf.extend_from_slice(s);
    }

    /// Push one tensor-info entry: name + n_dims + dims[] + type + offset.
    fn push_tensor_info(
        buf: &mut Vec<u8>, name: &[u8], dims: &[u64],
        ggml_type: u32, data_offset: u64,
    ) {
        push_string(buf, name);
        buf.extend_from_slice(&(dims.len() as u32).to_le_bytes());
        for &d in dims {
            buf.extend_from_slice(&d.to_le_bytes());
        }
        buf.extend_from_slice(&ggml_type.to_le_bytes());
        buf.extend_from_slice(&data_offset.to_le_bytes());
    }

    /// Pad `buf` to next 32-byte boundary (v3 data alignment).
    fn pad_to_32(buf: &mut Vec<u8>) {
        let pad = (32 - (buf.len() % 32)) % 32;
        buf.extend(core::iter::repeat(0u8).take(pad));
    }

    /// Build a minimal 2-layer-MLP GGUF blob (`w1`, `b1`, `w2`, `b2`, all
    /// F32, all-zero data — the dims tests below care only about shapes)
    /// with `w1` declared `[w1_dims[0] x w1_dims[1]]` and `w2` declared
    /// `[w2_dims[0] x w2_dims[1]]`, exactly as `gguf_mlp_infer` reads them.
    fn build_mlp_gguf(w1_dims: [u64; 2], w2_dims: [u64; 2]) -> Vec<u8> {
        let w1_elems = (w1_dims[0] * w1_dims[1]) as usize;
        let hid      = w1_dims[1] as usize;
        let w2_elems = (w2_dims[0] * w2_dims[1]) as usize;
        let out      = w2_dims[1] as usize;

        let mut buf = header(3, 4, 0);
        let mut off = 0u64;
        push_tensor_info(&mut buf, b"w1", &w1_dims, GgmlType::F32 as u32, off);
        off += (w1_elems * 4) as u64;
        push_tensor_info(&mut buf, b"b1", &[hid as u64], GgmlType::F32 as u32, off);
        off += (hid * 4) as u64;
        push_tensor_info(&mut buf, b"w2", &w2_dims, GgmlType::F32 as u32, off);
        off += (w2_elems * 4) as u64;
        push_tensor_info(&mut buf, b"b2", &[out as u64], GgmlType::F32 as u32, off);
        pad_to_32(&mut buf);
        buf.extend(core::iter::repeat(0u8).take(w1_elems * 4 + hid * 4 + w2_elems * 4 + out * 4));
        buf
    }

    // ── Rejection cases ────────────────────────────────────────

    // ── Malformed input must REFUSE, never abort ────────────────────────
    //
    // The kernel opens `/fat/POLICY.GGF` off the FAT32 partition and hands the
    // bytes straight to `GgufFile::parse` at every boot
    // (`kernel/src/main.rs`). The release profile is `panic = "abort"` with
    // `overflow-checks = true`, so a panic in here is not a failed parse — it
    // is a board that resets, and on a robot that is a physical-safety event.
    // Both tests below were written from defects found on 2026-09-19.

    /// **Checked multiply, unchecked add.** `skip_kv`'s array arm computed
    /// `pos + count.checked_mul(esz)?`. `count` is a raw `u64` from the file,
    /// so `u64::MAX` with a one-byte element type makes `checked_mul` answer
    /// `Some(usize::MAX)` and the *add* overflow.
    ///
    /// **Canary.** Put the `+` back: this test aborts instead of failing,
    /// which the runner reports as a failure either way.
    #[test]
    fn an_array_count_of_u64_max_is_refused_not_overflowed() {
        const GGUF_TYPE_ARRAY: u32 = 9;
        const GGUF_TYPE_UINT8: u32 = 0;
        for count in [u64::MAX, u64::MAX - 1, u64::MAX / 2, 1u64 << 62] {
            let mut buf = header(3, 0, 1);
            push_string(&mut buf, b"k");
            buf.extend_from_slice(&GGUF_TYPE_ARRAY.to_le_bytes());
            buf.extend_from_slice(&GGUF_TYPE_UINT8.to_le_bytes());
            buf.extend_from_slice(&count.to_le_bytes());
            assert!(
                GgufFile::parse(&buf).is_none(),
                "array count {count} must be refused, not summed into an overflow",
            );
        }
    }

    /// **The guard must count the slots the body writes.** `dequant_q4_0`
    /// writes `out[elem]` and `out[elem + 1]`, so an odd-length slice used to
    /// take the last iteration one past the end.
    ///
    /// Reached from a real file: an odd `dims[1]` on a Q4_0 tensor.
    ///
    /// **Canary.** Restore `elem + 1 > n`: the odd lengths abort.
    #[test]
    fn an_odd_output_length_is_not_written_past() {
        // One Q4_0 block: 2-byte f16 scale (1.0) + 16 packed bytes.
        let mut data = vec![0x00u8, 0x3C];
        data.extend_from_slice(&[0x21u8; 16]);

        for n in [1usize, 3, 5, 7, 31, 33] {
            let mut out = vec![0.0f32; n + 1];
            let len = out.len() - 1;
            out[len] = f32::from_bits(0xDEAD_BEEF); // sentinel past the end
            crate::quant::dequant_q4_0(&data, &mut out[..n]);
            assert_eq!(
                out[len].to_bits(), 0xDEAD_BEEF,
                "n={n}: dequant wrote past the slice it was given",
            );
        }

        // And the clamp is a clamp, not a refusal: the even case still fills.
        let mut out = vec![0.0f32; 4];
        crate::quant::dequant_q4_0(&data, &mut out);
        assert!(out.iter().all(|v| *v != 0.0), "an even-length slice must be written");
    }

    #[test]
    fn rejects_short_buffer() {
        // Header is 24 bytes; anything less must fail.
        assert!(GgufFile::parse(&[]).is_none());
        assert!(GgufFile::parse(b"GGUF").is_none());
        assert!(GgufFile::parse(&[0u8; 23]).is_none());
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut buf = header(3, 0, 0);
        buf[0] = b'X';
        assert!(GgufFile::parse(&buf).is_none());
    }

    #[test]
    fn rejects_version_0() {
        let buf = header(0, 0, 0);
        assert!(GgufFile::parse(&buf).is_none());
    }

    #[test]
    fn rejects_version_4_and_above() {
        for v in [4u32, 5, 99, u32::MAX] {
            let buf = header(v, 0, 0);
            assert!(GgufFile::parse(&buf).is_none(),
                "version {} must be rejected (impl supports 1..=3)", v);
        }
    }

    #[test]
    fn accepts_versions_1_to_3() {
        for v in [1u32, 2, 3] {
            let buf = header(v, 0, 0);
            assert!(GgufFile::parse(&buf).is_some(),
                "version {} must parse (impl supports 1..=3)", v);
        }
    }

    #[test]
    fn rejects_too_many_tensors() {
        // MAX_TENSORS is 32; declare 33.
        let buf = header(3, (MAX_TENSORS + 1) as u64, 0);
        assert!(GgufFile::parse(&buf).is_none());
    }

    // ── Happy-path parses ──────────────────────────────────────

    #[test]
    fn empty_blob_parses() {
        let buf = header(3, 0, 0);
        let f = GgufFile::parse(&buf).unwrap();
        assert_eq!(f.n_tensors, 0);
    }

    #[test]
    fn parses_one_tensor_metadata() {
        let mut buf = header(3, 1, 0);
        push_tensor_info(&mut buf, b"weights.0", &[4, 2], GgmlType::F32 as u32, 0);
        // Tensor data: 4*2 f32 = 32 bytes, aligned to 32-byte boundary.
        pad_to_32(&mut buf);
        buf.extend(core::iter::repeat(0u8).take(32));

        let f = GgufFile::parse(&buf).unwrap();
        assert_eq!(f.n_tensors, 1);
        let info = f.tensor_info(b"weights.0").unwrap();
        assert_eq!(info.name_bytes(), b"weights.0");
        assert_eq!(info.n_dims, 2);
        assert_eq!(info.dims[0], 4);
        assert_eq!(info.dims[1], 2);
        assert_eq!(info.n_elements(), 8);
    }

    #[test]
    fn tensor_data_returns_correct_slice() {
        let mut buf = header(3, 1, 0);
        push_tensor_info(&mut buf, b"w", &[4], GgmlType::F32 as u32, 0);
        pad_to_32(&mut buf);
        // Write 4 f32s (16 bytes) of known data.
        let pattern: [u8; 16] = [
            1, 2, 3, 4,  5, 6, 7, 8,
            9,10,11,12, 13,14,15,16,
        ];
        buf.extend_from_slice(&pattern);

        let f = GgufFile::parse(&buf).unwrap();
        let (data, ty, n) = f.tensor_data(b"w").unwrap();
        assert_eq!(n, 4);
        assert_eq!(ty as u32, GgmlType::F32 as u32);
        assert_eq!(data, &pattern[..]);
    }

    #[test]
    fn tensor_data_missing_returns_none() {
        let mut buf = header(3, 1, 0);
        push_tensor_info(&mut buf, b"present", &[1], GgmlType::F32 as u32, 0);
        pad_to_32(&mut buf);
        buf.extend(core::iter::repeat(0u8).take(4)); // 1 × f32
        let f = GgufFile::parse(&buf).unwrap();
        assert!(f.tensor_data(b"absent").is_none());
    }

    // ── Helper-method sanity ───────────────────────────────────

    #[test]
    fn ggml_type_byte_size_f32() {
        assert_eq!(GgmlType::F32.byte_size(0),   0);
        assert_eq!(GgmlType::F32.byte_size(1),   4);
        assert_eq!(GgmlType::F32.byte_size(100), 400);
    }

    #[test]
    fn ggml_type_byte_size_f16() {
        // F16 = 2 bytes per element.
        assert_eq!(GgmlType::F16.byte_size(10), 20);
    }

    #[test]
    fn ggml_type_byte_size_q4_0_quantised_block() {
        // Q4_0 is block-quantised: 32 values pack into 18 bytes
        // (2-byte f16 scale + 16 bytes of nibbles).  Asking for
        // 32 elements ⇒ 1 block ⇒ 18 bytes.
        assert_eq!(GgmlType::Q4_0.byte_size(32), 18);
        // 64 elements ⇒ 2 blocks ⇒ 36 bytes.
        assert_eq!(GgmlType::Q4_0.byte_size(64), 36);
        // 33 elements: rounds up to 2 blocks (can't represent a
        // partial block in this format).
        assert_eq!(GgmlType::Q4_0.byte_size(33), 36);
    }

    #[test]
    fn tensor_data_truncated_returns_none() {
        let mut buf = header(3, 1, 0);
        push_tensor_info(&mut buf, b"big", &[100], GgmlType::F32 as u32, 0);
        pad_to_32(&mut buf);
        // Promise 100 f32s (400 bytes) but only provide 16.
        buf.extend(core::iter::repeat(0u8).take(16));
        let f = GgufFile::parse(&buf).unwrap();
        assert!(f.tensor_data(b"big").is_none(),
            "tensor_data must reject when declared size walks past EOF");
    }

    // ── Skipping KV metadata ───────────────────────────────────

    #[test]
    fn skips_a_simple_kv_string_then_parses_zero_tensors() {
        let mut buf = header(3, 0, 1);
        // KV: key (string) + type (u32) + value
        push_string(&mut buf, b"general.architecture");
        buf.extend_from_slice(&GGUF_TYPE_STRING.to_le_bytes());
        push_string(&mut buf, b"llama");

        let f = GgufFile::parse(&buf).unwrap();
        assert_eq!(f.n_tensors, 0);
    }

    #[test]
    fn skips_a_simple_kv_uint32_then_parses_zero_tensors() {
        let mut buf = header(3, 0, 1);
        push_string(&mut buf, b"some.scalar");
        buf.extend_from_slice(&GGUF_TYPE_UINT32.to_le_bytes());
        buf.extend_from_slice(&123u32.to_le_bytes());

        let f = GgufFile::parse(&buf).unwrap();
        assert_eq!(f.n_tensors, 0);
    }

    // ── U11-9: gguf_mlp_infer must refuse a dims mismatch, not misalign ──
    //
    // Before the 2026-09-26 fix, `gguf_mlp_infer` never checked `input.len()`
    // against `w1.dims[0]`, `output.len()` against `w2.dims[1]`, or the two
    // layers' hidden width against each other. `linear_layer` computes its
    // per-row byte stride from the CALLER's slice length, so a mismatch did
    // not panic — it silently dequantised the wrong byte ranges and returned
    // logits computed from misaligned weights. These are the fuzz-style
    // dims tests audit unit 11 asked for.

    use super::ggml_nano::gguf_mlp_infer;

    #[test]
    fn mlp_infer_accepts_matching_dims() {
        let buf = build_mlp_gguf([4, 8], [8, 3]);
        let f = GgufFile::parse(&buf).unwrap();
        let input = [0.5f32; 4];
        let mut output = [0.0f32; 3];
        assert!(gguf_mlp_infer(&f, &input, &mut output), "matching dims must be accepted");
    }

    /// **Canary bucket 1 (discriminates).** RED without the `w1i.dims[0] as
    /// usize != in_sz` check this test's fix added.
    #[test]
    fn mlp_infer_refuses_input_len_mismatching_w1_dims0() {
        let buf = build_mlp_gguf([4, 8], [8, 3]);
        let f = GgufFile::parse(&buf).unwrap();
        let input = [0.5f32; 5]; // w1.dims[0] says 4
        let mut output = [0.0f32; 3];
        assert!(!gguf_mlp_infer(&f, &input, &mut output),
            "input.len() != w1.dims[0] must refuse, not silently misalign");
    }

    /// **Canary bucket 1.** RED without the `w2i.dims[1] as usize != out_sz`
    /// check.
    #[test]
    fn mlp_infer_refuses_output_len_mismatching_w2_dims1() {
        let buf = build_mlp_gguf([4, 8], [8, 3]);
        let f = GgufFile::parse(&buf).unwrap();
        let input = [0.5f32; 4];
        let mut output = [0.0f32; 5]; // w2.dims[1] says 3
        assert!(!gguf_mlp_infer(&f, &input, &mut output),
            "output.len() != w2.dims[1] must refuse, not silently misalign");
    }

    /// **Canary bucket 1.** The two layers disagree on hidden width (w1
    /// says 8, w2 says 6) even though `input`/`output` individually match
    /// each layer's OTHER dimension. RED without the
    /// `w2i.dims[0] as usize != hid_sz` check — this is the one the other
    /// two tests above cannot catch, since neither touches `w2.dims[0]`.
    #[test]
    fn mlp_infer_refuses_hidden_width_disagreement_between_layers() {
        let buf = build_mlp_gguf([4, 8], [6, 3]);
        let f = GgufFile::parse(&buf).unwrap();
        let input = [0.5f32; 4];
        let mut output = [0.0f32; 3];
        assert!(!gguf_mlp_infer(&f, &input, &mut output),
            "w1.dims[1] != w2.dims[0] (hidden width) must refuse");
    }
}
