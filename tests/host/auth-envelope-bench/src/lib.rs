// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side benchmark for the HMAC-SHA-256 authenticated envelope.
//!
//! Mirrors the wire format defined in
//! `domains/robot/behavior/src/auth_envelope.rs` (option (b) from the task spec:
//! re-implement the pure HMAC math locally so we remain independent of
//! kernel-only static state and `azos_drv_sys::timebase::now()`).
//!
//! ## Wire format (must match auth_envelope.rs byte-for-byte)
//!
//! ```text
//! Offset  Size  Field
//! 0x00    8     Nonce (monotonic u64, big-endian)
//! 0x08    16    HMAC-SHA-256 over (nonce_b || len_b || inner) truncated to 16B
//! 0x18    2     Inner length (LE u16)
//! 0x1A    N     Inner brain-protocol packet
//! ```
//!
//! ## Running
//!
//! ```text
//! cd tests/host/auth-envelope-bench && cargo +stable test --release -- --nocapture
//! ```

use azos_crypto::sha256::{Digest, Sha256};

// ── Wire-format constants (copied verbatim from auth_envelope.rs) ────────────

/// Length of the symmetric pre-shared key in bytes.
pub const KEY_BYTES: usize = 32;
/// Length of the nonce field in bytes.
pub const NONCE_BYTES: usize = 8;
/// Length of the truncated HMAC field in bytes.
pub const HMAC_BYTES: usize = 16;
/// Length of the inner-length field in bytes.
pub const LEN_BYTES: usize = 2;
/// Total overhead added to each inner packet by the envelope.
pub const ENVELOPE_OVERHEAD: usize = NONCE_BYTES + HMAC_BYTES + LEN_BYTES;
/// Maximum inner packet size accepted by the kernel.
pub const MAX_INNER_BYTES: usize = 8 * 1024;

/// SHA-256 block size (FIPS 180-4).
const SHA256_BLOCK_SIZE: usize = 64;
/// HMAC inner-pad byte (RFC 2104).
const HMAC_IPAD: u8 = 0x36;
/// HMAC outer-pad byte (RFC 2104).
const HMAC_OPAD: u8 = 0x5C;

// ── Benchmark configuration constants ────────────────────────────────────────

/// Number of wrap() iterations per bench run.
pub const WRAP_ITERATIONS: u64 = 50_000;
/// Number of unwrap() iterations per bench run.
pub const UNWRAP_ITERATIONS: u64 = 50_000;
/// Number of raw SHA-256 iterations for the floor measurement.
pub const HMAC_ONLY_ITERATIONS: u64 = 50_000;
/// Size of the inner payload used in wrap/unwrap bench loops.
pub const INNER_PAYLOAD_BYTES: usize = 20;
/// Scaling divisor: ops-per-second → kpkt/s (matches brain bench convention).
pub const OPS_PER_KILO: u64 = 1_000;
/// Nanoseconds per second (for ns/op → op/s conversion).
pub const NANOS_PER_SEC: u64 = 1_000_000_000;

// ── HMAC-SHA-256 ─────────────────────────────────────────────────────────────

/// Pre-computed key blocks used by `hmac_sha256_precomputed`.
///
/// The kernel pre-computes these once at `init()` time to avoid redundant
/// XOR work at every wrap/unwrap call. We do the same in the bench: build
/// them once per bench function, then pass them into each loop iteration.
/// This keeps the bench numbers honest relative to the kernel hot-path.
pub struct HmacKey {
    ikey_block: [u8; SHA256_BLOCK_SIZE],
    okey_block: [u8; SHA256_BLOCK_SIZE],
}

impl HmacKey {
    /// Derive ikey/okey from a 32-byte raw key.
    ///
    /// Matches the `init()` precomputation in `auth_envelope.rs`:
    ///   k_pad = key ++ 0×(64-32)
    ///   ikey_block[i] = k_pad[i] ^ HMAC_IPAD
    ///   okey_block[i] = k_pad[i] ^ HMAC_OPAD
    pub fn from_bytes(key: &[u8; KEY_BYTES]) -> Self {
        let mut k_pad = [0u8; SHA256_BLOCK_SIZE];
        k_pad[..KEY_BYTES].copy_from_slice(key);

        let mut ikey_block = [0u8; SHA256_BLOCK_SIZE];
        let mut okey_block = [0u8; SHA256_BLOCK_SIZE];
        for i in 0..SHA256_BLOCK_SIZE {
            ikey_block[i] = k_pad[i] ^ HMAC_IPAD;
            okey_block[i] = k_pad[i] ^ HMAC_OPAD;
        }
        Self { ikey_block, okey_block }
    }

    /// HMAC-SHA-256 using pre-computed ikey/okey blocks.
    ///
    /// Matches `hmac_sha256_precomputed()` in `auth_envelope.rs`.
    /// `data_parts` is a slice of byte slices fed in order to the inner hash.
    pub fn hmac(&self, data_parts: &[&[u8]]) -> Digest {
        // Inner: SHA-256(ikey_block || data_parts...)
        let mut h = Sha256::new();
        h.update(&self.ikey_block);
        for part in data_parts {
            h.update(part);
        }
        let inner = h.finalize();

        // Outer: SHA-256(okey_block || inner)
        let mut h = Sha256::new();
        h.update(&self.okey_block);
        h.update(&inner);
        h.finalize()
    }
}

// ── Stateless wrap / unwrap ───────────────────────────────────────────────────
//
// Unlike the kernel's public API, these functions are fully stateless: the
// caller supplies the key blocks and nonce. This makes them deterministic
// and safe to call from a tight benchmark loop without atomics or static state.

/// Wrap `inner` into `out` using the pre-computed HMAC key and explicit nonce.
///
/// Returns the number of bytes written into `out`, or 0 on failure.
///
/// ## Wire format produced
/// ```text
/// out[0..8]   = nonce.to_be_bytes()
/// out[8..24]  = HMAC(nonce_b || len_b || inner)[..16]
/// out[24..26] = (inner.len() as u16).to_le_bytes()
/// out[26..26+N] = inner
/// ```
pub fn wrap(key: &HmacKey, nonce: u64, inner: &[u8], out: &mut [u8]) -> usize {
    if inner.len() > MAX_INNER_BYTES {
        return 0;
    }
    let total = ENVELOPE_OVERHEAD + inner.len();
    if out.len() < total {
        return 0;
    }

    let nonce_b = nonce.to_be_bytes();
    let len_b = (inner.len() as u16).to_le_bytes();

    let mac = key.hmac(&[&nonce_b, &len_b, inner]);

    out[0..NONCE_BYTES].copy_from_slice(&nonce_b);
    out[NONCE_BYTES..NONCE_BYTES + HMAC_BYTES].copy_from_slice(&mac[..HMAC_BYTES]);
    out[NONCE_BYTES + HMAC_BYTES..NONCE_BYTES + HMAC_BYTES + LEN_BYTES]
        .copy_from_slice(&len_b);
    out[ENVELOPE_OVERHEAD..ENVELOPE_OVERHEAD + inner.len()].copy_from_slice(inner);
    total
}

/// Unwrap a frame produced by `wrap()`.
///
/// Returns `Some(inner_len)` and copies the inner bytes into `out`, or
/// `None` on frame-too-short / HMAC mismatch.
///
/// NOTE: no replay-window check here — the kernel's `HIGHEST_RX_NONCE`
/// is stateful and kernel-specific. This bench omits it intentionally;
/// the HMAC verification is the performance-critical path.
pub fn unwrap(key: &HmacKey, frame: &[u8], out: &mut [u8]) -> Option<usize> {
    if frame.len() < ENVELOPE_OVERHEAD {
        return None;
    }

    let nonce_b: &[u8] = &frame[0..NONCE_BYTES];
    let mac_b: &[u8] = &frame[NONCE_BYTES..NONCE_BYTES + HMAC_BYTES];
    let len_b: &[u8] =
        &frame[NONCE_BYTES + HMAC_BYTES..NONCE_BYTES + HMAC_BYTES + LEN_BYTES];

    let n = u16::from_le_bytes([len_b[0], len_b[1]]) as usize;
    if n > MAX_INNER_BYTES {
        return None;
    }
    if frame.len() < ENVELOPE_OVERHEAD + n {
        return None;
    }
    if out.len() < n {
        return None;
    }

    let inner = &frame[ENVELOPE_OVERHEAD..ENVELOPE_OVERHEAD + n];
    let expected = key.hmac(&[nonce_b, len_b, inner]);

    // Constant-time comparison (mirrors ct_eq() in auth_envelope.rs).
    let mut diff = 0u8;
    for i in 0..HMAC_BYTES {
        diff |= expected[i] ^ mac_b[i];
    }
    if std::hint::black_box(diff) != 0 {
        return None;
    }

    out[..n].copy_from_slice(inner);
    Some(n)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    // Fixed test vectors — deterministic so the byte-identity assertion below
    // is verifiable against a Python reference or manual computation.
    const TEST_KEY: [u8; KEY_BYTES] = [0x11u8; KEY_BYTES];
    const TEST_NONCE: u64 = 1;
    const TEST_INNER: &[u8] = b"hello world test!!!!"; // 20 bytes
    // Maximum frame size for the bench payload.
    const FRAME_BUF_LEN: usize = ENVELOPE_OVERHEAD + INNER_PAYLOAD_BYTES;

    // ── Byte-identity check ──────────────────────────────────────────────────
    //
    // This test proves that our local re-impl produces bytes identical to what
    // the kernel's auth_envelope.rs would produce for the same inputs. We
    // compute the expected frame fully from first principles using only
    // azos_crypto::sha256 directly (no helper from this crate), then
    // compare against wrap()'s output.
    //
    // If the two diverge, the bench is measuring a different wire format than
    // the kernel — which defeats the whole point.

    #[test]
    fn wrap_bytes_match_manual_computation() {
        let key = HmacKey::from_bytes(&TEST_KEY);

        // --- Compute expected frame manually ---
        let nonce_b = TEST_NONCE.to_be_bytes();
        let len_b = (TEST_INNER.len() as u16).to_le_bytes();

        // Build ikey/okey the same way HmacKey::from_bytes does.
        let mut k_pad = [0u8; SHA256_BLOCK_SIZE];
        k_pad[..KEY_BYTES].copy_from_slice(&TEST_KEY);
        let mut ikey_block = [0u8; SHA256_BLOCK_SIZE];
        let mut okey_block = [0u8; SHA256_BLOCK_SIZE];
        for i in 0..SHA256_BLOCK_SIZE {
            ikey_block[i] = k_pad[i] ^ HMAC_IPAD;
            okey_block[i] = k_pad[i] ^ HMAC_OPAD;
        }

        // Inner hash: SHA-256(ikey_block || nonce_b || len_b || inner)
        let mut h = Sha256::new();
        h.update(&ikey_block);
        h.update(&nonce_b);
        h.update(&len_b);
        h.update(TEST_INNER);
        let inner_hash = h.finalize();

        // Outer hash: SHA-256(okey_block || inner_hash)
        let mut h = Sha256::new();
        h.update(&okey_block);
        h.update(&inner_hash);
        let full_mac = h.finalize();

        // Build the expected wire frame.
        let mut expected = [0u8; FRAME_BUF_LEN];
        expected[0..NONCE_BYTES].copy_from_slice(&nonce_b);
        expected[NONCE_BYTES..NONCE_BYTES + HMAC_BYTES].copy_from_slice(&full_mac[..HMAC_BYTES]);
        expected[NONCE_BYTES + HMAC_BYTES..NONCE_BYTES + HMAC_BYTES + LEN_BYTES]
            .copy_from_slice(&len_b);
        expected[ENVELOPE_OVERHEAD..ENVELOPE_OVERHEAD + TEST_INNER.len()]
            .copy_from_slice(TEST_INNER);

        // --- Compute actual frame via wrap() ---
        let mut actual = [0u8; FRAME_BUF_LEN];
        let written = wrap(&key, TEST_NONCE, TEST_INNER, &mut actual);

        assert_eq!(written, FRAME_BUF_LEN, "wrap() wrote wrong number of bytes");
        assert_eq!(
            &actual[..written],
            &expected[..written],
            "wrap() output does not match manual computation — wire format mismatch!"
        );
    }

    // ── Round-trip ────────────────────────────────────────────────────────────

    #[test]
    fn wrap_then_unwrap_recovers_inner() {
        let key = HmacKey::from_bytes(&TEST_KEY);
        let mut frame = [0u8; FRAME_BUF_LEN];
        let written = wrap(&key, TEST_NONCE, TEST_INNER, &mut frame);
        assert_eq!(written, FRAME_BUF_LEN);

        let mut recovered = [0u8; INNER_PAYLOAD_BYTES];
        let n = unwrap(&key, &frame[..written], &mut recovered).expect("unwrap failed");
        assert_eq!(n, TEST_INNER.len());
        assert_eq!(&recovered[..n], TEST_INNER);
    }

    #[test]
    fn unwrap_rejects_tampered_mac() {
        let key = HmacKey::from_bytes(&TEST_KEY);
        let mut frame = [0u8; FRAME_BUF_LEN];
        let written = wrap(&key, TEST_NONCE, TEST_INNER, &mut frame);
        assert_eq!(written, FRAME_BUF_LEN);

        // Flip one bit in the MAC field.
        frame[NONCE_BYTES] ^= 0xFF;

        let mut out = [0u8; INNER_PAYLOAD_BYTES];
        assert!(
            unwrap(&key, &frame[..written], &mut out).is_none(),
            "unwrap must reject a tampered MAC"
        );
    }

    #[test]
    fn unwrap_rejects_tampered_inner() {
        let key = HmacKey::from_bytes(&TEST_KEY);
        let mut frame = [0u8; FRAME_BUF_LEN];
        let written = wrap(&key, TEST_NONCE, TEST_INNER, &mut frame);

        // Flip one bit in the inner payload.
        frame[ENVELOPE_OVERHEAD] ^= 0x01;

        let mut out = [0u8; INNER_PAYLOAD_BYTES];
        assert!(
            unwrap(&key, &frame[..written], &mut out).is_none(),
            "unwrap must reject tampered inner payload"
        );
    }

    #[test]
    fn unwrap_rejects_truncated_frame() {
        let key = HmacKey::from_bytes(&TEST_KEY);
        let mut frame = [0u8; FRAME_BUF_LEN];
        let written = wrap(&key, TEST_NONCE, TEST_INNER, &mut frame);

        let mut out = [0u8; INNER_PAYLOAD_BYTES];
        // One byte too short.
        assert!(
            unwrap(&key, &frame[..written - 1], &mut out).is_none(),
            "unwrap must reject a truncated frame"
        );
    }

    #[test]
    fn wrap_rejects_oversized_inner() {
        let key = HmacKey::from_bytes(&TEST_KEY);
        let big_inner = vec![0u8; MAX_INNER_BYTES + 1];
        let mut out = vec![0u8; ENVELOPE_OVERHEAD + MAX_INNER_BYTES + 1];
        let written = wrap(&key, 1, &big_inner, &mut out);
        assert_eq!(written, 0, "wrap must return 0 for oversized inner");
    }

    // ── Benchmark 1: wrap throughput ─────────────────────────────────────────

    #[test]
    fn bench_wrap_throughput() {
        let key = HmacKey::from_bytes(&TEST_KEY);
        let inner = [0xAAu8; INNER_PAYLOAD_BYTES];
        let mut out = [0u8; ENVELOPE_OVERHEAD + INNER_PAYLOAD_BYTES];

        // Warm-up: one pass outside the timed region.
        let _ = wrap(&key, 0, &inner, &mut out);

        let start = Instant::now();
        for i in 0..WRAP_ITERATIONS {
            let _ = std::hint::black_box(wrap(&key, i + 1, &inner, &mut out));
        }
        let elapsed = start.elapsed();

        let total_nanos = elapsed.as_nanos() as u64;
        let ns_per_op = total_nanos / WRAP_ITERATIONS;
        let ops_per_sec = NANOS_PER_SEC * WRAP_ITERATIONS / total_nanos.max(1);
        let kpkt_per_sec = ops_per_sec / OPS_PER_KILO;

        println!(
            "[bench] wrap_throughput: {} ops in {:.3} ms  |  {} ns/op  |  {} kpkt/s",
            WRAP_ITERATIONS,
            elapsed.as_secs_f64() * 1_000.0,
            ns_per_op,
            kpkt_per_sec,
        );
    }

    // ── Benchmark 2: unwrap throughput ───────────────────────────────────────

    #[test]
    fn bench_unwrap_throughput() {
        let key = HmacKey::from_bytes(&TEST_KEY);
        let inner = [0xBBu8; INNER_PAYLOAD_BYTES];
        let mut frame = [0u8; ENVELOPE_OVERHEAD + INNER_PAYLOAD_BYTES];
        // Pre-build one valid frame (nonce = 1) to unwrap repeatedly.
        // The replay window is absent here (we're testing pure HMAC cost),
        // so the same frame is re-verified every iteration.
        let frame_len = wrap(&key, 1, &inner, &mut frame);
        assert!(frame_len > 0, "pre-build wrap must succeed");

        let mut out = [0u8; INNER_PAYLOAD_BYTES];

        // Warm-up.
        let _ = unwrap(&key, &frame[..frame_len], &mut out);

        let start = Instant::now();
        for _ in 0..UNWRAP_ITERATIONS {
            let _ = std::hint::black_box(unwrap(&key, &frame[..frame_len], &mut out));
        }
        let elapsed = start.elapsed();

        let total_nanos = elapsed.as_nanos() as u64;
        let ns_per_op = total_nanos / UNWRAP_ITERATIONS;
        let ops_per_sec = NANOS_PER_SEC * UNWRAP_ITERATIONS / total_nanos.max(1);
        let kpkt_per_sec = ops_per_sec / OPS_PER_KILO;

        println!(
            "[bench] unwrap_throughput: {} ops in {:.3} ms  |  {} ns/op  |  {} kpkt/s",
            UNWRAP_ITERATIONS,
            elapsed.as_secs_f64() * 1_000.0,
            ns_per_op,
            kpkt_per_sec,
        );
    }

    // ── Benchmark 3: raw SHA-256 floor ───────────────────────────────────────
    //
    // Measures the cost of a single sha256() call on a fixed-size buffer.
    // This establishes the floor: wrap/unwrap each do 2× SHA-256 rounds
    // (inner + outer pass of HMAC), so wrap_throughput should be roughly
    // half this rate.

    #[test]
    fn bench_hmac_only_throughput() {
        // Data size matched to what one HMAC call sees:
        // SHA256_BLOCK_SIZE (ikey) + NONCE_BYTES + LEN_BYTES + INNER_PAYLOAD_BYTES
        // = 64 + 8 + 2 + 20 = 94 bytes for the inner pass.
        const SHA_INPUT_BYTES: usize =
            SHA256_BLOCK_SIZE + NONCE_BYTES + LEN_BYTES + INNER_PAYLOAD_BYTES;
        let data = [0xCCu8; SHA_INPUT_BYTES];

        // Warm-up.
        let _ = azos_crypto::sha256::sha256(&data);

        let start = Instant::now();
        for _ in 0..HMAC_ONLY_ITERATIONS {
            let _ = std::hint::black_box(azos_crypto::sha256::sha256(&data));
        }
        let elapsed = start.elapsed();

        let total_nanos = elapsed.as_nanos() as u64;
        let ns_per_op = total_nanos / HMAC_ONLY_ITERATIONS;
        let ops_per_sec = NANOS_PER_SEC * HMAC_ONLY_ITERATIONS / total_nanos.max(1);
        let kpkt_per_sec = ops_per_sec / OPS_PER_KILO;

        println!(
            "[bench] hmac_only_throughput (SHA-256 floor, single call): {} ops in {:.3} ms  |  {} ns/op  |  {} kpkt/s",
            HMAC_ONLY_ITERATIONS,
            elapsed.as_secs_f64() * 1_000.0,
            ns_per_op,
            kpkt_per_sec,
        );
        println!(
            "  Note: wrap/unwrap each call SHA-256 twice (inner+outer HMAC pass),",
        );
        println!(
            "  so wrap/unwrap throughput should be ~50 % of this SHA-256-floor rate.",
        );
    }
}
