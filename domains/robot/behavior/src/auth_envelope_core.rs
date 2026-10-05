// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The PURE half of the brain-link envelope (`auth_envelope.rs`): HMAC-SHA-256
//! over the same wire format, with no timebase, no policy gate, no static key
//! state. `auth_envelope.rs` is kernel-only (`azos_drv_sys::timebase::now()`
//! for the send-nonce seed, `kprintln!` for denial logging, `LINK_ENCRYPT_
//! ENFORCED`/K-C5 policy) and cannot be `#[path]`-pulled into ring 3.
//! `userspace/services/brain_client` needs exactly the MAC/wire-format half — V1.9,
//! coordinator decision 2026-09-26 — so it lives here, `#[no_std]`-clean and
//! dependent only on `azos_crypto`, and `auth_envelope.rs` is left as-is
//! (its own path is exercised in production and by the host suite already;
//! rewriting it to call this too is a separate, lower-risk follow-up, not
//! done here to avoid touching a tested kernel path under time pressure).
//!
//! Byte format (identical to `auth_envelope.rs`'s module doc):
//! ```text
//! Offset  Size  Field
//! 0x00    8     Nonce (monotonic u64, big-endian)
//! 0x08    16    HMAC-SHA-256 over (dir || nonce || len || inner) trunc 16
//! 0x18    2     Inner length (LE u16)
//! 0x1A    N     Inner payload
//! ```
//! `dir` is hashed but never transmitted — see `auth_envelope.rs` for why.
//!
//! Pinned byte-for-byte against the real kernel path by
//! `tests/host/behavior-tests`' `auth_envelope_core_matches_the_kernel_path`.

use azos_crypto::ct::ct_eq;
use azos_crypto::sha256::{Sha256, Digest};

pub const KEY_BYTES:         usize = 32;
pub const NONCE_BYTES:       usize = 8;
pub const HMAC_BYTES:        usize = 16;
pub const LEN_BYTES:         usize = 2;
pub const ENVELOPE_OVERHEAD: usize = NONCE_BYTES + HMAC_BYTES + LEN_BYTES;

const SHA256_BLOCK_SIZE: usize = 64;
const HMAC_IPAD: u8 = 0x36;
const HMAC_OPAD: u8 = 0x5C;

/// Direction label bound into a frame the RECEIVER reads (brain → kernel).
pub const DIR_RX: &[u8; 3] = b"C2S";
/// Direction label bound into a frame the SENDER writes (kernel → brain).
pub const DIR_TX: &[u8; 3] = b"S2C";

/// HMAC-SHA-256, computed fresh each call (no ikey/okey precomputation —
/// this path runs at brain_client's own low packet rate, not the kernel's
/// perf-sensitive one; see `auth_envelope.rs` for why IT precomputes).
fn hmac_sha256(key: &[u8; KEY_BYTES], data_parts: &[&[u8]]) -> Digest {
    let mut ikey = [HMAC_IPAD; SHA256_BLOCK_SIZE];
    let mut okey = [HMAC_OPAD; SHA256_BLOCK_SIZE];
    for i in 0..KEY_BYTES {
        ikey[i] ^= key[i];
        okey[i] ^= key[i];
    }
    let mut h = Sha256::new();
    h.update(&ikey);
    for part in data_parts { h.update(part); }
    let inner = h.finalize();

    let mut h = Sha256::new();
    h.update(&okey);
    h.update(&inner);
    h.finalize()
}

/// Wrap `inner` under `key`/`dir`/`nonce`. Byte-identical to `auth_envelope::
/// wrap`'s keyed path for the same inputs. Returns 0 if `out` is too small.
pub fn wrap(key: &[u8; KEY_BYTES], dir: &[u8; 3], nonce: u64, inner: &[u8], out: &mut [u8]) -> usize {
    let total = ENVELOPE_OVERHEAD + inner.len();
    if out.len() < total { return 0; }

    let nonce_b = nonce.to_be_bytes();
    let len_b   = (inner.len() as u16).to_le_bytes();
    let mac = hmac_sha256(key, &[dir, &nonce_b, &len_b, inner]);

    out[0..NONCE_BYTES].copy_from_slice(&nonce_b);
    out[NONCE_BYTES..NONCE_BYTES + HMAC_BYTES].copy_from_slice(&mac[..HMAC_BYTES]);
    out[NONCE_BYTES + HMAC_BYTES..ENVELOPE_OVERHEAD].copy_from_slice(&len_b);
    out[ENVELOPE_OVERHEAD..ENVELOPE_OVERHEAD + inner.len()].copy_from_slice(inner);
    total
}

/// Verify and unwrap one envelope against `key`/`dir`, refusing a nonce that
/// is not strictly greater than `floor`. Returns `Some((nonce, inner_len))`
/// on success, with the inner payload written into `out`; the caller owns
/// the replay floor and must advance it itself on `Some` (this function is
/// pure — no static state — so it cannot do that for the caller).
///
/// Refuses on: a frame shorter than the envelope, a declared inner length
/// that does not fit what actually arrived, an HMAC mismatch (constant-time
/// compare), or replay.
pub fn verify_and_unwrap(
    key: &[u8; KEY_BYTES], dir: &[u8; 3], floor: u64, frame: &[u8], out: &mut [u8],
) -> Option<(u64, usize)> {
    if frame.len() < ENVELOPE_OVERHEAD { return None; }
    let nonce_b: [u8; NONCE_BYTES] = frame[0..NONCE_BYTES].try_into().ok()?;
    let nonce = u64::from_be_bytes(nonce_b);
    let mac_recv = &frame[NONCE_BYTES..NONCE_BYTES + HMAC_BYTES];
    let len_b: [u8; LEN_BYTES] =
        frame[NONCE_BYTES + HMAC_BYTES..ENVELOPE_OVERHEAD].try_into().ok()?;
    let len = u16::from_le_bytes(len_b) as usize;
    if frame.len() < ENVELOPE_OVERHEAD + len { return None; }
    let inner = &frame[ENVELOPE_OVERHEAD..ENVELOPE_OVERHEAD + len];

    let mac = hmac_sha256(key, &[dir, &nonce_b, &len_b, inner]);
    if !ct_eq(&mac[..HMAC_BYTES], mac_recv) { return None; }
    if nonce <= floor { return None; }
    if out.len() < len { return None; }
    out[..len].copy_from_slice(inner);
    Some((nonce, len))
}
