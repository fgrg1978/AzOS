// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! HMAC-SHA256 with an arbitrary-length key, and HKDF-SHA256 (RFC 5869),
//! from the RustCrypto `hmac` and `hkdf` crates over this crate's SHA-256
//! (`sha256::Hasher`, so the block function is the one the CPU selected).
//!
//! The one HMAC-SHA256 in the crate: the entropy pool's HMAC_DRBG, the TCP
//! ISN generator, Noise and the RPC warrants all call it. The key may be any
//! length (HKDF's extract salt and the Noise chaining key are caller-sized).
//! No allocation; the keyed hash states are wiped when they drop, and what
//! the crates leave on the stack is scrubbed when each call returns
//! (`ct::scrub_stack`).

use crate::ct::scrub_stack;
use crate::sha256::{Digest, Hasher};
use hmac::{Hmac, Mac};

/// SHA-256 output / HMAC tag length.
pub const HASH_LEN: usize = 32;
/// RFC 5869 §2.3: L <= 255 * HashLen.
pub const MAX_OKM: usize = 255 * HASH_LEN;

type Hkdf = hkdf::Hkdf<Hasher>;

/// `HMAC-SHA256(key, parts[0] || parts[1] || ...)` (RFC 2104).
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Digest {
    let tag = hmac_inner(key, parts);
    scrub_stack();
    tag
}

/// HKDF-Extract: `PRK = HMAC(salt, ikm)`. An empty salt is HashLen zeros
/// (RFC 5869 §2.2), which HMAC's zero padding makes the same thing.
pub fn extract(salt: &[u8], ikm: &[u8]) -> Digest {
    let prk = extract_inner(salt, ikm);
    scrub_stack();
    prk
}

/// HKDF-Expand into `okm`. Returns false (and writes nothing) when
/// `okm.len() > MAX_OKM`.
pub fn expand(prk: &[u8; HASH_LEN], info: &[u8], okm: &mut [u8]) -> bool {
    let ok = expand_inner(prk, info, okm);
    scrub_stack();
    ok
}

/// Extract-then-expand in one call.
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> bool {
    let ok = hkdf_inner(salt, ikm, info, okm);
    scrub_stack();
    ok
}

// The crate calls, out of line so that their frames lie where `scrub_stack`'s
// will.

#[inline(never)]
fn hmac_inner(key: &[u8], parts: &[&[u8]]) -> Digest {
    let Ok(mut mac) = <Hmac<Hasher> as Mac>::new_from_slice(key) else {
        unreachable!("HMAC takes a key of any length")
    };
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

#[inline(never)]
fn extract_inner(salt: &[u8], ikm: &[u8]) -> Digest {
    Hkdf::extract(Some(salt), ikm).0.into()
}

#[inline(never)]
fn expand_inner(prk: &[u8; HASH_LEN], info: &[u8], okm: &mut [u8]) -> bool {
    Hkdf::from_prk(prk).is_ok_and(|h| h.expand(info, okm).is_ok())
}

#[inline(never)]
fn hkdf_inner(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> bool {
    Hkdf::new(Some(salt), ikm).expand(info, okm).is_ok()
}
