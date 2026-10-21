// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! HMAC-SHA256 with an arbitrary-length key, and HKDF-SHA256 (RFC 5869).
//!
//! The one HMAC-SHA256 in the crate: the entropy pool's HMAC_DRBG, the TCP
//! ISN generator, Noise and the RPC warrants all call it. The key may be any
//! length (HKDF's extract salt and the Noise chaining key are caller-sized).
//! No allocation: the key pads live in two 64-byte stack blocks, wiped on
//! exit.

use crate::ct::secure_zero;
use crate::sha256::{Digest, Sha256};

/// SHA-256 output / HMAC tag length.
pub const HASH_LEN: usize = 32;
/// SHA-256 block length (the HMAC pad width).
const BLOCK_LEN: usize = 64;
/// RFC 5869 §2.3: L <= 255 * HashLen.
pub const MAX_OKM: usize = 255 * HASH_LEN;

/// `HMAC-SHA256(key, parts[0] || parts[1] || ...)` (RFC 2104).
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Digest {
    let mut k = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        let d = {
            let mut h = Sha256::new();
            h.update(key);
            h.finalize()
        };
        k[..HASH_LEN].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK_LEN];
    let mut opad = [0x5cu8; BLOCK_LEN];
    for i in 0..BLOCK_LEN {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    for p in parts {
        inner.update(p);
    }
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner);
    let tag = outer.finalize();
    secure_zero(&mut k);
    secure_zero(&mut ipad);
    secure_zero(&mut opad);
    tag
}

/// HKDF-Extract: `PRK = HMAC(salt, ikm)`. An empty salt is HashLen zeros
/// (RFC 5869 §2.2), which HMAC's zero padding makes the same thing.
pub fn extract(salt: &[u8], ikm: &[u8]) -> Digest {
    hmac_sha256(salt, &[ikm])
}

/// HKDF-Expand into `okm`. Returns false (and writes nothing) when
/// `okm.len() > MAX_OKM`.
pub fn expand(prk: &[u8; HASH_LEN], info: &[u8], okm: &mut [u8]) -> bool {
    if okm.len() > MAX_OKM {
        return false;
    }
    let mut t = [0u8; HASH_LEN];
    let mut t_len = 0usize;
    for (i, chunk) in okm.chunks_mut(HASH_LEN).enumerate() {
        let ctr = [(i + 1) as u8];
        t = hmac_sha256(prk, &[&t[..t_len], info, &ctr]);
        t_len = HASH_LEN;
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
    secure_zero(&mut t);
    true
}

/// Extract-then-expand in one call.
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> bool {
    let mut prk = extract(salt, ikm);
    let ok = expand(&prk, info, okm);
    secure_zero(&mut prk);
    ok
}
