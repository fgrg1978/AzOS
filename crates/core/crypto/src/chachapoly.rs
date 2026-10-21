// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ChaCha20, Poly1305 and the ChaCha20-Poly1305 AEAD of RFC 8439.
//!
//! Portable and constant-time by construction: ChaCha20 is add/rotate/xor on
//! 32-bit words, Poly1305 is the 26-bit-limb schoolbook multiply with a
//! branch-free final reduction, and the tag comparison is `ct::ct_eq`. No
//! table lookup, no secret-dependent branch or index. No allocation: the
//! cipher is in place and detached (the tag is returned / passed alongside),
//! so a ring slot can be sealed where it sits.
//!
//! `open` verifies the tag over the ciphertext BEFORE decrypting; on a
//! mismatch the buffer is left untouched and no plaintext is produced.

use crate::ct::{ct_eq, secure_zero};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// RFC 8439 §2.8: the keystream block counter is 32 bits and block 0 is
/// spent on the Poly1305 key, so a message is at most 2^32 - 1 blocks.
pub const MAX_DATA_LEN: u64 = (u32::MAX as u64) * 64;

#[inline(always)]
fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

#[inline]
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// One 64-byte ChaCha20 keystream block (RFC 8439 §2.3).
pub fn chacha20_block(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN]) -> [u8; 64] {
    let mut init = [0u32; 16];
    init[0] = 0x6170_7865;
    init[1] = 0x3320_646e;
    init[2] = 0x7962_2d32;
    init[3] = 0x6b20_6574;
    for i in 0..8 {
        init[4 + i] = le32(&key[i * 4..]);
    }
    init[12] = counter;
    for i in 0..3 {
        init[13 + i] = le32(&nonce[i * 4..]);
    }
    let mut s = init;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    secure_zero(&mut s);
    secure_zero(&mut init);
    out
}

/// XOR `data` with the ChaCha20 keystream starting at block `counter`.
/// Returns false (data untouched) when the keystream would wrap the 32-bit
/// block counter.
pub fn chacha20_xor(
    key: &[u8; KEY_LEN],
    counter: u32,
    nonce: &[u8; NONCE_LEN],
    data: &mut [u8],
) -> bool {
    let blocks = (data.len() as u64).div_ceil(64);
    if blocks > (u32::MAX as u64) - counter as u64 + 1 {
        return false;
    }
    let mut ctr = counter;
    for chunk in data.chunks_mut(64) {
        let mut ks = chacha20_block(key, ctr, nonce);
        for (d, k) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= *k;
        }
        secure_zero(&mut ks);
        ctr = ctr.wrapping_add(1);
    }
    true
}

/// Poly1305 (RFC 8439 §2.5), 26-bit limbs.
pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let r = [
            le32(&key[0..]) & 0x3ff_ffff,
            (le32(&key[3..]) >> 2) & 0x3ff_ff03,
            (le32(&key[6..]) >> 4) & 0x3ff_c0ff,
            (le32(&key[9..]) >> 6) & 0x3f0_3fff,
            (le32(&key[12..]) >> 8) & 0x00f_ffff,
        ];
        let pad = [le32(&key[16..]), le32(&key[20..]), le32(&key[24..]), le32(&key[28..])];
        Self { r, h: [0; 5], pad }
    }

    /// Absorb one 16-byte block. `hibit` is 1<<24 for a full block, 0 for
    /// the final partial block of the plain (non-AEAD) construction, whose
    /// 0x01 terminator is already in the buffer.
    fn block(&mut self, m: &[u8; 16], hibit: u32) {
        const M: u32 = 0x3ff_ffff;
        let [r0, r1, r2, r3, r4] = self.r;
        let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
        let mut h0 = self.h[0] + (le32(&m[0..]) & M);
        let mut h1 = self.h[1] + ((le32(&m[3..]) >> 2) & M);
        let mut h2 = self.h[2] + ((le32(&m[6..]) >> 4) & M);
        let mut h3 = self.h[3] + ((le32(&m[9..]) >> 6) & M);
        let mut h4 = self.h[4] + ((le32(&m[12..]) >> 8) | hibit);

        let mul = |a: u32, b: u32| a as u64 * b as u64;
        let d0 = mul(h0, r0) + mul(h1, s4) + mul(h2, s3) + mul(h3, s2) + mul(h4, s1);
        let mut d1 = mul(h0, r1) + mul(h1, r0) + mul(h2, s4) + mul(h3, s3) + mul(h4, s2);
        let mut d2 = mul(h0, r2) + mul(h1, r1) + mul(h2, r0) + mul(h3, s4) + mul(h4, s3);
        let mut d3 = mul(h0, r3) + mul(h1, r2) + mul(h2, r1) + mul(h3, r0) + mul(h4, s4);
        let mut d4 = mul(h0, r4) + mul(h1, r3) + mul(h2, r2) + mul(h3, r1) + mul(h4, r0);

        let mut c = (d0 >> 26) as u32;
        h0 = d0 as u32 & M;
        d1 += c as u64;
        c = (d1 >> 26) as u32;
        h1 = d1 as u32 & M;
        d2 += c as u64;
        c = (d2 >> 26) as u32;
        h2 = d2 as u32 & M;
        d3 += c as u64;
        c = (d3 >> 26) as u32;
        h3 = d3 as u32 & M;
        d4 += c as u64;
        c = (d4 >> 26) as u32;
        h4 = d4 as u32 & M;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= M;
        h1 += c;
        self.h = [h0, h1, h2, h3, h4];
    }

    /// AEAD absorb (RFC 8439 §2.8): whole blocks, then the tail zero-padded
    /// to 16 bytes and absorbed as a full block.
    pub fn update_padded(&mut self, data: &[u8]) {
        let mut it = data.chunks_exact(16);
        for b in &mut it {
            let mut m = [0u8; 16];
            m.copy_from_slice(b);
            self.block(&m, 1 << 24);
        }
        let rem = it.remainder();
        if !rem.is_empty() {
            let mut m = [0u8; 16];
            m[..rem.len()].copy_from_slice(rem);
            self.block(&m, 1 << 24);
        }
    }

    /// Absorb one full 16-byte block (the AEAD length block).
    pub fn update_block(&mut self, m: &[u8; 16]) {
        self.block(m, 1 << 24);
    }

    /// Final reduction, add the pad, emit the tag. Consumes the state.
    pub fn finish(mut self) -> [u8; TAG_LEN] {
        const M: u32 = 0x3ff_ffff;
        let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;
        let mut c = h1 >> 26;
        h1 &= M;
        h2 += c;
        c = h2 >> 26;
        h2 &= M;
        h3 += c;
        c = h3 >> 26;
        h3 &= M;
        h4 += c;
        c = h4 >> 26;
        h4 &= M;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= M;
        h1 += c;

        // g = h + 5 - 2^130; keep g when h >= p (no borrow out of g4).
        let mut g0 = h0 + 5;
        c = g0 >> 26;
        g0 &= M;
        let mut g1 = h1 + c;
        c = g1 >> 26;
        g1 &= M;
        let mut g2 = h2 + c;
        c = g2 >> 26;
        g2 &= M;
        let mut g3 = h3 + c;
        c = g3 >> 26;
        g3 &= M;
        let g4 = (h4 + c).wrapping_sub(1 << 26);
        let keep_g = (g4 >> 31).wrapping_sub(1);
        let keep_h = !keep_g;
        h0 = (h0 & keep_h) | (g0 & keep_g);
        h1 = (h1 & keep_h) | (g1 & keep_g);
        h2 = (h2 & keep_h) | (g2 & keep_g);
        h3 = (h3 & keep_h) | (g3 & keep_g);
        h4 = (h4 & keep_h) | (g4 & keep_g);

        let w0 = (h0 | (h1 << 26)) as u64;
        let w1 = ((h1 >> 6) | (h2 << 20)) as u64;
        let w2 = ((h2 >> 12) | (h3 << 14)) as u64;
        let w3 = ((h3 >> 18) | (h4 << 8)) as u64;
        let mut f = w0 + self.pad[0] as u64;
        let t0 = f as u32;
        f = w1 + self.pad[1] as u64 + (f >> 32);
        let t1 = f as u32;
        f = w2 + self.pad[2] as u64 + (f >> 32);
        let t2 = f as u32;
        f = w3 + self.pad[3] as u64 + (f >> 32);
        let t3 = f as u32;

        let mut tag = [0u8; TAG_LEN];
        tag[0..4].copy_from_slice(&t0.to_le_bytes());
        tag[4..8].copy_from_slice(&t1.to_le_bytes());
        tag[8..12].copy_from_slice(&t2.to_le_bytes());
        tag[12..16].copy_from_slice(&t3.to_le_bytes());
        self.h = [0; 5];
        self.r = [0; 5];
        self.pad = [0; 4];
        tag
    }
}

/// One-shot Poly1305 over an arbitrary message (RFC 8439 §2.5: the final
/// partial block gets a 0x01 terminator instead of the high bit).
pub fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; TAG_LEN] {
    let mut p = Poly1305::new(key);
    let mut it = msg.chunks_exact(16);
    for b in &mut it {
        let mut m = [0u8; 16];
        m.copy_from_slice(b);
        p.block(&m, 1 << 24);
    }
    let rem = it.remainder();
    if !rem.is_empty() {
        let mut m = [0u8; 16];
        m[..rem.len()].copy_from_slice(rem);
        m[rem.len()] = 1;
        p.block(&m, 0);
    }
    p.finish()
}

/// AEAD tag over `aad` and `ciphertext` with the one-time key from block 0.
fn aead_tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; TAG_LEN] {
    let mut p = Poly1305::new(otk);
    p.update_padded(aad);
    p.update_padded(ciphertext);
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    p.update_block(&lens);
    p.finish()
}

fn one_time_key(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    let mut blk = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&blk[..32]);
    secure_zero(&mut blk);
    otk
}

/// Encrypt `data` in place and return the detached tag. `None` when `data`
/// exceeds `MAX_DATA_LEN` (nothing is modified).
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
) -> Option<[u8; TAG_LEN]> {
    if data.len() as u64 > MAX_DATA_LEN {
        return None;
    }
    let mut otk = one_time_key(key, nonce);
    chacha20_xor(key, 1, nonce, data);
    let tag = aead_tag(&otk, aad, data);
    secure_zero(&mut otk);
    Some(tag)
}

/// Verify `tag` over (`aad`, ciphertext `data`) and, only if it matches,
/// decrypt `data` in place. On failure `data` is left as received.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> bool {
    if data.len() as u64 > MAX_DATA_LEN {
        return false;
    }
    let mut otk = one_time_key(key, nonce);
    let mut expect = aead_tag(&otk, aad, data);
    secure_zero(&mut otk);
    let ok = ct_eq(&expect, tag);
    secure_zero(&mut expect);
    if ok {
        chacha20_xor(key, 1, nonce, data);
    }
    ok
}
