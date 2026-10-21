// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The cryptographic toolbox of LE Secure Connections (Core Vol 3 Part H 2.2):
//! AES-CMAC (RFC 4493) over the tree's AES-128, and the functions f4, f5, f6
//! and g2 built on it.
//!
//! Every value here is in the **specification's order, most significant byte
//! first**. On the air (and in [`smp`](crate::smp)'s PDUs) the same values are
//! least significant byte first; the pairing code reverses at that boundary and
//! nowhere else.

use azos_crypto::aes::Aes128;

/// A 128-bit value.
pub type U128 = [u8; 16];

const RB: u8 = 0x87;

fn shift_left(b: &U128) -> U128 {
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = b[i] << 1 | if i < 15 { b[i + 1] >> 7 } else { 0 };
    }
    o
}

fn xor16(a: &mut U128, b: &U128) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

/// AES-CMAC of `msg` under `key` (RFC 4493). `msg` is a list of parts, taken
/// as one message, so the callers do not assemble a buffer.
pub fn cmac(key: &U128, parts: &[&[u8]]) -> U128 {
    let aes = Aes128::new(key);
    let mut l = [0u8; 16];
    aes.encrypt_block(&mut l);
    let mut k1 = shift_left(&l);
    if l[0] & 0x80 != 0 {
        k1[15] ^= RB;
    }
    let mut k2 = shift_left(&k1);
    if k1[0] & 0x80 != 0 {
        k2[15] ^= RB;
    }

    let total: usize = parts.iter().map(|p| p.len()).sum();
    let blocks = if total == 0 { 1 } else { total.div_ceil(16) };
    let complete = total != 0 && total % 16 == 0;

    let mut x = [0u8; 16];
    let mut cur = [0u8; 16];
    let mut fill = 0usize;
    let mut done = 0usize; // blocks absorbed before the last one
    for part in parts {
        for &byte in part.iter() {
            if fill == 16 {
                // A block that is not the last: absorb it.
                xor16(&mut x, &cur);
                aes.encrypt_block(&mut x);
                done += 1;
                fill = 0;
            }
            cur[fill] = byte;
            fill += 1;
        }
    }
    debug_assert_eq!(done + 1, blocks);
    let mut last = [0u8; 16];
    if complete {
        last = cur;
        xor16(&mut last, &k1);
    } else {
        last[..fill].copy_from_slice(&cur[..fill]);
        last[fill] = 0x80;
        xor16(&mut last, &k2);
    }
    xor16(&mut x, &last);
    aes.encrypt_block(&mut x);
    x
}

/// Confirm value generation (f4): `CMAC_X(U || V || Z)`; `u` and `v` are the
/// X coordinates of the two public keys.
pub fn f4(u: &[u8; 32], v: &[u8; 32], x: &U128, z: u8) -> U128 {
    cmac(x, &[u, v, &[z]])
}

/// Key generation (f5): the MacKey and the LTK from the DH key, the two nonces
/// and the two device addresses (`A1`, `A2`: type byte then six address bytes).
pub fn f5(w: &[u8; 32], n1: &U128, n2: &U128, a1: &[u8; 7], a2: &[u8; 7]) -> (U128, U128) {
    const SALT: U128 = [
        0x6C, 0x88, 0x83, 0x91, 0xAA, 0xF5, 0xA5, 0x38, 0x60, 0x37, 0x0B, 0xDB, 0x5A, 0x60, 0x83, 0xBE,
    ];
    const KEY_ID: [u8; 4] = [0x62, 0x74, 0x6C, 0x65]; // "btle"
    const LENGTH: [u8; 2] = [0x01, 0x00]; // 256 bits
    let t = cmac(&SALT, &[w]);
    let mac_key = cmac(&t, &[&[0], &KEY_ID, n1, n2, a1, a2, &LENGTH]);
    let ltk = cmac(&t, &[&[1], &KEY_ID, n1, n2, a1, a2, &LENGTH]);
    (mac_key, ltk)
}

/// Check value generation (f6): `CMAC_W(N1 || N2 || R || IOcap || A1 || A2)`,
/// `iocap` being `AuthReq || OOB flag || IO capability`.
pub fn f6(w: &U128, n1: &U128, n2: &U128, r: &U128, iocap: &[u8; 3], a1: &[u8; 7], a2: &[u8; 7]) -> U128 {
    cmac(w, &[n1, n2, r, iocap, a1, a2])
}

/// Numeric comparison value (g2): the six decimal digits both users read.
pub fn g2(u: &[u8; 32], v: &[u8; 32], x: &U128, y: &U128) -> u32 {
    let m = cmac(x, &[u, v, y]);
    u32::from_be_bytes([m[12], m[13], m[14], m[15]]) % 1_000_000
}

/// `b` reversed (specification order to air order and back).
pub fn rev<const N: usize>(b: &[u8; N]) -> [u8; N] {
    let mut o = *b;
    o.reverse();
    o
}
