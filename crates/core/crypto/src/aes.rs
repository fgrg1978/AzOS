// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AES-128 block cipher (FIPS 197).
//!
//! Pure software, no_std, no allocations. ECB and CTR modes.
//! Key schedule computed once, reused for all blocks.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// AES block size in bytes (128 bits).
pub const AES_BLOCK_SIZE: usize = 16;

/// AES-128 key size in bytes.
pub const AES_KEY_SIZE: usize = 16;

/// Number of rounds for AES-128.
const NR: usize = 10;

/// Number of 32-bit words in the key.
const NK: usize = 4;

/// Expanded key size: 4 × (NR + 1) = 44 words.
const EXPANDED_KEY_WORDS: usize = 4 * (NR + 1);

// ---------------------------------------------------------------------------
// S-Box (FIPS 197 §5.1.1)
// ---------------------------------------------------------------------------

const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

/// Round constants (FIPS 197 §5.2).
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// AES-128 context with expanded key.
pub struct Aes128 {
    rk: [u32; EXPANDED_KEY_WORDS],
}

impl Aes128 {
    /// Create AES-128 context from a 16-byte key.
    pub fn new(key: &[u8; AES_KEY_SIZE]) -> Self {
        let mut ctx = Aes128 { rk: [0u32; EXPANDED_KEY_WORDS] };
        key_expansion(key, &mut ctx.rk);
        ctx
    }

    /// Encrypt one 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        let mut state = [0u32; 4];
        for i in 0..4 {
            state[i] = u32::from_be_bytes([block[4*i], block[4*i+1], block[4*i+2], block[4*i+3]]);
        }
        cipher(&mut state, &self.rk);
        for i in 0..4 {
            let b = state[i].to_be_bytes();
            block[4*i..4*i+4].copy_from_slice(&b);
        }
    }

    /// Encrypt data using CTR mode.
    ///
    /// `nonce`: 12-byte nonce. Counter starts at 1 and occupies the last 4 bytes.
    /// `data`: plaintext (encrypted in place). Any length.
    pub fn ctr_encrypt(&self, nonce: &[u8; 12], data: &mut [u8]) {
        let mut counter: u32 = 1;
        let mut offset = 0;

        while offset < data.len() {
            // Build counter block: nonce(12) || counter(4 BE)
            let mut ctr_block = [0u8; AES_BLOCK_SIZE];
            ctr_block[..12].copy_from_slice(nonce);
            ctr_block[12..16].copy_from_slice(&counter.to_be_bytes());

            // Encrypt counter block to get keystream
            self.encrypt_block(&mut ctr_block);

            // XOR keystream with data
            let remaining = data.len() - offset;
            let chunk = remaining.min(AES_BLOCK_SIZE);
            for i in 0..chunk {
                data[offset + i] ^= ctr_block[i];
            }

            offset += chunk;
            counter += 1;
        }
    }

    /// Decrypt data using CTR mode (same as encrypt — CTR is symmetric).
    pub fn ctr_decrypt(&self, nonce: &[u8; 12], data: &mut [u8]) {
        self.ctr_encrypt(nonce, data);
    }
}

// ---------------------------------------------------------------------------
// Key expansion (FIPS 197 §5.2)
// ---------------------------------------------------------------------------

fn key_expansion(key: &[u8; AES_KEY_SIZE], rk: &mut [u32; EXPANDED_KEY_WORDS]) {
    // First NK words are the key itself
    for i in 0..NK {
        rk[i] = u32::from_be_bytes([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]);
    }

    for i in NK..EXPANDED_KEY_WORDS {
        let mut temp = rk[i - 1];
        if i % NK == 0 {
            temp = sub_word(rot_word(temp)) ^ ((RCON[i / NK - 1] as u32) << 24);
        }
        rk[i] = rk[i - NK] ^ temp;
    }
}

// ---------------------------------------------------------------------------
// Cipher (FIPS 197 §5.1)
// ---------------------------------------------------------------------------

fn cipher(state: &mut [u32; 4], rk: &[u32; EXPANDED_KEY_WORDS]) {
    // Initial round key addition
    add_round_key(state, rk, 0);

    // Rounds 1..NR-1
    for round in 1..NR {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, rk, round);
    }

    // Final round (no MixColumns)
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, rk, NR);
}

// ---------------------------------------------------------------------------
// AES operations
// ---------------------------------------------------------------------------

fn add_round_key(state: &mut [u32; 4], rk: &[u32; EXPANDED_KEY_WORDS], round: usize) {
    for i in 0..4 {
        state[i] ^= rk[round * 4 + i];
    }
}

fn sub_bytes(state: &mut [u32; 4]) {
    for w in state.iter_mut() {
        let b = w.to_be_bytes();
        *w = u32::from_be_bytes([
            SBOX[b[0] as usize], SBOX[b[1] as usize],
            SBOX[b[2] as usize], SBOX[b[3] as usize],
        ]);
    }
}

fn shift_rows(state: &mut [u32; 4]) {
    // State is column-major: state[col] = [row0, row1, row2, row3]
    // ShiftRows rotates row i left by i positions.
    let mut flat = [0u8; 16];
    for c in 0..4 {
        let b = state[c].to_be_bytes();
        for r in 0..4 { flat[r * 4 + c] = b[r]; }
    }
    // Shift each row
    // Row 0: no shift
    // Row 1: shift left by 1
    let tmp = flat[4];
    flat[4] = flat[5]; flat[5] = flat[6]; flat[6] = flat[7]; flat[7] = tmp;
    // Row 2: shift left by 2
    flat.swap(8, 10); flat.swap(9, 11);
    // Row 3: shift left by 3 (= right by 1)
    let tmp = flat[15];
    flat[15] = flat[14]; flat[14] = flat[13]; flat[13] = flat[12]; flat[12] = tmp;
    // Pack back
    for c in 0..4 {
        state[c] = u32::from_be_bytes([flat[c], flat[4+c], flat[8+c], flat[12+c]]);
    }
}

fn mix_columns(state: &mut [u32; 4]) {
    for c in 0..4 {
        let b = state[c].to_be_bytes();
        let (s0, s1, s2, s3) = (b[0], b[1], b[2], b[3]);
        state[c] = u32::from_be_bytes([
            gf_mul2(s0) ^ gf_mul3(s1) ^ s2 ^ s3,
            s0 ^ gf_mul2(s1) ^ gf_mul3(s2) ^ s3,
            s0 ^ s1 ^ gf_mul2(s2) ^ gf_mul3(s3),
            gf_mul3(s0) ^ s1 ^ s2 ^ gf_mul2(s3),
        ]);
    }
}

// ---------------------------------------------------------------------------
// GF(2^8) arithmetic
// ---------------------------------------------------------------------------

#[inline(always)]
fn gf_mul2(x: u8) -> u8 {
    let shifted = (x as u16) << 1;
    if shifted & 0x100 != 0 { (shifted ^ 0x11b) as u8 } else { shifted as u8 }
}

#[inline(always)]
fn gf_mul3(x: u8) -> u8 {
    gf_mul2(x) ^ x
}

// ---------------------------------------------------------------------------
// Word operations
// ---------------------------------------------------------------------------

#[inline(always)]
fn sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([SBOX[b[0] as usize], SBOX[b[1] as usize],
                        SBOX[b[2] as usize], SBOX[b[3] as usize]])
}

#[inline(always)]
fn rot_word(w: u32) -> u32 {
    w.rotate_left(8)
}
