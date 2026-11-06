// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AES-128 (FIPS 197) and its CTR mode, from the RustCrypto `aes` and `ctr`
//! crates (the ones the ring-3 QUIC stack links). On every kernel target the
//! block cipher is `aes`'s fixsliced software backend: no table indexed by a
//! secret. No allocation; the key schedule is computed once and wiped on drop.

use aes::cipher::{BlockEncrypt, InnerIvInit, KeyInit, StreamCipher, StreamCipherCoreWrapper};
use ctr::{flavors::Ctr32BE, CtrCore};

/// AES block size in bytes (128 bits).
pub const AES_BLOCK_SIZE: usize = 16;

/// AES-128 key size in bytes.
pub const AES_KEY_SIZE: usize = 16;

/// AES-128 context with expanded key.
pub struct Aes128(aes::Aes128);

impl Aes128 {
    /// Create AES-128 context from a 16-byte key.
    pub fn new(key: &[u8; AES_KEY_SIZE]) -> Self {
        Self(aes::Aes128::new(key.into()))
    }

    /// Encrypt one 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        self.0.encrypt_block(block.into());
    }

    /// Encrypt data using CTR mode.
    ///
    /// `nonce`: 12-byte nonce. Counter starts at 1 and occupies the last 4
    /// bytes, big-endian (RFC 3686's counter block). `data`: plaintext
    /// (encrypted in place). Any length.
    pub fn ctr_encrypt(&self, nonce: &[u8; 12], data: &mut [u8]) {
        let mut iv = [0u8; AES_BLOCK_SIZE];
        iv[..12].copy_from_slice(nonce);
        iv[12..].copy_from_slice(&1u32.to_be_bytes());
        let core = CtrCore::<aes::Aes128, Ctr32BE>::inner_iv_init(self.0.clone(), (&iv).into());
        StreamCipherCoreWrapper::from_core(core).apply_keystream(data);
    }

    /// Decrypt data using CTR mode (same as encrypt — CTR is symmetric).
    pub fn ctr_decrypt(&self, nonce: &[u8; 12], data: &mut [u8]) {
        self.ctr_encrypt(nonce, data);
    }
}
