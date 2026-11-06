// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SHA-256 (FIPS 180-4) over RustCrypto's `digest` core API: the block
//! buffer and the padding are `block-buffer`'s, the block function is the
//! parent module's `compress_blocks` (the kernel's choice of backend; the
//! resident monitor includes this file by path and answers with
//! `sha2::compress256`).

use super::compress_blocks;
use crate::ct::secure_zero;
use digest::block_buffer::Eager;
use digest::core_api::{
    BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore, OutputSizeUser, UpdateCore,
};
use digest::generic_array::GenericArray;
use digest::typenum::{U32, U64};
use digest::{FixedOutput, HashMarker, Output, Update};

/// Initial hash values H0 (FIPS 180-4 §5.3.3).
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// One 64-byte message block.
pub type Block = GenericArray<u8, U64>;

/// SHA-256 digest (32 bytes).
pub type Digest = [u8; 32];

/// The chaining state and the count of whole blocks hashed; wiped on drop
/// (an HMAC keeps its keyed states in two of these).
#[derive(Clone)]
pub struct Core {
    state: [u32; 8],
    blocks: u64,
}

impl Default for Core {
    fn default() -> Self {
        Self { state: H0, blocks: 0 }
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        secure_zero(&mut self.state);
    }
}

impl HashMarker for Core {}

impl BlockSizeUser for Core {
    type BlockSize = U64;
}

impl BufferKindUser for Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Core {
    type OutputSize = U32;
}

impl UpdateCore for Core {
    fn update_blocks(&mut self, blocks: &[Block]) {
        self.blocks += blocks.len() as u64;
        compress_blocks(&mut self.state, blocks);
    }
}

impl FixedOutputCore for Core {
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bit_len = 8 * (self.blocks * 64 + buffer.get_pos() as u64);
        let state = &mut self.state;
        buffer.len64_padding_be(bit_len, |b| compress_blocks(state, core::slice::from_ref(b)));
        for (word, v) in out.chunks_exact_mut(4).zip(state.iter()) {
            word.copy_from_slice(&v.to_be_bytes());
        }
    }
}

/// The hasher as a `digest` type, for HMAC and HKDF.
pub type Hasher = CoreWrapper<Core>;

/// Incremental SHA-256 hasher.
#[derive(Clone, Default)]
pub struct Sha256(Hasher);

impl Sha256 {
    /// Create a new SHA-256 hasher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.0, data);
    }

    /// Finalize and return the 32-byte digest.
    pub fn finalize(self) -> Digest {
        self.0.finalize_fixed().into()
    }
}

/// One-shot SHA-256: hash `data` and return the 32-byte digest.
pub fn sha256(data: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}
