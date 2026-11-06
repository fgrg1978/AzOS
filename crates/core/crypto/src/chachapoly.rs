// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ChaCha20, Poly1305 and the ChaCha20-Poly1305 AEAD of RFC 8439, from the
//! RustCrypto `chacha20`, `poly1305` and `chacha20poly1305` crates (the ones
//! the ring-3 TLS/QUIC provider links), in their portable constant-time
//! backends on every kernel target. No allocation: the cipher is in place and
//! detached (the tag is returned / passed alongside), so a ring slot can be
//! sealed where it sits.
//!
//! `open` verifies the tag over the ciphertext BEFORE decrypting; on a
//! mismatch the buffer is left untouched and no plaintext is produced.

use crate::ct::secure_zero;
use chacha20::cipher::consts::{U10, U64};
use chacha20::cipher::inout::InOutBuf;
use chacha20::cipher::{Block, KeyIvInit, StreamCipherCore, StreamCipherSeekCore};
use chacha20::ChaChaCore;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use poly1305::Poly1305;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// The AEAD's keystream starts at block 1 and its 32-bit block counter may
/// not wrap, so a message is at most 2^32 - 2 whole blocks.
pub const MAX_DATA_LEN: u64 = (u32::MAX as u64 - 1) * 64;

fn core(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN]) -> ChaChaCore<U10> {
    let mut c = ChaChaCore::<U10>::new(key.into(), nonce.into());
    c.set_block_pos(counter);
    c
}

/// One 64-byte ChaCha20 keystream block (RFC 8439 §2.3).
pub fn chacha20_block(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN]) -> [u8; 64] {
    let mut block = [0u8; 64];
    core(key, counter, nonce).write_keystream_block((&mut block).into());
    block
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
    // Block 2^32 - 1 is a valid block; the crate's own partial-apply refuses
    // it, so the range is checked above and the blocks are applied directly.
    let mut c = core(key, counter, nonce);
    let (blocks, mut tail) = InOutBuf::from(data).into_chunks::<U64>();
    c.apply_keystream_blocks_inout(blocks);
    if !tail.is_empty() {
        let mut ks = Block::<ChaChaCore<U10>>::default();
        c.write_keystream_block(&mut ks);
        tail.xor_in2out(&ks[..tail.len()]);
        secure_zero(&mut ks[..]);
    }
    true
}

/// One-shot Poly1305 over an arbitrary message (RFC 8439 §2.5: the final
/// partial block gets a 0x01 terminator instead of the high bit).
pub fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; TAG_LEN] {
    Poly1305::new(key.into()).compute_unpadded(msg).into()
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
    let tag = ChaCha20Poly1305::new(key.into()).encrypt_in_place_detached(nonce.into(), aad, data).ok()?;
    Some(tag.into())
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
    ChaCha20Poly1305::new(key.into())
        .decrypt_in_place_detached(nonce.into(), aad, data, tag.into())
        .is_ok()
}
