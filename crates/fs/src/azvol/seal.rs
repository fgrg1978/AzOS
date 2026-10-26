// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Sealing: ChaCha20-Poly1305 on every block of an azvol volume's data area
//! (file data, directory blocks, tree nodes, the inode table's data).
//!
//! **What is sealed.** The data area. The superblocks, the free-space bitmap
//! and the table below are not: they hold geometry, allocation state and
//! tags, no file content or names. The allocation pattern is visible to
//! whoever holds the medium.
//!
//! **The table.** A sealed volume's per-block table (the checksum table of a
//! plain volume) holds one 24-byte entry per volume block: the 16-byte
//! Poly1305 tag and the 8-byte *write sequence number* the block was sealed
//! under. A read opens the block with the entry's sequence number, and a
//! block whose tag fails is an error ([`Error::Auth`]), never returned. The
//! table is updated in place at commit exactly like the crc32c table is, and
//! for the same reason it is safe: only blocks no committed tree names are
//! ever resealed.
//!
//! **Nonce.** 12 bytes: the write sequence number (8 bytes) then the block
//! number (4 bytes, which is why a sealed volume holds fewer than 2^32
//! blocks). The sequence number is `generation << 28 | counter`: the commit
//! generation the block is written in, which is what makes copy on write
//! never reuse a nonce (a block is rewritten at a later generation), and a
//! counter of the writes of that transaction, because a generation alone is
//! not enough:
//!
//! * a block written in the open transaction is overwritten in place by a
//!   later write of the same transaction (its extent carries the open
//!   generation, nothing committed names it), and the allocator can hand a
//!   freed block back within the transaction;
//! * a cut loses the transaction but its ciphertext stays on the medium, and
//!   the next mount reuses the generation.
//!
//! The counter covers the first two (it never goes back within a mount, not
//! even across an aborted change group); the third is closed by
//! [`super::Volume::mount_sealed`], which commits a new generation before it
//! returns, so no generation is ever opened twice. Past 2^28 block writes in
//! one transaction, or generation 2^36, a write fails with
//! [`Error::NonceExhausted`] instead of repeating a nonce (commit and carry
//! on, or reformat).
//!
//! The block number and the volume uuid are also authenticated (associated
//! data), so a sealed block moved to another place, or to another volume
//! under the same key, fails its tag.
//!
//! **Keys.** The caller holds a 32-byte *master key* (from the keystore, the
//! link-key family) and passes it to format and mount as a [`VolumeKey`].
//! The key sealing the blocks is `HKDF-SHA256(salt = uuid, ikm = master)`, so
//! two volumes under one master never share a stream (the uuid must be fresh
//! for every format). The superblock's `key_id` is a second, independent
//! derivation: a mount compares it first, so a wrong key is refused
//! ([`Error::WrongKey`]) before any data is touched, and the id reveals
//! nothing of the key. `wrapped_key` stays zero: it is the slot for
//! per-user wrapped copies of the master (D10).
//!
//! **Not covered.** Freshness. A tag binds a block to its place, its volume
//! and its sequence number, but whoever can write the medium can put an old
//! block back together with its old table entry, and the volume will take
//! it for the block it was. Authenticating the table against rollback needs a
//! root the medium cannot rewrite (a counter in the device, a signed
//! superblock chain); this layer does not claim it.

use azos_crypto::chachapoly;
use azos_crypto::ct::{ct_eq, secure_zero};
use azos_crypto::hkdf;

use super::layout::{BLOCK_SIZE, SEAL_ENTRY_SIZE};
use super::Error;

/// `key_alg` of a volume sealed block by block with ChaCha20-Poly1305.
pub const ALG_CHACHA20_POLY1305: u32 = 1;

/// Bits of the sequence number below the generation.
pub const COUNTER_BITS: u32 = 28;
/// Largest generation a sealed volume can write at.
pub const MAX_GENERATION: u64 = (1 << (64 - COUNTER_BITS)) - 1;

const KEY_INFO: &[u8] = b"azvol/chacha20-poly1305/v1 volume key";
const ID_INFO: &[u8] = b"azvol/chacha20-poly1305/v1 key id";

/// The master key a sealed volume is opened with. Wiped when dropped; it is
/// neither `Clone` nor `Debug`.
pub struct VolumeKey([u8; chachapoly::KEY_LEN]);

impl VolumeKey {
    pub fn from_bytes(key: &[u8; chachapoly::KEY_LEN]) -> VolumeKey {
        VolumeKey(*key)
    }

    /// The identifier stored in the superblock for this key and volume.
    pub fn key_id(&self, uuid: &[u8; 16]) -> [u8; 16] {
        let mut id = [0u8; 16];
        let ok = hkdf::hkdf(uuid, &self.0, ID_INFO, &mut id);
        debug_assert!(ok);
        id
    }

    pub fn sealer(&self, uuid: &[u8; 16]) -> Sealer {
        let mut key = [0u8; chachapoly::KEY_LEN];
        let ok = hkdf::hkdf(uuid, &self.0, KEY_INFO, &mut key);
        debug_assert!(ok);
        Sealer { key, uuid: *uuid, gen: 0, counter: 0 }
    }
}

impl Drop for VolumeKey {
    fn drop(&mut self) {
        secure_zero(&mut self.0);
    }
}

/// The write sequence number of the `counter`-th block write of generation
/// `gen`.
pub fn seq(gen: u64, counter: u64) -> u64 {
    debug_assert!(gen <= MAX_GENERATION && counter < (1 << COUNTER_BITS));
    gen << COUNTER_BITS | counter
}

/// The generation a sequence number was written in.
pub fn seq_generation(seq: u64) -> u64 {
    seq >> COUNTER_BITS
}

/// The AEAD nonce of block `blk` sealed under sequence number `seq`.
pub fn nonce(seq: u64, blk: u64) -> [u8; chachapoly::NONCE_LEN] {
    let mut n = [0u8; chachapoly::NONCE_LEN];
    n[..8].copy_from_slice(&seq.to_le_bytes());
    n[8..].copy_from_slice(&(blk as u32).to_le_bytes());
    n
}

/// One table entry: tag, then sequence number.
pub fn encode_entry(tag: &[u8; chachapoly::TAG_LEN], seq: u64, out: &mut [u8]) {
    out[..chachapoly::TAG_LEN].copy_from_slice(tag);
    out[chachapoly::TAG_LEN..SEAL_ENTRY_SIZE].copy_from_slice(&seq.to_le_bytes());
}

pub fn decode_entry(b: &[u8]) -> ([u8; chachapoly::TAG_LEN], u64) {
    let mut tag = [0u8; chachapoly::TAG_LEN];
    tag.copy_from_slice(&b[..chachapoly::TAG_LEN]);
    let mut s = [0u8; 8];
    s.copy_from_slice(&b[chachapoly::TAG_LEN..SEAL_ENTRY_SIZE]);
    (tag, u64::from_le_bytes(s))
}

/// The state of a mounted sealed volume: the derived key and the write
/// counter of the open generation.
pub struct Sealer {
    key: [u8; chachapoly::KEY_LEN],
    uuid: [u8; 16],
    gen: u64,
    counter: u64,
}

impl Sealer {
    /// The sequence number for the next block write in generation `gen`.
    pub fn next_seq(&mut self, gen: u64) -> Result<u64, Error> {
        if gen != self.gen {
            self.gen = gen;
            self.counter = 0;
        }
        if gen > MAX_GENERATION || self.counter >= 1 << COUNTER_BITS {
            return Err(Error::NonceExhausted);
        }
        let s = seq(gen, self.counter);
        self.counter += 1;
        Ok(s)
    }

    fn aad(&self, blk: u64) -> [u8; 24] {
        let mut a = [0u8; 24];
        a[..8].copy_from_slice(&blk.to_le_bytes());
        a[8..].copy_from_slice(&self.uuid);
        a
    }

    /// Encrypt one block in place; returns its tag.
    pub fn seal(&self, blk: u64, seq: u64, data: &mut [u8]) -> [u8; chachapoly::TAG_LEN] {
        debug_assert_eq!(data.len(), BLOCK_SIZE);
        chachapoly::seal(&self.key, &nonce(seq, blk), &self.aad(blk), data).expect("a block is far below the AEAD limit")
    }

    /// Verify and decrypt one block in place. `false`: the tag fails and
    /// `data` is left as received.
    pub fn open(&self, blk: u64, seq: u64, tag: &[u8; chachapoly::TAG_LEN], data: &mut [u8]) -> bool {
        debug_assert_eq!(data.len(), BLOCK_SIZE);
        chachapoly::open(&self.key, &nonce(seq, blk), &self.aad(blk), data, tag)
    }
}

/// Compare a stored key id with the one a key derives (constant time).
pub fn ids_match(stored: &[u8; 16], derived: &[u8; 16]) -> bool {
    ct_eq(stored, derived)
}

impl Drop for Sealer {
    fn drop(&mut self) {
        secure_zero(&mut self.key);
    }
}
