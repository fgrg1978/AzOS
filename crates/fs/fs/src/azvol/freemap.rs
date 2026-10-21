// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The free-space map: one bit per volume block, kept in memory as a flat
//! byte vector and stored in the static bitmap region (blocks
//! `bitmap_start..+bitmap_blocks`), each block `4092` bytes of bits plus a
//! crc32c trailer.
//!
//! The map is a cache of what the trees reference, not a source of truth:
//! a bitmap block that fails its checksum, or a map whose population count
//! disagrees with the superblock's `used_blocks`, is rebuilt by walking the
//! trees at mount (`Volume::mount`). That is what lets the map be updated in
//! place without a journal; the commit ordering only has to keep the stored
//! map a SUPERSET of the live blocks (allocations reach the disk before the
//! superblock that names them, frees after).

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;

use super::crc32c::crc32c;
use super::layout::{rd32, wr32, Geometry, BITMAP_BITS_PER_BLOCK, BITMAP_PAYLOAD};

pub struct FreeMap {
    bits: Vec<u8>,
    blocks: u64,
    hint: u64,
    dirty: BTreeSet<u64>,
}

impl FreeMap {
    /// All blocks free, nothing dirty.
    pub fn new(geo: &Geometry) -> FreeMap {
        FreeMap {
            bits: vec![0u8; geo.bitmap_blocks as usize * BITMAP_PAYLOAD],
            blocks: geo.block_count,
            hint: geo.data_start,
            dirty: BTreeSet::new(),
        }
    }

    /// Mark the static regions (everything below `data_start`) as used.
    pub fn set_static(&mut self, geo: &Geometry) {
        for b in 0..geo.data_start {
            self.bits[(b / 8) as usize] |= 1 << (b % 8);
        }
    }

    pub fn is_set(&self, b: u64) -> bool {
        b < self.blocks && self.bits[(b / 8) as usize] & (1 << (b % 8)) != 0
    }

    /// Set the bit; returns whether it was clear before.
    pub fn set(&mut self, b: u64) -> bool {
        if b >= self.blocks {
            return false;
        }
        let m = 1u8 << (b % 8);
        let i = (b / 8) as usize;
        let was_clear = self.bits[i] & m == 0;
        self.bits[i] |= m;
        self.dirty.insert(b / BITMAP_BITS_PER_BLOCK);
        was_clear
    }

    /// Clear the bit; returns whether it was set before.
    pub fn clear(&mut self, b: u64) -> bool {
        if b >= self.blocks {
            return false;
        }
        let m = 1u8 << (b % 8);
        let i = (b / 8) as usize;
        let was_set = self.bits[i] & m != 0;
        self.bits[i] &= !m;
        self.dirty.insert(b / BITMAP_BITS_PER_BLOCK);
        was_set
    }

    /// Set bits in the whole map.
    pub fn count(&self) -> u64 {
        self.bits.iter().map(|b| b.count_ones() as u64).sum()
    }

    /// Next-fit: the first free run at or after the hint (wrapping to
    /// `data_start`), at most `want` blocks long. The run is NOT marked.
    pub fn find_run(&mut self, want: u32, data_start: u64) -> Option<(u64, u32)> {
        let start = if self.hint >= data_start && self.hint < self.blocks { self.hint } else { data_start };
        let (a, b) = (start, self.blocks);
        if let Some(r) = self.scan(a, b, want) {
            self.hint = r.0 + r.1 as u64;
            return Some(r);
        }
        if let Some(r) = self.scan(data_start, start, want) {
            self.hint = r.0 + r.1 as u64;
            return Some(r);
        }
        None
    }

    fn scan(&self, lo: u64, hi: u64, want: u32) -> Option<(u64, u32)> {
        let mut b = lo;
        while b < hi {
            if self.bits[(b / 8) as usize] == 0xFF && b % 8 == 0 {
                b += 8;
                continue;
            }
            if self.is_set(b) {
                b += 1;
                continue;
            }
            let s = b;
            while b < hi && (b - s) < want as u64 && !self.is_set(b) {
                b += 1;
            }
            return Some((s, (b - s) as u32));
        }
        None
    }

    /// Bitmap blocks changed since the last call, in order.
    pub fn take_dirty(&mut self) -> Vec<u64> {
        let v: Vec<u64> = self.dirty.iter().copied().collect();
        self.dirty.clear();
        v
    }

    pub fn mark_all_dirty(&mut self, geo: &Geometry) {
        for i in 0..geo.bitmap_blocks {
            self.dirty.insert(i);
        }
    }

    /// Serialise bitmap block `idx` into `out` (`BLOCK_SIZE` bytes).
    pub fn encode_block(&self, idx: u64, out: &mut [u8]) {
        let o = idx as usize * BITMAP_PAYLOAD;
        out[..BITMAP_PAYLOAD].copy_from_slice(&self.bits[o..o + BITMAP_PAYLOAD]);
        let crc = crc32c(&out[..BITMAP_PAYLOAD]);
        wr32(out, BITMAP_PAYLOAD, crc);
    }

    /// Load bitmap block `idx` from `data`; false if its checksum is bad
    /// (the block is then left clear).
    pub fn decode_block(&mut self, idx: u64, data: &[u8]) -> bool {
        if rd32(data, BITMAP_PAYLOAD) != crc32c(&data[..BITMAP_PAYLOAD]) {
            return false;
        }
        let o = idx as usize * BITMAP_PAYLOAD;
        self.bits[o..o + BITMAP_PAYLOAD].copy_from_slice(&data[..BITMAP_PAYLOAD]);
        true
    }

    /// True if no bit at or beyond the volume end is set.
    pub fn padding_clean(&self) -> bool {
        let mut b = self.blocks;
        while b < self.bits.len() as u64 * 8 {
            if self.bits[(b / 8) as usize] & (1 << (b % 8)) != 0 {
                return false;
            }
            b += 1;
        }
        true
    }

    /// Set every bit that is set in `other` (same geometry).
    pub fn union_with(&mut self, other: &FreeMap) {
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a |= *b;
        }
    }

    /// Blocks set in `self` and clear in `other` (and the reverse count).
    pub fn diff(&self, other: &FreeMap) -> (u64, u64) {
        let (mut only_self, mut only_other) = (0u64, 0u64);
        for (a, b) in self.bits.iter().zip(other.bits.iter()) {
            only_self += (a & !b).count_ones() as u64;
            only_other += (b & !a).count_ones() as u64;
        }
        (only_self, only_other)
    }
}
