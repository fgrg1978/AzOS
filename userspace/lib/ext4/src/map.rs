// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! From a file's logical block to the volume's: extents and the block map.

use crate::inode::FL_EXTENTS;
use crate::{csum, le16, le32, BlockSource, Corrupt, Error, Inode, Volume};

const EXT_MAGIC: u16 = 0xF30A;
const EXT_HEADER: usize = 12;
const EXT_ENTRY: usize = 12;
/// `EXT4_MAX_EXTENT_DEPTH`.
const EXT_DEPTH_MAX: u16 = 5;
/// Above this an extent's length is unwritten: `len - 32768` blocks of zeros.
const EXT_INIT_MAX: u16 = 32768;
/// Entries the inode's own 60 bytes hold.
const EXT_ROOT_MAX: u16 = 4;

/// Direct blocks of the block map.
const DIRECT: u32 = 12;

/// A run of logical blocks: `len` of them from the asked one, at `start` on
/// the volume, or a hole (`None`, read as zeros).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Run {
    pub start: Option<u64>,
    pub len: u32,
}

impl<S: BlockSource> Volume<S> {
    /// Where logical block `lblk` of `ino` lives.
    pub(crate) fn map(&mut self, ino: &Inode, lblk: u32) -> Result<Run, Error> {
        if ino.flags & FL_EXTENTS != 0 {
            self.map_extent(ino, lblk)
        } else {
            self.map_blockmap(ino, lblk)
        }
    }

    fn map_extent(&mut self, ino: &Inode, lblk: u32) -> Result<Run, Error> {
        let bs = self.sb.block_size as usize;
        // The node being read lives in the volume's block buffer: a map is
        // always made before the block it finds is loaded there.
        let node = &mut self.blk;
        node[..60].copy_from_slice(&ino.block);
        let mut len = 60usize;
        let mut cap = EXT_ROOT_MAX;
        let mut want_depth: Option<u16> = None;
        // Each pass goes one level down; the depth is checked against the
        // bound and against the level above, so this ends.
        loop {
            let n = &node[..len];
            if le16(n, 0)? != EXT_MAGIC {
                return Err(Corrupt::Extent.into());
            }
            let entries = le16(n, 2)?;
            let max = le16(n, 4)?;
            let depth = le16(n, 6)?;
            if entries > max || max > cap || depth > EXT_DEPTH_MAX || want_depth.is_some_and(|d| d != depth) {
                return Err(Corrupt::Extent.into());
            }
            // The last entry that starts at or before `lblk`, and the start of
            // the one after it (where a hole ends).
            let mut hit: Option<usize> = None;
            let mut next_start: Option<u32> = None;
            let mut prev: Option<u32> = None;
            for i in 0..entries as usize {
                let e = EXT_HEADER + i * EXT_ENTRY;
                let first = le32(n, e)?;
                if prev.is_some_and(|p| first <= p) {
                    return Err(Corrupt::Extent.into());
                }
                prev = Some(first);
                if first <= lblk {
                    hit = Some(e);
                } else {
                    next_start = Some(first);
                    break;
                }
            }
            if depth == 0 {
                let hole_to = |next: Option<u32>| Run { start: None, len: next.map_or(u32::MAX - lblk, |s| s - lblk).max(1) };
                let Some(e) = hit else { return Ok(hole_to(next_start)) };
                let first = le32(n, e)?;
                let raw_len = le16(n, e + 4)?;
                let (unwritten, elen) =
                    if raw_len > EXT_INIT_MAX { (true, raw_len - EXT_INIT_MAX) } else { (false, raw_len) };
                let pstart = (le16(n, e + 6)? as u64) << 32 | le32(n, e + 8)? as u64;
                if elen == 0 || pstart.checked_add(elen as u64).is_none_or(|end| end > self.sb.blocks_count) {
                    return Err(Corrupt::Extent.into());
                }
                // `first <= lblk` here.
                let off = lblk - first;
                if off >= elen as u32 {
                    return Ok(hole_to(next_start));
                }
                let left = elen as u32 - off;
                // An extent that overlaps the next one is out of shape.
                if next_start.is_some_and(|s| s - first < elen as u32) {
                    return Err(Corrupt::Extent.into());
                }
                return Ok(Run { start: if unwritten { None } else { Some(pstart + off as u64) }, len: left });
            }
            let Some(e) = hit else { return Ok(Run { start: None, len: next_start.map_or(1, |s| s - lblk) }) };
            let child = (le16(n, e + 8)? as u64) << 32 | le32(n, e + 4)? as u64;
            crate::read_run(&mut self.src, &self.sb, child, 0, &mut node[..bs], false)?;
            len = bs;
            cap = ((bs - EXT_HEADER - 4) / EXT_ENTRY) as u16;
            want_depth = Some(depth - 1);
            if self.sb.features.metadata_csum() {
                let max = le16(&node[..], 4)? as usize;
                let tail = EXT_HEADER + max.min(cap as usize) * EXT_ENTRY;
                if csum(ino.csum_seed, &node[..tail]) != le32(&node[..], tail)? {
                    return Err(Corrupt::Checksum.into());
                }
            }
        }
    }

    fn map_blockmap(&mut self, ino: &Inode, lblk: u32) -> Result<Run, Error> {
        let per = self.sb.block_size / 4;
        let ptr = |i: u32| le32(&ino.block, i as usize * 4);
        if lblk < DIRECT {
            return self.blockmap_leaf(ptr(lblk)?);
        }
        // The levels: single, double, triple indirect, each `per` times wider.
        let mut rel = (lblk - DIRECT) as u64;
        let mut span = per as u64;
        for level in 0..3u32 {
            if rel < span {
                let mut b = ptr(DIRECT + level)?;
                let mut unit = span / per as u64;
                for _ in 0..=level {
                    if b == 0 {
                        return Ok(Run { start: None, len: 1 });
                    }
                    let idx = (rel / unit) as usize;
                    let at = idx * 4;
                    let mut w = [0u8; 4];
                    self.read_blocks(b as u64, at, &mut w)?;
                    b = u32::from_le_bytes(w);
                    rel %= unit;
                    unit = (unit / per as u64).max(1);
                }
                return self.blockmap_leaf(b);
            }
            rel -= span;
            span = span.saturating_mul(per as u64);
        }
        Err(Corrupt::Size.into())
    }

    fn blockmap_leaf(&self, b: u32) -> Result<Run, Error> {
        if b == 0 {
            return Ok(Run { start: None, len: 1 });
        }
        if b as u64 >= self.sb.blocks_count {
            return Err(Corrupt::BlockRange.into());
        }
        Ok(Run { start: Some(b as u64), len: 1 })
    }
}
