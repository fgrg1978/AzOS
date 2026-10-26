// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The in-memory extent list of one file, sorted by file block and
//! non-overlapping, and the operations on it. A hole is the absence of an
//! extent. Pure functions: the volume decides what to do with the blocks
//! they report as freed.

use alloc::vec::Vec;

use super::layout::{Extent, Geometry, EXT_KNOWN_FLAGS};
use super::Error;

/// Index of the first extent that ends after file block `fb`.
pub fn first_after(exts: &[Extent], fb: u64) -> usize {
    exts.partition_point(|e| e.file_end() <= fb)
}

/// The extent containing file block `fb`, if any.
pub fn containing(exts: &[Extent], fb: u64) -> Option<usize> {
    let i = first_after(exts, fb);
    match exts.get(i) {
        Some(e) if e.file_blk <= fb => Some(i),
        _ => None,
    }
}

/// Check a list read from disk: known flags, ranges inside the data area,
/// ordered, non-overlapping, generations not from the future.
pub fn validate(exts: &[Extent], geo: &Geometry, max_gen: u64) -> Result<(), Error> {
    let mut prev_end = 0u64;
    for e in exts {
        if e.nblocks == 0 {
            return Err(Error::Corrupt("empty extent"));
        }
        if e.flags & !EXT_KNOWN_FLAGS != 0 {
            return Err(Error::Unsupported("extent flags"));
        }
        let disk_end = e.disk_blk.checked_add(e.nblocks as u64).ok_or(Error::Corrupt("extent range"))?;
        if e.disk_blk < geo.data_start || disk_end > geo.block_count {
            return Err(Error::Corrupt("extent outside data area"));
        }
        let file_end = e.file_blk.checked_add(e.nblocks as u64).ok_or(Error::Corrupt("extent range"))?;
        if e.file_blk < prev_end {
            return Err(Error::Corrupt("extents out of order"));
        }
        if e.gen > max_gen {
            return Err(Error::Corrupt("extent from the future"));
        }
        prev_end = file_end;
    }
    Ok(())
}

/// One run of volume blocks given up by [`punch`].
#[derive(Clone, Copy, Debug)]
pub struct Freed {
    pub disk_blk: u64,
    pub nblocks: u32,
    pub gen: u64,
}

/// Remove the mapping of file blocks `[start, end)`, splitting extents at
/// the edges (the remainders keep their generation). Returns what to free.
pub fn punch(exts: &mut Vec<Extent>, start: u64, end: u64, freed: &mut Vec<Freed>) {
    if start >= end {
        return;
    }
    let i = first_after(exts, start);
    let mut j = i;
    while j < exts.len() && exts[j].file_blk < end {
        j += 1;
    }
    if i == j {
        return;
    }
    let removed: Vec<Extent> = exts.drain(i..j).collect();
    let mut keep: Vec<Extent> = Vec::new();
    for e in removed {
        let ov_s = e.file_blk.max(start);
        let ov_e = e.file_end().min(end);
        if e.file_blk < ov_s {
            keep.push(Extent { nblocks: (ov_s - e.file_blk) as u32, ..e });
        }
        freed.push(Freed { disk_blk: e.disk_blk + (ov_s - e.file_blk), nblocks: (ov_e - ov_s) as u32, gen: e.gen });
        if ov_e < e.file_end() {
            keep.push(Extent {
                file_blk: ov_e,
                disk_blk: e.disk_blk + (ov_e - e.file_blk),
                nblocks: (e.file_end() - ov_e) as u32,
                ..e
            });
        }
    }
    exts.splice(i..i, keep);
}

fn mergeable(a: &Extent, b: &Extent) -> bool {
    a.file_end() == b.file_blk
        && a.disk_blk + a.nblocks as u64 == b.disk_blk
        && a.gen == b.gen
        && a.flags == b.flags
        && (a.nblocks as u64 + b.nblocks as u64) <= u32::MAX as u64
}

/// Insert an extent into a range that was punched (no overlap), merging it
/// with a neighbour that continues it on disk in the same generation.
pub fn insert(exts: &mut Vec<Extent>, e: Extent) {
    let i = first_after(exts, e.file_blk);
    exts.insert(i, e);
    if i + 1 < exts.len() && mergeable(&exts[i], &exts[i + 1]) {
        exts[i].nblocks += exts[i + 1].nblocks;
        exts.remove(i + 1);
    }
    if i > 0 && mergeable(&exts[i - 1], &exts[i]) {
        exts[i - 1].nblocks += exts[i].nblocks;
        exts.remove(i);
    }
}
