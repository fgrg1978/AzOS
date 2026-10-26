// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Verity: a SHA-256 hash tree over a whole read-only azvol volume, checked on
//! every read. [`VerityDev`] is a [`BlockDev`] that sits between the engine and
//! the partition; the engine does not know it is there.
//!
//! **What is covered.** Every block of the volume, `[0, N)`: the superblocks,
//! the free-space map and the checksum table as well as the data area. A tree
//! over the data area alone would leave the superblock out, and the
//! superblock's inode-table record is the root of everything the volume
//! means: an attacker who can swap it can point the files at other (each
//! individually authentic) blocks. Covering the whole volume means no read
//! the engine makes is unchecked, and no range needs a rule.
//!
//! **Where the tree lives.** After the volume, on the same partition, so the
//! volume format itself does not change (the engine sees a volume of `N`
//! blocks and a device of `N` blocks):
//!
//! ```text
//!   [0, N)            the volume
//!   N                 header (one block, below)
//!   N+1 ..            level 0: one 32-byte SHA-256 per volume block,
//!                     128 to a hash block, in block order
//!   ..                level 1: one hash per level-0 hash block, and so on
//!                     until a level is a single block (the top)
//! ```
//!
//! Slots past the last child of a level are zero. A hash block is hashed whole.
//! Levels are laid out bottom first; their sizes follow from `N` alone
//! ([`Shape`]), so nothing in the header can describe a layout other than the
//! one `N` implies. The partition may be larger than the tree needs.
//!
//! **Header.** `AZVERITY`, version 1, hash algorithm 1 (SHA-256), `N`, the
//! number of levels, the SHA-256 of the top hash block, all other bytes zero.
//! The **verity root** is the SHA-256 of the header block: it commits to `N`,
//! the shape and the top, and through them to every block. It is the trust
//! anchor and it is not stored on the volume: the topology row carries it
//! (`verity_root`), and `tools/image/mkazvol.py create --verity` prints it.
//!
//! **Open.** The header's place depends on `N`, which only the superblock
//! says, and the superblock is not yet trusted. The superblock's block count
//! is therefore only a *hint* where to look: the block there must hash to the
//! root, and then `N` is the header's, authenticated. A wrong hint, a flipped
//! header and a wrong root all fail the same way ([`OpenError::RootMismatch`]).
//!
//! **Read.** The blocks are read in one device call, then each is hashed and
//! compared with its level-0 slot; that hash block is itself checked against
//! its slot a level up, to the top, whose hash is in the header. A hash block
//! that has checked out is kept (a bounded cache, [`CACHE_BLOCKS`], the lowest
//! level and block evicted first so the few upper levels stay), so a repeat
//! costs the data block's hash and nothing else. On any mismatch the whole
//! call fails, the caller's buffer is zeroed (an unchecked byte is never
//! returned) and the failure is handed to the [`Record`]. A run that includes
//! one bad block therefore fails entirely; the engine reads at most 64 blocks
//! a call.
//!
//! **Write.** Refused. The device is read-only; the volume under it is never
//! committed to (a read-only mount writes nothing).
//!
//! **Not covered: freshness.** The root names one image. An older image with
//! its own, older root is a different volume; which root the device accepts is
//! the signed topology's decision.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use azos_crypto::sha256::sha256;

use super::dev::{BlockDev, DevError};
use super::layout::{rd32, rd64, sbo, BLOCK_SIZE, MAGIC, SB_SLOTS};

pub const HEADER_MAGIC: [u8; 8] = *b"AZVERITY";
pub const VERSION: u32 = 1;
/// Hash algorithm id of the header: SHA-256.
pub const ALG_SHA256: u32 = 1;
pub const HASH_LEN: usize = 32;
/// Hashes in one hash block.
pub const FANOUT: u64 = (BLOCK_SIZE / HASH_LEN) as u64;
/// Deepest tree: `FANOUT^6` is past the largest volume (2^40 blocks).
pub const MAX_LEVELS: usize = 6;
/// Verified hash blocks kept (256 KiB).
pub const CACHE_BLOCKS: usize = 64;

pub type Hash = [u8; HASH_LEN];

/// Where the levels of the tree of an `N`-block volume lie.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    /// `N`: volume blocks covered.
    pub data_blocks: u64,
    pub levels: usize,
    /// Hash blocks in each level.
    pub count: [u64; MAX_LEVELS],
    /// Device block of each level's first hash block.
    pub start: [u64; MAX_LEVELS],
    /// Hash blocks in all levels.
    pub total: u64,
}

impl Shape {
    pub fn new(n: u64) -> Option<Shape> {
        if n == 0 || n > (1 << 40) {
            return None;
        }
        let mut s = Shape { data_blocks: n, levels: 0, count: [0; MAX_LEVELS], start: [0; MAX_LEVELS], total: 0 };
        let mut children = n;
        let mut at = n + 1;
        loop {
            if s.levels == MAX_LEVELS {
                return None;
            }
            let c = children.div_ceil(FANOUT);
            s.count[s.levels] = c;
            s.start[s.levels] = at;
            s.levels += 1;
            s.total += c;
            at += c;
            if c == 1 {
                return Some(s);
            }
            children = c;
        }
    }

    /// Device blocks the header and the tree take after the volume.
    pub fn blocks_after(&self) -> u64 {
        1 + self.total
    }
}

/// The header block as stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Header {
    data_blocks: u64,
    levels: u32,
    top: Hash,
}

const H_VERSION: usize = 8;
const H_ALG: usize = 12;
const H_BLOCKS: usize = 16;
const H_LEVELS: usize = 24;
const H_RESERVED: usize = 28;
const H_TOP: usize = 32;

impl Header {
    fn decode(b: &[u8]) -> Result<Header, OpenError> {
        if b[..8] != HEADER_MAGIC {
            return Err(OpenError::Malformed("verity header magic"));
        }
        if rd32(b, H_VERSION) != VERSION || rd32(b, H_ALG) != ALG_SHA256 {
            return Err(OpenError::Malformed("verity version or algorithm"));
        }
        if rd32(b, H_RESERVED) != 0 || b[H_TOP + HASH_LEN..BLOCK_SIZE].iter().any(|&x| x != 0) {
            return Err(OpenError::Malformed("verity header padding"));
        }
        let mut top = [0u8; HASH_LEN];
        top.copy_from_slice(&b[H_TOP..H_TOP + HASH_LEN]);
        Ok(Header { data_blocks: rd64(b, H_BLOCKS), levels: rd32(b, H_LEVELS), top })
    }
}

/// Why a device was not opened as a verity volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The device failed a read.
    Io,
    /// No superblock copy names a place to look for the header.
    NoHeader,
    /// Nothing at the place a superblock names hashes to the root.
    RootMismatch,
    /// The block hashes to the root but is not a header this implementation
    /// understands, or the tree it describes does not fit the device.
    Malformed(&'static str),
}

/// Which check a failed read failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fail {
    /// At open: no superblock names a place for the header, or the block there
    /// does not hash to the root.
    Header,
    /// A volume block does not hash to its level-0 slot.
    Data,
    /// A hash block of this level does not hash to the slot above it.
    Hash(u8),
}

/// One verification failure, handed to the [`Record`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tamper {
    /// Device block that failed: a volume block, or a hash block.
    pub block: u64,
    pub what: Fail,
    /// Failures of this device so far, this one included.
    pub count: u64,
}

/// Where failures are written down. The mount's implementation forwards them
/// to the system around it (`mount::Env::tampered`).
pub trait Record {
    fn tampered(&self, t: &Tamper);
}

enum Bad {
    Io,
    Tamper(u64, Fail),
}

/// A read-only device that returns only blocks that hash into the root.
pub struct VerityDev<D: BlockDev, R: Record> {
    dev: D,
    shape: Shape,
    top: Hash,
    rec: R,
    failures: u64,
    cache: BTreeMap<(u8, u64), Vec<u8>>,
}

impl<D: BlockDev, R: Record> VerityDev<D, R> {
    /// Open `dev` as the volume whose verity root is `root`.
    pub fn open(mut dev: D, root: &Hash, rec: R) -> Result<Self, OpenError> {
        let have = dev.block_count();
        let mut hints = [0u64; SB_SLOTS.len()];
        let mut nhints = 0;
        let mut blk = vec![0u8; BLOCK_SIZE];
        for slot in SB_SLOTS {
            if slot >= have || dev.read(slot, &mut blk).is_err() || blk[..8] != MAGIC {
                continue;
            }
            let n = rd64(&blk, sbo::BLOCK_COUNT);
            if n > 0 && n < have && !hints[..nhints].contains(&n) {
                hints[nhints] = n;
                nhints += 1;
            }
        }
        if nhints == 0 {
            rec.tampered(&Tamper { block: SB_SLOTS[0], what: Fail::Header, count: 1 });
            return Err(OpenError::NoHeader);
        }
        for &n in &hints[..nhints] {
            dev.read(n, &mut blk).map_err(|_| OpenError::Io)?;
            if sha256(&blk) != *root {
                continue;
            }
            // Authentic from here on: a header that is wrong is the builder's.
            let h = Header::decode(&blk)?;
            let shape = Shape::new(h.data_blocks).ok_or(OpenError::Malformed("verity block count"))?;
            if h.data_blocks != n || h.levels as usize != shape.levels {
                return Err(OpenError::Malformed("verity header disagrees with its place"));
            }
            if n + shape.blocks_after() > have {
                return Err(OpenError::Malformed("verity tree past the end of the device"));
            }
            return Ok(VerityDev { dev, shape, top: h.top, rec, failures: 0, cache: BTreeMap::new() });
        }
        rec.tampered(&Tamper { block: hints[0], what: Fail::Header, count: 1 });
        Err(OpenError::RootMismatch)
    }

    /// The stored hash of child `child` of level `level` (a volume block for
    /// level 0, a hash block of the level below otherwise).
    fn slot(&mut self, level: usize, child: u64) -> Result<Hash, Bad> {
        let idx = child / FANOUT;
        self.verified(level, idx)?;
        let at = (child % FANOUT) as usize * HASH_LEN;
        let blk = &self.cache[&(level as u8, idx)];
        let mut h = [0u8; HASH_LEN];
        h.copy_from_slice(&blk[at..at + HASH_LEN]);
        Ok(h)
    }

    /// Make hash block `idx` of `level` present in the cache, checked against
    /// its slot one level up (the header's top for the last level).
    fn verified(&mut self, level: usize, idx: u64) -> Result<(), Bad> {
        let key = (level as u8, idx);
        if self.cache.contains_key(&key) {
            return Ok(());
        }
        let dev_blk = self.shape.start[level] + idx;
        let mut blk = vec![0u8; BLOCK_SIZE];
        self.dev.read(dev_blk, &mut blk).map_err(|_| Bad::Io)?;
        let want = if level + 1 == self.shape.levels { self.top } else { self.slot(level + 1, idx)? };
        if sha256(&blk) != want {
            return Err(Bad::Tamper(dev_blk, Fail::Hash(level as u8)));
        }
        if self.cache.len() >= CACHE_BLOCKS {
            self.cache.pop_first();
        }
        self.cache.insert(key, blk);
        Ok(())
    }

    fn check(&mut self, first: u64, buf: &[u8]) -> Result<(), Bad> {
        for (i, b) in buf.chunks_exact(BLOCK_SIZE).enumerate() {
            let blk = first + i as u64;
            if sha256(b) != self.slot(0, blk)? {
                return Err(Bad::Tamper(blk, Fail::Data));
            }
        }
        Ok(())
    }
}

impl<D: BlockDev, R: Record> BlockDev for VerityDev<D, R> {
    /// The volume's `N` blocks; the tree after them is not the engine's.
    fn block_count(&self) -> u64 {
        self.shape.data_blocks
    }

    fn read(&mut self, first: u64, buf: &mut [u8]) -> Result<(), DevError> {
        let n = (buf.len() / BLOCK_SIZE) as u64;
        if n == 0 || buf.len() % BLOCK_SIZE != 0 || first.checked_add(n).map_or(true, |e| e > self.shape.data_blocks) {
            return Err(DevError);
        }
        self.dev.read(first, buf)?;
        match self.check(first, buf) {
            Ok(()) => Ok(()),
            Err(bad) => {
                buf.fill(0);
                if let Bad::Tamper(block, what) = bad {
                    self.failures += 1;
                    self.rec.tampered(&Tamper { block, what, count: self.failures });
                }
                Err(DevError)
            }
        }
    }

    fn write(&mut self, _first: u64, _buf: &[u8]) -> Result<(), DevError> {
        Err(DevError)
    }

    /// Nothing is ever written, so nothing is pending.
    fn flush(&mut self) -> Result<(), DevError> {
        Ok(())
    }
}

/// Building an image's tree in Rust: only the host tests do (the tool that
/// builds the real ones is `tools/image/mkazvol.py`, a second implementation of this
/// layout; the suite compares the two roots).
#[cfg(test)]
pub mod build {
    use super::*;
    use super::super::layout::{wr32, wr64};

    /// Header, then tree, for the `n`-block volume at the start of `image`
    /// (`n` blocks, then room for [`Shape::blocks_after`] more); returns the
    /// verity root.
    pub fn build_in(image: &mut [u8], n: u64) -> Hash {
        let s = Shape::new(n).expect("a volume this size has a tree");
        let bs = BLOCK_SIZE;
        assert!(image.len() as u64 >= (n + s.blocks_after()) * bs as u64);
        let mut below: Vec<Hash> = (0..n as usize).map(|i| sha256(&image[i * bs..(i + 1) * bs])).collect();
        let mut top = [0u8; HASH_LEN];
        for level in 0..s.levels {
            let mut hashes = Vec::new();
            for c in 0..s.count[level] as usize {
                let at = (s.start[level] as usize + c) * bs;
                let blk = &mut image[at..at + bs];
                blk.fill(0);
                for (k, h) in below.iter().skip(c * FANOUT as usize).take(FANOUT as usize).enumerate() {
                    blk[k * HASH_LEN..(k + 1) * HASH_LEN].copy_from_slice(h);
                }
                hashes.push(sha256(blk));
            }
            if level + 1 == s.levels {
                top = hashes[0];
            }
            below = hashes;
        }
        let at = n as usize * bs;
        let out = &mut image[at..at + bs];
        out.fill(0);
        out[..8].copy_from_slice(&HEADER_MAGIC);
        wr32(out, H_VERSION, VERSION);
        wr32(out, H_ALG, ALG_SHA256);
        wr64(out, H_BLOCKS, n);
        wr32(out, H_LEVELS, s.levels as u32);
        out[H_TOP..H_TOP + HASH_LEN].copy_from_slice(&top);
        sha256(out)
    }
}
