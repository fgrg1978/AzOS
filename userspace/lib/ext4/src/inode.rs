// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Inodes.

use crate::{csum, le16, le32, BlockSource, Corrupt, Error, Unread, Volume};

const S_IFMT: u16 = 0o170000;
const S_IFREG: u16 = 0o100000;
const S_IFDIR: u16 = 0o040000;
const S_IFLNK: u16 = 0o120000;

pub(crate) const FL_INDEX: u32 = 0x1000;
pub(crate) const FL_EXTENTS: u32 = 0x8_0000;
const FL_ENCRYPT: u32 = 0x800;
const FL_INLINE_DATA: u32 = 0x1000_0000;
const FL_CASEFOLD: u32 = 0x4000_0000;

const GOOD_OLD_SIZE: usize = 128;
const I_CHECKSUM_LO: usize = 0x7C;
const I_EXTRA_ISIZE: usize = 0x80;
const I_CHECKSUM_HI: usize = 0x82;
/// The largest inode [`Volume::inode`] reads (the superblock check bounds
/// `inode_size` by it).
const INODE_MAX: usize = 1024;

/// One inode, the fields read.
#[derive(Clone, Copy, Debug)]
pub struct Inode {
    pub ino: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub links: u16,
    pub flags: u32,
    pub atime: u32,
    pub mtime: u32,
    pub ctime: u32,
    /// `i_block`: the extent root, the block map, or a fast symlink's target.
    pub(crate) block: [u8; 60],
    /// The seed of the checksums of the blocks this inode owns.
    pub(crate) csum_seed: u32,
}

impl Inode {
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
    pub fn is_file(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }
    /// A symlink whose target is in the inode itself.
    pub(crate) fn fast_symlink(&self) -> bool {
        self.is_symlink() && self.size < 60 && self.flags & FL_EXTENTS == 0
    }
    pub(crate) fn inline_target(&self) -> &[u8] {
        &self.block[..(self.size as usize).min(60)]
    }
    /// Refuse data this parser cannot read.
    pub(crate) fn readable(&self) -> Result<(), Error> {
        if self.flags & FL_INLINE_DATA != 0 {
            return Err(Error::Unread(Unread::Inline));
        }
        if self.flags & FL_ENCRYPT != 0 {
            return Err(Error::Unread(Unread::Encrypted));
        }
        if self.flags & FL_CASEFOLD != 0 {
            return Err(Error::Unread(Unread::Casefold));
        }
        Ok(())
    }
}

impl<S: BlockSource> Volume<S> {
    /// Read inode `ino`, checking its checksum.
    pub fn inode(&mut self, ino: u32) -> Result<Inode, Error> {
        if ino == 0 || ino > self.sb.inodes_count {
            return Err(Corrupt::InodeRange.into());
        }
        let idx = ino - 1;
        let g = self.group(idx / self.sb.inodes_per_group)?;
        if g.inode_uninit() {
            return Err(Corrupt::InodeRange.into());
        }
        let isz = self.sb.inode_size as usize;
        let bs = self.sb.block_size as u64;
        let at = (idx % self.sb.inodes_per_group) as u64 * isz as u64;
        let mut raw = [0u8; INODE_MAX];
        let raw = &mut raw[..isz];
        self.read_blocks(g.inode_table + at / bs, (at % bs) as usize, raw)?;

        let generation = le32(raw, 0x64)?;
        let seed = if self.sb.features.metadata_csum() {
            let s = csum(self.sb.csum_seed, &ino.to_le_bytes());
            csum(s, &generation.to_le_bytes())
        } else {
            0
        };
        if self.sb.features.metadata_csum() && !cfg!(feature = "csum-skip-canary") {
            verify(raw, seed)?;
        }
        let mode = le16(raw, 0x00)?;
        let flags = le32(raw, 0x20)?;
        let size = le32(raw, 0x04)? as u64 | (le32(raw, 0x6C)? as u64) << 32;
        // A file's blocks are numbered by a u32: no size reaches past them.
        if size > (u32::MAX as u64 + 1) * bs {
            return Err(Corrupt::Size.into());
        }
        let mut block = [0u8; 60];
        block.copy_from_slice(raw.get(0x28..0x64).ok_or(Corrupt::Truncated)?);
        Ok(Inode {
            ino,
            mode,
            uid: le16(raw, 0x02)? as u32 | (le16(raw, 0x78)? as u32) << 16,
            gid: le16(raw, 0x18)? as u32 | (le16(raw, 0x7A)? as u32) << 16,
            size,
            links: le16(raw, 0x1A)?,
            flags,
            atime: le32(raw, 0x08)?,
            ctime: le32(raw, 0x0C)?,
            mtime: le32(raw, 0x10)?,
            block,
            csum_seed: seed,
        })
    }
}

/// Check an inode's checksum: the whole inode with its checksum fields zeroed,
/// 32 bits when the large inode holds the high half, else the low 16.
fn verify(raw: &mut [u8], seed: u32) -> Result<(), Corrupt> {
    let lo = le16(raw, I_CHECKSUM_LO)? as u32;
    let mut stored = lo;
    let mut wide = false;
    if raw.len() > GOOD_OLD_SIZE {
        let extra = le16(raw, I_EXTRA_ISIZE)? as usize;
        if GOOD_OLD_SIZE + extra > raw.len() {
            return Err(Corrupt::Truncated);
        }
        if I_CHECKSUM_HI + 2 <= GOOD_OLD_SIZE + extra {
            stored |= (le16(raw, I_CHECKSUM_HI)? as u32) << 16;
            raw[I_CHECKSUM_HI..I_CHECKSUM_HI + 2].fill(0);
            wide = true;
        }
    }
    raw[I_CHECKSUM_LO..I_CHECKSUM_LO + 2].fill(0);
    let c = csum(seed, raw);
    let c = if wide { c } else { c & 0xFFFF };
    if c != stored {
        return Err(Corrupt::Checksum);
    }
    Ok(())
}
