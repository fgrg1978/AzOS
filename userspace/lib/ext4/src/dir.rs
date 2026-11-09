// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Directories and paths.

use crate::inode::FL_INDEX;
use crate::{csum, le16, le32, BlockSource, Corrupt, Error, Inode, Volume, NAME_MAX, PATH_MAX, ROOT_INO, SYMLINKS_MAX};

/// The checksum tail of a directory leaf: a fake entry of 12 bytes.
const TAIL: usize = 12;
const TAIL_FT: u8 = 0xDE;
/// `EXT4_DIR_REC_LEN(1)`: the smallest entry.
const REC_MIN: usize = 12;
/// Directories nested deeper than this are refused by [`Volume::resolve`]
/// (it keeps the ancestors to walk `..` without trusting the volume's).
const DEPTH_MAX: usize = 64;

/// One directory entry.
#[derive(Clone, Copy)]
pub struct DirEntry {
    pub ino: u32,
    pub name: [u8; NAME_MAX],
    pub name_len: u8,
    /// The entry's type byte (`filetype` feature), 0 without it.
    pub file_type: u8,
}

impl DirEntry {
    pub const fn new() -> Self {
        DirEntry { ino: 0, name: [0; NAME_MAX], name_len: 0, file_type: 0 }
    }
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

impl Default for DirEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Is this a name an entry may carry (one component, not `.` or `..`)?
fn plain_name(n: &[u8]) -> Result<(), Error> {
    if n.len() > NAME_MAX {
        return Err(Error::NameTooLong);
    }
    if n.is_empty() || n == b"." || n == b".." || n.iter().any(|&c| c == b'/' || c == 0) {
        return Err(Error::BadName);
    }
    Ok(())
}

impl<S: BlockSource> Volume<S> {
    /// Load directory `dir`'s logical block `lblk` into the block buffer and
    /// check it: the span its entries may use, or `None` for a block that
    /// holds no entries (a hole, an htree index block).
    fn dir_block(&mut self, dir: &Inode, lblk: u32) -> Result<Option<usize>, Error> {
        let bs = self.sb.block_size as usize;
        let run = self.map(dir, lblk)?;
        let Some(p) = run.start else { return Ok(None) };
        self.load_block(p)?;
        let b = &self.blk[..bs];
        // An htree root (block 0 of an indexed directory) holds `.`, `..`
        // and the index; an index node is one empty entry that spans the
        // block. Neither names a file.
        let first_ino = le32(b, 0)?;
        let first_rec = le16(b, 4)? as usize;
        if (dir.flags & FL_INDEX != 0 && lblk == 0) || (first_ino == 0 && first_rec == bs) {
            return Ok(None);
        }
        if !self.sb.features.metadata_csum() {
            return Ok(Some(bs));
        }
        let t = bs - TAIL;
        if le32(b, t)? != 0 || le16(b, t + 4)? as usize != TAIL || b[t + 6] != 0 || b[t + 7] != TAIL_FT {
            return Err(Corrupt::Checksum.into());
        }
        if csum(dir.csum_seed, &b[..t]) != le32(b, t + 8)? {
            return Err(Corrupt::Checksum.into());
        }
        Ok(Some(t))
    }

    /// The entry at byte `at` of the loaded block, within `span`: the entry
    /// and its record length.
    fn entry_at(&self, at: usize, span: usize, out: &mut DirEntry) -> Result<usize, Error> {
        let b = &self.blk[..span];
        let ino = le32(b, at)?;
        let rec = le16(b, at + 4)? as usize;
        let (nlen, ft) = if self.sb.features.filetype() {
            (b.get(at + 6).copied().ok_or(Corrupt::DirEntry)? as usize, b.get(at + 7).copied().unwrap_or(0))
        } else {
            (le16(b, at + 6)? as usize, 0)
        };
        if rec < REC_MIN || rec % 4 != 0 || at + rec > span || 8 + nlen > rec || (nlen > NAME_MAX && !cfg!(feature = "dirent-bound-canary")) {
            return Err(Corrupt::DirEntry.into());
        }
        if ino > self.sb.inodes_count {
            return Err(Corrupt::InodeRange.into());
        }
        let name = &b[at + 8..at + 8 + nlen];
        // A live entry names one component: never empty, no `/`, no NUL
        // (Linux's `verify_dirent_name`). A deleted one's bytes are not read.
        if ino != 0 && (nlen == 0 || name.iter().any(|&c| c == b'/' || c == 0)) && !cfg!(feature = "dirent-name-canary") {
            return Err(Corrupt::DirEntry.into());
        }
        out.ino = ino;
        out.name_len = nlen as u8;
        out.name[..nlen].copy_from_slice(name);
        out.file_type = ft;
        Ok(rec)
    }

    /// The first live entry of `dir` at or after byte position `pos`, other
    /// than `.` and `..`, into `out`: the position after it, or `None` past
    /// the last entry.
    pub fn readdir(&mut self, dir: &Inode, mut pos: u64, out: &mut DirEntry) -> Result<Option<u64>, Error> {
        if !dir.is_dir() {
            return Err(Error::NotDir);
        }
        dir.readable()?;
        let bs = self.sb.block_size as u64;
        // Holes are allowed; a directory larger than the volume is not, and
        // bounds the walk.
        if dir.size > self.sb.blocks_count.saturating_mul(bs) {
            return Err(Corrupt::Size.into());
        }
        while pos < dir.size {
            let lblk = u32::try_from(pos / bs).map_err(|_| Corrupt::Size)?;
            let base = lblk as u64 * bs;
            let Some(span) = self.dir_block(dir, lblk)? else {
                pos = base + bs;
                continue;
            };
            // A position inside a block that is not an entry's start (a
            // stale cookie) restarts at the block's first entry it passes.
            let mut at = 0usize;
            let want = (pos - base) as usize;
            while at < span {
                let rec = self.entry_at(at, span, out)?;
                let next = at + rec;
                if at >= want && out.ino != 0 && out.name() != b"." && out.name() != b".." {
                    return Ok(Some(base + next as u64));
                }
                at = next;
            }
            pos = base + bs;
        }
        Ok(None)
    }

    /// The inode number `name` names in `dir`, or `NotFound`.
    pub fn lookup(&mut self, dir: &Inode, name: &[u8]) -> Result<u32, Error> {
        plain_name(name)?;
        let mut e = DirEntry::new();
        let mut pos = 0u64;
        while let Some(next) = self.readdir(dir, pos, &mut e)? {
            if e.name() == name {
                return Ok(e.ino);
            }
            pos = next;
        }
        Err(Error::NotFound)
    }

    /// The inode `path` names, relative to the volume's root (a leading `/`
    /// is the root too). Symlinks are followed beneath the root: an absolute
    /// target starts again at the root, and `..` never climbs above it. The
    /// last component's symlink is followed only with `follow_last`.
    pub fn resolve(&mut self, path: &[u8], follow_last: bool) -> Result<Inode, Error> {
        self.resolve_in(ROOT_INO, false, path, follow_last)
    }

    /// [`Volume::resolve`] beneath the directory `base`, which is where the
    /// path starts and, for a `strict` resolution, where it ends: a `..` at
    /// `base` and a symlink with an absolute target are [`Error::Escape`], as
    /// `openat2`'s `RESOLVE_BENEATH` refuses them. Not strict, `base` is the
    /// volume's root and both are what `resolve` does.
    pub fn resolve_beneath(&mut self, base: &Inode, path: &[u8], follow_last: bool) -> Result<Inode, Error> {
        if !base.is_dir() {
            return Err(Error::NotDir);
        }
        self.resolve_in(base.ino, !cfg!(feature = "escape-canary"), path, follow_last)
    }

    fn resolve_in(&mut self, base: u32, strict: bool, path: &[u8], follow_last: bool) -> Result<Inode, Error> {
        let mut work = [0u8; PATH_MAX];
        if path.len() > PATH_MAX {
            return Err(Error::NameTooLong);
        }
        work[..path.len()].copy_from_slice(path);
        let mut wlen = path.len();
        let mut at = 0usize;
        let mut stack = [base; DEPTH_MAX];
        let mut depth = 0usize;
        let mut cur = self.inode(base)?;
        let mut links = 0u32;
        loop {
            while at < wlen && work[at] == b'/' {
                at += 1;
            }
            if at >= wlen {
                return Ok(cur);
            }
            let end = work[at..wlen].iter().position(|&c| c == b'/').map_or(wlen, |p| at + p);
            let last = work[end..wlen].iter().all(|&c| c == b'/');
            let mut comp = [0u8; NAME_MAX];
            let clen = end - at;
            if clen > NAME_MAX {
                return Err(Error::NameTooLong);
            }
            comp[..clen].copy_from_slice(&work[at..end]);
            let comp = &comp[..clen];
            at = end;
            if !cur.is_dir() {
                return Err(Error::NotDir);
            }
            if comp == b"." {
                continue;
            }
            if comp == b".." {
                if strict && depth == 0 {
                    return Err(Error::Escape);
                }
                depth = depth.saturating_sub(1);
                cur = self.inode(stack[depth])?;
                continue;
            }
            let ino = self.lookup(&cur, comp)?;
            let next = self.inode(ino)?;
            if next.is_symlink() && (!last || follow_last) {
                links += 1;
                if links > SYMLINKS_MAX {
                    return Err(Error::Loop);
                }
                let mut target = [0u8; PATH_MAX];
                let tlen = self.readlink(&next, &mut target)?;
                if tlen == 0 {
                    return Err(Error::NotFound);
                }
                // The new work: the target, then what is left of the path.
                let rest = wlen - at;
                if tlen + rest > PATH_MAX {
                    return Err(Error::NameTooLong);
                }
                let mut nw = [0u8; PATH_MAX];
                nw[..tlen].copy_from_slice(&target[..tlen]);
                nw[tlen..tlen + rest].copy_from_slice(&work[at..wlen]);
                work = nw;
                wlen = tlen + rest;
                at = 0;
                if target[0] == b'/' {
                    if strict {
                        return Err(Error::Escape);
                    }
                    depth = 0;
                    cur = self.inode(base)?;
                }
                continue;
            }
            if next.is_dir() {
                depth += 1;
                if depth >= DEPTH_MAX {
                    return Err(Error::NameTooLong);
                }
                stack[depth] = ino;
            }
            cur = next;
        }
    }
}
