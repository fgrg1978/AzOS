// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A read-only ext4 parser.
//!
//! [`Volume::mount`] reads the superblock and every group descriptor of a
//! partition through a [`BlockSource`] and refuses, with a typed
//! [`MountError`], anything it cannot read correctly: an incompatible feature
//! it does not parse, a journal that needs recovery, a geometry that does not
//! add up, a checksum that does not match. Once mounted, the volume names
//! files by path ([`Volume::resolve`]), reads them ([`Volume::read`]), lists
//! directories ([`Volume::readdir`]) and reads symlinks
//! ([`Volume::readlink`]).
//!
//! # Hostile images
//!
//! The image is untrusted: every on-disk number is checked before it
//! addresses anything (a block inside the volume, an entry inside its block,
//! a depth inside its bound), and every loop is bounded by the volume's own
//! geometry or a constant. A damaged structure is an [`Error::Corrupt`],
//! never a panic; `tests/host/ext4-tests` flips bytes of real images and holds
//! the parser to that.
//!
//! # What is read
//!
//! * Block sizes 1, 2 and 4 KiB; inodes of 128 to 1024 bytes.
//! * Files mapped by extents (depth at most 5) or by the legacy block map
//!   (direct, single, double and triple indirect); holes and unwritten
//!   extents read as zeros.
//! * Directories walked linearly: an htree directory's index blocks hold no
//!   names, so its leaves are read as a linear directory's are.
//! * Fast symlinks (the target in the inode) and slow ones (in a block),
//!   followed by [`Volume::resolve`] beneath the volume's root.
//! * With `metadata_csum`, the checksums of the superblock, every group
//!   descriptor, every inode read, every extent block and every directory
//!   leaf are verified; a mismatch is [`Corrupt::Checksum`].
//!
//! The journal is not replayed: a volume that needs recovery is refused
//! ([`MountError::NeedsRecovery`]); a clean one is read as it stands.
#![no_std]
#![forbid(unsafe_code)]

mod dir;
mod inode;
mod map;
mod sb;

pub use dir::DirEntry;
pub use inode::Inode;
pub use sb::{Features, Super};

/// Largest block size read.
pub const MAX_BLOCK: usize = 4096;
/// Longest name an entry carries.
pub const NAME_MAX: usize = 255;
/// Longest path [`Volume::resolve`] takes, symlink targets spliced in.
pub const PATH_MAX: usize = 1024;
/// Symlinks one resolution follows at most.
pub const SYMLINKS_MAX: u32 = 8;
/// The root directory's inode.
pub const ROOT_INO: u32 = 2;

/// A failed read of the medium.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoError;

/// The partition, read by byte offset.
pub trait BlockSource {
    /// Fill `buf` from byte `off` of the partition: metadata (the superblock,
    /// descriptors, inodes, directory, extent and indirect blocks).
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), IoError>;
    /// The same for a file's contents, which a source that caches metadata
    /// need not keep (the reader of the file has its own cache).
    fn read_data(&mut self, off: u64, buf: &mut [u8]) -> Result<(), IoError> {
        self.read_at(off, buf)
    }
    /// The partition's length in bytes.
    fn len(&self) -> u64;
}

/// Why a volume was not mounted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountError {
    Io,
    /// No ext2/3/4 superblock magic.
    BadMagic,
    /// A block size other than 1, 2 or 4 KiB (the log₂ given, minus 10).
    BlockSize(u32),
    /// An inode size outside 128..=1024, not a power of two, or larger than
    /// a block.
    InodeSize(u32),
    /// A group descriptor size the feature set does not allow.
    DescSize(u32),
    /// Counts that do not add up (blocks, groups, inodes, the descriptor
    /// table, the volume against its partition).
    Geometry,
    /// Incompatible features this parser does not read: the bits.
    Incompat(u32),
    /// Read-only compatible features that change how blocks are addressed
    /// (bigalloc): the bits.
    RoCompat(u32),
    /// The journal holds transactions that were never checkpointed.
    NeedsRecovery,
    /// `metadata_csum` with a checksum type other than crc32c.
    ChecksumType(u8),
    /// The superblock's own checksum.
    SuperChecksum,
    /// Group `n`'s descriptor: its checksum, or an inode table outside the
    /// volume.
    Group(u32),
    /// The root inode is not a readable directory.
    Root,
}

/// What made a read refuse a structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Corrupt {
    /// A checksum (inode, extent block, directory block) does not match.
    Checksum,
    /// A block number outside the volume.
    BlockRange,
    /// An inode number outside the volume, or in a group with no inode table.
    InodeRange,
    /// An extent header or entry out of shape.
    Extent,
    /// A directory entry out of shape.
    DirEntry,
    /// A size the volume cannot hold.
    Size,
    /// A field that does not fit where it says it is.
    Truncated,
}

/// What an inode carries that this parser does not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unread {
    /// Data inline in the inode (`inline_data`).
    Inline,
    /// Encrypted contents or names.
    Encrypted,
    /// Case-folded names.
    Casefold,
}

/// Why an operation on a mounted volume failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Io,
    NotFound,
    NotDir,
    /// A symlink where a directory or file was asked for, followed too often.
    Loop,
    NameTooLong,
    /// A name with `/`, NUL, or one that is `.`/`..` where a name is asked.
    BadName,
    /// Not a regular file or symlink where its data was asked for.
    NotFile,
    /// A `..` or an absolute symlink target that leaves the directory a path is
    /// resolved beneath.
    Escape,
    /// The work one call may do ([`Volume::begin_call`]) is spent.
    Busy,
    Corrupt(Corrupt),
    Unread(Unread),
}

impl From<IoError> for Error {
    fn from(_: IoError) -> Self {
        Error::Io
    }
}

impl From<Corrupt> for Error {
    fn from(c: Corrupt) -> Self {
        Error::Corrupt(c)
    }
}

pub(crate) fn le16(b: &[u8], off: usize) -> Result<u16, Corrupt> {
    let s = b.get(off..off.checked_add(2).ok_or(Corrupt::Truncated)?).ok_or(Corrupt::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

pub(crate) fn le32(b: &[u8], off: usize) -> Result<u32, Corrupt> {
    let s = b.get(off..off.checked_add(4).ok_or(Corrupt::Truncated)?).ok_or(Corrupt::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// ext4's checksum: CRC-32C from `seed` with no final inversion, so that
/// `csum(csum(s, a), b) == csum(s, a ‖ b)`.
pub(crate) fn csum(seed: u32, data: &[u8]) -> u32 {
    !azos_common::crc32c::crc32c_update(!seed, data)
}

/// Read `buf.len()` bytes at byte `off` of the run that starts at block
/// `pblk`, checking that the run lies inside the volume.
pub(crate) fn read_run<S: BlockSource>(
    src: &mut S,
    sb: &Super,
    pblk: u64,
    off: usize,
    buf: &mut [u8],
    data: bool,
) -> Result<(), Error> {
    let bs = sb.block_size as u64;
    let end = (off as u64).checked_add(buf.len() as u64).ok_or(Corrupt::BlockRange)?;
    let blocks = end.div_ceil(bs);
    if pblk.checked_add(blocks).is_none_or(|e| e > sb.blocks_count) {
        return Err(Corrupt::BlockRange.into());
    }
    let at = pblk.checked_mul(bs).and_then(|b| b.checked_add(off as u64)).ok_or(Corrupt::BlockRange)?;
    if data {
        src.read_data(at, buf)?;
    } else {
        src.read_at(at, buf)?;
    }
    Ok(())
}

/// A mounted volume.
pub struct Volume<S: BlockSource> {
    src: S,
    sb: Super,
    /// One block: a directory block, an extent node, an indirect block.
    blk: [u8; MAX_BLOCK],
    /// Directory steps taken so far: one per block walked or hole skipped.
    work: u64,
    /// `work` at which the current call's allowance ends; none when unmetered.
    limit: Option<u64>,
}

impl<S: BlockSource> Volume<S> {
    /// Read and check the superblock and the group descriptors.
    pub fn mount(mut src: S) -> Result<Self, MountError> {
        let sb = Super::read(&mut src)?;
        let mut v = Volume { src, sb, blk: [0; MAX_BLOCK], work: 0, limit: None };
        v.check_groups()?;
        match v.inode(ROOT_INO) {
            Ok(root) if root.is_dir() => Ok(v),
            _ => Err(MountError::Root),
        }
    }

    /// Allow the directory walks that follow `steps` steps before they refuse
    /// with [`Error::Busy`]: a server calls it at the start of each request so
    /// one crafted directory cannot hold it. Never called, the volume is unmetered.
    pub fn begin_call(&mut self, steps: u32) {
        self.limit = Some(self.work + steps as u64);
    }

    /// Directory steps taken since the mount.
    pub fn work(&self) -> u64 {
        self.work
    }

    pub(crate) fn step(&mut self) -> Result<(), Error> {
        self.work += 1;
        match self.limit {
            Some(l) if self.work > l => Err(Error::Busy),
            _ => Ok(()),
        }
    }

    /// The superblock as read.
    pub fn info(&self) -> &Super {
        &self.sb
    }

    /// The block source back.
    pub fn into_source(self) -> S {
        self.src
    }

    /// Read `buf.len()` bytes at byte `off` of block `pblk`'s run.
    pub(crate) fn read_blocks(&mut self, pblk: u64, off: usize, buf: &mut [u8]) -> Result<(), Error> {
        read_run(&mut self.src, &self.sb, pblk, off, buf, false)
    }

    /// Read block `pblk` whole into the volume's block buffer.
    pub(crate) fn load_block(&mut self, pblk: u64) -> Result<(), Error> {
        let bs = self.sb.block_size as usize;
        read_run(&mut self.src, &self.sb, pblk, 0, &mut self.blk[..bs], false)
    }

    /// Bytes of the file `ino` from `off` into `dst`: the count, short only
    /// at the end of the file. A hole, or an unwritten extent, reads zeros.
    pub fn read(&mut self, ino: &Inode, off: u64, dst: &mut [u8]) -> Result<usize, Error> {
        if !(ino.is_file() || ino.is_symlink()) {
            return Err(Error::NotFile);
        }
        ino.readable()?;
        if ino.is_symlink() && ino.fast_symlink() {
            let t = ino.inline_target();
            let from = (off.min(t.len() as u64)) as usize;
            let n = dst.len().min(t.len() - from);
            dst[..n].copy_from_slice(&t[from..from + n]);
            return Ok(n);
        }
        let size = ino.size;
        if off >= size {
            return Ok(0);
        }
        let want = (size - off).min(dst.len() as u64) as usize;
        let bs = self.sb.block_size as u64;
        let mut done = 0usize;
        while done < want {
            let pos = off + done as u64;
            let lblk = u32::try_from(pos / bs).map_err(|_| Corrupt::Size)?;
            let inblk = (pos % bs) as usize;
            let run = self.map(ino, lblk)?;
            let run_bytes = (run.len as u64).saturating_mul(bs) - inblk as u64;
            let n = run_bytes.min((want - done) as u64) as usize;
            let out = &mut dst[done..done + n];
            match run.start {
                Some(p) => read_run(&mut self.src, &self.sb, p, inblk, out, true)?,
                None => out.fill(0),
            }
            done += n;
        }
        Ok(done)
    }

    /// A symlink's target into `out`: its length (`NameTooLong` when `out`
    /// is shorter).
    pub fn readlink(&mut self, ino: &Inode, out: &mut [u8]) -> Result<usize, Error> {
        if !ino.is_symlink() {
            return Err(Error::NotFile);
        }
        let len = usize::try_from(ino.size).map_err(|_| Error::NameTooLong)?;
        if len > out.len() || len > PATH_MAX {
            return Err(Error::NameTooLong);
        }
        let n = self.read(ino, 0, &mut out[..len])?;
        if n != len {
            return Err(Corrupt::Size.into());
        }
        Ok(n)
    }
}
