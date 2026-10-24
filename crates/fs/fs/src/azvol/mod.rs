// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! azvol: AzOS's own volume format (L15).
//!
//! Self-contained: `core` and `alloc` only, a [`BlockDev`] trait for the
//! medium, no global state, so the same source runs in the kernel, in the
//! host test suite (`tests/host/fs-tests/src/azvol_format.rs`) and is
//! mirrored by `tools/image/mkazvol.py`, which builds plain (unsealed) images. This
//! module is the format and its host-testable read/write engine, with
//! snapshots ([`snap`]), change groups ([`group`]) and per-block
//! ChaCha20-Poly1305 at rest ([`seal`]). The kernel mounts it into the VFS in
//! `kernel/src/boot/azvol.rs`.
//!
//! # Layout (4096-byte blocks, all fields little-endian)
//!
//! ```text
//!   block 0, 64      superblock copies A and B (see below)
//!   1..127           reserved (zero)
//!   128..            free-space bitmap   bitmap_blocks   one bit per volume block
//!                    checksum table      csum_blocks     one crc32c per volume block
//!   data_start..     everything else: file data, directory blocks, tree nodes,
//!                    the inode table's data
//! ```
//!
//! Static region sizes follow from the block count alone
//! ([`layout::Geometry`]); the superblock repeats them and a mount refuses
//! a superblock that disagrees.
//!
//! **Superblock** (`layout::sbo` has every offset): magic `AZVOLUME`,
//! version, block size (log2), a crc32c over the whole block, incompat
//! feature bits (refused if non-zero), the commit **generation**, volume
//! size, uuid, label, the free-inode list head, the inode-table slot count,
//! the live-block count, the key slot (algorithm id, key id, wrapped key,
//! all zero = unsealed; see [`seal`]) and
//! the inode table's own inode record, and the records of the snapshot table
//! and the dead list (zeros, and the incompat bit clear, while there is no
//! snapshot). Two copies; a commit with generation `g` writes copy `g & 1`;
//! mount takes the valid copy with the highest generation.
//!
//! **Checksums.** Every block of the data area has a crc32c in the
//! checksum table, indexed by block number: file data and tree nodes alike.
//! A read verifies the block it got against the table entry, and a mismatch
//! is an error, never silently wrong data. The table is a side table rather
//! than a per-block trailer so that a data block keeps all 4096 bytes
//! (page-aligned, mappable, direct-I/O friendly), and it is safe to update
//! in place: only the entries of blocks that no committed tree names change
//! during a transaction. A sealed volume ([`seal`]) keeps a tag and a write
//! sequence number there instead (24 bytes a block, so a bigger table) and a
//! block that fails its tag is an error just the same.
//!
//! **Inodes.** The inode table is a file (its record is in the superblock),
//! 256 bytes per inode: size, times, the generation of the last change,
//! kind, mode, and an extent root. Slot 0 is reserved, inode 1 is the root
//! directory, a freed slot joins a list threaded through the table.
//!
//! **Extents.** A file is a sorted list of extents
//! `{file_blk, disk_blk, nblocks, flags, gen}`. Up to six sit in the inode
//! record; more go to tree nodes (leaf nodes of 127 extents, index nodes of
//! 127 `{key, child, child_gen}`, depth up to three above the leaves). A
//! node names its own block, its owner inode and its generation, so a
//! misdirected or stale node is refused. A hole is no extent. A directory
//! is a file of name records ([`dir`]).
//!
//! **Copy on write.** A committed block is never overwritten; see
//! [`volume`] for the commit order and what a power cut leaves behind.
//! Because the previous tree stays whole until the new superblock is
//! durable, keeping it longer is a snapshot ([`snap`]: which blocks it holds
//! follows from the generations on the extents), and a set of operations
//! can be made to share one commit ([`group`]).
//!
//! **Verity.** A read-only volume can be served over a SHA-256 hash tree kept
//! after it on the same partition ([`verity`]): the topology row's
//! `verity_root` is the trust anchor and every block the engine reads is
//! checked against it. The volume format itself does not change.
//!
//! Limits of this revision, all in the engine and none in the format:
//! the whole free-space map and an inode's whole extent list are held in
//! memory; a commit rewrites the extent tree of an inode it changed rather
//! than updating nodes incrementally; directories are scanned linearly.

pub mod check;
pub mod engine;
pub mod crc32c;
pub mod dev;
pub mod dir;
pub mod extent;
pub mod freemap;
pub mod group;
pub mod layout;
pub mod seal;
pub mod snap;
pub mod verity;
pub mod volume;

pub use check::{CheckReport, Problem};
pub use dev::{BlockDev, DevError};
pub use layout::{Kind, BLOCK_SIZE};
pub use seal::VolumeKey;
pub use snap::{SnapInfo, SnapView};
pub use volume::{DirEntry, FormatOptions, MountReport, Stat, StatFs, Volume};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The device failed a read, write or flush.
    Io,
    /// Neither superblock copy carries the azvol magic.
    BadMagic,
    /// A copy has the magic but no copy checks out.
    NoSuperblock,
    /// A feature or version this implementation does not have.
    Unsupported(&'static str),
    /// A structure fails validation; the string says which.
    Corrupt(&'static str),
    /// The block fails its checksum (the block number).
    Checksum(u64),
    /// A sealed block fails its AEAD tag (the block number): it was changed,
    /// moved, or sealed under another key. Its content is never returned.
    Auth(u64),
    /// The volume is sealed and no key was given (see [`Volume::mount_sealed`]).
    KeyRequired,
    /// The key does not match the one the volume was formatted with.
    WrongKey,
    /// A sealed write would repeat a nonce: 2^28 block writes in one
    /// transaction, or generation 2^36. Commit (or reformat) and go on.
    NonceExhausted,
    NoSpace,
    NotFound,
    Exists,
    NotDir,
    IsDir,
    NotEmpty,
    NameInvalid,
    TooBig,
    /// The device or requested size is too small for a volume.
    TooSmall,
    /// An earlier commit failed; remount.
    Poisoned,
    /// A change group is open: plain commit, check and snapshot create and
    /// delete wait for `commit_group` or `abort_group`, and a second group
    /// cannot start.
    GroupOpen,
    /// `commit_group` or `abort_group` without a group.
    NoGroup,
    /// No retained generation has that id (never created, or deleted).
    NoSnapshot,
    /// The change is a delete the caller's envelope row does not allow
    /// ([`Volume::set_delete_gate`]); nothing was changed.
    Denied,
}

/// Asked before a delete the engine itself takes (today: dropping a snapshot)
/// with the op and the volume's id (the first eight bytes of its uuid):
/// `true` to go ahead. The engine keeps no global state, so the mount hands
/// each volume the gate it uses (`azos_fs::delete_admitted`).
pub type DeleteGate = fn(op: azos_common::envelope::DeleteOp, volume: u64) -> bool;
