// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The file protocol: [`Node`] (an open file) and [`Dir`] (a directory).
//!
//! **One op table, two forms.** The kernel serves these ops itself, as the
//! `SYS_INVOKE` ops of a `Cap<File>` and of a `Cap<Dir>`
//! (`azos_abi::invoke::NODE_*`): the words in registers, names and data at
//! addresses of the caller's own memory. A file system served from ring 3
//! answers the same interface on an endpoint, with names and data in a region
//! it shares with its client ([`Extent`]: an offset and a length in that
//! region, never an address); a mount it serves is reached through the
//! kernel's form (the VFS forwards to the endpoint), so a client of the mount
//! cannot tell which one serves it. Every method names its op number with `#[op = ..]` as the kernel's
//! constant: there is no second numbering, and `tests/host/syscall-tests`
//! (`fs_protocol.rs`) checks that the kernel dispatches exactly the ops of
//! these two tables on a file handle, besides the socket ops (their own
//! protocol) and the mapping of a file (`NODE_MMAP`: a ring-3 file system
//! would lend the pages as a memory object, which the page cache must agree
//! to first).
//!
//! Every name is relative to the directory and stays beneath it
//! (`RESOLVE_BENEATH`): an absolute name, a `..` above the directory, or an
//! entry to change whose last component is `.` or `..`, is
//! [`outcome::BAD_ARGUMENT`].
//!
//! # Authority
//!
//! On the kernel's form `READ` on the directory names beneath it, and an op
//! that changes the tree also needs a held write tree that covers the entry
//! and whose caveats admit the op (`azos_abi::invoke`); a ring-3 mount's
//! clients are checked there, before the server is asked. A server reached
//! directly on its endpoint takes the endpoint's rights as that authority:
//! `READ` to name, `WRITE` to change the tree.
//!
//! # Outcomes
//!
//! The codes of [`outcome`] and the file codes below; the kernel's fast form
//! answers the same refusal as the `Errno` [`ERRNO_CODES`] pairs with it, one
//! to one.
//!
//! # Reads: all, or the end
//!
//! A read moves `min(len, READ_MAX)` bytes unless the file ends first, and
//! then says so ([`ReadDone::end`]). A short read that does not say so is a
//! server out of contract: the client refuses it ([`read_checked`],
//! [`SHORT_READ`]), so a truncated file is never taken for the whole one.

use crate::outcome::{self, Out};
use azos_abi::error::Errno;
use azos_abi::invoke::{
    NODE_FSYNC, NODE_MKDIRAT, NODE_OPENAT, NODE_READ, NODE_READDIR, NODE_RENAMEAT, NODE_SEEK, NODE_STATAT,
    NODE_STATFS, NODE_TRUNCATEAT, NODE_UNLINKAT, NODE_WRITE,
};
use azos_idl::{azos_interface, Lent, Reader, Wire, Writer};

/// The interface id of [`Node`] (ASCII "NODE").
pub const NODE_ID: u32 = 0x4E4F_4445;
/// The interface id of [`Dir`] (ASCII "DIR ").
pub const DIR_ID: u32 = 0x4449_5220;

/// The badge of the kernel's capability on a ring-3 file server: the one
/// caller the server answers as its root [`Dir`] (the kernel's VFS, which
/// checks its own clients' authority first). An open file's badge is never
/// this one.
pub const DIR_BADGE: u32 = 1;

/// Bytes one read or write moves at most: the kernel's clamp
/// (`azos_abi::syscall_nr::IO_MAX_BYTES`).
pub const READ_MAX: u32 = azos_abi::syscall_nr::IO_MAX_BYTES as u32;

/// No such entry.
pub const NOT_FOUND: u32 = 16;
/// The entry exists.
pub const EXISTS: u32 = 17;
/// The directory is not empty.
pub const NOT_EMPTY: u32 = 18;
/// The entry is a directory.
pub const IS_DIR: u32 = 19;
/// A component of the name is not a directory.
pub const NOT_DIR: u32 = 20;
/// The volume is full.
pub const NO_SPACE: u32 = 21;
/// The volume is served read-only.
pub const READ_ONLY: u32 = 22;
/// The name does not fit.
pub const NAME_TOO_LONG: u32 = 23;
/// Client side only, never on the wire: the server answered a read that is
/// shorter than asked without saying the file ended, or longer than asked.
pub const SHORT_READ: u32 = 24;

/// Each code of the protocol and the `Errno` the kernel's fast form answers
/// for it: one row per code, one per errno.
pub const ERRNO_CODES: [(u32, Errno); 15] = [
    (outcome::DENIED, Errno::EACCES),
    (outcome::BAD_ARGUMENT, Errno::EINVAL),
    (outcome::NOT_READY, Errno::EAGAIN),
    (outcome::FAULT, Errno::EIO),
    (outcome::UNSUPPORTED, Errno::ENOSYS),
    (outcome::BUSY, Errno::EBUSY),
    (outcome::NO_RESOURCE, Errno::ENODEV),
    (NOT_FOUND, Errno::ENOENT),
    (EXISTS, Errno::EEXIST),
    (NOT_EMPTY, Errno::ENOTEMPTY),
    (IS_DIR, Errno::EISDIR),
    (NOT_DIR, Errno::ENOTDIR),
    (NO_SPACE, Errno::ENOSPC),
    (READ_ONLY, Errno::EROFS),
    (NAME_TOO_LONG, Errno::ENAMETOOLONG),
];

/// The code the protocol answers for the kernel's `e` ([`outcome::FAULT`]
/// for an errno no file op answers).
pub fn code_of(e: Errno) -> u32 {
    ERRNO_CODES.iter().find(|r| r.1 == e).map_or(outcome::FAULT, |r| r.0)
}

/// The `Errno` the kernel's fast form answers for `code`; `None` for a code
/// that is not a refusal of this protocol.
pub fn errno_of(code: u32) -> Option<Errno> {
    ERRNO_CODES.iter().find(|r| r.0 == code).map(|r| r.1)
}

/// A run of bytes in the region a server shares with its client: a name
/// (NUL-terminated within `len`), data, or a record the op writes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Extent {
    pub off: u64,
    pub len: u32,
}

impl Wire for Extent {
    const WORDS: usize = 2;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.off.put(w);
        self.len.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let off = u64::get(r);
        Extent { off, len: u32::get(r) }
    }
}

/// What a read moved: `count` bytes, and whether the file ended within the
/// read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadDone {
    pub count: u32,
    pub end: bool,
}

impl Wire for ReadDone {
    const WORDS: usize = 2;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.count.put(w);
        self.end.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let count = u32::get(r);
        ReadDone { count, end: bool::get(r) }
    }
}

/// A read of `buf` through any placement of [`Node`], checked against its
/// request: the count, or the code of the refusal ([`outcome::NO_SERVER`]
/// when no server answered; [`SHORT_READ`] for an answer out of contract:
/// more than asked, or fewer than `min(len, READ_MAX)` without the end of
/// the file).
pub fn read_checked<C: NodeCall>(node: &mut C, buf: Extent) -> Result<u32, u32> {
    let d = outcome::served(node.read(buf))?;
    if d.count > buf.len || (d.count < buf.len.min(READ_MAX) && !d.end) {
        return Err(SHORT_READ);
    }
    Ok(d.count)
}

/// One entry of a directory, as [`Dir::readdir`] answers it (its name is in
/// the region); `present` is false past the last entry, `cut` true when the
/// name did not fit `out` (what is there is a prefix, not the name).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    pub present: bool,
    pub size: u32,
    pub is_dir: bool,
    pub cut: bool,
}

impl Wire for Entry {
    const WORDS: usize = 4;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.present.put(w);
        self.size.put(w);
        self.is_dir.put(w);
        self.cut.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let present = bool::get(r);
        let size = u32::get(r);
        let is_dir = bool::get(r);
        Entry { present, size, is_dir, cut: bool::get(r) }
    }
}

/// What an opened file's capability names (a marker, never constructed).
pub struct OpenNode;

#[azos_interface(id = 0x4E4F_4445, level = 1)]
pub trait Node {
    /// Read from the file's offset into `buf`, at most `READ_MAX` bytes; the
    /// offset moves by the count. Needs `READ`.
    #[op = NODE_READ]
    #[at_most_once]
    fn read(&mut self, buf: Extent) -> Out<ReadDone>;
    /// Write `buf` at the file's offset; the bytes written. Needs `WRITE`.
    #[op = NODE_WRITE]
    #[at_most_once]
    fn write(&mut self, buf: Extent) -> Out<u32>;
    /// Make the file's writes durable. Any right.
    #[op = NODE_FSYNC]
    #[idempotent]
    fn fsync(&mut self) -> Out<()>;
    /// Move the offset (`whence` 0 from the start, 1 from the offset, 2 from
    /// the end); the new offset. Any right.
    #[op = NODE_SEEK]
    #[at_most_once]
    fn seek(&mut self, offset: i64, whence: u32) -> Out<u64>;
}

#[azos_interface(id = 0x4449_5220, level = 1)]
pub trait Dir {
    /// Open the name `name` with `flags` (`O_*`): the file's capability,
    /// `READ` and `WRITE` as the access mode asks. Needs `READ` on the
    /// directory; an open that changes the tree also needs write authority
    /// over it. The first `floor` components of `name` are the directory the
    /// caller's authority is rooted at: a symlink met below it that leads out of
    /// it is refused (`DENIED`), whatever the volume holds above.
    #[op = NODE_OPENAT]
    #[at_most_once]
    fn openat(&mut self, name: Extent, flags: u32, floor: u32) -> Out<Lent<OpenNode>>;
    /// The record of `name` (`azos_abi::syscall_nr::STAT_BYTES`) into `out`;
    /// `floor` as for [`Dir::openat`].
    #[op = NODE_STATAT]
    #[idempotent]
    fn statat(&mut self, name: Extent, floor: u32, out: Extent) -> Out<()>;
    /// Entry `index` of the directory `name`: its name into `out`
    /// (`READDIR_NAME_BYTES`, zero-padded); `floor` as for [`Dir::openat`], and
    /// the size and type listed for a link that leads out of it are the link's own.
    #[op = NODE_READDIR]
    #[idempotent]
    fn readdir(&mut self, name: Extent, floor: u32, index: u32, out: Extent) -> Out<Entry>;
    /// Capacity and free space of the volume `name` is on
    /// (`azos_abi::syscall_nr::STATFS_BYTES`) into `out`; `floor` as for
    /// [`Dir::openat`].
    #[op = NODE_STATFS]
    #[idempotent]
    fn statfs(&mut self, name: Extent, floor: u32, out: Extent) -> Out<()>;
    /// Make the directory `name`. Needs write authority over it.
    #[op = NODE_MKDIRAT]
    #[at_most_once]
    fn mkdirat(&mut self, name: Extent) -> Out<()>;
    /// Remove the entry `name`; with `UNLINK_DIR` in `flags`, the empty
    /// directory. Needs write authority over it.
    #[op = NODE_UNLINKAT]
    #[at_most_once]
    fn unlinkat(&mut self, name: Extent, flags: u32) -> Out<()>;
    /// Rename `from` to `to`, both beneath this directory. Needs write
    /// authority over both.
    #[op = NODE_RENAMEAT]
    #[at_most_once]
    fn renameat(&mut self, from: Extent, to: Extent) -> Out<()>;
    /// Set the size of the file `name` to `len` bytes. Needs write authority
    /// over it.
    #[op = NODE_TRUNCATEAT]
    #[idempotent]
    fn truncateat(&mut self, name: Extent, len: u64) -> Out<()>;
}
