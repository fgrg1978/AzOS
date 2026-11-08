// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The parts of `std::fs` that are arithmetic on bytes: making a path absolute,
//! the open flags of `OpenOptions`, and the stat record. No call, no allocation,
//! so `tests/host/stdrt-tests` builds this file on the host.

use azos_abi::syscall_nr::{STAT_BYTES, STAT_OFF_ATIME, STAT_OFF_CTIME, STAT_OFF_MODE, STAT_OFF_MTIME, STAT_OFF_SIZE};
use azos_abi::syscall_nr::{STAT_S_IFDIR, STAT_S_IFMT};

/// Bytes the kernel reads for a path, its NUL included.
pub const PATH_MAX: usize = azos_abi::syscall_nr::SYS_PATH_MAX;

/// An absolute path, lexically normal, NUL-terminated.
#[derive(Clone, Copy)]
pub struct AbsPath {
    pub buf: [u8; PATH_MAX],
    /// Bytes before the NUL.
    pub len: usize,
}

impl AbsPath {
    pub const ROOT: AbsPath = {
        let mut buf = [0u8; PATH_MAX];
        buf[0] = b'/';
        AbsPath { buf, len: 1 }
    };

    /// The path without its NUL.
    pub fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// The path with its NUL.
    pub fn with_nul(&self) -> &[u8] {
        &self.buf[..self.len + 1]
    }
}

/// Why a path could not be made absolute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    /// The empty path names nothing.
    Empty,
    /// A byte is NUL: the kernel would read the name up to it.
    Nul,
    /// The result, with its NUL, does not fit [`PATH_MAX`].
    TooLong,
}

/// `path` made absolute against `base` (an absolute path) and lexically normal:
/// no `.` or doubled `/`, and `..` removes a component and stops at the root.
///
/// `..` is resolved lexically because the volumes have no symbolic links; it
/// can never climb above `/`, so a path cannot name something outside the root
/// it is opened beneath.
pub fn normalize(base: &[u8], path: &[u8]) -> Result<AbsPath, PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    if path.contains(&0) {
        return Err(PathError::Nul);
    }
    let mut out = AbsPath { buf: [0; PATH_MAX], len: 0 };
    let mut n = 0usize;
    let chunks: [&[u8]; 2] = if path[0] == b'/' { [b"", path] } else { [base, path] };
    for chunk in chunks {
        for comp in chunk.split(|&b| b == b'/') {
            match comp {
                b"" | b"." => {}
                b".." => {
                    while n > 0 && out.buf[n - 1] != b'/' {
                        n -= 1;
                    }
                    n = n.saturating_sub(1);
                }
                c => {
                    if n + 1 + c.len() >= PATH_MAX {
                        return Err(PathError::TooLong);
                    }
                    out.buf[n] = b'/';
                    out.buf[n + 1..n + 1 + c.len()].copy_from_slice(c);
                    n += 1 + c.len();
                }
            }
        }
    }
    if n == 0 {
        out.buf[0] = b'/';
        n = 1;
    }
    out.buf[n] = 0;
    out.len = n;
    Ok(out)
}

/// The directory that holds `abs` (`/` for a name directly beneath the root, and for the root).
pub fn parent_of(abs: &AbsPath) -> AbsPath {
    let mut p = *abs;
    let mut n = p.len;
    while n > 1 && p.buf[n - 1] != b'/' {
        n -= 1;
    }
    p.len = if n > 1 { n - 1 } else { 1 };
    p.buf[p.len] = 0;
    p
}

/// The native open flags (Linux's numbers: the access mode, `O_CREAT`,
/// `O_TRUNC`, `O_APPEND`) of an `OpenOptions`.
pub const O_WRONLY: u64 = 1;
pub const O_RDWR: u64 = 2;
pub const O_CREAT: u64 = 0o100;
pub const O_TRUNC: u64 = 0o1000;
pub const O_APPEND: u64 = 0o2000;

/// An `OpenOptions` the native open cannot carry out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The combination `std` itself refuses (no access mode; create or truncate without write).
    Invalid,
    /// `create_new`: the native open creates a missing file but cannot refuse an
    /// existing one, and a check before it would race with it.
    CreateNew,
}

/// The flags of `read`/`write`/`append`/`truncate`/`create`/`create_new`, with
/// the checks `std` makes of every platform.
pub fn open_flags(read: bool, write: bool, append: bool, truncate: bool, create: bool, create_new: bool) -> Result<u64, OpenError> {
    let access = match (read, write, append) {
        (true, false, false) => 0,
        (false, true, false) => O_WRONLY,
        (true, true, false) => O_RDWR,
        (false, _, true) => O_WRONLY | O_APPEND,
        (true, _, true) => O_RDWR | O_APPEND,
        (false, false, false) => return Err(OpenError::Invalid),
    };
    if !write && !append && (truncate || create || create_new) {
        return Err(OpenError::Invalid);
    }
    if append && truncate && !create_new {
        return Err(OpenError::Invalid);
    }
    if create_new {
        return Err(OpenError::CreateNew);
    }
    Ok(access | if create { O_CREAT } else { 0 } | if truncate { O_TRUNC } else { 0 })
}

/// What the native stat record says of a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub size: u64,
    pub mode: u32,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
}

impl Stat {
    pub fn decode(b: &[u8; STAT_BYTES]) -> Stat {
        let u64at = |o: usize| u64::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7]]);
        let mode = u32::from_le_bytes([b[STAT_OFF_MODE], b[STAT_OFF_MODE + 1], b[STAT_OFF_MODE + 2], b[STAT_OFF_MODE + 3]]);
        Stat { size: u64at(STAT_OFF_SIZE), mode, atime: u64at(STAT_OFF_ATIME), mtime: u64at(STAT_OFF_MTIME), ctime: u64at(STAT_OFF_CTIME) }
    }

    pub fn is_dir(&self) -> bool {
        self.mode & STAT_S_IFMT == STAT_S_IFDIR
    }

    /// No write bit: the only permission `std` reports.
    pub fn readonly(&self) -> bool {
        self.mode & 0o222 == 0
    }
}
