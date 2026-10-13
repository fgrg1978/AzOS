// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The parts of the platform layer that are arithmetic on bytes: path
//! normalisation, the wait status of an exit code, `dirent` records, the string
//! blobs of a spawn request and the futex timeout. No relibc type and no call, so
//! the host tests (tests/host/relibc-azos-tests) include this file as it is.

use alloc::{boxed::Box, vec::Vec};

// ── paths ────────────────────────────────────────────────────────────────────

/// Why a path could not be made absolute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    /// The empty path names nothing (`ENOENT`).
    Empty,
    /// The result, with its NUL, does not fit `max` bytes (`ENAMETOOLONG`).
    TooLong,
}

/// `path` made absolute against `base` (an absolute path without NUL) and
/// lexically normal: no `.` or doubled `/`, and `..` removes a component and
/// stops at the root. NUL-terminated, at most `max` bytes with the NUL.
///
/// `..` is resolved lexically because the volumes have no symbolic links; it
/// can never climb above `/`, so a path cannot name something outside the
/// root it was given.
pub fn normalize(base: &[u8], path: &[u8], max: usize) -> Result<Vec<u8>, PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    let mut parts: Vec<&[u8]> = Vec::new();
    // An absolute path ignores the base.
    let chunks: &[&[u8]] = if path[0] == b'/' { &[path] } else { &[base, path] };
    for chunk in chunks {
        for comp in chunk.split(|&b| b == b'/') {
            match comp {
                b"" | b"." => {}
                b".." => {
                    parts.pop();
                }
                c => parts.push(c),
            }
        }
    }
    let mut out = Vec::with_capacity(path.len() + 2);
    if parts.is_empty() {
        out.push(b'/');
    }
    for p in parts {
        out.push(b'/');
        out.extend_from_slice(p);
    }
    if out.len() >= max {
        return Err(PathError::TooLong);
    }
    out.push(0);
    Ok(out)
}

// ── wait ─────────────────────────────────────────────────────────────────────

/// The POSIX wait status of a native exit code. The kernel's own kills (a fault,
/// a stop request: `azos_abi::exit_status`) are exit codes of 128 + a signal
/// number; a shell shows them as that signal, and so does `WIFSIGNALED` here.
/// Any other code is a normal exit.
pub fn wait_status(code: i32) -> i32 {
    use azos_abi::exit_status::{KILLED_BUS, KILLED_ILL, KILLED_KILL, KILLED_SEGV, KILLED_TRAP};
    match code {
        KILLED_SEGV | KILLED_ILL | KILLED_BUS | KILLED_TRAP | KILLED_KILL => code - 128,
        c => (c & 0xff) << 8,
    }
}

// ── directory records ────────────────────────────────────────────────────────

/// The `dirent` records `getdents` returns are Linux's `linux_dirent64`: this is
/// where each field sits (the platform module asserts it against relibc's `dirent`).
pub const D_INO: usize = 0;
pub const D_OFF: usize = 8;
pub const D_RECLEN: usize = 16;
pub const D_TYPE: usize = 18;
pub const D_NAME: usize = 19;
/// `d_type` values.
pub const DT_REG: u8 = 8;
pub const DT_DIR: u8 = 4;

/// Bytes of a record for a name of `len` bytes: the header, the name and its
/// NUL, rounded up to 8.
pub const fn dirent_reclen(len: usize) -> usize {
    (D_NAME + len + 1).next_multiple_of(8)
}

/// Write the record for entry `index` (`name` without NUL) into `rec`, which is
/// exactly `dirent_reclen(name.len())` bytes. The inode is made from the index
/// (the volumes number nothing), and `d_off` is the index of the next entry,
/// which is what `getdents` is handed to continue from.
pub fn write_dirent(rec: &mut [u8], index: u64, is_dir: bool, name: &[u8]) {
    debug_assert_eq!(rec.len(), dirent_reclen(name.len()));
    let len = rec.len() as u16;
    rec.fill(0);
    rec[D_INO..D_INO + 8].copy_from_slice(&(index + 1).to_ne_bytes());
    rec[D_OFF..D_OFF + 8].copy_from_slice(&(index + 1).to_ne_bytes());
    rec[D_RECLEN..D_RECLEN + 2].copy_from_slice(&len.to_ne_bytes());
    rec[D_TYPE] = if is_dir { DT_DIR } else { DT_REG };
    rec[D_NAME..D_NAME + name.len()].copy_from_slice(name);
}

/// One entry of a directory as `opendir` found it.
pub struct DirEntry {
    pub name: Box<[u8]>,
    pub is_dir: bool,
}

/// The first record is larger than the buffer (`EINVAL` for `getdents`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferTooSmall;

/// Records of `entries[first..]` into `buf`, as many whole ones as fit; the bytes
/// written, 0 at the end. The directory is the snapshot taken when it was opened,
/// so reading it later asks the filesystem nothing and cannot land in another
/// directory.
pub fn pack_dirents(entries: &[DirEntry], first: u64, buf: &mut [u8]) -> Result<usize, BufferTooSmall> {
    let mut at = 0;
    let from = usize::try_from(first).unwrap_or(usize::MAX);
    for (index, e) in entries.iter().enumerate().skip(from) {
        let rl = dirent_reclen(e.name.len());
        if at + rl > buf.len() {
            return if at == 0 { Err(BufferTooSmall) } else { Ok(at) };
        }
        write_dirent(&mut buf[at..at + rl], index as u64, e.is_dir, &e.name);
        at += rl;
    }
    Ok(at)
}

/// `(d_reclen, d_off)` of the record at the start of `rec`.
pub fn read_dirent(rec: &[u8]) -> Option<(u16, u64)> {
    let rl = rec.get(D_RECLEN..D_RECLEN + 2)?;
    let off = rec.get(D_OFF..D_OFF + 8)?;
    Some((u16::from_ne_bytes(rl.try_into().ok()?), u64::from_ne_bytes(off.try_into().ok()?)))
}

// ── spawn request strings ────────────────────────────────────────────────────

/// Too many strings, or too many bytes, for the request (`E2BIG`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooBig;

/// NUL-separated strings of `items` (each ends with a NUL), at most `max_n` of
/// them and `max_bytes` bytes: the form of the argument and environment blocks of
/// `SpawnReq`. Returns the block and how many strings it holds.
pub fn cstr_blob<'a>(
    items: impl Iterator<Item = &'a [u8]>,
    max_n: usize,
    max_bytes: usize,
) -> Result<(Vec<u8>, u32), TooBig> {
    let mut out = Vec::new();
    let mut n = 0u32;
    for s in items {
        out.extend_from_slice(s);
        out.push(0);
        n += 1;
        if n as usize > max_n || out.len() > max_bytes {
            return Err(TooBig);
        }
    }
    Ok((out, n))
}

// ── futex ────────────────────────────────────────────────────────────────────

/// The relative timeout the kernel's futex wait takes, for an absolute deadline
/// `deadline_ns` on the clock read as `now_ns`: `None` when the deadline has
/// passed (the wait must report a timeout, because a timeout of 0 means "no
/// limit" to the kernel), `Some(0)` is never returned.
pub fn futex_timeout(deadline_ns: u64, now_ns: u64) -> Option<u64> {
    match deadline_ns.checked_sub(now_ns) {
        None | Some(0) => None,
        Some(left) => Some(left),
    }
}
