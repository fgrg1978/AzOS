// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_coreutils::host::Host` on libsys: files and directories beneath the
//! row's root `Cap<Dir>` (a path is made absolute against the working
//! directory by the tool, then named below the root here), standard input and
//! output through the small fds the shell moved to this task.

use azos_abi::syscall_nr::{STATFS_BYTES, STAT_BYTES, STAT_S_IFDIR, STAT_S_IFMT};
use azos_coreutils::host::{Entry, Error, FsInfo, FsKind, Host, Kind, Open, Stat, NAME_MAX};
use azos_coreutils::path::PATH_MAX;
use azos_libsys as sys;

// The tools' name buffer is the record the kernel writes.
const _: () = assert!(NAME_MAX == sys::READDIR_NAME_BYTES);

const O_WRONLY: u64 = 1;
const O_CREAT: u64 = 0x40;
const O_TRUNC: u64 = 0x200;
const O_APPEND: u64 = 0x400;

/// `STATFS` filesystem types (`azos_abi::syscall_nr::STATFS_BYTES`).
const FS_FAT32: u32 = 1;
const FS_TMPFS: u32 = 2;
const FS_DEVFS: u32 = 3;
const FS_AZVOL: u32 = 4;

pub struct Native {
    root: Option<u32>,
    out: [u8; 512],
    n: usize,
}

fn fs_err(e: sys::Errno) -> Error {
    use azos_abi::error::Errno as E;
    match e {
        E::ENOENT => Error::NotFound,
        E::EEXIST => Error::Exists,
        E::ENOTDIR => Error::NotDir,
        E::EISDIR => Error::IsDir,
        E::ENOTEMPTY => Error::NotEmpty,
        E::EACCES | E::EPERM | E::ECAPPERMS | E::EROFS => Error::Denied,
        E::ENAMETOOLONG => Error::TooLong,
        E::ENOSPC | E::EQUOTA => Error::NoSpace,
        E::ENOSYS => Error::Unsupported,
        E::EINTR => Error::Interrupted,
        E::EPIPE => Error::Closed,
        _ => Error::Io,
    }
}

/// A negative answer of a handle op.
fn io_err(rc: isize) -> Error {
    match rc {
        sys::E_INTR => Error::Interrupted,
        sys::E_PIPE => Error::Closed,
        _ => Error::Io,
    }
}

/// `path` (absolute, no NUL) as the NUL-terminated name beneath the root.
fn below<'a>(path: &[u8], buf: &'a mut [u8; PATH_MAX + 2]) -> &'a [u8] {
    let rel = sys::below_root(path);
    if rel.is_empty() {
        buf[..2].copy_from_slice(b".\0");
        return &buf[..2];
    }
    buf[..rel.len()].copy_from_slice(rel);
    buf[rel.len()] = 0;
    &buf[..rel.len() + 1]
}

impl Native {
    pub fn new() -> Native {
        let r = sys::root_dir();
        Native { root: if r >= 0 { Some(r as u32) } else { None }, out: [0; 512], n: 0 }
    }

    fn root(&self) -> Result<u32, Error> {
        self.root.ok_or(Error::NotFound)
    }

    /// Write out what standard output holds.
    pub fn flush(&mut self) -> Result<(), Error> {
        let n = core::mem::take(&mut self.n);
        write_all(1, &self.out[..n])
    }
}

fn write_all(fd: u64, mut b: &[u8]) -> Result<(), Error> {
    while !b.is_empty() {
        let r = sys::write(fd, b);
        if r <= 0 {
            return Err(io_err(r));
        }
        b = &b[r as usize..];
    }
    Ok(())
}

impl Host for Native {
    type File = u32;

    fn cwd(&self) -> &[u8] {
        sys::cwd()
    }

    fn env(&self, i: usize) -> Option<&[u8]> {
        sys::env_at(i)
    }

    fn wall_ns(&self) -> Option<u64> {
        // The wall clock is the monotonic one plus the offset a time source
        // published; zero until one has.
        let real = sys::vdso_clock_offsets().real;
        if real == 0 {
            return None;
        }
        Some(sys::vdso_now_ns().saturating_add(real))
    }

    fn stdin(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        match sys::read(0, buf) {
            // The console has no read: a tool started on it sees an empty input.
            sys::E_BADF => Ok(0),
            r if r < 0 => Err(io_err(r)),
            r => Ok(r as usize),
        }
    }

    fn out(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.n + bytes.len() > self.out.len() {
            self.flush()?;
        }
        if bytes.len() > self.out.len() {
            return write_all(1, bytes);
        }
        self.out[self.n..self.n + bytes.len()].copy_from_slice(bytes);
        self.n += bytes.len();
        Ok(())
    }

    fn err(&mut self, bytes: &[u8]) {
        // What was printed before the message comes before it.
        let _ = self.flush();
        let _ = write_all(2, bytes);
    }

    fn stat(&mut self, path: &[u8]) -> Result<Stat, Error> {
        let (mut nb, mut st) = ([0u8; PATH_MAX + 2], [0u8; STAT_BYTES]);
        sys::stat_at(self.root()?, below(path, &mut nb), &mut st).map_err(fs_err)?;
        let u64_at = |o: usize| u64::from_le_bytes(st[o..o + 8].try_into().unwrap());
        let mode = u32::from_le_bytes(st[8..12].try_into().unwrap());
        Ok(Stat {
            kind: if mode & STAT_S_IFMT == STAT_S_IFDIR { Kind::Dir } else { Kind::File },
            size: u64_at(0),
            mtime: u64_at(32),
        })
    }

    fn readdir(&mut self, path: &[u8], index: u32, name: &mut [u8; NAME_MAX]) -> Result<Option<Entry>, Error> {
        let mut nb = [0u8; PATH_MAX + 2];
        match sys::readdir_at(self.root()?, below(path, &mut nb), index, name).map_err(fs_err)? {
            None => Ok(None),
            Some(e) if e.cut => Err(Error::TooLong),
            Some(e) => Ok(Some(Entry { kind: if e.is_dir { Kind::Dir } else { Kind::File }, size: e.size })),
        }
    }

    fn open(&mut self, path: &[u8], mode: Open) -> Result<u32, Error> {
        let flags = match mode {
            Open::Read => 0,
            Open::Truncate => O_WRONLY | O_CREAT | O_TRUNC,
            Open::Append => O_WRONLY | O_CREAT | O_APPEND,
            Open::Create => O_WRONLY | O_CREAT,
        };
        let mut nb = [0u8; PATH_MAX + 2];
        let rc = sys::open_at(self.root()?, below(path, &mut nb), flags);
        match rc {
            r if r >= 0 => Ok(r as u32),
            // The kernel's plain "the open failed".
            -1 => Err(Error::NotFound),
            r => Err(sys::Errno::from_syscall_ret(r as i64).map_or(Error::Io, fs_err)),
        }
    }

    fn read(&mut self, file: u32, buf: &mut [u8]) -> Result<usize, Error> {
        match sys::file_read_typed(file, buf) {
            r if r < 0 => Err(io_err(r)),
            r => Ok(r as usize),
        }
    }

    fn write(&mut self, file: u32, buf: &[u8]) -> Result<usize, Error> {
        match sys::file_write_typed(file, buf) {
            r if r < 0 => Err(io_err(r)),
            r => Ok(r as usize),
        }
    }

    fn close(&mut self, file: u32) {
        let _ = sys::close_typed(file);
    }

    fn mkdir(&mut self, path: &[u8]) -> Result<(), Error> {
        let mut nb = [0u8; PATH_MAX + 2];
        sys::mkdir_at(self.root()?, below(path, &mut nb)).map_err(fs_err)
    }

    fn unlink(&mut self, path: &[u8]) -> Result<(), Error> {
        let mut nb = [0u8; PATH_MAX + 2];
        sys::unlink_at(self.root()?, below(path, &mut nb)).map_err(fs_err)
    }

    fn rmdir(&mut self, path: &[u8]) -> Result<(), Error> {
        let mut nb = [0u8; PATH_MAX + 2];
        sys::rmdir_at(self.root()?, below(path, &mut nb)).map_err(fs_err)
    }

    fn rename(&mut self, from: &[u8], to: &[u8]) -> Result<(), Error> {
        let (mut a, mut b) = ([0u8; PATH_MAX + 2], [0u8; PATH_MAX + 2]);
        let (fa, fb) = (below(from, &mut a), below(to, &mut b));
        // Across two volumes the kernel answers `EINVAL`.
        sys::rename_at(self.root()?, fa, fb).map_err(|e| if e == sys::Errno::EINVAL { Error::OtherVolume } else { fs_err(e) })
    }

    fn fs_info(&mut self, path: &[u8]) -> Result<FsInfo, Error> {
        let (mut nb, mut st) = ([0u8; PATH_MAX + 2], [0u8; STATFS_BYTES]);
        sys::statfs_at(self.root()?, below(path, &mut nb), &mut st).map_err(fs_err)?;
        let u32_at = |o: usize| u32::from_le_bytes(st[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(st[o..o + 8].try_into().unwrap());
        Ok(FsInfo {
            kind: match u32_at(0) {
                FS_FAT32 => FsKind::Fat32,
                FS_TMPFS => FsKind::Tmpfs,
                FS_DEVFS => FsKind::Devfs,
                FS_AZVOL => FsKind::Volume,
                _ => FsKind::Other,
            },
            block: u32_at(4),
            blocks: u64_at(8),
            free: u64_at(16),
        })
    }
}
