// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What a tool needs from the system, as one trait. The toolbox implements it
//! on libsys handles beneath its root `Cap<Dir>`; the host tests implement it
//! on an in-memory tree. Paths are absolute and normalised (`path.rs`), with
//! no NUL; the implementation turns one into the name beneath its directory.

/// Why an operation did not happen. The names are the failures a tool can say
/// something useful about; the rest is `Io`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NotFound,
    Exists,
    NotDir,
    IsDir,
    NotEmpty,
    /// The row holds no write tree covering the path, or the tree is read-only.
    Denied,
    TooLong,
    /// A rename between two mounted volumes.
    OtherVolume,
    Unsupported,
    NoSpace,
    /// A stop request ended the wait.
    Interrupted,
    /// The reader of the output went away.
    Closed,
    Io,
}

impl Error {
    pub fn text(self) -> &'static [u8] {
        match self {
            Error::NotFound => b"no such file or directory",
            Error::Exists => b"already exists",
            Error::NotDir => b"not a directory",
            Error::IsDir => b"is a directory",
            Error::NotEmpty => b"directory not empty",
            Error::Denied => b"denied: no write tree of this row covers it",
            Error::TooLong => b"path or name too long",
            Error::OtherVolume => b"on another volume",
            Error::Unsupported => b"not supported by this filesystem",
            Error::NoSpace => b"no space left",
            Error::Interrupted => b"interrupted",
            Error::Closed => b"output closed",
            Error::Io => b"input/output error",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
}

#[derive(Clone, Copy, Debug)]
pub struct Stat {
    pub kind: Kind,
    pub size: u64,
    /// Seconds since the epoch, 0 when the filesystem keeps none.
    pub mtime: u64,
}

/// Longest entry name `readdir` returns.
pub const NAME_MAX: usize = 256;

#[derive(Clone, Copy, Debug)]
pub struct Entry {
    pub kind: Kind,
    pub size: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsKind {
    Fat32,
    Tmpfs,
    Devfs,
    Volume,
    Other,
}

impl FsKind {
    pub fn name(self) -> &'static [u8] {
        match self {
            FsKind::Fat32 => b"fat32",
            FsKind::Tmpfs => b"tmpfs",
            FsKind::Devfs => b"devfs",
            FsKind::Volume => b"azvol",
            FsKind::Other => b"other",
        }
    }

    /// Names are stored upper-cased and looked up without case.
    pub fn folds_case(self) -> bool {
        self == FsKind::Fat32
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FsInfo {
    pub kind: FsKind,
    pub block: u32,
    pub blocks: u64,
    pub free: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Open {
    Read,
    /// Create, or empty an existing file.
    Truncate,
    /// Create, or write after the existing bytes.
    Append,
    /// Create, keeping an existing file's bytes.
    Create,
}

pub trait Host {
    type File: Copy;

    /// The working directory the spawner gave, absolute.
    fn cwd(&self) -> &[u8];
    /// Environment string `i` (`NAME=VALUE`).
    fn env(&self, i: usize) -> Option<&[u8]>;
    /// The wall clock in nanoseconds since the epoch; `None` until a time
    /// source has set it.
    fn wall_ns(&self) -> Option<u64>;

    /// Standard input: bytes read, 0 at the end.
    fn stdin(&mut self, buf: &mut [u8]) -> Result<usize, Error>;
    /// Standard output (buffered by the implementation until `flush`).
    fn out(&mut self, bytes: &[u8]) -> Result<(), Error>;
    /// Standard error, written whole.
    fn err(&mut self, bytes: &[u8]);

    fn stat(&mut self, path: &[u8]) -> Result<Stat, Error>;
    /// Entry `index` of the directory, its name NUL-padded into `name`;
    /// `None` past the last.
    fn readdir(&mut self, path: &[u8], index: u32, name: &mut [u8; NAME_MAX]) -> Result<Option<Entry>, Error>;
    fn open(&mut self, path: &[u8], mode: Open) -> Result<Self::File, Error>;
    fn read(&mut self, file: Self::File, buf: &mut [u8]) -> Result<usize, Error>;
    fn write(&mut self, file: Self::File, buf: &[u8]) -> Result<usize, Error>;
    fn close(&mut self, file: Self::File);
    fn mkdir(&mut self, path: &[u8]) -> Result<(), Error>;
    /// Remove a file (`IsDir` for a directory).
    fn unlink(&mut self, path: &[u8]) -> Result<(), Error>;
    /// Remove an empty directory.
    fn rmdir(&mut self, path: &[u8]) -> Result<(), Error>;
    fn rename(&mut self, from: &[u8], to: &[u8]) -> Result<(), Error>;
    fn fs_info(&mut self, path: &[u8]) -> Result<FsInfo, Error>;
}
