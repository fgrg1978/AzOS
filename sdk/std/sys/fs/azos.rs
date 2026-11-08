// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `std::fs` over the node ops of `azos_stdrt::fs`: paths are made absolute
//! against the working directory and opened beneath the task's root `Cap<Dir>`,
//! so a program reaches only what its row grants.
//!
//! What the native ops cannot do is `Unsupported`, never a fake success: a file
//! handle has read, write, seek and fsync, but no stat (its size, type and times
//! are the stat of a name, and the name it was opened by may by then be another
//! file), no truncate, no times and no lock; there are no links, modes or owners;
//! `create_new` cannot be honoured because the native open cannot refuse an
//! existing file.

use azos_stdrt::fspure::{self, OpenError};
use azos_stdrt::fs as nfs;

use crate::ffi::OsString;
use crate::fmt;
use crate::fs::TryLockError;
use crate::hash::{Hash, Hasher};
use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut, SeekFrom};
use crate::path::{Path, PathBuf};
pub use crate::sys::fs::common::Dir;
use crate::sync::Arc;
use crate::sys::time::SystemTime;
use crate::sys::{map_native_error, unsupported, unsupported_err};

fn bytes(p: &Path) -> &[u8] {
    p.as_os_str().as_encoded_bytes()
}

fn native<T>(r: Result<T, isize>) -> io::Result<T> {
    r.map_err(map_native_error)
}

/// A native result that is a count or an offset, or a negative code.
fn count(rc: isize) -> io::Result<usize> {
    if rc < 0 { Err(map_native_error(rc)) } else { Ok(rc as usize) }
}

pub struct File {
    handle: u32,
}

#[derive(Clone)]
pub struct FileAttr {
    stat: fspure::Stat,
}

pub struct ReadDir {
    dir: Arc<PathBuf>,
    entries: crate::vec::IntoIter<(OsString, bool)>,
}

pub struct DirEntry {
    dir: Arc<PathBuf>,
    name: OsString,
    is_dir: bool,
}

#[derive(Clone, Debug)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct FileTimes {}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FilePermissions {
    readonly: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct FileType {
    dir: bool,
}

#[derive(Debug)]
pub struct DirBuilder {}

impl FileAttr {
    pub fn size(&self) -> u64 {
        self.stat.size
    }

    pub fn perm(&self) -> FilePermissions {
        FilePermissions { readonly: self.stat.readonly() }
    }

    pub fn file_type(&self) -> FileType {
        FileType { dir: self.stat.is_dir() }
    }

    pub fn modified(&self) -> io::Result<SystemTime> {
        Ok(SystemTime::from_unix_secs(self.stat.mtime))
    }

    pub fn accessed(&self) -> io::Result<SystemTime> {
        Ok(SystemTime::from_unix_secs(self.stat.atime))
    }

    /// The volumes keep no creation time.
    pub fn created(&self) -> io::Result<SystemTime> {
        unsupported()
    }
}

impl FilePermissions {
    pub fn readonly(&self) -> bool {
        self.readonly
    }

    pub fn set_readonly(&mut self, readonly: bool) {
        self.readonly = readonly;
    }
}

impl FileTimes {
    pub fn set_accessed(&mut self, _t: SystemTime) {}
    pub fn set_modified(&mut self, _t: SystemTime) {}
}

impl FileType {
    pub fn is_dir(&self) -> bool {
        self.dir
    }

    pub fn is_file(&self) -> bool {
        !self.dir
    }

    /// There are no symbolic links.
    pub fn is_symlink(&self) -> bool {
        false
    }
}

impl fmt::Debug for ReadDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ReadDir").field(&*self.dir).finish()
    }
}

impl Iterator for ReadDir {
    type Item = io::Result<DirEntry>;

    fn next(&mut self) -> Option<io::Result<DirEntry>> {
        let (name, is_dir) = self.entries.next()?;
        Some(Ok(DirEntry { dir: Arc::clone(&self.dir), name, is_dir }))
    }
}

impl DirEntry {
    pub fn path(&self) -> PathBuf {
        self.dir.join(&self.name)
    }

    pub fn file_name(&self) -> OsString {
        self.name.clone()
    }

    pub fn metadata(&self) -> io::Result<FileAttr> {
        stat(&self.path())
    }

    pub fn file_type(&self) -> io::Result<FileType> {
        Ok(FileType { dir: self.is_dir })
    }
}

impl OpenOptions {
    pub fn new() -> OpenOptions {
        OpenOptions { read: false, write: false, append: false, truncate: false, create: false, create_new: false }
    }

    pub fn read(&mut self, read: bool) {
        self.read = read;
    }
    pub fn write(&mut self, write: bool) {
        self.write = write;
    }
    pub fn append(&mut self, append: bool) {
        self.append = append;
    }
    pub fn truncate(&mut self, truncate: bool) {
        self.truncate = truncate;
    }
    pub fn create(&mut self, create: bool) {
        self.create = create;
    }
    pub fn create_new(&mut self, create_new: bool) {
        self.create_new = create_new;
    }
}

impl File {
    pub fn open(path: &Path, opts: &OpenOptions) -> io::Result<File> {
        let flags = fspure::open_flags(opts.read, opts.write, opts.append, opts.truncate, opts.create, opts.create_new)
            .map_err(|e| match e {
                OpenError::Invalid => io::const_error!(io::ErrorKind::InvalidInput, "invalid combination of open options"),
                OpenError::CreateNew => unsupported_err(),
            })?;
        Ok(File { handle: native(nfs::open(bytes(path), flags))? })
    }

    /// A handle has no stat: the size, type and times are those of a name.
    pub fn file_attr(&self) -> io::Result<FileAttr> {
        unsupported()
    }

    pub fn fsync(&self) -> io::Result<()> {
        count(nfs::fsync(self.handle)).map(|_| ())
    }

    pub fn datasync(&self) -> io::Result<()> {
        self.fsync()
    }

    pub fn lock(&self) -> io::Result<()> {
        unsupported()
    }

    pub fn lock_shared(&self) -> io::Result<()> {
        unsupported()
    }

    pub fn try_lock(&self) -> Result<(), TryLockError> {
        Err(TryLockError::Error(unsupported_err()))
    }

    pub fn try_lock_shared(&self) -> Result<(), TryLockError> {
        Err(TryLockError::Error(unsupported_err()))
    }

    pub fn unlock(&self) -> io::Result<()> {
        unsupported()
    }

    /// The native truncate takes a name, not a handle.
    pub fn truncate(&self, _size: u64) -> io::Result<()> {
        unsupported()
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        count(nfs::read(self.handle, buf))
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        crate::io::default_read_vectored(|b| self.read(b), bufs)
    }

    pub fn is_read_vectored(&self) -> bool {
        false
    }

    pub fn read_buf(&self, cursor: BorrowedCursor<'_>) -> io::Result<()> {
        crate::io::default_read_buf(|b| self.read(b), cursor)
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        count(nfs::write(self.handle, buf))
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        crate::io::default_write_vectored(|b| self.write(b), bufs)
    }

    pub fn is_write_vectored(&self) -> bool {
        false
    }

    pub fn flush(&self) -> io::Result<()> {
        Ok(())
    }

    pub fn seek(&self, pos: SeekFrom) -> io::Result<u64> {
        let (offset, whence) = match pos {
            SeekFrom::Start(n) => (i64::try_from(n).map_err(|_| io::const_error!(io::ErrorKind::InvalidInput, "offset too large"))?, 0),
            SeekFrom::Current(n) => (n, 1),
            SeekFrom::End(n) => (n, 2),
        };
        count(nfs::seek(self.handle, offset, whence)).map(|n| n as u64)
    }

    /// Unknown without a stat of the name.
    pub fn size(&self) -> Option<io::Result<u64>> {
        None
    }

    pub fn tell(&self) -> io::Result<u64> {
        self.seek(SeekFrom::Current(0))
    }

    pub fn duplicate(&self) -> io::Result<File> {
        unsupported()
    }

    pub fn set_permissions(&self, _perm: FilePermissions) -> io::Result<()> {
        unsupported()
    }

    pub fn set_times(&self, _times: FileTimes) -> io::Result<()> {
        unsupported()
    }
}

impl Drop for File {
    fn drop(&mut self) {
        let _ = nfs::close(self.handle);
    }
}

impl fmt::Debug for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("File").field("handle", &self.handle).finish()
    }
}

impl DirBuilder {
    pub fn new() -> DirBuilder {
        DirBuilder {}
    }

    pub fn mkdir(&self, p: &Path) -> io::Result<()> {
        native(nfs::mkdir(bytes(p)))
    }
}

pub fn readdir(p: &Path) -> io::Result<ReadDir> {
    let mut entries = crate::vec::Vec::new();
    let mut name = [0u8; azos_stdrt::fs::NAME_BYTES];
    let mut index = 0u32;
    while let Some(is_dir) = native(nfs::readdir(bytes(p), index, &mut name))? {
        let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        // SAFETY: names are bytes of the volume's choosing; the encoding of an `OsString` here is bytes.
        entries.push((unsafe { OsString::from_encoded_bytes_unchecked(name[..len].to_vec()) }, is_dir));
        index += 1;
    }
    Ok(ReadDir { dir: Arc::new(p.to_path_buf()), entries: entries.into_iter() })
}

pub fn unlink(p: &Path) -> io::Result<()> {
    native(nfs::unlink(bytes(p)))
}

pub fn rename(old: &Path, new: &Path) -> io::Result<()> {
    native(nfs::rename(bytes(old), bytes(new)))
}

/// The volumes keep no modes.
pub fn set_perm(_p: &Path, _perm: FilePermissions) -> io::Result<()> {
    unsupported()
}

pub fn set_times(_p: &Path, _times: FileTimes) -> io::Result<()> {
    unsupported()
}

pub fn set_times_nofollow(_p: &Path, _times: FileTimes) -> io::Result<()> {
    unsupported()
}

pub fn rmdir(p: &Path) -> io::Result<()> {
    native(nfs::rmdir(bytes(p)))
}

pub use crate::sys::fs::common::{exists, remove_dir_all};

pub fn readlink(_p: &Path) -> io::Result<PathBuf> {
    unsupported()
}

pub fn symlink(_original: &Path, _link: &Path) -> io::Result<()> {
    unsupported()
}

pub fn link(_src: &Path, _dst: &Path) -> io::Result<()> {
    unsupported()
}

pub fn stat(p: &Path) -> io::Result<FileAttr> {
    Ok(FileAttr { stat: native(nfs::stat(bytes(p)))? })
}

/// There are no symbolic links: a name is what it names.
pub fn lstat(p: &Path) -> io::Result<FileAttr> {
    stat(p)
}

pub fn canonicalize(p: &Path) -> io::Result<PathBuf> {
    let abs = native(nfs::resolve(bytes(p)))?;
    native(nfs::stat(abs.bytes()))?;
    // SAFETY: bytes of the volume's names are a valid `OsString` on this platform.
    Ok(PathBuf::from(unsafe { OsString::from_encoded_bytes_unchecked(abs.bytes().to_vec()) }))
}

/// The contents; no modes to copy.
pub fn copy(from: &Path, to: &Path) -> io::Result<u64> {
    let mut reader = crate::fs::File::open(from)?;
    let mut writer = crate::fs::File::create(to)?;
    io::copy(&mut reader, &mut writer)
}
