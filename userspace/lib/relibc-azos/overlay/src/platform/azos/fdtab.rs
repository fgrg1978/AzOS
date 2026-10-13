// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The POSIX descriptor table: small integers over native handles.
//!
//! The native ABI has no integer descriptors; an open file, a pipe end and the
//! console are handles (capabilities) or, for the console, a stream of the
//! domain's log object. A C program wants `int fd`, `dup`, `dup2` and
//! `FD_CLOEXEC`, so this layer keeps the table, in user space, exactly as the
//! kernel decided it should (`libsys` keeps its own 8-entry table for native
//! programs and the shell; a relibc program uses this one, seeded from it).
//!
//! An entry is a shared `OpenFile` (a POSIX "open file description"): `dup`
//! makes a second entry on the same one, and only the last `close` of it
//! reaches the kernel (`SYS_CAP_CLOSE`), because the kernel has no `dup` of a
//! file handle.
//!
//! A handle moved into a spawned child (`SYS_SPAWN_EX`'s move list) is gone
//! from this process: the `OpenFile` is marked `gone` and never closes it.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

use super::{check, pure::DirEntry};
use crate::{
    error::{Errno, Result},
    header::{
        errno::{EBADF, EINVAL, EMFILE},
        fcntl::{
            F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_GETFL, F_SETFD, F_SETFL, FD_CLOEXEC, O_ACCMODE,
            O_APPEND, O_CLOEXEC, O_NONBLOCK, O_RDONLY, O_RDWR, O_WRONLY,
        },
    },
    out::Out,
    platform::types::{c_int, c_ulonglong},
    sync::Mutex,
};

/// Descriptors a process may hold. The native handle table is the real bound
/// (`-EMFILE` from the kernel); this is the size of the integer space.
pub(crate) const FD_MAX: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// The console: `handle` is the stream, `STDOUT` or `STDERR` for writes
    /// and `STDIN_STREAM` for reads.
    Console,
    /// A `Cap<File>`.
    File,
    /// A directory: no handle (the native ABI has none for a directory), only
    /// the entries it had when it was opened.
    Dir,
    /// A pipe end.
    Pipe,
}

/// `OpenFile::handle` of the console's input stream.
pub(crate) const STDIN_STREAM: u32 = 0;

/// An open file description.
pub(crate) struct OpenFile {
    pub kind: Kind,
    pub handle: u32,
    /// The absolute path, NUL-terminated, this description was opened by. A
    /// report for `F_GETPATH` and nothing more: it is never resolved again, so
    /// a rename or a replacement of the file changes what it names and not
    /// what an operation on the descriptor acts on.
    pub opened_as: Option<Box<[u8]>>,
    /// A directory's entries as `opendir` read them (empty for anything else).
    pub entries: Box<[DirEntry]>,
    /// `O_ACCMODE`, `O_APPEND` and `O_NONBLOCK` (`F_GETFL`).
    pub status: AtomicI32,
    /// Index of the next directory entry.
    pub dpos: AtomicU64,
    gone: AtomicBool,
}

impl OpenFile {
    pub(crate) fn new(kind: Kind, handle: u32, opened_as: Option<Box<[u8]>>, status: c_int) -> Arc<Self> {
        Arc::new(Self {
            kind,
            handle,
            opened_as,
            entries: Box::default(),
            status: AtomicI32::new(status),
            dpos: AtomicU64::new(0),
            gone: AtomicBool::new(false),
        })
    }

    /// A directory descriptor over its snapshot.
    pub(crate) fn dir(opened_as: Box<[u8]>, entries: Box<[DirEntry]>) -> Arc<Self> {
        Arc::new(Self {
            kind: Kind::Dir,
            handle: 0,
            opened_as: Some(opened_as),
            entries,
            status: AtomicI32::new(O_RDONLY),
            dpos: AtomicU64::new(0),
            gone: AtomicBool::new(false),
        })
    }

    /// The handle left this process (moved into a child): do not close it.
    pub(crate) fn mark_gone(&self) {
        self.gone.store(true, Ordering::Release);
    }

    /// Can this description be read / written, by its access mode?
    pub(crate) fn readable(&self) -> bool {
        self.status.load(Ordering::Relaxed) & O_ACCMODE != O_WRONLY
    }

    pub(crate) fn writable(&self) -> bool {
        self.status.load(Ordering::Relaxed) & O_ACCMODE != O_RDONLY
    }
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        if matches!(self.kind, Kind::File | Kind::Pipe) && !self.gone.load(Ordering::Acquire) {
            let _ = azos_libsys::close_typed(self.handle);
        }
    }
}

#[derive(Clone)]
struct Slot {
    file: Arc<OpenFile>,
    cloexec: bool,
}

static TABLE: Mutex<[Option<Slot>; FD_MAX]> = Mutex::new([const { None }; FD_MAX]);

fn index(fd: c_int) -> Result<usize> {
    usize::try_from(fd).ok().filter(|&i| i < FD_MAX).ok_or(Errno(EBADF))
}

/// The open file description behind `fd`.
pub(crate) fn get(fd: c_int) -> Result<Arc<OpenFile>> {
    let i = index(fd)?;
    TABLE.lock()[i].as_ref().map(|s| s.file.clone()).ok_or(Errno(EBADF))
}

/// Put `file` at the lowest free descriptor at or above `min`.
pub(crate) fn install(file: Arc<OpenFile>, cloexec: bool, min: usize) -> Result<c_int> {
    let mut t = TABLE.lock();
    let free = (min..FD_MAX).find(|&i| t[i].is_none()).ok_or(Errno(EMFILE))?;
    t[free] = Some(Slot { file, cloexec });
    Ok(free as c_int)
}

pub(crate) fn close(fd: c_int) -> Result<()> {
    let i = index(fd)?;
    // Drop outside the lock: the last close traps into the kernel.
    let old = TABLE.lock()[i].take();
    old.map(|_| ()).ok_or(Errno(EBADF))
}

pub(crate) fn dup(fd: c_int, min: usize, cloexec: bool) -> Result<c_int> {
    let file = get(fd)?;
    install(file, cloexec, min)
}

pub(crate) fn dup2(fd: c_int, new: c_int) -> Result<c_int> {
    let file = get(fd)?;
    let n = index(new)?;
    if fd == new {
        return Ok(new);
    }
    let old = core::mem::replace(&mut TABLE.lock()[n], Some(Slot { file, cloexec: false }));
    drop(old);
    Ok(new)
}

pub(crate) fn fcntl(fd: c_int, cmd: c_int, arg: c_ulonglong) -> Result<c_int> {
    match cmd {
        F_DUPFD => dup(fd, arg as usize, false),
        F_DUPFD_CLOEXEC => dup(fd, arg as usize, true),
        F_GETFD => {
            let i = index(fd)?;
            let t = TABLE.lock();
            let s = t[i].as_ref().ok_or(Errno(EBADF))?;
            Ok(if s.cloexec { FD_CLOEXEC } else { 0 })
        }
        F_SETFD => {
            let i = index(fd)?;
            let mut t = TABLE.lock();
            let s = t[i].as_mut().ok_or(Errno(EBADF))?;
            s.cloexec = arg as c_int & FD_CLOEXEC != 0;
            Ok(0)
        }
        F_GETFL => Ok(get(fd)?.status.load(Ordering::Relaxed)),
        F_SETFL => {
            // Only the flags that can change after open.
            let f = get(fd)?;
            let keep = f.status.load(Ordering::Relaxed) & !(O_APPEND | O_NONBLOCK);
            f.status.store(keep | (arg as c_int & (O_APPEND | O_NONBLOCK)), Ordering::Relaxed);
            Ok(0)
        }
        _ => Err(Errno(EINVAL)),
    }
}

pub(crate) fn pipe2(mut fildes: Out<[c_int; 2]>, flags: c_int) -> Result<()> {
    let mut ends = [0u32; 2];
    let nb = if flags & O_NONBLOCK != 0 { azos_libsys::PIPE_NONBLOCK } else { 0 };
    check(azos_libsys::pipe_typed(&mut ends, nb))?;
    let cloexec = flags & O_CLOEXEC != 0;
    let status = flags & O_NONBLOCK;
    let r = install(OpenFile::new(Kind::Pipe, ends[0], None, O_RDONLY | status), cloexec, 0);
    let r = match r {
        Ok(r) => r,
        Err(e) => {
            let _ = azos_libsys::close_typed(ends[0]);
            let _ = azos_libsys::close_typed(ends[1]);
            return Err(e);
        }
    };
    let w = match install(OpenFile::new(Kind::Pipe, ends[1], None, O_WRONLY | status), cloexec, 0) {
        Ok(w) => w,
        Err(e) => {
            let _ = close(r);
            let _ = azos_libsys::close_typed(ends[1]);
            return Err(e);
        }
    };
    fildes.write([r, w]);
    Ok(())
}

/// Fill descriptors 0..8 from what the spawner gave (`libsys` read the startup
/// block): the console, or a handle of a file or a pipe. Without a block fd 1
/// and 2 are the console, as for every native program.
pub(crate) fn init_stdio() {
    use azos_abi::cap::ty;
    use azos_libsys::{cap_info, fd_get, FdEntry, STDERR, STDOUT};
    for fd in 0..azos_libsys::FD_TABLE_LEN as u64 {
        let file = match fd_get(fd) {
            FdEntry::Closed => continue,
            FdEntry::Console => {
                // The console has no read (`libsys`): input is its wait op,
                // taken only on fd 0.
                let (stream, status) = match fd {
                    0 => (STDIN_STREAM, O_RDONLY),
                    2 => (STDERR as u32, O_WRONLY),
                    _ => (STDOUT as u32, O_WRONLY),
                };
                OpenFile::new(Kind::Console, stream, None, status)
            }
            FdEntry::Handle(h) => {
                let Ok(info) = cap_info(h) else { continue };
                let kind = if info.ty == ty::PIPE.raw() { Kind::Pipe } else { Kind::File };
                let read = info.rights & 1 != 0;
                let write = info.rights & 2 != 0;
                let status = match (read, write) {
                    (true, true) => O_RDWR,
                    (false, true) => O_WRONLY,
                    _ => O_RDONLY,
                };
                OpenFile::new(kind, h, None, status)
            }
        };
        TABLE.lock()[fd as usize] = Some(Slot { file, cloexec: false });
    }
}

/// The child's view of this table for a spawn: for each of fds 0..8 the
/// description it would inherit (an entry without `FD_CLOEXEC`).
pub(crate) fn inheritable() -> Vec<Option<Arc<OpenFile>>> {
    let t = TABLE.lock();
    (0..azos_libsys::FD_TABLE_LEN)
        .map(|i| t[i].as_ref().filter(|s| !s.cloexec).map(|s| s.file.clone()))
        .collect()
}
