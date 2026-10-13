// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Files, directories and paths over the domain's file ops and the node ops of a
//! handle (`DOMAIN_OPEN`, `DOMAIN_STAT`, `DOMAIN_READDIR`, `DOMAIN_MKDIR`, `NODE_READ`,
//! `NODE_WRITE`, ...), through `azos_libsys`.
//!
//! This is the one module that knows how a file is reached. The native model
//! will serve files behind a filesystem interface (IDL) on an endpoint; the
//! POSIX side below calls only the helpers of this file, so that change is
//! local to it.
//!
//! **A descriptor acts on the object its handle names, or it does nothing.** The
//! node ops of a file handle are read, write and fsync; everything else the
//! domain offers (stat, truncate, statfs, readdir, rename ...) takes a path. A
//! POSIX call on a descriptor that would need one of those is refused with
//! `ENOSYS`: this layer never turns a descriptor back into the name it was
//! opened by and runs the path op on it, because the name may by then belong to
//! another file (renamed, unlinked, replaced), and the call would act on, or
//! report, that one. The same holds for a directory descriptor: the native ABI
//! has no directory handle, so one carries the entries the directory had when it
//! was opened (`getdents` serves them) and nothing that could be resolved again;
//! `fchdir` and a `dirfd` that anchors a relative path are refused.
//!
//! `O_CREAT | O_EXCL` is refused too (`EINVAL`, as the Linux personality does):
//! the native open creates and truncates but cannot refuse an existing file, and
//! a check made before it would race with it.
//!
//! The kernel keeps no working directory: this layer does, and makes every path
//! absolute (and lexically normal) before the call.

use alloc::{boxed::Box, vec::Vec};
use core::{
    mem::offset_of,
    sync::atomic::{AtomicU32, Ordering},
};

use super::{
    check, errno_of, nosys,
    fdtab::{self, Kind, OpenFile, STDIN_STREAM},
    pure::{self, DirEntry},
};
use crate::{
    c_str::CStr,
    error::{Errno, Result},
    header::{
        dirent::{dirent, DT_DIR, DT_REG},
        errno::*,
        fcntl::{
            AT_EMPTY_PATH, AT_FDCWD, AT_REMOVEDIR, O_ACCMODE, O_APPEND, O_CLOEXEC, O_CREAT,
            O_DIRECTORY, O_EXCL, O_NONBLOCK, O_RDONLY, O_TRUNC,
        },
        sys_stat::{stat, S_IFCHR, S_IFIFO},
        sys_statvfs::statvfs,
        sys_uio::iovec,
        sys_utsname::utsname,
    },
    out::Out,
    platform::types::{c_char, c_int, mode_t, off_t},
    sync::Mutex,
};

/// Bytes the kernel reads for a path (`SYS_PATH_MAX`), its NUL included.
const PATH_MAX: usize = 256;

/// Largest transfer one node op takes (`azos_libsys::IO_MAX_BYTES`): longer
/// buffers go in several ops.
const CHUNK: usize = azos_libsys::IO_MAX_BYTES;

static CWD: Mutex<Option<Vec<u8>>> = Mutex::new(None);
static UMASK: AtomicU32 = AtomicU32::new(0o022);

/// The working directory: what the spawner gave, `/` without one.
fn cwd() -> Vec<u8> {
    CWD.lock().get_or_insert_with(|| azos_libsys::cwd().to_vec()).clone()
}

/// `path` made absolute and lexically normal, NUL-terminated.
fn normalize(base: &[u8], path: &[u8]) -> Result<Vec<u8>> {
    pure::normalize(base, path, PATH_MAX).map_err(|e| {
        Errno(match e {
            pure::PathError::Empty => ENOENT,
            pure::PathError::TooLong => ENAMETOOLONG,
        })
    })
}

/// The absolute NUL-terminated form of `path` as seen from the working directory.
pub(crate) fn resolve_cwd(path: &[u8]) -> Result<Vec<u8>> {
    resolve(AT_FDCWD, path)
}

/// The working directory, absolute and NUL-terminated.
pub(crate) fn cwd_abs() -> Vec<u8> {
    let mut c = cwd();
    c.push(0);
    c
}

/// The absolute NUL-terminated form of `path` as seen from `dirfd`. A relative
/// path under a real `dirfd` has no native meaning (a directory has no handle to
/// anchor it), so it is refused rather than joined onto a remembered name.
fn resolve(dirfd: c_int, path: &[u8]) -> Result<Vec<u8>> {
    if path.first() == Some(&b'/') {
        return normalize(b"/", path);
    }
    if dirfd == AT_FDCWD {
        return normalize(&cwd(), path);
    }
    let dir = fdtab::get(dirfd)?;
    if dir.kind != Kind::Dir {
        return Err(Errno(ENOTDIR));
    }
    nosys()
}

/// What the domain's stat op says of an absolute path.
struct Native {
    size: u64,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    atime: u64,
    mtime: u64,
    ctime: u64,
}

fn native_stat(path: &[u8]) -> Result<Native> {
    use azos_abi::syscall_nr::*;
    let mut b = [0u8; STAT_BYTES];
    let r = azos_libsys::stat(path, &mut b);
    if r < 0 {
        return Err(errno_of(r));
    }
    let u32at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    let u64at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    Ok(Native {
        size: u64at(STAT_OFF_SIZE),
        mode: u32at(STAT_OFF_MODE),
        nlink: u32at(STAT_OFF_NLINK),
        uid: u32at(STAT_OFF_UID),
        gid: u32at(STAT_OFF_GID),
        atime: u64at(STAT_OFF_ATIME),
        mtime: u64at(STAT_OFF_MTIME),
        ctime: u64at(STAT_OFF_CTIME),
    })
}

fn is_dir(n: &Native) -> bool {
    n.mode & azos_abi::syscall_nr::STAT_S_IFMT == azos_abi::syscall_nr::STAT_S_IFDIR
}

/// `stat` of a path given with `dirfd`. The descriptor itself (an empty path
/// with `AT_EMPTY_PATH`) can only be told apart for the console and a pipe: the
/// node ops cannot stat a file handle, and the name it was opened by is not it.
pub(crate) fn fstatat(dirfd: c_int, path: Option<CStr>, mut buf: Out<stat>, flags: c_int) -> Result<()> {
    let empty = path.is_none_or(|p| p.to_bytes().is_empty());
    let mut st = stat::default();
    if empty && flags & AT_EMPTY_PATH != 0 {
        let f = fdtab::get(dirfd)?;
        match f.kind {
            Kind::Console => st.st_mode = S_IFCHR | 0o620,
            Kind::Pipe => st.st_mode = S_IFIFO | 0o600,
            Kind::File | Kind::Dir => return nosys(),
        }
    } else {
        let p = path.ok_or(Errno(EFAULT))?;
        fill(&mut st, &native_stat(&resolve(dirfd, p.to_bytes())?)?);
    }
    buf.write(st);
    Ok(())
}

fn fill(st: &mut stat, n: &Native) {
    st.st_mode = n.mode as mode_t;
    st.st_nlink = n.nlink.max(1) as _;
    st.st_uid = n.uid as _;
    st.st_gid = n.gid as _;
    st.st_size = n.size as off_t;
    st.st_blksize = 4096;
    st.st_blocks = n.size.div_ceil(512) as _;
    st.st_atim.tv_sec = n.atime as _;
    st.st_mtim.tv_sec = n.mtime as _;
    st.st_ctim.tv_sec = n.ctime as _;
}

pub(crate) fn access(dirfd: c_int, path: CStr, _mode: c_int) -> Result<()> {
    // Existence is all the native stat can tell; rights are the handle's.
    native_stat(&resolve(dirfd, path.to_bytes())?).map(|_| ())
}

pub(crate) fn chdir(path: CStr) -> Result<()> {
    let abs = resolve(AT_FDCWD, path.to_bytes())?;
    if !is_dir(&native_stat(&abs)?) {
        return Err(Errno(ENOTDIR));
    }
    *CWD.lock() = Some(abs[..abs.len() - 1].to_vec());
    Ok(())
}

/// A directory descriptor holds no directory, only its entries: there is nothing
/// to make the working directory.
pub(crate) fn fchdir(fd: c_int) -> Result<()> {
    let f = fdtab::get(fd)?;
    if f.kind != Kind::Dir {
        return Err(Errno(ENOTDIR));
    }
    nosys()
}

pub(crate) fn getcwd(mut buf: Out<[u8]>) -> Result<()> {
    let c = cwd();
    if c.len() + 1 > buf.len() {
        return Err(Errno(ERANGE));
    }
    let mut out = c;
    out.push(0);
    buf.subslice(0, out.len()).copy_from_slice(&out);
    Ok(())
}

pub(crate) fn openat(dirfd: c_int, path: CStr, oflag: c_int, _mode: mode_t) -> Result<c_int> {
    // The native open creates a missing file and truncates an existing one but
    // cannot refuse one that exists, so "create, and fail if it is there" cannot
    // be asked of it; checking first would be a race with the open, not O_EXCL.
    if oflag & O_CREAT != 0 && oflag & O_EXCL != 0 {
        return Err(Errno(EINVAL));
    }
    let abs = resolve(dirfd, path.to_bytes())?;
    let want_dir = oflag & O_DIRECTORY != 0;
    let create = oflag & O_CREAT != 0;
    let cloexec = oflag & O_CLOEXEC != 0;
    // The stat only separates a directory (which has no native open) from a file
    // and chooses the errno of a refusal; the open below is the authority.
    match native_stat(&abs) {
        Ok(n) => {
            if is_dir(&n) {
                if oflag & O_ACCMODE != O_RDONLY {
                    return Err(Errno(EISDIR));
                }
                let f = OpenFile::dir(abs.as_slice().into(), snapshot(&abs));
                return fdtab::install(f, cloexec, 0);
            }
            if want_dir {
                return Err(Errno(ENOTDIR));
            }
        }
        Err(Errno(ENOENT)) if create && !want_dir => {}
        Err(e) => return Err(e),
    }
    // The access mode, O_CREAT and O_TRUNC are the open flags of the vfs (Linux's
    // numbers, which the headers of this platform use); O_APPEND rides along.
    let native = (oflag & (O_ACCMODE | O_CREAT | O_TRUNC | O_APPEND)) as u64;
    let h = azos_libsys::file_open_typed(&abs, native);
    if h == -1 {
        // "-1 if the open fails": the call gives no reason.
        return Err(Errno(if create { EACCES } else { ENOENT }));
    }
    let h = check(h)? as u32;
    let status = oflag & (O_ACCMODE | O_APPEND | O_NONBLOCK);
    let f = OpenFile::new(Kind::File, h, Some(abs.into()), status);
    fdtab::install(f, cloexec, 0).inspect_err(|_| {
        let _ = azos_libsys::close_typed(h);
    })
}

pub(crate) fn read(fd: c_int, buf: &mut [u8]) -> Result<usize> {
    let f = fdtab::get(fd)?;
    if !f.readable() {
        return Err(Errno(EBADF));
    }
    if buf.is_empty() {
        return Ok(0);
    }
    let len = buf.len().min(CHUNK);
    let n = &mut buf[..len];
    match f.kind {
        Kind::Console if f.handle == STDIN_STREAM => {
            check(azos_libsys::console_wait(n, azos_libsys::CONSOLE_WAIT_FOREVER))
        }
        Kind::File | Kind::Pipe => check(azos_libsys::file_read_typed(f.handle, n)),
        Kind::Dir => Err(Errno(EISDIR)),
        Kind::Console => Err(Errno(EBADF)),
    }
}

pub(crate) fn write(fd: c_int, buf: &[u8]) -> Result<usize> {
    let f = fdtab::get(fd)?;
    if !f.writable() {
        return Err(Errno(EBADF));
    }
    let mut done = 0;
    while done < buf.len() {
        let chunk = &buf[done..buf.len().min(done + CHUNK)];
        let r = match f.kind {
            Kind::Console if f.handle != STDIN_STREAM => azos_libsys::console_write(f.handle as u64, chunk),
            Kind::File | Kind::Pipe => azos_libsys::file_write_typed(f.handle, chunk),
            Kind::Dir => return Err(Errno(EISDIR)),
            Kind::Console => return Err(Errno(EBADF)),
        };
        match check(r) {
            Ok(0) => break,
            Ok(n) => done += n,
            // A partial transfer is a success; the error is for the next call.
            Err(_) if done > 0 => break,
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}

pub(crate) unsafe fn readv(fd: c_int, iov: *const iovec, iovcnt: c_int) -> Result<usize> {
    let iov = unsafe { core::slice::from_raw_parts(iov, usize::try_from(iovcnt).map_err(|_| Errno(EINVAL))?) };
    let mut total = 0;
    for v in iov {
        let b = unsafe { core::slice::from_raw_parts_mut(v.iov_base.cast::<u8>(), v.iov_len) };
        match read(fd, b) {
            Ok(n) => {
                total += n;
                if n < b.len() {
                    break;
                }
            }
            Err(_) if total > 0 => break,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

pub(crate) unsafe fn writev(fd: c_int, iov: *const iovec, iovcnt: c_int) -> Result<usize> {
    let iov = unsafe { core::slice::from_raw_parts(iov, usize::try_from(iovcnt).map_err(|_| Errno(EINVAL))?) };
    let mut total = 0;
    for v in iov {
        let b = unsafe { core::slice::from_raw_parts(v.iov_base.cast::<u8>(), v.iov_len) };
        match write(fd, b) {
            Ok(n) => {
                total += n;
                if n < b.len() {
                    break;
                }
            }
            Err(_) if total > 0 => break,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// The node ops carry no offset (a file is read where it was left): a seek
/// would need the filesystem interface, so no descriptor is seekable yet.
pub(crate) fn lseek(fd: c_int, _offset: off_t, _whence: c_int) -> Result<off_t> {
    fdtab::get(fd)?;
    Err(Errno(ESPIPE))
}

pub(crate) fn fsync(fd: c_int) -> Result<()> {
    let f = fdtab::get(fd)?;
    match f.kind {
        Kind::File => check(azos_libsys::fsync_typed(f.handle)).map(|_| ()),
        _ => Err(Errno(EINVAL)),
    }
}

/// The native truncate takes a path, and a file handle has no truncate op: the
/// descriptor's own file cannot be truncated, and its old name must not be.
pub(crate) fn ftruncate(fd: c_int, length: off_t) -> Result<()> {
    let f = fdtab::get(fd)?;
    if !f.writable() || f.kind != Kind::File || length < 0 {
        return Err(Errno(EINVAL));
    }
    nosys()
}

/// The name the descriptor was opened by (`F_GETPATH`): a report, which stops
/// being true if the file is renamed.
pub(crate) fn fpath(fd: c_int, out: &mut [u8]) -> Result<usize> {
    let f = fdtab::get(fd)?;
    let p = f.opened_as.as_deref().ok_or(Errno(EBADF))?;
    let n = (p.len() - 1).min(out.len());
    out[..n].copy_from_slice(&p[..n]);
    Ok(n)
}

pub(crate) fn mkdirat(dirfd: c_int, path: CStr) -> Result<()> {
    check(azos_libsys::mkdir(&resolve(dirfd, path.to_bytes())?)).map(|_| ())
}

pub(crate) fn unlinkat(dirfd: c_int, path: CStr, flags: c_int) -> Result<()> {
    let abs = resolve(dirfd, path.to_bytes())?;
    let dir = is_dir(&native_stat(&abs)?);
    if flags & AT_REMOVEDIR != 0 {
        if !dir {
            return Err(Errno(ENOTDIR));
        }
        check(azos_libsys::rmdir(&abs)).map(|_| ())
    } else if dir {
        // The native unlink takes a directory away too; POSIX unlink does not.
        Err(Errno(EISDIR))
    } else {
        check(azos_libsys::unlink(&abs)).map(|_| ())
    }
}

pub(crate) fn renameat(old_dir: c_int, old: CStr, new_dir: c_int, new: CStr) -> Result<()> {
    let from = resolve(old_dir, old.to_bytes())?;
    let to = resolve(new_dir, new.to_bytes())?;
    check(azos_libsys::rename(&from, &to)).map(|_| ())
}

/// The native statfs takes a path and a file handle has no such op (relibc's
/// `statvfs(path)` opens and comes here too): refused, not answered for the
/// name the descriptor was opened by.
pub(crate) fn fstatvfs(fd: c_int, _buf: Out<statvfs>) -> Result<()> {
    fdtab::get(fd)?;
    nosys()
}

// ── directories ──────────────────────────────────────────────────────────────

// The records are `pure`'s; they must be what relibc's `dirent` is.
const _: () = {
    assert!(offset_of!(dirent, d_ino) == pure::D_INO);
    assert!(offset_of!(dirent, d_off) == pure::D_OFF);
    assert!(offset_of!(dirent, d_reclen) == pure::D_RECLEN);
    assert!(offset_of!(dirent, d_type) == pure::D_TYPE);
    assert!(offset_of!(dirent, d_name) == pure::D_NAME);
    assert!(DT_REG as u8 == pure::DT_REG && DT_DIR as u8 == pure::DT_DIR);
};

/// The entries of the directory at `abs` as they are now, read once, when a
/// descriptor is opened on it. 0 an entry, -1 past the end.
fn snapshot(abs: &[u8]) -> Box<[DirEntry]> {
    let mut entries = Vec::new();
    loop {
        let mut name = [0u8; azos_libsys::READDIR_NAME_BYTES];
        let (mut size, mut dir) = (0u32, 0u32);
        if azos_libsys::readdir(abs, entries.len() as u64, &mut name, &mut size, &mut dir) != 0 {
            break;
        }
        let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        entries.push(DirEntry { name: name[..len].into(), is_dir: dir != 0 });
    }
    entries.into()
}

/// Fill `buf` with the entries of directory `f` from index `first`; the
/// bytes written. 0 at the end of the directory.
fn read_entries(f: &OpenFile, buf: &mut [u8], first: u64) -> Result<usize> {
    if f.kind != Kind::Dir {
        return Err(Errno(ENOTDIR));
    }
    pure::pack_dirents(&f.entries, first, buf).map_err(|_| Errno(EINVAL))
}

pub(crate) fn getdents(fd: c_int, buf: &mut [u8], opaque_offset: u64) -> Result<usize> {
    read_entries(&*fdtab::get(fd)?, buf, opaque_offset)
}

pub(crate) fn dir_seek(fd: c_int, opaque_offset: u64) -> Result<()> {
    // Entries are read by index and `getdents` is handed the next one: nothing
    // to reposition, only the descriptor to check.
    let f = fdtab::get(fd)?;
    f.dpos.store(opaque_offset, Ordering::Relaxed);
    Ok(())
}

pub(crate) fn posix_getdents(fd: c_int, buf: &mut [u8]) -> Result<usize> {
    let f = fdtab::get(fd)?;
    let n = read_entries(&f, buf, f.dpos.load(Ordering::Relaxed))?;
    // The next index is the last record's d_off.
    let mut at = 0;
    let mut next = f.dpos.load(Ordering::Relaxed);
    while at < n {
        let (rl, off) = dent_reclen_offset(&buf[at..n]).ok_or(Errno(EIO))?;
        next = off;
        at += rl as usize;
    }
    f.dpos.store(next, Ordering::Relaxed);
    Ok(n)
}

pub(crate) fn dent_reclen_offset(this_dent: &[u8]) -> Option<(u16, u64)> {
    pure::read_dirent(this_dent)
}

// ── process-wide file state ────────────────────────────────────────────────────

pub(crate) fn umask(mask: mode_t) -> mode_t {
    // Modes do not exist on the native volumes; the mask is kept so a program
    // that reads it back sees what it set.
    UMASK.swap(mask & 0o777, Ordering::Relaxed) as mode_t
}

pub(crate) fn uname(mut out: Out<utsname>) -> Result<()> {
    fn put(dst: &mut [c_char], s: &[u8]) {
        for (d, &b) in dst.iter_mut().zip(s.iter().chain(core::iter::once(&0))) {
            *d = b as c_char;
        }
    }
    // SAFETY: `utsname` is arrays of `c_char`; all-zero is a valid, empty value.
    let mut u: utsname = unsafe { core::mem::zeroed() };
    put(&mut u.sysname, b"AzOS");
    put(&mut u.nodename, b"azos");
    let mut rel = *b"abi-0";
    rel[4] = b'0' + (azos_abi::ABI_VERSION % 10) as u8;
    put(&mut u.release, &rel);
    put(&mut u.version, b"native");
    put(
        &mut u.machine,
        if cfg!(target_arch = "riscv64") {
            b"riscv64"
        } else if cfg!(target_arch = "aarch64") {
            b"aarch64"
        } else {
            b"x86_64"
        },
    );
    out.write(u);
    Ok(())
}
