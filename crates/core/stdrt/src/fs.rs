// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Files and directories over the node ops of a handle: the `*at` ops beneath
//! the task's root `Cap<Dir>` (`NODE_OPENAT`, `NODE_STATAT`, `NODE_READDIR`,
//! `NODE_MKDIRAT`, ...) and the ops of an open file (`NODE_READ`, `NODE_WRITE`,
//! `NODE_SEEK`, ...).
//!
//! The kernel keeps no working directory and takes no absolute path, so this
//! module keeps the working directory (the spawner's, until a program changes it)
//! and makes every path absolute and lexically normal ([`crate::fspure`]) before
//! it names it beneath the root `Cap<Dir>`: a path can only reach what that
//! capability, and the write trees of the task's row, allow. There is no ambient
//! authority here: a task whose row grants no root directory opens nothing.
//!
//! A file handle has read, write, seek and fsync; its size, type and times are
//! the stat of a *name*. A call on an open file that would need the name is not
//! answered for the name the file was opened by (it may by then belong to another
//! file): `std` gets `Unsupported` for it.
//!
//! The results are the native codes (negative); the std overlay turns them into
//! `io::ErrorKind`s.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::fspure::{normalize, parent_of, AbsPath, PathError, Stat, PATH_MAX};
use crate::start::{cap_lookup, cwd as startup_cwd};
use crate::sys::{invoke, syscall6};
use azos_abi::cap::ty;
use azos_abi::invoke as inv;
use azos_abi::syscall_nr::{READDIR_NAME_BYTES, STAT_BYTES, SYS_CAP_CLOSE};

pub use crate::console::IO_MAX;

/// The buffer [`readdir`] fills with a name.
pub const NAME_BYTES: usize = READDIR_NAME_BYTES;

const ENOENT: isize = -2;
const EACCES: isize = -13;
const EINVAL: isize = -22;
pub const ENAMETOOLONG: isize = -36;
const ENOTDIR: isize = -20;

static ROOT: AtomicU32 = AtomicU32::new(0);

/// This task's root `Cap<Dir>`, looked up once; `ENOENT` when its row grants none.
fn root() -> Result<u32, isize> {
    let h = ROOT.load(Ordering::Relaxed);
    if h != 0 {
        return Ok(h);
    }
    let r = cap_lookup(ty::FILE.raw(), inv::ROOT_DIR_RESOURCE);
    if r > 0 {
        ROOT.store(r as u32, Ordering::Relaxed);
        Ok(r as u32)
    } else {
        // A row with no root directory grants no file access: a refusal, not a missing file.
        Err(if r < 0 { r } else { EACCES })
    }
}

// ── the working directory ────────────────────────────────────────────────────

static CWD_LOCK: AtomicBool = AtomicBool::new(false);

/// The working directory, once read from the startup block.
#[derive(Clone, Copy)]
enum Cwd {
    Unset,
    Set(AbsPath),
    /// The spawner's directory does not fit a path: relative names fail instead of meaning `/`.
    TooLong,
}

static mut CWD: Cwd = Cwd::Unset;

fn with_cwd<T>(f: impl FnOnce(&mut Cwd) -> T) -> T {
    while CWD_LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    // SAFETY: the flag above is the lock.
    let r = f(unsafe { &mut *core::ptr::addr_of_mut!(CWD) });
    CWD_LOCK.store(false, Ordering::Release);
    r
}

/// The working directory: the spawner's, or what a program changed it to;
/// `ENAMETOOLONG` when the spawner's does not fit a path.
pub fn getcwd() -> Result<AbsPath, isize> {
    with_cwd(|c| {
        if let Cwd::Unset = *c {
            *c = normalize(b"/", startup_cwd()).map_or(Cwd::TooLong, Cwd::Set);
        }
        match *c {
            Cwd::Set(p) => Ok(p),
            _ => Err(ENAMETOOLONG),
        }
    })
}

fn path_err(e: PathError) -> isize {
    match e {
        PathError::Empty => ENOENT,
        PathError::Nul => EINVAL,
        PathError::TooLong => ENAMETOOLONG,
    }
}

/// `path` made absolute against the working directory.
pub fn resolve(path: &[u8]) -> Result<AbsPath, isize> {
    // An absolute name needs no working directory, so a poisoned one still opens those.
    if path.first() == Some(&b'/') {
        return normalize(b"/", path).map_err(path_err);
    }
    let base = getcwd()?;
    normalize(base.bytes(), path).map_err(path_err)
}

/// Make `path` the working directory; it must be a directory.
pub fn chdir(path: &[u8]) -> Result<(), isize> {
    let abs = resolve(path)?;
    if !stat_abs(&abs)?.is_dir() {
        return Err(ENOTDIR);
    }
    with_cwd(|c| *c = Cwd::Set(abs));
    Ok(())
}

/// The root directory and the name of `abs` beneath it (`.` for `/` itself), NUL-terminated.
fn beneath(abs: &AbsPath) -> Result<(u32, &[u8]), isize> {
    let name = crate::pure::below_root(abs.with_nul());
    Ok((root()?, if name.first() == Some(&0) { b".\0" } else { name }))
}

fn done(rc: isize) -> Result<(), isize> {
    if rc >= 0 { Ok(()) } else { Err(rc) }
}

// ── names ────────────────────────────────────────────────────────────────────

fn stat_abs(abs: &AbsPath) -> Result<Stat, isize> {
    let (dir, name) = beneath(abs)?;
    let mut b = [0u8; STAT_BYTES];
    done(invoke(dir, inv::NODE_STATAT, [name.as_ptr() as u64, b.as_mut_ptr() as u64, 0, 0]).0)?;
    Ok(Stat::decode(&b))
}

/// The stat record of `path`.
pub fn stat(path: &[u8]) -> Result<Stat, isize> {
    stat_abs(&resolve(path)?)
}

/// Open `path` with the native flags of [`crate::fspure::open_flags`]: the file's handle.
pub fn open(path: &[u8], flags: u64) -> Result<u32, isize> {
    let abs = resolve(path)?;
    let (dir, name) = beneath(&abs)?;
    let h = invoke(dir, inv::NODE_OPENAT, [name.as_ptr() as u64, flags, 0, 0]).0;
    // "-1 if the open fails": the call gives no reason, so a stat names one. A name that is
    // not there is `ENOENT` (for a create, the missing parent: make it, then retry);
    // otherwise the open was refused for want of authority.
    if h == -1 {
        let creating = flags & crate::fspure::O_CREAT != 0;
        let probe = if creating { parent_of(&abs) } else { abs };
        return Err(match stat_abs(&probe) {
            Err(ENOENT) => ENOENT,
            Err(e) => e,
            Ok(_) => EACCES,
        });
    }
    if h < 0 { Err(h) } else { Ok(h as u32) }
}

/// Entry `index` of the directory `path`: its name into `name` (NUL-padded) and
/// whether it is a directory; `None` past the last entry. An entry whose name did
/// not fit the buffer is `Err(ENAMETOOLONG)`: its prefix would name another file.
pub fn readdir(path: &[u8], index: u32, name: &mut [u8; READDIR_NAME_BYTES]) -> Result<Option<bool>, isize> {
    let abs = resolve(path)?;
    let (dir, rel) = beneath(&abs)?;
    let (rc, rep) = invoke(
        dir,
        inv::NODE_READDIR,
        [rel.as_ptr() as u64, index as u64, name.as_mut_ptr() as u64, READDIR_NAME_BYTES as u64],
    );
    match rc {
        0 => Ok(None),
        1 if rep[2] != 0 => Err(ENAMETOOLONG),
        1 => Ok(Some(rep[1] != 0)),
        e => Err(e),
    }
}

pub fn mkdir(path: &[u8]) -> Result<(), isize> {
    let abs = resolve(path)?;
    let (dir, name) = beneath(&abs)?;
    done(invoke(dir, inv::NODE_MKDIRAT, [name.as_ptr() as u64, 0, 0, 0]).0)
}

/// Remove the file `path`; a directory is refused (`EISDIR`), as `unlink` does.
pub fn unlink(path: &[u8]) -> Result<(), isize> {
    let abs = resolve(path)?;
    if stat_abs(&abs)?.is_dir() {
        return Err(-21);
    }
    let (dir, name) = beneath(&abs)?;
    done(invoke(dir, inv::NODE_UNLINKAT, [name.as_ptr() as u64, 0, 0, 0]).0)
}

pub fn rmdir(path: &[u8]) -> Result<(), isize> {
    let abs = resolve(path)?;
    if !stat_abs(&abs)?.is_dir() {
        return Err(ENOTDIR);
    }
    let (dir, name) = beneath(&abs)?;
    done(invoke(dir, inv::NODE_UNLINKAT, [name.as_ptr() as u64, inv::UNLINK_DIR, 0, 0]).0)
}

pub fn rename(from: &[u8], to: &[u8]) -> Result<(), isize> {
    let (from, to) = (resolve(from)?, resolve(to)?);
    let (dir, from) = beneath(&from)?;
    let (_, to) = beneath(&to)?;
    done(invoke(dir, inv::NODE_RENAMEAT, [from.as_ptr() as u64, to.as_ptr() as u64, 0, 0]).0)
}

// ── open files ───────────────────────────────────────────────────────────────

pub fn read(h: u32, buf: &mut [u8]) -> isize {
    let len = buf.len().min(IO_MAX) as u64;
    invoke(h, inv::NODE_READ, [buf.as_mut_ptr() as u64, len, 0, 0]).0
}

pub fn write(h: u32, buf: &[u8]) -> isize {
    let len = buf.len().min(IO_MAX) as u64;
    invoke(h, inv::NODE_WRITE, [buf.as_ptr() as u64, len, 0, 0]).0
}

pub fn fsync(h: u32) -> isize {
    invoke(h, inv::NODE_FSYNC, [0; 4]).0
}

/// Reposition the file (`whence` 0 from the start, 1 from the offset, 2 from the end): the new offset.
pub fn seek(h: u32, offset: i64, whence: u64) -> isize {
    invoke(h, inv::NODE_SEEK, [offset as u64, whence, 0, 0]).0
}

pub fn close(h: u32) -> isize {
    // SAFETY: a plain call.
    unsafe { syscall6(SYS_CAP_CLOSE, h as u64, 0, 0, 0, 0, 0) }
}

/// The longest path `resolve` accepts, with its NUL.
pub const MAX_PATH: usize = PATH_MAX;
