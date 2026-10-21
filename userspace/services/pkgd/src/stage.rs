// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Where `pkgd` keeps what it stages, and the order it writes it in.
//!
//! The installer library names its files under `/fat/PKG` (`STAGE_DIR`, the
//! journal, a staged package `XXXXXXXX.PKG`). The topology declares a native
//! volume at [`STAGE_MOUNT`] (a `[volume.NAME]` row, `azvol`), and the staged
//! packages and the journal live there: this file maps the library's paths
//! onto it, and keeps the ones that must stay on the boot volume where they
//! are. With no such mount the library's paths are used as they are, on FAT32,
//! for everything but the packages: the kernel applies what is staged at boot
//! from the native volume only (`kernel/src/boot/pkg_apply.rs`; it needs the
//! snapshots and the atomic group of that volume), so `/fat/PKG` is not a place
//! to stage one (`dir_exists` says it is not) and an install without the
//! volume is refused, not staged where nothing would ever apply it.
//!
//! * `/fat/PKG/SYS_A` and `/fat/PKG/SYS_B` (a whole-system update's slot
//!   directories) stay on the boot volume: the kernel-side switch reads them
//!   there, as part of the boot (`crates/core/ota/src/update.rs`, `set_dir`).
//! * Everything else under `/fat/PKG` (staged application packages, the
//!   journal) goes to `/pkg`.
//! * `/fat/CAPS.TOM` and the other files the installer reads from the boot
//!   volume are not under `/fat/PKG` and are not touched.
//!
//! # The order, which is the atomicity
//!
//! The volume commits only when asked (`fsync`), and everything written
//! between two commits becomes durable together or not at all (see
//! `crates/fs/fs/src/azvol/mount.rs`). The installer writes a staged file
//! (`write_file`: open, write, close, no `fsync`) and then appends the
//! decision to the journal (`append`: open, write, **`fsync`**, close). The
//! journal append is the commit point of the one transaction, so a power cut
//! leaves both the staged package and its journal record, or neither; a
//! removal is the same with the unlink first. Staging an update's files, one
//! after another, ends with its journal append the same way.
//!
//! That holds whoever else has write rights on the mount, because the mount
//! fences the transaction (`azvol/mount.rs`, "who may make it so"): it belongs
//! to the task whose write opened it, which is the installer. Another task's
//! change answers `Busy` while it is open, and another task's `fsync` or
//! `sync` answers `Busy` and commits nothing, so the package cannot be made
//! durable without its journal record by a commit that is not the
//! installer's. If the installer exits mid-install, the next task to touch the
//! volume (the restarted installer) finds it as the last commit left it.
//! `pkgd` never renames on the volume (a rename is a commit point for its
//! caller).
//!
//! This file is the installer's volume, minus the two things that need ring 3:
//! the file calls ([`Files`], implemented over libsys by `main.rs`) and the
//! shared-memory and OTA calls ([`Platform`]). `tests/host/pkg-tests` compiles
//! it unchanged over the real azvol engine and runs the installer's own
//! library on top, cutting power at every device write of an install.

use azos_idl::Cap;
use azos_packages::update::{IoErr, Source, Store, NAME_BUF};
use azos_packages::{PkgMem, Read, VolErr, Volume};

/// A path longer than this is not one the installer builds.
pub const PATH_MAX: usize = 64;

/// `O_WRONLY`, `O_CREAT`, `O_TRUNC`, `O_APPEND` (`azos_fs` values).
pub const O_WRONLY: u64 = 0x1;
pub const O_CREAT: u64 = 0x40;
pub const O_TRUNC: u64 = 0x200;
pub const O_APPEND: u64 = 0x400;

/// The installer library's staging directory (`azos_packages::service::STAGE_DIR`).
const LIBRARY_ROOT: &[u8] = b"/fat/PKG";
/// Where the native volume that holds the staged packages is mounted.
pub use azos_pkg::apply::STAGE_MOUNT;
/// The slot directories of a whole-system update, which stay on the boot volume.
const BOOT_SETS: [&[u8]; 2] = [b"/fat/PKG/SYS_A", b"/fat/PKG/SYS_B"];

/// What `unlink` came to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Unlinked {
    Done,
    /// There was no such file.
    Missing,
    Failed,
}

/// The file calls the installer makes on the volume. Paths are plain bytes
/// (no NUL), absolute; handles are the kernel's `u32`.
pub trait Files {
    fn open(&mut self, path: &[u8], flags: u64) -> Option<u32>;
    fn read(&mut self, h: u32, buf: &mut [u8]) -> Result<usize, ()>;
    /// Bytes written (a short write is the caller's to repeat).
    fn write(&mut self, h: u32, data: &[u8]) -> Result<usize, ()>;
    /// Make the writes of the volume durable (`fsync`).
    fn sync(&mut self, h: u32) -> Result<(), ()>;
    fn close(&mut self, h: u32) -> Result<(), ()>;
    fn unlink(&mut self, path: &[u8]) -> Unlinked;
    /// Is there a file or directory at `path`?
    fn exists(&mut self, path: &[u8]) -> bool;
    fn mkdir(&mut self, path: &[u8]) -> bool;
    /// The `index`-th entry of `dir` as the volume lists it: its name into
    /// `name`, its length. A FAT32 subdirectory lists `.` and `..` first (the
    /// kernel's `readdir` returns them); [`Paths`] leaves them out of the
    /// installer's view.
    fn entry(&mut self, dir: &[u8], index: usize, name: &mut [u8; NAME_BUF]) -> Option<usize>;
}

/// What the volume needs of the machine besides files: the client's memory
/// objects, the OTA endpoint and the clock.
pub trait Platform {
    type Bundle: Source;
    fn read_package(&mut self, cap: Cap<PkgMem>, len: usize, buf: &mut [u8]) -> Result<usize, VolErr>;
    fn open_bundle(&mut self, cap: Cap<PkgMem>, len: usize) -> Result<Self::Bundle, VolErr>;
    fn boot_slots(&mut self) -> Option<(u8, u8)>;
    fn now_ns(&mut self) -> u64;
}

/// The installer's paths on the files: the mapping and the file-level
/// operations the library asks for. Also the volume's [`Store`] (a reader).
#[derive(Clone)]
pub struct Paths<F> {
    files: F,
    /// The staging volume is mounted: the library's paths are mapped to it.
    volume: bool,
}

/// `path` under `root`: equal, or `root` and a `/`.
fn under(path: &[u8], root: &[u8]) -> bool {
    path.starts_with(root) && (path.len() == root.len() || path[root.len()] == b'/')
}

impl<F: Files> Paths<F> {
    /// The installer's volume over `files`: on the native volume if one is
    /// mounted at [`STAGE_MOUNT`], on the boot volume otherwise.
    pub fn new(mut files: F) -> Self {
        let volume = files.exists(STAGE_MOUNT);
        Paths { files, volume }
    }

    /// Is the staging volume in use?
    pub fn on_volume(&self) -> bool {
        self.volume
    }

    /// The path the library's `path` is stored at, in `out`. `None` when it
    /// does not fit.
    fn route<'a>(&self, path: &'a [u8], out: &'a mut [u8; PATH_MAX]) -> Option<&'a [u8]> {
        if self.volume && under(path, LIBRARY_ROOT) && !BOOT_SETS.iter().any(|s| under(path, s)) {
            let rest = &path[LIBRARY_ROOT.len()..];
            let n = STAGE_MOUNT.len() + rest.len();
            if n > PATH_MAX {
                return None;
            }
            out[..STAGE_MOUNT.len()].copy_from_slice(STAGE_MOUNT);
            out[STAGE_MOUNT.len()..n].copy_from_slice(rest);
            return Some(&out[..n]);
        }
        if path.len() > PATH_MAX {
            return None;
        }
        Some(path)
    }

    fn open(&mut self, path: &[u8], flags: u64) -> Result<u32, VolErr> {
        let mut buf = [0u8; PATH_MAX];
        let p = self.route(path, &mut buf).ok_or(VolErr::Io)?;
        self.files.open(p, flags).ok_or(VolErr::Missing)
    }

    fn write_all(&mut self, h: u32, data: &[u8]) -> Result<(), VolErr> {
        let mut at = 0;
        while at < data.len() {
            match self.files.write(h, &data[at..]) {
                Ok(n) if n > 0 => at += n,
                _ => return Err(VolErr::Io),
            }
        }
        Ok(())
    }

    /// Fill `buf` from handle `h`; `more` says the file goes on past it.
    fn read_up_to(&mut self, h: u32, buf: &mut [u8]) -> Result<Read, VolErr> {
        let mut n = 0;
        while n < buf.len() {
            match self.files.read(h, &mut buf[n..]) {
                Err(()) => return Err(VolErr::Io),
                Ok(0) => return Ok(Read { n, more: false }),
                Ok(r) => n += r,
            }
        }
        // The buffer is full: is there a byte after it?
        let mut probe = [0u8; 1];
        match self.files.read(h, &mut probe) {
            Err(()) => Err(VolErr::Io),
            Ok(0) => Ok(Read { n, more: false }),
            Ok(_) => Ok(Read { n, more: true }),
        }
    }

    /// Create or replace the file at `path` with `data`. **Not durable on
    /// return**: it joins the volume's open transaction, which the next
    /// [`append`](Self::append) commits.
    pub fn write_file(&mut self, path: &[u8], data: &[u8]) -> Result<(), VolErr> {
        let h = self.open(path, O_WRONLY | O_CREAT | O_TRUNC).map_err(|_| VolErr::Io)?;
        let r = self.write_all(h, data);
        let c = self.files.close(h);
        r.and(c.map_err(|()| VolErr::Io))
    }

    /// Append `data` to the file at `path`, creating it, and make the volume's
    /// transaction durable: everything written since the last commit, this
    /// record included, or nothing.
    pub fn append(&mut self, path: &[u8], data: &[u8]) -> Result<(), VolErr> {
        let h = self.open(path, O_WRONLY | O_CREAT | O_APPEND).map_err(|_| VolErr::Io)?;
        let r = self.write_all(h, data).and_then(|()| self.files.sync(h).map_err(|()| VolErr::Io));
        let c = self.files.close(h);
        r.and(c.map_err(|()| VolErr::Io))
    }

    pub fn read_file(&mut self, path: &[u8], buf: &mut [u8]) -> Result<Read, VolErr> {
        let h = self.open(path, 0)?;
        let r = self.read_up_to(h, buf);
        let _ = self.files.close(h);
        r
    }

    pub fn dir_exists(&mut self, dir: &[u8]) -> bool {
        // Packages are staged on the native volume only (see the module doc).
        if !self.volume && dir == LIBRARY_ROOT {
            return false;
        }
        let mut buf = [0u8; PATH_MAX];
        match self.route(dir, &mut buf) {
            Some(p) => self.files.exists(p),
            None => false,
        }
    }
}

impl<F: Files + Clone> Store for Paths<F> {
    fn open_read(&mut self, path: &[u8]) -> Result<u32, IoErr> {
        self.open(path, 0).map_err(|_| IoErr::Missing)
    }

    fn read(&mut self, h: u32, buf: &mut [u8]) -> Result<usize, IoErr> {
        self.files.read(h, buf).map_err(|()| IoErr::Io)
    }

    fn open_write(&mut self, path: &[u8]) -> Result<u32, IoErr> {
        self.open(path, O_WRONLY | O_CREAT | O_TRUNC).map_err(|_| IoErr::Io)
    }

    fn write(&mut self, h: u32, data: &[u8]) -> Result<(), IoErr> {
        self.write_all(h, data).map_err(|_| IoErr::Io)
    }

    fn close(&mut self, h: u32) -> Result<(), IoErr> {
        self.files.close(h).map_err(|()| IoErr::Io)
    }

    fn remove(&mut self, path: &[u8]) -> Result<(), IoErr> {
        let mut buf = [0u8; PATH_MAX];
        let p = self.route(path, &mut buf).ok_or(IoErr::Io)?;
        match self.files.unlink(p) {
            Unlinked::Done => Ok(()),
            Unlinked::Missing => Err(IoErr::Missing),
            Unlinked::Failed => Err(IoErr::Io),
        }
    }

    fn ensure_dir(&mut self, path: &[u8]) -> Result<(), IoErr> {
        let mut buf = [0u8; PATH_MAX];
        let p = self.route(path, &mut buf).ok_or(IoErr::Io)?;
        if self.files.exists(p) || self.files.mkdir(p) { Ok(()) } else { Err(IoErr::Io) }
    }

    fn entry(&mut self, dir: &[u8], index: usize, name: &mut [u8; NAME_BUF]) -> Option<usize> {
        let mut buf = [0u8; PATH_MAX];
        let p = self.route(dir, &mut buf)?;
        // `.` and `..` are the volume's, not entries of the directory: a
        // listing that returned them made `clear_dir` try to remove the
        // directory itself (the kernel-side store skips them the same way).
        let mut real = 0;
        for listed in 0.. {
            let len = self.files.entry(p, listed, name)?;
            if matches!(&name[..len], b"." | b"..") {
                continue;
            }
            if real == index {
                return Some(len);
            }
            real += 1;
        }
        None
    }
}

/// The installer's volume: [`Paths`] and the platform.
pub struct Stage<F, P> {
    pub paths: Paths<F>,
    pub plat: P,
}

// Open authority gap: this store takes the default `Store::may_apply` (every step
// goes), so a Domain whose `ota` envelope row holds it can still stage through
// this program. Documentation/effects.md, "Configuration, update and
// real-time-time envelopes".
impl<F: Files + Clone, P: Platform> Store for Stage<F, P> {
    fn open_read(&mut self, path: &[u8]) -> Result<u32, IoErr> {
        self.paths.open_read(path)
    }
    fn read(&mut self, h: u32, buf: &mut [u8]) -> Result<usize, IoErr> {
        Store::read(&mut self.paths, h, buf)
    }
    fn open_write(&mut self, path: &[u8]) -> Result<u32, IoErr> {
        self.paths.open_write(path)
    }
    fn write(&mut self, h: u32, data: &[u8]) -> Result<(), IoErr> {
        Store::write(&mut self.paths, h, data)
    }
    fn close(&mut self, h: u32) -> Result<(), IoErr> {
        Store::close(&mut self.paths, h)
    }
    fn remove(&mut self, path: &[u8]) -> Result<(), IoErr> {
        self.paths.remove(path)
    }
    fn ensure_dir(&mut self, path: &[u8]) -> Result<(), IoErr> {
        self.paths.ensure_dir(path)
    }
    fn entry(&mut self, dir: &[u8], index: usize, name: &mut [u8; NAME_BUF]) -> Option<usize> {
        self.paths.entry(dir, index, name)
    }
}

impl<F: Files + Clone, P: Platform> Volume for Stage<F, P> {
    type Bundle = P::Bundle;
    type Reader = Paths<F>;

    fn reader(&mut self) -> Paths<F> {
        self.paths.clone()
    }

    fn read_file(&mut self, path: &[u8], buf: &mut [u8]) -> Result<Read, VolErr> {
        self.paths.read_file(path, buf)
    }

    fn read_package(&mut self, cap: Cap<PkgMem>, len: usize, buf: &mut [u8]) -> Result<usize, VolErr> {
        self.plat.read_package(cap, len, buf)
    }

    fn open_bundle(&mut self, cap: Cap<PkgMem>, len: usize) -> Result<P::Bundle, VolErr> {
        self.plat.open_bundle(cap, len)
    }

    fn boot_slots(&mut self) -> Option<(u8, u8)> {
        self.plat.boot_slots()
    }

    fn write_file(&mut self, path: &[u8], data: &[u8]) -> Result<(), VolErr> {
        self.paths.write_file(path, data)
    }

    fn append(&mut self, path: &[u8], data: &[u8]) -> Result<(), VolErr> {
        self.paths.append(path, data)
    }

    fn dir_exists(&mut self, dir: &[u8]) -> bool {
        self.paths.dir_exists(dir)
    }

    fn now_ns(&mut self) -> u64 {
        self.plat.now_ns()
    }
}
