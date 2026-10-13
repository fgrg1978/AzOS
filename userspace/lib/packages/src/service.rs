// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The installer's pure half: the [`Packages`](crate::Packages) service over a
//! volume it does not own.
//!
//! Everything the installer does to the world goes through [`Volume`], so the
//! host suite runs it over a map of files and `pkgd` runs it over libsys. The
//! rest is `azos_pkg` and `azos_topology`: the signed topology is read off the
//! volume and verified against the topology key like the kernel does at boot
//! (`signed::fill_signed`, with no device or counter policy: a ring-3 program
//! cannot know the device record, so the installer checks neither the device id
//! nor the counter floor, and nothing else does for a package yet), the packages
//! already staged are merged into it, and the candidate is judged against the
//! result.
//!
//! # Memory
//!
//! One [`Work`] holds every buffer, and a [`Topology`] beside it; the program
//! places both in statics (the buffers are all zero, so they are `.bss`; the
//! topology is not, a `MaybeStr` of nothing is a dangling pointer, so it is
//! `.data`, and its size is the Kconfig tables'). A request reloads the topology
//! from the volume (its text is borrowed from the buffers, so each request
//! clears the topology before the buffers are overwritten: [`parts`]).

use azos_decision::{ProvenanceRecord, Rule, Verdict};
use azos_idl::Cap;
use azos_pkg::container::{ParseError, HEADER_LEN, KEY_LEN_MAX, SIG_LEN_MAX};
use azos_pkg::{admit, receipt, verify, verify_head, Device, Package, Refusal};
use azos_topology::signed::{fill_signed, DeviceContext, SignedFiles};
use azos_topology::{Topology, CAPS_SIG_PATH, CAPS_TOML_PATH, SCHED_TOML_PATH};

use crate::{id_words, io, status, step, words_id, Packages, PkgMem};

/// Where packages are staged.
pub const STAGE_DIR: &[u8] = b"/fat/PKG";
/// The install journal: `ProvenanceRecord` wire records, appended.
pub const JOURNAL: &[u8] = b"/fat/PKG/JOURNAL.BIN";

const META_MAX: usize = azos_limits::PKG_META_MAX_KB as usize * 1024;
/// Packages staged at once (Kconfig `PKG_MAX_STAGED`).
pub const MAX_STAGED: usize = azos_limits::PKG_MAX_STAGED as usize;
/// The package buffer (Kconfig `PKG_MAX_KB`).
pub const PKG_BUF: usize = azos_limits::PKG_MAX_KB as usize * 1024;
/// What the installer reads of a staged package: everything but the images.
pub const HEAD_BUF: usize = HEADER_LEN + KEY_LEN_MAX + SIG_LEN_MAX + 2 * META_MAX;
const CAPS_BUF: usize = azos_limits::TOPOLOGY_CAPS_MAX_KB as usize * 1024;
const SCHED_BUF: usize = azos_limits::TOPOLOGY_SCHED_MAX_KB as usize * 1024;
/// Directory entries one scan reads before it stops.
const SCAN_MAX: usize = 4 * MAX_STAGED + 8;

/// Why the volume refused an access.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VolErr {
    /// No such file.
    Missing,
    /// Anything else.
    Io,
    /// More bytes than the buffer holds.
    TooLarge,
}

/// A read: how many bytes, and whether the file has more than the buffer held.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Read {
    /// Bytes read.
    pub n: usize,
    /// The buffer was filled and the file goes on.
    pub more: bool,
}

/// What the installer needs of the machine.
pub trait Volume {
    /// The file at `path`, from its start, into `buf`.
    fn read_file(&mut self, path: &[u8], buf: &mut [u8]) -> Result<Read, VolErr>;
    /// The first `len` bytes of the memory object `cap` names, copied into
    /// `buf` (the client keeps its own mapping, so what is read must be copied
    /// before it is checked), and release the capability whatever happens: the
    /// installer owns what a client gave it. `Err(TooLarge)` when `len` does
    /// not fit `buf`, `Err(Io)` when the object holds fewer than `len` bytes.
    /// The bytes read.
    fn read_package(&mut self, cap: Cap<PkgMem>, len: usize, buf: &mut [u8]) -> Result<usize, VolErr>;
    /// Create or replace the file at `path` with `data`.
    fn write_file(&mut self, path: &[u8], data: &[u8]) -> Result<(), VolErr>;
    /// Append `data` to the file at `path`, creating it.
    fn append(&mut self, path: &[u8], data: &[u8]) -> Result<(), VolErr>;
    /// Remove the file at `path`.
    fn remove(&mut self, path: &[u8]) -> Result<(), VolErr>;
    /// The `index`-th entry of directory `dir`: its name into `name`, its
    /// length; `None` past the last.
    fn entry(&mut self, dir: &[u8], index: usize, name: &mut [u8; 64]) -> Option<usize>;
    /// Does directory `dir` exist? The installer never creates one: its
    /// authority is a tree *inside* `/fat/PKG`, which cannot make `/fat/PKG`
    /// itself, so the volume is provisioned with it (the build's `mmd`).
    fn dir_exists(&mut self, dir: &[u8]) -> bool;
    /// The clock, in nanoseconds, for the journal.
    fn now_ns(&mut self) -> u64;
}

/// Every buffer of the installer. Large, all zero: place it in a static.
pub struct Work {
    pkg: [u8; PKG_BUF],
    head: [u8; HEAD_BUF],
    caps: [u8; CAPS_BUF],
    sig: [u8; 64],
    sched: [u8; SCHED_BUF],
    arena: [u8; MAX_STAGED * META_MAX],
}

struct Parts<'r> {
    pkg: &'r mut [u8],
    head: &'r mut [u8],
    caps: &'r mut [u8],
    sig: &'r mut [u8],
    sched: &'r mut [u8],
    arena: &'r mut [u8],
    topo: &'r mut Topology<'r>,
}

impl Work {
    /// Empty buffers.
    pub const fn new() -> Self {
        Self {
            pkg: [0; PKG_BUF],
            head: [0; HEAD_BUF],
            caps: [0; CAPS_BUF],
            sig: [0; 64],
            sched: [0; SCHED_BUF],
            arena: [0; MAX_STAGED * META_MAX],
        }
    }
}

/// The buffers, and the topology emptied: it is about to borrow from them.
fn parts<'r>(w: &'r mut Work, topo: &'r mut Topology<'static>) -> Parts<'r> {
    topo.clear();
    // SAFETY: `topo` holds `MaybeStr`s that point into `caps`, `sched` and
    // `arena`, and nothing else; the service is the only path to either, its
    // `&mut` keeps them from being reached twice, and the topology was emptied
    // above before any buffer is handed out to be overwritten. The lifetime it
    // is handed out with is the request's, so safe code cannot keep a
    // reference into it past the next `parts()`.
    let topo = unsafe { core::mem::transmute::<&mut Topology<'static>, &mut Topology<'_>>(topo) };
    Parts {
        pkg: &mut w.pkg,
        head: &mut w.head,
        caps: &mut w.caps,
        sig: &mut w.sig,
        sched: &mut w.sched,
        arena: &mut w.arena,
        topo,
    }
}

impl Default for Work {
    fn default() -> Self {
        Self::new()
    }
}

/// The installer: a volume, its buffers, the topology key and the device.
pub struct Service<'w, V: Volume> {
    /// The volume.
    pub vol: V,
    work: &'w mut Work,
    topo: &'w mut Topology<'static>,
    key: [u8; 32],
    dev: Device<'w>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Admit,
    Install,
}

impl<'w, V: Volume> Service<'w, V> {
    /// An installer over `vol`, with its buffers and its topology. `key` is the topology key the signed CAPS.TOM
    /// is verified with (`azos_topology::TRUSTED_PUBKEY` in `pkgd`), `dev`
    /// what packages are admitted against.
    pub fn new(vol: V, work: &'w mut Work, topo: &'w mut Topology<'static>, key: [u8; 32], dev: Device<'w>) -> Self {
        Self { vol, work, topo, key, dev }
    }

    fn request(&mut self, cap: Cap<PkgMem>, len: u32, mode: Mode) -> [u64; 4] {
        let now = self.vol.now_ns();
        let Self { vol, work, topo, key, dev } = self;
        install_or_admit(vol, parts(work, topo), key, dev, (cap, len as usize), mode, now)
    }
}

impl<V: Volume> Packages for Service<'_, V> {
    fn admit(&mut self, pkg: Cap<PkgMem>, len: u32) -> [u64; 4] {
        self.request(pkg, len, Mode::Admit)
    }

    fn install(&mut self, pkg: Cap<PkgMem>, len: u32) -> [u64; 4] {
        self.request(pkg, len, Mode::Install)
    }

    fn remove(&mut self, id: [u64; 4]) -> [u64; 4] {
        let now = self.vol.now_ns();
        let want = words_id(&id);
        let head = &mut self.work.head[..];
        let mut i = 0;
        while let Some((path, pk)) = staged_at(&mut self.vol, head, &mut i) {
            if pk.id() != want {
                continue;
            }
            if self.vol.remove(&path.bytes()).is_err() {
                return [status(step::IO, io::REMOVE), receipt::id_prefix(&want), 0, 0];
            }
            let rows = azos_pkg::Meta::parse(pk.meta).map_or(0, |m| m.images().len() as u32);
            let mut rec = ProvenanceRecord::new(Rule::PackageInstall as u8, Verdict::Deny as u8, rows, [rows as u64, 0, 0]);
            rec.image_hash_prefix = receipt::id_prefix(&want);
            rec.clock_ns = now;
            // A removal that cannot be recorded is still a removal; say so.
            if self.vol.append(JOURNAL, &rec.to_bytes()).is_err() {
                return [status(step::IO, io::JOURNAL), receipt::id_prefix(&want), rows as u64, 0];
            }
            return [0, receipt::id_prefix(&want), rows as u64, 0];
        }
        [status(step::NOT_STAGED, 0), receipt::id_prefix(&want), 0, 0]
    }

    fn installed(&mut self, index: u32) -> [u64; 4] {
        let head = &mut self.work.head[..];
        let (mut i, mut n) = (0, 0u32);
        while let Some((_, pk)) = staged_at(&mut self.vol, head, &mut i) {
            if n == index {
                return id_words(&pk.id());
            }
            n += 1;
        }
        [0; 4]
    }
}

/// `/fat/PKG/XXXXXXXX.PKG`: the staged file of a package. The 8.3 name holds
/// four bytes of the package id in upper-case hex, so two packages can share
/// one: [`StagePath::of_id`] takes `try_` windows of the id in turn (bytes
/// `4*try_..4*try_+4`) and the installer stages at the first one that is free
/// or already this package's, never over another package's file.
struct StagePath {
    b: [u8; 21],
}

/// Names one id can have (the 32 bytes of an id, four to a name).
const STAGE_NAMES: usize = 8;

impl StagePath {
    fn of_id(id: &[u8; 32], try_: usize) -> Self {
        let mut b = *b"/fat/PKG/00000000.PKG";
        for (i, byte) in id[4 * try_..4 * try_ + 4].iter().enumerate() {
            b[9 + 2 * i] = b"0123456789ABCDEF"[(byte >> 4) as usize];
            b[10 + 2 * i] = b"0123456789ABCDEF"[(byte & 15) as usize];
        }
        Self { b }
    }

    fn of_name(name: &[u8]) -> Self {
        let mut b = *b"/fat/PKG/00000000.PKG";
        b[9..].copy_from_slice(name);
        Self { b }
    }

    fn bytes(&self) -> [u8; 21] {
        self.b
    }
}

/// Where `id` is staged: the first of its names that holds no package or
/// holds this one. A file there that is not a package parses to nothing and is
/// free (the installer owns the directory and nothing reads it). `Err(true)`
/// when `id` is staged at that name already, `Err(false)` when every name is
/// another package's.
fn stage_path<V: Volume>(vol: &mut V, head: &mut [u8], id: &[u8; 32]) -> Result<StagePath, bool> {
    for t in 0..STAGE_NAMES {
        let path = StagePath::of_id(id, t);
        match vol.read_file(&path.bytes(), head) {
            Err(VolErr::Missing) => return Ok(path),
            // A name that cannot be read is not known to be free.
            Err(_) => {}
            Ok(r) => match Package::parse_head(&head[..r.n]) {
                Err(_) => return Ok(path),
                Ok(p) if p.id() == *id => return Err(true),
                Ok(_) => {}
            },
        }
    }
    Err(false)
}

/// Is a directory entry the name a staged package has?
fn staged_name(n: &[u8]) -> bool {
    n.len() == 12 && n[8..] == *b".PKG" && n[..8].iter().all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(c))
}

/// The next staged package at or after directory index `*i`: its path and its
/// head (read into `head`, parsed, NOT verified: the caller decides what that
/// is worth). `*i` is left after the entry.
fn staged_at<'h, V: Volume>(vol: &mut V, head: &'h mut [u8], i: &mut usize) -> Option<(StagePath, Package<'h>)> {
    let mut name = [0u8; 64];
    // The borrow of `head` that the returned package keeps is made once, at
    // the end, from the bytes the successful read left there.
    let (path, n) = loop {
        if *i >= SCAN_MAX {
            return None;
        }
        let len = vol.entry(STAGE_DIR, *i, &mut name)?;
        *i += 1;
        if !staged_name(&name[..len]) {
            continue;
        }
        let path = StagePath::of_name(&name[..len]);
        let Ok(r) = vol.read_file(&path.bytes(), head) else { continue };
        if Package::parse_head(&head[..r.n]).is_ok() {
            break (path, r.n);
        }
    };
    let pk = Package::parse_head(&head[..n]).ok()?;
    Some((path, pk))
}

fn pkg_status(r: &Refusal) -> u64 {
    r.code()
}

/// The reply of a refused package, journalled when it was an install.
fn refuse<V: Volume>(vol: &mut V, mode: Mode, id: &[u8; 32], signer: u64, r: Refusal, now: u64) -> [u64; 4] {
    if mode == Mode::Install {
        let rec = receipt::refused(id, signer, &r, now);
        // The refusal is the answer whether or not it could be written down.
        let _ = vol.append(JOURNAL, &rec.to_bytes());
    }
    [pkg_status(&r), receipt::id_prefix(id), 0, signer]
}

fn install_or_admit<'r, V: Volume>(
    vol: &mut V,
    p: Parts<'r>,
    key: &[u8; 32],
    dev: &Device<'_>,
    pkg: (Cap<PkgMem>, usize),
    mode: Mode,
    now: u64,
) -> [u64; 4] {
    let Parts { pkg: pkg_buf, head, caps: caps_buf, sig: sig_buf, sched: sched_buf, arena, topo } = p;
    let none = [0u8; 32];

    // 1. The package, whole, copied out of the client's object. One larger
    // than the buffer is not read.
    let n = match vol.read_package(pkg.0, pkg.1, pkg_buf) {
        Ok(n) => n,
        Err(VolErr::TooLarge) => return refuse(vol, mode, &none, 0, Refusal::Container(ParseError::Length), now),
        Err(_) => return [status(step::IO, io::READ_PACKAGE), 0, 0, 0],
    };
    let (pkg_bytes, _) = pkg_buf.split_at_mut(n);
    let pkg_bytes: &'r [u8] = pkg_bytes;
    let id = Package::parse(pkg_bytes).map_or(none, |p| p.id());

    // 2. The device's signed topology, verified like the kernel does.
    let no_topology = |detail: u64| [status(step::NO_TOPOLOGY, detail), 0, 0, 0];
    let Ok(Read { n: nc, more: false }) = vol.read_file(CAPS_TOML_PATH, caps_buf) else { return no_topology(0) };
    let Ok(Read { n: ns, more: false }) = vol.read_file(CAPS_SIG_PATH, sig_buf) else { return no_topology(0) };
    let Ok(Read { n: nh, more: false }) = vol.read_file(SCHED_TOML_PATH, sched_buf) else { return no_topology(0) };
    let (caps, _) = caps_buf.split_at_mut(nc);
    let (sched, _) = sched_buf.split_at_mut(nh);
    let files = SignedFiles { caps, caps_sig: &sig_buf[..ns], sched };
    // The device id and the counter floor are the device record's, which a ring-3
    // program cannot read: neither is checked here (see the module docs).
    let ctx = DeviceContext { device_id: None, floor: 0, bind_device: false, enforce_floor: false };
    if let Err(r) = fill_signed(topo, &files, key, &ctx) {
        return no_topology(r.code() as u64 >> 28);
    }

    // 3. What is staged already, merged in first: a package is admitted against
    // the device as it will be, not as it is.
    let mut ids = [[0u8; 32]; MAX_STAGED];
    let mut staged = 0usize;
    let mut arena: &'r mut [u8] = arena;
    let mut i = 0;
    while let Some((_, pk)) = staged_at(vol, head, &mut i) {
        if staged == MAX_STAGED {
            break;
        }
        // A staged package that no longer verifies (its signer was dropped)
        // takes its slot but adds no rows.
        ids[staged] = pk.id();
        staged += 1;
        let Ok(v) = verify_head(pk, topo) else { continue };
        let (slot, rest) = core::mem::take(&mut arena).split_at_mut(META_MAX);
        arena = rest;
        let (rows, _) = slot.split_at_mut(pk.rows.len());
        rows.copy_from_slice(pk.rows);
        let rows: &'r [u8] = rows;
        let _ = admit(&v, rows, topo, dev);
    }
    let full = staged == MAX_STAGED;
    if ids[..staged].contains(&id) {
        return [status(step::ALREADY_STAGED, 0), receipt::id_prefix(&id), 0, 0];
    }
    if mode == Mode::Install && full {
        return [status(step::NO_ROOM, 0), receipt::id_prefix(&id), 0, 0];
    }

    // 4. The candidate. A refusal names the signer when the key was one.
    let signer_of_key = Package::parse(pkg_bytes)
        .ok()
        .and_then(|p| topo.signers().iter().position(|s| s.key_id == p.key_id()))
        .map_or(0, |i| i as u64 + 1);
    let v = match verify(pkg_bytes, topo) {
        Ok(v) => v,
        Err(r) => return refuse(vol, mode, &id, signer_of_key, r, now),
    };
    let signer = v.signer_index as u64 + 1;
    let a = match admit(&v, v.pkg.rows, topo, dev) {
        Ok(a) => a,
        Err(r) => return refuse(vol, mode, &id, signer, r, now),
    };
    if mode == Mode::Admit {
        return [0, receipt::id_prefix(&id), a.rows as u64, a.first_row as u64];
    }

    // 5. Stage it, and write the decision down. An install the journal cannot
    // record is undone.
    if !vol.dir_exists(STAGE_DIR) {
        return [status(step::IO, io::NO_STAGE_DIR), receipt::id_prefix(&id), 0, 0];
    }
    let path = match stage_path(vol, head, &id) {
        Ok(p) => p,
        Err(true) => return [status(step::ALREADY_STAGED, 0), receipt::id_prefix(&id), 0, 0],
        Err(false) => return [status(step::NO_ROOM, 0), receipt::id_prefix(&id), 0, 0],
    };
    if vol.write_file(&path.bytes(), pkg_bytes).is_err() {
        let _ = vol.remove(&path.bytes());
        return [status(step::IO, io::WRITE_PACKAGE), receipt::id_prefix(&id), 0, 0];
    }
    if vol.append(JOURNAL, &receipt::admitted(&v, &a, now).to_bytes()).is_err() {
        let _ = vol.remove(&path.bytes());
        return [status(step::IO, io::JOURNAL), receipt::id_prefix(&id), 0, 0];
    }
    [0, receipt::id_prefix(&id), a.rows as u64, a.first_row as u64]
}
