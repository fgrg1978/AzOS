// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! An azvol volume behind the VFS: [`AzvolFs`] implements
//! [`FileSystem`](crate::vfs::FileSystem), so `vfs_mount_fs(path, fs)` is the
//! whole of mounting one (`kernel/src/boot/azvol.rs` does it for each
//! `[volume.NAME]` row of the topology).
//!
//! Declared from `lib.rs` (`azvol_mount`), not from `azvol/mod.rs`: the engine
//! stays `core` + `alloc` and pullable on its own, and this file is the one
//! piece that knows the VFS and the kernel's locks. It reaches the engine as
//! `super::azvol` and the VFS as `crate::vfs`, which both resolve the same way
//! in the kernel and in a test file that declares `mod azvol; mod mount;`
//! beside each other.
//!
//! # What a file is here
//!
//! The backend's key for a file is its path beneath the mount point
//! (`a/b/c`, at most [`INODE_KEY_LEN`] bytes, no `.` or `..`, no empty
//! component): azvol has directories, so unlike tmpfs the key may hold `/`.
//! Every call resolves the path under the volume's lock; the engine caches
//! the inodes, so a repeat costs the directory lookups and no device read.
//! The backend is [`streaming`](FileSystem::streaming): the VFS reads and
//! writes it in place at the descriptor's offset. The volume is held as a
//! [`Claim`], not a lock: its owner waits on the device while it holds it
//! (owner rule F1: no `Mutex`, which would boost an owner waiting on hardware,
//! and no spinlock, across a device wait).
//!
//! # A volume with a `verity_root`
//!
//! The row's root names a SHA-256 hash tree over the whole volume
//! ([`verity`](super::azvol::verity)). The mount opens the partition through
//! it ([`open_verity`]) and the engine reads the volume as it reads any other:
//! a block that does not hash into the root is never returned. The row's
//! outcome says which check failed ([`Why::Verity`], [`Why::Tampered`]); a
//! failed read afterwards is an I/O error to the caller and one record to
//! [`Env::tampered`]. The volume is read-only (the device refuses writes), and
//! a row with a root is never mounted without the check.
//!
//! # When anything becomes durable, and who may make it so
//!
//! **Only `fsync` and `sync` commit.** Everything between two commits is one
//! transaction of the engine (`volume.rs`): a power cut leaves the volume as
//! the last commit left it or with every change since applied, never part of
//! them. Nothing here commits on its own (no timer, no size threshold): a
//! flusher would cut transactions where it likes. The price is that a writer
//! that never calls `fsync` loses what it wrote at a power cut; the topology
//! gives a volume's writable tree to the services that own it, and they sync.
//!
//! The transaction has an **owner**, enforced here and not assumed: the task
//! whose change opened it (the engine's change group, [`group`](super::azvol::group),
//! is what the transaction is, so that a discard is possible). While it is open:
//!
//! * every other task's change answers `Busy`;
//! * `fsync` and `sync` by any other task answer `Busy` and commit nothing (a
//!   commit by someone who did not write the transaction would make half of the
//!   owner's multi-file change durable: the package without its journal
//!   record, `pkgd`'s case);
//! * a task that has written nothing, and the volume with nothing pending, make
//!   `fsync` a no-op that succeeds;
//! * the owner's `fsync` or `sync` commits it, whole, and ends it. A writer
//!   that never commits therefore holds every other writer off until it
//!   exits.
//!
//! An owner that exits without committing (`Env::alive` says so; task ids are
//! never reused, so a new task is never taken for the dead owner) leaves a
//! half-written transaction: the next change or commit by any task discards
//! it (a read does not, and still sees it), which is what a power cut at that
//! point would have done, and carries on. So
//! an installer that is killed mid-install and restarted finds the volume as
//! its last commit left it, not stuck. Reads see the open transaction's
//! writes.
//!
//! [`rename`](FileSystem::rename) is its own atomic unit: it commits the
//! caller's earlier changes first (a commit point of the owner's choosing),
//! then copies and removes inside one group, and commits that.
//!
//! No snapshot or caller-opened change group is reachable from here. The
//! engine has both (`snap.rs`, `group.rs`) and ring 3 has no call for either:
//! the ABI carries none and new service functions are IDL interfaces on
//! endpoints, so a `Volume` interface (begin, commit, abort, snapshot
//! create/delete/restore) on a kernel-hosted endpoint is where they would
//! come in, with the envelope check and the record before each destructive
//! one. Until a task needs it, nothing in this file calls them.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use core::sync::atomic::{AtomicU64, Ordering};
use azos_sync::claim::Claim;

use super::azvol::verity::{Hash, OpenError, Record, Tamper, VerityDev};
use super::azvol::{BlockDev, CheckReport, Error, Kind, MountReport, Volume, VolumeKey, BLOCK_SIZE};
use super::probe::{probe_volume, VolumeKind};
use crate::vfs::{
    DirEnt, FileStat, FileSystem, FsCheck, FsErr, InodeKey, SectorRun, StatFs, FS_TYPE_AZVOL, INODE_KEY_LEN, NAME_MAX,
    S_IFDIR, S_IFREG,
};

/// Deepest directory a rename walks (the longest key is
/// [`INODE_KEY_LEN`] bytes, so 32 one-letter components): the recursion is
/// bounded, whatever the medium holds.
const MAX_DEPTH: usize = INODE_KEY_LEN / 2;
/// Bytes copied per step by rename.
const COPY_CHUNK: usize = 64 * 1024;

// ─── The system around the mount ──────────────────────────────────────────────

/// What the mount needs from the system it runs in: the clock, the tasks and a
/// place to write down a verity failure. The kernel's implementation is in
/// `kernel/src/boot/azvol.rs`; the host suite's lets a test play several tasks.
pub trait Env: Sync {
    /// Wall-ish time stamped on created and changed files.
    fn now_ns(&self) -> u64;
    /// The calling task (the owner of the open transaction).
    fn tid(&self) -> u32;
    /// Is task `tid` still running? A transaction whose owner is not is
    /// discarded by the next task to use the volume.
    fn alive(&self, tid: u32) -> bool;
    /// A block of a verity-checked volume did not hash into the row's
    /// `verity_root` (see [`super::azvol::verity`]). Called for the failed
    /// open and for every failed read, from whatever task read; it must not
    /// block.
    fn tampered(&self, t: &Tamper);
}

// ─── The mounted volume ───────────────────────────────────────────────────────

struct State<D: BlockDev> {
    vol: Volume<D>,
    /// The task that owns the open transaction (the engine's change group is
    /// open exactly when this is `Some`).
    txn: Option<u32>,
}

/// A mounted azvol volume as a [`FileSystem`].
pub struct AzvolFs<D: BlockDev + Send> {
    read_only: bool,
    env: &'static dyn Env,
    report: MountReport,
    /// What the check after an unclean mount found, when it found damage (the
    /// volume is then read-only: [`open_plain`]).
    damage: Option<Damage>,
    state: Claim<State<D>>,
}

fn fs_err(e: Error) -> FsErr {
    match e {
        Error::NoSpace | Error::TooBig => FsErr::NoSpace,
        Error::NotFound | Error::NoSnapshot => FsErr::NotFound,
        Error::Exists => FsErr::Exists,
        Error::NotDir => FsErr::NotDir,
        Error::IsDir => FsErr::IsDir,
        Error::NotEmpty => FsErr::NotEmpty,
        Error::Denied => FsErr::Denied,
        Error::NameInvalid | Error::TooSmall | Error::NoGroup => FsErr::Invalid,
        // A sealed block that fails its tag is damaged data; a nonce that ran out
        // clears with the next commit. The key errors are mount-time only (a
        // mounted volume holds its key), so they cannot reach a file operation.
        Error::GroupOpen | Error::NonceExhausted => FsErr::Busy,
        Error::KeyRequired | Error::WrongKey => FsErr::Invalid,
        Error::Io
        | Error::BadMagic
        | Error::NoSuperblock
        | Error::Unsupported(_)
        | Error::Corrupt(_)
        | Error::Checksum(_)
        | Error::Auth(_)
        | Error::Poisoned => FsErr::Io,
    }
}

/// The key's path: its bytes up to the first NUL.
fn key_path(key: &InodeKey) -> &[u8] {
    let n = key.bytes.iter().position(|&b| b == 0).unwrap_or(INODE_KEY_LEN);
    &key.bytes[..n]
}

/// A path the mount accepts: relative, components non-empty and neither `.`
/// nor `..`, no NUL, short enough to be a key. The engine's own name rules
/// (`dir::name_ok`) apply to each component when it is looked up or created.
fn path_ok(p: &[u8]) -> bool {
    !p.is_empty()
        && p.len() <= INODE_KEY_LEN
        && p[0] != b'/'
        && p[p.len() - 1] != b'/'
        && p.split(|&c| c == b'/').all(|c| !c.is_empty() && c != b"." && c != b".." && !c.contains(&0))
}

/// `a/b/c` as (`a/b`, `c`).
fn split(p: &[u8]) -> (&[u8], &[u8]) {
    match p.iter().rposition(|&c| c == b'/') {
        Some(i) => (&p[..i], &p[i + 1..]),
        None => (&[], p),
    }
}

impl<D: BlockDev + Send> AzvolFs<D> {
    /// Serve the mounted `volume`. `read_only` refuses every change before it
    /// reaches the engine.
    pub fn new(mut volume: Volume<D>, read_only: bool, env: &'static dyn Env) -> Self {
        // Whoever reaches the engine's snapshot drop through this mount asks
        // the effect gate first.
        volume.set_delete_gate(crate::vfs::delete_admitted);
        let report = volume.report();
        AzvolFs { read_only, env, report, damage: None, state: Claim::new(State { vol: volume, txn: None }) }
    }

    /// The damage the check after an unclean mount found (the volume is then
    /// served read-only), or `None`.
    pub fn damage(&self) -> Option<Damage> {
        self.damage
    }

    /// What the mount found (generation, which superblock copy, whether the
    /// free-space map had to be rebuilt).
    pub fn report(&self) -> MountReport {
        self.report
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// The fence: leave the volume with no transaction open, or with the
    /// caller's. Another live task's transaction is `Busy`; a dead owner's is
    /// discarded (see the module doc).
    fn fence(&self, g: &mut State<D>) -> Result<(), FsErr> {
        if let Some(owner) = g.txn {
            if owner == self.env.tid() {
                return Ok(());
            }
            if self.env.alive(owner) {
                return Err(FsErr::Busy);
            }
            g.txn = None;
            g.vol.abort_group().map_err(fs_err)?;
        }
        Ok(())
    }

    /// A change: the checks, the caller's transaction (opened if there is
    /// none), the clock, then `f` on the volume.
    fn change<R>(&self, f: impl FnOnce(&mut Volume<D>) -> Result<R, Error>) -> Result<R, FsErr> {
        if self.read_only {
            return Err(FsErr::ReadOnly);
        }
        let mut g = self.state.acquire();
        self.fence(&mut g)?;
        if g.txn.is_none() {
            // Nothing is pending (every commit and discard ends the group),
            // so this commits nothing.
            g.vol.begin_group().map_err(fs_err)?;
            g.txn = Some(self.env.tid());
        }
        g.vol.set_time_ns(self.env.now_ns());
        f(&mut g.vol).map_err(fs_err)
    }

    /// A read: `f` on the volume.
    fn look<R>(&self, f: impl FnOnce(&mut Volume<D>) -> Result<R, Error>) -> Result<R, FsErr> {
        let mut g = self.state.acquire();
        f(&mut g.vol).map_err(fs_err)
    }

    /// Make the caller's transaction durable. `Busy` when another live task
    /// owns the open one; Ok and nothing to do when none is open.
    fn commit(&self) -> Result<(), FsErr> {
        if self.read_only {
            return Ok(());
        }
        let mut g = self.state.acquire();
        self.fence(&mut g)?;
        if g.txn.take().is_none() {
            return Ok(());
        }
        g.vol.commit_group().map_err(fs_err)
    }
}

// ─── Mounting a topology row ──────────────────────────────────────────────────

/// One `[volume.NAME]` row of the topology, as the mount reads it
/// (`azos_topology::VolumeSpec`, copied field by field by
/// `kernel/src/boot/azvol.rs`, which is the only place that names the crate).
#[derive(Clone, Copy, Debug)]
pub struct Row<'a> {
    pub name: &'a [u8],
    /// 1-based, as the row spells it.
    pub partition: u8,
    pub mount: &'a [u8],
    pub read_only: bool,
    /// `aead = true`: the blocks are sealed at rest, and the mount needs the
    /// volume's key ([`mount_rows`]'s `key`).
    pub aead: bool,
    /// `verity_root = "<64 hex>"`: the volume must match the hash tree whose
    /// root this is ([`open_verity`]). Such a volume is served read-only,
    /// whatever `read_only` says.
    pub verity_root: Option<Hash>,
}

/// Why a row was not mounted. A row that asks for a protection this build
/// does not provide is REFUSED, not mounted without it: a volume the owner
/// declared sealed must never be served as a plain one, and one declared
/// hash-checked is never served unchecked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// `aead = true`, and the system holds no key for the volume: the keystore
    /// has no seed (the board is not provisioned) or the caller gave none.
    NoKey,
    /// `aead = true` together with `verity_root`: a hash tree over sealed
    /// blocks has no defined meaning here (neither check has run on the
    /// other), so the row is refused rather than mounted with one of them.
    SealedAndHashed,
    /// `verity_root` set, and the device does not open as the volume that root
    /// names: a wrong root, a changed header or superblock, no tree.
    Verity(OpenError),
    /// `verity_root` set, the device opened, and a block the mount itself read
    /// did not hash into the root. One failed block is enough: a superblock
    /// copy or a free-space block that does not check out is not "worked
    /// around" by the engine's fallbacks.
    Tampered,
    /// The row's partition is not on the medium (no such partition).
    NoDevice,
    /// The partition does not hold a usable azvol volume. It is never
    /// formatted here: a blank partition is the owner's to provision.
    NotAzvol(VolumeKind),
    /// The engine refused the volume.
    Engine(Error),
    /// The check after an unclean mount found damage, and Kconfig
    /// `FS_CHECK_FAILED` refuses such a volume.
    CheckFailed(Damage),
    /// The VFS has no room or the mount point is taken.
    Vfs,
}

/// What the check after an unclean mount found that it cannot vouch for:
/// how many problems (`Volume::check`'s list, less the leaked blocks, which are
/// not damage) and the first of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Damage {
    pub problems: u32,
    pub first: &'static str,
}

/// What a mount does with a volume whose check found damage (Kconfig
/// `FS_CHECK_FAILED`). A parameter of [`open_plain`] so a test takes either.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnDamage {
    /// Serve it, every change refused.
    ReadOnly,
    /// Do not serve it ([`Why::CheckFailed`]).
    Refuse,
}

impl OnDamage {
    /// The member this build's Kconfig chose.
    pub const CONFIGURED: OnDamage = if azos_limits::FS_CHECK_FAILED_REFUSE { OnDamage::Refuse } else { OnDamage::ReadOnly };
}

/// Did this mount find the volume unclean? The format has no clean flag (a
/// committed tree is whole by construction, see `volume.rs`): what a cut or a
/// bad write leaves is what the mount had to work around, a free-space map
/// that did not match its trees (rebuilt) or a superblock copy that does not
/// check out.
pub fn unclean(r: &MountReport) -> bool {
    r.bitmap_rebuilt || !r.other_valid
}

/// The damage in `rep`: every problem but the leaked blocks (marked used,
/// named by nothing), which cost space and nothing else.
pub fn damage(rep: &CheckReport) -> Option<Damage> {
    if cfg!(feature = "azvol-check-never-fails-canary") {
        return None;
    }
    let mut hurt = rep.problems.iter().filter(|p| p.what != LEAKED);
    let first = hurt.next()?.what;
    Some(Damage { problems: 1 + hurt.count() as u32, first })
}

/// `Volume::check`'s words for a leaked block.
const LEAKED: &str = "block marked used but named by nothing";

/// What mounting one row came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Mounted(MountReport),
    /// Mounted, and the check after an unclean mount found damage: served
    /// read-only (Kconfig `FS_CHECK_FAILED_READ_ONLY`).
    MountedReadOnly(MountReport, Damage),
    Refused(Why),
}

/// Probe the device and, if it holds an azvol volume, make the filesystem for
/// it: the engine mounts it (refusing a bad superblock, a mismatched geometry,
/// a volume that is not what its checksums say). Nothing is served yet
/// ([`mount_volume`] does that). With a `key` the volume is mounted sealed: a
/// plain volume is then refused by the engine (`Unsupported`), and a wrong key
/// is `WrongKey` before any data is read.
///
/// An [`unclean`] mount is checked (`Volume::check`, no scrub: the trees, the
/// free-space map, the inode list, the directories). Damage ([`damage`])
/// makes the volume read-only or refuses it, as `on_damage` says; a check
/// that cannot run (a read error) refuses it either way.
pub fn open_plain<D: BlockDev + Send>(
    mut dev: D,
    read_only: bool,
    env: &'static dyn Env,
    key: Option<&VolumeKey>,
    on_damage: OnDamage,
) -> Result<AzvolFs<D>, Why> {
    let kind = probe_volume(&mut |blk, buf| dev.read(blk, buf).is_ok());
    if !matches!(kind, VolumeKind::Azvol { .. }) {
        return Err(Why::NotAzvol(kind));
    }
    let mut vol = match key {
        Some(k) => Volume::mount_sealed(dev, k),
        None => Volume::mount(dev),
    }
    .map_err(Why::Engine)?;
    let mut found = None;
    if unclean(&vol.report()) && !cfg!(feature = "azvol-unclean-unchecked-canary") {
        // Nothing is pending after a mount, so the check's commit writes
        // nothing: a read-only device (a verity one) is checked the same way.
        found = damage(&vol.check(false).map_err(Why::Engine)?);
    }
    let read_only = match (found, on_damage) {
        (Some(d), OnDamage::Refuse) => return Err(Why::CheckFailed(d)),
        (Some(_), OnDamage::ReadOnly) => true,
        (None, _) => read_only,
    };
    let mut fs = AzvolFs::new(vol, read_only, env);
    fs.damage = found;
    Ok(fs)
}

/// Where a verity device's failures go: the system's record
/// ([`Env::tampered`]), and a count the mount reads back, because the engine
/// folds a device failure into a plain I/O error and its fallbacks (the other
/// superblock copy, a rebuilt free-space map) would otherwise carry a
/// tampered volume on to a successful mount.
pub struct Watch {
    env: &'static dyn Env,
    seen: Arc<AtomicU64>,
}

impl Record for Watch {
    fn tampered(&self, t: &Tamper) {
        self.seen.fetch_add(1, Ordering::Relaxed);
        self.env.tampered(t);
    }
}

/// [`open_plain`] over the hash tree `root` names: the device is opened as the
/// volume of that root ([`VerityDev::open`]) and the engine mounts it through
/// it, so every block it reads is checked. The volume is read-only. A block
/// that fails while the mount reads the volume refuses the mount
/// ([`Why::Tampered`]), whichever block it was and whatever the engine would
/// have made of the failure.
pub fn open_verity<D: BlockDev + Send>(
    dev: D,
    root: &Hash,
    env: &'static dyn Env,
) -> Result<AzvolFs<VerityDev<D, Watch>>, Why> {
    let seen = Arc::new(AtomicU64::new(0));
    let checked = VerityDev::open(dev, root, Watch { env, seen: seen.clone() }).map_err(Why::Verity)?;
    let opened = open_plain(checked, true, env, None, OnDamage::CONFIGURED);
    if seen.load(Ordering::Relaxed) != 0 {
        return Err(Why::Tampered);
    }
    opened
}

/// Serve `fs` at `at`. The reference lives for the rest of the boot: a volume
/// is not unmounted yet, and its state is behind its own lock.
fn serve<D: BlockDev + Send + 'static>(fs: AzvolFs<D>, at: &[u8]) -> Result<Outcome, Why> {
    let outcome = match fs.damage() {
        Some(d) => Outcome::MountedReadOnly(fs.report(), d),
        None => Outcome::Mounted(fs.report()),
    };
    let fs: &'static AzvolFs<D> = Box::leak(Box::new(fs));
    crate::vfs::vfs_mount_fs(at, fs).map_err(|()| Why::Vfs)?;
    Ok(outcome)
}

/// Mount the row's volume at its mount point: through the hash tree when the
/// row has a `verity_root`, directly otherwise.
///
/// A sealed row (`aead`) is mounted with `key` and only with it: no key is
/// [`Why::NoKey`]. A key handed to a row that is not sealed is ignored.
pub fn mount_volume<D: BlockDev + Send + 'static>(
    dev: D,
    row: &Row<'_>,
    env: &'static dyn Env,
    key: Option<&VolumeKey>,
) -> Result<Outcome, Why> {
    if row.aead && row.verity_root.is_some() {
        return Err(Why::SealedAndHashed);
    }
    if row.aead && key.is_none() {
        return Err(Why::NoKey);
    }
    let key = key.filter(|_| row.aead);
    match &row.verity_root {
        Some(root) => serve(open_verity(dev, root, env)?, row.mount),
        None => serve(open_plain(dev, row.read_only, env, key, OnDamage::CONFIGURED)?, row.mount),
    }
}

/// Mount every row. `open` hands out the device of a partition (1-based) or
/// `None`; `key` hands out the key of a sealed row's volume, or `None` when the
/// system holds none (the kernel derives it from its keystore); `done` hears
/// each row's outcome (the kernel prints it and writes the receipt of a
/// refusal). Rows are independent: one that fails leaves the others mounted.
pub fn mount_rows<'a, D: BlockDev + Send + 'static>(
    rows: impl IntoIterator<Item = Row<'a>>,
    open: &mut dyn FnMut(u8) -> Option<D>,
    key: &mut dyn FnMut(&Row<'a>) -> Option<VolumeKey>,
    env: &'static dyn Env,
    done: &mut dyn FnMut(&Row<'a>, Outcome),
) {
    for row in rows {
        let key = if row.aead { key(&row) } else { None };
        let outcome = if row.aead && row.verity_root.is_some() {
            Outcome::Refused(Why::SealedAndHashed)
        } else if row.aead && key.is_none() {
            Outcome::Refused(Why::NoKey)
        } else {
            match open(row.partition) {
                None => Outcome::Refused(Why::NoDevice),
                Some(dev) => mount_volume(dev, &row, env, key.as_ref()).unwrap_or_else(Outcome::Refused),
            }
        };
        done(&row, outcome);
    }
}

// ─── Trees: copy, remove ─────────────────────────────────────────────

/// Remove `name` under `dir`, a directory with everything below it.
fn remove_tree<D: BlockDev>(v: &mut Volume<D>, dir: u64, name: &[u8], depth: usize) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::TooBig);
    }
    let e = v.lookup(dir, name)?;
    if e.kind == Kind::Dir {
        for c in v.readdir(e.ino)? {
            remove_tree(v, e.ino, &c.name, depth + 1)?;
        }
    }
    v.unlink(dir, name)
}

/// Copy the `size` bytes of file `src` into the (new, empty) file `dst`.
fn copy_file<D: BlockDev>(v: &mut Volume<D>, src: u64, dst: u64, size: u64) -> Result<(), Error> {
    let mut buf = vec![0u8; COPY_CHUNK];
    let mut off = 0u64;
    while off < size {
        let want = ((size - off) as usize).min(COPY_CHUNK);
        let n = v.read(src, off, &mut buf[..want])?;
        if n == 0 {
            return Err(Error::Corrupt("file shorter than its size"));
        }
        if v.write(dst, off, &buf[..n])? != n {
            return Err(Error::NoSpace);
        }
        off += n as u64;
    }
    Ok(())
}

/// Copy the entry `src` (name `name` in `sdir`) to `dname` in `ddir`, then
/// its subtree if it is a directory.
fn copy_tree<D: BlockDev>(
    v: &mut Volume<D>,
    src: u64,
    kind: Kind,
    ddir: u64,
    dname: &[u8],
    depth: usize,
) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::TooBig);
    }
    match kind {
        Kind::Dir => {
            let d = v.create(ddir, dname, Kind::Dir, 0o755)?;
            for c in v.readdir(src)? {
                copy_tree(v, c.ino, c.kind, d, &c.name, depth + 1)?;
            }
            Ok(())
        }
        Kind::File => {
            let mode = v.stat(src)?.mode;
            let f = v.create(ddir, dname, Kind::File, mode)?;
            let size = v.stat(src)?.size;
            copy_file(v, src, f, size)
        }
        _ => Err(Error::Corrupt("directory entry of a kind a tree does not hold")),
    }
}

// ─── FileSystem ───────────────────────────────────────────────────────────────

/// A stat of the inode as the VFS's [`FileStat`].
fn file_stat(st: &super::azvol::Stat) -> FileStat {
    let is_dir = st.kind == Kind::Dir;
    let secs = |ns: u64| ns / 1_000_000_000;
    FileStat {
        size: if is_dir { 0 } else { st.size },
        is_dir,
        cookie: 0,
        mode: (if is_dir { S_IFDIR } else { S_IFREG }) | (st.mode as u32 & 0o7777),
        uid: 0,
        gid: 0,
        nlink: 1,
        atime: secs(st.mtime_ns),
        mtime: secs(st.mtime_ns),
        ctime: secs(st.ctime_ns),
    }
}

impl<D: BlockDev + Send> FileSystem for AzvolFs<D> {
    fn fs_type(&self) -> u32 {
        FS_TYPE_AZVOL
    }

    /// Mounted when built ([`AzvolFs::new`] takes a mounted volume).
    fn mount(&self) -> Result<(), ()> {
        Ok(())
    }

    fn sync(&self) -> Result<(), ()> {
        self.commit().map_err(|_| ())
    }

    fn key_for(&self, name: &[u8]) -> Option<InodeKey> {
        if !path_ok(name) {
            return None;
        }
        let mut bytes = [0u8; INODE_KEY_LEN];
        bytes[..name.len()].copy_from_slice(name);
        Some(InodeKey { bytes })
    }

    fn stat(&self, key: &InodeKey) -> Option<FileStat> {
        self.look(|v| {
            let ino = v.lookup_path(key_path(key))?;
            v.stat(ino)
        })
        .ok()
        .map(|st| file_stat(&st))
    }

    fn read_all(&self, key: &InodeKey, st: &FileStat, dst: &mut [u8]) -> usize {
        let n = (st.size as usize).min(dst.len());
        self.read_at(key, 0, &mut dst[..n])
    }

    fn write_all(&self, key: &InodeKey, src: &[u8]) -> Result<(), ()> {
        let p = key_path(key);
        let (parent, name) = split(p);
        self.change(|v| {
            let dir = v.lookup_path(parent)?;
            let ino = match v.lookup(dir, name) {
                Ok(e) => e.ino,
                Err(Error::NotFound) => v.create(dir, name, Kind::File, 0o644)?,
                Err(e) => return Err(e),
            };
            v.truncate(ino, 0)?;
            if v.write(ino, 0, src)? != src.len() {
                return Err(Error::NoSpace);
            }
            Ok(())
        })
        .map_err(|_| ())
    }

    fn unlink(&self, key: &InodeKey) -> Result<(), ()> {
        let (parent, name) = split(key_path(key));
        self.change(|v| {
            let dir = v.lookup_path(parent)?;
            if v.lookup(dir, name)?.kind == Kind::Dir {
                return Err(Error::IsDir);
            }
            v.unlink(dir, name)
        })
        .map_err(|_| ())
    }

    fn read_at(&self, key: &InodeKey, offset: u64, dst: &mut [u8]) -> usize {
        self.look(|v| {
            let ino = v.lookup_path(key_path(key))?;
            v.read(ino, offset, dst)
        })
        .unwrap_or(0)
    }

    fn write_at(&self, key: &InodeKey, offset: u64, src: &[u8]) -> Result<usize, ()> {
        self.change(|v| {
            let ino = v.lookup_path(key_path(key))?;
            v.write(ino, offset, src)
        })
        .map_err(|_| ())
    }

    fn streaming(&self) -> bool {
        true
    }

    fn create(&self, key: &InodeKey) -> Result<(), FsErr> {
        let (parent, name) = split(key_path(key));
        self.change(|v| {
            let dir = v.lookup_path(parent)?;
            match v.lookup(dir, name) {
                Ok(e) if e.kind == Kind::File => Ok(()),
                Ok(_) => Err(Error::IsDir),
                Err(Error::NotFound) => v.create(dir, name, Kind::File, 0o644).map(|_| ()),
                Err(e) => Err(e),
            }
        })
    }

    fn truncate(&self, key: &InodeKey, len: u64) -> Result<(), FsErr> {
        self.change(|v| {
            let ino = v.lookup_path(key_path(key))?;
            v.truncate(ino, len)
        })
    }

    /// Swap file: `len` is whole blocks. Zeroed blocks are written through the
    /// engine (real blocks, with their checksums, so nothing is a hole) or the
    /// tail is cut, and
    /// the change is committed whatever its outcome: the reclaim task that
    /// calls this never exits, and a transaction it left open would answer
    /// `Busy` to every other writer.
    fn swap_resize(&self, key: &InodeKey, len: u64) -> Result<(), FsErr> {
        // Whole blocks: cutting inside one rewrites it (copy on write moves it).
        if len % BLOCK_SIZE as u64 != 0 {
            return Err(FsErr::Invalid);
        }
        let zeros = [0u8; BLOCK_SIZE];
        let r = self.change(|v| {
            let ino = v.lookup_path(key_path(key))?;
            let size = v.stat(ino)?.size;
            if len > size {
                let mut at = size;
                while at < len {
                    let n = ((len - at) as usize).min(BLOCK_SIZE);
                    if v.write(ino, at, &zeros[..n])? != n {
                        return Err(Error::NoSpace);
                    }
                    at += n as u64;
                }
                Ok(())
            } else if len < size {
                v.truncate(ino, len)
            } else {
                Ok(())
            }
        });
        let c = self.commit();
        r.and(c)
    }

    /// Swap file: the file's block runs as medium sectors. A device that is
    /// not a plain window onto the medium (the verity wrapper) is
    /// `Unsupported`.
    fn swap_runs(&self, key: &InodeKey, len: u64, out: &mut [SectorRun]) -> Result<usize, FsErr> {
        let mut g = self.state.acquire();
        let v = &mut g.vol;
        let ino = v.lookup_path(key_path(key)).map_err(fs_err)?;
        if len > v.stat(ino).map_err(fs_err)?.size {
            return Err(FsErr::Invalid);
        }
        let mut blocks = vec![(0u64, 0u64); out.len()];
        let n = v.file_runs(ino, len, &mut blocks).map_err(fs_err)?;
        for (o, &(first, count)) in out.iter_mut().zip(&blocks[..n]) {
            let lba = v.device().raw_sector(first).ok_or(FsErr::Unsupported)?;
            let sectors = count.checked_mul((BLOCK_SIZE / 512) as u64).and_then(|c| u32::try_from(c).ok());
            *o = SectorRun { lba, sectors: sectors.ok_or(FsErr::Invalid)? };
        }
        Ok(n)
    }

    /// Commit. The volume is the unit, as FAT32's is (`fat32_sync`): there is
    /// no per-file durability to offer when the transaction is the volume's.
    fn fsync(&self, _key: &InodeKey) -> Result<(), FsErr> {
        self.commit()
    }

    fn mkdir(&self, name: &[u8]) -> Result<(), FsErr> {
        if !path_ok(name) {
            return Err(FsErr::Invalid);
        }
        let (parent, leaf) = split(name);
        self.change(|v| {
            let dir = v.lookup_path(parent)?;
            v.create(dir, leaf, Kind::Dir, 0o755).map(|_| ())
        })
    }

    fn rmdir(&self, name: &[u8]) -> Result<(), FsErr> {
        if !path_ok(name) {
            return Err(FsErr::Invalid);
        }
        let (parent, leaf) = split(name);
        self.change(|v| {
            let dir = v.lookup_path(parent)?;
            if v.lookup(dir, leaf)?.kind != Kind::Dir {
                return Err(Error::NotDir);
            }
            v.unlink(dir, leaf)
        })
    }

    /// Rename, atomically: the engine has no rename record, so the entry is
    /// copied to its new name and the old one removed inside one change
    /// group (a cut leaves the old name or the new, whole). The caller's
    /// earlier changes are committed first, so a rename is a commit point
    /// for its caller; another live task's open transaction answers `Busy`.
    /// An existing file at `to` is replaced; an existing directory only by an
    /// empty one. The work is the size of the tree, not a directory-entry
    /// change; a native rename in the engine would make it O(1).
    fn rename(&self, from: &[u8], to: &[u8]) -> Result<(), FsErr> {
        if !path_ok(from) || !path_ok(to) {
            return Err(FsErr::Invalid);
        }
        if self.read_only {
            return Err(FsErr::ReadOnly);
        }
        if from == to {
            return Ok(());
        }
        // A directory cannot move beneath itself.
        if to.len() > from.len() && to.starts_with(from) && to[from.len()] == b'/' {
            return Err(FsErr::Invalid);
        }
        let mut g = self.state.acquire();
        self.fence(&mut g)?;
        if g.txn.take().is_some() {
            g.vol.commit_group().map_err(fs_err)?;
        }
        g.vol.set_time_ns(self.env.now_ns());
        let v = &mut g.vol;
        v.begin_group().map_err(fs_err)?;
        let (fp, fname) = split(from);
        let (tp, tname) = split(to);
        let r = (|| {
            let sdir = v.lookup_path(fp)?;
            let src = v.lookup(sdir, fname)?;
            let ddir = v.lookup_path(tp)?;
            match v.lookup(ddir, tname) {
                Ok(d) => match (src.kind, d.kind) {
                    (Kind::File, Kind::File) => v.unlink(ddir, tname)?,
                    (Kind::Dir, Kind::Dir) => v.unlink(ddir, tname)?, // NotEmpty if it is not
                    (Kind::File, _) => return Err(Error::IsDir),
                    _ => return Err(Error::NotDir),
                },
                Err(Error::NotFound) => {}
                Err(e) => return Err(e),
            }
            copy_tree(v, src.ino, src.kind, ddir, tname, 0)?;
            remove_tree(v, sdir, fname, 0)
        })();
        match r {
            Ok(()) => v.commit_group().map_err(fs_err),
            Err(e) => {
                let _ = v.abort_group();
                Err(fs_err(e))
            }
        }
    }

    fn statfs(&self) -> Result<StatFs, FsErr> {
        let s = self.state.acquire().vol.statfs();
        Ok(StatFs {
            fs_type: FS_TYPE_AZVOL,
            block_size: BLOCK_SIZE as u32,
            blocks: s.blocks_total,
            blocks_free: s.blocks_total.saturating_sub(s.blocks_used),
            // The inode table grows with the files: no fixed count to report.
            files: 0,
            files_free: 0,
            name_max: NAME_MAX as u32,
        })
    }

    /// `Volume::check` under the volume's claim. `Busy` while a transaction
    /// is open, whoever owns it: the check commits before it walks, and a
    /// commit is the owner's to make (see the module doc), so with nothing
    /// open it writes nothing.
    fn check(&self, scrub: bool) -> Result<FsCheck, FsErr> {
        let mut g = self.state.acquire();
        if g.txn.is_some() {
            return Err(FsErr::Busy);
        }
        let rep = g.vol.check(scrub).map_err(fs_err)?;
        let leaked = rep.problems.iter().filter(|p| p.what == LEAKED).count() as u64;
        Ok(FsCheck {
            problems: damage(&rep).map_or(0, |d| d.problems),
            leaked,
            mismatched: 0,
            items: rep.inodes,
            scrubbed: rep.blocks_scrubbed,
            complete: true,
            read_only: self.damage.is_some(),
        })
    }

    /// The cookie is the entry's position in the directory's order, which the
    /// engine keeps across calls while the directory is unchanged.
    fn readdir(&self, dir: &[u8], cookie: u64, out: &mut DirEnt) -> Result<Option<u64>, FsErr> {
        let mut g = self.state.acquire();
        let v = &mut g.vol;
        let d = v.lookup_path(dir).map_err(fs_err)?;
        let list = v.readdir(d).map_err(fs_err)?;
        let mut i = usize::try_from(cookie).unwrap_or(usize::MAX);
        while i < list.len() {
            let e = &list[i];
            i += 1;
            let is_dir = e.kind == Kind::Dir;
            let size = if is_dir { 0 } else { v.stat(e.ino).map_err(fs_err)?.size };
            // A name the VFS cannot carry is skipped, not an error for the walk.
            if out.set(&e.name, is_dir, size) {
                return Ok(Some(i as u64));
            }
        }
        Ok(None)
    }
}
