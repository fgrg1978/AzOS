// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The boot-time apply of staged packages.
//!
//! The installer (`userspace/services/pkgd`, ring 3) stages a signed package
//! as `XXXXXXXX.PKG` on the staging volume and says it admitted it. Nothing it
//! says is trusted here: the volume is a file system any writer of it can
//! change. At boot, while the topology is still a candidate (before it is
//! published, so before anything is started), this step repeats the whole
//! decision for every staged package, with what the installer cannot know: the
//! signature and the images' hashes, the signer table of the SIGNED topology,
//! the device's interface levels and security epoch floor
//! (`azos_pkg::admit`), and, over the merged topology, the kernel's own boot
//! admission (the caller's `check`). A package that passes has its rows merged
//! into the candidate and its programs written to `APPS/NAME.ELF` on the
//! staging volume, where the loader finds them (`image_path`); once the
//! candidate is published, each program's SHA-256 is bound to its own row
//! (`pkg_boot::Staged::finish`), without which no exec site would start it.
//!
//! ```text
//!   staged  XXXXXXXX.PKG ─ verify ─ admit ─┬─ rows ──► the candidate topology ─► kernel check
//!                                          └─ images ► APPS/NAME.ELF   (a trial: see below)
//! ```
//!
//! # Atomic, and undone by a snapshot
//!
//! The programs of a package that was not applied before are written as one
//! change group after a snapshot of the volume (`Volume::snapshot_create`): a
//! power cut or an I/O error leaves the volume as it was, and the apply is a
//! **trial** (`azos_pkg::apply`): the boot is on probation like the first
//! boot of an updated slot. The trial ends at a later boot by the A/B rule
//! (`trial_next`): confirmed (the snapshot stays as a restore point, which the
//! installer prunes), still waiting, or rolled back, which restores `APPS/` from
//! the snapshot (`SnapView`) and removes the trial's packages from the staging
//! directory with a refusal on record. The same rollback runs at once when the
//! kernel's check of the merged topology refuses it AND passes without the
//! packages (`undo`): the packages did not fit this device, whatever their
//! signers allowed. When the signed topology alone is refused as well, the
//! packages are not to blame and the trial stands.
//!
//! # Launch grants
//!
//! A row that says `start = true` is started at boot by the component manager
//! (`userspace/services/compmgr`), and `SYS_SPAWN_EX` starts an image only for a
//! caller that holds a launch grant on it. The manager's row holds one per
//! static row of the signed topology; a row a package brought is not in the
//! signed text, so after the last merge [`grant_launches`] adds to the manager's
//! row one grant per admitted package row that starts: `EXEC` on exactly that
//! row's name, `transfer = false`, nothing wider. The child holds what its own
//! row grants (merge held every grant of it under the signer's warrants), never
//! the manager's. A row that failed admission is not in the topology, so no
//! grant names it. The manager's row is where the grants live, not a mint after
//! its spawn: the kernel seeds them from the row at every start of the
//! manager, so a restart of it keeps them.
//!
//! # Decisions
//!
//! Every package gets a decision record (`Rule::PackageInstall`): admitted or
//! refused, with the package id. Every row that starts gets one more, for its
//! launch grant: the subject is the row's id (1-based), `reason` carries
//! [`LAUNCH_GRANT`] (and, for a grant that could not be made, the [`GrantDenied`]
//! code); `images` and `signer` are 0, the record's `image_hash_prefix` is the
//! program's digest. [`Sink`] is the kernel's ring; the records of
//! a new apply and of a rollback are also appended to the installer's journal
//! (`JOURNAL.BIN`) in the same group, so the volume tells the same story as the
//! ring after a restart.
//!
//! # What this file is not
//!
//! It touches the volume through the engine (`azos_fs::azvol::Volume`), not the
//! VFS, because it runs before the VFS serves the volume, and it keeps no state
//! beyond the call: the state is `APPLY.TBL`, the snapshots and `APPS/`.
//! `tests/host/pkg-tests/src/apply.rs` includes this file unchanged over the real
//! engine and cuts power at every device write.

use alloc::boxed::Box;
use alloc::vec::Vec;

use azos_abi::cap::{CapKind, CapPerms};
use azos_decision::{ProvenanceRecord, Rule, Verdict};
use super::engine::{BlockDev, DirEntry, Error, Kind, SnapView, Volume};
use azos_pkg::apply::{
    encode_table, requested, staged_name, trial_next, BootWhy, Next, SnapRec, SnapState, Table, APPS_DIR,
    DELETE_REQUESTS, JOURNAL, SNAPSHOT_LABEL, SNAP_MAX, TABLE, TABLE_MAX,
};
use azos_pkg::container::{HEADER_LEN, KEY_LEN_MAX, SIG_LEN_MAX};
use azos_pkg::{admit, receipt, verify, Device, Package, Refusal};
use azos_topology::builder::{manager_starts, MANAGER_CAPS_MAX, TASK_COMPMGR_IMAGE};
use azos_topology::{CapSpec, MaybeStr, Topology};

/// A package file this large is not read (Kconfig `PKG_MAX_KB`).
const PKG_MAX: usize = azos_limits::PKG_MAX_KB as usize * 1024;
/// What of a staged package decides its id: everything but the images.
const HEAD_MAX: usize = HEADER_LEN + KEY_LEN_MAX + SIG_LEN_MAX + 2 * azos_limits::PKG_META_MAX_KB as usize * 1024;
/// Bytes moved per read of a snapshot's file.
const COPY: usize = 64 * 1024;

/// Where the apply says what it did.
pub trait Sink {
    /// One decision. The kernel writes it to the decision ring; the host
    /// suite collects it.
    fn record(&mut self, p: &ProvenanceRecord);
    /// A line for the console.
    fn note(&mut self, line: core::fmt::Arguments<'_>);
}

/// What the apply needs to know about this boot.
pub struct Boot<'d> {
    /// The device a package is admitted on, with the epoch floor in force.
    pub device: Device<'d>,
    /// The clock, ns.
    pub now_ns: u64,
    /// `BootValidation::prior_unconfirmed`: boots in a row never confirmed.
    pub prior_unconfirmed: u32,
    /// `BootValidation::max_attempts`.
    pub max_attempts: u32,
}

/// What an apply left in the candidate topology.
#[derive(Default)]
pub struct Applied {
    /// Index of the first row a package added.
    pub first_row: usize,
    /// Rows packages added.
    pub rows: usize,
    /// Packages whose rows joined.
    pub packages: usize,
    /// Of those, the ones whose programs were written by this apply.
    pub fresh: Vec<[u8; 32]>,
    /// The snapshot of the trial this apply began, if it began one.
    pub trial: Option<u64>,
    /// Every program of the packages whose rows joined: the name of its row
    /// and the SHA-256 the signed metadata states, which is the digest of the
    /// bytes in `APPS/` (checked byte for byte at every apply).
    pub images: Vec<AppliedImage>,
}

/// One program of an applied package.
pub struct AppliedImage {
    /// Its file name in `APPS/`, which is also the name of its row.
    pub name: Vec<u8>,
    /// Its SHA-256.
    pub sha256: [u8; 32],
}

// ─── The volume, through the engine ──────────────────────────────────────────

fn find<D: BlockDev>(v: &mut Volume<D>, dir: u64, name: &[u8]) -> Result<Option<DirEntry>, Error> {
    match v.lookup(dir, name) {
        Ok(e) => Ok(Some(e)),
        Err(Error::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The first `max` bytes of file `ino` (all of it if shorter); `TooBig` when
/// `whole` and it is longer.
fn read_file<D: BlockDev>(v: &mut Volume<D>, ino: u64, max: usize, whole: bool) -> Result<Vec<u8>, Error> {
    let size = v.stat(ino)?.size;
    if whole && size > max as u64 {
        return Err(Error::TooBig);
    }
    let n = size.min(max as u64) as usize;
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(|_| Error::NoSpace)?;
    out.resize(n, 0);
    let mut at = 0;
    while at < n {
        match v.read(ino, at as u64, &mut out[at..])? {
            0 => return Err(Error::Corrupt("file shorter than its size")),
            r => at += r,
        }
    }
    Ok(out)
}

fn write_all<D: BlockDev>(v: &mut Volume<D>, ino: u64, mut off: u64, mut data: &[u8]) -> Result<(), Error> {
    while !data.is_empty() {
        match v.write(ino, off, data)? {
            0 => return Err(Error::Io),
            n => {
                off += n as u64;
                data = &data[n..];
            }
        }
    }
    Ok(())
}

/// Create or replace file `name` of `dir` with `data`.
fn put<D: BlockDev>(v: &mut Volume<D>, dir: u64, name: &[u8], data: &[u8]) -> Result<(), Error> {
    let ino = match find(v, dir, name)? {
        Some(e) => {
            v.truncate(e.ino, 0)?;
            e.ino
        }
        None => v.create(dir, name, Kind::File, 0o644)?,
    };
    write_all(v, ino, 0, data)
}

fn append<D: BlockDev>(v: &mut Volume<D>, dir: u64, name: &[u8], data: &[u8]) -> Result<(), Error> {
    let (ino, end) = match find(v, dir, name)? {
        Some(e) => (e.ino, v.stat(e.ino)?.size),
        None => (v.create(dir, name, Kind::File, 0o644)?, 0),
    };
    write_all(v, ino, end, data)
}

fn remove<D: BlockDev>(v: &mut Volume<D>, dir: u64, name: &[u8]) -> Result<(), Error> {
    match v.unlink(dir, name) {
        Ok(()) | Err(Error::NotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

/// `f` as one change group: durable whole, or the volume as it was.
fn grouped<D: BlockDev, R>(v: &mut Volume<D>, f: impl FnOnce(&mut Volume<D>) -> Result<R, Error>) -> Result<R, Error> {
    v.begin_group()?;
    match f(v) {
        Ok(r) => {
            v.commit_group()?;
            Ok(r)
        }
        Err(e) => {
            let _ = v.abort_group();
            Err(e)
        }
    }
}

/// The apply's state on the volume: the snapshots it took (the engine is the
/// truth for which exist; the table says which is the trial) and the open
/// trial's package ids.
struct State {
    recs: Vec<SnapRec>,
    ids: Vec<[u8; 32]>,
}

fn load_state<D: BlockDev>(v: &mut Volume<D>) -> Result<State, Error> {
    let root = v.root();
    let bytes = match find(v, root, TABLE)? {
        Some(e) => read_file(v, e.ino, TABLE_MAX, true).ok(),
        None => None,
    };
    let table = bytes.as_deref().and_then(|b| Table::parse(b).ok());
    let mut recs = Vec::new();
    for s in v.snapshots() {
        if s.label != SNAPSHOT_LABEL {
            continue;
        }
        // A snapshot the table does not know (its write was cut, or it is a
        // rolled-back trial whose deletion was) is a restore point.
        let known = table.and_then(|t| t.snaps().find(|r| r.id == s.id));
        recs.push(known.unwrap_or_else(|| SnapRec::new(s.id, s.created_ns, 0, SnapState::Kept, SNAPSHOT_LABEL)));
    }
    let ids = match table {
        Some(t) if recs.iter().any(|r| r.state == SnapState::Trial) => t.ids().collect(),
        _ => Vec::new(),
    };
    Ok(State { recs, ids })
}

fn write_table<D: BlockDev>(v: &mut Volume<D>, st: &State) -> Result<(), Error> {
    let root = v.root();
    let from = st.recs.len().saturating_sub(SNAP_MAX);
    let mut buf = Vec::new();
    buf.try_reserve_exact(TABLE_MAX).map_err(|_| Error::NoSpace)?;
    buf.resize(TABLE_MAX, 0);
    let n = encode_table(&st.recs[from..], &st.ids, &mut buf).ok_or(Error::TooBig)?;
    put(v, root, TABLE, &buf[..n])
}

fn journal<D: BlockDev>(v: &mut Volume<D>, p: &ProvenanceRecord) -> Result<(), Error> {
    let root = v.root();
    append(v, root, JOURNAL, &p.to_bytes())
}

// ─── Restoring a snapshot ────────────────────────────────────────────────────

/// Put `APPS/` back to what snapshot `view` held: entries it did not have are
/// removed, the ones it had are rewritten if they differ. `APPS/` is the whole
/// of what an apply writes besides the table, so this IS the volume restored,
/// for the part a rollback is about.
fn restore_apps<D: BlockDev>(v: &mut Volume<D>, view: &mut SnapView) -> Result<(), Error> {
    let root = v.root();
    let snap_dir = match view.lookup(v, root, APPS_DIR) {
        Ok(e) => Some(e.ino),
        Err(Error::NotFound) => None,
        Err(e) => return Err(e),
    };
    let live = find(v, root, APPS_DIR)?;
    let Some(snap_dir) = snap_dir else {
        if let Some(l) = live {
            for e in v.readdir(l.ino)? {
                v.unlink(l.ino, &e.name)?;
            }
            v.unlink(root, APPS_DIR)?;
        }
        return Ok(());
    };
    let live_ino = match live {
        Some(l) => l.ino,
        None => v.create(root, APPS_DIR, Kind::Dir, 0o755)?,
    };
    let want = view.readdir(v, snap_dir)?;
    for e in v.readdir(live_ino)? {
        if !want.iter().any(|w| w.name == e.name) {
            v.unlink(live_ino, &e.name)?;
        }
    }
    for w in want.iter().filter(|w| w.kind == Kind::File) {
        let size = view.stat(v, w.ino)?.size as usize;
        let mut data = Vec::new();
        data.try_reserve_exact(size).map_err(|_| Error::NoSpace)?;
        data.resize(size, 0);
        let mut at = 0;
        while at < size {
            let end = (at + COPY).min(size);
            match view.read(v, w.ino, at as u64, &mut data[at..end])? {
                0 => return Err(Error::Corrupt("snapshot file shorter than its size")),
                r => at += r,
            }
        }
        let same = match find(v, live_ino, &w.name)? {
            Some(c) => read_file(v, c.ino, size, true).is_ok_and(|cur| cur == data),
            None => false,
        };
        if !same {
            put(v, live_ino, &w.name, &data)?;
        }
    }
    Ok(())
}

/// Remove the staged file of package `id`, if the staging directory holds it.
fn quarantine<D: BlockDev>(v: &mut Volume<D>, id: &[u8; 32]) -> Result<bool, Error> {
    let root = v.root();
    for e in v.readdir(root)? {
        if e.kind != Kind::File || !staged_name(&e.name) {
            continue;
        }
        let head = read_file(v, e.ino, HEAD_MAX, false)?;
        if Package::parse_head(&head).is_ok_and(|p| p.id() == *id) {
            v.unlink(root, &e.name)?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// End trial `snap`: `APPS/` back to the snapshot, the trial's packages out of
/// the staging directory with a refusal on record, the snapshot deleted.
fn roll_back<D: BlockDev>(
    v: &mut Volume<D>,
    st: &mut State,
    snap: SnapRec,
    why: BootWhy,
    boot: &Boot<'_>,
    sink: &mut dyn Sink,
) -> bool {
    let ids = core::mem::take(&mut st.ids);
    let mut view = match v.snapshot_open(snap.id) {
        Ok(view) => view,
        Err(e) => {
            sink.note(format_args!("[PKG] trial snapshot {} cannot be opened ({:?}): the trial stays", snap.id, e));
            st.ids = ids;
            return false;
        }
    };
    let recs_before = st.recs.clone();
    st.recs.retain(|r| r.id != snap.id);
    let mut records = Vec::new();
    let done = grouped(v, |v| {
        restore_apps(v, &mut view)?;
        for id in &ids {
            let p = receipt::refused(id, 0, &Refusal::Boot(why), boot.now_ns);
            if quarantine(v, id)? {
                journal(v, &p)?;
            }
            records.push(p);
        }
        write_table(v, st)
    });
    match done {
        Ok(()) => {
            for p in &records {
                sink.record(p);
            }
            if let Err(e) = v.snapshot_delete(snap.id) {
                sink.note(format_args!("[PKG] snapshot {} kept after the rollback ({:?})", snap.id, e));
            }
            sink.note(format_args!(
                "[PKG] trial of snapshot {} rolled back ({:?}): APPS/ restored, {} package(s) removed", snap.id, why, ids.len()
            ));
            true
        }
        Err(e) => {
            sink.note(format_args!("[PKG] rollback of snapshot {} FAILED ({:?}): the volume is as it was", snap.id, e));
            st.recs = recs_before;
            st.ids = ids;
            false
        }
    }
}

// ─── The apply ───────────────────────────────────────────────────────────────

/// The signer of `bytes`' key, as the receipt spells it (index plus one).
fn signer_of(pkg: &Package<'_>, topo: &Topology<'_>) -> u64 {
    topo.signers().iter().position(|s| s.key_id == pkg.key_id()).map_or(0, |i| i as u64 + 1)
}

/// Does `APPS/` hold every image of `v`, byte for byte?
fn holds_images<D: BlockDev>(vol: &mut Volume<D>, apps: Option<u64>, v: &azos_pkg::Verified<'_, '_>) -> bool {
    let Some(apps) = apps else { return false };
    v.meta.images().iter().enumerate().all(|(i, im)| {
        let Some(want) = v.image(i) else { return false };
        match find(vol, apps, im.name.as_bytes()) {
            Ok(Some(e)) => read_file(vol, e.ino, want.len(), true).is_ok_and(|have| have == want),
            _ => false,
        }
    })
}

/// Bit of a launch grant's `reason` field: this record is the grant of a row
/// to start, not the install of a package (a refusal code is below 2^32).
pub const LAUNCH_GRANT: u64 = 1 << 32;

/// Why a row that starts got no launch grant (the low bits of `reason` beside
/// [`LAUNCH_GRANT`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GrantDenied {
    /// The topology has no component manager row: nobody would start it.
    NoManager = 1,
    /// The row falls beyond the table of components the manager keeps
    /// (`MANAGER_CAPS_MAX - 1`): it would not start it either.
    PastTable = 2,
    /// The kernel interns at most [`LAUNCH_NAMES_MAX`] image names for launch
    /// grants and the topology already names that many.
    NamesFull = 3,
    /// The capability pool has no room for the grants.
    PoolFull = 4,
}

/// The image names `azos_ipc::launch_cap` interns (its `MAX_LAUNCH_NAMES`;
/// `pkg_boot` holds the two equal at compile time). A grant on a name past
/// them cannot be minted, so none is made.
pub const LAUNCH_NAMES_MAX: usize = 32;

/// The record of the launch grant of row `row` (an index into the topology):
/// `denied` says why there is none.
fn grant_receipt(row: usize, sha256: Option<&[u8; 32]>, denied: Option<GrantDenied>, clock_ns: u64) -> ProvenanceRecord {
    let (verdict, reason) = match denied {
        None => (Verdict::Admit, LAUNCH_GRANT),
        Some(d) => (Verdict::Deny, LAUNCH_GRANT | d as u64),
    };
    let mut p = ProvenanceRecord::new(Rule::PackageInstall as u8, verdict as u8, row as u32 + 1, [0, 0, reason]);
    p.topology_row_id = row as u32 + 1;
    if let Some(h) = sha256 {
        p.image_hash_prefix = u64::from_be_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]);
    }
    p.clock_ns = clock_ns;
    p
}

/// Give the component manager a launch grant on each row of `topo` from
/// `first_row` on that it starts (`manager_starts`): `EXEC` on the row's name
/// (see the module's *Launch grants*). Called once, after the last merge, on a
/// candidate that is never rolled back. Every row gets a decision record.
fn grant_launches(topo: &mut Topology<'static>, first_row: usize, images: &[AppliedImage], boot: &Boot<'_>, sink: &mut dyn Sink) {
    if cfg!(feature = "pkg-launch-grant-canary") {
        return;
    }
    let wanted: Vec<usize> = (first_row..topo.tasks_len()).filter(|&i| manager_starts(&topo.tasks()[i])).collect();
    if wanted.is_empty() {
        return;
    }
    let manager = MaybeStr::from_bytes(TASK_COMPMGR_IMAGE);
    let has_manager = topo.find_task(&manager).is_some();
    // Where each row stands in the manager's table, and the names launch
    // grants already intern (a name is interned once however many rows name it).
    let mut slot = topo.tasks()[..first_row].iter().filter(|t| manager_starts(t)).count();
    let mut names: Vec<&[u8]> = Vec::new();
    for t in topo.tasks() {
        for c in topo.caps_of(t).iter().filter(|c| c.kind == CapKind::Node && !c.target.as_bytes().starts_with(b"/")) {
            if !names.contains(&c.target.as_bytes()) {
                names.push(c.target.as_bytes());
            }
        }
    }
    let mut grants: Vec<CapSpec<'static>> = Vec::new();
    let mut verdicts: Vec<(usize, Option<GrantDenied>)> = Vec::new();
    for &i in &wanted {
        let name = topo.tasks()[i].name;
        let denied = if !has_manager {
            Some(GrantDenied::NoManager)
        } else if slot >= MANAGER_CAPS_MAX - 1 {
            Some(GrantDenied::PastTable)
        } else if !names.contains(&name.as_bytes()) && names.len() >= LAUNCH_NAMES_MAX {
            Some(GrantDenied::NamesFull)
        } else {
            if !names.contains(&name.as_bytes()) {
                names.push(name.as_bytes());
            }
            grants.push(CapSpec { kind: CapKind::Node, perms: CapPerms::EXEC, target: name, transfer: false, ops: 0 });
            None
        };
        slot += 1;
        verdicts.push((i, denied));
    }
    if !grants.is_empty() && !topo.extend_task_caps(&manager, &grants) {
        for v in verdicts.iter_mut().filter(|v| v.1.is_none()) {
            v.1 = Some(GrantDenied::PoolFull);
        }
    }
    for (i, denied) in verdicts {
        let name = topo.tasks()[i].name;
        let sha = images.iter().find(|im| im.name.as_slice() == name.as_bytes()).map(|im| &im.sha256);
        if let Some(d) = denied {
            sink.note(format_args!("[PKG] {} starts at boot but gets no launch grant ({:?}): the manager does not start it", name.as_str(), d));
        }
        sink.record(&grant_receipt(i, sha, denied, boot.now_ns));
    }
}

/// Apply the staged packages of `vol` to `topo`, the signed candidate.
///
/// The volume is left durable and consistent whatever happens; a failure of
/// the volume costs the packages that needed it, never the topology.
pub fn apply<D: BlockDev>(
    vol: &mut Volume<D>,
    topo: &mut Topology<'static>,
    boot: &Boot<'_>,
    sink: &mut dyn Sink,
) -> Applied {
    let mut out = Applied { first_row: topo.tasks_len(), ..Applied::default() };
    vol.set_time_ns(boot.now_ns);
    let mut st = match load_state(vol) {
        Ok(s) => s,
        Err(e) => {
            sink.note(format_args!("[PKG] the staging volume's state cannot be read ({:?}): no package applied", e));
            return out;
        }
    };

    // 1. A trial from an earlier boot ends, or goes on.
    let mut waiting = false;
    if let Some(trial) = st.recs.iter().copied().find(|r| r.state == SnapState::Trial) {
        match trial_next(trial.base_prior, boot.prior_unconfirmed, boot.max_attempts) {
            Next::Confirm => {
                for r in st.recs.iter_mut().filter(|r| r.id == trial.id) {
                    r.state = SnapState::Kept;
                }
                let ids = core::mem::take(&mut st.ids);
                match grouped(vol, |v| write_table(v, &st)) {
                    Ok(()) => sink.note(format_args!("[PKG] trial of snapshot {} confirmed: kept as a restore point", trial.id)),
                    Err(e) => {
                        sink.note(format_args!("[PKG] confirming snapshot {} failed ({:?}): the trial stays", trial.id, e));
                        for r in st.recs.iter_mut().filter(|r| r.id == trial.id) {
                            r.state = SnapState::Trial;
                        }
                        st.ids = ids;
                        waiting = true;
                    }
                }
            }
            Next::Wait => {
                sink.note(format_args!(
                    "[PKG] trial of snapshot {} not confirmed yet ({} unconfirmed boot(s)); no new package this boot",
                    trial.id, boot.prior_unconfirmed
                ));
                waiting = true;
            }
            Next::RollBack => {
                if !roll_back(vol, &mut st, trial, BootWhy::Unconfirmed, boot, sink) {
                    waiting = true;
                }
            }
        }
    }

    // 2. Snapshots the installer asked to drop.
    let root = vol.root();
    if let Ok(Some(req)) = find(vol, root, DELETE_REQUESTS) {
        if let Ok(bytes) = read_file(vol, req.ino, 8 * 1024, false) {
            for id in requested(&bytes) {
                // Never the trial's: a rollback needs it.
                if !st.recs.iter().any(|r| r.id == id && r.state == SnapState::Kept) {
                    continue;
                }
                match vol.snapshot_delete(id) {
                    Ok(()) => st.recs.retain(|r| r.id != id),
                    Err(e) => sink.note(format_args!("[PKG] snapshot {} not deleted ({:?})", id, e)),
                }
            }
        }
        if let Err(e) = grouped(vol, |v| {
            remove(v, root, DELETE_REQUESTS)?;
            write_table(v, &st)
        }) {
            sink.note(format_args!("[PKG] the deletion requests could not be cleared ({:?})", e));
        }
    }

    // 3. The staged packages. Applied ones first, so a new package that clashes
    // with one cannot displace it.
    let apps = match find(vol, root, APPS_DIR) {
        Ok(Some(e)) if e.kind == Kind::Dir => Some(e.ino),
        _ => None,
    };
    let names: Vec<Vec<u8>> = match vol.readdir(root) {
        Ok(es) => es.into_iter().filter(|e| e.kind == Kind::File && staged_name(&e.name)).map(|e| e.name).collect(),
        Err(e) => {
            sink.note(format_args!("[PKG] the staging directory cannot be read ({:?}): no package applied", e));
            return out;
        }
    };
    let mut fresh: Vec<Vec<u8>> = Vec::new();
    let mut kept_images: Vec<Vec<u8>> = Vec::new();
    for name in &names {
        let Ok(Some(e)) = find(vol, root, name) else { continue };
        let bytes = match read_file(vol, e.ino, PKG_MAX, true) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let Ok(pkg) = Package::parse(&bytes) else { continue };
        let id = pkg.id();
        let v = match verify(&bytes, topo) {
            Ok(v) => v,
            Err(r) => {
                sink.record(&receipt::refused(&id, signer_of(&pkg, topo), &r, boot.now_ns));
                continue;
            }
        };
        if !holds_images(vol, apps, &v) {
            if waiting {
                sink.note(format_args!("[PKG] {} waits for the trial to end", core::str::from_utf8(name).unwrap_or("?")));
            } else {
                fresh.push(bytes);
            }
            continue;
        }
        let rows: &'static [u8] = Box::leak(v.pkg.rows.to_vec().into_boxed_slice());
        match admit(&v, rows, topo, &boot.device) {
            Ok(a) => {
                sink.record(&receipt::admitted(&v, &a, boot.now_ns));
                out.packages += 1;
                for im in v.meta.images() {
                    kept_images.push(im.name.as_bytes().to_vec());
                    out.images.push(AppliedImage { name: im.name.as_bytes().to_vec(), sha256: im.sha256 });
                }
            }
            Err(r) => sink.record(&receipt::refused(&id, v.signer_index as u64 + 1, &r, boot.now_ns)),
        }
    }

    // 4. The new ones: admitted into the candidate, then their programs written
    // after a snapshot, in one group.
    let mark = topo.checkpoint();
    let mut admitted: Vec<(azos_pkg::Verified<'_, 'static>, azos_pkg::Admitted)> = Vec::new();
    for bytes in &fresh {
        let Ok(v) = verify(bytes, topo) else { continue };
        let rows: &'static [u8] = Box::leak(v.pkg.rows.to_vec().into_boxed_slice());
        match admit(&v, rows, topo, &boot.device) {
            Ok(a) => admitted.push((v, a)),
            Err(r) => sink.record(&receipt::refused(&v.id, v.signer_index as u64 + 1, &r, boot.now_ns)),
        }
    }
    let wanted: Vec<&[u8]> = kept_images
        .iter()
        .map(|n| n.as_slice())
        .chain(admitted.iter().flat_map(|(v, _)| v.meta.images().iter().map(|im| im.name.as_bytes())))
        .collect();
    let stray = apps.is_some_and(|a| vol.readdir(a).is_ok_and(|es| es.iter().any(|e| !wanted.contains(&e.name.as_slice()))));

    if !admitted.is_empty() {
        let fail = |topo: &mut Topology<'static>, sink: &mut dyn Sink, why: &str, admitted: &[(azos_pkg::Verified<'_, 'static>, azos_pkg::Admitted)]| {
            topo.rollback(mark);
            sink.note(format_args!("[PKG] {} new package(s) not applied: {}", admitted.len(), why));
            for (v, _) in admitted {
                sink.record(&receipt::refused(&v.id, v.signer_index as u64 + 1, &Refusal::Boot(BootWhy::Volume), boot.now_ns));
            }
        };
        if st.recs.len() >= SNAP_MAX {
            fail(topo, sink, "the volume holds the most snapshots it may; prune the restore points", &admitted);
        } else {
            match vol.snapshot_create(SNAPSHOT_LABEL) {
                Err(_) => fail(topo, sink, "the volume cannot take a snapshot", &admitted),
                Ok(snap_id) => {
                    let mut ids: Vec<[u8; 32]> = Vec::new();
                    let mut records = Vec::new();
                    let rec = SnapRec::new(snap_id, boot.now_ns, boot.prior_unconfirmed, SnapState::Trial, SNAPSHOT_LABEL);
                    let wrote = grouped(vol, |v| {
                        let dir = match find(v, root, APPS_DIR)? {
                            Some(e) => e.ino,
                            None => v.create(root, APPS_DIR, Kind::Dir, 0o755)?,
                        };
                        for (pv, a) in &admitted {
                            for (i, im) in pv.meta.images().iter().enumerate() {
                                let data = pv.image(i).ok_or(Error::Corrupt("image"))?;
                                put(v, dir, im.name.as_bytes(), data)?;
                            }
                            let p = receipt::admitted(pv, a, boot.now_ns);
                            journal(v, &p)?;
                            records.push(p);
                            ids.push(pv.id);
                        }
                        for e in v.readdir(dir)? {
                            if !wanted.contains(&e.name.as_slice()) {
                                v.unlink(dir, &e.name)?;
                            }
                        }
                        let mut next = State { recs: st.recs.clone(), ids: ids.clone() };
                        next.recs.push(rec);
                        write_table(v, &next)
                    });
                    match wrote {
                        Ok(()) => {
                            st.recs.push(rec);
                            st.ids = ids.clone();
                            for p in &records {
                                sink.record(p);
                            }
                            out.packages += admitted.len();
                            for (pv, _) in &admitted {
                                for im in pv.meta.images() {
                                    out.images.push(AppliedImage { name: im.name.as_bytes().to_vec(), sha256: im.sha256 });
                                }
                            }
                            out.fresh = ids;
                            out.trial = Some(snap_id);
                        }
                        Err(e) => {
                            let _ = vol.snapshot_delete(snap_id);
                            sink.note(format_args!("[PKG] writing the programs failed ({:?}): the volume is as it was", e));
                            fail(topo, sink, "the volume refused the programs", &admitted);
                        }
                    }
                }
            }
        }
    } else if stray {
        // Programs of packages that are gone: removed, no snapshot (it only
        // makes the system smaller).
        let _ = grouped(vol, |v| {
            if let Some(dir) = find(v, root, APPS_DIR)? {
                for e in v.readdir(dir.ino)? {
                    if !wanted.contains(&e.name.as_slice()) {
                        v.unlink(dir.ino, &e.name)?;
                    }
                }
            }
            Ok(())
        });
    }

    out.rows = topo.tasks_len() - out.first_row;
    grant_launches(topo, out.first_row, &out.images, boot, sink);
    out
}

/// The kernel's check refused the merged topology and passed the signed one
/// without the packages: end the trial this apply began. The packages it wrote are removed from the staging directory
/// with a refusal on record (they do not fit this device); the others stay and
/// are tried again next boot, with no package merged this time.
pub fn undo<D: BlockDev>(vol: &mut Volume<D>, applied: &Applied, boot: &Boot<'_>, sink: &mut dyn Sink) {
    let Some(snap_id) = applied.trial else { return };
    vol.set_time_ns(boot.now_ns);
    let Ok(mut st) = load_state(vol) else { return };
    let Some(trial) = st.recs.iter().copied().find(|r| r.id == snap_id) else { return };
    st.ids = applied.fresh.clone();
    roll_back(vol, &mut st, trial, BootWhy::Admission, boot, sink);
}
