// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `pkgd` staging on a native volume (L15): the installer's own library
//! (`userspace/lib/packages`) running on `userspace/services/pkgd/src/stage.rs`,
//! compiled unchanged, over the REAL azvol engine on a device that can replay
//! a power cut. Cutting power at every device write of an install (and of a
//! removal) leaves the staged package and its journal record both, or neither;
//! never one without the other.
//!
//! What stands in for ring 3: [`Files`] is implemented here over the engine
//! with the mount's rules (`crates/fs/fs/src/azvol/mount.rs`, tested against
//! the real `FileSystem` in `tests/host/fs-tests/src/azvol_mount.rs`): a plain
//! write joins the open transaction, only `fsync` commits. The mount's fence
//! (a transaction has one owner; another task's change or commit is `Busy`)
//! is tested on the real mount, with an installer-shaped cut sweep, in
//! `fs-tests`. The boot volume is a map of files, as in `service.rs`.
//!
//! Three buckets. DISCRIMINATING, each red under the change named:
//! `Paths::write_file` fsyncing too (the cut sweep finds a package without its
//! record), `Paths::append` not fsyncing (the journal is not durable on
//! return), the route sending slot directories to the volume. The rest check
//! shape.
//!
//! Wired into the suite by `mod azvol_mount;` in `src/lib.rs`.

use super::service::NoRemote;
use super::*;
use azos_decision::{ProvenanceRecord, Rule, Verdict, PROVENANCE_SIZE};
use azos_idl::Cap;
use azos_packages::update::{IoErr, NAME_BUF};
use azos_packages::{id_words, step, step_name, Packages, PkgMem, Service, VolErr, Work};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/fs/fs/src/azvol/mod.rs"]
pub(crate) mod azvol;

#[allow(dead_code)]
#[path = "../../../../userspace/services/pkgd/src/stage.rs"]
mod stage;

// The restore points the installer lists and prunes: `pkgd`'s own file.
#[allow(dead_code)]
#[path = "../../../../userspace/services/pkgd/src/snap.rs"]
mod snap;

use azvol::{BlockDev, DevError, FormatOptions, Kind, Volume, BLOCK_SIZE};
use stage::{Files, Paths, Platform, Stage, Unlinked, O_APPEND, O_CREAT, O_TRUNC, O_WRONLY, STAGE_MOUNT};

const SECTOR: usize = 512;

// ── the device ────────────────────────────────────────────────────

#[derive(Clone)]
enum DevOp {
    Write { blk: u64, data: Vec<u8> },
    Flush,
}

struct Inner {
    img: Vec<u8>,
    log: Vec<DevOp>,
    /// `flush` fails (a device that takes writes and cannot make them durable).
    fail_flush: bool,
}

#[derive(Clone)]
struct Dev(Arc<Mutex<Inner>>);

impl Dev {
    fn blank(blocks: u64) -> Dev {
        Dev(Arc::new(Mutex::new(Inner { img: vec![0; blocks as usize * BLOCK_SIZE], log: vec![], fail_flush: false })))
    }
    fn from_image(img: Vec<u8>) -> Dev {
        Dev(Arc::new(Mutex::new(Inner { img, log: vec![], fail_flush: false })))
    }
    fn image(&self) -> Vec<u8> {
        self.0.lock().unwrap().img.clone()
    }
    fn log(&self) -> Vec<DevOp> {
        self.0.lock().unwrap().log.clone()
    }
    fn clear_log(&self) {
        self.0.lock().unwrap().log.clear();
    }
}

impl BlockDev for Dev {
    fn block_count(&self) -> u64 {
        (self.0.lock().unwrap().img.len() / BLOCK_SIZE) as u64
    }
    fn read(&mut self, first: u64, buf: &mut [u8]) -> Result<(), DevError> {
        let g = self.0.lock().unwrap();
        let o = first as usize * BLOCK_SIZE;
        if buf.is_empty() || buf.len() % BLOCK_SIZE != 0 || o + buf.len() > g.img.len() {
            return Err(DevError);
        }
        buf.copy_from_slice(&g.img[o..o + buf.len()]);
        Ok(())
    }
    fn write(&mut self, first: u64, buf: &[u8]) -> Result<(), DevError> {
        let mut g = self.0.lock().unwrap();
        let o = first as usize * BLOCK_SIZE;
        if buf.is_empty() || buf.len() % BLOCK_SIZE != 0 || o + buf.len() > g.img.len() {
            return Err(DevError);
        }
        g.img[o..o + buf.len()].copy_from_slice(buf);
        for (i, c) in buf.chunks(BLOCK_SIZE).enumerate() {
            g.log.push(DevOp::Write { blk: first + i as u64, data: c.to_vec() });
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), DevError> {
        let mut g = self.0.lock().unwrap();
        if g.fail_flush {
            return Err(DevError);
        }
        g.log.push(DevOp::Flush);
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Fate {
    Lost,
    Whole,
    Torn(usize),
}

/// The disk after a cut before log op `cut`: everything up to the last flush
/// barrier before it is durable, the writes after it get their `fate`.
fn crash_image(base: &[u8], log: &[DevOp], cut: usize, fate: Fate) -> Vec<u8> {
    let mut img = base.to_vec();
    let barrier = log[..cut].iter().rposition(|o| matches!(o, DevOp::Flush)).map_or(0, |i| i + 1);
    for (i, op) in log[..cut].iter().enumerate() {
        if let DevOp::Write { blk, data } = op {
            let dst = &mut img[*blk as usize * BLOCK_SIZE..(*blk as usize + 1) * BLOCK_SIZE];
            if i < barrier {
                dst.copy_from_slice(data);
            } else {
                match fate {
                    Fate::Lost => {}
                    Fate::Whole => dst.copy_from_slice(data),
                    Fate::Torn(n) => dst[..n * SECTOR].copy_from_slice(&data[..n * SECTOR]),
                }
            }
        }
    }
    img
}

// ── the machine: a boot volume of files and, maybe, a native volume ──

enum Open {
    Vol { ino: u64, pos: u64, append: bool },
    Boot { path: Vec<u8>, pos: usize, buf: Vec<u8>, write: bool },
}

struct World {
    /// The native volume at `/pkg`, if the topology declares one.
    vol: Option<Volume<Dev>>,
    /// The boot volume: files and directories.
    boot: BTreeMap<Vec<u8>, Vec<u8>>,
    boot_dirs: BTreeSet<Vec<u8>>,
    caps: HashMap<u32, Vec<u8>>,
    opens: HashMap<u32, Open>,
    next: u32,
    clock: u64,
}

/// `/pkg/x/y` as `x/y`, or `None` when `path` is not on the native volume.
fn vol_path(path: &[u8]) -> Option<&[u8]> {
    let rest = path.strip_prefix(STAGE_MOUNT)?;
    match rest.first() {
        None => Some(rest),
        Some(b'/') => Some(&rest[1..]),
        Some(_) => None,
    }
}

fn split(p: &[u8]) -> (&[u8], &[u8]) {
    match p.iter().rposition(|&c| c == b'/') {
        Some(i) => (&p[..i], &p[i + 1..]),
        None => (&[], p),
    }
}

#[derive(Clone)]
struct EngineFiles(Rc<RefCell<World>>);

impl Files for EngineFiles {
    fn open(&mut self, path: &[u8], flags: u64) -> Option<u32> {
        let mut w = self.0.borrow_mut();
        let write = flags & O_WRONLY != 0;
        w.next += 1;
        let h = w.next;
        if let Some(rel) = vol_path(path) {
            let v = w.vol.as_mut()?;
            let (parent, name) = split(rel);
            let dir = v.lookup_path(parent).ok()?;
            let ino = match v.lookup(dir, name) {
                Ok(e) => e.ino,
                Err(azvol::Error::NotFound) if flags & O_CREAT != 0 => v.create(dir, name, Kind::File, 0o644).ok()?,
                Err(_) => return None,
            };
            if flags & O_TRUNC != 0 {
                v.truncate(ino, 0).ok()?;
            }
            w.opens.insert(h, Open::Vol { ino, pos: 0, append: flags & O_APPEND != 0 });
            return Some(h);
        }
        let existing = w.boot.get(path).cloned();
        let buf = match (existing, write) {
            (Some(b), false) => b,
            (None, false) => return None,
            (Some(b), true) if flags & O_APPEND != 0 => b,
            (Some(_), true) if flags & O_TRUNC != 0 => Vec::new(),
            (Some(b), true) => b,
            (None, true) if flags & O_CREAT != 0 => Vec::new(),
            (None, true) => return None,
        };
        w.opens.insert(h, Open::Boot { path: path.to_vec(), pos: 0, buf, write });
        Some(h)
    }

    fn read(&mut self, h: u32, out: &mut [u8]) -> Result<usize, ()> {
        let mut w = self.0.borrow_mut();
        let World { vol, opens, .. } = &mut *w;
        match opens.get_mut(&h).ok_or(())? {
            Open::Vol { ino, pos, .. } => {
                let n = vol.as_mut().ok_or(())?.read(*ino, *pos, out).map_err(|_| ())?;
                *pos += n as u64;
                Ok(n)
            }
            Open::Boot { pos, buf, .. } => {
                let n = out.len().min(buf.len().saturating_sub(*pos));
                out[..n].copy_from_slice(&buf[*pos..*pos + n]);
                *pos += n;
                Ok(n)
            }
        }
    }

    fn write(&mut self, h: u32, data: &[u8]) -> Result<usize, ()> {
        let mut w = self.0.borrow_mut();
        let World { vol, opens, .. } = &mut *w;
        match opens.get_mut(&h).ok_or(())? {
            Open::Vol { ino, pos, append } => {
                let v = vol.as_mut().ok_or(())?;
                if *append {
                    *pos = v.stat(*ino).map_err(|_| ())?.size;
                }
                let n = v.write(*ino, *pos, data).map_err(|_| ())?;
                *pos += n as u64;
                Ok(n)
            }
            Open::Boot { buf, write, .. } => {
                if !*write {
                    return Err(());
                }
                buf.extend_from_slice(data);
                Ok(data.len())
            }
        }
    }

    /// `fsync`: the native volume commits its open transaction; the boot
    /// volume has nothing to add.
    fn sync(&mut self, h: u32) -> Result<(), ()> {
        let mut w = self.0.borrow_mut();
        if matches!(w.opens.get(&h), Some(Open::Vol { .. })) {
            w.vol.as_mut().ok_or(())?.commit().map_err(|_| ())?;
        }
        Ok(())
    }

    fn close(&mut self, h: u32) -> Result<(), ()> {
        let mut w = self.0.borrow_mut();
        if let Some(Open::Boot { path, buf, write: true, .. }) = w.opens.remove(&h) {
            w.boot.insert(path, buf);
        }
        Ok(())
    }

    fn unlink(&mut self, path: &[u8]) -> Unlinked {
        let mut w = self.0.borrow_mut();
        if let Some(rel) = vol_path(path) {
            let Some(v) = w.vol.as_mut() else { return Unlinked::Failed };
            let (parent, name) = split(rel);
            let Ok(dir) = v.lookup_path(parent) else { return Unlinked::Missing };
            return match v.unlink(dir, name) {
                Ok(()) => Unlinked::Done,
                Err(azvol::Error::NotFound) => Unlinked::Missing,
                Err(_) => Unlinked::Failed,
            };
        }
        if w.boot.remove(path).is_some() { Unlinked::Done } else { Unlinked::Missing }
    }

    fn exists(&mut self, path: &[u8]) -> bool {
        let mut w = self.0.borrow_mut();
        if let Some(rel) = vol_path(path) {
            return w.vol.as_mut().is_some_and(|v| v.lookup_path(rel).is_ok());
        }
        w.boot.contains_key(path) || w.boot_dirs.contains(path)
    }

    fn mkdir(&mut self, path: &[u8]) -> bool {
        let mut w = self.0.borrow_mut();
        if let Some(rel) = vol_path(path) {
            let Some(v) = w.vol.as_mut() else { return false };
            let (parent, name) = split(rel);
            return v.lookup_path(parent).ok().is_some_and(|d| v.create(d, name, Kind::Dir, 0o755).is_ok());
        }
        w.boot_dirs.insert(path.to_vec());
        true
    }

    fn entry(&mut self, dir: &[u8], index: usize, name: &mut [u8; NAME_BUF]) -> Option<usize> {
        let mut w = self.0.borrow_mut();
        if let Some(rel) = vol_path(dir) {
            let v = w.vol.as_mut()?;
            let d = v.lookup_path(rel).ok()?;
            let e = v.readdir(d).ok()?.into_iter().nth(index)?;
            name[..e.name.len()].copy_from_slice(&e.name);
            return Some(e.name.len());
        }
        let prefix = [dir, b"/"].concat();
        // A FAT32 subdirectory lists `.` and `..` first, as the kernel's
        // `readdir` returns them (the installer's `Paths` leaves them out).
        let dots: [&[u8]; 2] = [b".", b".."];
        let e = dots.into_iter()
            .chain(w.boot.keys().filter_map(|k| k.strip_prefix(&prefix[..])).filter(|r| !r.contains(&b'/')))
            .nth(index)?;
        name[..e.len()].copy_from_slice(e);
        Some(e.len())
    }
}

struct MemBundle(Vec<u8>);

impl azos_packages::update::Source for MemBundle {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read(&mut self, off: u64, buf: &mut [u8]) -> Result<usize, IoErr> {
        let off = off as usize;
        if off > self.0.len() {
            return Err(IoErr::Io);
        }
        let n = buf.len().min(self.0.len() - off);
        buf[..n].copy_from_slice(&self.0[off..off + n]);
        Ok(n)
    }
}

struct TestPlatform(Rc<RefCell<World>>);

impl Platform for TestPlatform {
    type Bundle = MemBundle;

    fn read_package(&mut self, cap: Cap<PkgMem>, len: usize, buf: &mut [u8]) -> Result<usize, VolErr> {
        let obj = self.0.borrow_mut().caps.remove(&cap.raw()).ok_or(VolErr::Io)?;
        if len > buf.len() {
            return Err(VolErr::TooLarge);
        }
        if obj.len() < len {
            return Err(VolErr::Io);
        }
        buf[..len].copy_from_slice(&obj[..len]);
        Ok(len)
    }
    fn open_bundle(&mut self, cap: Cap<PkgMem>, len: usize) -> Result<MemBundle, VolErr> {
        let obj = self.0.borrow_mut().caps.remove(&cap.raw()).ok_or(VolErr::Io)?;
        if obj.len() < len {
            return Err(VolErr::Io);
        }
        Ok(MemBundle(obj[..len].to_vec()))
    }
    fn boot_slots(&mut self) -> Option<(u8, u8)> {
        Some((0, 0))
    }
    fn now_ns(&mut self) -> u64 {
        let mut w = self.0.borrow_mut();
        w.clock += 1;
        w.clock
    }
}

// ── the rig ───────────────────────────────────────────────────────

/// A device (the signed topology on its boot volume, optionally a native
/// volume at `/pkg`) and the installer running on `stage.rs` over it.
struct Az {
    world: Rc<RefCell<World>>,
    dev: Dev,
    work: Box<Work>,
    topo: Box<Topology<'static>>,
}

fn boot_files() -> (BTreeMap<Vec<u8>, Vec<u8>>, BTreeSet<Vec<u8>>) {
    let d = Device0::with_signers(&signer_text("acme", &author(), CEILING));
    let m = service::MemVol::device(&d, &owner());
    (m.files, m.dirs)
}

impl Az {
    /// With a freshly formatted native volume at `/pkg`.
    fn with_volume() -> Az {
        let dev = Dev::blank(2048);
        let o = FormatOptions { block_count: None, label: b"pkg", uuid: [3; 16], time_ns: 1_000 };
        let v = Volume::format(dev.clone(), &o).expect("format");
        Az::over(Some(v), dev)
    }

    /// With no native volume: the installer stages on the boot volume.
    fn boot_only() -> Az {
        Az::over(None, Dev::blank(1))
    }

    fn over(vol: Option<Volume<Dev>>, dev: Dev) -> Az {
        let (boot, mut boot_dirs) = boot_files();
        // The build provisions the staging directory with the boot volume.
        boot_dirs.insert(b"/fat/PKG".to_vec());
        let world = World { vol, boot, boot_dirs, caps: HashMap::new(), opens: HashMap::new(), next: 0, clock: 1000 };
        Az { world: Rc::new(RefCell::new(world)), dev, work: Box::new(Work::new()), topo: Box::new(Topology::empty()) }
    }

    fn service(&mut self) -> Service<'_, Stage<EngineFiles, TestPlatform>, NoRemote> {
        let paths = Paths::new(EngineFiles(self.world.clone()));
        let vol = Stage { paths, plat: TestPlatform(self.world.clone()) };
        Service::new(vol, NoRemote, &mut self.work, &mut self.topo, *owner().verifying_key().as_bytes(), device())
    }

    fn put(&self, handle: u32, bytes: &[u8]) -> (Cap<PkgMem>, u32) {
        self.world.borrow_mut().caps.insert(handle, bytes.to_vec());
        (Cap::from_raw(handle), bytes.len() as u32)
    }
}

/// What a volume image durably holds of the installer's: the packages staged
/// (their ids) and the journal's records.
fn durable(img: Vec<u8>) -> (Vec<[u8; 32]>, Vec<ProvenanceRecord>) {
    let mut v = Volume::mount(Dev::from_image(img)).expect("mount");
    let report = v.check(true).expect("check");
    assert!(report.is_clean(), "the volume does not check clean: {:?}", report.problems);
    let root = v.root();
    let mut staged = Vec::new();
    let mut journal = Vec::new();
    for e in v.readdir(root).unwrap() {
        let size = v.stat(e.ino).unwrap().size as usize;
        let mut data = vec![0u8; size];
        if size > 0 {
            assert_eq!(v.read(e.ino, 0, &mut data).unwrap(), size);
        }
        if e.name.ends_with(b".PKG") {
            staged.push(azos_pkg::Package::parse(&data).expect("a staged file is a whole package").id());
        } else if e.name == b"JOURNAL.BIN" {
            assert_eq!(data.len() % PROVENANCE_SIZE, 0, "the journal ends in the middle of a record");
            journal = data.chunks(PROVENANCE_SIZE).map(|c| ProvenanceRecord::from_bytes(c).unwrap()).collect();
        }
    }
    (staged, journal)
}

fn prefix(id: &[u8; 32]) -> u64 {
    u64::from_be_bytes(id[..8].try_into().unwrap())
}

const FATES: [Fate; 3] = [Fate::Lost, Fate::Whole, Fate::Torn(2)];

// ── tests ─────────────────────────────────────────────────────────

#[test]
fn install_stages_on_the_volume_and_journals_there_and_touches_no_boot_path() {
    let mut a = Az::with_volume();
    let bytes = build(&Spec::acme(), &author());
    let id = azos_pkg::Package::parse(&bytes).unwrap().id();
    let (cap, len) = a.put(7, &bytes);
    let boot_before = a.world.borrow().boot.clone();
    let reply = a.service().install(cap, len);
    assert_eq!(reply[0], 0, "{}", step_name(reply[0]));
    // On return both are durable: no cut, no replay, just the device as it is.
    let (staged, journal) = durable(a.dev.image());
    assert_eq!(staged, vec![id]);
    assert_eq!(journal.len(), 1);
    assert_eq!((journal[0].rule, journal[0].verdict), (Rule::PackageInstall as u8, Verdict::Admit as u8));
    assert_eq!(journal[0].image_hash_prefix, prefix(&id));
    // The boot volume was only read.
    assert_eq!(a.world.borrow().boot, boot_before, "an install wrote to the boot volume");
    // And the installer lists it from the volume.
    assert_eq!(a.service().installed(0), id_words(&id));
    assert_eq!(a.service().installed(1), [0; 4]);
}

/// **Canary.** Make `Paths::write_file` `fsync` too (or `Paths::append` not
/// `fsync` at all): the first turns this red by a cut that finds the package
/// without its record, the second by the no-cut check that the install is
/// durable when it returns.
#[test]
fn power_cut_at_any_device_write_of_an_install_leaves_the_package_and_its_record_or_neither() {
    let mut a = Az::with_volume();
    let base = a.dev.image();
    a.dev.clear_log();
    let bytes = build(&Spec::acme(), &author());
    let id = azos_pkg::Package::parse(&bytes).unwrap().id();
    let (cap, len) = a.put(7, &bytes);
    assert_eq!(a.service().install(cap, len)[0], 0);
    let log = a.dev.log();
    assert!(log.iter().filter(|o| matches!(o, DevOp::Write { .. })).count() > 4, "{}", log.len());
    let (mut none, mut both) = (0, 0);
    for cut in 0..=log.len() {
        for fate in FATES {
            let (staged, journal) = durable(crash_image(&base, &log, cut, fate));
            match (staged.len(), journal.len()) {
                (0, 0) => none += 1,
                (1, 1) => {
                    assert_eq!(staged[0], id);
                    assert_eq!(journal[0].image_hash_prefix, prefix(&id));
                    both += 1;
                }
                (s, j) => panic!("cut {cut}: {s} staged package(s) and {j} journal record(s)"),
            }
        }
    }
    assert!(none > 0 && both > 0, "the sweep must see both ends: none {none} both {both}");
    // Nothing is durable before the journal append's commit: every cut before
    // the last flush-and-superblock pair is the empty volume.
    let first_flush = log.iter().position(|o| matches!(o, DevOp::Flush)).unwrap();
    let (s, j) = durable(crash_image(&base, &log, first_flush, Fate::Whole));
    assert_eq!((s.len(), j.len()), (0, 0), "something was committed before the journal append");
}

#[test]
fn power_cut_at_any_device_write_of_a_removal_leaves_the_package_or_its_removal_record() {
    let mut a = Az::with_volume();
    let bytes = build(&Spec::acme(), &author());
    let id = azos_pkg::Package::parse(&bytes).unwrap().id();
    let (cap, len) = a.put(7, &bytes);
    assert_eq!(a.service().install(cap, len)[0], 0);
    let base = a.dev.image();
    a.dev.clear_log();
    let reply = a.service().remove(id_words(&id));
    assert_eq!(reply[0], 0, "{}", step_name(reply[0]));
    let log = a.dev.log();
    let (mut present, mut gone) = (0, 0);
    for cut in 0..=log.len() {
        for fate in FATES {
            let (staged, journal) = durable(crash_image(&base, &log, cut, fate));
            match (staged.len(), journal.len()) {
                (1, 1) => present += 1,
                (0, 2) => {
                    assert_eq!((journal[1].rule, journal[1].verdict), (Rule::PackageInstall as u8, Verdict::Deny as u8));
                    gone += 1;
                }
                (s, j) => panic!("cut {cut}: {s} staged, {j} journal records"),
            }
        }
    }
    assert!(present > 0 && gone > 0, "present {present} gone {gone}");
}

#[test]
fn a_journal_append_whose_commit_fails_leaves_the_volume_as_it_was() {
    let mut a = Az::with_volume();
    let first = build(&Spec::acme(), &author());
    let (cap, len) = a.put(1, &first);
    assert_eq!(a.service().install(cap, len)[0], 0);
    let before = durable(a.dev.image());
    let mut s = Spec::acme();
    s.name = "second".into();
    s.images = vec![("TWO.ELF".into(), (0..64u8).collect())];
    s.rows = row("TWO.ELF", "best_effort", 20, "{ kind = \"endpoint\", target = \"endpoint.acme\", perm = \"rw\" }");
    let second = build(&s, &author());
    // The device takes the writes and refuses the flush: the commit fails.
    a.dev.0.lock().unwrap().fail_flush = true;
    let (cap, len) = a.put(2, &second);
    let reply = a.service().install(cap, len);
    assert_eq!(reply[0] >> 24, step::IO, "{}", step_name(reply[0]));
    assert_eq!(reply[0] & 0xFF_FFFF, azos_packages::io::JOURNAL);
    let after = durable(a.dev.image());
    assert_eq!(after.0, before.0, "the failed install left a staged package behind");
    assert_eq!(after.1.len(), before.1.len(), "and a journal record");
}

#[test]
fn the_library_paths_are_mapped_to_the_volume_and_the_boot_sets_stay_on_the_boot_volume() {
    let a = Az::with_volume();
    let mut p = Paths::new(EngineFiles(a.world.clone()));
    assert!(p.on_volume());
    // A staged package and the journal: the volume.
    p.write_file(b"/fat/PKG/0A0B0C0D.PKG", b"pkg").unwrap();
    // A whole-system update's slot directory: the boot volume.
    p.write_file(b"/fat/PKG/SYS_B/KERN.BIN", b"kernel").unwrap();
    p.write_file(b"/fat/PKG/SYS_A", b"x").unwrap();
    let w = a.world.borrow();
    assert!(!w.boot.contains_key(&b"/fat/PKG/0A0B0C0D.PKG"[..]));
    assert_eq!(w.boot.get(&b"/fat/PKG/SYS_B/KERN.BIN"[..]).map(|v| &v[..]), Some(&b"kernel"[..]));
    assert!(w.boot.contains_key(&b"/fat/PKG/SYS_A"[..]));
    drop(w);
    // The topology is read from the boot volume, not mapped.
    // The whole signed topology in one read: the default topology is past
    // 8 KiB, so the buffer is a size it fits with room (`!r.more` is the check).
    let mut buf = vec![0u8; 16384];
    let r = p.read_file(b"/fat/CAPS.TOM", &mut buf).unwrap();
    assert!(r.n > 0 && !r.more);
    // The library's directory and its listing are the volume's.
    assert!(p.dir_exists(b"/fat/PKG"));
    let mut name = [0u8; NAME_BUF];
    use azos_packages::update::Store as _;
    let n = p.entry(b"/fat/PKG", 0, &mut name).unwrap();
    assert_eq!(&name[..n], b"0A0B0C0D.PKG");
    drop(p);
    // Only the volume's root lists it.
    let staged_names = {
        let mut w = a.world.borrow_mut();
        let v = w.vol.as_mut().unwrap();
        let root = v.root();
        v.readdir(root).unwrap().into_iter().map(|e| e.name).collect::<Vec<_>>()
    };
    assert_eq!(staged_names, vec![b"0A0B0C0D.PKG".to_vec()]);
    // Names of other directories sharing a prefix are not the library's.
    let mut p = Paths::new(EngineFiles(a.world.clone()));
    p.write_file(b"/fat/PKGX", b"not under the stage directory").unwrap();
    assert!(a.world.borrow().boot.contains_key(&b"/fat/PKGX"[..]));
}

/// **Canary**: `dir_exists` answering for `/fat/PKG` on the boot volume stages
/// a package the kernel's apply never reads.
#[test]
fn with_no_volume_an_install_is_refused_because_nothing_would_apply_it() {
    let mut a = Az::boot_only();
    assert!(!Paths::new(EngineFiles(a.world.clone())).on_volume());
    let bytes = build(&Spec::acme(), &author());
    let (cap, len) = a.put(7, &bytes);
    let r = a.service().install(cap, len);
    assert_eq!(r[0], azos_packages::status(step::IO, azos_packages::io::NO_STAGE_DIR), "{r:?}");
    let w = a.world.borrow();
    assert!(!w.boot.keys().any(|k| k.ends_with(b".PKG")), "nothing is staged on the boot volume");
    assert!(!w.boot.contains_key(&b"/fat/PKG/JOURNAL.BIN"[..]), "and no decision is written for it");
}

/// A distinct package per `i`: its own name, program and row.
fn numbered(i: usize) -> Vec<u8> {
    let mut s = Spec::acme();
    s.name = format!("acme-{i}");
    let image = format!("PKG{i}.ELF");
    s.images = vec![(image.clone(), (0..200u32).map(|b| (b as usize * 5 + i) as u8).collect())];
    s.rows = row(&image, "best_effort", 20, "{ kind = \"endpoint\", target = \"endpoint.acme\", perm = \"rw\" }");
    build(&s, &author())
}

/// The installer and the kernel's apply on one volume: the installer stages,
/// the kernel applies and keeps a restore point per confirmed trial, the
/// installer lists them and asks for the old ones to go, the next boot deletes
/// them. **Canary**: `excess` offering the trial (or `prune` not reading the
/// requests already made) turns the second half red.
#[test]
fn the_installer_prunes_the_restore_points_and_the_next_boot_drops_them() {
    use crate::apply::{boot, pkg_apply, signed_device, Log};
    let d = signed_device();
    let mut a = Az::with_volume();
    let mut buf = Box::new([0u8; snap::BUF]);
    let mut paths = Paths::new(EngineFiles(a.world.clone()));
    assert!(paths.on_volume());
    assert_eq!(snap::list(&mut paths, &mut buf), Ok(snap::Points { kept: 0, trial: false }), "nothing applied yet");
    assert_eq!(snap::prune(&mut paths, 3, &mut buf), Ok(0));
    // Five packages, each installed, applied on a boot and confirmed on the next.
    let kernel_boot = |a: &mut Az, prior: u32| {
        let mut t = d.topology();
        let mut w = a.world.borrow_mut();
        pkg_apply::apply(w.vol.as_mut().unwrap(), &mut t, &boot(prior), &mut Log::default())
    };
    for i in 0..5 {
        let (cap, len) = a.put(10 + i as u32, &numbered(i));
        assert_eq!(a.service().install(cap, len)[0], 0, "install {i}");
        assert!(kernel_boot(&mut a, 0).trial.is_some(), "boot applying package {i}");
        kernel_boot(&mut a, 0); // confirmed
    }
    assert_eq!(snap::list(&mut paths, &mut buf), Ok(snap::Points { kept: 5, trial: false }));
    // The installer keeps three: it asks for the two oldest, once.
    let ids: Vec<u64> = a.world.borrow_mut().vol.as_mut().unwrap().snapshots().iter().map(|s| s.id).collect();
    assert_eq!(snap::prune(&mut paths, 3, &mut buf), Ok(2));
    assert_eq!(snap::prune(&mut paths, 3, &mut buf), Ok(0), "already asked");
    let asked = {
        let mut w = a.world.borrow_mut();
        let v = w.vol.as_mut().unwrap();
        let root = v.root();
        let e = v.lookup(root, azos_pkg::apply::DELETE_REQUESTS).expect("the requests are on the volume");
        let mut b = vec![0u8; v.stat(e.ino).unwrap().size as usize];
        v.read(e.ino, 0, &mut b).unwrap();
        azos_pkg::apply::requested(&b).collect::<Vec<_>>()
    };
    assert_eq!(asked, ids[..2].to_vec(), "the oldest two");
    // Nothing is deleted until the kernel's next boot.
    assert_eq!(a.world.borrow_mut().vol.as_mut().unwrap().snapshots().len(), 5);
    kernel_boot(&mut a, 0);
    let left: Vec<u64> = a.world.borrow_mut().vol.as_mut().unwrap().snapshots().iter().map(|s| s.id).collect();
    assert_eq!(left, ids[2..].to_vec(), "the restore points the installer kept");
    assert_eq!(snap::list(&mut paths, &mut buf), Ok(snap::Points { kept: 3, trial: false }));
    assert_eq!(snap::prune(&mut paths, 3, &mut buf), Ok(0));
    // A new package begins a trial; retention 0 asks for every restore point
    // and never for the one on probation.
    let (cap, len) = a.put(40, &numbered(5));
    assert_eq!(a.service().install(cap, len)[0], 0);
    let trial = kernel_boot(&mut a, 0).trial.expect("a trial");
    assert_eq!(snap::list(&mut paths, &mut buf), Ok(snap::Points { kept: 3, trial: true }));
    assert_eq!(snap::prune(&mut paths, 0, &mut buf), Ok(3));
    kernel_boot(&mut a, 1);
    let left: Vec<u64> = a.world.borrow_mut().vol.as_mut().unwrap().snapshots().iter().map(|s| s.id).collect();
    assert_eq!(left, vec![trial], "only the trial's snapshot is left");
    // The volume checks clean after all of it.
    assert!(a.world.borrow_mut().vol.as_mut().unwrap().check(true).unwrap().is_clean());
}

/// A device with the installer's volume gone has nothing to prune.
#[test]
fn with_no_volume_there_are_no_restore_points() {
    let a = Az::boot_only();
    let mut paths = Paths::new(EngineFiles(a.world.clone()));
    let mut buf = Box::new([0u8; snap::BUF]);
    assert_eq!(snap::list(&mut paths, &mut buf), Ok(snap::Points::default()));
    assert_eq!(snap::prune(&mut paths, 0, &mut buf), Ok(0));
}

/// **An update staged over the files of a FAT32 boot volume**: the slot's
/// directory is listed with `.` and `..` (a FAT32 subdirectory has them), and
/// the second stage into the same slot clears the first set's files, not the
/// directory itself. `Paths` leaves the dot entries out of what the stager
/// sees; with them in, `clear_dir` tries to remove `.` and the stage is
/// refused `Io(Dir)`.
#[test]
fn an_update_staged_twice_into_a_slot_clears_the_old_set_and_not_the_dot_entries() {
    let mut az = Az::boot_only();
    for epoch in [5u32, 6] {
        let bundle = super::update::good(epoch);
        let (cap, len) = az.put(7, &bundle);
        let reply = az.service().update(cap, len);
        assert_eq!(reply[0], 0, "epoch {epoch}: {}", step_name(reply[0]));
    }
    let w = az.world.borrow();
    for (_, name, bytes) in &super::update::parts(6, 3, &super::owner()) {
        assert_eq!(w.boot.get(format!("/fat/PKG/SYS_B/{name}").as_bytes()), Some(bytes), "{name}");
    }
    assert!(w.boot.keys().all(|k| !k.ends_with(b"/.") && !k.ends_with(b"/..")), "no dot entry was ever written or removed");
}
