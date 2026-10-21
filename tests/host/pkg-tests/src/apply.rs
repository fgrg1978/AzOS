// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The boot-time apply of staged packages (`kernel/src/boot/pkg_apply.rs`),
//! compiled unchanged over the REAL azvol engine on a device that can replay a
//! power cut. What stands in for the kernel: [`Log`] for the decision ring and
//! the console, and a topology built from the fixture device's signed texts.
//!
//! Three buckets. DISCRIMINATING (each red under the canary or the change
//! named): the repeated signature, signer and image checks
//! (`pkg-verify-skip-canary`, `pkg-signer-canary`, `pkg-image-canary`), the
//! epoch floor (`pkg-epoch-canary`), the trial's rollback
//! (`pkg-trial-canary`), the atomicity of the apply (the cut sweep: images written
//! outside the group show up as a half-applied volume) and the restore of `APPS/`
//! from the snapshot. The rest check shape.
//!
//! Wired into the suite by `mod apply;` in `src/lib.rs`.

use super::*;
use crate::azvol_mount::azvol as engine;
use azos_decision::{ProvenanceRecord, Rule, Verdict};
use azos_pkg::apply::{self as proto, SnapState};
use azos_pkg::Package;
use engine::{BlockDev, DevError, FormatOptions, Kind, Volume, BLOCK_SIZE};
use std::collections::BTreeMap;

#[allow(dead_code)]
#[path = "../../../../kernel/src/boot/pkg_apply.rs"]
pub(crate) mod pkg_apply;
use pkg_apply::{apply, undo, Applied, Boot, Sink};

const SECTOR: usize = 512;

// ── the device ────────────────────────────────────────────────────

#[derive(Clone)]
enum Op {
    Write { blk: u64, data: Vec<u8> },
    Flush,
}

struct MemDev {
    img: Vec<u8>,
    log: Vec<Op>,
}

impl MemDev {
    fn new(blocks: u64) -> MemDev {
        MemDev { img: vec![0u8; blocks as usize * BLOCK_SIZE], log: Vec::new() }
    }
    fn from_image(img: Vec<u8>) -> MemDev {
        MemDev { img, log: Vec::new() }
    }
}

impl BlockDev for MemDev {
    fn block_count(&self) -> u64 {
        (self.img.len() / BLOCK_SIZE) as u64
    }
    fn read(&mut self, first: u64, buf: &mut [u8]) -> Result<(), DevError> {
        let o = first as usize * BLOCK_SIZE;
        if buf.is_empty() || buf.len() % BLOCK_SIZE != 0 || o + buf.len() > self.img.len() {
            return Err(DevError);
        }
        buf.copy_from_slice(&self.img[o..o + buf.len()]);
        Ok(())
    }
    fn write(&mut self, first: u64, buf: &[u8]) -> Result<(), DevError> {
        let o = first as usize * BLOCK_SIZE;
        if buf.is_empty() || buf.len() % BLOCK_SIZE != 0 || o + buf.len() > self.img.len() {
            return Err(DevError);
        }
        self.img[o..o + buf.len()].copy_from_slice(buf);
        for (i, c) in buf.chunks(BLOCK_SIZE).enumerate() {
            self.log.push(Op::Write { blk: first + i as u64, data: c.to_vec() });
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), DevError> {
        self.log.push(Op::Flush);
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Fate {
    Lost,
    Whole,
    Torn(usize),
}

/// The disk after a cut before log op `cut`: everything behind the last flush
/// is durable, the writes after it get their `fate`.
fn crash_image(base: &[u8], log: &[Op], cut: usize, fate: &dyn Fn(usize) -> Fate) -> Vec<u8> {
    let mut img = base.to_vec();
    let barrier = log[..cut].iter().rposition(|o| matches!(o, Op::Flush)).map_or(0, |i| i + 1);
    for (i, op) in log[..cut].iter().enumerate() {
        if let Op::Write { blk, data } = op {
            let dst = &mut img[*blk as usize * BLOCK_SIZE..(*blk as usize + 1) * BLOCK_SIZE];
            if i < barrier {
                dst.copy_from_slice(data);
            } else {
                match fate(i) {
                    Fate::Lost => {}
                    Fate::Whole => dst.copy_from_slice(data),
                    Fate::Torn(n) => dst[..n * SECTOR].copy_from_slice(&data[..n * SECTOR]),
                }
            }
        }
    }
    img
}

// ── the kernel's side ─────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct Log {
    pub(crate) records: Vec<ProvenanceRecord>,
    pub(crate) notes: Vec<String>,
}

impl Sink for Log {
    fn record(&mut self, p: &ProvenanceRecord) {
        self.records.push(*p);
    }
    fn note(&mut self, line: core::fmt::Arguments<'_>) {
        self.notes.push(line.to_string());
    }
}

impl Log {
    fn verdicts(&self) -> Vec<(u8, u64)> {
        self.records.iter().map(|p| (p.verdict, p.n[2])).collect()
    }
}

pub(crate) fn signed_device() -> &'static Device0 {
    Box::leak(Box::new(Device0::with_signers(&signer_text("acme", &author(), CEILING))))
}

fn topo(d: &'static Device0) -> Box<Topology<'static>> {
    d.topology()
}

pub(crate) fn boot(prior: u32) -> Boot<'static> {
    Boot { device: device(), now_ns: 7_000, prior_unconfirmed: prior, max_attempts: 3 }
}

fn volume() -> Volume<MemDev> {
    let o = FormatOptions { block_count: None, label: b"pkgvol", uuid: [3; 16], time_ns: 1_000 };
    Volume::format(MemDev::new(2048), &o).expect("format")
}

/// The staged file name of a package: the first four bytes of its id.
fn staged_name_of(bytes: &[u8]) -> String {
    let id = Package::parse(bytes).expect("a package").id();
    format!("{:02X}{:02X}{:02X}{:02X}.PKG", id[0], id[1], id[2], id[3])
}

/// What pkgd leaves: the package as a file in the volume root, committed.
fn stage(v: &mut Volume<MemDev>, bytes: &[u8]) -> String {
    let name = staged_name_of(bytes);
    let root = v.root();
    let ino = v.create(root, name.as_bytes(), Kind::File, 0o644).expect("create");
    assert_eq!(v.write(ino, 0, bytes).expect("write"), bytes.len());
    v.commit().expect("commit");
    name
}

fn staged(v: &mut Volume<MemDev>) -> Vec<String> {
    let root = v.root();
    v.readdir(root)
        .unwrap()
        .into_iter()
        .filter(|e| proto::staged_name(&e.name))
        .map(|e| String::from_utf8(e.name).unwrap())
        .collect()
}

fn apps(v: &mut Volume<MemDev>) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let root = v.root();
    let Ok(dir) = v.lookup(root, proto::APPS_DIR) else { return out };
    for e in v.readdir(dir.ino).unwrap() {
        let size = v.stat(e.ino).unwrap().size as usize;
        let mut data = vec![0u8; size];
        let mut done = 0;
        while done < size {
            done += v.read(e.ino, done as u64, &mut data[done..]).unwrap();
        }
        out.insert(String::from_utf8(e.name).unwrap(), data);
    }
    out
}

fn table(v: &mut Volume<MemDev>) -> Vec<(u64, SnapState)> {
    let root = v.root();
    let Ok(e) = v.lookup(root, proto::TABLE) else { return Vec::new() };
    let size = v.stat(e.ino).unwrap().size as usize;
    let mut b = vec![0u8; size];
    v.read(e.ino, 0, &mut b).unwrap();
    proto::Table::parse(&b).expect("the table parses").snaps().map(|s| (s.id, s.state)).collect()
}

fn journal(v: &mut Volume<MemDev>) -> Vec<ProvenanceRecord> {
    let root = v.root();
    let Ok(e) = v.lookup(root, proto::JOURNAL) else { return Vec::new() };
    let size = v.stat(e.ino).unwrap().size as usize;
    let mut b = vec![0u8; size];
    v.read(e.ino, 0, &mut b).unwrap();
    b.chunks_exact(azos_decision::PROVENANCE_SIZE).map(|c| ProvenanceRecord::from_bytes(c).unwrap()).collect()
}

fn run(v: &mut Volume<MemDev>, d: &'static Device0, prior: u32) -> (Box<Topology<'static>>, Applied, Log) {
    let mut t = topo(d);
    let mut log = Log::default();
    let a = apply(v, &mut t, &boot(prior), &mut log);
    (t, a, log)
}

fn acme() -> Vec<u8> {
    build(&Spec::acme(), &author())
}

fn other() -> Vec<u8> {
    let mut s = Spec::acme();
    s.name = "acme-other".into();
    s.images = vec![("OTHER.ELF".into(), (0..500u32).map(|i| (i * 3) as u8).collect())];
    s.rows = row("OTHER.ELF", "best_effort", 21, "{ kind = \"endpoint\", target = \"endpoint.acme\", perm = \"rw\" }");
    build(&s, &author())
}

// ── the apply ─────────────────────────────────────────────────────

/// **Canary** `pkg-verify-skip-canary`, `pkg-signer-canary`: the forged and the
/// foreign package are applied although the installer "admitted" them.
#[test]
fn what_the_installer_staged_is_judged_again() {
    let d = signed_device();
    let mut v = volume();
    let mut forged = acme();
    forged[HEADER_LEN + 32 + 5] ^= 1; // one bit of the signature
    stage(&mut v, &forged);
    stage(&mut v, &build(&other_with_stranger(), &stranger()));
    let before = topo(d).tasks_len();
    let (t, a, log) = run(&mut v, d, 0);
    assert_eq!((t.tasks_len(), a.rows, a.packages), (before, 0, 0), "no row joined");
    assert!(apps(&mut v).is_empty(), "no program written");
    assert!(a.trial.is_none() && table(&mut v).is_empty(), "no trial: nothing was applied");
    assert_eq!(log.records.len(), 2);
    assert!(log.records.iter().all(|p| p.verdict == Verdict::Refuse as u8 && p.rule == Rule::PackageInstall as u8));
    let codes: Vec<u64> = log.records.iter().map(|p| p.n[2] >> 24).collect();
    assert!(codes.contains(&4), "signature (step 4): {codes:?}");
    assert!(codes.contains(&3), "unknown signer (step 3): {codes:?}");
}

fn other_with_stranger() -> Spec {
    let mut s = Spec::acme();
    s.name = "stranger".into();
    s
}

/// **Canary** `pkg-image-canary`: an image that is not the signed one is applied.
#[test]
fn an_image_that_is_not_the_signed_one_is_not_applied() {
    let d = signed_device();
    let mut v = volume();
    let mut bytes = acme();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x40;
    stage(&mut v, &bytes);
    let (t, a, log) = run(&mut v, d, 0);
    assert_eq!((a.packages, t.tasks_len()), (0, topo(d).tasks_len()));
    assert!(apps(&mut v).is_empty());
    assert_eq!(log.records.len(), 1);
    assert_eq!(log.records[0].n[2] >> 24, 6, "images (step 6)");
}

/// **Canary** `pkg-epoch-canary`: a package signed against an epoch below the
/// device's floor is applied.
#[test]
fn a_package_below_the_epoch_floor_is_not_applied() {
    let d = signed_device();
    let mut v = volume();
    let mut s = Spec::acme();
    s.sec_epoch = 1;
    stage(&mut v, &build(&s, &author()));
    let mut t = topo(d);
    let mut log = Log::default();
    let b = Boot { device: Device { epoch_floor: 2, ..device() }, ..boot(0) };
    let a = apply(&mut v, &mut t, &b, &mut log);
    assert_eq!((a.packages, a.rows), (0, 0));
    assert!(apps(&mut v).is_empty());
    assert_eq!(log.records[0].n[2] >> 24, 18, "epoch (step 18)");
    // At the floor it applies.
    let mut t = topo(d);
    let b = Boot { device: Device { epoch_floor: 1, ..device() }, ..boot(0) };
    assert_eq!(apply(&mut v, &mut t, &b, &mut Log::default()).packages, 1);
}

#[test]
fn a_staged_package_is_applied_after_a_snapshot_and_begins_a_trial() {
    let d = signed_device();
    let mut v = volume();
    let name = stage(&mut v, &acme());
    let before = topo(d).tasks_len();
    let (t, a, log) = run(&mut v, d, 0);
    assert_eq!((a.first_row, a.rows, a.packages), (before, 1, 1));
    assert_eq!(t.tasks()[before].name.as_bytes(), b"ACME.ELF");
    assert_eq!(apps(&mut v).get("ACME.ELF").map(|d| d.len()), Some(300), "the program is on the volume");
    let id = a.trial.expect("a trial began");
    assert_eq!(table(&mut v), vec![(id, SnapState::Trial)]);
    assert_eq!(v.snapshots().len(), 1);
    assert_eq!(v.snapshots()[0].label, proto::SNAPSHOT_LABEL);
    assert_eq!(staged(&mut v), vec![name], "the staged package stays: it is the installed set");
    assert_eq!(log.verdicts(), vec![(Verdict::Admit as u8, 0)]);
    assert_eq!(a.fresh.len(), 1);
    // What the kernel binds to the row: the digest of the bytes on the volume.
    let on_volume = apps(&mut v).remove("ACME.ELF").unwrap();
    assert_eq!(a.images.len(), 1);
    assert_eq!(a.images[0].name, b"ACME.ELF");
    assert_eq!(a.images[0].sha256, azos_crypto::sha256::sha256(&on_volume), "the signed digest is that of the written program");
    // The decision is on the volume too, with the package id.
    let j = journal(&mut v);
    assert_eq!(j.len(), 1);
    assert_eq!(j[0].image_hash_prefix, receipt_prefix(&acme()));
    assert!(v.check(true).unwrap().is_clean());
}

fn receipt_prefix(bytes: &[u8]) -> u64 {
    azos_pkg::receipt::id_prefix(&Package::parse(bytes).unwrap().id())
}

#[test]
fn the_next_boot_merges_the_same_rows_and_confirms_the_trial() {
    let d = signed_device();
    let mut v = volume();
    stage(&mut v, &acme());
    let (_, a, _) = run(&mut v, d, 0);
    let id = a.trial.unwrap();
    // Boot 2: the counter is 0 (the first boot was confirmed good).
    let (t, a2, log) = run(&mut v, d, 0);
    assert_eq!((a2.rows, a2.packages, a2.fresh.len(), a2.trial), (1, 1, 0, None), "the rows join again, nothing is rewritten");
    assert_eq!(t.tasks().last().unwrap().name.as_bytes(), b"ACME.ELF");
    assert_eq!(a2.images.len(), 1, "a program already on the volume is bound at every boot, not only at its first");
    assert_eq!(a2.images[0].sha256, a.images[0].sha256);
    assert_eq!(table(&mut v), vec![(id, SnapState::Kept)], "the snapshot is a restore point now");
    assert_eq!(v.snapshots().len(), 1);
    assert_eq!(log.verdicts(), vec![(Verdict::Admit as u8, 0)]);
    assert_eq!(journal(&mut v).len(), 1, "a repeat is not journalled again");
}

/// **Canary** `pkg-trial-canary`: the attempts are spent and the package stays.
#[test]
fn a_trial_that_never_confirms_is_rolled_back_to_the_snapshot() {
    let d = signed_device();
    let mut v = volume();
    // An earlier package, applied and confirmed: its program must survive.
    stage(&mut v, &other());
    run(&mut v, d, 0);
    run(&mut v, d, 0);
    let kept = apps(&mut v);
    assert_eq!(kept.keys().collect::<Vec<_>>(), vec!["OTHER.ELF"]);
    // The new one begins a trial at a boot with 1 unconfirmed boot behind it.
    let new = stage(&mut v, &acme());
    let (_, a, _) = run(&mut v, d, 1);
    let trial = a.trial.expect("trial");
    assert_eq!(apps(&mut v).len(), 2);
    // Two failed boots later it is still on probation: rows merge, nothing moves.
    for prior in [2, 3] {
        let (t, a, log) = run(&mut v, d, prior);
        assert_eq!(a.packages, 2, "both packages are still applied at prior {prior}");
        assert!(t.tasks().iter().any(|r| r.name.as_bytes() == b"ACME.ELF"));
        assert!(log.notes.iter().any(|n| n.contains("not confirmed yet")), "{:?}", log.notes);
    }
    // The third failed boot spends the attempts (prior 4 - base 1 = 3).
    let (t, a, log) = run(&mut v, d, 4);
    assert_eq!(a.packages, 1, "only the confirmed package is applied");
    assert!(t.tasks().iter().all(|r| r.name.as_bytes() != b"ACME.ELF"));
    assert_eq!(apps(&mut v), kept, "APPS/ is what the snapshot held");
    assert!(!staged(&mut v).contains(&new), "the trial's package is out of the staging directory");
    assert_eq!(table(&mut v).iter().filter(|(_, s)| *s == SnapState::Trial).count(), 0);
    assert!(!v.snapshots().iter().any(|s| s.id == trial), "the trial's snapshot is gone");
    let refused: Vec<u64> = log.records.iter().filter(|p| p.verdict == Verdict::Refuse as u8).map(|p| p.n[2] >> 24).collect();
    assert_eq!(refused, vec![20], "unconfirmed trial (step 20)");
    assert!(journal(&mut v).iter().any(|p| p.verdict == Verdict::Refuse as u8), "and the journal says so");
    assert!(v.check(true).unwrap().is_clean());
}

#[test]
fn a_new_package_waits_while_a_trial_is_on_probation() {
    let d = signed_device();
    let mut v = volume();
    stage(&mut v, &acme());
    run(&mut v, d, 0);
    stage(&mut v, &other());
    let (_, a, log) = run(&mut v, d, 1);
    assert_eq!((a.packages, a.trial), (1, None), "one trial at a time");
    assert!(!apps(&mut v).contains_key("OTHER.ELF"));
    assert!(log.notes.iter().any(|n| n.contains("waits for the trial")));
    // Once the boot is confirmed, the waiting one is applied.
    let (_, a, _) = run(&mut v, d, 0);
    assert_eq!(a.fresh.len(), 1);
    assert!(apps(&mut v).contains_key("OTHER.ELF"));
}

#[test]
fn the_kernels_check_refusing_the_merge_undoes_the_trial() {
    let d = signed_device();
    let mut v = volume();
    stage(&mut v, &other());
    run(&mut v, d, 0);
    run(&mut v, d, 0);
    let kept = apps(&mut v);
    let new = stage(&mut v, &acme());
    let (_, a, _) = run(&mut v, d, 0);
    assert_eq!(apps(&mut v).len(), 2);
    // The kernel's memory/deadline check refused the merged topology.
    let mut log = Log::default();
    undo(&mut v, &a, &boot(0), &mut log);
    assert_eq!(apps(&mut v), kept, "the new program is gone, the old one is untouched");
    assert!(!staged(&mut v).contains(&new));
    assert_eq!(log.records.len(), 1);
    assert_eq!(log.records[0].n[2] >> 24, 19, "boot admission (step 19)");
    assert!(table(&mut v).iter().all(|(_, s)| *s == SnapState::Kept));
    assert_eq!(v.snapshots().len(), 1, "only the old restore point is left");
    // An apply that began no trial has nothing to undo (and binds nothing).
    assert!(Applied::default().images.is_empty());
    let mut log = Log::default();
    undo(&mut v, &Applied::default(), &boot(0), &mut log);
    assert!(log.records.is_empty());
}

#[test]
fn a_removed_package_takes_its_program_with_it() {
    let d = signed_device();
    let mut v = volume();
    let a = stage(&mut v, &acme());
    stage(&mut v, &other());
    run(&mut v, d, 0);
    run(&mut v, d, 0);
    assert_eq!(apps(&mut v).len(), 2);
    let root = v.root();
    v.unlink(root, a.as_bytes()).unwrap();
    v.commit().unwrap();
    let (t, r, _) = run(&mut v, d, 0);
    assert_eq!(r.packages, 1);
    assert!(t.tasks().iter().all(|x| x.name.as_bytes() != b"ACME.ELF"));
    assert_eq!(apps(&mut v).keys().collect::<Vec<_>>(), vec!["OTHER.ELF"], "the stray program is removed");
}

#[test]
fn a_program_changed_on_the_volume_is_written_back() {
    let d = signed_device();
    let mut v = volume();
    stage(&mut v, &acme());
    run(&mut v, d, 0);
    run(&mut v, d, 0);
    let root = v.root();
    let dir = v.lookup(root, proto::APPS_DIR).unwrap().ino;
    let ino = v.lookup(dir, b"ACME.ELF").unwrap().ino;
    v.write(ino, 10, &[0xEE; 4]).unwrap();
    v.commit().unwrap();
    let (_, a, _) = run(&mut v, d, 0);
    assert_eq!(a.fresh.len(), 1, "what runs is what was signed, not what a writer left");
    assert_eq!(apps(&mut v)["ACME.ELF"], Spec::acme().images[0].1);
}

#[test]
fn snapshots_the_installer_asked_to_drop_are_dropped_but_never_the_trial() {
    let d = signed_device();
    let mut v = volume();
    stage(&mut v, &acme());
    let (_, a, _) = run(&mut v, d, 0);
    let first = a.trial.unwrap();
    run(&mut v, d, 0); // confirmed: a restore point
    stage(&mut v, &other());
    let (_, a, _) = run(&mut v, d, 0);
    let second = a.trial.unwrap();
    assert_eq!(table(&mut v), vec![(first, SnapState::Kept), (second, SnapState::Trial)]);
    // The installer asks for both.
    let root = v.root();
    let req = v.create(root, proto::DELETE_REQUESTS, Kind::File, 0o644).unwrap();
    let mut b = Vec::new();
    b.extend_from_slice(&proto::request(first));
    b.extend_from_slice(&proto::request(second));
    b.extend_from_slice(&proto::request(999));
    v.write(req, 0, &b).unwrap();
    v.commit().unwrap();
    run(&mut v, d, 1);
    assert_eq!(table(&mut v), vec![(second, SnapState::Trial)], "the restore point went, the trial stayed");
    assert!(v.snapshots().iter().all(|s| s.id == second));
    assert!(v.lookup(root, proto::DELETE_REQUESTS).is_err(), "the requests are consumed");
    assert!(v.check(true).unwrap().is_clean());
}

#[test]
fn a_new_package_is_not_applied_when_the_snapshots_are_all_taken() {
    let d = signed_device();
    let mut v = volume();
    for _ in 0..proto::SNAP_MAX {
        v.snapshot_create(proto::SNAPSHOT_LABEL).unwrap();
    }
    stage(&mut v, &acme());
    let before = topo(d).tasks_len();
    let (t, a, log) = run(&mut v, d, 0);
    assert_eq!((a.packages, t.tasks_len(), a.trial), (0, before, None), "the rows are not merged without the programs");
    assert!(apps(&mut v).is_empty());
    assert_eq!(log.records[0].n[2] >> 24, 21, "volume (step 21)");
}

/// The atomicity of an apply: at every device write of it, with the writes
/// since the last flush lost, whole or torn, the volume that comes back is
/// either as it was before (staged package, no program, no trial) or holds the
/// whole apply (program, trial in the table, the journal record), never a
/// program without its trial. And the boot after the cut applies it either way.
#[test]
fn power_cut_at_any_device_write_of_an_apply_leaves_the_old_volume_or_the_whole_apply() {
    let d = signed_device();
    let mut v = volume();
    stage(&mut v, &acme());
    let base = v.device().img.clone();
    v.device_mut().log.clear();
    let (_, a, _) = run(&mut v, d, 0);
    assert!(a.trial.is_some());
    let log = v.device().log.clone();
    assert!(log.len() > 8, "the apply wrote something to cut ({})", log.len());
    let want = Spec::acme().images[0].1.clone();
    let fates: [(&str, &dyn Fn(usize) -> Fate); 3] =
        [("lost", &|_| Fate::Lost), ("whole", &|_| Fate::Whole), ("torn", &|i| if i % 2 == 0 { Fate::Torn(3) } else { Fate::Lost })];
    let (mut old, mut new) = (0, 0);
    for cut in 0..=log.len() {
        for (fname, fate) in &fates {
            let img = crash_image(&base, &log, cut, *fate);
            let mut w = Volume::mount(MemDev::from_image(img)).unwrap_or_else(|e| panic!("cut {cut} {fname}: mount {e:?}"));
            let programs = apps(&mut w);
            let t = table(&mut w);
            match (programs.len(), t.len()) {
                (0, 0) => old += 1,
                (1, 1) => {
                    assert_eq!(programs["ACME.ELF"], want, "cut {cut} {fname}: the program is whole");
                    assert_eq!(t[0].1, SnapState::Trial);
                    assert_eq!(journal(&mut w).len(), 1, "cut {cut} {fname}: and its record with it");
                    new += 1;
                }
                (p, s) => panic!("cut {cut} {fname}: {p} program(s) and {s} snapshot(s) in the table: a half apply"),
            }
            assert!(w.check(true).unwrap().is_clean(), "cut {cut} {fname}: the volume checks");
            // The next boot finishes the job from whichever state came back.
            let (t, a, _) = run(&mut w, d, 0);
            assert_eq!(a.packages, 1, "cut {cut} {fname}: the package is applied after the cut");
            assert!(t.tasks().iter().any(|r| r.name.as_bytes() == b"ACME.ELF"));
            assert_eq!(apps(&mut w)["ACME.ELF"], want);
        }
    }
    assert!(old > 0 && new > 0, "the sweep saw both sides ({old} old, {new} new)");
}

#[test]
fn the_table_round_trips_and_a_file_that_is_not_one_is_refused() {
    let snaps = [
        proto::SnapRec::new(3, 100, 2, SnapState::Kept, b"pkg-apply"),
        proto::SnapRec::new(9, 200, 0, SnapState::Trial, b"pkg-apply"),
    ];
    let ids = [[1u8; 32], [2u8; 32]];
    let mut buf = vec![0u8; proto::TABLE_MAX];
    let n = proto::encode_table(&snaps, &ids, &mut buf).unwrap();
    let t = proto::Table::parse(&buf[..n]).unwrap();
    assert_eq!(t.snaps().collect::<Vec<_>>(), snaps);
    assert_eq!(t.ids().collect::<Vec<_>>(), ids);
    assert_eq!(t.trial().map(|s| s.id), Some(9));
    for cut in [0, 7, 15, n - 1] {
        assert!(proto::Table::parse(&buf[..cut]).is_err(), "truncated at {cut}");
    }
    let mut bad_state = buf[..n].to_vec();
    bad_state[16 + 20] = 9;
    assert_eq!(proto::Table::parse(&bad_state).err(), Some(proto::TableError::Record));
    let mut magic = buf[..n].to_vec();
    magic[0] ^= 1;
    assert_eq!(proto::Table::parse(&magic).err(), Some(proto::TableError::Format));
}

#[test]
fn the_installers_retention_keeps_the_newest_restore_points_and_never_the_trial() {
    let snaps: Vec<_> = (1..=6u64)
        .map(|i| proto::SnapRec::new(i, i * 10, 0, if i == 6 { SnapState::Trial } else { SnapState::Kept }, b"pkg-apply"))
        .collect();
    let mut buf = vec![0u8; proto::TABLE_MAX];
    let n = proto::encode_table(&snaps, &[], &mut buf).unwrap();
    let t = proto::Table::parse(&buf[..n]).unwrap();
    assert_eq!(proto::excess(&t, 3, &[]).collect::<Vec<_>>(), vec![1, 2], "five restore points, three kept");
    assert_eq!(proto::excess(&t, 5, &[]).count(), 0);
    assert_eq!(proto::excess(&t, 0, &[]).collect::<Vec<_>>(), vec![1, 2, 3, 4, 5], "the trial is never offered");
    // Ones already asked for count as gone.
    let asked = proto::request(1);
    assert_eq!(proto::excess(&t, 3, &asked).collect::<Vec<_>>(), vec![2], "four live, three kept");
}

/// **Canary** `pkg-trial-canary`.
#[test]
fn the_trial_rule_is_the_ab_rule() {
    use proto::{trial_next, Next};
    assert_eq!(trial_next(0, 0, 3), Next::Confirm);
    assert_eq!(trial_next(5, 0, 3), Next::Confirm, "a cleared counter confirms whatever it was");
    assert_eq!(trial_next(0, 1, 3), Next::Wait);
    assert_eq!(trial_next(0, 2, 3), Next::Wait);
    assert_eq!(trial_next(0, 3, 3), Next::RollBack);
    assert_eq!(trial_next(2, 4, 3), Next::Wait, "attempts count from the boot that took the snapshot");
    assert_eq!(trial_next(2, 5, 3), Next::RollBack);
}

// ── launch grants: a package row that starts ──────────────────────

#[allow(dead_code)]
#[path = "../../../../userspace/services/compmgr/src/tree.rs"]
mod tree;

use azos_abi::cap::{CapKind, CapPerms};
use azos_topology::builder::{manager_starts, MANAGER_CAPS_MAX, TASK_COMPMGR_IMAGE};
use azos_topology::MaybeStr;

/// A package whose one row, `START.ELF`, says `start = true`.
fn starting() -> Vec<u8> {
    let mut s = Spec::acme();
    s.name = "acme-start".into();
    s.images = vec![("START.ELF".into(), (0..400u32).map(|i| (i * 5) as u8).collect())];
    s.rows = "[task.START.ELF]\nclass = \"best_effort\"\npriority = 20\nmem_pages = 32\nstart = true\n\
              caps = [\n    { kind = \"endpoint\", target = \"endpoint.acme\", perm = \"rw\" },\n]\n"
        .into();
    build(&s, &author())
}

/// The component manager's grants, as (kind, permission bits, target, transfer).
fn manager_caps(t: &Topology<'static>) -> Vec<(CapKind, u8, String, bool)> {
    let row = t.find_task(&MaybeStr::from_bytes(TASK_COMPMGR_IMAGE)).expect("the fixture topology has the component manager's row");
    t.caps_of(row).iter().map(|c| (c.kind, c.perms.bits(), c.target.as_str().to_string(), c.transfer)).collect()
}

fn launch_grants(t: &Topology<'static>, image: &str) -> usize {
    manager_caps(t).iter().filter(|c| c.0 == CapKind::Node && c.1 == CapPerms::EXEC.bits() && c.2 == image).count()
}

/// The records that are launch grants.
fn grant_records(log: &Log) -> Vec<&ProvenanceRecord> {
    log.records.iter().filter(|p| p.n[2] & pkg_apply::LAUNCH_GRANT != 0).collect()
}

/// **Canary** `pkg-launch-grant-canary`: the apply leaves the grant out, and
/// the manager's row is as the signed topology had it.
#[test]
fn a_merged_row_that_starts_gets_a_launch_grant_on_exactly_that_row() {
    let d = signed_device();
    let mut v = volume();
    stage(&mut v, &starting());
    let before = manager_caps(&topo(d));
    let (t, a, log) = run(&mut v, d, 0);
    assert_eq!((a.rows, a.packages), (1, 1));
    let row = &t.tasks()[a.first_row];
    assert!(manager_starts(row), "the row starts and the manager is the one to start it");
    let after = manager_caps(&t);
    assert_eq!(after[..before.len()], before[..], "the grants the signed topology gave are untouched, in order");
    assert_eq!(
        after[before.len()..],
        [(CapKind::Node, CapPerms::EXEC.bits(), "START.ELF".to_string(), false)],
        "one grant: EXEC on the row's name, not transferable"
    );
    assert_eq!(launch_grants(&t, "START.ELF"), 1);
    // The decision: the install, then the grant of the row.
    assert_eq!(log.records.len(), 2);
    let g = grant_records(&log);
    assert_eq!(g.len(), 1);
    assert_eq!((g[0].rule, g[0].verdict), (Rule::PackageInstall as u8, Verdict::Admit as u8));
    assert_eq!((g[0].subject, g[0].topology_row_id), (a.first_row as u32 + 1, a.first_row as u32 + 1));
    assert_eq!(g[0].n[2], pkg_apply::LAUNCH_GRANT, "granted: no denial code");
    assert_eq!(g[0].image_hash_prefix, u64::from_be_bytes(a.images[0].sha256[..8].try_into().unwrap()));
    // The manager's row is the only one whose grants changed.
    assert!(t.tasks().iter().all(|r| r.name.as_bytes() == TASK_COMPMGR_IMAGE || r.name.as_bytes() == b"START.ELF" || {
        let was = topo(d);
        let same = was.find_task(&r.name).map(|o| was.caps_of(o).len() == t.caps_of(r).len());
        same == Some(true)
    }));
}

/// The kernel's check at `SYS_SPAWN_EX`, over what the topology gives the
/// manager: a launch grant with `EXEC` on the image's name.
struct Manager<'t> {
    topo: &'t Topology<'static>,
    spawned: Vec<(String, String)>,
    refused: Vec<String>,
}

impl tree::Host for Manager<'_> {
    fn spawn(&mut self, dir: &[u8], image: &[u8]) -> Result<u32, i32> {
        let name = String::from_utf8(image.to_vec()).unwrap();
        if launch_grants(self.topo, &name) == 0 {
            self.refused.push(name);
            return Err(-13);
        }
        self.spawned.push((name, String::from_utf8(dir.to_vec()).unwrap()));
        Ok(100 + self.spawned.len() as u32)
    }
    fn stop(&mut self, _: u32) {}
    fn now_ns(&mut self) -> u64 {
        10_000_000_000
    }
    fn record(&mut self, _: &tree::Event<'_>) {}
    fn contract(&mut self, _: &[u8]) -> Option<azos_idl::OnFailure> {
        None
    }
}

/// What `/proc/components` renders for the manager: the rows it starts, in
/// row order, the ones a package brought with their directory.
fn view(t: &Topology<'static>, first_package_row: usize) -> String {
    let mut out = String::new();
    for (i, r) in t.tasks().iter().enumerate().filter(|(_, r)| manager_starts(r)) {
        out.push_str(&format!("{} on-failure - -", r.name.as_str()));
        if i >= first_package_row {
            out.push_str(" /pkg/APPS");
        }
        out.push('\n');
    }
    out.push_str("end\n");
    out
}

fn start_all<'a>(t: &'a Topology<'static>, first_package_row: usize) -> Manager<'a> {
    let mut m = Manager { topo: t, spawned: Vec::new(), refused: Vec::new() };
    let mut tree = tree::Tree::new(tree::Intensity { burst: 3, interval_ns: 300_000_000_000, cooldown_ns: 1_000_000_000 });
    tree.load(view(t, first_package_row).as_bytes(), &mut m);
    tree.start_all(&mut m);
    m
}

/// **Canary** `pkg-launch-grant-canary`: without the grant the manager's spawn
/// of the merged row is refused (the boot bug), and the rows of the signed
/// topology still start.
#[test]
fn the_manager_starts_a_merged_row_from_the_package_directory_like_a_static_one() {
    let d = signed_device();
    let mut v = volume();
    stage(&mut v, &starting());
    let (t, a, _) = run(&mut v, d, 0);
    let m = start_all(&t, a.first_row);
    assert!(m.refused.is_empty(), "no spawn refused: {:?}", m.refused);
    assert!(m.spawned.contains(&("START.ELF".to_string(), "/pkg/APPS".to_string())), "{:?}", m.spawned);
    let statics = topo(d).tasks().iter().filter(|r| manager_starts(r)).count();
    assert_eq!(m.spawned.len(), statics + 1, "every static row started, and the package's");
}

/// A package refused at the repeated checks has no row, so no grant and no
/// start; a row that does not say `start` is not granted either.
#[test]
fn a_row_that_failed_admission_or_does_not_start_gets_no_grant() {
    let d = signed_device();
    // Refused: one bit of the signature.
    let mut v = volume();
    let mut forged = starting();
    forged[HEADER_LEN + 32 + 5] ^= 1;
    stage(&mut v, &forged);
    let before = manager_caps(&topo(d));
    let (t, a, log) = run(&mut v, d, 0);
    assert_eq!((a.rows, a.packages), (0, 0));
    assert_eq!(manager_caps(&t), before, "the manager's row is as the signed topology had it");
    assert!(grant_records(&log).is_empty());
    assert_eq!((log.records.len(), log.records[0].verdict), (1, Verdict::Refuse as u8), "refused, with its receipt");
    let m = start_all(&t, a.first_row);
    assert!(!m.spawned.iter().any(|s| s.0 == "START.ELF") && m.refused.is_empty());
    // Refused: asks for more than the signer's ceiling.
    let mut v = volume();
    let mut s = Spec::acme();
    s.images = vec![("START.ELF".into(), vec![7; 64])];
    s.rows = "[task.START.ELF]\nclass = \"best_effort\"\npriority = 20\nmem_pages = 32\nstart = true\n\
              caps = [\n    { kind = \"endpoint\", target = \"endpoint.power\", perm = \"rw\" },\n]\n"
        .into();
    stage(&mut v, &build(&s, &author()));
    let (t, _, log) = run(&mut v, d, 0);
    assert_eq!(launch_grants(&t, "START.ELF"), 0);
    assert!(grant_records(&log).is_empty() && log.records.iter().all(|p| p.verdict == Verdict::Refuse as u8));
    // Admitted, but it does not start at boot: nothing to grant.
    let mut v = volume();
    stage(&mut v, &acme());
    let (t, a, log) = run(&mut v, d, 0);
    assert_eq!(a.rows, 1);
    assert_eq!(manager_caps(&t), before);
    assert!(grant_records(&log).is_empty());
}

/// **Canary** `pkg-launch-grant-canary`: the boot after the apply merges the
/// same rows from the staged package (the trial's, no new write) and the grant
/// is made again: the candidate is rebuilt from the signed texts every boot.
#[test]
fn the_grant_is_made_at_every_boot_the_row_is_merged() {
    let d = signed_device();
    let mut v = volume();
    stage(&mut v, &starting());
    let (_, first, _) = run(&mut v, d, 0);
    assert_eq!(first.fresh.len(), 1);
    let (t, again, log) = run(&mut v, d, 0);
    assert!(again.fresh.is_empty() && again.packages == 1, "the staged package is merged, not written again");
    assert_eq!(launch_grants(&t, "START.ELF"), 1);
    assert_eq!(grant_records(&log).len(), 1);
}

/// The manager keeps `MANAGER_CAPS_MAX - 1` components; a row past its table
/// is not started by it, so it is not granted, and the record says so.
#[test]
fn a_row_past_the_managers_table_is_denied_with_a_record() {
    let d = signed_device();
    let mut v = volume();
    stage(&mut v, &starting());
    let mut t = topo(d);
    let have = t.tasks().iter().filter(|r| manager_starts(r)).count();
    for i in 0..(MANAGER_CAPS_MAX - 1).saturating_sub(have) {
        let name = Box::leak(format!("FILL{i}.ELF").into_boxed_str());
        t.push_task(MaybeStr::from_bytes(name.as_bytes()), MaybeStr::from_bytes(b"best_effort"), 20, &[]).unwrap();
        assert!(t.set_last_task_start(true));
    }
    let before = manager_caps(&t);
    let mut log = Log::default();
    let a = apply(&mut v, &mut t, &boot(0), &mut log);
    assert_eq!(a.rows, 1);
    assert_eq!(manager_caps(&t), before, "no grant");
    let g = grant_records(&log);
    assert_eq!(g.len(), 1);
    assert_eq!((g[0].verdict, g[0].n[2]), (Verdict::Deny as u8, pkg_apply::LAUNCH_GRANT | pkg_apply::GrantDenied::PastTable as u64));
}

/// Without a component manager row nobody would start the row: denied.
#[test]
fn a_topology_without_a_manager_denies_the_grant() {
    let d = signed_device();
    let mut v = volume();
    stage(&mut v, &starting());
    let mut t = Box::new(Topology::empty());
    let sched: &'static str = Box::leak(d.sched.replace("COMPMGR.ELF", "COMPMGX.ELF").into_boxed_str());
    let caps: &'static str = Box::leak(d.caps.replace("COMPMGR.ELF", "COMPMGX.ELF").into_boxed_str());
    azos_topology::parse_sched(sched.as_bytes(), &mut t).unwrap();
    azos_topology::parse_caps(caps.as_bytes(), &mut t).unwrap();
    let mut log = Log::default();
    let a = apply(&mut v, &mut t, &boot(0), &mut log);
    assert_eq!(a.rows, 1);
    let g = grant_records(&log);
    assert_eq!(g.len(), 1);
    assert_eq!((g[0].verdict, g[0].n[2]), (Verdict::Deny as u8, pkg_apply::LAUNCH_GRANT | pkg_apply::GrantDenied::NoManager as u64));
}

/// The kernel interns a bounded number of image names for launch grants: a
/// row whose name would be one too many is denied, not granted a capability
/// that cannot be minted.
#[test]
fn a_row_whose_name_the_launch_table_cannot_intern_is_denied() {
    let d = signed_device();
    let mut v = volume();
    stage(&mut v, &starting());
    let mut t = topo(d);
    let named = |t: &Topology<'static>| {
        let mut n: Vec<Vec<u8>> = Vec::new();
        for r in t.tasks() {
            for c in t.caps_of(r).iter().filter(|c| c.kind == CapKind::Node && !c.target.as_bytes().starts_with(b"/")) {
                if !n.contains(&c.target.as_bytes().to_vec()) {
                    n.push(c.target.as_bytes().to_vec());
                }
            }
        }
        n.len()
    };
    let mut i = 0;
    while named(&t) < pkg_apply::LAUNCH_NAMES_MAX {
        let name: &'static str = Box::leak(format!("NAME{i}.ELF").into_boxed_str());
        let grant = azos_topology::CapSpec { kind: CapKind::Node, perms: CapPerms::EXEC, target: MaybeStr::from_bytes(name.as_bytes()), transfer: false, ops: 0 };
        t.push_task(MaybeStr::from_bytes(format!("HOLD{i}.ELF").leak().as_bytes()), MaybeStr::from_bytes(b"best_effort"), 20, &[grant]).unwrap();
        i += 1;
    }
    let before = manager_caps(&t);
    let mut log = Log::default();
    apply(&mut v, &mut t, &boot(0), &mut log);
    assert_eq!(manager_caps(&t), before);
    let g = grant_records(&log);
    assert_eq!((g.len(), g[0].verdict, g[0].n[2]), (1, Verdict::Deny as u8, pkg_apply::LAUNCH_GRANT | pkg_apply::GrantDenied::NamesFull as u64));
}

/// `Topology::extend_task_caps`: a row that is not the last keeps its grants
/// in order and gains the new ones; the last row grows in place; a bad request
/// changes nothing.
#[test]
fn extending_the_grants_of_a_row_keeps_its_grants_and_the_others() {
    let g = |t: &'static [u8]| azos_topology::CapSpec { kind: CapKind::Node, perms: CapPerms::EXEC, target: MaybeStr::from_bytes(t), transfer: false, ops: 0 };
    let mut t = Box::new(Topology::empty());
    let push = |t: &mut Topology<'static>, n: &'static [u8], caps: &[azos_topology::CapSpec<'static>]| {
        t.push_task(MaybeStr::from_bytes(n), MaybeStr::from_bytes(b"best_effort"), 20, caps).unwrap();
    };
    push(&mut t, b"A.ELF", &[g(b"X.ELF"), g(b"Y.ELF")]);
    push(&mut t, b"B.ELF", &[g(b"Z.ELF")]);
    let a = MaybeStr::from_bytes(b"A.ELF");
    let b = MaybeStr::from_bytes(b"B.ELF");
    let targets = |t: &Topology<'static>, n: &MaybeStr<'static>| -> Vec<String> {
        t.caps_of(t.find_task(n).unwrap()).iter().map(|c| c.target.as_str().to_string()).collect()
    };
    assert!(t.extend_task_caps(&a, &[g(b"P.ELF"), g(b"Q.ELF")]), "not the last row: moved");
    assert_eq!(targets(&t, &a), ["X.ELF", "Y.ELF", "P.ELF", "Q.ELF"]);
    assert_eq!(targets(&t, &b), ["Z.ELF"], "the other row's grants are where they were");
    assert!(t.extend_task_caps(&a, &[g(b"R.ELF")]), "now the last grants of the pool: grown in place");
    assert_eq!(targets(&t, &a), ["X.ELF", "Y.ELF", "P.ELF", "Q.ELF", "R.ELF"]);
    assert_eq!(targets(&t, &b), ["Z.ELF"]);
    let null = azos_topology::CapSpec { kind: CapKind::Null, ..g(b"N.ELF") };
    assert!(!t.extend_task_caps(&a, &[null]) && !t.extend_task_caps(&MaybeStr::from_bytes(b"NONE.ELF"), &[g(b"P.ELF")]));
    assert_eq!(targets(&t, &a).len(), 5);
}
