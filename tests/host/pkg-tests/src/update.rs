// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The whole-system update through the installer (`Packages::update`): the
//! service over an in-memory volume, the `pkg update` command line, and a bundle
//! built by `tools/sign_ota.py` fed to the same code.
//!
//! The update's own rules (the manifest, the stager, the switch, the floors,
//! power loss) are tested where the code lives, in `tests/host/ota-tests`. What
//! is tested here is what the installer adds: the capability is released, the
//! decision is written down, a decision that cannot be written withdraws the
//! stage, and a device with no boot record has nowhere to stage.

use super::service::{MemVol, NoRemote, Rig, Shared};
use super::*;
use azos_crypto::sha256::sha256;
use azos_decision::{Rule, Verdict};
use azos_idl::{Cap, MsgDesc, Transport};
use azos_packages::cli::{self, Fail, Opener};
use azos_packages::{step, step_name, status, Packages, PackagesClient, PackagesIdl, PkgMem, Service, Work};
use azos_topology::Topology;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::process::Command;

// ── The bundle, built independently of the module under test ────────────────

fn data(seed: u32, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u32).wrapping_mul(2654435761).wrapping_add(seed) as u8).collect()
}

fn ksig(key: &SigningKey, fw: u32, kernel: &[u8]) -> Vec<u8> {
    let mut msg = b"azos-rsig-v2".to_vec();
    msg.extend_from_slice(&1u16.to_le_bytes());
    msg.extend_from_slice(&fw.to_le_bytes());
    msg.extend_from_slice(&(kernel.len() as u32).to_le_bytes());
    msg.extend_from_slice(&sha256(kernel));
    let mut v = b"RSIG".to_vec();
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&64u16.to_le_bytes());
    v.extend_from_slice(&key_id(1, key.verifying_key().as_bytes()));
    v.extend_from_slice(&(kernel.len() as u32).to_le_bytes());
    v.extend_from_slice(&fw.to_le_bytes());
    v.extend_from_slice(&key.sign(&msg).to_bytes());
    v
}

pub(crate) type Parts = Vec<(u8, String, Vec<u8>)>;

pub(crate) fn parts(epoch: u32, fw: u32, key: &SigningKey) -> Parts {
    let kernel = data(epoch, 6000);
    let sig = ksig(key, fw, &kernel);
    vec![
        (1, "KERN.BIN".into(), kernel),
        (2, "KERN.SIG".into(), sig),
        (3, "CAPS.TOM".into(), data(epoch + 1, 2000)),
        (3, "CAPS.SIG".into(), data(epoch + 2, 64)),
        (3, "SCHED.TOM".into(), data(epoch + 3, 500)),
        (4, "CONFIG.INI".into(), data(epoch + 4, 200)),
        (5, "BRAIN.ELF".into(), data(epoch + 5, 9000)),
    ]
}

fn bundle(epoch: u32, fw: u32, platform: u8, parts: &Parts, key: &SigningKey) -> Vec<u8> {
    let mut b = b"AZUM".to_vec();
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&epoch.to_le_bytes());
    b.extend_from_slice(&fw.to_le_bytes());
    b.push(platform);
    b.extend_from_slice(&[0, 0, 0]);
    b.extend_from_slice(&(parts.len() as u16).to_le_bytes());
    b.extend_from_slice(&64u16.to_le_bytes());
    for (kind, name, bytes) in parts {
        b.push(*kind);
        b.extend_from_slice(&[0, 0, 0]);
        b.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        let mut n = [0u8; 12];
        n[..name.len()].copy_from_slice(name.as_bytes());
        b.extend_from_slice(&n);
        b.extend_from_slice(&sha256(bytes));
    }
    let mut msg = b"AZOS-SYSUPDATE-V1\0".to_vec();
    msg.extend_from_slice(&b);
    b.extend_from_slice(&key.sign(&msg).to_bytes());
    for (_, _, bytes) in parts {
        b.extend_from_slice(bytes);
    }
    b
}

/// A device whose installer trusts `owner()`, running from slot A.
fn rig() -> Rig {
    Rig::new(MemVol::device(&Device0::with_signers(&signer_text("acme", &author(), CEILING)), &owner()))
}

pub(crate) fn good(epoch: u32) -> Vec<u8> {
    bundle(epoch, 3, 0, &parts(epoch, 3, &owner()), &owner())
}

fn has_marker(r: &Rig, slot: char) -> bool {
    r.vol.borrow().files.contains_key(format!("/fat/PKG/SYS_{slot}/UPDATE.MAN").as_bytes())
}

// ── The service ─────────────────────────────────────────────────────────────

#[test]
fn an_update_is_staged_into_the_inactive_slot_and_the_decision_is_journalled() {
    let mut r = rig();
    let b = good(5);
    let (cap, len) = r.put(7, &b);
    let reply = r.service().update(cap, len);
    assert_eq!(reply[0], 0, "{}", step_name(reply[0]));
    assert_eq!((reply[2], reply[3]), (5, 1), "epoch 5, into slot B (the device runs from A)");

    let v = r.vol.borrow();
    let ps = parts(5, 3, &owner());
    for (_, name, bytes) in &ps {
        assert_eq!(v.files.get(format!("/fat/PKG/SYS_B/{name}").as_bytes()), Some(bytes), "{name}");
    }
    assert!(v.files.contains_key(&b"/fat/PKG/SYS_B/UPDATE.MAN"[..]));
    assert!(!v.files.keys().any(|k| k.starts_with(b"/fat/PKG/SYS_A")), "the running slot's set is not touched");
    assert!(!v.files.contains_key(&b"/fat/KERN_B.BIN"[..]), "staging leaves the boot paths to the switch");
    assert!(v.caps.is_empty(), "the capability is the installer's, and is closed");

    let j = v.journal();
    assert_eq!(j.len(), 1);
    assert_eq!((j[0].rule, j[0].verdict), (Rule::PackageInstall as u8, Verdict::Admit as u8));
    assert_eq!(j[0].image_hash_prefix, reply[1], "the record names the manifest");
    assert_eq!((j[0].n[0], j[0].n[1], j[0].n[2]), (7, 0, 5 << 8 | 2), "7 parts, no signer, epoch 5, slot B + 1");
    // The manifest's id is the first eight bytes of its signature.
    let sig_at = 24 + 7 * 52;
    assert_eq!(reply[1], u64::from_be_bytes(b[sig_at..sig_at + 8].try_into().unwrap()));
}

#[test]
fn refusals_are_journalled_and_stage_nothing() {
    let mut r = rig();
    let stranger = SigningKey::from_bytes(&[0x99; 32]);
    let forged = bundle(5, 3, 0, &parts(5, 3, &stranger), &stranger);
    let mut tampered = good(6);
    let at = tampered.len() - 100;
    tampered[at] ^= 1; // inside the last part
    let mut short = good(7);
    short.pop();
    let cases: [(&str, Vec<u8>, &str); 3] = [
        ("forged", forged, "update signature"),
        ("tampered", tampered, "update part hash"),
        ("short", short, "update length"),
    ];
    for (i, (what, b, name)) in cases.iter().enumerate() {
        let (cap, len) = r.put(10 + i as u32, b);
        let reply = r.service().update(cap, len);
        assert_eq!(step_name(reply[0]), *name, "{what}");
        assert!(!has_marker(&r, 'B'), "{what} left a staged set");
    }
    let v = r.vol.borrow();
    assert!(v.caps.is_empty(), "every capability was released");
    let j = v.journal();
    assert_eq!(j.len(), 3, "every refusal is a decision");
    assert!(j.iter().all(|p| p.rule == Rule::PackageInstall as u8 && p.verdict == Verdict::Refuse as u8));
    // A refusal that came after the signature names the manifest; one before it cannot.
    assert_eq!(j[0].image_hash_prefix, 0);
    assert_ne!(j[1].image_hash_prefix, 0);
    // Update refusals are steps no package refusal uses, so a reader can tell them apart.
    assert!(j.iter().all(|p| p.n[2] >> 24 >= 48));
}

#[test]
fn an_update_on_trial_is_refused_before_anything_is_written() {
    // B was switched to and has not been confirmed: A is the way back.
    let mut r = rig();
    r.vol.borrow_mut().slots = Some((1, 0));
    let before = r.vol.borrow().files.clone();
    let (cap, len) = r.put(1, &good(5));
    let reply = r.service().update(cap, len);
    assert_eq!(step_name(reply[0]), "update trial pending");
    let mut after = r.vol.borrow().files.clone();
    let journal = after.remove(&b"/fat/PKG/JOURNAL.BIN"[..]);
    assert_eq!(after, before, "only the journal grew");
    assert!(journal.is_some());
}

#[test]
fn without_a_boot_record_there_is_nowhere_to_stage() {
    let mut r = rig();
    r.vol.borrow_mut().slots = None;
    let before = r.vol.borrow().files.clone();
    let (cap, len) = r.put(1, &good(5));
    let reply = r.service().update(cap, len);
    assert_eq!(reply[0], status(step::NO_BOOT_RECORD, 0));
    assert_eq!(step_name(reply[0]), "no boot record");
    assert_eq!(r.vol.borrow().files, before);
    assert!(r.vol.borrow().caps.is_empty());
}

#[test]
fn an_update_the_journal_cannot_record_is_withdrawn() {
    let mut r = rig();
    r.vol.borrow_mut().fail_append = true;
    let (cap, len) = r.put(1, &good(5));
    let reply = r.service().update(cap, len);
    assert_eq!(reply[0], status(step::IO, azos_packages::io::JOURNAL));
    assert!(!has_marker(&r, 'B'), "an unrecorded stage is not a stage");
}

#[test]
fn a_volume_that_refuses_the_writes_refuses_the_update() {
    let mut r = rig();
    r.vol.borrow_mut().fail_stream_write = true;
    let (cap, len) = r.put(1, &good(5));
    let reply = r.service().update(cap, len);
    assert_eq!(step_name(reply[0]), "update volume");
    assert!(!has_marker(&r, 'B'));
}

#[test]
fn an_object_shorter_than_its_length_is_refused_and_released() {
    let mut r = rig();
    let b = good(5);
    r.vol.borrow_mut().caps.insert(4, b[..100].to_vec());
    let reply = r.service().update(Cap::from_raw(4), b.len() as u32);
    assert_eq!(reply[0], status(step::IO, azos_packages::io::READ_PACKAGE));
    assert!(r.vol.borrow().caps.is_empty());
}

#[test]
fn a_second_update_replaces_the_first_whole() {
    let mut r = rig();
    for (h, epoch) in [(1, 5), (2, 6)] {
        let (cap, len) = r.put(h, &good(epoch));
        assert_eq!(r.service().update(cap, len)[0], 0);
    }
    let v = r.vol.borrow();
    let n = v.files.keys().filter(|k| k.starts_with(b"/fat/PKG/SYS_B/")).count();
    assert_eq!(n, 7 + 1, "the second set and its marker, nothing of the first");
    assert_eq!(v.journal().len(), 2);
}

/// The names the status words print are the steps `update::Refusal::code`
/// numbers: one name per step, in order.
#[test]
fn every_update_refusal_prints_the_name_of_its_step() {
    use azos_packages::update::{Io, Refusal, Shape, STEPS, STEP_FIRST};
    assert_eq!(azos_packages::UPDATE_STEP_FIRST as u64, STEP_FIRST);
    assert_eq!(azos_packages::UPDATE_STEPS.len() as u64, STEPS);
    let cases = [
        (Refusal::Truncated, "update truncated"),
        (Refusal::Format, "update format"),
        (Refusal::Signature, "update signature"),
        (Refusal::Reserved, "update reserved field"),
        (Refusal::Part(1), "update part"),
        (Refusal::Shape(Shape::Kernel), "update shape"),
        (Refusal::Platform, "update platform"),
        (Refusal::TrialPending, "update trial pending"),
        (Refusal::EpochFloor, "update epoch floor"),
        (Refusal::FwFloor, "update firmware floor"),
        (Refusal::NotInactive, "update slot"),
        (Refusal::Length, "update length"),
        (Refusal::TooLarge, "update kernel too large"),
        (Refusal::Io(Io::Dir), "update volume"),
        (Refusal::PartHash(0), "update part hash"),
        (Refusal::NotStaged, "update not staged"),
        (Refusal::Extra, "update extra file"),
        (Refusal::KernelSig, "update kernel signature"),
        (Refusal::Envelope, "update held by envelope"),
    ];
    assert_eq!(cases.len() as u64, STEPS);
    for (r, name) in cases {
        assert_eq!(step_name(r.code()), name, "{r:?}");
    }
}

// ── A delta update ──────────────────────────────────────────────────────────

/// The generator's patch from `old` to `new` (`tools/ota_delta.py`, the real
/// one, so the installer and the tool are checked against each other).
fn make_delta(old: &[u8], new: &[u8]) -> Vec<u8> {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "azos-pkg-delta-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (o, n, d) = (dir.join("old"), dir.join("new"), dir.join("delta"));
    std::fs::write(&o, old).unwrap();
    std::fs::write(&n, new).unwrap();
    let tool = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tools/ota_delta.py");
    let out = Command::new("python3").arg(tool).arg("make").arg(&o).arg(&n).arg("-o").arg(&d).output().expect("python3");
    assert!(out.status.success(), "ota_delta.py make: {}", String::from_utf8_lossy(&out.stderr));
    let delta = std::fs::read(&d).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    delta
}

/// The next generation of `parts(epoch)`: the kernel changed in a few bytes and
/// re-signed, one image touched, the rest the same.
fn next_parts(epoch: u32) -> Parts {
    let mut ps = parts(epoch, 3, &owner());
    for b in &mut ps[0].2[2000..2010] {
        *b ^= 0x5A;
    }
    ps[1].2 = ksig(&owner(), 3, &ps[0].2);
    for b in &mut ps[6].2[4000..4100] {
        *b = b.wrapping_add(1);
    }
    ps
}

/// A device running epoch 5 from slot B: it was staged there whole and the
/// boot record points at it.
fn running_b() -> (Rig, Vec<u8>) {
    let mut r = rig();
    let old = good(5);
    let (cap, len) = r.put(1, &old);
    assert_eq!(r.service().update(cap, len)[0], 0);
    r.vol.borrow_mut().slots = Some((1, 1));
    (r, old)
}

#[test]
fn a_delta_is_applied_inside_the_atomic_update() {
    let (mut r, old) = running_b();
    let next = bundle(6, 3, 0, &next_parts(5), &owner());
    let delta = make_delta(&old, &next);
    assert!(delta.len() * 2 < next.len(), "the patch is what changed: {} of {}", delta.len(), next.len());

    let (cap, len) = r.put(2, &delta);
    let reply = r.service().update(cap, len);
    assert_eq!(reply[0], 0, "{}", step_name(reply[0]));
    assert_eq!((reply[2], reply[3]), (6, 0), "epoch 6, into slot A (the device runs from B)");

    let v = r.vol.borrow();
    for (_, name, bytes) in &next_parts(5) {
        assert_eq!(v.files.get(format!("/fat/PKG/SYS_A/{name}").as_bytes()), Some(bytes), "{name}");
    }
    assert!(v.files.contains_key(&b"/fat/PKG/SYS_A/UPDATE.MAN"[..]));
    for (_, name, bytes) in &parts(5, 3, &owner()) {
        assert_eq!(v.files.get(format!("/fat/PKG/SYS_B/{name}").as_bytes()), Some(bytes), "the running set's {name} is untouched");
    }
    assert!(v.caps.is_empty(), "the patch's capability is released");
    let j = v.journal();
    assert_eq!(j.len(), 2, "the whole stage and the delta stage");
    assert_eq!((j[1].verdict, j[1].n[2]), (Verdict::Admit as u8, 6 << 8 | 1), "epoch 6, slot A + 1");
}

#[test]
fn a_delta_goes_through_pkg_update_like_a_bundle() {
    let (r, old) = running_b();
    let next = bundle(6, 3, 0, &next_parts(5), &owner());
    let mut work = Box::new(Work::new());
    let mut topo = Box::new(Topology::empty());
    let svc = RefCell::new(Service::new(Shared(&r.vol), NoRemote, &mut work, &mut topo, *owner().verifying_key().as_bytes(), device()));
    let mut c = PackagesClient::new(Loop(&svc));
    let mut files = Files { vol: &r.vol, named: vec![(b"/fat/NEXT.AZD", make_delta(&old, &next))], next: 0 };
    let mut out = String::new();
    assert_eq!(cli::run(&cli::Cmd::Update(b"/fat/NEXT.AZD"), &mut c, &mut files, &mut out), Ok(0), "{out}");
    assert!(out.contains("epoch 6, into slot A"), "{out}");
}

#[test]
fn a_delta_against_another_base_is_refused_before_the_inactive_slot_is_written() {
    let (mut r, _) = running_b();
    let other = good(7);
    let next = bundle(8, 3, 0, &next_parts(7), &owner());
    let before = r.vol.borrow().files.clone();
    let (cap, len) = r.put(2, &make_delta(&other, &next));
    let reply = r.service().update(cap, len);
    assert_eq!(step_name(reply[0]), "delta base hash");
    assert_eq!(reply[1], 0, "no manifest had been verified: the record names none");
    let mut after = r.vol.borrow().files.clone();
    let journal = after.remove(&b"/fat/PKG/JOURNAL.BIN"[..]);
    assert_eq!(after, {
        let mut b = before;
        b.remove(&b"/fat/PKG/JOURNAL.BIN"[..]);
        b
    }, "only the journal grew");
    assert!(journal.is_some());
    assert!(r.vol.borrow().caps.is_empty());
}

#[test]
fn a_damaged_delta_is_refused_and_stages_nothing() {
    let (mut r, old) = running_b();
    let next = bundle(6, 3, 0, &next_parts(5), &owner());
    let mut delta = make_delta(&old, &next);
    let at = delta.len() - 5; // inside the last INSERT or COPY
    delta[at] ^= 1;
    let (cap, len) = r.put(2, &delta);
    let reply = r.service().update(cap, len);
    assert!(
        ["delta result hash", "delta op"].contains(&step_name(reply[0])),
        "{}",
        step_name(reply[0])
    );
    assert!(!has_marker(&r, 'A'));
    let j = r.vol.borrow().journal();
    assert_eq!((j.len(), j[1].verdict), (2, Verdict::Refuse as u8));
}

#[test]
fn a_delta_cannot_make_an_update_the_signature_does_not_cover() {
    let (mut r, old) = running_b();
    let stranger = SigningKey::from_bytes(&[0x99; 32]);
    let forged = bundle(6, 3, 0, &parts(6, 3, &stranger), &stranger);
    let (cap, len) = r.put(2, &make_delta(&old, &forged));
    let reply = r.service().update(cap, len);
    assert_eq!(step_name(reply[0]), "update signature");
    assert!(!has_marker(&r, 'A'), "the stager refused the bundle the patch makes");
}

#[test]
fn a_running_slot_with_no_staged_set_cannot_be_a_base() {
    // The device runs from A, which a kernel-only install left without a set.
    let mut r = rig();
    let next = bundle(6, 3, 0, &next_parts(5), &owner());
    let (cap, len) = r.put(2, &make_delta(&good(5), &next));
    let reply = r.service().update(cap, len);
    assert_eq!(step_name(reply[0]), "update not staged");
    assert!(!has_marker(&r, 'B'));
}

#[test]
fn every_delta_refusal_prints_its_reason() {
    use azos_packages::pure::DeltaError::*;
    let all = [Truncated, Format, TooLarge, BaseLength, BaseHash, Op, ResultHash, Io];
    assert_eq!(all.len(), azos_packages::DELTA_REASONS.len());
    for (i, e) in all.iter().enumerate() {
        assert_eq!(e.code(), i as u64 + 1);
        assert_eq!(step_name(status(step::DELTA, e.code())), azos_packages::DELTA_REASONS[i]);
    }
    assert_eq!(step_name(status(step::DELTA, 0)), "delta");
}

// ── The command line ────────────────────────────────────────────────────────

struct Loop<'a, 'w>(&'a RefCell<Service<'w, Shared<'a>, NoRemote>>);

impl Transport for Loop<'_, '_> {
    fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
        let req = *msg;
        let mut rep = MsgDesc::default();
        PackagesIdl::dispatch(&mut *self.0.borrow_mut(), &req, &mut rep)?;
        *msg = rep;
        Ok(())
    }
}

struct Files<'a> {
    vol: &'a RefCell<MemVol>,
    named: Vec<(&'static [u8], Vec<u8>)>,
    next: u32,
}

impl Opener for Files<'_> {
    fn open(&mut self, path: &[u8]) -> Option<(Cap<PkgMem>, u32)> {
        let (_, bytes) = self.named.iter().find(|(p, _)| *p == path)?;
        self.next += 1;
        self.vol.borrow_mut().caps.insert(self.next, bytes.clone());
        Some((Cap::from_raw(self.next), bytes.len() as u32))
    }
}

#[test]
fn pkg_update_stages_and_says_where() {
    let d = Device0::with_signers(&signer_text("acme", &author(), CEILING));
    let vol = RefCell::new(MemVol::device(&d, &owner()));
    let mut work = Box::new(Work::new());
    let mut topo = Box::new(Topology::empty());
    let svc = RefCell::new(Service::new(Shared(&vol), NoRemote, &mut work, &mut topo, *owner().verifying_key().as_bytes(), device()));
    let mut c = PackagesClient::new(Loop(&svc));
    let mut files = Files { vol: &vol, named: vec![(b"/fat/SYS.AZU", good(9)), (b"/fat/BAD.AZU", good(1)[..40].to_vec())], next: 0 };

    assert_eq!(cli::parse(&[b"update".as_slice(), b"/fat/SYS.AZU"]), Ok(cli::Cmd::Update(b"/fat/SYS.AZU")));
    assert!(cli::parse(&[b"update".as_slice()]).is_err());

    let mut out = String::new();
    let r = cli::run(&cli::Cmd::Update(b"/fat/SYS.AZU"), &mut c, &mut files, &mut out);
    assert_eq!(r, Ok(0), "{out}");
    assert!(out.starts_with("staged: update ") && out.contains("epoch 9, into slot B"), "{out}");

    let mut out = String::new();
    let r = cli::run(&cli::Cmd::Update(b"/fat/BAD.AZU"), &mut c, &mut files, &mut out);
    assert_eq!(r, Ok(1), "{out}");
    assert!(out.starts_with("refused: update "), "{out}");

    let mut out = String::new();
    assert_eq!(cli::run(&cli::Cmd::Update(b"/fat/NOPE.AZU"), &mut c, &mut files, &mut out), Err(Fail::Open));
}

// ── tools/sign_ota.py ───────────────────────────────────────────────────────

fn tool() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tools/sign_ota.py")
}

fn python() -> Option<String> {
    let mut candidates: Vec<String> = std::env::var("PYTHON").ok().into_iter().collect();
    candidates.extend(["/opt/homebrew/bin/python3".to_string(), "python3".to_string()]);
    candidates.into_iter().find(|p| {
        Command::new(p).args(["-c", "import cryptography"]).output().is_ok_and(|o| o.status.success())
    })
}

/// The bundle the tool makes from the same inputs as `parts()`: `None` where no
/// interpreter can run it.
fn made_by_the_tool(epoch: u32, fw: u32, ps: &Parts) -> Option<Vec<u8>> {
    let py = python()?;
    let dir = std::env::temp_dir().join(format!("azos-update-tests-{epoch}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("key.bin"), [0x5a; 32]).unwrap();
    let mut args: Vec<String> = ["bundle", "out.azu", "--epoch", &epoch.to_string(), "--fw-version", &fw.to_string(), "--priv", "key.bin"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for (_, name, bytes) in ps {
        let file = name.to_lowercase();
        std::fs::write(dir.join(&file), bytes).unwrap();
        let flag = match name.as_str() {
            "KERN.BIN" => "--kernel",
            "KERN.SIG" => "--kernel-sig",
            "CAPS.TOM" => "--caps",
            "CAPS.SIG" => "--caps-sig",
            "SCHED.TOM" => "--sched",
            "CONFIG.INI" => "--config",
            _ => "--image",
        };
        args.push(flag.into());
        args.push(file);
    }
    let out = Command::new(py).arg(tool()).args(&args).current_dir(&dir).output().ok()?;
    assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    Some(std::fs::read(dir.join("out.azu")).unwrap())
}

/// The producer and the verifier are two implementations of one format: the
/// same inputs give the same bytes (Ed25519 is deterministic), and the
/// installer accepts what the tool made.
#[test]
fn the_bundle_the_tool_makes_is_the_bundle_the_installer_reads() {
    let ps = parts(11, 4, &owner());
    let Some(made) = made_by_the_tool(11, 4, &ps) else {
        eprintln!("skipped: no python3 with `cryptography`");
        return;
    };
    assert_eq!(made, bundle(11, 4, 0, &ps, &owner()), "tools/sign_ota.py and the suite disagree on the wire form");
    let mut r = rig();
    let (cap, len) = r.put(1, &made);
    let reply = r.service().update(cap, len);
    assert_eq!(reply[0], 0, "{}", step_name(reply[0]));
    assert_eq!(reply[2], 11);
}

/// The `.SIG` the tool makes for a kernel is the one the boot gate and the
/// staged-set check read (an Ed25519 `RSIG`): the same bytes as the suite's.
#[test]
fn the_kernel_signature_the_tool_makes_is_the_one_the_device_reads() {
    let Some(py) = python() else {
        eprintln!("skipped: no python3 with `cryptography`");
        return;
    };
    let dir = std::env::temp_dir().join("azos-update-tests-ksig");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("key.bin"), [0x5a; 32]).unwrap();
    let kernel = data(3, 6000);
    std::fs::write(dir.join("kernel.bin"), &kernel).unwrap();
    let out = Command::new(py)
        .arg(tool())
        .args(["kernel.bin", "--fw-version", "9", "--priv", "key.bin", "--out", "kernel.sig"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read(dir.join("kernel.sig")).unwrap(), ksig(&owner(), 9, &kernel));
}

#[test]
fn the_tool_refuses_a_name_the_device_would_refuse() {
    let Some(py) = python() else {
        eprintln!("skipped: no python3 with `cryptography`");
        return;
    };
    let dir = std::env::temp_dir().join("azos-update-tests-names");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("key.bin"), [0x5a; 32]).unwrap();
    for f in ["k", "c", "cs", "s", "i", "tiny"] {
        std::fs::write(dir.join(f), b"x").unwrap();
    }
    std::fs::write(dir.join("too_long_name.elf"), b"x").unwrap();
    let out = Command::new(py)
        .arg(tool())
        .args(["bundle", "o.azu", "--epoch", "1", "--fw-version", "1", "--priv", "key.bin", "--kernel", "k", "--caps", "c", "--caps-sig", "cs", "--sched", "s", "--config", "i", "--image", "too_long_name.elf"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("8.3"), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!dir.join("o.azu").exists());
}
