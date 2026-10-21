// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The whole-system update: stage, switch, confirm, roll back, and the
//! refusals around them.
//!
//! The volume is a map of files with a power-loss switch (`crash_at`): the
//! n-th mutating operation does not happen and every later one fails until
//! `reboot`, which is what a power cut looks like to the code that was
//! running. The manifests are built here, byte by byte, independently of the
//! module under test, and signed with a key of the suite's own.
//!
//! Canaries (cargo features of this crate, each skips one check of the
//! module): `update-canary-sig` turns the forged-signature tests red,
//! `update-canary-epoch` the floor tests, `update-canary-hash` the tampered-part
//! tests, `update-canary-stale-epoch` the kernel-install test (the epoch of a
//! replaced set stays in the record) and `update-canary-root-files` the tests
//! of what the boot runs (the boot ignores the set), and `update-canary-apply-gate`
//! the tests of the Domain's `ota` envelope row (the store is not asked), and
//! nothing else.

use crate::pure::*;
use crate::update::*;
use azos_crypto::sha256::sha256;
use azos_crypto::sig::{key_id, manifest_message, SigAlg, SIG_LEN};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::{BTreeMap, BTreeSet};

// ── Fixtures ────────────────────────────────────────────────────────────────

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

fn pubkey() -> [u8; 32] {
    signer().verifying_key().to_bytes()
}

fn data(seed: u32, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u32).wrapping_mul(2654435761).wrapping_add(seed) as u8).collect()
}

#[derive(Clone)]
struct PartSpec {
    kind: u8,
    name: String,
    bytes: Vec<u8>,
}

#[derive(Clone)]
struct Spec {
    epoch: u32,
    fw: u32,
    platform: u8,
    /// The algorithm id the head names, and the signature length it declares.
    alg: u16,
    sig_len: u16,
    parts: Vec<PartSpec>,
}

fn part(kind: u8, name: &str, bytes: Vec<u8>) -> PartSpec {
    PartSpec { kind, name: name.to_string(), bytes }
}

fn kernel_sig(fw: u32, kernel: &[u8]) -> Vec<u8> {
    let msg = manifest_message(SigAlg::Ed25519, fw, kernel.len() as u32, &sha256(kernel));
    let sig = signer().sign(&msg);
    let mut v = b"RSIG".to_vec();
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&64u16.to_le_bytes());
    v.extend_from_slice(&key_id(1, &pubkey()));
    v.extend_from_slice(&(kernel.len() as u32).to_le_bytes());
    v.extend_from_slice(&fw.to_le_bytes());
    v.extend_from_slice(&sig.to_bytes());
    v
}

/// A complete, valid set. Its bytes depend on the epoch, so two epochs differ in
/// every part.
fn spec(epoch: u32, fw: u32) -> Spec {
    let k = data(epoch, 9000);
    Spec {
        epoch,
        fw,
        platform: OTA_PLATFORM_QEMU,
        alg: 1,
        sig_len: 64,
        parts: vec![
            part(1, "KERN.BIN", k.clone()),
            part(2, "KERN.SIG", kernel_sig(fw, &k)),
            part(3, "CAPS.TOM", data(epoch + 1, 3000)),
            part(3, "CAPS.SIG", data(epoch + 2, 64)),
            part(3, "SCHED.TOM", data(epoch + 3, 700)),
            part(4, "CONFIG.INI", data(epoch + 4, 300)),
            part(4, "CONFIG.SIG", data(epoch + 5, 64)),
            part(5, "BRAIN.ELF", data(epoch + 6, 20000)),
            part(5, "GPIO.ELF", data(epoch + 7, 5000)),
        ],
    }
}

fn body(s: &Spec) -> Vec<u8> {
    let mut b = b"AZUM".to_vec();
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&s.alg.to_le_bytes());
    b.extend_from_slice(&s.epoch.to_le_bytes());
    b.extend_from_slice(&s.fw.to_le_bytes());
    b.push(s.platform);
    b.extend_from_slice(&[0, 0, 0]);
    b.extend_from_slice(&(s.parts.len() as u16).to_le_bytes());
    b.extend_from_slice(&s.sig_len.to_le_bytes());
    for p in &s.parts {
        b.push(p.kind);
        b.extend_from_slice(&[0, 0, 0]);
        b.extend_from_slice(&(p.bytes.len() as u32).to_le_bytes());
        let mut name = [0u8; 12];
        name[..p.name.len()].copy_from_slice(p.name.as_bytes());
        b.extend_from_slice(&name);
        b.extend_from_slice(&sha256(&p.bytes));
    }
    b
}

fn manifest_with(s: &Spec, key: &SigningKey) -> Vec<u8> {
    let mut b = body(s);
    let mut msg = b"AZOS-SYSUPDATE-V1\0".to_vec();
    msg.extend_from_slice(&b);
    b.extend_from_slice(&key.sign(&msg).to_bytes());
    b
}

fn bundle_with(s: &Spec, key: &SigningKey) -> Vec<u8> {
    let mut b = manifest_with(s, key);
    for p in &s.parts {
        b.extend_from_slice(&p.bytes);
    }
    b
}

fn bundle(s: &Spec) -> Vec<u8> {
    bundle_with(s, &signer())
}

struct Bytes(Vec<u8>);

impl Source for Bytes {
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

/// A volume that can lose power.
#[derive(Clone, Default)]
struct Mem {
    files: BTreeMap<Vec<u8>, Vec<u8>>,
    dirs: BTreeSet<Vec<u8>>,
    open: BTreeMap<u32, (Vec<u8>, Vec<u8>, bool)>,
    next: u32,
    ops: usize,
    crash_at: Option<usize>,
    dead: bool,
    /// Flip a byte of this file when it is committed: a medium that lies.
    corrupt: Option<Vec<u8>>,
    /// The steps the requester's Domain is held from (`Store::may_apply`).
    held: Vec<Apply>,
    /// Every question `may_apply` was asked, in order.
    asked: Vec<(Apply, u8)>,
}

impl Mem {
    fn mutate(&mut self) -> Result<(), IoErr> {
        if self.dead {
            return Err(IoErr::Io);
        }
        self.ops += 1;
        if self.crash_at == Some(self.ops) {
            self.dead = true;
            return Err(IoErr::Io);
        }
        Ok(())
    }

    fn reboot(&mut self) {
        self.dead = false;
        self.crash_at = None;
        self.open.clear();
        self.ops = 0;
    }

    fn file(&self, path: &str) -> Option<&Vec<u8>> {
        self.files.get(path.as_bytes())
    }

    fn untouched_below(&self, dir: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.files.iter().filter(|(p, _)| p.starts_with(dir.as_bytes())).map(|(p, v)| (p.clone(), v.clone())).collect()
    }
}

impl Store for Mem {
    fn may_apply(&mut self, step: Apply, slot: u8) -> bool {
        self.asked.push((step, slot));
        !self.held.contains(&step)
    }

    fn open_read(&mut self, path: &[u8]) -> Result<u32, IoErr> {
        if self.dead {
            return Err(IoErr::Io);
        }
        if !self.files.contains_key(path) {
            return Err(IoErr::Missing);
        }
        self.next += 1;
        self.open.insert(self.next, (path.to_vec(), Vec::new(), false));
        // The read position lives in `buf.len()`: bytes consumed so far.
        Ok(self.next)
    }

    fn read(&mut self, h: u32, buf: &mut [u8]) -> Result<usize, IoErr> {
        if self.dead {
            return Err(IoErr::Io);
        }
        let (path, pos, _) = self.open.get_mut(&h).ok_or(IoErr::Io)?;
        let f = self.files.get(path.as_slice()).ok_or(IoErr::Missing)?;
        let at = pos.len();
        let n = buf.len().min(f.len().saturating_sub(at));
        buf[..n].copy_from_slice(&f[at..at + n]);
        pos.extend(std::iter::repeat(0).take(n));
        Ok(n)
    }

    fn open_write(&mut self, path: &[u8]) -> Result<u32, IoErr> {
        self.mutate()?;
        self.files.insert(path.to_vec(), Vec::new());
        self.next += 1;
        self.open.insert(self.next, (path.to_vec(), Vec::new(), true));
        Ok(self.next)
    }

    fn write(&mut self, h: u32, data: &[u8]) -> Result<(), IoErr> {
        self.mutate()?;
        self.open.get_mut(&h).ok_or(IoErr::Io)?.1.extend_from_slice(data);
        Ok(())
    }

    fn close(&mut self, h: u32) -> Result<(), IoErr> {
        let writing = self.open.get(&h).map_or(false, |o| o.2);
        if writing {
            self.mutate()?;
        }
        let Some((path, buf, w)) = self.open.remove(&h) else { return Ok(()) };
        if w {
            let mut buf = buf;
            if self.corrupt.as_deref() == Some(path.as_slice()) && !buf.is_empty() {
                buf[0] ^= 0xFF;
            }
            self.files.insert(path, buf);
        }
        Ok(())
    }

    fn remove(&mut self, path: &[u8]) -> Result<(), IoErr> {
        self.mutate()?;
        self.files.remove(path).map(|_| ()).ok_or(IoErr::Missing)
    }

    fn ensure_dir(&mut self, path: &[u8]) -> Result<(), IoErr> {
        self.mutate()?;
        self.dirs.insert(path.to_vec());
        Ok(())
    }

    fn entry(&mut self, dir: &[u8], index: usize, name: &mut [u8; NAME_BUF]) -> Option<usize> {
        let mut prefix = dir.to_vec();
        prefix.push(b'/');
        let n = self.files.keys().filter_map(|p| p.strip_prefix(prefix.as_slice())).nth(index)?;
        name[..n.len()].copy_from_slice(n);
        Some(n.len())
    }
}

/// Verify and parse `bytes` as a manifest under the suite's key.
fn parse_m(bytes: &[u8]) -> Result<(), Refusal> {
    let mut msg = [0u8; MSG_MAX];
    Manifest::parse(bytes, &pubkey(), &mut msg).map(|_| ())
}

fn dev(meta: BootMeta) -> Device {
    Device { platform: Some(OTA_PLATFORM_QEMU), meta, max_kernel_size: 1 << 20 }
}

const BOOT: BootPaths<'static> = BootPaths { kernel: b"/fat/KERN_B.BIN", kernel_sig: b"/fat/KERN_B.SIG" };
const BOOT_A: BootPaths<'static> = BootPaths { kernel: b"/fat/KERN_A.BIN", kernel_sig: b"/fat/KERN_A.SIG" };

fn do_stage(st: &mut Mem, s: &Spec, meta: BootMeta) -> Result<Verified, Refusal> {
    let mut buf = [0u8; 1024];
    stage(st, &mut Bytes(bundle(s)), &dev(meta), &pubkey(), &mut Work::new(), &mut buf)
}

fn do_switch(st: &mut Mem, meta: BootMeta) -> Result<Verified, SwitchError> {
    let mut buf = [0u8; 1024];
    let boot = if meta.active_slot == SLOT_A { &BOOT } else { &BOOT_A };
    switch(st, &dev(meta), &pubkey(), boot, &mut Work::new(), &mut buf)
}

/// Stage, switch and confirm `s` on a device that is on `meta`'s active slot:
/// the install of one generation, as the boot machinery sees it.
fn install(st: &mut Mem, meta: &mut BootMeta, s: &Spec) {
    do_stage(st, s, *meta).expect("stage");
    let v = do_switch(st, *meta).expect("switch");
    ota_switch_pure(meta, v.slot, &v.set()).expect("record");
    assert_eq!(ota_boot_validate_pure(meta, 3), BootValidateOutcome::Normal);
    ota_mark_boot_good_pure(meta);
}

fn assert_untouched(st: &Mem) {
    assert!(st.files.is_empty() && st.dirs.is_empty(), "the volume was written: {:?}", st.files.keys().collect::<Vec<_>>());
}

// ── The record ──────────────────────────────────────────────────────────────

#[test]
fn bootmeta_carries_the_epochs_and_fits_a_record() {
    let mut m = BootMeta::default();
    m.sec_epoch_a = 4_000_000_000;
    m.sec_epoch_b = 7;
    m.min_sec_epoch = 3;
    let rec = BootMetaRecord { meta: m, seq: 9 };
    let mut buf = [0u8; 512];
    let n = serialize_boot_meta_record(&rec, &mut buf);
    assert!(n < 512 - 64, "the record must keep headroom in its 512 bytes, took {n}");
    let back = parse_boot_meta_record(&buf[..n]).expect("crc");
    assert_eq!(back.meta, m);
    // A record from before the epochs read as zeros: no floor, no epoch.
    let old = parse_boot_meta(b"active_slot=b\nlast_good=a\nmin_fw_version=4\n");
    assert_eq!((old.sec_epoch_a, old.sec_epoch_b, old.min_sec_epoch), (0, 0, 0));
}

// REQ-014
#[test]
fn the_floor_moves_only_when_a_boot_is_confirmed() {
    let mut m = BootMeta::default();
    m.sec_epoch_b = 9;
    m.min_sec_epoch = 4;
    m.active_slot = SLOT_B;
    assert_eq!(ota_boot_validate_pure(&mut m, 3), BootValidateOutcome::Normal);
    assert_eq!(m.min_sec_epoch, 4, "a boot that is not confirmed does not move the floor");
    ota_mark_boot_good_pure(&mut m);
    assert_eq!(m.min_sec_epoch, 9);
    // A set with a lower (or no) epoch never lowers it.
    m.active_slot = SLOT_A;
    m.sec_epoch_a = 0;
    ota_mark_boot_good_pure(&mut m);
    assert_eq!(m.min_sec_epoch, 9);
}

#[test]
fn the_switch_refuses_what_would_cost_the_way_back() {
    let set = StagedSet { fw_version: 5, sec_epoch: 5, kernel_size: 100, kernel_crc: 0xABCD };
    let mut m = BootMeta::default();
    assert_eq!(ota_switch_pure(&mut m, SLOT_A, &set), Err(SwitchRefusal::NotInactive));
    assert_eq!(ota_switch_pure(&mut m, SLOT_R, &set), Err(SwitchRefusal::NotInactive));
    assert_eq!(m, BootMeta::default(), "a refusal leaves the record as it was");

    let mut trial = BootMeta::default();
    trial.active_slot = SLOT_B;
    assert_eq!(ota_switch_pure(&mut trial, SLOT_A, &set), Err(SwitchRefusal::TrialPending));

    assert_eq!(ota_switch_pure(&mut m, SLOT_B, &set), Ok(()));
    assert_eq!((m.active_slot, m.boot_count, m.last_good), (SLOT_B, 0, SLOT_A));
    assert_eq!((m.image_size_b, m.image_crc_b, m.sec_epoch_b, m.authenticated_fw_version_b), (100, 0xABCD, 5, 5));
    assert_eq!((m.min_fw_version, m.min_sec_epoch), (0, 0), "the floors wait for the confirmation");
}

// ── Stage, switch, confirm ──────────────────────────────────────────────────

#[test]
fn a_set_is_staged_switched_and_confirmed() {
    let mut st = Mem::default();
    let mut meta = BootMeta::default();
    let s = spec(5, 7);

    let v = do_stage(&mut st, &s, meta).expect("stage");
    assert_eq!((v.slot, v.sec_epoch, v.fw_version), (SLOT_B, 5, 7));
    // Everything is in the inactive slot's directory, nothing in the active one.
    for p in &s.parts {
        assert_eq!(st.file(&format!("/fat/PKG/SYS_B/{}", p.name)), Some(&p.bytes), "{}", p.name);
    }
    assert!(st.file("/fat/PKG/SYS_B/UPDATE.MAN").is_some());
    assert!(st.untouched_below("/fat/PKG/SYS_A").is_empty());
    assert!(st.file("/fat/KERN_B.BIN").is_none(), "staging does not touch the boot paths");

    let v = do_switch(&mut st, meta).expect("switch");
    assert_eq!(st.file("/fat/KERN_B.BIN"), Some(&s.parts[0].bytes));
    assert_eq!(st.file("/fat/KERN_B.SIG"), Some(&s.parts[1].bytes));
    assert_eq!(v.kernel_crc, crc32(&s.parts[0].bytes), "BOOTMETA records the CRC `ota_verify_slot` will check");

    ota_switch_pure(&mut meta, v.slot, &v.set()).expect("record");
    assert_eq!((meta.active_slot, meta.last_good), (SLOT_B, SLOT_A));
    assert_eq!(ota_boot_validate_pure(&mut meta, 3), BootValidateOutcome::Normal);
    ota_mark_boot_good_pure(&mut meta);
    assert_eq!((meta.active_slot, meta.last_good, meta.boot_count), (SLOT_B, SLOT_B, 0));
    assert_eq!((meta.min_sec_epoch, meta.min_fw_version), (5, 7), "the confirmation moves both floors");
}

#[test]
fn an_unconfirmed_set_rolls_back_whole() {
    let mut st = Mem::default();
    let mut meta = BootMeta::default();
    install(&mut st, &mut meta, &spec(1, 1)); // A -> B, confirmed
    assert_eq!((meta.active_slot, meta.min_sec_epoch), (SLOT_B, 1));
    let confirmed = st.untouched_below("/fat/PKG/SYS_B");

    // The next generation goes to A and is switched to, but never confirmed.
    let next = spec(2, 2);
    do_stage(&mut st, &next, meta).expect("stage");
    let v = do_switch(&mut st, meta).expect("switch");
    ota_switch_pure(&mut meta, v.slot, &v.set()).expect("record");
    assert_eq!((meta.active_slot, meta.last_good), (SLOT_A, SLOT_B));
    for boot in 1..=3 {
        assert_eq!(ota_boot_validate_pure(&mut meta, 3), BootValidateOutcome::Normal, "boot {boot}");
    }
    assert_eq!(ota_boot_validate_pure(&mut meta, 3), BootValidateOutcome::RolledBack);

    // Back on B: kernel, images, topology and config are B's, all of them,
    // because they are one directory and one boot path.
    assert_eq!(meta.active_slot, SLOT_B);
    assert_eq!(set_dir(meta.active_slot), Some(&b"/fat/PKG/SYS_B"[..]));
    assert_eq!(st.untouched_below("/fat/PKG/SYS_B"), confirmed, "the rollback target was never touched");
    let mut buf = [0u8; 1024];
    let still = verify_set(&mut st, SLOT_B, &pubkey(), &mut Work::new(), &mut buf).expect("B's set still verifies");
    assert_eq!(still.sec_epoch, 1);
    assert_eq!(meta.min_sec_epoch, 1, "the unconfirmed epoch 2 pinned nothing");
    // And the failed generation can be replaced by the next one.
    do_stage(&mut st, &spec(3, 3), meta).expect("a later update is not locked out");
}

#[test]
fn the_same_epoch_is_a_valid_reinstall() {
    let mut st = Mem::default();
    let mut meta = BootMeta::default();
    install(&mut st, &mut meta, &spec(5, 5));
    do_stage(&mut st, &spec(5, 5), meta).expect("equal to the floor is allowed");
}

// ── Refusals ────────────────────────────────────────────────────────────────

// REQ-006
#[test]
fn a_manifest_below_the_epoch_floor_is_refused_and_writes_nothing() {
    let mut meta = BootMeta::default();
    meta.min_sec_epoch = 5;
    let mut st = Mem::default();
    assert_eq!(do_stage(&mut st, &spec(4, 1), meta).unwrap_err(), Refusal::EpochFloor);
    assert_untouched(&st);
    assert!(do_stage(&mut st, &spec(5, 1), meta).is_ok());
}

#[test]
fn a_kernel_below_the_firmware_floor_is_refused() {
    let mut meta = BootMeta::default();
    meta.min_fw_version = 10;
    let mut st = Mem::default();
    assert_eq!(do_stage(&mut st, &spec(9, 9), meta).unwrap_err(), Refusal::FwFloor);
    assert_untouched(&st);
}

#[test]
fn the_switch_enforces_the_floor_the_stager_could_not_know() {
    // The ring-3 stager has no floor to compare with; the switch has the record.
    let mut st = Mem::default();
    let meta = BootMeta::default();
    do_stage(&mut st, &spec(3, 3), meta).expect("stage");
    let mut later = meta;
    later.min_sec_epoch = 4;
    assert_eq!(do_switch(&mut st, later).unwrap_err(), SwitchError::Refused(Refusal::EpochFloor));
    assert!(st.file("/fat/KERN_B.BIN").is_none(), "a refused switch promotes nothing");
}

// REQ-006
#[test]
fn a_bad_signature_is_refused_before_anything_is_read_or_written() {
    let s = spec(2, 2);
    // Another key.
    let mut st = Mem::default();
    let mut buf = [0u8; 1024];
    let other = SigningKey::from_bytes(&[0x99; 32]);
    let r = stage(&mut st, &mut Bytes(bundle_with(&s, &other)), &dev(BootMeta::default()), &pubkey(), &mut Work::new(), &mut buf);
    assert_eq!(r.unwrap_err(), Refusal::Signature);
    assert_untouched(&st);
    // Every bit of the body is covered: flip the epoch, the platform, a hash.
    let good = bundle(&s);
    for at in [8, 12, 16, 24, 24 + 20, 24 + 51] {
        let mut b = good.clone();
        b[at] ^= 1;
        let r = stage(&mut st, &mut Bytes(b), &dev(BootMeta::default()), &pubkey(), &mut Work::new(), &mut buf);
        assert_eq!(r.unwrap_err(), Refusal::Signature, "byte {at}");
        assert_untouched(&st);
    }
    // And the signature itself.
    let mut b = good;
    let sig_at = HEAD_LEN + s.parts.len() * ENTRY_LEN;
    b[sig_at] ^= 0x80;
    let r = stage(&mut st, &mut Bytes(b), &dev(BootMeta::default()), &pubkey(), &mut Work::new(), &mut buf);
    assert_eq!(r.unwrap_err(), Refusal::Signature);
    assert_untouched(&st);
}

#[test]
fn nothing_but_the_head_is_read_before_the_signature() {
    // A part with a kind that does not exist, under a bad signature, is a
    // signature failure: the table was not interpreted.
    let mut s = spec(2, 2);
    s.parts[3].kind = 77;
    let other = SigningKey::from_bytes(&[0x99; 32]);
    assert_eq!(parse_m(&manifest_with(&s, &other)).unwrap_err(), Refusal::Signature);
    // Under the right one it is a part failure, at that part.
    assert_eq!(parse_m(&manifest_with(&s, &signer())).unwrap_err(), Refusal::Part(3));
}

#[test]
fn a_tampered_part_is_refused_and_leaves_no_marker() {
    let s = spec(2, 2);
    let mut b = bundle(&s);
    // Inside CAPS.TOM, the third part.
    let at = manifest_with(&s, &signer()).len() + s.parts[..2].iter().map(|p| p.bytes.len()).sum::<usize>() + 5;
    b[at] ^= 1;
    let mut st = Mem::default();
    let mut buf = [0u8; 1024];
    let r = stage(&mut st, &mut Bytes(b), &dev(BootMeta::default()), &pubkey(), &mut Work::new(), &mut buf);
    assert_eq!(r.unwrap_err(), Refusal::PartHash(2));
    assert!(st.file("/fat/PKG/SYS_B/UPDATE.MAN").is_none());
    assert_eq!(verify_set(&mut st, SLOT_B, &pubkey(), &mut Work::new(), &mut buf).unwrap_err(), Refusal::NotStaged);
    assert_eq!(do_switch(&mut st, BootMeta::default()).unwrap_err(), SwitchError::Refused(Refusal::NotStaged));
}

#[test]
fn a_medium_that_corrupts_a_part_is_caught_by_the_read_back() {
    let s = spec(2, 2);
    let mut st = Mem { corrupt: Some(b"/fat/PKG/SYS_B/BRAIN.ELF".to_vec()), ..Mem::default() };
    let r = do_stage(&mut st, &s, BootMeta::default());
    assert_eq!(r.unwrap_err(), Refusal::PartHash(7));
    assert!(st.file("/fat/PKG/SYS_B/UPDATE.MAN").is_none(), "the marker is withdrawn");
}

#[test]
fn a_forged_directory_is_not_a_staged_set() {
    // Someone with the volume writes the files, and a marker of their own.
    let s = spec(8, 8);
    let mut st = Mem::default();
    let other = SigningKey::from_bytes(&[0x99; 32]);
    for p in &s.parts {
        st.files.insert(format!("/fat/PKG/SYS_B/{}", p.name).into_bytes(), p.bytes.clone());
    }
    st.files.insert(b"/fat/PKG/SYS_B/UPDATE.MAN".to_vec(), manifest_with(&s, &other));
    assert_eq!(do_switch(&mut st, BootMeta::default()).unwrap_err(), SwitchError::Refused(Refusal::Signature));
    assert!(st.file("/fat/KERN_B.BIN").is_none());
}

#[test]
fn a_file_the_manifest_does_not_name_is_refused() {
    let mut st = Mem::default();
    do_stage(&mut st, &spec(2, 2), BootMeta::default()).expect("stage");
    st.files.insert(b"/fat/PKG/SYS_B/EVIL.ELF".to_vec(), vec![1, 2, 3]);
    assert_eq!(do_switch(&mut st, BootMeta::default()).unwrap_err(), SwitchError::Refused(Refusal::Extra));
}

#[test]
fn a_part_changed_after_staging_is_caught_at_the_switch() {
    let mut st = Mem::default();
    do_stage(&mut st, &spec(2, 2), BootMeta::default()).expect("stage");
    st.files.get_mut(b"/fat/PKG/SYS_B/GPIO.ELF".as_slice()).unwrap()[10] ^= 1;
    assert_eq!(do_switch(&mut st, BootMeta::default()).unwrap_err(), SwitchError::Refused(Refusal::PartHash(8)));
}

#[test]
fn the_kernel_signature_must_describe_the_signed_kernel() {
    let mut s = spec(2, 2);
    let k = s.parts[0].bytes.clone();
    s.parts[1].bytes = kernel_sig(99, &k); // a valid signature file, for another version
    let mut st = Mem::default();
    assert_eq!(do_stage(&mut st, &s, BootMeta::default()).unwrap_err(), Refusal::KernelSig);
    assert!(st.file("/fat/PKG/SYS_B/UPDATE.MAN").is_none());
}

#[test]
fn a_set_that_cannot_boot_is_refused() {
    let key = signer();
    let parse = |s: &Spec| parse_m(&manifest_with(s, &key));
    let drop_part = |name: &str| {
        let mut s = spec(1, 1);
        s.parts.retain(|p| p.name != name);
        s
    };
    assert_eq!(parse(&drop_part("CAPS.TOM")), Err(Refusal::Shape(Shape::Topology)));
    assert_eq!(parse(&drop_part("SCHED.TOM")), Err(Refusal::Shape(Shape::Topology)));
    assert_eq!(parse(&drop_part("CONFIG.INI")), Err(Refusal::Shape(Shape::Config)));
    assert_eq!(parse(&drop_part("KERN.SIG")), Err(Refusal::Shape(Shape::Kernel)));
    assert_eq!(parse(&drop_part("KERN.BIN")), Err(Refusal::Shape(Shape::Kernel)));
    assert!(parse(&drop_part("CONFIG.SIG")).is_ok(), "the config signature is optional");
    assert!(parse(&drop_part("GPIO.ELF")).is_ok(), "images are as many as the set has");

    let mut s = spec(1, 1);
    s.parts.push(part(5, "DATA.BIN", vec![1]));
    assert_eq!(parse(&s), Err(Refusal::Shape(Shape::Image)));
    let mut s = spec(1, 1);
    s.parts.push(part(3, "OTHER.TOM", vec![1]));
    assert_eq!(parse(&s), Err(Refusal::Shape(Shape::Topology)));
    let mut s = spec(1, 1);
    s.parts.push(part(1, "KERN2.BIN", vec![1]));
    assert_eq!(parse(&s), Err(Refusal::Shape(Shape::Kernel)));
}

#[test]
fn part_names_are_exact() {
    let key = signer();
    let one = |name: &str, bytes: Vec<u8>| {
        let mut s = spec(1, 1);
        s.parts.push(part(5, name, bytes));
        parse_m(&manifest_with(&s, &key))
    };
    let bad = Err(Refusal::Part(9));
    assert!(one("OK_1.ELF", vec![1]).is_ok());
    assert_eq!(one("lower.ELF", vec![1]), bad);
    assert_eq!(one("A/B.ELF", vec![1]), bad);
    assert_eq!(one("LONGBASENAME", vec![1]), bad);
    assert_eq!(one("A.ELFX", vec![1]), bad);
    assert_eq!(one("EMPTY.ELF", vec![]), bad, "a part has bytes");
    assert_eq!(one("GPIO.ELF", vec![1]), bad, "names are unique");
    assert_eq!(one("UPDATE.MAN", vec![1]), bad, "the marker's name is not a part's");
}

#[test]
fn one_name_has_one_encoding() {
    // Junk after the NUL of a name, under a valid signature, is refused: the
    // name a FAT volume stores and the name the manifest signed cannot differ.
    let s = spec(1, 1);
    let mut b = body(&s);
    b[HEAD_LEN + ENTRY_LEN + 8 + 11] = b'X'; // part 1 is KERN.SIG: byte 11 of its name
    let mut msg = b"AZOS-SYSUPDATE-V1\0".to_vec();
    msg.extend_from_slice(&b);
    let sig = signer().sign(&msg).to_bytes();
    b.extend_from_slice(&sig);
    assert_eq!(parse_m(&b).unwrap_err(), Refusal::Part(1));
}

#[test]
fn reserved_fields_must_be_zero() {
    // The three bytes after the platform, under a valid signature.
    for at in [17, 18, 19] {
        let mut b = body(&spec(1, 1));
        b[at] = 1;
        let mut msg = b"AZOS-SYSUPDATE-V1\0".to_vec();
        msg.extend_from_slice(&b);
        b.extend_from_slice(&signer().sign(&msg).to_bytes());
        assert_eq!(parse_m(&b).unwrap_err(), Refusal::Reserved, "byte {at}");
    }
}

#[test]
fn the_algorithm_and_signature_length_are_the_devices() {
    let ok = spec(1, 1);
    assert_eq!(SIG_LEN, 64, "the suite runs the default algorithm");
    assert_eq!(Manifest::wire_len(&manifest_with(&ok, &signer())), Some(HEAD_LEN + ok.parts.len() * ENTRY_LEN + SIG_LEN));
    // Another algorithm's id (reserved, known but not this device's, unknown):
    // not a manifest this build reads, whatever else it says.
    for alg in [0u16, 2, 3, 4, 0xFFFF] {
        let mut s = spec(1, 1);
        s.alg = alg;
        let m = manifest_with(&s, &signer());
        assert_eq!(parse_m(&m).unwrap_err(), Refusal::Format, "algorithm {alg}");
        assert_eq!(Manifest::wire_len(&m), None, "algorithm {alg}");
    }
    // Another algorithm's whole shape: ML-DSA-65's id and signature length,
    // and a signature of that length. Known, but not this device's.
    let mut s = spec(1, 1);
    s.alg = 2;
    s.sig_len = 3309;
    let mut m = body(&s);
    m.extend_from_slice(&[0u8; 3309]);
    assert_eq!(parse_m(&m).unwrap_err(), Refusal::Format);
    assert_eq!(Manifest::wire_len(&m), None);
    // A signature length the algorithm does not have, however long the bytes.
    for len in [0u16, 1, 63, 65, 3309, 0xFFFF] {
        let mut s = spec(1, 1);
        s.sig_len = len;
        let m = manifest_with(&s, &signer());
        assert_eq!(parse_m(&m).unwrap_err(), Refusal::Format, "sig_len {len}");
        assert_eq!(Manifest::wire_len(&m), None, "sig_len {len}");
    }
}

#[test]
fn a_kernel_signature_of_another_algorithm_does_not_describe_the_kernel() {
    for alg in [0u8, 2, 3] {
        let mut s = spec(2, 2);
        s.parts[1].bytes[4] = alg;
        let mut st = Mem::default();
        assert_eq!(do_stage(&mut st, &s, BootMeta::default()).unwrap_err(), Refusal::KernelSig, "algorithm {alg}");
        assert!(st.file("/fat/PKG/SYS_B/UPDATE.MAN").is_none());
    }
    // And one cut short of its signature.
    let mut s = spec(2, 2);
    s.parts[1].bytes.truncate(100);
    let mut st = Mem::default();
    assert_eq!(do_stage(&mut st, &s, BootMeta::default()).unwrap_err(), Refusal::KernelSig);
}

#[test]
fn every_refusal_has_its_step() {
    let all = [
        Refusal::Truncated, Refusal::Format, Refusal::Signature, Refusal::Reserved, Refusal::Part(3),
        Refusal::Shape(Shape::Image), Refusal::Platform, Refusal::TrialPending, Refusal::EpochFloor,
        Refusal::FwFloor, Refusal::NotInactive, Refusal::Length, Refusal::TooLarge, Refusal::Io(Io::Read),
        Refusal::PartHash(2), Refusal::NotStaged, Refusal::Extra, Refusal::KernelSig, Refusal::Envelope,
    ];
    let steps: Vec<u64> = all.iter().map(|r| r.code() >> 24).collect();
    let want: Vec<u64> = (STEP_FIRST..STEP_FIRST + STEPS).collect();
    assert_eq!(steps, want, "the codes cover the steps, in order");
}

#[test]
fn a_ring_three_stager_that_cannot_name_the_platform_leaves_it_to_the_switch() {
    let mut st = Mem::default();
    let mut s = spec(1, 1);
    s.platform = OTA_PLATFORM_VF2;
    let mut d = dev(BootMeta::default());
    d.platform = None;
    let mut buf = [0u8; 1024];
    stage(&mut st, &mut Bytes(bundle(&s)), &d, &pubkey(), &mut Work::new(), &mut buf).expect("staged");
    // The switch knows the board and refuses.
    assert_eq!(do_switch(&mut st, BootMeta::default()).unwrap_err(), SwitchError::Refused(Refusal::Platform));
    assert!(st.file("/fat/KERN_B.BIN").is_none());
}

#[test]
fn a_refusal_names_the_manifest_it_was_about() {
    let s = spec(2, 2);
    let mut meta = BootMeta::default();
    meta.min_sec_epoch = 9;
    let mut w = Work::new();
    let mut buf = [0u8; 1024];
    let b = bundle(&s);
    let sig_at = HEAD_LEN + s.parts.len() * ENTRY_LEN;
    let want = u64::from_be_bytes(b[sig_at..sig_at + 8].try_into().unwrap());
    let r = stage(&mut Mem::default(), &mut Bytes(b), &dev(meta), &pubkey(), &mut w, &mut buf);
    assert_eq!(r.unwrap_err(), Refusal::EpochFloor);
    assert_eq!(w.last_id(), want);
    // A manifest that did not verify names nothing.
    let mut w = Work::new();
    let other = SigningKey::from_bytes(&[0x99; 32]);
    let _ = stage(&mut Mem::default(), &mut Bytes(bundle_with(&s, &other)), &dev(meta), &pubkey(), &mut w, &mut buf);
    assert_eq!(w.last_id(), 0);
}

#[test]
fn the_platform_and_the_size_are_checked() {
    let mut st = Mem::default();
    let mut s = spec(1, 1);
    s.platform = OTA_PLATFORM_VF2;
    assert_eq!(do_stage(&mut st, &s, BootMeta::default()).unwrap_err(), Refusal::Platform);
    let mut d = dev(BootMeta::default());
    d.max_kernel_size = 8999;
    let mut buf = [0u8; 1024];
    let r = stage(&mut st, &mut Bytes(bundle(&spec(1, 1))), &d, &pubkey(), &mut Work::new(), &mut buf);
    assert_eq!(r.unwrap_err(), Refusal::TooLarge);
    assert_untouched(&st);
}

#[test]
fn the_bundle_is_exactly_as_long_as_the_manifest_says() {
    let mut st = Mem::default();
    let mut buf = [0u8; 1024];
    let good = bundle(&spec(1, 1));
    for b in [good[..good.len() - 1].to_vec(), [good.clone(), vec![0]].concat()] {
        let r = stage(&mut st, &mut Bytes(b), &dev(BootMeta::default()), &pubkey(), &mut Work::new(), &mut buf);
        assert_eq!(r.unwrap_err(), Refusal::Length);
        assert_untouched(&st);
    }
    for cut in [0, 10, 23, 100] {
        let r = stage(&mut st, &mut Bytes(good[..cut].to_vec()), &dev(BootMeta::default()), &pubkey(), &mut Work::new(), &mut buf);
        assert!(matches!(r.unwrap_err(), Refusal::Format | Refusal::Truncated), "cut at {cut}");
    }
    assert_untouched(&st);
}

#[test]
fn a_trial_in_progress_cannot_be_staged_over() {
    // B is on trial; A is what a rollback returns to.
    let mut meta = BootMeta::default();
    meta.active_slot = SLOT_B;
    meta.last_good = SLOT_A;
    let mut st = Mem::default();
    assert_eq!(do_stage(&mut st, &spec(2, 2), meta).unwrap_err(), Refusal::TrialPending);
    assert_untouched(&st);
    // Running the recovery slot is not an installable state either.
    meta.active_slot = SLOT_R;
    assert_eq!(do_stage(&mut st, &spec(2, 2), meta).unwrap_err(), Refusal::TrialPending);
}

// ── Power loss ──────────────────────────────────────────────────────────────

/// A volume that already holds a confirmed generation in B, and the device
/// record that says so: the next update goes to A.
fn running_on_b() -> (Mem, BootMeta, Vec<(Vec<u8>, Vec<u8>)>) {
    let mut st = Mem::default();
    let mut meta = BootMeta::default();
    install(&mut st, &mut meta, &spec(3, 3));
    let b_set = st.untouched_below("/fat/PKG/SYS_B");
    assert_eq!(meta.active_slot, SLOT_B);
    (st, meta, b_set)
}

#[test]
fn a_crash_at_any_point_of_staging_leaves_no_set_and_the_running_one_intact() {
    let (base, meta, b_set) = running_on_b();
    let boot_b = (base.file("/fat/KERN_B.BIN").cloned(), base.file("/fat/KERN_B.SIG").cloned());
    let next = spec(4, 4);

    // How many mutating operations a clean staging takes.
    let mut clean = base.clone();
    clean.ops = 0;
    do_stage(&mut clean, &next, meta).expect("clean");
    let total = clean.ops;
    assert!(total > 10);

    for k in 1..=total {
        let mut st = base.clone();
        st.ops = 0;
        st.crash_at = Some(k);
        assert!(do_stage(&mut st, &next, meta).is_err(), "crash at op {k} of {total} must fail the stage");
        st.reboot();

        // The running generation is exactly as it was.
        assert_eq!(st.untouched_below("/fat/PKG/SYS_B"), b_set, "op {k}");
        assert_eq!((st.file("/fat/KERN_B.BIN").cloned(), st.file("/fat/KERN_B.SIG").cloned()), boot_b, "op {k}");

        // Nothing half-staged is switchable. What verifies is the generation
        // that was staged before (the crash came before the marker went), never
        // a mixture and never the new one.
        let mut buf = [0u8; 1024];
        match verify_set(&mut st, SLOT_A, &pubkey(), &mut Work::new(), &mut buf) {
            Err(_) => {}
            Ok(v) => panic!("crash at op {k}: a set verifies after a failed stage: epoch {}", v.sec_epoch),
        }
        assert!(do_switch(&mut st, meta).is_err(), "op {k}");

        // And the update simply runs again.
        let v = do_stage(&mut st, &next, meta).unwrap_or_else(|e| panic!("restage after crash at {k}: {e:?}"));
        assert_eq!(v.sec_epoch, 4);
    }
}

#[test]
fn a_crash_during_staging_keeps_a_previously_staged_set_until_the_marker_goes() {
    // A complete set is staged, then a newer update is interrupted. Either the
    // old set still verifies whole, or nothing does; the new one never does.
    let (mut base, meta, _) = running_on_b();
    do_stage(&mut base, &spec(4, 4), meta).expect("first");
    let next = spec(5, 5);
    let mut clean = base.clone();
    clean.ops = 0;
    do_stage(&mut clean, &next, meta).expect("clean");
    for k in 1..clean.ops {
        let mut st = base.clone();
        st.ops = 0;
        st.crash_at = Some(k);
        assert!(do_stage(&mut st, &next, meta).is_err());
        st.reboot();
        let mut buf = [0u8; 1024];
        if let Ok(v) = verify_set(&mut st, SLOT_A, &pubkey(), &mut Work::new(), &mut buf) {
            assert_eq!(v.sec_epoch, 4, "crash at op {k}: only the old, whole set may survive");
        }
    }
}

#[test]
fn a_crash_at_any_point_of_the_switch_leaves_the_boot_record_alone() {
    let (base, meta, _) = running_on_b();
    let mut staged = base.clone();
    do_stage(&mut staged, &spec(4, 4), meta).expect("stage");

    let mut clean = staged.clone();
    clean.ops = 0;
    do_switch(&mut clean, meta).expect("clean");
    let total = clean.ops;

    for k in 1..=total {
        let mut st = staged.clone();
        st.ops = 0;
        st.crash_at = Some(k);
        // The caller writes the record only on Ok; here it would not have.
        assert!(do_switch(&mut st, meta).is_err(), "crash at op {k} of {total}");
        st.reboot();
        // The generation that is running boots from B and B was not touched.
        assert_eq!(meta.active_slot, SLOT_B);
        assert_eq!(st.untouched_below("/fat/PKG/SYS_B"), base.untouched_below("/fat/PKG/SYS_B"), "op {k}");
        assert_eq!(st.file("/fat/KERN_B.BIN"), base.file("/fat/KERN_B.BIN"), "op {k}");
        // The staged set is still whole and the switch can simply be run again.
        let v = do_switch(&mut st, meta).unwrap_or_else(|e| panic!("switch again after crash at {k}: {e:?}"));
        assert_eq!(v.sec_epoch, 4);
    }
}

#[test]
fn a_kernel_that_lands_wrong_is_not_switched_to() {
    let mut st = Mem::default();
    do_stage(&mut st, &spec(2, 2), BootMeta::default()).expect("stage");
    st.corrupt = Some(b"/fat/KERN_B.BIN".to_vec());
    assert_eq!(do_switch(&mut st, BootMeta::default()).unwrap_err(), SwitchError::PromotedHash);
}

#[test]
fn a_reinstall_into_a_used_slot_replaces_the_old_set_whole() {
    // Slot B held generation 1's set, with an image generation 2 does not have.
    let (mut st, mut meta, _) = running_on_b();
    let mut gen4 = spec(4, 4);
    gen4.parts.retain(|p| p.name != "GPIO.ELF");
    install(&mut st, &mut meta, &gen4); // into A
    assert_eq!(meta.active_slot, SLOT_A);
    let mut gen5 = spec(5, 5);
    gen5.parts.retain(|p| p.name != "GPIO.ELF");
    install(&mut st, &mut meta, &gen5); // back into B, which held gen 3 with GPIO.ELF
    assert!(st.file("/fat/PKG/SYS_B/GPIO.ELF").is_none(), "the old set's image is gone");
    assert_eq!(meta.active_slot, SLOT_B);
    let mut buf = [0u8; 1024];
    let v = verify_set(&mut st, SLOT_B, &pubkey(), &mut Work::new(), &mut buf).expect("B");
    assert_eq!(v.sec_epoch, 5);
    assert_eq!(st.untouched_below("/fat/PKG/SYS_B").len(), gen5.parts.len() + 1, "the new set and its marker, nothing else");
}

// ── What the boot runs: the set of the slot that is running ─────────────────

/// The boot's view of `meta`'s slot.
fn boot_of(st: &mut Mem, meta: &BootMeta) -> Result<Option<BootSet>, Refusal> {
    boot_set(st, meta, &pubkey(), &mut Work::new())
}

fn names_of(set: &BootSet) -> Vec<String> {
    set.names().map(|n| String::from_utf8(n.to_vec()).unwrap()).collect()
}

/// A device that has installed generation `s` (A -> B), confirmed.
fn installed(s: &Spec) -> (Mem, BootMeta) {
    let mut st = Mem::default();
    let mut meta = BootMeta::default();
    install(&mut st, &mut meta, s);
    (st, meta)
}

#[test]
fn the_switched_slot_boots_the_sets_images_topology_and_config() {
    // The switch flips the record; what the NEXT boot reads is the set it
    // names. Every file of the set, and only those, resolve to its directory.
    let s = spec(5, 7);
    let (mut st, meta) = installed(&s);
    assert_eq!(meta.active_slot, SLOT_B);

    let set = boot_of(&mut st, &meta).expect("verifies").expect("a slot with a set has one in force");
    assert_eq!(set.dir, &b"/fat/PKG/SYS_B"[..]);
    assert_eq!(set.sec_epoch, 5);
    let mut got = names_of(&set);
    let mut want: Vec<String> = s.parts.iter().map(|p| p.name.clone()).collect();
    got.sort();
    want.sort();
    assert_eq!(got, want, "the names the signed manifest lists, no more");
    for p in &s.parts {
        let at = format!("/fat/PKG/SYS_B/{}", p.name);
        assert_eq!(st.file(&at), Some(&p.bytes), "{} is in the directory the boot resolves to", p.name);
    }
    for must in ["CAPS.TOM", "CAPS.SIG", "SCHED.TOM", "CONFIG.INI", "BRAIN.ELF", "GPIO.ELF"] {
        assert!(names_of(&set).iter().any(|n| n == must), "{must}");
    }
}

#[test]
fn a_slot_without_a_set_boots_the_volumes_root_files() {
    // Slot A of a device that never took an update, and R.
    let mut meta = BootMeta::default();
    assert_eq!(boot_of(&mut Mem::default(), &meta).unwrap().map(|s| s.sec_epoch), None);
    meta.active_slot = SLOT_R;
    assert!(boot_of(&mut Mem::default(), &meta).unwrap().is_none());

    // After the update is rolled back to A the files are A's again, whatever
    // B's directory still holds.
    let (mut st, mut meta) = installed(&spec(5, 7));
    assert!(boot_of(&mut st, &meta).unwrap().is_some());
    meta.active_slot = SLOT_A;
    assert!(boot_of(&mut st, &meta).unwrap().is_none(), "A holds no set: the root files");
}

#[test]
fn a_set_the_record_promises_and_the_volume_does_not_hold_is_refused() {
    let (mut st, meta) = installed(&spec(5, 7));
    // The marker is gone (a stage in progress, a removal): nothing is in force.
    st.files.remove(b"/fat/PKG/SYS_B/UPDATE.MAN".as_slice());
    assert_eq!(boot_of(&mut st, &meta).unwrap_err(), Refusal::NotStaged);

    // A marker of another generation is not the set that was switched to.
    let (mut st, meta) = installed(&spec(5, 7));
    let other = spec(6, 8);
    st.files.insert(b"/fat/PKG/SYS_B/UPDATE.MAN".to_vec(), manifest_with(&other, &signer()));
    assert_eq!(boot_of(&mut st, &meta).unwrap_err(), Refusal::NotStaged);

    // A marker by someone without the key.
    let (mut st, meta) = installed(&spec(5, 7));
    let forger = SigningKey::from_bytes(&[0x13; 32]);
    st.files.insert(b"/fat/PKG/SYS_B/UPDATE.MAN".to_vec(), manifest_with(&spec(5, 7), &forger));
    assert_eq!(boot_of(&mut st, &meta).unwrap_err(), Refusal::Signature);
}

#[test]
fn an_epoch_of_zero_is_not_a_set() {
    // 0 is the record's "no set": a manifest cannot claim it.
    let s = spec(0, 1);
    assert_eq!(parse_m(&manifest_with(&s, &signer())), Err(Refusal::EpochFloor));
}

#[test]
fn a_kernel_only_install_withdraws_the_set_from_the_boot() {
    // B holds the signed set of epoch 5; the OTA receiver then puts another
    // kernel into B (after a later update went to A).
    let mut st = Mem::default();
    let mut meta = BootMeta::default();
    install(&mut st, &mut meta, &spec(5, 5)); // A -> B
    install(&mut st, &mut meta, &spec(6, 6)); // B -> A
    assert_eq!((meta.active_slot, meta.sec_epoch_b), (SLOT_A, 5));

    unstage(&mut st, SLOT_B).expect("withdrawn");
    ota_kernel_install_pure(&mut meta, SLOT_B, 9, Some(9), 1234, 0xBEEF);
    assert_eq!(meta.active_slot, SLOT_B);
    assert_eq!(boot_of(&mut st, &meta).unwrap().map(|s| s.sec_epoch), None, "the root files, not B's old set");
    // And the marker alone, left behind, would not have been taken for one.
    let mut again = meta;
    again.sec_epoch_b = 0;
    st.files.insert(b"/fat/PKG/SYS_B/UPDATE.MAN".to_vec(), manifest_with(&spec(5, 5), &signer()));
    assert!(boot_of(&mut st, &again).unwrap().is_none());
}

// ── The kernel-only install's record ────────────────────────────────────────

#[test]
fn kernel_install_resets_the_epoch() {
    // Slot B holds a signed set (epoch 7); the floor is at 3. A kernel-only
    // install replaces B's kernel: B's epoch must go to 0, and A's stays.
    let mut meta = BootMeta::default();
    meta.sec_epoch_a = 4;
    meta.sec_epoch_b = 7;
    meta.min_sec_epoch = 3;
    meta.authenticated_fw_version_b = 6;
    meta.mark_slot_bad(SLOT_B);
    ota_kernel_install_pure(&mut meta, SLOT_B, 9, None, 1234, 0xBEEF);
    assert_eq!(meta.sec_epoch_b, 0, "the slot no longer holds the set");
    assert_eq!(meta.sec_epoch_a, 4, "the other slot is not touched");
    assert_eq!((meta.active_slot, meta.boot_count), (SLOT_B, 0));
    assert_eq!((meta.fw_version_b, meta.image_size_b, meta.image_crc_b), (9, 1234, 0xBEEF));
    assert_eq!(meta.authenticated_fw_version_b, 6, "an unverified install does not set it");
    assert!(!meta.slot_is_bad(SLOT_B));

    // The confirmation then raises no floor from an epoch no system had.
    ota_mark_boot_good_pure(&mut meta);
    assert_eq!(meta.min_sec_epoch, 3);

    // A verified install records the version it verified, on either slot.
    let mut meta = BootMeta::default();
    meta.sec_epoch_a = 2;
    ota_kernel_install_pure(&mut meta, SLOT_A, 4, Some(4), 10, 11);
    assert_eq!((meta.sec_epoch_a, meta.authenticated_fw_version_a, meta.fw_version_a), (0, 4, 4));
}

// Delta updates: the new bundle sent as a patch against the running one.
#[path = "delta_tests.rs"]
mod delta_tests;

// ── The Domain's `ota` envelope row ─────────────────────────────────────────

/// A stage the requester's Domain is held from writes nothing: the question is
/// asked once, for the inactive slot, after the manifest verified and before the
/// first write. **Canary.** `update-canary-apply-gate`: the stager never asks,
/// the set is staged, red.
#[test]
fn a_held_stage_writes_nothing_and_asks_once() {
    let mut st = Mem { held: vec![Apply::Stage], ..Mem::default() };
    let err = do_stage(&mut st, &spec(1, 1), BootMeta::default()).unwrap_err();
    assert_eq!(err, Refusal::Envelope);
    assert_untouched(&st);
    assert_eq!(st.asked, vec![(Apply::Stage, SLOT_B)], "asked once, for the inactive slot");
}

/// A switch the Domain is held from promotes no byte and records nothing: the
/// set stays staged for whoever may switch it, and the boot paths are empty.
/// **Canary.** `update-canary-apply-gate`: red.
#[test]
fn a_held_switch_promotes_nothing() {
    let mut st = Mem { held: vec![Apply::Switch], ..Mem::default() };
    let meta = BootMeta::default();
    do_stage(&mut st, &spec(1, 1), meta).expect("a Domain held only from the switch may stage");
    let before = st.files.clone();
    let err = do_switch(&mut st, meta).unwrap_err();
    assert_eq!(err, SwitchError::Refused(Refusal::Envelope));
    assert_eq!(st.files, before, "a refused switch wrote to the volume");
    assert!(st.file("/fat/KERN_B.BIN").is_none() && st.file("/fat/KERN_B.SIG").is_none());
    assert_eq!(st.asked, vec![(Apply::Stage, SLOT_B), (Apply::Switch, SLOT_B)]);
}

/// A set that does not verify is refused for what is wrong with it, before the
/// row is asked: the gate holds only updates that would otherwise go through,
/// so a forged bundle leaves no `ota` record of its own.
#[test]
fn the_row_is_asked_only_about_a_set_that_verified() {
    let mut st = Mem { held: vec![Apply::Stage], ..Mem::default() };
    let mut b = bundle(&spec(1, 1));
    b[40] ^= 0xFF;
    let mut buf = [0u8; 1024];
    let err = stage(&mut st, &mut Bytes(b), &dev(BootMeta::default()), &pubkey(), &mut Work::new(), &mut buf).unwrap_err();
    assert_ne!(err, Refusal::Envelope);
    assert!(st.asked.is_empty());
}

/// With no row holding anything (the default store), a whole install asks twice
/// and nothing else changes.
#[test]
fn a_domain_held_from_nothing_installs_as_before() {
    let mut st = Mem::default();
    let mut meta = BootMeta::default();
    install(&mut st, &mut meta, &spec(1, 1));
    assert_eq!(st.asked, vec![(Apply::Stage, SLOT_B), (Apply::Switch, SLOT_B)]);
    assert_eq!(meta.active_slot, SLOT_B);
}
