// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Delta updates: the new bundle as a patch against the running slot's set.
//!
//! A child of `update_tests`, which owns the fixtures: the volume with a
//! power-loss switch, the signed bundles and the stage/switch helpers. The
//! deltas the tests apply are made by the real generator (`tools/image/ota_delta.py`,
//! run as a subprocess), so the Rust applier and the Python generator are
//! checked against each other; the refusals are checked on bytes this file
//! builds itself.
//!
//! Canary: `update-canary-hash` skips the delta's base and result checks along
//! with the stager's part hashes, and the tests that expect a refusal of a
//! wrong or damaged delta go red.

use super::*;
use std::process::Command;

const MAX_BUNDLE: u32 = 1 << 20;

// ── Fixtures ────────────────────────────────────────────────────────────────

/// The next generation of `old`: a kernel with a few bytes changed and some
/// inserted, one image touched, everything else the same, the epoch one higher.
fn next_gen(old: &Spec) -> Spec {
    let mut s = old.clone();
    s.epoch += 1;
    s.fw += 1;
    let mut k = old.parts[0].bytes.clone();
    for b in &mut k[6000..6010] {
        *b ^= 0x5A;
    }
    let tail = k.split_off(3000);
    k.extend_from_slice(&data(0xC0FFEE, 40));
    k.extend_from_slice(&tail);
    s.parts[1].bytes = kernel_sig(s.fw, &k);
    s.parts[0].bytes = k;
    for b in &mut s.parts[7].bytes[4000..4100] {
        *b = b.wrapping_add(1);
    }
    s
}

/// A device that has installed and confirmed `s`, and its boot record.
fn running(s: &Spec) -> (Mem, BootMeta) {
    let mut st = Mem::default();
    let mut meta = BootMeta::default();
    install(&mut st, &mut meta, s);
    assert_eq!((meta.active_slot, meta.last_good), (SLOT_B, SLOT_B));
    (st, meta)
}

/// A scratch directory of this test run that no other test uses.
fn scratch(what: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "azos-ota-delta-{what}-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn tool() -> String {
    format!("{}/../../../tools/image/ota_delta.py", env!("CARGO_MANIFEST_DIR"))
}

/// Run the generator on two bundles.
fn py_make(old: &[u8], new: &[u8]) -> Vec<u8> {
    let dir = scratch("make");
    let (o, n, d) = (dir.join("old"), dir.join("new"), dir.join("delta"));
    std::fs::write(&o, old).unwrap();
    std::fs::write(&n, new).unwrap();
    let out = Command::new("python3").arg(tool()).args(["make"]).arg(&o).arg(&n).arg("-o").arg(&d).output().expect("python3");
    assert!(out.status.success(), "ota_delta.py make: {}", String::from_utf8_lossy(&out.stderr));
    let delta = std::fs::read(&d).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    delta
}

/// The generator's own applier on a pair of files: did it accept?
fn py_apply_ok(old: &[u8], delta: &[u8]) -> bool {
    let dir = scratch("apply");
    let (o, d, r) = (dir.join("old"), dir.join("delta"), dir.join("result"));
    std::fs::write(&o, old).unwrap();
    std::fs::write(&d, delta).unwrap();
    let ok = Command::new("python3").arg(tool()).arg("apply").arg(&o).arg(&d).arg("-o").arg(&r).output().unwrap().status.success();
    std::fs::remove_dir_all(&dir).ok();
    ok
}

/// A delta built here, byte by byte. `ops`: `Ok((src, len))` is a COPY,
/// `Err(bytes)` an INSERT. The head names `base` and `result`.
fn encode(base: &[u8], result: &[u8], ops: &[Result<(u32, u32), Vec<u8>>]) -> Vec<u8> {
    let mut d = b"AZDL".to_vec();
    d.extend_from_slice(&1u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&(base.len() as u32).to_le_bytes());
    d.extend_from_slice(&sha256(base));
    d.extend_from_slice(&(result.len() as u32).to_le_bytes());
    d.extend_from_slice(&sha256(result));
    for op in ops {
        match op {
            Ok((src, len)) => {
                d.push(1);
                d.extend_from_slice(&src.to_le_bytes());
                d.extend_from_slice(&len.to_le_bytes());
            }
            Err(bytes) => {
                d.push(2);
                d.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                d.extend_from_slice(bytes);
            }
        }
    }
    d
}

#[derive(Debug, PartialEq, Eq)]
enum Fail {
    /// The set directory of the running slot is not a base.
    Base(Refusal),
    /// The delta is refused before anything is written.
    Delta(DeltaError),
    /// The stager refuses the bundle the delta makes.
    Stage(Refusal),
}

/// What the installer does with a delta: the running slot's set as the base, the
/// delta checked against it, the bundle it makes staged.
fn stage_delta(st: &mut Mem, delta: &[u8], meta: BootMeta) -> Result<Verified, Fail> {
    let mut mb = [0u8; MANIFEST_MAX];
    let mut msg = [0u8; MSG_MAX];
    let base = SetBase::open(st.clone(), meta.active_slot, &pubkey(), &mut mb, &mut msg).map_err(Fail::Base)?;
    let mut buf = [0u8; 512];
    let mut src = DeltaSource::open(base, Bytes(delta.to_vec()), MAX_BUNDLE, &mut buf).map_err(Fail::Delta)?;
    stage(st, &mut src, &dev(meta), &pubkey(), &mut Work::new(), &mut buf).map_err(Fail::Stage)
}

/// Read a whole source in `chunk`-byte reads.
fn read_all<R: Source>(src: &mut R, chunk: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; chunk];
    while (out.len() as u64) < src.len() {
        let n = src.read(out.len() as u64, &mut buf).expect("read");
        assert!(n > 0, "a short source at {}", out.len());
        out.extend_from_slice(&buf[..n]);
    }
    out
}

fn open_raw(base: &[u8], delta: &[u8]) -> Result<DeltaSource<Bytes, Bytes>, DeltaError> {
    DeltaSource::open(Bytes(base.to_vec()), Bytes(delta.to_vec()), MAX_BUNDLE, &mut [0u8; 256])
}

// ── The base ────────────────────────────────────────────────────────────────

#[test]
fn the_running_set_reads_back_as_the_bundle_it_was_staged_from() {
    let s = spec(5, 7);
    let (st, meta) = running(&s);
    let want = bundle(&s);
    let mut mb = [0u8; MANIFEST_MAX];
    let mut msg = [0u8; MSG_MAX];
    for chunk in [1usize, 7, 64, 1000, 4096, 100_000] {
        let mut base = SetBase::open(st.clone(), meta.active_slot, &pubkey(), &mut mb, &mut msg).unwrap();
        assert_eq!(base.len(), want.len() as u64);
        assert_eq!(read_all(&mut base, chunk), want, "chunk {chunk}");
    }
    // Reads that go backwards, jump between files and span two of them.
    let mut base = SetBase::open(st.clone(), meta.active_slot, &pubkey(), &mut mb, &mut msg).unwrap();
    let mut buf = vec![0u8; 3000];
    for off in [20_000u64, 5, 9_900, 0, want.len() as u64 - 10, 1_800, 1_700, 12_000] {
        let n = base.read(off, &mut buf).unwrap();
        let end = (off as usize + buf.len()).min(want.len());
        assert_eq!(&buf[..n], &want[off as usize..end], "at {off}");
        assert_eq!(n, end - off as usize, "a read is short only at the end");
    }
    assert_eq!(base.read(want.len() as u64, &mut buf), Ok(0));
    assert!(base.read(want.len() as u64 + 1, &mut buf).is_err());
}

#[test]
fn a_slot_without_a_set_is_not_a_base() {
    let mut mb = [0u8; MANIFEST_MAX];
    let mut msg = [0u8; MSG_MAX];
    let r = SetBase::open(Mem::default(), SLOT_B, &pubkey(), &mut mb, &mut msg);
    assert_eq!(r.err(), Some(Refusal::NotStaged));
    // Nor is a directory whose manifest was written by somebody without the key.
    let s = spec(5, 7);
    let (mut st, _) = running(&s);
    let forged = bundle_with(&s, &SigningKey::from_bytes(&[0x43; 32]));
    let mlen = Manifest::wire_len(&forged).unwrap();
    st.files.insert(b"/fat/PKG/SYS_B/UPDATE.MAN".to_vec(), forged[..mlen].to_vec());
    let r = SetBase::open(st, SLOT_B, &pubkey(), &mut mb, &mut msg);
    assert_eq!(r.err(), Some(Refusal::Signature));
}

// ── Round trip ──────────────────────────────────────────────────────────────

#[test]
fn a_delta_round_trips_and_the_update_goes_through_the_atomic_path() {
    let old = spec(5, 7);
    let new = next_gen(&old);
    let (mut st, mut meta) = running(&old);
    let (old_bundle, new_bundle) = (bundle(&old), bundle(&new));
    let delta = py_make(&old_bundle, &new_bundle);
    assert!(delta.len() * 5 < new_bundle.len(), "{} bytes for a {}-byte bundle", delta.len(), new_bundle.len());

    // The delta, applied, is the new bundle, however it is read.
    let mut mb = [0u8; MANIFEST_MAX];
    let mut msg = [0u8; MSG_MAX];
    for chunk in [1usize, 13, 512, 100_000] {
        let base = SetBase::open(st.clone(), meta.active_slot, &pubkey(), &mut mb, &mut msg).unwrap();
        let mut d = DeltaSource::open(base, Bytes(delta.clone()), MAX_BUNDLE, &mut [0u8; 300]).unwrap();
        assert_eq!(d.len(), new_bundle.len() as u64);
        assert_eq!(read_all(&mut d, chunk), new_bundle, "chunk {chunk}");
        // A read behind the cursor starts over, and says the same.
        let mut b = [0u8; 100];
        assert_eq!(d.read(2, &mut b), Ok(100));
        assert_eq!(&b[..], &new_bundle[2..102]);
    }

    // And the stager takes it as it takes a bundle that came whole.
    let before_base = st.untouched_below("/fat/PKG/SYS_B");
    let v = stage_delta(&mut st, &delta, meta).expect("stage");
    assert_eq!((v.slot, v.sec_epoch, v.fw_version), (SLOT_A, 6, 8));
    for p in &new.parts {
        assert_eq!(st.file(&format!("/fat/PKG/SYS_A/{}", p.name)), Some(&p.bytes), "{}", p.name);
    }
    assert_eq!(st.untouched_below("/fat/PKG/SYS_B"), before_base, "the running set is only read");

    let v = do_switch(&mut st, meta).expect("switch");
    assert_eq!(st.file("/fat/KERN_A.BIN"), Some(&new.parts[0].bytes));
    ota_switch_pure(&mut meta, v.slot, &v.set()).expect("record");
    assert_eq!(ota_boot_validate_pure(&mut meta, 3), BootValidateOutcome::Normal);
    ota_mark_boot_good_pure(&mut meta);
    assert_eq!((meta.active_slot, meta.last_good, meta.min_sec_epoch, meta.min_fw_version), (SLOT_A, SLOT_A, 6, 8));

    // The generation after that is a delta against the one just installed, into B.
    let third = next_gen(&new);
    let delta = py_make(&new_bundle, &bundle(&third));
    let v = stage_delta(&mut st, &delta, meta).expect("stage the third");
    assert_eq!((v.slot, v.sec_epoch), (SLOT_B, 7));
    assert_eq!(st.file("/fat/PKG/SYS_B/KERN.BIN"), Some(&third.parts[0].bytes));
}

#[test]
fn the_generator_and_the_applier_agree_on_awkward_shapes() {
    // Identical, wholly different, shifted, truncated, extended, repeated data.
    let a = data(1, 5000);
    let mut shifted = vec![9u8; 77];
    shifted.extend_from_slice(&a);
    let zeros = vec![0u8; 4000];
    let cases: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (a.clone(), a.clone()),
        (a.clone(), data(2, 5000)),
        (a.clone(), shifted),
        (a.clone(), a[..1234].to_vec()),
        (a.clone(), [a.clone(), data(3, 300)].concat()),
        (zeros.clone(), [zeros.clone(), vec![1u8], zeros.clone()].concat()),
        (a.clone(), [a[2500..].to_vec(), a[..2500].to_vec()].concat()),
        (vec![7u8; 10], data(4, 50)),
    ];
    for (i, (old, new)) in cases.iter().enumerate() {
        let delta = py_make(old, new);
        let mut d = open_raw(old, &delta).unwrap_or_else(|e| panic!("case {i}: {e:?}"));
        assert_eq!(&read_all(&mut d, 97), new, "case {i}");
    }
    // The first case is nearly free.
    assert!(py_make(&a, &a).len() < DELTA_HEAD_LEN + 2 * DELTA_COPY_LEN);
}

// ── Refusals, before anything is written ────────────────────────────────────

#[test]
fn a_corrupted_delta_never_makes_another_bundle() {
    let old = spec(5, 7);
    let new = next_gen(&old);
    let (st, meta) = running(&old);
    let (old_bundle, new_bundle) = (bundle(&old), bundle(&new));
    let delta = py_make(&old_bundle, &new_bundle);
    let mut mb = [0u8; MANIFEST_MAX];
    let mut msg = [0u8; MSG_MAX];
    let (mut refused, mut equivalent) = (0, 0);
    let mut check = |bad: Vec<u8>, what: &str| {
        let base = SetBase::open(st.clone(), meta.active_slot, &pubkey(), &mut mb, &mut msg).unwrap();
        match DeltaSource::open(base, Bytes(bad), MAX_BUNDLE, &mut [0u8; 256]) {
            Err(_) => refused += 1,
            // A COPY whose source moved onto identical bytes is the same
            // delta: what must never happen is another bundle.
            Ok(mut d) => {
                assert_eq!(read_all(&mut d, 4096), new_bundle, "{what} made a different bundle");
                equivalent += 1;
            }
        }
    };
    // Every byte, flipped two ways.
    for i in 0..delta.len() {
        for x in [0x01u8, 0xFF] {
            let mut bad = delta.clone();
            bad[i] ^= x;
            check(bad, &format!("byte {i} ^ {x:#x} (of {})", delta.len()));
        }
    }
    // Cut short anywhere, or with something after the end.
    for n in 0..delta.len() {
        check(delta[..n].to_vec(), &format!("truncated to {n}"));
    }
    let mut longer = delta.clone();
    longer.push(0);
    check(longer, "a trailing byte");
    // The head, the INSERT payloads and the lengths are all covered: only a
    // few source offsets can land on the same bytes.
    assert!(equivalent * 50 < refused, "{equivalent} equivalent of {}", refused + equivalent);
}

#[test]
fn the_refusals_name_what_is_wrong() {
    let base = data(1, 2000);
    let result = [base[100..900].to_vec(), data(2, 50)].concat();
    let ops = vec![Ok((100, 800)), Err(data(2, 50))];
    let good = encode(&base, &result, &ops);
    assert_eq!(read_all(&mut open_raw(&base, &good).unwrap(), 64), result);

    let open = |d: &[u8]| open_raw(&base, d).err();
    // Head.
    let mut d = good.clone();
    d[0] = b'X';
    assert_eq!(open(&d), Some(DeltaError::Format));
    let mut d = good.clone();
    d[4] = 2;
    assert_eq!(open(&d), Some(DeltaError::Format));
    let mut d = good.clone();
    d[6] = 1;
    assert_eq!(open(&d), Some(DeltaError::Format));
    assert_eq!(open(&good[..DELTA_HEAD_LEN - 1]), Some(DeltaError::Truncated));
    // A result nobody accepts.
    assert_eq!(DeltaSource::open(Bytes(base.clone()), Bytes(good.clone()), 849, &mut [0u8; 64]).err(), Some(DeltaError::TooLarge));
    assert_eq!(open(&encode(&base, &[], &[])), Some(DeltaError::TooLarge));
    // Ops.
    assert_eq!(open(&encode(&base, &result, &[Ok((1300, 800)), Err(data(2, 50))])), Some(DeltaError::Op), "past the base");
    assert_eq!(open(&encode(&base, &result, &[Ok((100, 0)), Ok((100, 800)), Err(data(2, 50))])), Some(DeltaError::Op), "empty op");
    assert_eq!(open(&encode(&base, &result, &[Ok((100, 800))])), Some(DeltaError::Op), "ops short of the result");
    assert_eq!(open(&encode(&base, &result, &[Ok((100, 800)), Err(data(2, 60))])), Some(DeltaError::Op), "ops past the result");
    let mut d = good.clone();
    d[DELTA_HEAD_LEN] = 9;
    assert_eq!(open(&d), Some(DeltaError::Op), "unknown op");
    // The ops make something else than the head says.
    let mut other = result.clone();
    other[10] ^= 1;
    assert_eq!(open(&encode(&base, &other, &ops)), Some(DeltaError::ResultHash));
    let mut d = good.clone();
    *d.last_mut().unwrap() ^= 1;
    assert_eq!(open(&d), Some(DeltaError::ResultHash), "a damaged INSERT");
}

#[test]
fn a_delta_against_the_wrong_base_is_refused_before_a_byte_is_written() {
    let made_for = spec(5, 7);
    let new = next_gen(&made_for);
    let delta = py_make(&bundle(&made_for), &bundle(&new));

    // A device on another build of the same size: the base hash differs.
    let (mut st, meta) = running(&spec(9, 7));
    let volume = st.clone();
    assert_eq!(stage_delta(&mut st, &delta, meta).err(), Some(Fail::Delta(DeltaError::BaseHash)));
    assert_eq!(st.files, volume.files, "nothing was written");
    assert!(st.untouched_below("/fat/PKG/SYS_A").is_empty());

    // One whose bundle is a different length.
    let mut other = spec(5, 7);
    other.parts[7].bytes.truncate(100);
    let (mut st, meta) = running(&other);
    assert_eq!(stage_delta(&mut st, &delta, meta).err(), Some(Fail::Delta(DeltaError::BaseLength)));

    // One that holds no set at all (a kernel-only install): the update must come whole.
    let mut st = Mem::default();
    assert_eq!(stage_delta(&mut st, &delta, BootMeta::default()).err(), Some(Fail::Base(Refusal::NotStaged)));
    assert_volume_empty(&st);

    // The generator's own applier refuses the same pair.
    assert!(!py_apply_ok(&bundle(&spec(9, 7)), &delta));
    assert!(py_apply_ok(&bundle(&made_for), &delta));
}

fn assert_volume_empty(st: &Mem) {
    assert!(st.files.is_empty());
}

#[test]
fn a_delta_cannot_make_what_the_signature_does_not_cover() {
    // A delta whose head is consistent with a bundle the key never signed: the
    // delta checks pass, the stager refuses, nothing stays staged.
    let old = spec(5, 7);
    let new = next_gen(&old);
    let (mut st, meta) = running(&old);
    let (ob, mut nb) = (bundle(&old), bundle(&new));
    let n = nb.len();
    nb[n - 3000] ^= 0xFF; // inside a part: the manifest's hash no longer matches
    let delta = encode(&ob, &nb, &[Err(nb.clone())]);
    assert!(matches!(stage_delta(&mut st, &delta, meta), Err(Fail::Stage(Refusal::PartHash(_)))));
    assert!(st.untouched_below("/fat/PKG/SYS_A/UPDATE.MAN").is_empty(), "no marker");
    assert_eq!(do_switch(&mut st, meta).unwrap_err(), SwitchError::Refused(Refusal::NotStaged));

    // A whole new bundle signed by somebody else: refused at the signature,
    // before a byte is written.
    let (mut st, meta) = running(&old);
    let forged = bundle_with(&new, &SigningKey::from_bytes(&[0x43; 32]));
    let delta = encode(&ob, &forged, &[Err(forged.clone())]);
    assert_eq!(stage_delta(&mut st, &delta, meta).err(), Some(Fail::Stage(Refusal::Signature)));
    assert!(st.untouched_below("/fat/PKG/SYS_A").is_empty());
}

#[test]
fn a_delta_does_not_get_around_the_floors() {
    // The epoch floor is enforced by the stager, which the delta feeds.
    let old = spec(5, 7);
    let mut stale = next_gen(&old);
    stale.epoch = 4;
    let (mut st, meta) = running(&old);
    let delta = py_make(&bundle(&old), &bundle(&stale));
    assert_eq!(stage_delta(&mut st, &delta, meta).err(), Some(Fail::Stage(Refusal::EpochFloor)));
    assert!(st.untouched_below("/fat/PKG/SYS_A").is_empty());
}

// ── Power cut ───────────────────────────────────────────────────────────────

#[test]
fn a_power_cut_at_any_step_of_the_apply_leaves_the_inactive_slot_unswitched() {
    let old = spec(5, 7);
    let new = next_gen(&old);
    let (st0, meta) = running(&old);
    let delta = py_make(&bundle(&old), &bundle(&new));

    // How many writes the whole apply takes.
    let mut probe = st0.clone();
    probe.ops = 0;
    stage_delta(&mut probe, &delta, meta).expect("stage");
    let total = probe.ops;
    assert!(total > 10, "{total}");

    let running_files = st0.untouched_below("/fat/PKG/SYS_B");
    let boot_files = (st0.file("/fat/KERN_B.BIN").cloned(), st0.file("/fat/KERN_B.SIG").cloned());
    for k in 1..=total {
        let mut st = st0.clone();
        st.ops = 0;
        st.crash_at = Some(k);
        let r = stage_delta(&mut st, &delta, meta);
        assert!(r.is_err(), "cut at write {k} of {total}: the apply reported success");
        st.reboot();

        // Nothing is staged: the switch has nothing to switch to.
        assert_eq!(
            do_switch(&mut st, meta).unwrap_err(),
            SwitchError::Refused(Refusal::NotStaged),
            "cut at write {k}: the half-written slot can be switched to"
        );
        let mut buf = [0u8; 512];
        assert_eq!(verify_set(&mut st, SLOT_A, &pubkey(), &mut Work::new(), &mut buf).unwrap_err(), Refusal::NotStaged);
        // The running system is as it was, and nothing named the other slot.
        assert_eq!(st.untouched_below("/fat/PKG/SYS_B"), running_files, "cut at write {k}");
        assert_eq!((st.file("/fat/KERN_B.BIN").cloned(), st.file("/fat/KERN_B.SIG").cloned()), boot_files);
        assert!(st.file("/fat/KERN_A.BIN").is_none(), "the kernel was promoted at write {k}");
        assert_eq!((meta.active_slot, meta.last_good), (SLOT_B, SLOT_B));

        // The same update, started again, completes.
        let v = stage_delta(&mut st, &delta, meta).expect("retry");
        assert_eq!(v.sec_epoch, 6);
        do_switch(&mut st, meta).expect("switch after the retry");
    }
}

#[test]
fn a_medium_that_corrupts_the_applied_part_is_caught_by_the_read_back() {
    let old = spec(5, 7);
    let new = next_gen(&old);
    let (mut st, meta) = running(&old);
    let delta = py_make(&bundle(&old), &bundle(&new));
    st.corrupt = Some(b"/fat/PKG/SYS_A/BRAIN.ELF".to_vec());
    assert!(matches!(stage_delta(&mut st, &delta, meta), Err(Fail::Stage(Refusal::PartHash(_)))));
    assert_eq!(do_switch(&mut st, meta).unwrap_err(), SwitchError::Refused(Refusal::NotStaged));
}
