// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the pure half of the signed kernel livepatch,
//! `crates/core/mm/src/livepatch_fmt.rs` (`azos_mm::text_poke::patch`): the
//! blob format and every refusal of `verify`, the pool layout, the
//! relocations, the redirect encoders of each ISA, the `int3` sequence with
//! its undo, the entry claims and the words an unwind writes back. What touches the machine (the text
//! writer, the pool, the grace period, the records) is
//! `kernel/src/boot/livepatch.rs` and boots in S6.
//!
//! The hash and the signature are stand-ins here (the `RSIG` container itself is
//! the real one, `azos_crypto::sig::Rsig`): SHA-256 and Ed25519 are
//! covered by the crypto suite, and these rows check what `verify` does with
//! their answers (which bytes it hashes, which fields it hands the
//! signature check, in which order it asks).
//!
//! Canaries (by hand, 2026-10-16), each turning the named rows red and no
//! others: `verify` testing the epoch floor with `<=` instead of `<`
//! (`an_epoch_at_the_floor_is_admitted`); dropping the compare of the blob's
//! build-id with the running kernel's (`a_blob_built_for_another_kernel_is_refused`
//! and `the_checks_run_in_the_documented_order`); `place` ignoring the pool's
//! fill (`bodies_are_laid_out_aligned_in_the_pool`, `the_pool_only_grows` and
//! `a_patch_that_does_not_fit_is_refused_and_one_that_just_fits_is_not`);
//! `relocate` using the first body's address for every function
//! (`relocation_of_the_second_function_uses_its_own_address`); `x86_steps`
//! writing the head byte first (`the_int3_sequence_never_shows_a_torn_instruction`);
//! `x86_bp_sequence` putting back only the first byte of `old` after a refused
//! head write (`a_refused_head_write_puts_all_five_old_bytes_back`).

#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/livepatch_fmt.rs"]
mod fmt;

use azos_crypto::sig::{RSIG_FILE_MAX, RSIG_FIXED_LEN};
use fmt::*;

/// The `RSIG` of the default algorithm (Ed25519): 48 bytes and a 64-byte
/// signature, then the payload.
const SIG_HEADER_LEN: usize = RSIG_FILE_MAX;

const TEXT: (u64, u64) = (0xffff_ffff_8000_0000, 0xffff_ffff_8040_0000);
const POOL: (u64, u64) = (TEXT.0 + 0x30_0000, TEXT.0 + 0x31_0000);
const F0: u64 = TEXT.0 + 0x1000;
const F1: u64 = TEXT.0 + 0x2000;
const KEY: [u8; 32] = [7; 32];
const BUILD: [u8; 32] = {
    let mut b = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        b[i] = 0xb0 + i as u8;
        i += 1;
    }
    b
};

/// A stand-in for SHA-256: every input byte reaches the output, so a changed
/// blob is a different one.
fn hash(b: &[u8]) -> [u8; 32] {
    let mut s = [0x5au8; 32];
    for (i, &x) in b.iter().enumerate() {
        let k = i % 32;
        s[k] = s[k].wrapping_mul(31).wrapping_add(x) ^ (i >> 5) as u8;
        s[(k + 7) % 32] ^= s[k].rotate_left(3);
    }
    s
}

/// The blob under test, field by field.
#[derive(Clone)]
struct Blob {
    isa: u8,
    epoch: u32,
    signed_epoch: u32,
    build: Vec<u8>,
    funcs: Vec<(u64, Vec<u8>, u32)>,
    relocs: Vec<(u16, u8, u32, u64)>,
    good_sig: bool,
    key: [u8; 32],
}

impl Blob {
    fn new(isa: u8) -> Blob {
        Blob {
            isa,
            epoch: 5,
            signed_epoch: 5,
            build: BUILD[..16].to_vec(),
            funcs: vec![(F0, vec![0x13; 32], F_NOSLEEP), (F1, vec![0x01; 16], F_NOSLEEP)],
            relocs: vec![],
            good_sig: true,
            key: KEY,
        }
    }

    fn payload(&self) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&MAGIC);
        p.push(VERSION);
        p.push(self.isa);
        p.extend_from_slice(&(self.funcs.len() as u16).to_le_bytes());
        p.extend_from_slice(&self.epoch.to_le_bytes());
        p.push(self.build.len() as u8);
        p.extend_from_slice(&[0; 3]);
        let mut bid = [0u8; 32];
        bid[..self.build.len()].copy_from_slice(&self.build);
        p.extend_from_slice(&bid);
        p.extend_from_slice(&(self.relocs.len() as u32).to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(p.len(), HEADER_LEN);
        let mut off = HEADER_LEN + self.funcs.len() * FUNC_LEN + self.relocs.len() * RELOC_LEN;
        for (va, body, flags) in &self.funcs {
            p.extend_from_slice(&va.to_le_bytes());
            p.extend_from_slice(&(off as u32).to_le_bytes());
            p.extend_from_slice(&(body.len() as u32).to_le_bytes());
            p.extend_from_slice(&flags.to_le_bytes());
            p.extend_from_slice(&0u32.to_le_bytes());
            off += body.len();
        }
        for (f, kind, offset, target) in &self.relocs {
            p.extend_from_slice(&f.to_le_bytes());
            p.push(*kind);
            p.push(0);
            p.extend_from_slice(&offset.to_le_bytes());
            p.extend_from_slice(&target.to_le_bytes());
        }
        for (_, body, _) in &self.funcs {
            p.extend_from_slice(body);
        }
        p
    }

    fn bytes(&self) -> Vec<u8> {
        let p = self.payload();
        let mut b = Vec::new();
        b.extend_from_slice(b"RSIG");
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&64u16.to_le_bytes());
        b.extend_from_slice(&self.key);
        b.extend_from_slice(&(p.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.signed_epoch.to_le_bytes());
        b.extend_from_slice(&[0; 64]);
        assert_eq!(b.len(), SIG_HEADER_LEN);
        b.extend_from_slice(&p);
        if self.good_sig {
            sign(&mut b);
        }
        b
    }
}

/// The signer's stand-in: a "signature" that holds the manifest it covers
/// (the payload's digest, the signed epoch and size) and a mark, so the
/// check can tell a payload or a header field changed after signing.
fn sign(b: &mut [u8]) {
    let d = hash(&b[SIG_HEADER_LEN..]);
    let (fw, size) = (b[44..48].to_vec(), b[40..44].to_vec());
    b[48..80].copy_from_slice(&d);
    b[80..84].copy_from_slice(&fw);
    b[84..88].copy_from_slice(&size);
    b[88] = 0x42;
}

/// What the kernel would pass; every field a row can move.
struct Env {
    isa: u8,
    build: [u8; 32],
    floor: u32,
    allowed: Vec<u64>,
    sites: Vec<u64>,
    /// `None`: the row names this blob. `Some(f)`: edit the row.
    row: Option<Box<dyn Fn(&mut Row)>>,
    no_row: bool,
    text: (u64, u64),
}

impl Env {
    fn new(isa: u8) -> Env {
        Env { isa, build: BUILD, floor: 0, allowed: vec![F0, F1], sites: vec![F0, F1, TEXT.0 + 0x3000], row: None, no_row: false, text: TEXT }
    }

    fn verify(&self, blob: &[u8], b: &Blob) -> Result<Verified, Reason> {
        let mut row = Row {
            isa: b.isa,
            build_id: {
                let mut x = [0u8; 32];
                x[..b.build.len()].copy_from_slice(&b.build);
                x
            },
            build_id_len: b.build.len() as u8,
            sec_epoch: b.epoch,
            sha256: hash(blob),
        };
        if let Some(f) = &self.row {
            f(&mut row);
        }
        let rows = if self.no_row { vec![] } else { vec![row] };
        let ctx = Ctx {
            isa: self.isa,
            build_id: &self.build,
            floor: self.floor,
            text: self.text,
            rows: &rows,
            sha256: &hash,
            // A valid signature: by the key whose id is KEY, marked good, over
            // the digest of the payload the blob carries.
            verify: &|s, digest| {
                *s.key_id == KEY
                    && s.signature[40] == 0x42
                    && s.signature[..32] == digest[..]
                    && s.signature[32..36] == s.fw_version.to_le_bytes()
                    && s.signature[36..40] == s.payload_size.to_le_bytes()
            },
            allowed: &|va| self.allowed.contains(&va),
            has_site: &|va| self.sites.contains(&va),
        };
        verify(blob, &ctx)
    }
}

fn ok(isa: u8) -> (Blob, Env) {
    (Blob::new(isa), Env::new(isa))
}

fn run(b: &Blob, e: &Env) -> Result<Verified, Reason> {
    e.verify(&b.bytes(), b)
}

#[test]
fn a_good_blob_verifies_and_reports_its_functions_and_relocations() {
    for isa in [ISA_RISCV64, ISA_AARCH64, ISA_X86_64] {
        let (mut b, e) = ok(isa);
        let kind = match isa {
            ISA_RISCV64 => R_RV_CALL,
            ISA_AARCH64 => R_A64_CALL26,
            _ => R_X86_PC32,
        };
        b.relocs.push((1, kind, 8, TEXT.0 + 0x500));
        let bytes = b.bytes();
        let v = run(&b, &e).unwrap_or_else(|r| panic!("isa {isa}: {r:?}"));
        assert_eq!((v.row, v.sec_epoch, v.nfuncs), (0, 5, 2));
        assert_eq!(v.name, u64::from_be_bytes(hash(&bytes)[..8].try_into().unwrap()));
        assert_eq!((v.funcs[0].old_va, v.funcs[0].body_len), (F0, 32));
        assert_eq!((v.funcs[1].old_va, v.funcs[1].body_len), (F1, 16));
        // The bodies are where the table says, in the blob.
        assert_eq!(&bytes[v.funcs[0].body_off..][..32], &[0x13; 32][..]);
        assert_eq!(&bytes[v.funcs[1].body_off..][..16], &[0x01; 16][..]);
        let rs: Vec<_> = v.relocs(&bytes).collect();
        assert_eq!((rs.len(), rs[0].func, rs[0].kind, rs[0].offset, rs[0].target), (1, 1, kind, 8, TEXT.0 + 0x500));
    }
}

#[test]
fn a_bad_signature_is_refused() {
    let (mut b, e) = ok(ISA_AARCH64);
    b.good_sig = false;
    assert_eq!(run(&b, &e).unwrap_err(), Reason::Signature);
    // Another signer's key.
    let (mut b, e) = ok(ISA_AARCH64);
    b.key = [8; 32];
    assert_eq!(run(&b, &e).unwrap_err(), Reason::Signature);
    // A payload changed after signing: the check is handed the digest of
    // the payload the blob carries, not of the one that was signed. (The row
    // follows the bytes in `Env::verify`, so only the signature can object.)
    let (b, e) = ok(ISA_AARCH64);
    let mut bytes = b.bytes();
    *bytes.last_mut().unwrap() ^= 1;
    assert_eq!(e.verify(&bytes, &b).unwrap_err(), Reason::Signature);
}

#[test]
fn the_signed_size_must_be_the_payloads() {
    let (b, e) = ok(ISA_AARCH64);
    let mut bytes = b.bytes();
    bytes[40] = bytes[40].wrapping_add(4); // payload_size in the RSIG header
    assert_eq!(e.verify(&bytes, &b).unwrap_err(), Reason::Signature);
}

#[test]
fn a_blob_no_row_names_is_refused_before_anything_else_is_asked() {
    let (mut b, mut e) = ok(ISA_AARCH64);
    e.no_row = true;
    // Also unsigned and for another kernel: the row is asked first.
    b.good_sig = false;
    b.build = vec![1; 16];
    assert_eq!(run(&b, &e).unwrap_err(), Reason::NotAdmitted);
    // A row for the same bytes but another ISA does not name it for this one.
    let (b, mut e) = ok(ISA_AARCH64);
    e.row = Some(Box::new(|r| r.isa = ISA_RISCV64));
    assert_eq!(run(&b, &e).unwrap_err(), Reason::NotAdmitted);
    // A row that names other bytes.
    let (b, mut e) = ok(ISA_AARCH64);
    e.row = Some(Box::new(|r| r.sha256[0] ^= 1));
    assert_eq!(run(&b, &e).unwrap_err(), Reason::NotAdmitted);
}

#[test]
fn a_blob_for_another_isa_is_refused() {
    // The row and the signature are right; the payload says riscv64 on an
    // aarch64 kernel.
    let (b, mut e) = ok(ISA_RISCV64);
    e.isa = ISA_AARCH64;
    e.row = Some(Box::new(|r| r.isa = ISA_AARCH64));
    assert_eq!(run(&b, &e).unwrap_err(), Reason::Isa);
}

#[test]
fn a_blob_built_for_another_kernel_is_refused() {
    // The running kernel is not the one the blob and its row name.
    let (b, mut e) = ok(ISA_AARCH64);
    e.build[3] ^= 0x40;
    assert_eq!(run(&b, &e).unwrap_err(), Reason::BuildId);
    // The row pins another kernel than the blob does.
    let (b, mut e) = ok(ISA_AARCH64);
    e.row = Some(Box::new(|r| r.build_id[0] ^= 1));
    assert_eq!(run(&b, &e).unwrap_err(), Reason::BuildId);
    // A shorter pin is another pin, even when it is a prefix.
    let (b, mut e) = ok(ISA_AARCH64);
    e.row = Some(Box::new(|r| r.build_id_len = 8));
    assert_eq!(run(&b, &e).unwrap_err(), Reason::BuildId);
    // A longer id (32 bytes) is compared whole.
    let (mut b, mut e) = ok(ISA_AARCH64);
    b.build = BUILD.to_vec();
    assert!(run(&b, &e).is_ok());
    e.build[31] ^= 1;
    assert_eq!(run(&b, &e).unwrap_err(), Reason::BuildId);
}

#[test]
fn an_epoch_below_the_floor_or_off_the_signature_or_the_row_is_refused() {
    let (b, mut e) = ok(ISA_AARCH64);
    e.floor = 6;
    assert_eq!(run(&b, &e).unwrap_err(), Reason::Epoch);
    // The epoch inside the payload is not the one the signature covers.
    let (mut b, e) = ok(ISA_AARCH64);
    b.epoch = 9;
    b.signed_epoch = 5;
    let mut e = e;
    e.row = Some(Box::new(|r| r.sec_epoch = 9));
    assert_eq!(run(&b, &e).unwrap_err(), Reason::Epoch);
    // The row admits another epoch.
    let (b, mut e) = ok(ISA_AARCH64);
    e.row = Some(Box::new(|r| r.sec_epoch = 4));
    assert_eq!(run(&b, &e).unwrap_err(), Reason::Epoch);
    // Epoch 0 is never an epoch.
    let (mut b, mut e) = ok(ISA_AARCH64);
    b.epoch = 0;
    b.signed_epoch = 0;
    e.row = Some(Box::new(|r| r.sec_epoch = 0));
    assert_eq!(run(&b, &e).unwrap_err(), Reason::Epoch);
}

#[test]
fn an_epoch_at_the_floor_is_admitted() {
    let (b, mut e) = ok(ISA_AARCH64);
    e.floor = 5;
    assert!(run(&b, &e).is_ok());
    e.floor = 0;
    assert!(run(&b, &e).is_ok());
}

#[test]
fn a_function_outside_the_allowlist_the_text_or_the_site_table_is_refused() {
    let (b, mut e) = ok(ISA_AARCH64);
    e.allowed = vec![F0]; // F1 is not allowlisted
    assert_eq!(run(&b, &e).unwrap_err(), Reason::NotAllowed);
    let (b, mut e) = ok(ISA_AARCH64);
    e.sites = vec![F0]; // F1 has no entry slot
    assert_eq!(run(&b, &e).unwrap_err(), Reason::NoSite);
    // An address outside the text is not allowed even when the lists say so.
    let (mut b, mut e) = ok(ISA_AARCH64);
    b.funcs[1].0 = TEXT.1 + 0x10;
    e.allowed.push(TEXT.1 + 0x10);
    e.sites.push(TEXT.1 + 0x10);
    assert_eq!(run(&b, &e).unwrap_err(), Reason::NotAllowed);
    // The same function twice.
    let (mut b, e) = ok(ISA_AARCH64);
    b.funcs[1].0 = F0;
    assert_eq!(run(&b, &e).unwrap_err(), Reason::Format);
}

#[test]
fn a_function_not_marked_as_never_sleeping_is_refused() {
    let (mut b, e) = ok(ISA_AARCH64);
    b.funcs[0].2 = 0;
    assert_eq!(run(&b, &e).unwrap_err(), Reason::NotNosleep);
    // An unknown bit is a format the verifier does not know.
    let (mut b, e) = ok(ISA_AARCH64);
    b.funcs[0].2 = F_NOSLEEP | 2;
    assert_eq!(run(&b, &e).unwrap_err(), Reason::Format);
}

#[test]
fn the_checks_run_in_the_documented_order() {
    // Everything wrong at once: the row is the first question, then the
    // signature, the ISA, the build, the epoch, then the functions.
    let (mut b, mut e) = ok(ISA_AARCH64);
    b.good_sig = false;
    b.build = vec![9; 16];
    b.epoch = 1;
    b.signed_epoch = 2;
    e.floor = 3;
    e.allowed.clear();
    assert_eq!(run(&b, &e).unwrap_err(), Reason::Signature);
    b.good_sig = true;
    assert_eq!(run(&b, &e).unwrap_err(), Reason::BuildId);
    b.build = BUILD[..16].to_vec();
    assert_eq!(run(&b, &e).unwrap_err(), Reason::Epoch);
    b.epoch = 5;
    b.signed_epoch = 5;
    e.floor = 3;
    assert_eq!(run(&b, &e).unwrap_err(), Reason::NotAllowed);
    e.allowed = vec![F0, F1];
    assert!(run(&b, &e).is_ok());
}

#[test]
fn malformed_blobs_are_refused() {
    let (b, e) = ok(ISA_AARCH64);
    let good = b.bytes();
    assert_eq!(e.verify(&good[..SIG_HEADER_LEN + 10], &b).unwrap_err(), Reason::Format);
    // Corrupt one field at a time and sign again (as a signer that builds a
    // bad blob would): only the format can object.
    let corrupt = |what: &str, at: usize, to: &[u8], want: Reason| {
        let mut bytes = good.clone();
        bytes[at..at + to.len()].copy_from_slice(to);
        if at >= SIG_HEADER_LEN {
            sign(&mut bytes);
        }
        assert_eq!(e.verify(&bytes, &b).unwrap_err(), want, "{what}");
    };
    corrupt("rsig magic", 0, b"X", Reason::Format);
    corrupt("rsig algorithm", 4, &[0], Reason::Format);
    corrupt("rsig algorithm of another kind", 4, &[2], Reason::Format);
    corrupt("rsig signature length", 6, &[63], Reason::Format);
    corrupt("rsig signature length of another algorithm", 6, &[0x1d, 0x0d], Reason::Format); // 3357: not 3309 either
    // Another algorithm's whole shape: ML-DSA-65's id and signature length, and
    // a signature of that length before the payload. Known, but not this device's.
    let mut ml = good[..RSIG_FIXED_LEN].to_vec();
    ml[4..6].copy_from_slice(&2u16.to_le_bytes());
    ml[6..8].copy_from_slice(&3309u16.to_le_bytes());
    ml.resize(RSIG_FIXED_LEN + 3309, 0);
    ml.extend_from_slice(&good[SIG_HEADER_LEN..]);
    assert_eq!(e.verify(&ml, &b).unwrap_err(), Reason::Format, "ML-DSA-65 on an Ed25519 device");
    let p = SIG_HEADER_LEN;
    corrupt("payload magic", p, b"X", Reason::Format);
    corrupt("payload version", p + 4, &[2], Reason::Format);
    corrupt("no functions", p + 6, &[0], Reason::Format);
    corrupt("too many functions", p + 6, &[(MAX_FUNCS + 1) as u8], Reason::Format);
    corrupt("reserved after the build-id length", p + 13, &[1], Reason::Format);
    corrupt("build-id too short", p + 12, &[7], Reason::Format);
    corrupt("build-id too long", p + 12, &[33], Reason::Format);
    corrupt("build-id padding", p + 16 + 20, &[1], Reason::Format);
    corrupt("reserved header word", p + 52, &[1], Reason::Format);
    // Function table: body past the end, misaligned, empty, inside the tables.
    let f0 = p + HEADER_LEN;
    let tables = (HEADER_LEN + 2 * FUNC_LEN) as u32;
    corrupt("body past the end", f0 + 12, &0x1000u32.to_le_bytes(), Reason::Format);
    corrupt("body length not a multiple of 4", f0 + 12, &30u32.to_le_bytes(), Reason::Format);
    corrupt("empty body", f0 + 12, &0u32.to_le_bytes(), Reason::Format);
    corrupt("body offset misaligned", f0 + 8, &(tables + 2).to_le_bytes(), Reason::Format);
    corrupt("body inside the tables", f0 + 8, &8u32.to_le_bytes(), Reason::Format);
    corrupt("reserved word of an entry", f0 + 20, &1u32.to_le_bytes(), Reason::Format);
    corrupt("relocation table past the end", p + 48, &0x10_0000u32.to_le_bytes(), Reason::Format);
    // Control: the same bytes, signed again by the helper, verify (so it is
    // the corruption that fails them, not the helper's signing).
    let mut again = good.clone();
    sign(&mut again);
    assert!(e.verify(&again, &b).is_ok());
}

#[test]
fn a_relocation_must_fit_its_body_its_isa_and_the_text() {
    let bad = |isa: u8, rel: (u16, u8, u32, u64), what: &str| {
        let (mut b, e) = ok(isa);
        b.relocs.push(rel);
        assert_eq!(run(&b, &e).unwrap_err(), Reason::Format, "{what}");
    };
    bad(ISA_AARCH64, (2, R_A64_CALL26, 0, TEXT.0 + 8), "function out of range");
    bad(ISA_AARCH64, (0, R_RV_CALL, 0, TEXT.0 + 8), "riscv relocation on aarch64");
    bad(ISA_RISCV64, (0, R_A64_CALL26, 0, TEXT.0 + 8), "aarch64 relocation on riscv64");
    bad(ISA_X86_64, (0, R_A64_CALL26, 0, TEXT.0 + 8), "aarch64 relocation on x86_64");
    bad(ISA_AARCH64, (0, R_A64_CALL26, 32, TEXT.0 + 8), "field past the body");
    bad(ISA_AARCH64, (0, R_A64_CALL26, 2, TEXT.0 + 8), "misaligned field");
    bad(ISA_RISCV64, (1, R_RV_CALL, 12, TEXT.0 + 8), "an 8-byte pair that runs 4 bytes past the body");
    bad(ISA_AARCH64, (0, R_A64_CALL26, 0, TEXT.1 + 8), "target outside the text");
    bad(ISA_AARCH64, (0, R_A64_CALL26, 0, TEXT.0 - 8), "target below the text");
    // x86 fields need no alignment.
    let (mut b, e) = ok(ISA_X86_64);
    b.relocs.push((0, R_X86_PC32, 5, TEXT.0 + 8));
    assert!(run(&b, &e).is_ok());
}

fn pool_blob() -> (Blob, Env) {
    ok(ISA_AARCH64)
}

#[test]
fn bodies_are_laid_out_aligned_in_the_pool() {
    let (b, e) = pool_blob();
    let v = run(&b, &e).unwrap();
    let p = place(&v, POOL, 0).unwrap();
    assert_eq!(p.body_va[0], POOL.0);
    assert_eq!(p.body_va[1], POOL.0 + 32, "the second body follows the first, 16-aligned");
    assert_eq!(p.end, 32 + 16);
    let p = place(&v, POOL, 5).unwrap();
    assert_eq!(p.body_va[0], POOL.0 + 16, "an odd fill rounds up to 16");
}

#[test]
fn the_pool_only_grows() {
    let (b, e) = pool_blob();
    let v = run(&b, &e).unwrap();
    let first = place(&v, POOL, 0).unwrap();
    // The second patch starts where the first one ended, whatever happened
    // to the first (the pool never gives space back).
    let second = place(&v, POOL, first.end).unwrap();
    assert!(second.body_va[0] >= POOL.0 + first.end);
    assert!(second.end > first.end);
}

#[test]
fn a_patch_that_does_not_fit_is_refused_and_one_that_just_fits_is_not() {
    let (b, e) = pool_blob();
    let v = run(&b, &e).unwrap();
    let size = POOL.1 - POOL.0;
    assert_eq!(place(&v, POOL, size - 47).unwrap_err(), Reason::PoolFull);
    assert_eq!(place(&v, POOL, size).unwrap_err(), Reason::PoolFull);
    assert_eq!(place(&v, POOL, u64::MAX).unwrap_err(), Reason::PoolFull);
    assert!(place(&v, POOL, size - 48).is_ok());
    assert_eq!(place(&v, (POOL.0, POOL.0), 0).unwrap_err(), Reason::PoolFull, "no pool");
}

/// Blob with one function whose body begins with `words`, and one relocation
/// at 0 of `kind` to `target`; verified and relocated at `body0`.
fn relocated(isa: u8, kind: u8, words: &[u8], target: u64, body0: u64) -> Result<Vec<u8>, Reason> {
    let (mut b, mut e) = ok(isa);
    // A text of 1 GiB, so that a target can be out of a branch's reach and
    // still inside the text.
    e.text = (TEXT.0, TEXT.0 + (1 << 30));
    b.funcs.truncate(1);
    b.funcs[0].1 = {
        let mut body = words.to_vec();
        body.resize(32, 0);
        body
    };
    b.relocs.push((0, kind, 0, target));
    let mut bytes = b.bytes();
    let v = run(&b, &e).unwrap();
    let at = Placement { body_va: { let mut x = [0; MAX_FUNCS]; x[0] = body0; x }, end: 32 };
    relocate(&mut bytes, &v, &at)?;
    Ok(bytes[v.funcs[0].body_off..][..32].to_vec())
}

fn w32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

#[test]
fn relocations_bind_to_where_the_pool_put_the_body() {
    // aarch64: `bl .` (imm26 = 0) and `b .` both take the new offset and
    // keep their opcode; the offset is from the body's own address.
    let bl = 0x9400_0000u32.to_le_bytes();
    for (body0, target) in [(POOL.0, F0), (POOL.0 + 0x100, F0 + 0x40), (POOL.0, POOL.0 - 0x2000)] {
        let got = relocated(ISA_AARCH64, R_A64_CALL26, &bl, target, body0).unwrap();
        let w = w32(&got, 0);
        assert_eq!(w & 0xfc00_0000, 0x9400_0000, "still a bl");
        let off = (((w & 0x03ff_ffff) << 6) as i32 >> 4) as i64;
        assert_eq!(body0.wrapping_add(off as u64), target);
    }
    let b = 0x1400_0000u32.to_le_bytes();
    let got = relocated(ISA_AARCH64, R_A64_CALL26, &b, F1, POOL.0).unwrap();
    assert_eq!(jump::a64_b_offset(w32(&got, 0)), Some(F1 as i64 - POOL.0 as i64));
    // Not a branch at the field: the builder lied; refuse.
    assert_eq!(relocated(ISA_AARCH64, R_A64_CALL26, &0xd503_201fu32.to_le_bytes(), F0, POOL.0).unwrap_err(), Reason::Format);
    // Out of reach: 128 MiB or more.
    assert_eq!(relocated(ISA_AARCH64, R_A64_CALL26, &bl, POOL.0 + (1 << 27), POOL.0).unwrap_err(), Reason::Range);

    // riscv64: auipc t1, 0 ; jalr ra, 0(t1) (the `call` expansion).
    let call: Vec<u8> = [0x0000_0317u32, 0x0003_00e7].iter().flat_map(|w| w.to_le_bytes()).collect();
    for (body0, target) in [(POOL.0, F0), (POOL.0 + 0x30, F0 + 0x7fc), (POOL.0, POOL.0 + 0x1000), (POOL.0, F0 - 0x800)] {
        let got = relocated(ISA_RISCV64, R_RV_CALL, &call, target, body0).unwrap();
        let (a, j) = (w32(&got, 0), w32(&got, 4));
        assert_eq!(a & 0xfff, 0x317, "auipc t1 keeps its register");
        assert_eq!(j & 0xfffff, 0x300e7, "jalr ra, t1 keeps its registers");
        let hi = ((a & 0xffff_f000) as i32) as i64;
        let lo = ((j as i32) >> 20) as i64;
        assert_eq!(body0.wrapping_add((hi + lo) as u64), target, "target {target:#x} from {body0:#x}");
    }
    assert_eq!(relocated(ISA_RISCV64, R_RV_CALL, &[0x13, 0, 0, 0, 0x13, 0, 0, 0], F0, POOL.0).unwrap_err(), Reason::Format);

    // x86_64: the field holds target - field address.
    for (body0, target) in [(POOL.0, F0), (POOL.0 + 0x10, F0 + 7)] {
        let got = relocated(ISA_X86_64, R_X86_PC32, &[0xe8, 0, 0, 0, 0], target, body0).unwrap();
        // The relocation is at offset 0 of the body here: S + A - P.
        let rel = i32::from_le_bytes(got[0..4].try_into().unwrap()) as i64;
        assert_eq!(body0.wrapping_add(rel as u64), target);
    }
}

#[test]
fn relocation_of_the_second_function_uses_its_own_address() {
    let (mut b, e) = ok(ISA_AARCH64);
    b.funcs[1].1 = [0x9400_0000u32.to_le_bytes().to_vec(), vec![0; 12]].concat();
    b.relocs.push((1, R_A64_CALL26, 0, F0));
    let mut bytes = b.bytes();
    let v = run(&b, &e).unwrap();
    let at = place(&v, POOL, 0).unwrap();
    relocate(&mut bytes, &v, &at).unwrap();
    assert_ne!(at.body_va[0], at.body_va[1]);
    let off = jump::a64_b_offset(w32(&bytes, v.funcs[1].body_off) & 0x03ff_ffff | 0x1400_0000).unwrap();
    assert_eq!(at.body_va[1].wrapping_add(off as u64), F0);
}

#[test]
fn the_redirect_of_each_isa_reaches_the_body_or_is_refused() {
    // aarch64: one B, +-128 MiB, from a 4-aligned entry.
    let to = POOL.0;
    let Redirect::Word(w) = redirect(ISA_AARCH64, F0, to).unwrap() else { panic!() };
    assert_eq!(w & 0xfc00_0000, 0x1400_0000);
    assert_eq!(jump::a64_b_offset(w), Some(to as i64 - F0 as i64));
    assert_eq!(redirect(ISA_AARCH64, F0 + 2, to).unwrap_err(), Reason::Entry);
    assert_eq!(redirect(ISA_AARCH64, F0, F0 + (1 << 27)).unwrap_err(), Reason::Range);
    assert!(redirect(ISA_AARCH64, F0, F0 + (1 << 27) - 4).is_ok());
    assert!(redirect(ISA_AARCH64, F0, F0.wrapping_sub(1 << 27)).is_ok());
    assert_eq!(redirect(ISA_AARCH64, F0, F0.wrapping_sub((1 << 27) + 4)).unwrap_err(), Reason::Range);

    // riscv64: one JAL x0, +-1 MiB.
    let Redirect::Word(w) = redirect(ISA_RISCV64, F0, F0 + 0xff000).unwrap() else { panic!() };
    assert_eq!(w & 0xfff, 0x06f, "jal x0");
    assert_eq!(jump::rv_jal_offset(w), Some(0xff000));
    let Redirect::Word(w) = redirect(ISA_RISCV64, F0, F0 - 0x1234).unwrap() else { panic!() };
    assert_eq!(jump::rv_jal_offset(w), Some(-0x1234));
    assert_eq!(redirect(ISA_RISCV64, F0, F0 + (1 << 20)).unwrap_err(), Reason::Range);
    assert_eq!(redirect(ISA_RISCV64, F0, F0.wrapping_sub((1 << 20) + 2)).unwrap_err(), Reason::Range);
    assert_eq!(redirect(ISA_RISCV64, F0 + 2, F0 + 0x100).unwrap_err(), Reason::Entry, "2 mod 4: a 32-bit store would tear");

    // x86_64: jmp rel32 from the entry's end.
    let Redirect::Bytes5(b) = redirect(ISA_X86_64, F0, F0 + 0x1005).unwrap() else { panic!() };
    assert_eq!(b, [0xe9, 0x00, 0x10, 0, 0]);
    let Redirect::Bytes5(b) = redirect(ISA_X86_64, F0, F0 - 5).unwrap() else { panic!() };
    assert_eq!(b, [0xe9, 0xf6, 0xff, 0xff, 0xff], "a jump back to just before the entry");
    assert_eq!(redirect(ISA_X86_64, 0x1000, 0x1000 + 5 + (1 << 31)).unwrap_err(), Reason::Range);
    assert!(redirect(ISA_X86_64, 0x1000, 0x1000 + 5 + (1 << 31) - 1).is_ok());
    assert!(redirect(ISA_X86_64, F0 + 1, to).is_ok(), "x86 entries need no alignment");
    assert_eq!(redirect(9, F0, to).unwrap_err(), Reason::Isa);
}

#[test]
fn only_the_compilers_entry_slot_is_overwritten() {
    // aarch64: one nop at the entry.
    let nop = 0xd503_201fu32.to_le_bytes();
    assert!(entry_is_slot(ISA_AARCH64, F0, &nop));
    assert!(!entry_is_slot(ISA_AARCH64, F0, &0xd65f_03c0u32.to_le_bytes()), "ret is not a slot");
    assert!(!entry_is_slot(ISA_AARCH64, F0, &nop[..3]), "too short");
    // riscv64, entry 4-aligned: `nop` or two `c.nop`s.
    assert!(entry_is_slot(ISA_RISCV64, F0, &[0x13, 0, 0, 0]));
    assert!(entry_is_slot(ISA_RISCV64, F0, &[0x01, 0, 0x01, 0]));
    assert!(!entry_is_slot(ISA_RISCV64, F0, &[0x01, 0, 0x82, 0x80]), "c.nop; c.ret");
    assert!(!entry_is_slot(ISA_RISCV64, F0, &redirect_word(ISA_RISCV64)), "an already redirected entry");
    // riscv64, entry 2 mod 4: the redirect goes 2 bytes in, so the slot is a
    // `c.nop` and then the 4 bytes; three `c.nop`s in all.
    let e = F0 + 2;
    assert_eq!((site(ISA_RISCV64, e), entry_span(ISA_RISCV64, e)), (F0 + 4, 6));
    assert!(entry_is_slot(ISA_RISCV64, e, &[0x01, 0, 0x01, 0, 0x01, 0]));
    assert!(entry_is_slot(ISA_RISCV64, e, &[0x01, 0, 0x13, 0, 0, 0]));
    assert!(!entry_is_slot(ISA_RISCV64, e, &[0x01, 0, 0x01, 0, 0x82, 0x80]), "two nops only: the third would be code");
    assert!(!entry_is_slot(ISA_RISCV64, e, &[0x82, 0x80, 0x01, 0, 0x01, 0]), "the lead must be a nop too");
    assert!(!entry_is_slot(ISA_RISCV64, e, &[0x01, 0, 0x01, 0]), "span of the wrong length");
    assert_eq!((site(ISA_RISCV64, F0), entry_span(ISA_RISCV64, F0)), (F0, 4));
    // x86_64: the one five-byte nop.
    assert!(entry_is_slot(ISA_X86_64, F0 + 1, &[0x0f, 0x1f, 0x44, 0, 0]));
    // What LLVM emits for `patchable-function-entry=5`: a count in the displacement.
    assert!(entry_is_slot(ISA_X86_64, F0, &[0x0f, 0x1f, 0x44, 0, 0x08]));
    assert!(!entry_is_slot(ISA_X86_64, F0, &[0x0f, 0x1f, 0x44, 0x01, 0]), "another sib/disp form is another instruction");
    assert!(!entry_is_slot(ISA_X86_64, F0, &[0x90; 5]), "a sled can be entered in the middle");
    assert!(!entry_is_slot(ISA_X86_64, F0, &[0xe9, 0, 0, 0, 0]));
    assert!(!entry_is_slot(ISA_X86_64, F0, &[0x0f, 0x1f, 0x44, 0]), "too short");
    assert!(!entry_is_slot(0, F0, &[0x13, 0, 0, 0]));
    assert_eq!((site(ISA_AARCH64, F0), site(ISA_X86_64, F0 + 1)), (F0, F0 + 1));
    assert_eq!((entry_len(ISA_AARCH64), entry_len(ISA_RISCV64), entry_len(ISA_X86_64)), (4, 4, 5));
    // What an unwind finds once it has written the entry back.
    assert!(is_slot(ISA_RISCV64, &[0x01, 0, 0x01, 0]));
    assert!(!is_slot(ISA_RISCV64, &redirect_word(ISA_RISCV64)));
}

fn redirect_word(isa: u8) -> [u8; 4] {
    let Redirect::Word(w) = redirect(isa, F0, F0 + 0x100).unwrap() else { panic!() };
    w.to_le_bytes()
}

/// Four bytes of text are either the old instruction, the new one, or the
/// breakpoint, as a CPU fetching them would decode; anything else is the
/// middle of an instruction that was never written.
#[derive(Debug, PartialEq)]
enum Fetch {
    Old,
    Trap,
    New,
    Torn,
}

fn fetch(mem: &[u8; 5], old: &[u8; 5], new: &[u8; 5]) -> Fetch {
    if mem[0] == 0xcc {
        Fetch::Trap
    } else if mem == old {
        Fetch::Old
    } else if mem == new {
        Fetch::New
    } else {
        Fetch::Torn
    }
}

#[test]
fn the_int3_sequence_never_shows_a_torn_instruction() {
    let old = [0x0f, 0x1f, 0x44, 0, 0];
    let new = x86_jmp(F0, POOL.0).unwrap();
    let s = x86_steps(&new);
    assert_eq!(s.trap, 0xcc);
    let mut mem = old;
    assert_eq!(fetch(&mem, &old, &new), Fetch::Old);
    mem[0] = s.trap;
    assert_eq!(fetch(&mem, &old, &new), Fetch::Trap);
    mem[1..].copy_from_slice(&s.tail);
    assert_eq!(fetch(&mem, &old, &new), Fetch::Trap, "the tail is in but the head still traps");
    mem[0] = s.head;
    assert_eq!(fetch(&mem, &old, &new), Fetch::New);
    assert_eq!(mem, new);
    // And back: the same three steps to the slot.
    let b = x86_steps(&old);
    mem[0] = b.trap;
    mem[1..].copy_from_slice(&b.tail);
    assert_eq!(fetch(&mem, &new, &old), Fetch::Trap);
    mem[0] = b.head;
    assert_eq!(mem, old);
}

#[test]
fn a_cpu_that_hits_the_trap_continues_as_the_new_instruction() {
    let new = x86_jmp(F0, POOL.0).unwrap();
    assert_eq!(x86_resume(F0, &new), POOL.0, "into the body");
    let slot = [0x0f, 0x1f, 0x44, 0, 0];
    assert_eq!(x86_resume(F0, &slot), F0 + 5, "past the slot when the undo is in progress");
    let back = x86_jmp(F0, F0 - 0x100).unwrap();
    assert_eq!(x86_resume(F0, &back), F0 - 0x100);
}

/// Text is a byte array; a redirect is a store, an unwind is the saved bytes
/// stored back. The entry of each ISA as the compiler leaves it, the redirect
/// where `site` says, and the unwind restores every byte and no other.
#[test]
fn an_unwind_writes_back_exactly_the_saved_entry() {
    for (isa, entry, slot) in [
        (ISA_RISCV64, F0, vec![0x01, 0, 0x01, 0, 0x01, 0]),
        // 2 mod 4: the first c.nop stays, the redirect is the next two.
        (ISA_RISCV64, F0 + 2, vec![0x01, 0, 0x01, 0, 0x01, 0]),
        (ISA_AARCH64, F0, vec![0x1f, 0x20, 0x03, 0xd5]),
        (ISA_X86_64, F0, vec![0x0f, 0x1f, 0x44, 0, 0]),
    ] {
        let mut text = [0xaau8; 24];
        let at = (entry - F0) as usize;
        text[at..at + slot.len()].copy_from_slice(&slot);
        let before = text;
        let span = entry_span(isa, entry);
        assert!(entry_is_slot(isa, entry, &text[at..at + span]), "isa {isa} entry {entry:#x}");

        // What the kernel records: the redirect site and the bytes under it.
        let va = site(isa, entry);
        let n = entry_len(isa);
        // Within a riscv64 JAL's reach of the entry.
        let body = if isa == ISA_RISCV64 { F0 + 0x800 } else { POOL.0 };
        let mut saved = Saved { va, body, len: n as u8, ..Default::default() };
        let off = (va - F0) as usize;
        saved.bytes[..n].copy_from_slice(&text[off..off + n]);

        match redirect(isa, va, body).unwrap() {
            Redirect::Word(w) => text[off..off + 4].copy_from_slice(&w.to_le_bytes()),
            Redirect::Bytes5(b) => text[off..off + 5].copy_from_slice(&b),
        }
        assert_ne!(text, before, "isa {isa}: the redirect changed the entry");
        assert!(!is_slot(isa, &text[off..off + n]));
        if isa == ISA_RISCV64 && entry % 4 != 0 {
            assert_eq!(&text[at..at + 2], &[0x01, 0], "the c.nop before the jal is untouched: it falls into it");
        }
        match saved.restore() {
            Redirect::Word(w) => text[off..off + 4].copy_from_slice(&w.to_le_bytes()),
            Redirect::Bytes5(b) => text[off..off + 5].copy_from_slice(&b),
        }
        assert_eq!(text, before, "isa {isa} entry {entry:#x}: the unwind restored every byte, and none past the entry");
        assert!(is_slot(isa, &text[off..off + n]), "the entry reads as the slot again");
    }
}

#[test]
fn every_reason_has_its_own_code_and_name() {
    use std::collections::HashSet;
    let all = [
        Reason::Applied, Reason::Profile, Reason::Format, Reason::Isa, Reason::NotAdmitted,
        Reason::Signature, Reason::BuildId, Reason::Epoch, Reason::NotNosleep, Reason::NotAllowed, Reason::NoSite,
        Reason::Entry, Reason::Range, Reason::PoolFull, Reason::Poke, Reason::TableFull,
        Reason::NoAlias, Reason::GraceMissed,
    ];
    assert_eq!(all.iter().map(|r| r.code()).collect::<HashSet<_>>().len(), all.len());
    assert_eq!(all.iter().map(|r| r.name()).collect::<HashSet<_>>().len(), all.len());
    for (i, r) in all.iter().enumerate() {
        assert_eq!(r.code(), i as u64, "codes are the record's numbers: they never move");
    }
    let admitted: Vec<_> = all.iter().filter(|r| r.admitted()).collect();
    assert_eq!(admitted, [&Reason::Applied, &Reason::GraceMissed]);
}

#[test]
fn the_limits_and_the_header_sizes_are_the_documented_ones() {
    assert_eq!(SIG_HEADER_LEN, RSIG_FIXED_LEN + 64);
    assert_eq!(RSIG_FIXED_LEN, 4 + 2 + 2 + 32 + 4 + 4);
    assert_eq!(HEADER_LEN, 56);
    assert_eq!((FUNC_LEN, RELOC_LEN), (24, 16));
    assert!(MAX_FUNCS >= 1);
    assert_eq!(Claim::EMPTY.state, SLOT_FREE);
    // The RAM of the patch table, as config/subsys/Kconfig.topology says it: 8 B per
    // function, 8 B per patch.
    assert_eq!(core::mem::size_of::<Claim>(), 8 + 8 * MAX_FUNCS);
}

#[test]
fn a_claim_holds_exactly_the_sites_it_was_given() {
    let mut c = Claim::EMPTY;
    assert!(!c.holds_any(&[F0]), "a free slot holds nothing, whatever it remembers");
    c.sites[0] = F0;
    c.sites[1] = F1;
    c.n = 2;
    c.state = SLOT_BUSY;
    assert!(c.holds_any(&[F1 + 8, F1]), "any one of the sites is enough");
    assert!(!c.holds_any(&[F0 + 4, F1 + 4]));
    c.sites[2] = F1 + 4;
    assert!(!c.holds_any(&[F1 + 4]), "past n is not claimed");
    c.state = SLOT_LIVE;
    assert!(c.holds_any(&[F0]), "a patch in force keeps its entries");
}

/// Text is five bytes; `write` is the text writer with one injected refusal;
/// `resume` is what the `#BP` arm would hand a CPU at each write.
struct Bp {
    mem: [u8; 5],
    /// Refuse the nth write (0-based); `None` never.
    fail_at: Option<usize>,
    /// Refuse every write from `fail_at` on, not only that one.
    keep_failing: bool,
    /// A refused write is stored all the same (a readback miss).
    store_failed: bool,
    writes: usize,
    resume: u64,
    /// `(mem before the write, resume in force)` for every write.
    seen: Vec<([u8; 5], u64)>,
}

impl Bp {
    fn run(old: [u8; 5], new: [u8; 5], fail_at: Option<usize>, keep_failing: bool, store_failed: bool) -> (Bp, BpOutcome<u8>) {
        let mut st = Bp { mem: old, fail_at, keep_failing, store_failed, writes: 0, resume: 0, seen: vec![] };
        let cell = std::cell::RefCell::new(&mut st);
        let out = x86_bp_sequence(
            F0,
            &old,
            &new,
            &mut |r| cell.borrow_mut().resume = r,
            &mut |va, b| {
                let mut s = cell.borrow_mut();
                let n = s.writes;
                s.writes += 1;
                let (m, r) = (s.mem, s.resume);
                s.seen.push((m, r));
                let refused = s.fail_at.is_some_and(|f| n == f || (s.keep_failing && n > f));
                if !refused || s.store_failed {
                    let off = (va - F0) as usize;
                    s.mem[off..off + b.len()].copy_from_slice(b);
                }
                if refused { Err(n as u8) } else { Ok(()) }
            },
        );
        (st, out)
    }
}

#[test]
fn the_int3_sequence_completes_when_every_write_is_taken() {
    let old = [0x0f, 0x1f, 0x44, 0, 0];
    let new = x86_jmp(F0, POOL.0).unwrap();
    let (st, out) = Bp::run(old, new, None, false, false);
    assert_eq!(out, BpOutcome::Done);
    assert_eq!(st.mem, new);
    assert_eq!(st.writes, 3);
    assert_eq!(st.resume, POOL.0, "the trap continues into the body until the end");
    assert!(st.seen.iter().all(|&(m, r)| fetch(&m, &old, &new) != Fetch::Torn && r == POOL.0));
}

/// The must-fix: the head write refused after the tail went in used to put
/// back only the first byte, leaving the new `rel32` under the old head.
#[test]
fn a_refused_head_write_puts_all_five_old_bytes_back() {
    let old = [0x0f, 0x1f, 0x44, 0, 0];
    let new = x86_jmp(F0, POOL.0).unwrap();
    for store_failed in [false, true] {
        // Write 2 is the head; 1 is the tail; 0 the trap.
        for fail in [0, 1, 2] {
            let (st, out) = Bp::run(old, new, Some(fail), false, store_failed);
            assert_eq!(out, BpOutcome::Undone(fail as u8), "fail {fail} stored {store_failed}");
            assert_eq!(st.mem, old, "fail {fail} stored {store_failed}: every byte is the old one again");
            assert_eq!(st.resume, F0 + 5, "the trap resumes as the old instruction from the undo on");
            // Every write after the failing one happens under the old
            // resume, and never on a site that shows a torn instruction.
            for &(m, r) in &st.seen[fail + 1..] {
                assert_eq!(r, F0 + 5, "fail {fail}: undo writes run with the old resume armed");
                assert_ne!(fetch(&m, &old, &new), Fetch::Torn, "fail {fail}: a CPU never sees e9 over old bytes: {m:02x?}");
            }
        }
    }
}

#[test]
fn an_undo_that_is_refused_too_leaves_the_trap_armed_as_the_old_instruction() {
    let old = [0x0f, 0x1f, 0x44, 0, 0];
    let new = x86_jmp(F0, POOL.0).unwrap();
    // The tail write fails and so does everything after it.
    let (st, out) = Bp::run(old, new, Some(1), true, false);
    assert_eq!(out, BpOutcome::Stuck(1));
    assert_eq!(st.mem[0], 0xcc, "the trap is still in");
    assert_eq!(st.resume, F0 + 5, "and a CPU that takes it goes on as the old nop");
}
