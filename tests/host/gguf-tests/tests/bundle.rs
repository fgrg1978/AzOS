// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The signed model bundle (`.MBL`, `azos_ml::bundle`): the writer
//! (`tools/image/make_mbl.py`) and the reader agree on the bytes, a bundle opens only
//! under its signature, every signed field is checked after the signature and
//! before use, the blobs are authenticated by the digests in the manifest, and
//! the variant choice walks the signed fallback list against what the machine
//! has, what is free and the time left.
//!
//! The bundles here are made by the real writer under a throwaway key and opened
//! with the real Ed25519 verifier and SHA-256 of `azos_crypto` (the pair the
//! inference service passes), so a layout change on one side only is red.

use azos_crypto::sig::{dsig_signature, SigAlg, DSIG_FILE_MAX};
use azos_crypto::sha256::sha256;
use azos_ml::bundle::{
    backend_bit, manifest_len, signed_len, Error, Manifest, Refusal, Select, BACKEND_GGUF, BACKEND_SPIRV,
    BACKEND_VENDOR, HEADER_BYTES, SIG_BYTES, VARIANT_BYTES,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const TOOL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../tools/image/make_mbl.py");

/// The bytes that stand for the three blobs: distinct, odd lengths, so the
/// 8-byte alignment padding between them is exercised.
const GGUF_BLOB: &[u8] = b"GGUF-blob-0123456789";
const SPIRV_BLOB: &[u8] = b"\x03\x02\x23\x07spirv-module";
const VENDOR_BLOB: &[u8] = b"npu-vendor-blob-xyz-12345";

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Tmp {
        let p = std::env::temp_dir().join(format!("azos-mbl-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn python(args: &[&str]) -> String {
    let out = Command::new("python3").args(args).output().expect("python3 is required (tools/image/make_mbl.py)");
    assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

/// A throwaway key: a fixed seed and the public key Python derives from it.
fn key(dir: &Path) -> (PathBuf, [u8; 32]) {
    let (priv_p, pub_p) = (dir.join("k.priv"), dir.join("k.pub"));
    std::fs::write(&priv_p, [7u8; 32]).unwrap();
    python(&[
        "-c",
        "import sys\nfrom cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K\n\
         from cryptography.hazmat.primitives import serialization as s\n\
         k = K.from_private_bytes(open(sys.argv[1], 'rb').read())\n\
         open(sys.argv[2], 'wb').write(k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw))",
        priv_p.to_str().unwrap(),
        pub_p.to_str().unwrap(),
    ]);
    (priv_p, std::fs::read(pub_p).unwrap().try_into().unwrap())
}

/// Write a bundle with the real writer. `variants` are `BACKEND:ID:WCET:ENERGY:MEM`
/// and the blob of backend `b` is the constant above.
fn make(tag: &str, variants: &[&str], fallback: Option<&str>) -> (Vec<u8>, [u8; 32], String) {
    let d = Tmp::new(tag);
    let (priv_p, pub_k) = key(&d.0);
    let mut args: Vec<String> =
        vec![TOOL.into(), "--name".into(), "policy-v1".into(), "--in-bytes".into(), "64".into(), "--out-bytes".into(), "32".into()];
    for v in variants {
        let f: Vec<&str> = v.split(':').collect();
        let (blob, file) = match f[0] {
            "gguf" => (GGUF_BLOB, "a.gguf"),
            "spirv" => (SPIRV_BLOB, "b.spv"),
            _ => (VENDOR_BLOB, "c.npu"),
        };
        std::fs::write(d.0.join(file), blob).unwrap();
        args.push("--variant".into());
        args.push(format!("{}:{}:{}:{}:{}:{}", f[0], f[1], d.0.join(file).display(), f[2], f[3], f[4]));
    }
    if let Some(fb) = fallback {
        args.push("--fallback".into());
        args.push(fb.into());
    }
    let out = d.0.join("M.MBL");
    args.extend(["--priv".into(), priv_p.display().to_string(), "--out".into(), out.display().to_string()]);
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    python(&a);
    let check = python(&[TOOL, "--check", out.to_str().unwrap(), "--pub", d.0.join("k.pub").to_str().unwrap()]);
    (std::fs::read(out).unwrap(), pub_k, check)
}

/// The shared three-variant bundle: the NPU first, then the GPU, then the CPU.
///   id 3 vendor  wcet   90 us  energy   15 uJ  mem 65536
///   id 2 spirv   wcet  200 us  energy  300 uJ  mem 1048576
///   id 1 gguf    wcet  800 us  energy  120 uJ  mem 4096
fn three() -> &'static (Vec<u8>, [u8; 32], String) {
    static B: OnceLock<(Vec<u8>, [u8; 32], String)> = OnceLock::new();
    B.get_or_init(|| {
        make("three", &["gguf:1:800:120:4096", "spirv:2:200:300:1048576", "vendor:3:90:15:65536"], Some("3,2,1"))
    })
}

/// The caller's check: the `DSIG` the bundle carries, the device's algorithm.
fn check_dsig(pub_k: &[u8; 32], m: &[u8], s: &[u8; SIG_BYTES]) -> bool {
    dsig_signature(s).is_some_and(|sig| SigAlg::CONFIGURED.verify(pub_k, m, sig))
}

fn verifier(pub_k: [u8; 32]) -> impl Fn(&[u8], &[u8; SIG_BYTES]) -> bool {
    move |m, s| check_dsig(&pub_k, m, s)
}

/// The reader has no dependencies, so its signature size is a literal: it is
/// the device's `DSIG`.
#[test]
fn the_signature_slot_is_a_dsig_of_the_device_algorithm() {
    assert_eq!(SIG_BYTES, DSIG_FILE_MAX);
    let (file, pub_k, _) = three();
    let at = manifest_len(3);
    let mut s: [u8; SIG_BYTES] = file[at..at + SIG_BYTES].try_into().unwrap();
    assert!(check_dsig(pub_k, &file[..at], &s));
    // Another algorithm's id, a bare signature without the container: refused
    // before the signature is looked at.
    s[4] = 2;
    assert!(!check_dsig(pub_k, &file[..at], &s));
    let mut bare = [0u8; SIG_BYTES];
    bare[..64].copy_from_slice(&file[at + 8..at + SIG_BYTES]);
    assert!(!check_dsig(pub_k, &file[..at], &bare));
}

fn all() -> Select {
    Select {
        backends: backend_bit(BACKEND_GGUF) | backend_bit(BACKEND_SPIRV) | backend_bit(BACKEND_VENDOR),
        mem_free: u32::MAX,
        budget_us: None,
        low_energy: false,
    }
}

/// The writer's bytes are the reader's fields: name, tensor sizes, every cost
/// row, the fallback order, the blobs at 8-aligned offsets, and the model
/// reference the writer prints is the one the reader derives from the digest.
///
/// **Canary.** Move one field in `make_mbl.py` (the energy and memory words
/// swapped) or in `bundle.rs` (`V_MEM` = 28): the row for that field is red.
#[test]
fn the_writer_and_the_reader_agree_on_every_field() {
    let (file, pub_k, printed) = three();
    let m = Manifest::open(file, verifier(*pub_k)).expect("a bundle under its own key opens");
    assert_eq!((m.name(), m.in_bytes(), m.out_bytes(), m.n_variants()), ("policy-v1", 64, 32, 3));
    // Table order is the order of --variant ...
    let t: Vec<_> = (0..3).map(|i| m.variant(i)).collect();
    assert_eq!((t[0].backend, t[0].id, t[0].wcet_us, t[0].energy_uj, t[0].mem_bytes), (BACKEND_GGUF, 1, 800, 120, 4096));
    assert_eq!((t[1].backend, t[1].id, t[1].wcet_us, t[1].energy_uj, t[1].mem_bytes), (BACKEND_SPIRV, 2, 200, 300, 1_048_576));
    assert_eq!((t[2].backend, t[2].id, t[2].wcet_us, t[2].energy_uj, t[2].mem_bytes), (BACKEND_VENDOR, 3, 90, 15, 65_536));
    // ... the fallback list is the publisher's.
    let order: Vec<u32> = m.fallback().map(|v| v.id).collect();
    assert_eq!(order, [3, 2, 1]);
    // Blobs: after the signature, 8-aligned, each the bytes and digest signed.
    let first = (manifest_len(3) + SIG_BYTES) as u64;
    for (v, blob) in t.iter().zip([GGUF_BLOB, SPIRV_BLOB, VENDOR_BLOB]) {
        assert!(v.blob_off >= first && v.blob_off % 8 == 0, "{v:?}");
        let bytes = &file[v.blob_off as usize..(v.blob_off + v.blob_len) as usize];
        assert_eq!(v.check_blob(bytes, |b| sha256(b)), Ok(blob));
    }
    // The reference a client names the model by.
    let digest = m.digest(|b| sha256(b));
    let want = u64::from_le_bytes(digest[..8].try_into().unwrap());
    assert!(printed.contains(&format!("model_ref 0x{want:016x}")), "{printed}");
}

/// Nothing past the length is believed before the signature verifies: the
/// verifier is called once, with exactly the manifest's bytes; a refusal is
/// `Signature` whatever else the bytes say; a file that is not a bundle never
/// reaches the verifier.
///
/// **Canary.** Call `validate` before `verify` in `Manifest::open`: the
/// garbage-after-magic row returns `Layout` instead of `Signature`, red.
#[test]
fn the_signature_is_checked_first_and_over_the_manifest_bytes() {
    let (file, pub_k, _) = three();
    let mlen = manifest_len(3);
    let calls = std::cell::RefCell::new(Vec::new());
    let ok = Manifest::open(file, |m, s| {
        calls.borrow_mut().push((m.to_vec(), *s));
        check_dsig(pub_k, m, s)
    });
    assert!(ok.is_ok());
    let c = calls.borrow();
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].0, file[..mlen], "the signed bytes are the manifest and only it");
    assert_eq!(c[0].1[..], file[mlen..mlen + SIG_BYTES]);
    assert_eq!(signed_len(&file[..HEADER_BYTES]), Ok(mlen + SIG_BYTES), "a small board reads the header first");

    // Magic and a plausible length, then garbage the layout would refuse: the
    // signature is what says no.
    let mut junk = file[..mlen + SIG_BYTES].to_vec();
    junk[8] = 0xAA;
    junk[7 * 8 + 30] ^= 0xFF;
    assert_eq!(Manifest::open(&junk, verifier(*pub_k)).unwrap_err(), Error::Signature);
    assert_eq!(Manifest::open(&junk, |_, _| false).unwrap_err(), Error::Signature);

    // Not a bundle at all: no verifier call.
    let mut seen = false;
    let mut other = file.clone();
    other[0] = b'G'; // GGUF-ish
    assert_eq!(Manifest::open(&other, |_, _| { seen = true; true }).unwrap_err(), Error::Magic);
    assert!(!seen, "the verifier never sees a file that is not a bundle");
    assert_eq!(Manifest::open(&file[..20], |_, _| true).unwrap_err(), Error::Short);
    assert_eq!(Manifest::open(&file[..mlen + 10], |_, _| true).unwrap_err(), Error::Short);
}

/// Every signed number is under the signature: one flipped bit in the cost
/// table, the fallback list or a digest is `Signature`, and a flipped bit in a
/// blob is `Blob` (the manifest signs its digest).
///
/// **Canary.** Verify over `bytes[..mlen - 1]`: the last digest byte's flip
/// passes the signature, red.
#[test]
fn a_flipped_bit_in_the_manifest_or_a_blob_is_refused() {
    let (file, pub_k, _) = three();
    let mlen = manifest_len(3);
    let v = verifier(*pub_k);
    for pos in [0usize, 4, 12, 24, 48, 56 + 24, 56 + 28, 56 + 32, 56 + 40, mlen - 1] {
        let mut f = file.clone();
        f[pos] ^= 1;
        let e = Manifest::open(&f, &v).unwrap_err();
        assert!(matches!(e, Error::Signature | Error::Magic), "byte {pos}: {e:?}");
    }
    let m = Manifest::open(file, &v).unwrap();
    let var = m.variant(0);
    let mut blob = file[var.blob_off as usize..(var.blob_off + var.blob_len) as usize].to_vec();
    blob[3] ^= 1;
    assert_eq!(var.check_blob(&blob, |b| sha256(b)), Err(Error::Blob));
    assert_eq!(var.check_blob(&blob[..blob.len() - 1], |b| sha256(b)), Err(Error::Blob), "short");
}

/// A manifest that is signed but is not the one shape this reader accepts is
/// `Layout` (or `Version`), field by field. The signature is stubbed true so
/// the bytes can be edited.
///
/// **Canary.** Drop the permutation check of the fallback list, or the overlap
/// check of the blobs: that row is red.
#[test]
fn a_signed_manifest_of_the_wrong_shape_is_refused_field_by_field() {
    let (file, _, _) = three();
    let mlen = manifest_len(3);
    let base = file[..mlen + SIG_BYTES].to_vec();
    assert!(Manifest::open(&base, |_, _| true).is_ok());
    let var = |i: usize, off: usize| HEADER_BYTES + i * VARIANT_BYTES + off;
    let set32 = |f: &mut Vec<u8>, at: usize, v: u32| f[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let set64 = |f: &mut Vec<u8>, at: usize, v: u64| f[at..at + 8].copy_from_slice(&v.to_le_bytes());
    let blob0 = u64::from_le_bytes(base[var(0, 8)..var(0, 8) + 8].try_into().unwrap());
    let len0 = u64::from_le_bytes(base[var(0, 16)..var(0, 16) + 8].try_into().unwrap());

    let rows: Vec<(&str, Box<dyn Fn(&mut Vec<u8>)>, Error)> = vec![
        ("version 2", Box::new(move |f| f[4] = 2), Error::Version),
        ("count says 2, length says 3", Box::new(move |f| f[6] = 2), Error::Layout),
        ("reserved header word", Box::new(move |f| f[8] = 1), Error::Layout),
        ("zero input tensor", Box::new(move |f| f[12..16].fill(0)), Error::Layout),
        ("zero output tensor", Box::new(move |f| f[16..20].fill(0)), Error::Layout),
        ("name with a space", Box::new(move |f| f[24 + 2] = b' '), Error::Layout),
        ("name with a byte after the NUL", Box::new(move |f| f[24 + 12] = b'x'), Error::Layout),
        ("empty name", Box::new(move |f| f[24] = 0), Error::Layout),
        ("fallback repeats a variant", Box::new(move |f| f[48 + 1] = f[48]), Error::Layout),
        ("fallback names variant 3 of 3", Box::new(move |f| f[48] = 3), Error::Layout),
        ("fallback does not end in 0xFF", Box::new(move |f| f[48 + 3] = 0), Error::Layout),
        ("backend 0", Box::new(move |f| set32(f, var(1, 0), 0)), Error::Layout),
        ("backend 4", Box::new(move |f| set32(f, var(1, 0), 4)), Error::Layout),
        ("duplicate variant id", Box::new(move |f| set32(f, var(1, 4), 1)), Error::Layout),
        ("reserved variant word", Box::new(move |f| set32(f, var(2, 36), 1)), Error::Layout),
        ("a worst case of 0", Box::new(move |f| set32(f, var(0, 24), 0)), Error::Layout),
        ("an empty blob", Box::new(move |f| set64(f, var(0, 16), 0)), Error::Layout),
        ("misaligned blob", Box::new(move |f| set64(f, var(0, 8), blob0 + 1)), Error::Layout),
        ("blob inside the manifest", Box::new(move |f| set64(f, var(0, 8), 0)), Error::Layout),
        ("blob offset wraps", Box::new(move |f| { set64(f, var(0, 8), u64::MAX - 7); set64(f, var(0, 16), 64) }), Error::Layout),
        ("blob overlaps the next", Box::new(move |f| set64(f, var(1, 8), blob0 + (len0 - 1) / 8 * 8)), Error::Layout),
    ];
    for (what, edit, want) in rows {
        let mut f = base.clone();
        edit(&mut f);
        assert_eq!(Manifest::open(&f, |_, _| true).unwrap_err(), want, "{what}");
    }

    // The length is bounded before anything else: no records, nine records,
    // a length that is not a whole number of records.
    for bad in [HEADER_BYTES as u32, (HEADER_BYTES + 9 * VARIANT_BYTES) as u32, (HEADER_BYTES + VARIANT_BYTES + 1) as u32, u32::MAX] {
        let mut f = base.clone();
        set32(&mut f, 20, bad);
        assert_eq!(signed_len(&f), Err(Error::Layout), "length {bad}");
        assert_eq!(Manifest::open(&f, |_, _| true).unwrap_err(), Error::Layout, "length {bad}");
    }
}

/// The variant choice: the first of the publisher's fallback list that has its
/// backend, memory and time; the reason is the furthest any variant got.
///
/// **Canary.** Walk the table order instead of the fallback list: the first
/// row (NPU first by the list, CPU first in the table) is red.
#[test]
fn the_choice_walks_the_signed_fallback_list() {
    let (file, pub_k, _) = three();
    let m = Manifest::open(file, verifier(*pub_k)).unwrap();
    let pick = |s: Select| m.select(&s).map(|v| v.id);
    assert_eq!(pick(all()), Ok(3), "the publisher's first choice");
    let no_npu = Select { backends: all().backends & !backend_bit(BACKEND_VENDOR), ..all() };
    assert_eq!(pick(no_npu), Ok(2), "next in the list");
    let cpu = Select { backends: backend_bit(BACKEND_GGUF), ..all() };
    assert_eq!(pick(cpu), Ok(1));
    // Time: the NPU's 90 us fits 100 us, nothing fits 50 us, the CPU's 800 us
    // fits 1000 us only when it is all that is present.
    assert_eq!(pick(Select { budget_us: Some(100), ..all() }), Ok(3));
    assert_eq!(pick(Select { budget_us: Some(90), ..all() }), Ok(3), "equal fits");
    assert_eq!(pick(Select { budget_us: Some(89), ..all() }), Err(Refusal::TooSlow));
    assert_eq!(pick(Select { budget_us: Some(150), backends: no_npu.backends, ..all() }), Err(Refusal::TooSlow), "GPU 200 us, CPU 800 us");
    assert_eq!(pick(Select { budget_us: Some(1000), ..cpu }), Ok(1));
    assert_eq!(pick(Select { budget_us: Some(0), ..all() }), Err(Refusal::TooSlow), "no time left is no time");
    // Memory: only the CPU's 4096 B fit 5000 B free; 1000 B free fits none.
    assert_eq!(pick(Select { mem_free: 5000, ..all() }), Ok(1), "falls past the two that do not fit");
    assert_eq!(pick(Select { mem_free: 1000, ..all() }), Err(Refusal::NoMemory));
    // The reason is the furthest any variant got: the CPU has memory but not
    // time while the others have time but not memory.
    assert_eq!(pick(Select { mem_free: 5000, budget_us: Some(500), ..all() }), Err(Refusal::TooSlow));
    assert_eq!(pick(Select { backends: 0, ..all() }), Err(Refusal::NoBackend));
    assert_eq!(pick(Select { backends: backend_bit(4), ..all() }), Err(Refusal::NoBackend), "a backend nobody defined");
}

/// With a low-energy hint the choice is the cheapest of those that fit, and a
/// tie goes to the earlier in the list; without it the list decides.
///
/// **Canary.** Use `<=` in the comparison: the tie row is red; ignore `fits`
/// before comparing energy: the budget row is red.
#[test]
fn the_energy_hint_picks_the_cheapest_that_fits_and_ties_keep_the_list() {
    let (file, pub_k, _) = make(
        "energy",
        &["gguf:1:800:120:4096", "spirv:2:200:300:1000", "vendor:3:90:300:1000"],
        Some("2,3,1"),
    );
    let m = Manifest::open(&file, verifier(pub_k)).unwrap();
    let id = |s: Select| m.select(&s).map(|v| v.id);
    assert_eq!(id(all()), Ok(2), "the list");
    assert_eq!(id(Select { low_energy: true, ..all() }), Ok(1), "120 uJ beats 300");
    // The CPU cannot make 500 us, so the cheapest that fits is the earlier of
    // the two 300 uJ rows, the GPU.
    assert_eq!(id(Select { low_energy: true, budget_us: Some(500), ..all() }), Ok(2), "tie keeps the list order");
    assert_eq!(id(Select { low_energy: true, budget_us: Some(50), ..all() }), Err(Refusal::TooSlow));
    // Only the vendor blob present: the hint cannot invent a choice.
    let npu = Select { backends: backend_bit(BACKEND_VENDOR), low_energy: true, ..all() };
    assert_eq!(id(npu), Ok(3));
}

/// A one-variant bundle is the smallest legal one; eight is the largest.
///
/// **Canary.** Lower `MAX_VARIANTS` in the reader to 7: the eight-variant row is
/// red.
#[test]
fn one_variant_is_a_bundle_and_so_are_eight() {
    let (f1, k1, _) = make("one", &["gguf:9:10:1:1"], None);
    let m = Manifest::open(&f1, verifier(k1)).unwrap();
    assert_eq!(m.n_variants(), 1);
    assert_eq!(m.fallback().map(|v| v.id).collect::<Vec<_>>(), [9]);
    assert_eq!(m.select(&all()).map(|v| v.id), Ok(9));

    let specs: Vec<String> = (1..=8).map(|i| format!("gguf:{i}:{}:{}:1", 100 + i, 10 * i)).collect();
    let r: Vec<&str> = specs.iter().map(String::as_str).collect();
    let (f8, k8, _) = make("eight", &r, Some("8,7,6,5,4,3,2,1"));
    let m = Manifest::open(&f8, verifier(k8)).unwrap();
    assert_eq!(m.n_variants(), 8);
    assert_eq!(m.fallback().map(|v| v.id).collect::<Vec<_>>(), [8, 7, 6, 5, 4, 3, 2, 1]);
}
