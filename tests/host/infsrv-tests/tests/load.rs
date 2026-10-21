// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Loading a bundle: the signature gates everything, only variants of a
//! backend the machine has are kept, and what is kept is what the manifest
//! signed.

use azos_infsrv_tests::*;
use infsrv::load::{Arena, Fate, LoadError};
use azos_ml::bundle::Error;

fn fate_of(r: &infsrv::load::Report, id: u32) -> Fate {
    r.fates.iter().find(|(i, _)| *i == id).unwrap().1
}

/// A bundle under its key loads whatever the file system's read size is, and
/// the variants come out in the publisher's order with their signed rows and
/// the model's reference.
///
/// **Canary.** Fill `slots` in the table's order instead of the fallback order
/// in `load`: `variants()` of a bundle written with `--fallback 3,1,2` comes
/// out 1,2,3 and the order row is red.
#[test]
fn a_signed_bundle_loads_in_the_publishers_order_at_any_read_size() {
    let (file, k) = bundle(
        "order",
        &[gguf(1, 2000, 400, 8192), gguf(2, 800, 120, 4096), gguf(3, 300, 40, 1024)],
        Some("3,1,2"),
    );
    for chunk in [1usize, 7, 64, 512, 100_000] {
        let mut buf = vec![0u8; 64 * 1024];
        let mut ar = Arena::new(&mut buf);
        let r = load_with(&file, k, &mut ar, chunk).unwrap_or_else(|e| panic!("chunk {chunk}: {e:?}"));
        let m = &r.model;
        assert_eq!((m.name(), m.in_bytes, m.out_bytes, m.n), ("policy-v1", IN_BYTES, OUT_BYTES, 3));
        let ids: Vec<u32> = m.variants().iter().map(|s| s.v.id).collect();
        assert_eq!(ids, [3, 1, 2], "chunk {chunk}");
        let cost: Vec<_> = m.variants().iter().map(|s| (s.v.wcet_us, s.v.energy_uj, s.v.mem_bytes)).collect();
        assert_eq!(cost, [(300, 40, 1024), (2000, 400, 8192), (800, 120, 4096)]);
        for s in m.variants() {
            let span = s.span.expect("every GGUF variant is runnable");
            assert_eq!(ar.bytes(span), model().as_slice(), "the blob is what was written");
        }
        assert!(r.fates.iter().take(3).all(|f| f.1 == Fate::Loaded));
        // The reference is the first eight bytes of the manifest digest.
        let mlen = azos_ml::bundle::manifest_len(3);
        let digest = azos_crypto::sha256::sha256(&file[..mlen]);
        assert_eq!(m.model_ref, u64::from_le_bytes(digest[..8].try_into().unwrap()));
    }
}

/// Nothing is kept of a bundle whose manifest does not verify: one flipped bit
/// of the manifest (a cost row), the wrong key, a file that is not a bundle,
/// a file that ends inside the manifest.
///
/// **Canary.** Skip the verifier in `load` (`|_, _| true`): the first three
/// rows load.
#[test]
fn a_bundle_that_does_not_verify_is_refused() {
    let (file, k) = three();
    let mut buf = vec![0u8; 64 * 1024];
    let mut flipped = file.clone();
    flipped[56 + 24] ^= 1; // the first variant's wcet
    assert_eq!(load_with(&flipped, k, &mut Arena::new(&mut buf), 512).err(), Some(LoadError::Bundle(Error::Signature)));
    assert_eq!(load_with(&file, [9; 32], &mut Arena::new(&mut buf), 512).err(), Some(LoadError::Bundle(Error::Signature)));
    let mut other = file.clone();
    other[0] = b'R';
    assert_eq!(load_with(&other, k, &mut Arena::new(&mut buf), 512).err(), Some(LoadError::Bundle(Error::Magic)));
    assert_eq!(load_with(&file[..40], k, &mut Arena::new(&mut buf), 512).err(), Some(LoadError::Truncated));
    assert_eq!(load_with(&file[..100], k, &mut Arena::new(&mut buf), 512).err(), Some(LoadError::Truncated));
}

/// A variant of a backend this machine does not have is skipped (its bytes are
/// read past and dropped, taking no arena), and the GGUF variant after it
/// still loads whichever order the blobs lie in the file.
///
/// **Canary.** Reserve the arena for every variant (drop the backend test in
/// `load`): the arena row (2 KiB, room for the GGUF blob alone) is red.
#[test]
fn only_the_backends_the_machine_has_take_the_arena() {
    let spirv = Var { backend: "spirv", id: 7, blob: vec![0x5A; 5000], wcet_us: 100, energy_uj: 300, mem_bytes: 1 << 20 };
    let vendor = Var { backend: "vendor", id: 8, blob: vec![0xA5; 3000], wcet_us: 50, energy_uj: 10, mem_bytes: 4096 };
    let (file, k) = bundle("backends", &[spirv, vendor, gguf(1, 800, 120, 4096)], Some("8,7,1"));
    let mut buf = vec![0u8; 2048];
    let mut ar = Arena::new(&mut buf);
    let r = load_with(&file, k, &mut ar, 300).unwrap();
    assert_eq!((fate_of(&r, 8), fate_of(&r, 7), fate_of(&r, 1)), (Fate::OtherBackend, Fate::OtherBackend, Fate::Loaded));
    let runnable: Vec<u32> = r.model.variants().iter().filter(|s| s.span.is_some()).map(|s| s.v.id).collect();
    assert_eq!(runnable, [1]);
    assert_eq!(ar.free(), 2048 - model().len());
}

/// A blob is believed only after its digest checks: a flipped byte, a blob the
/// file ends in the middle of, and a blob that is not a model of the manifest's
/// tensor sizes each leave their variant unavailable, and the others load.
///
/// **Canary.** Drop the `check_blob` in `load`: the digest row loads the
/// corrupted blob (and its output is wrong).
#[test]
fn a_blob_that_is_not_what_was_signed_is_not_kept() {
    let (file, k) = three();
    let mlen = azos_ml::bundle::manifest_len(3) + 64;
    let mut buf = vec![0u8; 64 * 1024];

    // The last byte of the third blob.
    let mut bad = file.clone();
    let n = bad.len();
    bad[n - 1] ^= 0xFF;
    let r = load_with(&bad, k, &mut Arena::new(&mut buf), 512).unwrap();
    assert_eq!((fate_of(&r, 1), fate_of(&r, 2), fate_of(&r, 3)), (Fate::Loaded, Fate::Loaded, Fate::BadDigest));
    assert!(r.model.variants().iter().find(|s| s.v.id == 3).unwrap().span.is_none());

    // The file ends inside the last blob.
    let r = load_with(&file[..file.len() - 5], k, &mut Arena::new(&mut buf), 512).unwrap();
    assert_eq!((fate_of(&r, 2), fate_of(&r, 3)), (Fate::Loaded, Fate::Short));
    assert!(file.len() > mlen);

    // Signed, with the right digest, and not a model of the sizes.
    let wrong = mlp_gguf(5, &[0.0; 10], &[0.0; 2], &[0.0; 4], &[0.0; 2]);
    let (file, k) = bundle("wrong", &[Var { blob: wrong, ..gguf(1, 800, 120, 4096) }, gguf(2, 300, 40, 1024)], None);
    let r = load_with(&file, k, &mut Arena::new(&mut buf), 512).unwrap();
    assert_eq!((fate_of(&r, 1), fate_of(&r, 2)), (Fate::BadModel, Fate::Loaded));
    let junk = Var { blob: b"not a gguf file at all".to_vec(), ..gguf(1, 800, 120, 4096) };
    let (file, k) = bundle("junk", &[junk], None);
    assert_eq!(fate_of(&load_with(&file, k, &mut Arena::new(&mut buf), 512).unwrap(), 1), Fate::BadModel);
}

/// The arena is shared by what loads into it: the second blob that does not
/// fit is `NoRoom` and takes nothing, the first is kept.
#[test]
fn an_arena_that_is_full_leaves_the_variant_unavailable() {
    let (file, k) = three();
    let one = model().len();
    let mut buf = vec![0u8; 2 * one + 8];
    let mut ar = Arena::new(&mut buf);
    let r = load_with(&file, k, &mut ar, 512).unwrap();
    assert_eq!((fate_of(&r, 1), fate_of(&r, 2), fate_of(&r, 3)), (Fate::Loaded, Fate::Loaded, Fate::NoRoom));
    // The two that fit are intact.
    for s in r.model.variants().iter().filter_map(|s| s.span) {
        assert_eq!(ar.bytes(s), model().as_slice());
    }
}

/// `Arena::reset` points the arena at other storage and empties it: what was
/// reserved before is free again, and the bytes are the new storage's.
///
/// **Canary.** Leave `used` alone in `reset`: the free space is the old one.
#[test]
fn an_arena_reset_onto_new_storage_is_empty() {
    let (file, k) = three();
    let mut old = vec![0u8; 64 * 1024];
    let mut ar = Arena::new(&mut old);
    load_with(&file, k, &mut ar, 512).unwrap();
    assert!(ar.free() < 64 * 1024);
    let mut fresh = vec![0u8; 32 * 1024];
    ar.reset(&mut fresh);
    assert_eq!(ar.free(), 32 * 1024);
    let r = load_with(&file, k, &mut ar, 512).unwrap();
    assert!(r.fates.iter().take(3).all(|f| f.1 == Fate::Loaded), "it loads into the new storage");
}
