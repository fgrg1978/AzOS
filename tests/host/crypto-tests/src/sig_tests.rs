// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_crypto::sig`: the algorithm registry, `RSIG`, `DSIG`, and the
//! trust-anchor slot.
//!
//! The host suite runs with the default Kconfig choice, Ed25519; the sizes of
//! the other two algorithms are pinned so the slots they will need are
//! checked before their verifiers exist.

use azos_crypto::sha256::sha256;
use azos_crypto::sig::{
    dsig_signature, key_array, key_id, manifest_message, Rsig, SigAlg, DSIG_FILE_MAX, DSIG_FIXED_LEN, DSIG_MAGIC,
    KEY_LEN, KEY_LEN_MAX, MANIFEST_MESSAGE_LEN, RSIG_FILE_MAX, RSIG_FIXED_LEN, RSIG_MAGIC, SIG_LEN, SIG_LEN_MAX,
};
use ed25519_dalek::{Signer, SigningKey};

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42u8; 32])
}

fn public() -> [u8; KEY_LEN] {
    signing_key().verifying_key().to_bytes()
}

/// An `RSIG` over `payload`, built the way `tools/sigalg.py` builds it.
fn rsig_file(alg_id: u16, sig_len_field: u16, fw_version: u32, payload: &[u8]) -> Vec<u8> {
    let digest = sha256(payload);
    let msg = manifest_message(SigAlg::Ed25519, fw_version, payload.len() as u32, &digest);
    let mut v = RSIG_MAGIC.to_vec();
    v.extend_from_slice(&alg_id.to_le_bytes());
    v.extend_from_slice(&sig_len_field.to_le_bytes());
    v.extend_from_slice(&key_id(SigAlg::Ed25519.id(), &public()));
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(&fw_version.to_le_bytes());
    v.extend_from_slice(&signing_key().sign(&msg).to_bytes());
    v
}

fn good_rsig(fw: u32, payload: &[u8]) -> Vec<u8> {
    rsig_file(1, 64, fw, payload)
}

fn dsig_file(alg_id: u16, sig_len_field: u16, msg: &[u8]) -> Vec<u8> {
    let mut v = DSIG_MAGIC.to_vec();
    v.extend_from_slice(&alg_id.to_le_bytes());
    v.extend_from_slice(&sig_len_field.to_le_bytes());
    v.extend_from_slice(&signing_key().sign(msg).to_bytes());
    v
}

// ── The registry ────────────────────────────────────────────────────────────

#[test]
fn the_algorithms_have_the_ids_and_sizes_the_formats_are_sized_for() {
    for (id, alg, key, sig) in [(1u16, SigAlg::Ed25519, 32, 64)] {
        assert_eq!(SigAlg::from_id(id), Some(alg));
        assert_eq!(alg.id(), id);
        assert_eq!((alg.key_len(), alg.sig_len()), (key, sig), "{alg:?}");
        // The wire formats allow the post-quantum sizes too (ML-DSA-65: 1952 and 3309;
        // SLH-DSA-SHA2-128s: 32 and 7856).
        assert!(1952 <= KEY_LEN_MAX && 3309 <= SIG_LEN_MAX && 7856 <= SIG_LEN_MAX);
        assert!(key <= KEY_LEN_MAX && sig <= SIG_LEN_MAX, "{alg:?} does not fit the ceilings");
    }
    for id in [0u16, 2, 3, 4, 0x80, 0xFFFF] {
        assert_eq!(SigAlg::from_id(id), None, "{id}");
        assert_eq!(SigAlg::accepted(id), None, "{id}");
    }
}

#[test]
fn a_device_accepts_only_its_configured_algorithm() {
    assert_eq!(SigAlg::CONFIGURED, SigAlg::Ed25519, "the one algorithm there is");
    assert_eq!(SigAlg::accepted(1), Some(SigAlg::Ed25519));
    assert_eq!(SigAlg::accepted(2), None, "ML-DSA-65's reserved id is not accepted");
    assert_eq!(SigAlg::accepted(3), None);
    assert_eq!((KEY_LEN, SIG_LEN), (32, 64), "the slots follow the algorithm");
    assert_eq!(RSIG_FILE_MAX, RSIG_FIXED_LEN + 64);
    assert_eq!(DSIG_FILE_MAX, DSIG_FIXED_LEN + 64);
}

#[test]
fn verify_refuses_a_key_or_signature_of_the_wrong_length() {
    let msg = b"m";
    let sig = signing_key().sign(msg).to_bytes();
    let pk = public();
    assert!(SigAlg::Ed25519.verify(&pk, msg, &sig));
    assert!(!SigAlg::Ed25519.verify(&pk[..31], msg, &sig));
    assert!(!SigAlg::Ed25519.verify(&pk, msg, &sig[..63]));
    assert!(!SigAlg::Ed25519.verify(&pk, msg, &[&sig[..], &[0]].concat()));
}

#[test]
fn key_ids_bind_the_algorithm() {
    let pk = public();
    assert_eq!(key_id(1, &pk), sha256(&[&1u16.to_le_bytes()[..], &pk].concat()));
    assert_ne!(key_id(1, &pk), key_id(2, &pk), "the same bytes under another algorithm are another key");
}

// ── The trust-anchor slot ───────────────────────────────────────────────────

#[test]
fn a_trust_anchor_is_a_key_of_the_algorithm_or_nothing() {
    assert_eq!(key_array(&[]), [0u8; KEY_LEN], "no key file: a key that verifies nothing");
    assert_eq!(key_array(&public()), public());
}

#[test]
#[should_panic(expected = "not a key of the configured algorithm")]
fn a_key_of_another_length_fails_the_build_that_embeds_it() {
    // `key_array` is a const fn: in the build this is a compile error.
    let _ = key_array(&[7u8; 1952]);
}

// ── RSIG ────────────────────────────────────────────────────────────────────

#[test]
fn an_rsig_parses_and_verifies_against_its_payload() {
    let payload = b"kernel image bytes";
    let file = good_rsig(5, payload);
    assert_eq!(file.len(), RSIG_FILE_MAX);
    let r = Rsig::parse(&file).expect("a well-formed RSIG parses");
    assert_eq!((r.alg, r.fw_version, r.payload_size), (SigAlg::Ed25519, 5, payload.len() as u32));
    assert_eq!(r.wire_len(), RSIG_FILE_MAX);
    assert_eq!(r.signature.len(), 64);
    assert!(r.names_key(&public()));
    assert!(r.verify(&public(), &sha256(payload)));
}

#[test]
fn an_rsig_is_bound_to_its_version_size_payload_and_signer() {
    let payload = b"kernel image bytes";
    let file = good_rsig(5, payload);
    let digest = sha256(payload);
    let key = public();

    // The anti-rollback property: a signed v5 relabelled v999 does not verify.
    for (at, what) in [(44usize, "fw_version"), (40, "payload_size")] {
        let mut f = file.clone();
        f[at] ^= 1;
        let r = Rsig::parse(&f).expect("still well formed");
        assert!(!r.verify(&key, &digest), "{what} is signed");
    }
    let r = Rsig::parse(&file).unwrap();
    let mut other = digest;
    other[0] ^= 1;
    assert!(!r.verify(&key, &other), "the payload hash is signed");

    // The signer id is checked before the signature, in its own right.
    let mut f = file.clone();
    f[8] ^= 1;
    let r = Rsig::parse(&f).unwrap();
    assert!(!r.names_key(&key) && !r.verify(&key, &digest));
    let mut wrong_key = key;
    wrong_key[0] ^= 1;
    assert!(!Rsig::parse(&file).unwrap().names_key(&wrong_key));

    // One bit of the signature.
    let mut f = file.clone();
    f[RSIG_FIXED_LEN] ^= 1;
    let r = Rsig::parse(&f).unwrap();
    assert!(r.names_key(&key), "the signer is the trusted one");
    assert!(!r.verify(&key, &digest), "but the signature is not");
}

#[test]
fn the_manifest_message_lays_out_domain_algorithm_version_size_hash() {
    let digest = [0xAAu8; 32];
    let m = manifest_message(SigAlg::Ed25519, 0x0102_0304, 0x0506_0708, &digest);
    assert_eq!(m.len(), MANIFEST_MESSAGE_LEN);
    assert_eq!(&m[..12], b"azos-rsig-v2");
    assert_eq!(&m[12..14], &1u16.to_le_bytes());
    assert_eq!(&m[14..18], &0x0102_0304u32.to_le_bytes());
    assert_eq!(&m[18..22], &0x0506_0708u32.to_le_bytes());
    assert_eq!(&m[22..], &digest[..]);
    // The algorithm id is in the message (bytes 12..14, checked above), so a
    // signature cannot be replayed under another id.
}

#[test]
fn an_rsig_naming_another_algorithm_or_length_is_refused() {
    let payload = b"p";
    assert!(Rsig::parse(&rsig_file(1, 64, 1, payload)).is_some());
    // Unknown, known-but-not-configured, and reserved ids.
    for alg in [0u16, 2, 3, 4, 0x80, 0xFFFF] {
        assert!(Rsig::parse(&rsig_file(alg, 64, 1, payload)).is_none(), "algorithm {alg:#x}");
    }
    // A signature length the algorithm does not have, whatever the bytes.
    for len in [0u16, 1, 63, 65, 3309, 0xFFFF] {
        assert!(Rsig::parse(&rsig_file(1, len, 1, payload)).is_none(), "sig_len {len}");
    }
    // Another algorithm's whole shape: ML-DSA-65's id, its signature length, its
    // signature's bytes. Known, and sized for, but not this device's.
    let mut ml = rsig_file(2, 3309, 1, payload);
    ml.resize(RSIG_FIXED_LEN + 3309, 0);
    assert!(Rsig::parse(&ml).is_none(), "ML-DSA-65 on an Ed25519 device");
    let mut slh = rsig_file(3, 7856, 1, payload);
    slh.resize(RSIG_FIXED_LEN + 7856, 0);
    assert!(Rsig::parse(&slh).is_none(), "SLH-DSA on an Ed25519 device");
    let mut f = good_rsig(1, payload);
    f[0] = b'X';
    assert!(Rsig::parse(&f).is_none(), "magic");
}

#[test]
fn an_rsig_shorter_than_it_declares_is_refused_and_a_longer_one_is_read_to_its_end() {
    let file = good_rsig(1, b"p");
    for n in [0usize, 1, 4, 7, 8, RSIG_FIXED_LEN - 1, RSIG_FIXED_LEN, RSIG_FILE_MAX - 1] {
        assert!(Rsig::parse(&file[..n]).is_none(), "len {n}");
    }
    let mut padded = file.clone();
    padded.extend_from_slice(&[0xEE; 40]);
    let r = Rsig::parse(&padded).expect("trailing bytes (the payload, cluster padding) are not the RSIG's");
    assert_eq!(r.wire_len(), RSIG_FILE_MAX);
}

// ── DSIG ────────────────────────────────────────────────────────────────────

#[test]
fn a_dsig_is_exactly_its_header_and_the_signature_of_the_algorithm() {
    let msg = b"CAPS.TOM bytes";
    let file = dsig_file(1, 64, msg);
    assert_eq!(file.len(), DSIG_FILE_MAX);
    let sig = dsig_signature(&file).expect("a well-formed DSIG");
    assert!(SigAlg::Ed25519.verify(&public(), msg, sig));

    for alg in [0u16, 2, 3, 0xFFFF] {
        assert!(dsig_signature(&dsig_file(alg, 64, msg)).is_none(), "algorithm {alg:#x}");
    }
    for len in [0u16, 63, 65, 0xFFFF] {
        assert!(dsig_signature(&dsig_file(1, len, msg)).is_none(), "sig_len {len}");
    }
    // Another algorithm's whole shape.
    let mut ml = dsig_file(2, 3309, msg);
    ml.resize(DSIG_FIXED_LEN + 3309, 0);
    assert!(dsig_signature(&ml).is_none(), "ML-DSA-65 on an Ed25519 device");
    // Nothing may follow, and nothing may be missing.
    let mut longer = file.clone();
    longer.push(0);
    assert!(dsig_signature(&longer).is_none());
    for n in [0usize, 4, 7, 8, DSIG_FILE_MAX - 1] {
        assert!(dsig_signature(&file[..n]).is_none(), "len {n}");
    }
    // A bare signature (the format before the algorithm id) is not a DSIG.
    assert!(dsig_signature(&file[DSIG_FIXED_LEN..]).is_none());
}

// ── The build tools write what the device reads ─────────────────────────────

/// `tools/sigalg.py` signs the same bytes the Rust side builds (Ed25519 is
/// deterministic), so the two halves of every format are checked against each
/// other, not each against its own idea of the layout. Skipped, and says so,
/// where python3 or its `cryptography` package is missing.
#[test]
fn tools_sigalg_py_writes_byte_for_byte_what_this_side_builds() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let script = "import os, sys, hashlib, tempfile, pathlib\n\
        sys.path.insert(0, os.path.dirname(sys.argv[1] + '/tools/sigalg.py'))\n\
        import sigalg\n\
        d = pathlib.Path(tempfile.mkdtemp()); k = d / 'k'; k.write_bytes(bytes([0x42]) * 32)\n\
        s = sigalg.signer(k)\n\
        print(sigalg.rsig(s, b'kernel image bytes', 5).hex())\n\
        print(sigalg.dsig(s, s.sign(b'CAPS.TOM bytes')).hex())\n";
    let out = match std::process::Command::new("python3").args(["-c", script]).arg(&root).output() {
        Ok(o) if o.status.success() => o,
        _ => {
            eprintln!("skipped: python3 + cryptography not available");
            return;
        }
    };
    let text = String::from_utf8(out.stdout).unwrap();
    let mut lines = text.lines();
    let hex = |s: &str| (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect::<Vec<u8>>();
    assert_eq!(hex(lines.next().unwrap()), good_rsig(5, b"kernel image bytes"), "RSIG");
    assert_eq!(hex(lines.next().unwrap()), dsig_file(1, 64, b"CAPS.TOM bytes"), "DSIG");
}
