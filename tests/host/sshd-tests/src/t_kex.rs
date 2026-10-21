// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Key exchange: the primitives against their standards, the exchange hash and
//! the key derivation against the test client's own, and the negotiation.

use crate::harness::*;
use crate::kex::*;
use crate::wire::*;
use sha2::{Digest, Sha256};

// ── The primitives ──────────────────────────────────────────────────────────

#[test]
fn ed25519_signatures_of_rfc8032() {
    // RFC 8032 section 7.1, tests 1 and 2.
    let t1 = (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    let t2 = (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    );
    for (sk, pk, msg, sig) in [t1, t2] {
        let sk = hex32(sk);
        assert_eq!(azos_crypto::ed25519::public_from_seed(&sk).to_vec(), hex(pk));
        let got = azos_crypto::ed25519::sign_message(&sk, &hex(msg));
        assert_eq!(got.to_vec(), hex(sig));
        let pk: [u8; 32] = hex(pk).try_into().unwrap();
        assert!(azos_crypto::ed25519::sig_verify_message(&pk, &got, &hex(msg)));
        assert!(!azos_crypto::ed25519::sig_verify_message(&pk, &got, b"other"));
    }
    // Against the reference crate, on messages the RFC does not cover.
    use ed25519_dalek::Signer;
    for n in [1usize, 31, 32, 33, 200, 1000] {
        let m: Vec<u8> = (0..n).map(|i| i as u8 ^ 0x5a).collect();
        let r = ed25519_dalek::SigningKey::from_bytes(&other_seed()).sign(&m).to_bytes();
        assert_eq!(azos_crypto::ed25519::sign_message(&other_seed(), &m), r, "message of {n} bytes");
    }
}

#[test]
fn x25519_diffie_hellman_of_rfc7748() {
    // RFC 7748 section 6.1.
    let a_sk = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let a_pk = hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let b_sk = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let b_pk = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let k = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    use azos_crypto::x25519::{x25519, x25519_checked, BASEPOINT};
    assert_eq!(x25519(&a_sk, &BASEPOINT), a_pk);
    assert_eq!(x25519(&b_sk, &BASEPOINT), b_pk);
    assert_eq!(x25519(&a_sk, &b_pk), k);
    assert_eq!(x25519(&b_sk, &a_pk), k);
    // A small-order point gives an all-zero secret: refused (RFC 8731 section 3.1).
    assert_eq!(x25519_checked(&a_sk, &[0u8; 32]), None);
    let mut one = [0u8; 32];
    one[0] = 1;
    assert_eq!(x25519_checked(&a_sk, &one), None);
}

#[test]
fn sha256_agrees_with_the_reference_on_every_length_around_the_blocks() {
    for n in (0..200).chain([255, 256, 1000, 4096]) {
        let m: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();
        let mut h = azos_crypto::sha256::Sha256::new();
        h.update(&m[..n / 2]);
        h.update(&m[n / 2..]);
        assert_eq!(h.finalize()[..], Sha256::digest(&m)[..], "{n} bytes");
    }
}

// ── The exchange ────────────────────────────────────────────────────────────

fn sample_exchange() -> ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32], [u8; 32]) {
    let k = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    let i_c = good_kexinit(true);
    let i_s = server_kexinit(&[9u8; 16]);
    let blob = host_key_blob(&pubkey(&host_seed()));
    let q_c = hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let q_s = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    (k, i_c, i_s, blob, q_c, q_s)
}

#[test]
fn exchange_hash_is_the_rfc8731_hash() {
    let (k, i_c, i_s, blob, q_c, q_s) = sample_exchange();
    let want = exchange_hash_ref(&k, &i_c, &i_s, &blob, &q_c, &q_s);
    let got = crate::kex::exchange_hash(
        &Exchange {
            client_version: CLIENT_VERSION,
            server_version: VERSION,
            client_kexinit: &i_c,
            server_kexinit: &i_s,
            host_key: &blob,
            client_public: &q_c,
            server_public: &q_s,
        },
        &k,
    );
    assert_eq!(got, want);
}

fn exchange_hash_ref(k: &[u8; 32], i_c: &[u8], i_s: &[u8], blob: &[u8], q_c: &[u8; 32], q_s: &[u8; 32]) -> [u8; 32] {
    crate::harness::exchange_hash(&HashInputs { v_c: CLIENT_VERSION, v_s: VERSION, i_c, i_s, k_s: blob, q_c, q_s, k })
}

#[test]
fn the_shared_secret_is_an_mpint_of_the_bytes_as_they_are() {
    // The RFC 7748 secret has its top bit clear in the first byte (0x4a): no
    // sign byte. A secret starting 0x80.. gets one, and one starting 00 00
    // loses them. The hash must follow.
    let (_, i_c, i_s, blob, q_c, q_s) = sample_exchange();
    for first in [[0x80u8, 1], [0x7f, 1], [0, 1], [0, 0x80]] {
        let mut k = [0x11u8; 32];
        k[0] = first[0];
        k[1] = first[1];
        let got = crate::kex::exchange_hash(
            &Exchange {
                client_version: CLIENT_VERSION,
                server_version: VERSION,
                client_kexinit: &i_c,
                server_kexinit: &i_s,
                host_key: &blob,
                client_public: &q_c,
                server_public: &q_s,
            },
            &k,
        );
        assert_eq!(got, exchange_hash_ref(&k, &i_c, &i_s, &blob, &q_c, &q_s), "secret starting {first:02x?}");
    }
}

#[test]
fn keys_are_derived_as_rfc4253_section_7_2() {
    let k = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    let h = Sha256::digest(b"exchange hash").into();
    let sid: [u8; 32] = Sha256::digest(b"session id").into();
    // The first exchange: the session id is H itself.
    let (c2s, s2c) = derive_keys(&k, &h, &h);
    // Seal a packet with each key and compare with ring keyed by the test's
    // own derivation: the same bytes come out only if the 64 key bytes match.
    for (key, letter) in [(&c2s, b'C'), (&s2c, b'D')] {
        let m: [u8; 64] = derive(&k, &h, letter, &h, 64).try_into().unwrap();
        let mut ours = Vec::new();
        crate::packet::seal(key, 5, b"payload", &mut ours).unwrap();
        let sk = ring::aead::chacha20_poly1305_openssh::SealingKey::new(&m);
        let mut buf = Vec::new();
        let pad = 8 - (1 + 7) % 8;
        let pad = if pad < 4 { pad + 8 } else { pad };
        buf.extend_from_slice(&((1 + 7 + pad) as u32).to_be_bytes());
        buf.push(pad as u8);
        buf.extend_from_slice(b"payload");
        buf.resize(buf.len() + pad, 0);
        let mut tag = [0u8; 16];
        sk.seal_in_place(5, &mut buf, &mut tag);
        buf.extend_from_slice(&tag);
        assert_eq!(ours, buf, "letter {}", letter as char);
    }
    // A later exchange keeps the first session id in the hash, and the keys
    // differ from the first exchange's.
    let (c2, s2) = derive_keys(&k, &h, &sid);
    let mut a = Vec::new();
    let mut b = Vec::new();
    crate::packet::seal(&c2s, 0, b"x", &mut a).unwrap();
    crate::packet::seal(&c2, 0, b"x", &mut b).unwrap();
    assert_ne!(a, b);
    let _ = s2;
    // The second 32 bytes extend the first (HASH(K || H || K1)).
    let k64 = derive(&k, &h, b'C', &h, 64);
    let k32 = derive(&k, &h, b'C', &h, 32);
    assert_eq!(k64[..32], k32[..]);
    assert_ne!(k64[..32], k64[32..]);
}

#[test]
fn the_fingerprint_is_openssh_s() {
    let pk = pubkey(&host_seed());
    let mut blob = Vec::new();
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend_from_slice(&pk);
    let digest = Sha256::digest(&blob);
    let mut want = b"SHA256:".to_vec();
    want.extend_from_slice(&base64_nopad(&digest));
    assert_eq!(fingerprint(&pk), want);
    // 32 bytes of hash are 43 base64 characters without padding.
    assert_eq!(want.len(), 7 + 43);
    assert_eq!(host_key_blob(&pk), blob);
    let sig = [3u8; 64];
    let sb = signature_blob(&sig);
    assert_eq!(&sb[..4], 11u32.to_be_bytes());
    assert_eq!(sb.len(), 4 + 11 + 4 + 64);
}

// ── The lists ───────────────────────────────────────────────────────────────

#[test]
fn the_server_kexinit_is_well_formed_and_offers_one_of_each() {
    let p = server_kexinit(&[1u8; 16]);
    let mut r = Reader::new(&p);
    assert_eq!(r.u8(), Some(MSG_KEXINIT));
    r.skip(16).unwrap();
    let lists: Vec<Vec<u8>> = (0..10).map(|_| r.string().unwrap().to_vec()).collect();
    assert!(list_has(&lists[0], "curve25519-sha256"));
    assert!(list_has(&lists[0], "kex-strict-s-v00@openssh.com"));
    assert_eq!(lists[1], b"ssh-ed25519");
    assert_eq!(lists[2], b"chacha20-poly1305@openssh.com");
    assert_eq!(lists[3], b"chacha20-poly1305@openssh.com");
    assert_eq!(lists[6], b"none");
    assert_eq!(lists[7], b"none");
    assert_eq!(r.boolean(), Some(false));
    assert_eq!(r.u32(), Some(0));
    assert_eq!(r.remaining(), 0);
}

fn offer(kex: &[&str], host: &[&str], enc: &[&str], comp: &[&str]) -> Vec<u8> {
    client_kexinit(2, false, kex, host, enc, comp)
}

#[test]
fn negotiation_takes_what_is_common_and_nothing_else() {
    let ok = negotiate(&good_kexinit(false)).unwrap();
    assert!(!ok.strict && !ok.skip_next);
    assert!(negotiate(&good_kexinit(true)).unwrap().strict);
    // The libssh name of the same exchange.
    assert!(negotiate(&offer(&["curve25519-sha256@libssh.org"], &["ssh-ed25519"], &["chacha20-poly1305@openssh.com"], &["none"])).is_ok());
    // A client with many choices, ours among them, in OpenSSH's usual order.
    assert!(negotiate(&offer(
        &["sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "ecdh-sha2-nistp256"],
        &["ecdsa-sha2-nistp256", "ssh-ed25519", "rsa-sha2-512"],
        &["aes128-ctr", "chacha20-poly1305@openssh.com"],
        &["none", "zlib@openssh.com"],
    ))
    .is_ok());
    assert_eq!(negotiate(&offer(&["ecdh-sha2-nistp256"], &["ssh-ed25519"], &["chacha20-poly1305@openssh.com"], &["none"])), Err(KexError::NoKex));
    assert_eq!(negotiate(&offer(&["curve25519-sha256"], &["ssh-rsa", "rsa-sha2-512"], &["chacha20-poly1305@openssh.com"], &["none"])), Err(KexError::NoHostKey));
    assert_eq!(negotiate(&offer(&["curve25519-sha256"], &["ssh-ed25519"], &["aes128-ctr", "aes256-gcm@openssh.com"], &["none"])), Err(KexError::NoCipher));
    assert_eq!(negotiate(&offer(&["curve25519-sha256"], &["ssh-ed25519"], &["chacha20-poly1305@openssh.com"], &["zlib"])), Err(KexError::NoCompression));
}

#[test]
fn a_wrong_first_guess_is_flagged_so_its_packet_is_dropped() {
    let mut p = offer(
        &["ecdh-sha2-nistp256", "curve25519-sha256"],
        &["ssh-ed25519"],
        &["chacha20-poly1305@openssh.com"],
        &["none"],
    );
    // first_kex_packet_follows is the byte before the last u32.
    let n = p.len();
    p[n - 5] = 1;
    assert!(negotiate(&p).unwrap().skip_next, "the guess named ecdh-sha2-nistp256, the server chose curve25519");
    let mut good = good_kexinit(false);
    let n = good.len();
    good[n - 5] = 1;
    assert!(!negotiate(&good).unwrap().skip_next, "a right guess is the packet to read");
}

#[test]
fn malformed_kexinit_is_refused() {
    let good = good_kexinit(false);
    assert_eq!(negotiate(&good[..20]), Err(KexError::Malformed));
    assert_eq!(negotiate(&good[..good.len() - 1]), Err(KexError::Malformed));
    assert_eq!(negotiate(&[MSG_NEWKEYS]), Err(KexError::Malformed));
    assert_eq!(negotiate(&[]), Err(KexError::Malformed));
}
