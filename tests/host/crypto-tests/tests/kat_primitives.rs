// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Published known answers for every primitive `azos_crypto` exports, through
//! its own API: FIPS 180-4 SHA-256, RFC 4231 HMAC-SHA256, RFC 8439 ChaCha20
//! and Poly1305 (the raw operations sshd's packet layer calls outside the
//! AEAD), FIPS 197 AES-128, RFC 3686 AES-CTR (the swap and zpool layout:
//! `nonce(12) || u32 BE counter from 1`), RFC 7748 X25519 and RFC 8032
//! Ed25519. Every expected value was also reproduced with pyca/cryptography.

mod common;
use azos_crypto::aes::Aes128;
use azos_crypto::chachapoly::{chacha20_xor, poly1305};
use azos_crypto::ed25519::{public_from_seed, sig_verify_message, sign_message};
use azos_crypto::hkdf::hmac_sha256;
use azos_crypto::sha256::{sha256, Sha256};
use azos_crypto::x25519::{x25519, BASEPOINT};
use common::{hex, unhex};

fn arr<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().unwrap()
}

#[test]
fn sha256_fips_180_4() {
    let two_blocks = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    for (msg, want) in [
        (&b"abc"[..], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (&b""[..], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (
            &b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"[..],
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (&two_blocks[..], "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
    ] {
        assert_eq!(hex(&sha256(msg)), want, "{} bytes", msg.len());
    }
}

#[test]
fn sha256_one_million_a_streamed() {
    let mut h = Sha256::new();
    let chunk = [b'a'; 1000];
    for _ in 0..1000 {
        h.update(&chunk);
    }
    assert_eq!(hex(&h.finalize()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

#[test]
fn hmac_sha256_rfc_4231() {
    let big = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
    let cases: [(Vec<u8>, Vec<u8>, &str); 7] = [
        (vec![0x0b; 20], b"Hi There".to_vec(), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec(), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        (vec![0xaa; 20], vec![0xdd; 50], "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
        (unhex("0102030405060708090a0b0c0d0e0f10111213141516171819"), vec![0xcd; 50], "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
        // Case 5 is truncated to 128 bits.
        (vec![0x0c; 20], b"Test With Truncation".to_vec(), "a3b6167473100ee06e0c796c2955552b"),
        (vec![0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        (vec![0xaa; 131], big.as_bytes().to_vec(), "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
    ];
    for (i, (key, msg, want)) in cases.iter().enumerate() {
        let tag = hmac_sha256(key, &[msg]);
        assert_eq!(hex(&tag[..want.len() / 2]), *want, "RFC 4231 case {}", i + 1);
    }
}

#[test]
fn chacha20_encryption_rfc_8439_2_4_2() {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let nonce: [u8; 12] = arr("000000000000004a00000000");
    let mut buf = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
    assert!(chacha20_xor(&key, 1, &nonce, &mut buf));
    assert_eq!(
        hex(&buf),
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
         f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
         07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
         5af90bbf74a35be6b40b8eedf2785e42874d"
            .replace(char::is_whitespace, "")
    );
}

/// RFC 8439 A.3 vectors 5 to 9: the carries and the final reduction mod
/// 2^130 - 5.
#[test]
fn poly1305_rfc_8439_a_3_reduction_edges() {
    let r2 = format!("02{}", "00".repeat(15));
    let r1 = format!("01{}", "00".repeat(15));
    let cases = [
        (format!("{r2}{}", "00".repeat(16)), "ff".repeat(16), format!("03{}", "00".repeat(15))),
        (format!("{r2}{}", "ff".repeat(16)), format!("02{}", "00".repeat(15)), format!("03{}", "00".repeat(15))),
        (
            format!("{r1}{}", "00".repeat(16)),
            format!("{}f0{}11{}", "ff".repeat(16), "ff".repeat(15), "00".repeat(15)),
            format!("05{}", "00".repeat(15)),
        ),
        (
            format!("{r1}{}", "00".repeat(16)),
            format!("{}fb{}{}", "ff".repeat(16), "fe".repeat(15), "01".repeat(16)),
            "00".repeat(16),
        ),
        (format!("{r2}{}", "00".repeat(16)), format!("fd{}", "ff".repeat(15)), format!("fa{}", "ff".repeat(15))),
    ];
    for (i, (key, msg, want)) in cases.iter().enumerate() {
        assert_eq!(hex(&poly1305(&arr(key), &unhex(msg))), *want, "A.3 vector {}", i + 5);
    }
}

#[test]
fn aes128_fips_197_c_1() {
    let mut block: [u8; 16] = arr("00112233445566778899aabbccddeeff");
    Aes128::new(&arr("000102030405060708090a0b0c0d0e0f")).encrypt_block(&mut block);
    assert_eq!(hex(&block), "69c4e0d86a7b0430d8cdb78070b4c55a");
}

/// RFC 3686 §6 vectors 1 to 3 (AES-128): its counter block is
/// `nonce(4) || IV(8) || 00000001`, the 12-byte nonce `ctr_encrypt` takes.
#[test]
fn aes128_ctr_rfc_3686() {
    let cases: [(&str, &str, Vec<u8>, &str); 3] = [
        ("ae6852f8121067cc4bf7a5765577f39e", "000000300000000000000000", b"Single block msg".to_vec(), "e4095d4fb7a7b3792d6175a3261311b8"),
        (
            "7e24067817fae0d743d6ce1f32539163",
            "006cb6dbc0543b59da48d90b",
            (0u8..32).collect(),
            "5104a106168a72d9790d41ee8edad388eb2e1efc46da57c8fce630df9141be28",
        ),
        (
            "7691be035e5020a8ac6e618529f9a0dc",
            "00e0017b27777f3f4a1786f0",
            (0u8..36).collect(),
            "c1cf48a89f2ffdd9cf4652e9efdb72d74540a42bde6d7836d59a5ceaaef3105325b2072f",
        ),
    ];
    for (i, (key, nonce, pt, want)) in cases.iter().enumerate() {
        let aes = Aes128::new(&arr(key));
        let mut buf = pt.clone();
        aes.ctr_encrypt(&arr(nonce), &mut buf);
        assert_eq!(hex(&buf), *want, "RFC 3686 vector {}", i + 1);
        aes.ctr_decrypt(&arr(nonce), &mut buf);
        assert_eq!(&buf, pt);
    }
}

/// RFC 7748 §5.2: `k = X25519(k, u)`, `u = old k`, from k = u = 9.
#[test]
fn x25519_rfc_7748_iterated() {
    let (mut k, mut u) = (BASEPOINT, BASEPOINT);
    for i in 1..=1000 {
        let out = x25519(&k, &u);
        u = k;
        k = out;
        if i == 1 {
            assert_eq!(hex(&k), "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
        }
    }
    assert_eq!(hex(&k), "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
}

/// RFC 8032 §7.1 TEST 3 (two-byte message): public key, signature, verify.
#[test]
fn ed25519_rfc_8032_test_3() {
    let seed: [u8; 32] = arr("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
    let msg = unhex("af82");
    let public = public_from_seed(&seed);
    assert_eq!(hex(&public), "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
    let sig = sign_message(&seed, &msg);
    assert_eq!(
        hex(&sig),
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
         18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
            .replace(char::is_whitespace, "")
    );
    assert!(sig_verify_message(&public, &sig, &msg));
}
