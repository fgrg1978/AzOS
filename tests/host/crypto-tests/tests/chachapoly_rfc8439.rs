// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ChaCha20 block (RFC 8439 §2.3.2), Poly1305 (§2.5.2), AEAD (§2.8.2), plus
//! tag/ciphertext digests at the block-boundary lengths computed with an
//! independent implementation (pyca/cryptography) and the failure paths.

mod common;
use azos_crypto::chachapoly::*;
use azos_crypto::sha256::sha256;
use common::{hex, unhex};

#[test]
fn chacha20_block_rfc8439_2_3_2() {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let nonce: [u8; 12] = unhex("000000090000004a00000000").try_into().unwrap();
    assert_eq!(
        hex(&chacha20_block(&key, 1, &nonce)),
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
         d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
    );
}

#[test]
fn poly1305_rfc8439_2_5_2() {
    let key: [u8; 32] =
        unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").try_into().unwrap();
    assert_eq!(
        hex(&poly1305(&key, b"Cryptographic Forum Research Group")),
        "a8061dc1305136c6c22b8baf0c0127a9"
    );
}

const SUNSCREEN: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
const SUN_CT: &str = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
3ff4def08e4b7a9de576d26586cec64b6116";
const SUN_TAG: &str = "1ae10b594f09e26a7e902ecbd0600691";

fn sun_params() -> ([u8; 32], [u8; 12], Vec<u8>) {
    (
        core::array::from_fn(|i| 0x80 + i as u8),
        unhex("070000004041424344454647").try_into().unwrap(),
        unhex("50515253c0c1c2c3c4c5c6c7"),
    )
}

#[test]
fn aead_rfc8439_2_8_2_seal_and_open() {
    let (key, nonce, aad) = sun_params();
    let mut buf = SUNSCREEN.to_vec();
    let tag = seal(&key, &nonce, &aad, &mut buf).unwrap();
    assert_eq!(hex(&buf), SUN_CT);
    assert_eq!(hex(&tag), SUN_TAG);
    assert!(open(&key, &nonce, &aad, &mut buf, &tag));
    assert_eq!(buf, SUNSCREEN);
}

#[test]
fn every_tampered_input_is_rejected_and_leaves_the_buffer_alone() {
    let (key, nonce, aad) = sun_params();
    let ct = unhex(SUN_CT);
    let tag: [u8; 16] = unhex(SUN_TAG).try_into().unwrap();

    // One flipped bit anywhere in the ciphertext.
    for i in 0..ct.len() {
        let mut b = ct.clone();
        b[i] ^= 1 << (i % 8);
        let before = b.clone();
        assert!(!open(&key, &nonce, &aad, &mut b, &tag), "ct bit {i}");
        assert_eq!(b, before, "buffer must not be decrypted on failure");
    }
    // One flipped bit anywhere in the tag.
    for i in 0..16 {
        let mut t = tag;
        t[i] ^= 0x80;
        let mut b = ct.clone();
        assert!(!open(&key, &nonce, &aad, &mut b, &t), "tag byte {i}");
    }
    // AAD, nonce, key, truncated AAD.
    let mut b = ct.clone();
    let mut a2 = aad.clone();
    a2[3] ^= 1;
    assert!(!open(&key, &nonce, &a2, &mut b, &tag));
    assert!(!open(&key, &nonce, &aad[..11], &mut b, &tag));
    let mut n2 = nonce;
    n2[11] ^= 1;
    assert!(!open(&key, &n2, &aad, &mut b, &tag));
    let mut k2 = key;
    k2[0] ^= 1;
    assert!(!open(&key.map(|x| x ^ 1), &nonce, &aad, &mut b, &tag));
    assert!(!open(&k2, &nonce, &aad, &mut b, &tag));
    // Ciphertext truncated by one byte.
    let mut short = ct[..ct.len() - 1].to_vec();
    assert!(!open(&key, &nonce, &aad, &mut short, &tag));
    // And the untouched triple still opens.
    let mut ok = ct.clone();
    assert!(open(&key, &nonce, &aad, &mut ok, &tag));
}

/// (len, tag, sha256(ciphertext)) for key=(i*7+3), nonce=(i*5+1),
/// aad=(i*3) (21 bytes), plaintext=(i*31+7): generated with pyca/cryptography.
const DIFF: &[(usize, &str, &str)] = &[
    (0, "087de0b598fa79e62bc0aa0b2198d050", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (1, "c95910078c60a8c539e8e5ba3f128962", "cdb4ee2aea69cc6a83331bbe96dc2caa9a299d21329efb0336fc02a82e1839a8"),
    (15, "16c124adec533f2fc57d7e8f6201202b", "915b7ad57b1ba29573f45f31e9229d1da7d19ba0046381b58c7d221dd882ac76"),
    (16, "33f0d6651cce50b1ac0e376a70457973", "8f0e8e2722e1f72697d10a583734737d8d397726b04bb31b6991db14bb3ee979"),
    (17, "996c0d7c05a6854bc9eb42454292c312", "0041d3c6b9bfe01598c2e62015045a86b4b11d89a573b6e6666f275252b6c00b"),
    (63, "96c24f0cd83c1ae0029a2ef7a2894097", "dbc5c81973cfd7403e40c649b09ca02e0c8b1f2446e51b6a498163b5c36c8f11"),
    (64, "af80b131366b06f3f7da7920c54dd04b", "96ddfc600c18ca21f70c691c1e11398b19905cab5775a87f2cd7f1c0f903979a"),
    (65, "f83ad11fb65074b300ec4efe81718b69", "04d2c68c420dda75cbec687950de2da8e1c0853be3bb835a41f8fc046ab1209c"),
    (129, "37f61a37a4afc3b03d7b02ebb7dc2763", "11df3c44299682d3a8d0af1e5452a4da1d182014b67dbd3b0cae02a93953c6dc"),
    (1000, "d2f62973857dd6325641f97ce96f8931", "386f4c3b9062fb9c851e5e088e0aa3acad64d5b0fc4342d87229a5fb72277e05"),
];

#[test]
fn block_boundary_lengths_match_an_independent_implementation() {
    let key: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);
    let nonce: [u8; 12] = core::array::from_fn(|i| (i * 5 + 1) as u8);
    let aad: Vec<u8> = (0..21).map(|i| (i * 3) as u8).collect();
    for &(len, tag, digest) in DIFF {
        let pt: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
        let mut buf = pt.clone();
        let t = seal(&key, &nonce, &aad, &mut buf).unwrap();
        assert_eq!(hex(&t), tag, "tag len {len}");
        assert_eq!(hex(&sha256(&buf)), digest, "ciphertext len {len}");
        assert!(open(&key, &nonce, &aad, &mut buf, &t));
        assert_eq!(buf, pt);
    }
}

#[test]
fn keystream_counter_wrap_is_refused() {
    let key = [9u8; 32];
    let nonce = [1u8; 12];
    let mut d = [0xa5u8; 130];
    // 3 blocks needed; counter u32::MAX leaves room for exactly one.
    assert!(!chacha20_xor(&key, u32::MAX, &nonce, &mut d));
    assert!(d.iter().all(|&b| b == 0xa5));
    assert!(chacha20_xor(&key, u32::MAX, &nonce, &mut d[..64]));
    assert!(chacha20_xor(&key, u32::MAX - 2, &nonce, &mut d));
}

#[test]
fn xor_is_its_own_inverse_and_matches_block() {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let nonce = [3u8; 12];
    let mut d = vec![0u8; 100];
    assert!(chacha20_xor(&key, 5, &nonce, &mut d));
    assert_eq!(&d[..64], &chacha20_block(&key, 5, &nonce)[..]);
    assert_eq!(&d[64..], &chacha20_block(&key, 6, &nonce)[..36]);
    assert!(chacha20_xor(&key, 5, &nonce, &mut d));
    assert!(d.iter().all(|&b| b == 0));
}
