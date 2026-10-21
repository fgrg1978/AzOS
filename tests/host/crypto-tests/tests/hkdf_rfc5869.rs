// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! HMAC-SHA256 (RFC 4231 case 6, key longer than a block) and HKDF-SHA256
//! (RFC 5869 appendix A.1 to A.3).

mod common;
use azos_crypto::hkdf::{expand, extract, hkdf, hmac_sha256, MAX_OKM};
use common::{hex, unhex};

#[test]
fn hmac_key_longer_than_block_is_hashed_first() {
    let key = [0xaau8; 131];
    let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
    assert_eq!(
        hex(&hmac_sha256(&key, &[msg])),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

#[test]
fn hmac_parts_equal_concatenation() {
    let k = [7u8; 32];
    let whole = hmac_sha256(&k, &[b"hello world"]);
    assert_eq!(whole, hmac_sha256(&k, &[b"hello", b" ", b"world"]));
    assert_eq!(whole, hmac_sha256(&k, &[b"", b"hello world", b""]));
}

fn case(salt: &[u8], ikm: &[u8], info: &[u8], prk: &str, okm: &str) {
    let want_okm = unhex(okm);
    let got_prk = extract(salt, ikm);
    assert_eq!(hex(&got_prk), prk);
    let mut out = vec![0u8; want_okm.len()];
    assert!(expand(&got_prk, info, &mut out));
    assert_eq!(out, want_okm);
    let mut one = vec![0u8; want_okm.len()];
    assert!(hkdf(salt, ikm, info, &mut one));
    assert_eq!(one, want_okm);
}

#[test]
fn rfc5869_case1_basic() {
    case(
        &(0u8..13).collect::<Vec<_>>(),
        &[0x0b; 22],
        &(0xf0u8..0xfa).collect::<Vec<_>>(),
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
}

#[test]
fn rfc5869_case2_long_inputs() {
    case(
        &(0x60u8..0xb0).collect::<Vec<_>>(),
        &(0x00u8..0x50).collect::<Vec<_>>(),
        &(0xb0u8..=0xff).collect::<Vec<_>>(),
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    );
}

#[test]
fn rfc5869_case3_empty_salt_and_info() {
    case(
        &[],
        &[0x0b; 22],
        &[],
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    );
}

#[test]
fn expand_limits() {
    let prk = [1u8; 32];
    let mut max = vec![0u8; MAX_OKM];
    assert!(expand(&prk, b"x", &mut max));
    let mut over = vec![0xeeu8; MAX_OKM + 1];
    assert!(!expand(&prk, b"x", &mut over));
    assert!(over.iter().all(|&b| b == 0xee), "nothing written on refusal");
    // Prefix property: a shorter request is a prefix of a longer one.
    let mut short = [0u8; 40];
    assert!(expand(&prk, b"x", &mut short));
    assert_eq!(&short[..], &max[..40]);
    assert!(expand(&prk, b"x", &mut []));
}
