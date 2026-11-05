// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! HKDF-SHA256 against RFC 5869 Appendix A (cases 1 to 3) and against 32-byte
//! roots with the keystore's salt and info lengths, whose answers come from
//! Python's `hmac` / `hashlib`, not from this crate. The resident monitor
//! runs this same source (`crates/core/hyp-mon`), so these are its answers
//! too.

use azos_crypto::hkdf::{extract, hkdf};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()).collect()
}

fn run(salt: &[u8], ikm: &[u8], info: &[u8], l: usize) -> (Vec<u8>, Vec<u8>) {
    let mut okm = vec![0u8; l];
    assert!(hkdf(salt, ikm, info, &mut okm));
    (extract(salt, ikm).to_vec(), okm)
}

#[test]
fn rfc_5869_case_1_basic() {
    let (prk, okm) = run(&(0u8..13).collect::<Vec<_>>(), &[0x0b; 22], &(0xf0u8..0xfa).collect::<Vec<_>>(), 42);
    assert_eq!(prk, hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
    assert_eq!(okm, hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
}

#[test]
fn rfc_5869_case_2_long_inputs() {
    let ikm: Vec<u8> = (0x00..=0x4f).collect();
    let salt: Vec<u8> = (0x60..=0xaf).collect();
    let info: Vec<u8> = (0xb0..=0xff).collect();
    let (prk, okm) = run(&salt, &ikm, &info, 82);
    assert_eq!(prk, hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"));
    assert_eq!(
        okm,
        hex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
    );
}

#[test]
fn rfc_5869_case_3_no_salt_no_info() {
    let (prk, okm) = run(&[], &[0x0b; 22], &[], 42);
    assert_eq!(prk, hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"));
    assert_eq!(okm, hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"));
}

/// What a keystore root asks: a 32-byte root, a 20- or 26-byte salt, an info of
/// 54 or 20 bytes, 32 bytes back; and the longest the monitor accepts.
#[test]
fn a_32_byte_root_with_the_keystores_inputs() {
    let root: Vec<u8> = (0..32).collect();
    let info = |n: u8| (0..n).collect::<Vec<u8>>();
    let one = |salt: &[u8], info: &[u8]| run(salt, &root, info, 32).1;
    assert_eq!(one(b"azos keystore key v1", &info(54)), hex("0592c62e4e194ffc23d6a8ef2ec32d94fdab341bba4dae7916d049f8617ebf4f"));
    assert_eq!(one(b"azos console login user v1", &info(20)), hex("d01f8a896571eefa33b021df96a6195baeb661b1b031c576f4ab1ddd55c33a73"));
    assert_eq!(one(b"", b""), hex("37ad29109f43265287804b674e2653d0a513718907f97fca97c95bded8104bbf"));
    assert_eq!(one(&[0; 64], &[0; 96]), hex("ca379b5130bf576c6f6b8f28ea700263481f3db2a37cebcaf406228e7d12074b"));
}
