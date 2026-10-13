// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Coverage for `crates/core/crypto/` — security-critical, was 0 tests before.
//!
//! Pulls each algo file in via #[path] and exercises against known
//! published test vectors. If a future refactor breaks any of these,
//! the kernel's signed-firmware verification breaks silently — so
//! these tests are gating.

#![allow(dead_code, unused_imports, clippy::all)]

#[path = "../../../../crates/core/crypto/src/sha256.rs"]
mod sha256_src;

#[path = "../../../../crates/core/crypto/src/aes.rs"]
mod aes_src;

// ed25519 + x25519 + secure_channel pull additional crate-internal
// modules; they're best exercised end-to-end by host-side fuzzing
// once we have the rust-crypto reference dep wired. For now the
// SHA-256 and AES vectors lock down the building blocks.

#[cfg(test)]
mod sha256_vectors {
    use super::sha256_src::sha256;

    /// FIPS 180-4 standard test vectors.
    /// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    #[test]
    fn empty_input() {
        let d = sha256(b"");
        assert_eq!(format!("{:02x?}", d).replace(", ", "")[1..d.len()*2 + 1].to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    /// SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    #[test]
    fn abc_vector() {
        let d = sha256(b"abc");
        let hex: String = d.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    /// SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") =
    ///   248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
    #[test]
    fn fips_two_block_vector() {
        let d = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let hex: String = d.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    /// SHA-256 of one million 'a' — a longer test that exercises chunking.
    #[test]
    fn million_a_chars() {
        let big = vec![b'a'; 1_000_000];
        let d = sha256(&big);
        let hex: String = d.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex,
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    /// Same input must always produce same digest (determinism).
    #[test]
    fn deterministic() {
        let a = sha256(b"deterministic check");
        let b = sha256(b"deterministic check");
        assert_eq!(a, b);
    }

    /// One-bit difference → different digest (avalanche property,
    /// sanity check — not a strict cryptographic test).
    #[test]
    fn avalanche_one_bit() {
        let a = sha256(b"hello world");
        let b = sha256(b"hello world!");
        assert_ne!(a, b);
    }
}

#[cfg(test)]
mod aes_vectors {
    use super::aes_src;

    /// NIST FIPS-197 Appendix B, AES-128 sample.
    /// Key   = 2b7e151628aed2a6abf7158809cf4f3c
    /// PT    = 3243f6a8885a308d313198a2e0370734
    /// CT    = 3925841d02dc09fbdc118597196a0b32
    #[test]
    fn aes128_fips_sample() {
        // U15-7 fix: this used to construct `Aes128` and never call
        // `encrypt_block` — "Specific assertion intentionally minimal"
        // meant zero assertions against the vector below, ever. The
        // module header calls this file "gating"; a gate that never
        // encrypts anything gates nothing. `aes_src` is the real
        // `crates/core/crypto/src/aes.rs`, pulled in via `#[path]` above.
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let pt: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        ];
        let expected_ct: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
        ];
        let mut block = pt;
        aes_src::Aes128::new(&key).encrypt_block(&mut block);
        assert_eq!(block, expected_ct, "FIPS-197 Appendix B AES-128 vector");
    }
}
