// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Every portable SHA-256 block path against FIPS 180-4 vectors and the
//! padding boundaries (wave 14): the generic path, then the riscv64 generic
//! arithmetic (`blocks_dup64`: 64-bit duplicate sigmas, mask-shift word
//! loads) and the Zbb/Zknh word loads (`blocks_wide`) installed through
//! `select_hook`. One test, in its own binary: the selection is
//! process-global.

use azos_crypto::sha256::{backend, blocks_dup64, blocks_wide, select_hook, sha256, Sha256};

fn hex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// `(i * 31 + 7) mod 256`, the first n bytes; digests from Python hashlib.
const PATTERN: &[(usize, &str)] = &[
    (55, "8aa994584139d128848eeebc4e815639ba5ab6e6e39574195a63ac4f14f7c43b"),
    (56, "ad574708f75c044c9b85de64cb568ee7711ff4f36448c6242f053ba8f6cc2b63"),
    (57, "5b46e502092be01b1100193e089fdda95638c12e19a1d24f308eb2c3d3ae849d"),
    (63, "280ed3e8ff1df845b2e7dfe6ac6cee817bef20e783cc65abc41b818b4d2fe076"),
    (64, "c6ab9724ade5b6a7a1edfffb12f3aa9181351355af8fd08c919952ad211339dd"),
    (65, "788367c73c7ddf4c53f65e68cc0d943e6227ab55b0e78ba63ace822b1c6301c0"),
    (119, "3d610547d68216dedf7435a4fb6260353911f6b3fd3f18805ddb8be285d726fe"),
    (120, "1f80156a804cb7862ad113e8200e9d74499723e7c7854d5f48776d3148e09656"),
    (121, "614571410beab3df68d50132a341d338575653da8374c630441bbe380b9b3136"),
    (127, "192409cd280e14b743642ad1343fbd3e82d9305de72c078117745a679210cc3d"),
    (128, "cc548ca2dec1f6fe4f58b2e27aa9c7521607df1130d140b55a4dad0665302356"),
    (129, "81e89a7b2911aaa7795f9e3d4910cb47d6cd2b00d83b8399481527261a1a7519"),
    (1000, "5097e7d587352f5097062ae679f37bda5802d9f875aba14c8cb4d1a188ada179"),
];

fn vectors(path: &str) {
    let fips: &[(&[u8], &str)] = &[
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        ),
    ];
    for (m, want) in fips {
        assert_eq!(sha256(m), hex(want), "{path}: FIPS vector of {} bytes", m.len());
    }
    let mut h = Sha256::new();
    let a = [b'a'; 1000];
    for _ in 0..1000 {
        h.update(&a);
    }
    assert_eq!(h.finalize(), hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
        "{path}: one million 'a'");

    // `u64` storage: offsets 0, 4 and 1 are 8-aligned, 4-aligned and odd,
    // so every branch of the word-load alignment test runs.
    let mut store = vec![0u64; 1100 / 8 + 2];
    // SAFETY: a u64 buffer viewed as its bytes.
    let bytes = unsafe { core::slice::from_raw_parts_mut(store.as_mut_ptr() as *mut u8, store.len() * 8) };
    for off in [0usize, 4, 1] {
        for (i, b) in bytes[off..off + 1100].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        for &(n, want) in PATTERN {
            let m = &bytes[off..off + n];
            assert_eq!(sha256(m), hex(want), "{path}: {n} bytes at offset {off}");
            // Streamed in uneven pieces: partial-buffer fills, a whole block
            // straight from the input, and a tail.
            let mut h = Sha256::new();
            let mut rest = m;
            for step in [1usize, 7, 64, 63, 65, 128].iter().cycle() {
                if rest.is_empty() {
                    break;
                }
                let k = (*step).min(rest.len());
                h.update(&rest[..k]);
                rest = &rest[k..];
            }
            assert_eq!(h.finalize(), hex(want), "{path}: {n} bytes streamed at offset {off}");
        }
    }
}

#[test]
fn every_portable_block_path_matches_fips_180_4() {
    assert_eq!(backend(), "generic");
    vectors("generic");
    assert!(select_hook(blocks_dup64), "the dup64 path failed its own self-test");
    vectors("dup64");
    assert!(select_hook(blocks_wide), "the wide-load path failed its own self-test");
    vectors("wide");
}
