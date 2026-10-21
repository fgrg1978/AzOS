// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The key of a sealed `[volume.NAME]` row (`kernel/src/boot/azvol_key.rs`),
//! compiled unchanged: one key per row and per board, none for a board with no
//! seed, and a key that really seals a volume (the engine's own round trip is
//! in `fs-tests/src/azvol_mount.rs`).
//!
//! DISCRIMINATING: the row name in the salt (two rows would share a key), the
//! seed in the input (two boards would), the all-zero refusal (an unprovisioned
//! board would seal under a key everyone can compute).
//!
//! Wired into the suite by `mod volume_key;` in `src/lib.rs`.

#[allow(dead_code)]
#[path = "../../../../kernel/src/boot/azvol_key.rs"]
mod azvol_key;

const SEED: [u8; 32] = [0x11; 32];

#[test]
fn a_row_has_its_own_key_on_each_board() {
    let a = azvol_key::derive(&SEED, b"data").expect("a key");
    assert_eq!(azvol_key::derive(&SEED, b"data"), Some(a), "deterministic: the same key at every boot");
    assert_ne!(Some(a), azvol_key::derive(&SEED, b"logs"), "another row, another key");
    assert_ne!(Some(a), azvol_key::derive(&[0x12; 32], b"data"), "another board, another key");
    assert_ne!(a, SEED, "the seed itself is never the key");
    assert_ne!(a, [0u8; 32]);
}

#[test]
fn a_board_with_no_seed_has_no_key() {
    assert_eq!(azvol_key::derive(&[0u8; 32], b"data"), None);
    // One set bit is a seed.
    let mut s = [0u8; 32];
    s[31] = 1;
    assert!(azvol_key::derive(&s, b"data").is_some());
}

#[test]
fn the_label_separates_this_use_of_the_seed_from_the_nodes_identity() {
    // The DICE node key is HKDF over the same seed with another salt and label.
    let node = azos_crypto::dice::node_static_key(&SEED, &[0x22; 32]).expect("node key");
    assert_ne!(Some(node), azvol_key::derive(&SEED, &[0x22; 32]), "a volume named like a measurement still gets another key");
}
