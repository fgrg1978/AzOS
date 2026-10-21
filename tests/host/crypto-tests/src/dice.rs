// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DICE-ID (`azos_crypto::dice`): the node's static key is `HKDF(device seed,
//! image measurement)`.
//!
//! **Canary.** Drop the measurement from the derivation (`salt = &[]`): the
//! different-measurement test finds equal keys. Derive from the measurement
//! alone: the different-seed test does.

use azos_crypto::dice::{node_static_key, NODE_KEY_INFO};
use azos_crypto::hkdf;
use azos_crypto::x25519::x25519_pubkey;

const SEED: [u8; 32] = [0x11; 32];
const IMAGE_A: [u8; 32] = [0xA0; 32];
const IMAGE_B: [u8; 32] = [0xB0; 32];

#[test]
fn the_same_seed_and_measurement_give_the_same_key() {
    let k1 = node_static_key(&SEED, &IMAGE_A).unwrap();
    let k2 = node_static_key(&SEED, &IMAGE_A).unwrap();
    assert_eq!(k1, k2);
    assert_ne!(k1, [0; 32]);
    // The public half is the pin a topology carries, and it is stable too.
    assert_eq!(x25519_pubkey(&k1), x25519_pubkey(&k2));
}

#[test]
fn another_measurement_gives_another_key_and_another_public_key() {
    let a = node_static_key(&SEED, &IMAGE_A).unwrap();
    let b = node_static_key(&SEED, &IMAGE_B).unwrap();
    assert_ne!(a, b);
    assert_ne!(x25519_pubkey(&a), x25519_pubkey(&b));
    // One flipped bit of the measurement is another identity.
    let mut m = IMAGE_A;
    m[31] ^= 1;
    assert_ne!(node_static_key(&SEED, &m).unwrap(), a);
}

#[test]
fn another_seed_gives_another_key() {
    let mut other = SEED;
    other[0] ^= 1;
    assert_ne!(node_static_key(&SEED, &IMAGE_A).unwrap(), node_static_key(&other, &IMAGE_A).unwrap());
}

#[test]
fn the_key_is_hkdf_of_the_seed_salted_by_the_measurement() {
    let mut want = [0u8; 32];
    assert!(hkdf::hkdf(&IMAGE_A, &SEED, NODE_KEY_INFO, &mut want));
    assert_eq!(node_static_key(&SEED, &IMAGE_A).unwrap(), want);
}

#[test]
fn the_key_carries_neither_the_seed_nor_the_measurement() {
    let k = node_static_key(&SEED, &IMAGE_A).unwrap();
    assert_ne!(k, SEED);
    assert_ne!(k, IMAGE_A);
    // Not the PRK either: the seed the kernel keeps cannot be read off the key.
    assert_ne!(k, hkdf::extract(&IMAGE_A, &SEED));
    assert!(!k.windows(8).any(|w| SEED.windows(8).any(|s| s == w)));
}

#[test]
fn no_seed_or_no_measurement_is_no_identity() {
    assert_eq!(node_static_key(&[0; 32], &IMAGE_A), None, "no seed provisioned");
    assert_eq!(node_static_key(&SEED, &[0; 32]), None, "an unmeasured image shares no key");
    assert_eq!(node_static_key(&[0; 32], &[0; 32]), None);
}
