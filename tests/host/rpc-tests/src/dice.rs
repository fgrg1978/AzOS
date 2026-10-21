// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DICE-ID on the link: the node's static key is the kernel's DICE identity
//! of its image (`azos_rpc::keys`, `azos_crypto::dice`), and a peer running a
//! different image than the one the topology pinned is refused at the
//! handshake.
//!
//! **Canary.** Make `chan::answer` skip the `ct_eq(rs, dialer_pk)` pin check:
//! the wrong-image test gets a session. Make `NodeKey::acquire` accept zeros:
//! the unmeasured test gets a key.

use azos_crypto::dice::node_static_key;
use azos_rpc::chan;
use azos_rpc::keys::{KeyError, NodeKey};

const SEED: [u8; 32] = [0x5e; 32];
const IMAGE_RPCSRV: [u8; 32] = [0xA1; 32];
const IMAGE_OTHER: [u8; 32] = [0xB2; 32];
const A: u32 = 1;
const B: u32 = 2;

/// The words the kernel's `LinkKey::node_key` replies with.
fn words(k: &[u8; 32]) -> [u64; 4] {
    core::array::from_fn(|i| u64::from_le_bytes(k[i * 8..i * 8 + 8].try_into().unwrap()))
}

/// The key the kernel issues to a task of `image` on the board with `SEED`.
fn issued(image: &[u8; 32]) -> Result<[u64; 4], u32> {
    node_static_key(&SEED, image).map(|k| words(&k)).ok_or(7)
}

fn key_of(image: &[u8; 32]) -> NodeKey {
    NodeKey::acquire(|| issued(image)).unwrap()
}

/// A dials B (whose key is the pinned one) as `dialer`, B pins `pinned_pk` for A.
/// Whether B accepts the session.
fn handshake(dialer: &NodeKey, pinned_pk: &[u8; 32], answerer: &NodeKey) -> bool {
    let (a_sk, b_sk) = (dialer.secret(), answerer.secret());
    let pro = chan::prologue(A, B, 3, 99);
    let mut hello = [0u8; 256];
    let Some((_hs, n)) = chan::dial(&a_sk, &answerer.public(), &pro, &[0x21; 32], &[0u8], &mut hello) else {
        return false;
    };
    let (mut ack, mut payload) = ([0u8; 256], [0u8; 64]);
    chan::answer(&b_sk, pinned_pk, &pro, &hello[..n], &[0x22; 32], &[0u8], &mut ack, &mut payload).is_some()
}

#[test]
fn the_pinned_image_gets_a_session() {
    let a = key_of(&IMAGE_RPCSRV);
    let b = key_of(&IMAGE_RPCSRV);
    // B's topology pins A's public key: the one the image derives on this board.
    assert!(handshake(&a, &a.public(), &b));
}

#[test]
fn a_peer_running_a_different_image_is_refused_at_the_handshake() {
    let pinned = key_of(&IMAGE_RPCSRV).public();
    let b = key_of(&IMAGE_RPCSRV);
    // Same board, same seed, another image: another key, and the pin refuses it.
    let intruder = key_of(&IMAGE_OTHER);
    assert_ne!(intruder.public(), pinned);
    assert!(!handshake(&intruder, &pinned, &b), "an image the topology did not pin got a session");
}

#[test]
fn a_peer_on_another_board_is_refused() {
    let a = key_of(&IMAGE_RPCSRV);
    let other_board = node_static_key(&[0x77; 32], &IMAGE_RPCSRV).unwrap();
    let intruder = NodeKey::acquire(|| Ok(words(&other_board))).unwrap();
    assert!(!handshake(&intruder, &a.public(), &key_of(&IMAGE_RPCSRV)));
}

#[test]
fn the_key_is_the_same_at_every_boot_and_the_public_half_is_the_pin() {
    let (k1, k2) = (key_of(&IMAGE_RPCSRV), key_of(&IMAGE_RPCSRV));
    assert_eq!(k1.secret(), k2.secret());
    assert_eq!(k1.public(), chan::static_public_key(&node_static_key(&SEED, &IMAGE_RPCSRV).unwrap()));
}

#[test]
fn what_the_kernel_refuses_is_no_identity() {
    // An image the loader did not measure, or a board with no seed: the
    // kernel's `NOT_READY` (here 7) comes back as the refusal.
    assert!(matches!(NodeKey::acquire(|| issued(&[0; 32])), Err(KeyError::Refused(7))));
    assert!(matches!(NodeKey::acquire(|| Err(2)), Err(KeyError::Refused(2))));
    // An answer of zeros is not a key.
    assert!(matches!(NodeKey::acquire(|| Ok([0; 4])), Err(KeyError::Zero)));
}

#[test]
fn only_the_public_half_is_printed_and_the_secret_is_derived_not_stored_as_the_seed() {
    let k = key_of(&IMAGE_RPCSRV);
    assert_ne!(k.secret(), SEED);
    assert_ne!(k.public(), k.secret());
    // The words the kernel sent are not the seed.
    assert_ne!(issued(&IMAGE_RPCSRV).unwrap(), words(&SEED));
}
