// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DICE-style node identity: the static key of a node is a function of the
//! board's secret and of the image that asks for it.
//!
//! ```text
//! node_static_key = HKDF-SHA256(salt = measurement, ikm = device seed,
//!                               info = "azos-dice node static key v1")
//! ```
//!
//! The **measurement** is the SHA-256 of the image a Domain started from (the
//! loader records it with `azos_sched::domain::set_measurement`); the **device
//! seed** is the board's reserved-sector secret, which only the kernel reads.
//! A different image under the same seed gets a different key, so the key a
//! topology pins in a `[peer.NAME]` row (`noise_pk`) is the key of exactly one
//! image on one board: a node that runs another image cannot present it, and
//! the Noise IK handshake refuses it. That is the whole of the check the
//! pinned `measurement` needs on the wire; the row's `measurement` is what the
//! operator derives the pinned `noise_pk` from when provisioning.
//!
//! The seed itself never leaves the kernel: the holder of `READ` on the
//! `linkkey` endpoint is handed the derived key of its own Domain's
//! measurement, nothing else. (The derived key does cross into ring 3, since
//! the Noise state machine runs there.)
//!
//! A domain with no measurement (all zeros: it was not started through the
//! measuring loader) has no identity: [`node_static_key`] refuses it rather
//! than derive the key every unmeasured image would share.

use crate::ct::secure_zero;
use crate::hkdf;

/// Length of the seed, of a measurement and of the derived key.
pub const KEY_LEN: usize = 32;

/// The HKDF `info` of the node's static key; a different purpose of the same
/// seed takes a different label.
pub const NODE_KEY_INFO: &[u8] = b"azos-dice node static key v1";

/// The node's static X25519 private key for `measurement` on the board whose
/// secret is `seed`. `None` when either is all zeros (no seed provisioned, no
/// measurement recorded): there is no identity to derive. Deterministic, so the
/// same image on the same board has the same key at every boot.
pub fn node_static_key(seed: &[u8; KEY_LEN], measurement: &[u8; KEY_LEN]) -> Option<[u8; KEY_LEN]> {
    if seed.iter().all(|&b| b == 0) || measurement.iter().all(|&b| b == 0) {
        return None;
    }
    let mut prk = hkdf::extract(measurement, seed);
    let mut sk = [0u8; KEY_LEN];
    let ok = hkdf::expand(&prk, NODE_KEY_INFO, &mut sk);
    secure_zero(&mut prk);
    ok.then_some(sk)
}
