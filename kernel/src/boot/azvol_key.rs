// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The key of a sealed `[volume.NAME]` row, derived from the board's seed.
//!
//! ```text
//!   volume key = HKDF-SHA256(salt = row name, ikm = device seed,
//!                            info = "azos-azvol volume key v1")
//! ```
//!
//! The seed is the one the `LinkKey` endpoint's reserved sector holds (the DICE
//! identity of the node derives from it too, with another label); it never
//! leaves the kernel. The row's name as the salt gives each volume its own key,
//! and the engine derives the per-block keys from that and the volume's uuid
//! (`azvol::seal`), so a volume cloned to another board, or to another row of
//! this one, does not open. An all-zero seed (nothing provisioned) derives
//! nothing, as `azos_crypto::dice::node_static_key` refuses it.
//!
//! Kept apart from `azvol.rs` so the host suite includes it unchanged
//! (`tests/host/pkg-tests/src/volume_key.rs`).

use azos_crypto::ct::secure_zero;
use azos_crypto::hkdf;

/// The HKDF `info`; another purpose of the same seed takes another label.
pub(super) const INFO: &[u8] = b"azos-azvol volume key v1";

/// The key of the row named `name` on the board whose seed is `seed`; `None`
/// when the seed is all zeros.
pub(super) fn derive(seed: &[u8; 32], name: &[u8]) -> Option<[u8; 32]> {
    if seed.iter().all(|&b| b == 0) {
        return None;
    }
    let mut prk = hkdf::extract(name, seed);
    let mut key = [0u8; 32];
    let ok = hkdf::expand(&prk, INFO, &mut key);
    secure_zero(&mut prk);
    ok.then_some(key)
}
