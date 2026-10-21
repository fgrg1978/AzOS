// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `LinkKey` interface: the brain-link PSK, for the one ring-3 task that
//! speaks the link (U06-9).
//!
//! The key lives in a reserved sector no USB host can address; the kernel
//! reads it for the holder of `READ` on the kernel-hosted `linkkey` endpoint.
//! The raw key is also the board's device seed, so the op that returns it
//! ([`LinkKey::read`]) is called by the link task alone: a task that needs
//! only an identity holds `READ` with an `OP_MASK` caveat that lists
//! [`NODE_KEY_OPS`] and nothing else (`azos_ipc::cap::caveat::OP_MASK`).
//! One key per board, so the endpoint carries no resource. There is no write
//! path: the key is provisioned at image-build time.
//!
//! The same endpoint also issues the node's DICE identity ([`LinkKey::node_key`]),
//! as an op of its own: the Noise static key of the caller's own image, so a
//! task that needs an identity does not need the board's secret, which never
//! leaves the kernel for it. It also hands out the brain's pinned static key
//! ([`LinkKey::brain_pk`]), the one datum of the signed topology the link
//! client needs.

use crate::outcome::Out;
use azos_idl::azos_interface;

/// The interface id (ASCII "LKEY").
pub const LINK_KEY_ID: u32 = 0x4C4B_4559;
/// Words of the key: 32 bytes.
pub const KEY_WORDS: usize = 4;
/// The `OP_MASK` of a holder that may call [`LinkKey::node_key`] and no other
/// op: bit n is the op numbered n, counted from 1, so `node_key` (the second
/// method of the trait) is bit 2. The host test `node_key_ops_name_node_key`
/// holds the number to the generated op table.
pub const NODE_KEY_OPS: u64 = 1 << 2;

#[azos_interface(id = 0x4C4B_4559, level = 1)]
pub trait LinkKey {
    /// The key, as four little-endian words. `NOT_READY` when the kernel
    /// holds none (absent, unprovisioned, or all zero): the same refusal to
    /// run in plaintext the kernel's own link applies. Needs `READ`.
    fn read(&mut self) -> Out<[u64; KEY_WORDS]>;

    /// The static X25519 private key of the caller's node, as four
    /// little-endian words: `HKDF(device seed, measurement of the caller's
    /// Domain)` (`azos_crypto::dice`). The same image on the same board gets
    /// the same key at every boot; another image gets another. `NOT_READY`
    /// when the kernel holds no seed or the caller's Domain has no
    /// measurement. Needs `READ`, like every op of the interface; a holder
    /// that must not read the seed has an `OP_MASK` of [`NODE_KEY_OPS`], which
    /// admits this op and not [`LinkKey::read`].
    fn node_key(&mut self) -> Out<[u64; KEY_WORDS]>;

    /// The brain's static X25519 PUBLIC key, as four little-endian words: the
    /// `noise_pk` of the signed topology's `[peer.brain]` row, the key a
    /// `Noise_IK` link toward the brain is pinned to. `NO_RESOURCE` when the
    /// topology has no such row or the row pins no key (the link then runs
    /// `Noise_XX`, authenticated by the link key). Public, but still `READ`:
    /// the link client is the only task that has a use for it.
    fn brain_pk(&mut self) -> Out<[u64; KEY_WORDS]>;
}
