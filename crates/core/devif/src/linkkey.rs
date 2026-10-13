// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `LinkKey` interface: the brain-link PSK, for the one ring-3 task that
//! speaks the link (U06-9).
//!
//! The key lives in a reserved sector no USB host can address; the kernel
//! reads it for the holder of `READ` on the kernel-hosted `linkkey` endpoint.
//! One key per board, so the endpoint carries no resource. There is no write
//! path: the key is provisioned at image-build time.

use crate::outcome::Out;
use azos_idl::azos_interface;

/// The interface id (ASCII "LKEY").
pub const LINK_KEY_ID: u32 = 0x4C4B_4559;
/// Words of the key: 32 bytes.
pub const KEY_WORDS: usize = 4;

#[azos_interface(id = 0x4C4B_4559, level = 1)]
pub trait LinkKey {
    /// The key, as four little-endian words. `NOT_READY` when the kernel
    /// holds none (absent, unprovisioned, or all zero): the same refusal to
    /// run in plaintext the kernel's own link applies. Needs `READ`.
    fn read(&mut self) -> Out<[u64; KEY_WORDS]>;
}
