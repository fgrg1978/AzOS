// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_crypto`'s SHA-256 without its choice of block function: the portable
//! one runs.

pub use self::core_impl::{Digest, Sha256};

fn compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    core_impl::blocks_generic(state, blocks)
}

#[path = "../../crypto/src/sha256_core.rs"]
mod core_impl;
