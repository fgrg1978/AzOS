// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_crypto`'s SHA-256 without its choice of block function: the portable
//! `sha2::compress256` runs.

pub use self::core_impl::{Digest, Sha256};

fn compress_blocks(state: &mut [u32; 8], blocks: &[core_impl::Block]) {
    sha2::compress256(state, blocks)
}

#[path = "../../crypto/src/sha256_core.rs"]
mod core_impl;
