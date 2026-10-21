// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Where the node's static Noise key comes from: the kernel, as a DICE
//! identity.
//!
//! The key is `HKDF(device seed, measurement of this server's image)`
//! (`azos_crypto::dice`), derived by the kernel for the Domain that asks and
//! issued through `LinkKey::node_key` on the `linkkey` endpoint. The server
//! reads no key from a file and derives nothing from a board secret: the seed
//! never reaches ring 3, and an image other than the one the topology pinned
//! the node's `noise_pk` for gets a key whose public half no peer accepts.
//! This module owns the part that is not the call: refusing an answer that is
//! no key, handing the key out once and wiping every copy it made.
//! The call itself is the caller's (the crate has no libsys), as the clock and
//! the capability calls are.

use azos_crypto::ct::secure_zero;
use azos_crypto::noise::DH_LEN;

use crate::chan;

/// Why there is no identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The kernel refused (its outcome code): no seed on this board, an image
    /// the loader did not measure, or no right on the endpoint.
    Refused(u32),
    /// The kernel answered, with all zeros: not a key.
    Zero,
}

/// A node's static key. Its secret half is wiped when it is dropped.
pub struct NodeKey {
    sk: [u8; DH_LEN],
}

impl NodeKey {
    /// The key from the kernel's four words (`LinkKey::node_key`), which
    /// `fetch` returns; the words are wiped here. `Err` when the kernel gives
    /// none or an all-zero one: there is no identity to run under.
    pub fn acquire(fetch: impl FnOnce() -> Result<[u64; 4], u32>) -> Result<NodeKey, KeyError> {
        let mut w = fetch().map_err(KeyError::Refused)?;
        let mut sk = [0u8; DH_LEN];
        for (c, x) in sk.chunks_exact_mut(8).zip(w.iter()) {
            c.copy_from_slice(&x.to_le_bytes());
        }
        secure_zero(&mut w);
        if sk.iter().all(|&b| b == 0) {
            return Err(KeyError::Zero);
        }
        Ok(NodeKey { sk })
    }

    /// The public half: what the topology of the peers pins as `noise_pk`.
    pub fn public(&self) -> [u8; DH_LEN] {
        chan::static_public_key(&self.sk)
    }

    /// The secret half, for the engine's `Host::static_key`. The caller wipes
    /// the copy it makes ([`chan::wipe`]).
    pub fn secret(&self) -> [u8; DH_LEN] {
        self.sk
    }
}

impl Drop for NodeKey {
    fn drop(&mut self) {
        secure_zero(&mut self.sk);
    }
}
