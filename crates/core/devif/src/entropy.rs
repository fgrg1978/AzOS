// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Entropy` interface: the kernel pool, for ring 3.
//!
//! A task that needs random bytes (an ephemeral key, a nonce prefix) holds an
//! endpoint capability with `READ` on the kernel-hosted `entropy` endpoint.
//! A ring-3 entropy source (the virtio-rng driver) holds one with `WRITE` and
//! feeds the pool what its device delivered.
//! The pool never hands out anything while unseeded: [`outcome::NOT_READY`](crate::outcome::NOT_READY)
//! on every build, because there is no counter-derived fallback worth the
//! name "entropy" (owner decision V1.2).

use crate::outcome::Out;
use azos_idl::azos_interface;

/// The interface id (ASCII "ENTR").
pub const ENTROPY_ID: u32 = 0x454E_5452;

/// Words one `draw` returns at most (the reply's room: eight words, the
/// status and the outcome take two).
pub const DRAW_WORDS: usize = 6;

/// Words one `feed` carries at most.
pub const FEED_WORDS: usize = 6;

#[azos_interface(id = 0x454E_5452, level = 2)]
pub trait Entropy {
    /// `words` (1..=[`DRAW_WORDS`]) 64-bit words of the pool, the rest of the
    /// reply zero. `NOT_READY` while the pool is unseeded, `BAD_ARGUMENT`
    /// outside the range. Needs `READ`.
    fn draw(&mut self, words: u32) -> Out<[u64; DRAW_WORDS]>;
    /// Mix the first `n` (1..=[`FEED_WORDS`]) of `words`, read from an
    /// entropy device, into the pool; they count toward a seed only where
    /// Kconfig `ENTROPY_RING3_FEED` is `credit` (by default they are mixed,
    /// never counted). `BAD_ARGUMENT` outside the range. Needs `WRITE`.
    fn feed(&mut self, words: [u64; FEED_WORDS], n: u32) -> Out<()>;
}
