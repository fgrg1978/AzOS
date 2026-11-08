// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Authority` interface: a ring-3 engine hands the kernel a protocol
//! frame that asks for its authority (an e-stop, degraded mode, an operator's
//! signed release, a payload or configuration effect), and the kernel decides
//! and acts.
//!
//! The engine parses its link (framing, checksum, the encrypted session) and
//! submits the frame's type and payload; the extension that owns the protocol
//! answers it in the kernel (`azos_syscall::authority_host`), with every check
//! and record its own. A build whose extensions register no answer has
//! nothing to submit to: `UNSUPPORTED`. Needs `WRITE`.

use crate::outcome::Out;
use azos_idl::azos_interface;

/// The interface id (ASCII "AUTH").
pub const AUTHORITY_ID: u32 = 0x4155_5448;

/// Bytes of a frame's payload at most: the largest authority frame (a
/// device-hold release: mode id, nonce, signature, device) with room.
pub const FRAME_BYTES: usize = 96;
/// Words one [`Authority::put`] carries: a request holds eight, the header
/// and the offset take two.
pub const PUT_WORDS: usize = 6;
/// Bytes one [`Authority::put`] carries.
pub const PUT_BYTES: usize = PUT_WORDS * 8;

/// `chunk` (at most [`PUT_BYTES`]) as the words of a [`Authority::put`],
/// little-endian.
pub fn put_words(chunk: &[u8]) -> [u64; PUT_WORDS] {
    let mut w = [0u64; PUT_WORDS];
    for (i, b) in chunk.iter().take(PUT_BYTES).enumerate() {
        w[i / 8] |= (*b as u64) << (8 * (i % 8));
    }
    w
}

/// The bytes of a [`Authority::put`]'s words.
pub fn put_bytes(words: &[u64; PUT_WORDS]) -> [u8; PUT_BYTES] {
    let mut out = [0u8; PUT_BYTES];
    for (i, b) in out.iter_mut().enumerate() {
        *b = (words[i / 8] >> (8 * (i % 8))) as u8;
    }
    out
}

/// Submit frame `kind` with `payload` through `a`: the payload in
/// [`PUT_BYTES`] pieces, then the frame. The first refusal is the answer.
pub fn submit<A: AuthorityCall + ?Sized>(a: &mut A, kind: u8, payload: &[u8]) -> Result<(), u32> {
    if payload.len() > FRAME_BYTES {
        return Err(crate::outcome::BAD_ARGUMENT);
    }
    for (i, chunk) in payload.chunks(PUT_BYTES).enumerate() {
        crate::outcome::served(a.put((i * PUT_BYTES) as u32, put_words(chunk)))?;
    }
    crate::outcome::served(a.frame(kind as u32, payload.len() as u32))
}

#[azos_interface(id = 0x4155_5448, level = 1)]
pub trait Authority {
    /// Stage [`PUT_BYTES`] of the caller's next frame at byte `offset` (a
    /// multiple of [`PUT_BYTES`] below [`FRAME_BYTES`], else `BAD_ARGUMENT`).
    /// `NO_RESOURCE` when every staging slot is another task's. Needs `WRITE`.
    #[on_failure(degrade)]
    #[deadline_ns = 1_000_000]
    #[budget_us = 50]
    fn put(&mut self, offset: u32, words: [u64; PUT_WORDS]) -> Out<()>;
    /// Submit frame `kind` (the protocol's type byte) with the first `len`
    /// staged bytes (more than [`FRAME_BYTES`] is `BAD_ARGUMENT`), and clear
    /// the stage. `OK` when the kernel answered it, whatever it decided (a
    /// refused release is recorded, not an error); `UNSUPPORTED` when no
    /// extension answers. Needs `WRITE`, without the containment step.
    #[on_failure(escalate)]
    #[deadline_ns = 5_000_000]
    #[budget_us = 1_000]
    fn frame(&mut self, kind: u32, len: u32) -> Out<()>;
}
