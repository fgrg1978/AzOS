// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Constant-time and secret-erasure primitives.
//!
//! ## Why this module exists
//!
//! Before this module the tree carried **five** hand-rolled copies of the
//! same "compare two byte slices without an early exit" loop, and only two
//! of them ended in `core::hint::black_box(diff) == 0`:
//!
//! | copy                                    | `black_box`? |
//! |-----------------------------------------|--------------|
//! | `behavior/src/auth_envelope.rs`         | yes          |
//! | `ota/src/secure_boot.rs`                | yes          |
//! | `encrypt-link/src/lib.rs` (PSK proofs)  | **no**       |
//! | `crypto/src/secure_channel.rs` (AEAD)   | **no**       |
//! | `crypto/src/ed25519.rs` (boot pubkey)   | **no**       |
//!
//! The three unhardened copies guarded the highest-value comparisons in
//! the system — the handshake PSK proofs, the AEAD tag, and the secure-boot
//! public key. The argument for fixing this is not that LLVM has been
//! observed to break the accumulate-then-compare loop; it is that one
//! codebase must not disagree with itself about whether that loop needs a
//! barrier. Either `black_box` is required or it is noise, and the two
//! copies that already have it settle which way we resolve the asymmetry.
//!
//! `crates/core/ota/src/secure_boot.rs` still carries its own (already-hardened)
//! copy; folding it in is a separate change in a different ownership lane.

use core::sync::atomic::{compiler_fence, Ordering};

/// Constant-time byte-slice equality.
///
/// Runs in time dependent only on `a.len()`, never on *where* the first
/// differing byte is. A length mismatch short-circuits: lengths are public
/// (they are on the wire in the clear) and comparing different-length
/// buffers is a programming error, not a secret-dependent branch.
///
/// The `black_box` on the accumulator is the load-bearing part. Without it
/// the optimiser is formally free to rewrite `diff |= a[i] ^ b[i]` plus the
/// final `== 0` into an early-exiting `memcmp`, which leaks the index of
/// the first mismatching byte through timing and turns a tag-forgery from
/// a 2^128 problem into a 16-byte-at-a-time search. `black_box` makes the
/// accumulator opaque, so the loop must run to completion.
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    core::hint::black_box(diff) == 0
}

/// Overwrite `buf` with zeros in a way the optimiser may not elide.
///
/// A plain `buf.fill(0)` on a buffer that is never read again is dead-store
/// eliminable, and LLVM does eliminate it — which is precisely the case for
/// key material being wiped in a `Drop`. `write_volatile` forbids removing
/// the stores, and the `SeqCst` compiler fence afterwards forbids sinking
/// them past the end of the object's lifetime.
///
/// This is not a defence against an attacker who can read RAM *while* the
/// key is live. It shrinks the window: after a `SecureChannel` or
/// `EncryptLink` is dropped, its key bytes are not left sitting in a stack
/// frame or heap block for a later crash dump, OTA image reader, or DMA
/// scribble to pick up.
#[inline]
pub fn secure_zero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` comes from a live `&mut [u8]`, so it is valid,
        // aligned and uniquely borrowed for the duration of the write.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}
