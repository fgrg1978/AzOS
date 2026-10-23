// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! X25519 Diffie-Hellman key exchange (RFC 7748).
//!
//! no_std, through `curve25519-dalek` (constant-time Montgomery ladder):
//! scalar multiplication on Curve25519 for key agreement.
//!
//! Usage:
//!   1. Each side generates a random 32-byte private key
//!   2. Each side computes public key: `x25519(private, BASEPOINT)`
//!   3. Each side computes shared secret: `x25519(my_private, their_public)`
//!   4. Both arrive at the same 32-byte shared secret

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The Curve25519 base point (u-coordinate = 9).
pub const BASEPOINT: [u8; 32] = {
    let mut bp = [0u8; 32];
    bp[0] = 9;
    bp
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute X25519 scalar multiplication: `result = scalar * point`.
///
/// - `scalar`: 32-byte private key (clamped internally per RFC 7748).
/// - `point`:  32-byte public key (or BASEPOINT for key generation).
///
/// Returns the 32-byte shared secret (or public key).
///
/// Backed by `curve25519-dalek::MontgomeryPoint::mul_clamped` — vetted,
/// constant-time, all RFC 7748 vectors pass (task #212).
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::MontgomeryPoint;
    let p = MontgomeryPoint(*point);
    p.mul_clamped(*scalar).0
}

/// Contributory-behaviour X25519: like [`x25519`], but returns `None` when
/// the shared secret is all zeros.
///
/// RFC 7748 §6.1 makes this check optional and says protocols "MAY" perform
/// it; for us it is mandatory, because of *where* the multiplication
/// happens: the brain-link handshake derives its shared secrets
/// from a peer public key that has not been authenticated yet — the peer's
/// static key is only checked afterwards. A peer who sends one of the twelve
/// small-order Curve25519 points (all-zero, `u=1`, the two order-8 points,
/// and their `p`-offset aliases) forces the product to the identity, so
/// *both* sides derive session keys from a shared secret of 32 zero bytes,
/// independent of either private key.
///
/// That is not exploitable today: the channel only reaches `Established`
/// after CONFIRM verifies against the PSK, and both `encrypt` and `decrypt`
/// refuse to run before then, so an attacker without the PSK never gets a
/// frame encrypted under the degenerate key. The reason to check anyway is
/// that this safety rests entirely on the *ordering* of two operations in a
/// different crate. Any refactor that derives keys before verifying the
/// proof — or that adds a code path emitting a frame from `AwaitConfirm` —
/// silently converts a fragile-but-correct handshake into a key exchange an
/// unauthenticated peer can pin to a known value. Rejecting the all-zero
/// output makes the failure structural rather than ordering-dependent.
///
/// The all-zero output test catches *every* small-order input, which is why
/// it is preferred over blacklisting the twelve point encodings: the
/// blacklist has to be complete and stay complete, this does not.
pub fn x25519_checked(scalar: &[u8; 32], point: &[u8; 32]) -> Option<[u8; 32]> {
    let shared = x25519(scalar, point);
    // Constant-time all-zero test: fold every byte into one accumulator so
    // the check itself does not leak which byte was non-zero. (A timing
    // leak here would be mild, but the primitive is already available and
    // an early-exit loop over a shared secret is exactly the pattern this
    // tree is trying to stop copying around.)
    let mut acc = 0u8;
    for b in shared.iter() {
        acc |= *b;
    }
    if core::hint::black_box(acc) == 0 {
        return None;
    }
    Some(shared)
}

/// Generate a public key from a private key.
pub fn x25519_pubkey(private_key: &[u8; 32]) -> [u8; 32] {
    x25519(private_key, &BASEPOINT)
}
