// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ed25519 (RFC 8032) verification and signing.
//!
//! The verifier is a wrapper over the vetted `ed25519-dalek` crate. The
//! formats that carry a signature, and the choice of algorithm, are in
//! [`crate::sig`]; this module is the Ed25519 primitive under it, plus the
//! signer the SSH server needs for its host key (at the end of the file).

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Ed25519 public key size in bytes.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 signature size in bytes.
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// Maximum message size [`sig_verify`] will hash/verify directly: for a
/// caller whose message is a small fixed structure (the e-stop release
/// nonce) and must not be handed an unbounded one. [`sig_verify_message`] has
/// no bound: its callers read into buffers of their own.
pub const MAX_VERIFY_MESSAGE_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Verify `firmware_data` (any short message) against a trusted public key
/// using **real Ed25519** (RFC 8032) via the vetted `ed25519-dalek` crate: no
/// pre-hash, no proprietary scheme, so it interoperates with any standard
/// `ed25519` signer.
///
/// Returns `true` if the signature is valid for `firmware_data`
/// under `trusted_key`.
pub fn sig_verify(
    trusted_key: &[u8; ED25519_PUBLIC_KEY_SIZE],
    signature: &[u8; ED25519_SIGNATURE_SIZE],
    firmware_data: &[u8],
) -> bool {
    if firmware_data.len() > MAX_VERIFY_MESSAGE_SIZE {
        return false;
    }
    sig_verify_message(trusted_key, signature, firmware_data)
}

/// [`sig_verify`] without [`MAX_VERIFY_MESSAGE_SIZE`]: for a caller whose
/// message is already bounded by the buffer it was read into (the signed
/// topology, the ML data files, a package's signed message). Reached through
/// [`crate::sig::SigAlg::verify`] by every signed format. The cost is one
/// SHA-512 pass over the message on top of the fixed verification.
pub fn sig_verify_message(
    trusted_key: &[u8; ED25519_PUBLIC_KEY_SIZE],
    signature: &[u8; ED25519_SIGNATURE_SIZE],
    message: &[u8],
) -> bool {
    let vk = match ed25519_dalek::VerifyingKey::from_bytes(trusted_key) {
        Ok(v) => v,
        Err(_) => return false,  // malformed pubkey bytes
    };
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    // strict variant rejects non-canonical signatures (point + scalar).
    vk.verify_strict(message, &sig).is_ok()
}

// ---------------------------------------------------------------------------
// Signing (the SSH server's host key)
// ---------------------------------------------------------------------------

/// The public key of the Ed25519 secret `seed` (RFC 8032 section 5.1.5).
pub fn public_from_seed(seed: &[u8; 32]) -> [u8; ED25519_PUBLIC_KEY_SIZE] {
    ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Sign `message` with the Ed25519 secret `seed` (RFC 8032: deterministic, so
/// no randomness is needed). The one signer in the tree outside the build
/// tools: `userspace/services/sshd` signs its key-exchange hash with the host
/// key. A verifier uses [`sig_verify_message`].
pub fn sign_message(seed: &[u8; 32], message: &[u8]) -> [u8; ED25519_SIGNATURE_SIZE] {
    use ed25519_dalek::Signer;
    ed25519_dalek::SigningKey::from_bytes(seed).sign(message).to_bytes()
}
