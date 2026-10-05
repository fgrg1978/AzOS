// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ed25519 signature verification (F18 — secure boot).
//!
//! Minimal verify-only implementation for firmware signature checking.
//!
//! NOTE: this is a verify-only wrapper (`ed25519-dalek`, RFC 8032) for
//! firmware verification where the signer is a trusted build system. For
//! production TLS, consider a full Ed25519 implementation.
//!
//! ## Manifest binding (U09-4 / U11-4 / security finding #10)
//!
//! The signature does NOT sign the raw image. It signs a fixed-size
//! **manifest** — `{fw_version, payload_size, sha256(image)}`, 40 bytes,
//! see [`sig_verify_manifest`] — computed on the build host by
//! `tools/sign_ota.py` and re-derived on the kernel side by streaming the
//! image through [`crate::sha256::Sha256`] (no need to hold the whole
//! image contiguously to verify it, unlike the pre-manifest scheme this
//! replaced).
//!
//! Binding `fw_version` into the signed message is what makes the OTA
//! anti-rollback floor (`crates/core/ota::pure::ota_check_rollback_pure`)
//! trustworthy: before this, `fw_version` was a plaintext field in the
//! *unsigned* 24-byte wire header (`crates/core/ota::pure::OtaHeader`), so any
//! sender could claim any version for a genuinely-signed old image. Now the
//! version a verified image is credited with is the one inside the
//! signature, not the one on the wire.

use crate::sha256::Digest;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Ed25519 public key size in bytes.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 signature size in bytes.
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// Maximum message size `sig_verify` will hash/verify directly.
///
/// This bounds the RAW-MESSAGE Ed25519 primitive only (used directly by
/// `sig_verify_manifest` on a fixed 40-byte manifest, and by the RFC 8032
/// test vectors). It is NOT a firmware-image size ceiling — the manifest
/// scheme hashes the image with a streaming [`crate::sha256::Sha256`] and
/// never asks `sig_verify` to hold a whole image, so there is no longer a
/// separate "too large to verify" limit distinct from the OTA acceptance
/// limit (Kconfig `OTA_MAX_IMAGE_SIZE_MB`). This used to be named
/// `MAX_VERIFY_SIZE` and gate whole-image verification directly; renamed so
/// nobody reads it as that ceiling again.
pub const MAX_VERIFY_MESSAGE_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Firmware signature header (prepended to signed firmware).
#[derive(Clone, Copy)]
pub struct FirmwareSignature {
    /// Magic bytes: "RSIG"
    pub magic: [u8; 4],
    /// Signature algorithm. Only [`SIG_ALGORITHM_MANIFEST_V1`] parses.
    pub algorithm: u8,
    /// Public key that signed this firmware.
    pub public_key: [u8; ED25519_PUBLIC_KEY_SIZE],
    /// Signature over the 40-byte manifest — see [`sig_verify_manifest`].
    pub signature: [u8; ED25519_SIGNATURE_SIZE],
    /// Size of the firmware payload (not including this header). Part of
    /// the signed manifest — an attacker cannot change it without
    /// invalidating the signature.
    pub payload_size: u32,
    /// Firmware version. Part of the signed manifest (see module docs) —
    /// this is the number the OTA anti-rollback floor must use, never the
    /// unsigned `fw_version` in the wire header.
    pub fw_version: u32,
}

/// Signature header magic bytes.
pub const SIG_MAGIC: [u8; 4] = *b"RSIG";

/// Signature header size in bytes (v1 manifest format).
///
/// magic(4) + algorithm(1) + pubkey(32) + signature(64) + payload_size(4)
/// + fw_version(4) = 109.
pub const SIG_HEADER_SIZE: usize =
    4 + 1 + ED25519_PUBLIC_KEY_SIZE + ED25519_SIGNATURE_SIZE + 4 + 4;

/// Byte size of the signed manifest message: `fw_version(4) ++
/// payload_size(4) ++ sha256(32)`. See [`sig_verify_manifest`].
pub const MANIFEST_MESSAGE_SIZE: usize = 4 + 4 + 32;

/// Legacy algorithm byte (pre-manifest scheme: signature over the raw
/// image bytes, no version binding). Refused by [`sig_parse_header`] —
/// see [`SIG_ALGORITHM_MANIFEST_V1`]. Kept as a named constant so a
/// `.SIG` file in this format is REJECTED explicitly rather than by an
/// unexplained magic-number mismatch, and so old fixtures are easy to spot.
pub const SIG_ALGORITHM_ED25519: u8 = 0;

/// The one algorithm this kernel verifies: Ed25519 (RFC 8032) over the
/// signed manifest `{fw_version, payload_size, sha256(image)}`.
///
/// Bumped from `SIG_ALGORITHM_ED25519` (0) when the version was bound into
/// the signed message (U09-4 / U11-4 / security finding #10): the old format
/// signed the raw image only, so `fw_version` was unauthenticated and an
/// attacker could claim any version for a genuinely-signed old image. A
/// `.SIG` file in the old format must be rejected, not silently trusted
/// with an implicit version of 0 — that would fail every legitimate
/// install once a floor is set, which is a worse failure mode than making
/// re-signing mandatory once, at the same moment the format changed.
pub const SIG_ALGORITHM_MANIFEST_V1: u8 = 1;

/// Parse a firmware signature header from raw bytes.
pub fn sig_parse_header(data: &[u8]) -> Option<FirmwareSignature> {
    if data.len() < SIG_HEADER_SIZE {
        return None;
    }
    if data[0..4] != SIG_MAGIC {
        return None;
    }
    // The algorithm byte, refused rather than merely recorded — see
    // `SIG_ALGORITHM_MANIFEST_V1`. Only the manifest scheme parses; the
    // legacy raw-image scheme (`SIG_ALGORITHM_ED25519` = 0) does not, so a
    // signature with no version binding cannot be mistaken for one that has.
    if data[4] != SIG_ALGORITHM_MANIFEST_V1 {
        return None;
    }

    let mut pub_key = [0u8; ED25519_PUBLIC_KEY_SIZE];
    pub_key.copy_from_slice(&data[5..37]);

    let mut signature = [0u8; ED25519_SIGNATURE_SIZE];
    signature.copy_from_slice(&data[37..101]);

    let payload_size = u32::from_le_bytes([data[101], data[102], data[103], data[104]]);
    let fw_version   = u32::from_le_bytes([data[105], data[106], data[107], data[108]]);

    Some(FirmwareSignature {
        magic: SIG_MAGIC,
        algorithm: data[4],
        public_key: pub_key,
        signature,
        payload_size,
        fw_version,
    })
}

/// Build the 40-byte signed manifest message: `fw_version(LE) ++
/// payload_size(LE) ++ sha256(image)`.
#[must_use]
pub fn manifest_message(fw_version: u32, payload_size: u32, sha256_digest: &Digest) -> [u8; MANIFEST_MESSAGE_SIZE] {
    let mut msg = [0u8; MANIFEST_MESSAGE_SIZE];
    msg[0..4].copy_from_slice(&fw_version.to_le_bytes());
    msg[4..8].copy_from_slice(&payload_size.to_le_bytes());
    msg[8..40].copy_from_slice(sha256_digest);
    msg
}

/// Verify a signed manifest — the version-bound replacement for verifying
/// the raw image directly. `sha256_digest` is the image's SHA-256, computed
/// by the caller (streamed off disk; see `crates/core/ota/src/secure_boot.rs`'s
/// `hash_image_file`, which never needs the whole image resident).
///
/// Returns `true` iff `signature` is a valid Ed25519 signature by
/// `trusted_key` over `manifest_message(fw_version, payload_size,
/// sha256_digest)`.
#[must_use]
pub fn sig_verify_manifest(
    trusted_key: &[u8; ED25519_PUBLIC_KEY_SIZE],
    signature: &[u8; ED25519_SIGNATURE_SIZE],
    fw_version: u32,
    payload_size: u32,
    sha256_digest: &Digest,
) -> bool {
    let msg = manifest_message(fw_version, payload_size, sha256_digest);
    sig_verify(trusted_key, signature, &msg)
}

/// Verify a firmware image against a trusted public key using
/// **real Ed25519** (RFC 8032) via the vetted `ed25519-dalek` crate.
///
/// Replaces the pre-2026-05 HMAC-SHA256 stub (task #213) which was
/// trivially forgeable by anyone holding the public key. The
/// signature now signs the firmware bytes directly per the RFC —
/// no pre-hash, no proprietary scheme — so it interoperates with
/// any standard `ed25519` signer (e.g. `tools/sign_ota.py`).
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
    let vk = match ed25519_dalek::VerifyingKey::from_bytes(trusted_key) {
        Ok(v) => v,
        Err(_) => return false,  // malformed pubkey bytes
    };
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    // strict variant rejects non-canonical signatures (point + scalar).
    vk.verify_strict(firmware_data, &sig).is_ok()
}

/// Compute SHA-256 hash of firmware data (for signing on the build system).
pub fn firmware_hash(data: &[u8]) -> Digest {
    crate::sha256::sha256(data)
}

/// Verify a parsed signature header against a trusted key and an
/// already-hashed image — the manifest-scheme replacement for the old
/// `verify_boot_image` (which signed the raw image directly and had no
/// caller in the kernel; removed, see U09-15's sibling finding in the
/// 2026-09-25 audit, U09 §4).
///
/// Returns `true` if:
/// 1. Header magic is valid.
/// 2. Public key matches the trusted key (constant-time).
/// 3. `payload_size` matches the actual streamed length.
/// 4. The Ed25519 signature verifies over the signed manifest.
#[must_use]
pub fn verify_boot_image(
    sig_header: &FirmwareSignature,
    trusted_key: &[u8; ED25519_PUBLIC_KEY_SIZE],
    actual_len: u32,
    sha256_digest: &Digest,
) -> bool {
    if sig_header.magic != SIG_MAGIC {
        return false;
    }
    if !crate::ct::ct_eq(&sig_header.public_key, trusted_key) {
        return false;
    }
    if sig_header.payload_size != actual_len {
        return false;
    }
    sig_verify_manifest(
        trusted_key, &sig_header.signature,
        sig_header.fw_version, sig_header.payload_size, sha256_digest,
    )
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// (Removed dead `hmac_sha256_verify` — leftover from the pre-#213 HMAC-SHA-256
// signature stub. `sig_verify` now uses real Ed25519 via `ed25519-dalek`.)

// The local `constant_time_eq` that used to live here guarded the
// secure-boot trusted-public-key comparison — the single highest-value
// comparison in the tree — and was one of the three copies missing the
// `black_box` barrier that `auth_envelope.rs` and `ota/secure_boot.rs`
// already had. It now calls `crate::ct::ct_eq`.
//
// The leak this closes is modest (the trusted key is not itself a secret),
// but an early-exiting compare against the trusted key lets an attacker
// with signing-free image control learn the key byte-by-byte from timing,
// which is a strictly worse position than the one we intended.
