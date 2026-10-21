// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Signature algorithms, and the containers every signed file of the system
//! carries a signature in.
//!
//! Every signed format names its algorithm by a 16-bit id ([`SigAlg::id`]) and
//! carries a signature whose length the algorithm decides, so adding a
//! post-quantum scheme is a new [`SigAlg`] variant (with its verifier, and the
//! Kconfig choice that selects it), not a new format. The ids are the ones
//! `azos_pkg`'s container and its `key_id` already used; 2 and 3 are reserved
//! for ML-DSA-65 and SLH-DSA-SHA2-128s and no build accepts them yet.
//!
//! # One algorithm per device
//!
//! A device's trust anchors (the update key, the topology key) are keys of ONE
//! algorithm, [`SigAlg::CONFIGURED`]. A file that names another algorithm is
//! refused before its signature is looked at ([`SigAlg::accepted`]), and every
//! slot that holds a key or a signature (the embedded keys, the `.SIG` read
//! buffers, the update manifest) is sized for that algorithm
//! ([`KEY_LEN`], [`SIG_LEN`]): an Ed25519 device pays 64 bytes of signature
//! slot. The wire formats themselves allow up to [`KEY_LEN_MAX`] and
//! [`SIG_LEN_MAX`] bytes.
//!
//! # The containers
//!
//! ```text
//! RSIG  the signature of an image (KERN_x.SIG, KERN.SIG of an update, a livepatch blob)
//!    0    4  magic "RSIG"
//!    4    2  algorithm id
//!    6    2  sig_len
//!    8   32  key_id: sha256(alg_le16 || the signing key), see [`key_id`]
//!   40    4  payload_size   of the image it covers, signed
//!   44    4  fw_version     signed; a livepatch's sec_epoch
//!   48  sig_len  signature over [`manifest_message`]
//!
//! DSIG  the detached signature of a file (CAPS.SIG, POLICY.SIG)
//!    0    4  magic "DSIG"
//!    4    2  algorithm id
//!    6    2  sig_len
//!    8  sig_len  signature over the file's exact bytes
//! ```
//!
//! An `RSIG` names its signer by id rather than carrying the key: the device
//! holds the one trusted key, and a large post-quantum key in every `.SIG`
//! would buy nothing. All integers are little endian.

use crate::ct::ct_eq;
use crate::sha256::{Digest, Sha256};

/// Longest public key a signed format may declare (an ML-DSA-87 key is 2592).
pub const KEY_LEN_MAX: usize = 4096;
/// Longest signature a signed format may declare (an SLH-DSA-SHA2-128s signature is 7856).
pub const SIG_LEN_MAX: usize = 8192;

/// A signature algorithm, by the id the formats carry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum SigAlg {
    /// Ed25519 (RFC 8032), strict verification: a 32-byte key, a 64-byte
    /// signature.
    Ed25519 = 1,
}

impl SigAlg {
    /// The algorithm of this device's trust anchors: the one place that names
    /// it, which every key slot, signature slot and parser follows.
    pub const CONFIGURED: SigAlg = SigAlg::Ed25519;

    /// The algorithm `id` names.
    pub const fn from_id(id: u16) -> Option<Self> {
        match id {
            1 => Some(SigAlg::Ed25519),
            _ => None,
        }
    }

    /// The algorithm `id` names if it is [`SigAlg::CONFIGURED`], else `None`:
    /// what every parser asks, so a file of another algorithm is refused
    /// before anything else of it is read.
    pub const fn accepted(id: u16) -> Option<Self> {
        match Self::from_id(id) {
            Some(a) if a as u16 == Self::CONFIGURED as u16 => Some(a),
            _ => None,
        }
    }

    /// The id the formats carry.
    pub const fn id(self) -> u16 {
        self as u16
    }

    /// Bytes of a public key.
    pub const fn key_len(self) -> usize {
        match self {
            SigAlg::Ed25519 => crate::ed25519::ED25519_PUBLIC_KEY_SIZE,
        }
    }

    /// Bytes of a signature.
    pub const fn sig_len(self) -> usize {
        match self {
            SigAlg::Ed25519 => crate::ed25519::ED25519_SIGNATURE_SIZE,
        }
    }

    /// Is `sig` a valid signature over `msg` by `key`? A key or a signature
    /// of the wrong length is a failure, not a panic.
    pub fn verify(self, key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        if key.len() != self.key_len() || sig.len() != self.sig_len() {
            return false;
        }
        match self {
            SigAlg::Ed25519 => {
                let (Ok(k), Ok(s)) = (key.try_into(), sig.try_into()) else { return false };
                crate::ed25519::sig_verify_message(k, s, msg)
            }
        }
    }
}

const _: () = assert!(SigAlg::CONFIGURED.key_len() <= KEY_LEN_MAX && SigAlg::CONFIGURED.sig_len() <= SIG_LEN_MAX);

/// Bytes of a public key of the configured algorithm: the size of every
/// embedded trust anchor.
pub const KEY_LEN: usize = SigAlg::CONFIGURED.key_len();
/// Bytes of a signature of the configured algorithm: the size of every
/// signature slot.
pub const SIG_LEN: usize = SigAlg::CONFIGURED.sig_len();

/// A trust anchor embedded by a build script: `bytes` (empty for none, which
/// verifies nothing) in a [`KEY_LEN`] array. Fails the build when the key file
/// is not a key of the configured algorithm.
pub const fn key_array(bytes: &[u8]) -> [u8; KEY_LEN] {
    assert!(bytes.is_empty() || bytes.len() == KEY_LEN, "the embedded public key is not a key of the configured algorithm");
    let mut out = [0u8; KEY_LEN];
    let mut i = 0;
    while i < bytes.len() {
        out[i] = bytes[i];
        i += 1;
    }
    out
}

/// The id of a key: `sha256(alg_le16 || key)`. What a topology's
/// `[signer.NAME]` section names (`key_id`) and what an [`Rsig`] names its
/// signer by. `alg_id` is as written in the file, known or not.
pub fn key_id(alg_id: u16, key: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(&alg_id.to_le_bytes());
    h.update(key);
    h.finalize()
}

// ---------------------------------------------------------------------------
// RSIG
// ---------------------------------------------------------------------------

/// `RSIG`.
pub const RSIG_MAGIC: [u8; 4] = *b"RSIG";
/// Bytes of an `RSIG` before the signature.
pub const RSIG_FIXED_LEN: usize = 48;
/// The largest `RSIG` file of the configured algorithm.
pub const RSIG_FILE_MAX: usize = RSIG_FIXED_LEN + SIG_LEN;
/// Domain tag of the signed manifest: no other signature of the same key is
/// also one over an image.
const RSIG_DOMAIN: [u8; 12] = *b"azos-rsig-v2";
/// Bytes of the signed manifest ([`manifest_message`]).
pub const MANIFEST_MESSAGE_LEN: usize = 12 + 2 + 4 + 4 + 32;

/// What an `RSIG` signs: the domain tag, the algorithm (so the signature
/// cannot be replayed under another algorithm id), the version, the payload
/// size and the payload's SHA-256.
pub fn manifest_message(alg: SigAlg, fw_version: u32, payload_size: u32, digest: &Digest) -> [u8; MANIFEST_MESSAGE_LEN] {
    let mut m = [0u8; MANIFEST_MESSAGE_LEN];
    m[..12].copy_from_slice(&RSIG_DOMAIN);
    m[12..14].copy_from_slice(&alg.id().to_le_bytes());
    m[14..18].copy_from_slice(&fw_version.to_le_bytes());
    m[18..22].copy_from_slice(&payload_size.to_le_bytes());
    m[22..].copy_from_slice(digest);
    m
}

/// A parsed `RSIG`, borrowed from the bytes it was read from.
#[derive(Clone, Copy, Debug)]
pub struct Rsig<'a> {
    /// The algorithm: always [`SigAlg::CONFIGURED`].
    pub alg: SigAlg,
    /// The id of the key that signed ([`key_id`]).
    pub key_id: &'a [u8; 32],
    /// Size of the payload the signature covers. Signed.
    pub payload_size: u32,
    /// The version it covers: the firmware version, or a patch's `sec_epoch`.
    /// Signed.
    pub fw_version: u32,
    /// The signature.
    pub signature: &'a [u8],
}

impl<'a> Rsig<'a> {
    /// Parse the `RSIG` that starts `data` (anything after it is ignored): its
    /// magic, an algorithm this device accepts, and a signature length that
    /// algorithm has.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < RSIG_FIXED_LEN || data[..4] != RSIG_MAGIC {
            return None;
        }
        let alg = SigAlg::accepted(u16::from_le_bytes([data[4], data[5]]))?;
        let sig_len = u16::from_le_bytes([data[6], data[7]]) as usize;
        if sig_len != alg.sig_len() || data.len() < RSIG_FIXED_LEN + sig_len {
            return None;
        }
        Some(Rsig {
            alg,
            key_id: data[8..40].try_into().ok()?,
            payload_size: u32::from_le_bytes([data[40], data[41], data[42], data[43]]),
            fw_version: u32::from_le_bytes([data[44], data[45], data[46], data[47]]),
            signature: &data[RSIG_FIXED_LEN..RSIG_FIXED_LEN + sig_len],
        })
    }

    /// Bytes the `RSIG` takes: where its payload starts, in a livepatch blob.
    pub fn wire_len(&self) -> usize {
        RSIG_FIXED_LEN + self.signature.len()
    }

    /// Does this `RSIG` name `key` as its signer? A constant-time compare of
    /// the ids: `!=` on them would leak the trusted key's id a byte per boot.
    pub fn names_key(&self, key: &[u8; KEY_LEN]) -> bool {
        ct_eq(self.key_id, &key_id(self.alg.id(), key))
    }

    /// Is this the signature by the trusted key `key` over a payload whose
    /// SHA-256 is `digest`? The signer's id is compared before the signature
    /// is looked at ([`Rsig::names_key`]).
    pub fn verify(&self, key: &[u8; KEY_LEN], digest: &Digest) -> bool {
        self.names_key(key)
            && self.alg.verify(key, &manifest_message(self.alg, self.fw_version, self.payload_size, digest), self.signature)
    }
}

// ---------------------------------------------------------------------------
// DSIG
// ---------------------------------------------------------------------------

/// `DSIG`.
pub const DSIG_MAGIC: [u8; 4] = *b"DSIG";
/// Bytes of a `DSIG` before the signature.
pub const DSIG_FIXED_LEN: usize = 8;
/// The largest `DSIG` file of the configured algorithm.
pub const DSIG_FILE_MAX: usize = DSIG_FIXED_LEN + SIG_LEN;

/// The signature in a `DSIG` file, if `file` is exactly one: the magic, an
/// algorithm this device accepts, and a length that algorithm has. Nothing may
/// follow the signature.
pub fn dsig_signature(file: &[u8]) -> Option<&[u8]> {
    if file.len() < DSIG_FIXED_LEN || file[..4] != DSIG_MAGIC {
        return None;
    }
    let alg = SigAlg::accepted(u16::from_le_bytes([file[4], file[5]]))?;
    let sig_len = u16::from_le_bytes([file[6], file[7]]) as usize;
    (sig_len == alg.sig_len() && file.len() == DSIG_FIXED_LEN + sig_len).then(|| &file[DSIG_FIXED_LEN..])
}
