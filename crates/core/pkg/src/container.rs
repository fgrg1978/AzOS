// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The container: the bytes of a `.azpkg` file and the message its author
//! signs.
//!
//! ```text
//! offset size
//!      0    4  magic "AZPK"
//!      4    2  format (1)
//!      6    2  signature algorithm ([`SigAlg`])
//!      8    2  key_len     the author's public key
//!     10    2  sig_len     the signature
//!     12    4  meta_len    the metadata text ([`crate::meta`])
//!     16    4  rows_len    the rows text: `[task.NAME]` sections in CAPS.TOM syntax
//!     20    4  images_len  the images, back to back, in the metadata's order
//!     24  key_len | sig_len | meta_len | rows_len | images_len
//! ```
//!
//! Every length is checked against the bytes there are, and nothing may follow
//! the last image. The key and the signature are variable-length so that a
//! post-quantum algorithm needs a new [`SigAlg`] (`azos_crypto::sig`, the
//! one registry every signed format shares) and no new container: the device
//! names a key by its id ([`key_id`]), which is 32 bytes whatever the
//! algorithm. The device accepts only the algorithm of its trust anchors
//! ([`SigAlg::CONFIGURED`]).
//!
//! # What is signed
//!
//! Not the file but a 78-byte message ([`message`]): a domain tag, the
//! algorithm, and the SHA-256 of the metadata and of the rows. The images are
//! bound through the metadata, which carries one SHA-256 and one size per
//! image, so the verifier checks the signature before it hashes a megabyte.
//! The algorithm is inside the message so a signature cannot be replayed
//! under another algorithm id, and the domain tag keeps it from being valid
//! as anything else the same key signs (firmware manifests, topologies).

use azos_crypto::sha256::{sha256, Sha256};

/// `AZPK`.
pub const MAGIC: [u8; 4] = *b"AZPK";
/// The only container format.
pub const FORMAT: u16 = 1;
/// Bytes before the key.
pub const HEADER_LEN: usize = 24;
/// The domain tag of the signed message.
pub const DOMAIN: [u8; 12] = *b"azos-pkg-v1\0";
/// Bytes of the signed message: tag, algorithm, two SHA-256 digests.
pub const MESSAGE_LEN: usize = DOMAIN.len() + 2 + 32 + 32;

/// Longest public key a header may declare.
pub use azos_crypto::sig::KEY_LEN_MAX;
/// Longest signature a header may declare.
pub use azos_crypto::sig::SIG_LEN_MAX;
pub use azos_crypto::sig::{key_id, SigAlg};

/// Why the bytes are not a package.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParseError {
    /// Shorter than the header, or than the lengths it declares.
    Short,
    /// Not `AZPK`.
    Magic,
    /// A container format this reader does not know.
    Format(u16),
    /// A length is past its ceiling (`PKG_MAX_KB`, `PKG_META_MAX_KB`,
    /// [`KEY_LEN_MAX`], [`SIG_LEN_MAX`]) or the declared parts do not add up
    /// to the file.
    Length,
}

/// A package, borrowed from the bytes it was read from.
#[derive(Clone, Copy, Debug)]
pub struct Package<'a> {
    /// The signature algorithm id, as written (not yet known to be supported).
    pub alg_id: u16,
    /// The author's public key.
    pub key: &'a [u8],
    /// The signature.
    pub sig: &'a [u8],
    /// The metadata text.
    pub meta: &'a [u8],
    /// The rows text.
    pub rows: &'a [u8],
    /// The images, back to back: all of them for a package from
    /// [`Package::parse`], whatever followed the rows for one from
    /// [`Package::parse_head`].
    pub images: &'a [u8],
    /// The length of the images the header declares.
    pub images_len: usize,
}

fn le16(b: &[u8], at: usize) -> usize {
    u16::from_le_bytes([b[at], b[at + 1]]) as usize
}

fn le32(b: &[u8], at: usize) -> usize {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as usize
}

impl<'a> Package<'a> {
    /// Split `bytes` into the parts its header declares. Nothing is verified:
    /// the parts are still the author's claims. The whole file must be there,
    /// and nothing may follow it.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let p = Self::parse_head(bytes)?;
        if (p.images.len()) != p.images_len {
            return Err(if p.images.len() < p.images_len { ParseError::Short } else { ParseError::Length });
        }
        Ok(p)
    }

    /// [`parse`](Self::parse) of a file read only as far as its rows: the
    /// header, key, signature, metadata and rows are there, the images may be
    /// missing or partial. What the signature covers is all in the head, so a
    /// reader that wants the admission of a package and not its programs (the
    /// installer, listing what is staged) reads a few kilobytes of it.
    pub fn parse_head(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() < HEADER_LEN {
            return Err(ParseError::Short);
        }
        if bytes[..4] != MAGIC {
            return Err(ParseError::Magic);
        }
        let format = le16(bytes, 4) as u16;
        if format != FORMAT {
            return Err(ParseError::Format(format));
        }
        let (alg_id, key_len, sig_len) = (le16(bytes, 6) as u16, le16(bytes, 8), le16(bytes, 10));
        let (meta_len, rows_len, images_len) = (le32(bytes, 12), le32(bytes, 16), le32(bytes, 20));
        let meta_max = azos_limits::PKG_META_MAX_KB as usize * 1024;
        // Each length is below 2^32, so the sum of five fits a u64 and cannot
        // wrap on a 32-bit usize host either.
        let total = HEADER_LEN as u64
            + key_len as u64
            + sig_len as u64
            + meta_len as u64
            + rows_len as u64
            + images_len as u64;
        if total > azos_limits::PKG_MAX_KB as u64 * 1024
            || key_len > KEY_LEN_MAX
            || sig_len > SIG_LEN_MAX
            || meta_len > meta_max
            || rows_len > meta_max
        {
            return Err(ParseError::Length);
        }
        let head = total as usize - images_len;
        if bytes.len() < head {
            return Err(ParseError::Short);
        }
        let (key, rest) = bytes[HEADER_LEN..head].split_at(key_len);
        let (sig, rest) = rest.split_at(sig_len);
        let (meta, rows) = rest.split_at(meta_len);
        Ok(Self { alg_id, key, sig, meta, rows, images: &bytes[head..], images_len })
    }

    /// The algorithm, if it is the one this device trusts
    /// ([`SigAlg::CONFIGURED`]) and the key and signature have the lengths its
    /// keys and signatures have.
    pub fn alg(&self) -> Option<SigAlg> {
        let a = SigAlg::accepted(self.alg_id)?;
        (self.key.len() == a.key_len() && self.sig.len() == a.sig_len()).then_some(a)
    }

    /// The id of the author's key ([`key_id`]).
    pub fn key_id(&self) -> [u8; 32] {
        key_id(self.alg_id, self.key)
    }

    /// The message the author signed.
    pub fn message(&self) -> [u8; MESSAGE_LEN] {
        message(self.alg_id, self.meta, self.rows)
    }

    /// The package's id: the SHA-256 of the signed message and the id of the
    /// author's key, so it names this metadata, these rows (and through them
    /// these images) under this algorithm AND this author, and no other
    /// package: the same bytes signed by another key are another package.
    pub fn id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&self.message());
        h.update(&self.key_id());
        h.finalize()
    }
}

/// The message an author signs: [`DOMAIN`], the algorithm id (2 bytes LE),
/// `sha256(meta)`, `sha256(rows)`. `tools/image/azpkg.py` builds the same bytes.
pub fn message(alg_id: u16, meta: &[u8], rows: &[u8]) -> [u8; MESSAGE_LEN] {
    let mut m = [0u8; MESSAGE_LEN];
    m[..12].copy_from_slice(&DOMAIN);
    m[12..14].copy_from_slice(&alg_id.to_le_bytes());
    m[14..46].copy_from_slice(&sha256(meta));
    m[46..78].copy_from_slice(&sha256(rows));
    m
}
