// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Is this package what one of the device's signers signed?
//!
//! In this order, each step trusting nothing the later ones read:
//!
//! 1. the container's structure ([`Package::parse`]);
//! 2. the algorithm, and the key and signature lengths it allows;
//! 3. the key's id against the topology's `[signer.NAME]` sections: a key the
//!    device does not admit is refused before its signature is looked at;
//! 4. the signature over the 78-byte message;
//! 5. the metadata, parsed ONLY now;
//! 6. the images: their total length, then each one's SHA-256 against the
//!    signed one.
//!
//! Steps 2 to 5 and the length of 6 need only the head of the file
//! ([`verify_head`]); the hashes of the images need the images ([`verify`]).
//! The rows are not read here; [`crate::admit`] reads them.

use azos_crypto::sha256::sha256;
use azos_topology::{SignerSpec, Topology};

use crate::container::Package;
use crate::meta::Meta;
use crate::Refusal;

/// A package whose signer, signature and metadata have checked out (and,
/// from [`verify`], whose images are the signed ones). `'p` is the lifetime of
/// the package's bytes, `'a` the topology's.
#[derive(Clone, Copy, Debug)]
pub struct Verified<'p, 'a> {
    /// The package.
    pub pkg: Package<'p>,
    /// Its metadata, parsed after the signature.
    pub meta: Meta<'p>,
    /// The signer the topology admits it under (a copy: the topology is
    /// then free to take the package's rows).
    pub signer: SignerSpec<'a>,
    /// The signer's index in the topology.
    pub signer_index: usize,
    /// [`Package::id`].
    pub id: [u8; 32],
}

impl<'p> Verified<'p, '_> {
    /// Image `i`'s bytes, if the package was read whole. Offsets follow the
    /// metadata's order.
    pub fn image(&self, i: usize) -> Option<&'p [u8]> {
        let before: u64 = self.meta.images().iter().take(i).map(|m| m.size as u64).sum();
        let len = self.meta.images().get(i)?.size as u64;
        self.pkg.images.get(before as usize..(before + len) as usize)
    }
}

/// Verify the head of `pkg` (everything but the image hashes) against the
/// signers of `topo`.
///
/// The canary features of the crate each skip one step (the signature, the
/// signer lookup, the image hashes); the host suite shows the matching refusal
/// turn into an installed package.
pub fn verify_head<'p, 'a>(pkg: Package<'p>, topo: &Topology<'a>) -> Result<Verified<'p, 'a>, Refusal> {
    let alg = pkg.alg().ok_or(Refusal::Algorithm(pkg.alg_id))?;

    let key_id = pkg.key_id();
    let signer_index = if cfg!(feature = "pkg-signer-canary") {
        0
    } else {
        topo.signers().iter().position(|s| s.key_id == key_id).ok_or(Refusal::UnknownSigner)?
    };
    let signer = *topo.signers().get(signer_index).ok_or(Refusal::UnknownSigner)?;

    if !cfg!(feature = "pkg-verify-skip-canary") && !alg.verify(pkg.key, &pkg.message(), pkg.sig) {
        return Err(Refusal::Signature);
    }

    let meta = Meta::parse(pkg.meta).map_err(Refusal::Meta)?;
    if meta.images_total() != pkg.images_len as u64 {
        return Err(Refusal::Images(meta.images().len() as u16));
    }
    Ok(Verified { pkg, meta, signer, signer_index, id: pkg.id() })
}

/// Verify the whole file `bytes` against the signers of `topo`.
pub fn verify<'p, 'a>(bytes: &'p [u8], topo: &Topology<'a>) -> Result<Verified<'p, 'a>, Refusal> {
    let pkg = Package::parse(bytes).map_err(Refusal::Container)?;
    let v = verify_head(pkg, topo)?;
    if !cfg!(feature = "pkg-image-canary") {
        for (i, img) in v.meta.images().iter().enumerate() {
            let data = v.image(i).ok_or(Refusal::Images(i as u16))?;
            if sha256(data) != img.sha256 {
                return Err(Refusal::Images(i as u16));
            }
        }
    }
    Ok(v)
}
