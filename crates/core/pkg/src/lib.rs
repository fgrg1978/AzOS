// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Signed application packages (plan D14, Phase 6).
//!
//! A package is images plus a manifest of what they ask for, signed by their
//! AUTHOR. Nothing runs as root because it was installed: the device decides
//! what an author's code may hold, and the install is an effect that is
//! recorded as a decision.
//!
//! ```text
//!   author                          device
//!   ──────                          ──────
//!   images ─┐
//!   rows ───┼─ azpkg build/sign ─►  .azpkg ─► verify ─► admit ─► stage ─► (not built) apply
//!   metadata┘   (Ed25519 today)      │         │          │        │
//!                                     │         │          │        └ files + a receipt
//!                                     │         │          └ the rows are `[task.NAME]`
//!                                     │         │            sections parsed into the
//!                                     │         │            topology and judged by the
//!                                     │         │            same admission as a signed
//!                                     │         │            CAPS.TOM (neverallow too)
//!                                     │         └ the key's id is a `[signer.NAME]` of
//!                                     │           the signed topology; the signature
//!                                     │           verifies; the images hash as signed
//!                                     └ [`container`]: magic, algorithm id,
//!                                       variable-length key and signature
//! ```
//!
//! # The pieces
//!
//! * [`container`]: the file ([`Package::parse`]) and the 78-byte message the
//!   author signs. The algorithm id and the lengths of the key and the
//!   signature are fields, so a post-quantum scheme is a new [`SigAlg`], not a
//!   new format. Unknown algorithm ids are refused.
//! * [`meta`]: the signed metadata: name, version, ABI, hardware classes, the
//!   lowest level of each IDL interface the package calls, the SBOM hash, one
//!   SHA-256 and size per image.
//! * [`verify`]: signature, signer, images. No byte of the metadata or the
//!   rows is interpreted before the signature has verified.
//! * [`admit`]: the package against THIS device: hardware class, ABI, interface
//!   levels, then the rows merged into the topology and judged by
//!   `Topology::admission_check` (neverallow, schedulability, one writer per
//!   motor) and by the signer's ceiling.
//! * [`receipt`]: the decision record of an install, `azos_decision::Rule::
//!   PackageInstall`, with the package id as the provenance hash.
//!
//! # Trust
//!
//! The root is the topology key: the signer table is the `[signer.NAME]`
//! sections of the signed CAPS.TOM, so a package cannot add a signer for
//! itself and a device with no signer admits no package. A signer's ceiling
//! (`warrants`, `rt`, `mem_pages_max`) bounds what ITS packages may ask for; the
//! package's manifest asks, the device's policy decides. The installer service
//! (`userspace/services/pkgd`) runs these checks in ring 3 and stages what
//! passes. **Nothing applies a staged package yet**: the rows join no topology
//! and no image of a package runs. The kernel's boot-time application is not
//! built; when it is, it must repeat [`verify`] and [`admit`] (with the device
//! id and the counter floor, which the ring-3 installer cannot know) and not
//! trust the installer's verdict, because the volume a package is staged on is
//! a file system any writer of the volume can change.
//!
//! # What a package cannot do
//!
//! Hold a `[operator]`, `[pipeline]`, `[class]` or `[signer]` section (only
//! `[task.NAME]` is read); replace a row of the topology (a duplicate name
//! fails admission); carry an image its rows do not start or a row without an
//! image; hold an actuator a `neverallow` rule forbids; or name a file other
//! than a `.ELF` program in the volume root.

#![no_std]
#![deny(missing_docs)]

pub mod admit;
pub mod container;
pub mod meta;
pub mod receipt;
pub mod verify;

pub use admit::{admit, Admitted, Device};
pub use container::{key_id, message, Package, ParseError, SigAlg, MESSAGE_LEN};
pub use meta::{HwClass, Image, Meta, MetaError, MAX_API, MAX_IMAGES};
pub use verify::{verify, verify_head, Verified};

use azos_topology::{AdmissionError, ParseError as RowsError};

/// Why a package was refused. The first check that failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The bytes are not a package.
    Container(ParseError),
    /// The algorithm id is not one this build verifies, or the key or
    /// signature has a length no key or signature of that algorithm has.
    Algorithm(u16),
    /// The author's key is not one of the topology's signers.
    UnknownSigner,
    /// The signature does not verify.
    Signature,
    /// The metadata is malformed.
    Meta(MetaError),
    /// The images are not the length the metadata says, or image `n`'s hash is
    /// not the signed one.
    Images(u16),
    /// The package does not run on this device's hardware class.
    Hardware,
    /// The package was built for another ABI version.
    Abi {
        /// The version it asks for.
        wanted: u32,
        /// This device's.
        have: u32,
    },
    /// Interface `n` of the package's `[api]` is missing here, or older than
    /// the level it needs.
    Api(u16),
    /// The rows hold a section other than `[task.NAME]`.
    ForeignSection,
    /// The rows do not parse into the topology.
    Rows(RowsError),
    /// The rows and the images do not correspond one to one: a row without an
    /// image of its name, an image without a row, or no row at all.
    RowsImages,
    /// Grant `grant` of row `row` is outside the warrant ceiling of the
    /// package's signer.
    OutsideWarrants {
        /// The row, among the rows the package added.
        row: u16,
        /// The grant, in the row.
        grant: u16,
    },
    /// Import `import` of row `row` names an endpoint outside the warrant
    /// ceiling of the package's signer (an import is authority by name).
    OutsideImports {
        /// The row, among the rows the package added.
        row: u16,
        /// The import, in the row.
        import: u16,
    },
    /// Row `row` asks for real-time scheduling and the signer may not.
    RealTime(u16),
    /// Row `row` asks for more frames than the signer's ceiling.
    Frames(u16),
    /// The merged topology is refused by admission.
    Admission(AdmissionError),
}

impl Refusal {
    /// The refusal as one number, for a decision record: bits 24.. the step
    /// (1 container, 2 algorithm, 3 signer, 4 signature, 5 metadata, 6 images,
    /// 7 hardware, 8 ABI, 9 interface level, 10 foreign section, 11 rows,
    /// 12 rows and images, 13 warrants, 14 real time, 15 frames, 16
    /// admission, 17 imports), bits 0..24 the step's own value (the algorithm id, the
    /// image or interface index, the row, the grant).
    pub const fn code(&self) -> u64 {
        let (step, low) = match *self {
            Refusal::Container(_) => (1u64, 0u64),
            Refusal::Algorithm(a) => (2, a as u64),
            Refusal::UnknownSigner => (3, 0),
            Refusal::Signature => (4, 0),
            Refusal::Meta(_) => (5, 0),
            Refusal::Images(i) => (6, i as u64),
            Refusal::Hardware => (7, 0),
            Refusal::Abi { wanted, .. } => (8, wanted as u64 & 0xFF_FFFF),
            Refusal::Api(i) => (9, i as u64),
            Refusal::ForeignSection => (10, 0),
            Refusal::Rows(_) => (11, 0),
            Refusal::RowsImages => (12, 0),
            Refusal::OutsideWarrants { row, grant } => (13, (row as u64) << 12 | (grant as u64 & 0xFFF)),
            Refusal::RealTime(r) => (14, r as u64),
            Refusal::Frames(r) => (15, r as u64),
            Refusal::Admission(_) => (16, 0),
            Refusal::OutsideImports { row, import } => (17, (row as u64) << 12 | (import as u64 & 0xFFF)),
        };
        step << 24 | low
    }
}
