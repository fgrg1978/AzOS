// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The decision record of an install.
//!
//! An install is an effect on the device: programs that did not run now may,
//! with authority they did not hold. It is written down like every other
//! admission: [`azos_decision::Rule::PackageInstall`], the verdict, the number
//! of rows, and as provenance the package's id (the first eight bytes, in the
//! record's `image_hash_prefix`) and the first row it added.
//!
//! The installer (ring 3) cannot write the kernel's ring, so it keeps its
//! records in the same 104-byte wire form (`ProvenanceRecord::to_bytes`) in an
//! append-only journal on the volume; the kernel writes the same record into
//! its own ring when it applies or refuses the package at boot.

use azos_decision::{ProvenanceRecord, Rule, Verdict};

use crate::admit::Admitted;
use crate::verify::Verified;
use crate::Refusal;

/// The record of package `id` admitted: `rows` rows from `images` images,
/// signer `signer_index` of the topology.
pub fn admitted(v: &Verified<'_, '_>, a: &Admitted, clock_ns: u64) -> ProvenanceRecord {
    let mut p = ProvenanceRecord::new(
        Rule::PackageInstall as u8,
        Verdict::Admit as u8,
        a.rows as u32,
        [v.meta.images().len() as u64, v.signer_index as u64 + 1, 0],
    );
    p.image_hash_prefix = id_prefix(&v.id);
    p.topology_row_id = a.first_row as u32 + 1;
    p.clock_ns = clock_ns;
    p
}

/// The record of a package refused. `id` is the package's id when the
/// container parsed far enough to compute one, else all zero; `signer` is the
/// topology index plus one of the signer that matched, 0 for none.
pub fn refused(id: &[u8; 32], signer: u64, r: &Refusal, clock_ns: u64) -> ProvenanceRecord {
    let mut p = ProvenanceRecord::new(Rule::PackageInstall as u8, Verdict::Refuse as u8, 0, [0, signer, r.code()]);
    p.image_hash_prefix = id_prefix(id);
    p.clock_ns = clock_ns;
    p
}

/// The first eight bytes of an id as a big-endian number, the form
/// `ProvenanceRecord::image_hash_prefix` has.
pub fn id_prefix(id: &[u8; 32]) -> u64 {
    u64::from_be_bytes([id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7]])
}
