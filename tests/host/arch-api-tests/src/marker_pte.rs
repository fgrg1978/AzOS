// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The page-marker half of the arch contract (`azos_arch_api::PageMarker`,
//! `Mmu::pte_make_marker`, `Mmu::pte_marker`): the kind codes every ISA stores
//! and the facade maps back, and the round trip through the trait. The encodings
//! themselves have their rows in `tests/host/arch-tests/src/marker_pte.rs`.
//!
//! Canaries (by hand, 2026-10-17; discriminates / does not / did not compile):
//! * `PageMarker::from_code` returning `Compressed` for code 0:
//!   `no_marker_has_code_zero` red.
//! * two kinds sharing a code: `every_kind_has_a_code_of_its_own` red.

use azos_arch_api::PageMarker;

const KINDS: [PageMarker; 3] = [PageMarker::Compressed, PageMarker::Swapped, PageMarker::InTransit];

#[test]
fn every_kind_has_a_code_of_its_own() {
    for (i, a) in KINDS.iter().enumerate() {
        assert_eq!(PageMarker::from_code(a.code()), Some(*a));
        for b in &KINDS[i + 1..] {
            assert_ne!(a.code(), b.code(), "{a:?} and {b:?}");
        }
        // The ISA modules keep the code in two bits.
        assert!(a.code() < 4, "{a:?}");
    }
}

#[test]
fn no_marker_has_code_zero() {
    // Code 0 is the kind field of a word that is not a marker; 4 and above do
    // not fit the field.
    assert_eq!(PageMarker::from_code(0), None);
    for c in 4..=u8::MAX {
        assert_eq!(PageMarker::from_code(c), None, "code {c}");
    }
}
