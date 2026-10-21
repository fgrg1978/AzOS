// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The not-present page markers (`azos_arch_api::PageMarker`) in each ISA's own
//! encoding: riscv64 (RSW bit 8), aarch64 (software bit 57), x86_64 (available
//! bit 11). The kernel's own `mmu` files are pulled in, not copies.
//!
//! What has to hold, per ISA: a marker is never valid (the walker would
//! translate it), is never a demand reservation or an empty word (the fault
//! path would take it for a zero page or a reservation), and carries its kind
//! and 32-bit payload back exactly, for every kind and for payloads at the
//! edges. A wrong bit is silent until a fault reads the page's contents from
//! the wrong place.
//!
//! Canaries (by hand, 2026-10-17; discriminates / does not / did not compile):
//! * riscv64 `marker_of` not testing the DEMAND bit: `a_marker_is_never_a_demand_word_or_a_leaf` red.
//! * riscv64 kind code placed at bits 3:1 (R/W/X): `riscv64_markers_are_not_leaves_even_without_the_valid_bit` red.
//! * aarch64 `marker_of` not testing `VALID`: `a_marker_is_never_valid` red (a valid
//!   descriptor with the flag bit decodes as a marker).
//! * aarch64 payload shifted into bits 63:32 (over the software bits): `the_payload_does_not_touch_the_software_bits` red.
//! * x86_64 payload stored not inverted: `x86_64_payload_is_inverted_and_guarded` red.
//! * x86_64 guard bits dropped: the same row red.
//! * any ISA's `make_marker` masking the payload to 31 bits: `every_kind_and_payload_round_trips` red.
//! * riscv64 or aarch64 `is_cow` not testing VALID: `a_marker_is_not_cow` red (x86_64 cannot discriminate: its marker never sets the bit).
//! * any ISA's `is_cow` returning false for a valid COW leaf: `a_marker_is_not_cow` red.
//! * any ISA accepting kind code 0 in `marker_of`: `code_zero_is_no_marker` red.

use azos_arch_api::{PageMarker, PagePerms};

const KINDS: [PageMarker; 3] = [PageMarker::Compressed, PageMarker::Swapped, PageMarker::InTransit];
const PAYLOADS: [u32; 8] = [0, 1, 2, 0x1234_5678, 0x7FFF_FFFF, 0x8000_0000, 0xDEAD_BEEF, u32::MAX];

/// One ISA's marker functions, as the facade's `Mmu` impl calls them.
struct Isa {
    name: &'static str,
    make: fn(u8, u32) -> u64,
    of: fn(u64) -> Option<(u8, u32)>,
    valid: fn(u64) -> bool,
    is_cow: fn(u64) -> bool,
    /// The software bit a COW-shared leaf is marked with.
    cow_bit: u64,
    demand: fn(u64) -> bool,
    /// The software bit a demand reservation is marked with.
    demand_bit: u64,
    /// A valid user leaf and a demand reservation, as the ISA builds them.
    leaf: fn() -> u64,
    reservation: fn() -> u64,
}

fn rv_leaf() -> u64 {
    crate::mmu::Pte::new(0x8020_0000, crate::mmu::PteFlags::USER_RW).0
}

fn rv_reservation() -> u64 {
    crate::mmu::PteFlags::DEMAND.bits() | (crate::mmu::PteFlags::READ | crate::mmu::PteFlags::WRITE | crate::mmu::PteFlags::USER).bits()
}

fn a64_leaf() -> u64 {
    crate::aarch64_mmu::make_leaf(0x4020_0000, PagePerms::USER_RW, 0).unwrap()
}

fn a64_reservation() -> u64 {
    crate::aarch64_mmu::make_demand(PagePerms::USER_RW).unwrap()
}

fn x86_leaf() -> u64 {
    crate::x86_paging::mmu::make_leaf(0x4020_0000, PagePerms::USER_RW, 0).unwrap()
}

fn x86_reservation() -> u64 {
    crate::x86_paging::mmu::make_demand(PagePerms::USER_RW)
}

fn isas() -> [Isa; 3] {
    [
        Isa {
            name: "riscv64",
            make: crate::mmu::make_marker,
            of: crate::mmu::marker_of,
            valid: |w| crate::mmu::Pte(w).is_valid(),
            is_cow: crate::mmu::is_cow,
            cow_bit: 1 << 8,
            demand: |w| w & crate::mmu::PteFlags::DEMAND.bits() != 0,
            demand_bit: 1 << 9,
            leaf: rv_leaf,
            reservation: rv_reservation,
        },
        Isa {
            name: "aarch64",
            make: crate::aarch64_mmu::make_marker,
            of: crate::aarch64_mmu::marker_of,
            valid: crate::aarch64_mmu::is_valid,
            is_cow: crate::aarch64_mmu::is_cow,
            cow_bit: 1 << 55,
            demand: crate::aarch64_mmu::is_demand,
            demand_bit: 1 << 58,
            leaf: a64_leaf,
            reservation: a64_reservation,
        },
        Isa {
            name: "x86_64",
            make: crate::x86_paging::mmu::make_marker,
            of: crate::x86_paging::mmu::marker_of,
            valid: crate::x86_paging::mmu::is_valid,
            is_cow: crate::x86_paging::mmu::is_cow,
            cow_bit: 1 << 9,
            demand: crate::x86_paging::mmu::is_demand,
            demand_bit: 1 << 10,
            leaf: x86_leaf,
            reservation: x86_reservation,
        },
    ]
}

#[test]
fn every_kind_and_payload_round_trips() {
    for isa in isas() {
        for k in KINDS {
            for p in PAYLOADS {
                let w = (isa.make)(k.code(), p);
                let (code, payload) = (isa.of)(w).unwrap_or_else(|| panic!("{}: {k:?}/{p:#x} does not decode", isa.name));
                assert_eq!(PageMarker::from_code(code), Some(k), "{}: kind of {k:?}/{p:#x}", isa.name);
                assert_eq!(payload, p, "{}: payload of {k:?}", isa.name);
            }
        }
    }
}

#[test]
fn a_marker_is_never_valid() {
    for isa in isas() {
        for k in KINDS {
            for p in PAYLOADS {
                assert!(!(isa.valid)((isa.make)(k.code(), p)), "{}: {k:?}/{p:#x} would be translated", isa.name);
            }
        }
    }
}

#[test]
fn a_marker_is_never_a_demand_word_or_a_leaf() {
    for isa in isas() {
        for k in KINDS {
            for p in PAYLOADS {
                let w = (isa.make)(k.code(), p);
                assert!(!(isa.demand)(w), "{}: {k:?}/{p:#x} reads as a demand reservation", isa.name);
                assert_ne!(w, 0, "{}: a marker is not the empty word", isa.name);
            }
        }
        // The flag alone is not enough: with the valid bit it is a leaf (the
        // walker would translate it), with the demand bit a reservation.
        let m = (isa.make)(PageMarker::Compressed.code(), 5);
        assert!((isa.demand)(m | isa.demand_bit), "{}: the demand bit is the one named", isa.name);
        assert_eq!((isa.of)(m | isa.demand_bit), None, "{}: flag + demand", isa.name);
        assert_eq!((isa.of)(m | 1), None, "{}: flag + valid", isa.name);
        // And the other way: the words the pager meets next to markers are not
        // markers.
        assert_eq!((isa.of)(0), None, "{}: empty", isa.name);
        assert_eq!((isa.of)((isa.leaf)()), None, "{}: a valid leaf", isa.name);
        assert_eq!((isa.of)((isa.reservation)()), None, "{}: a demand reservation", isa.name);
    }
}

#[test]
fn kinds_are_told_apart() {
    for isa in isas() {
        for p in PAYLOADS {
            let w: Vec<u64> = KINDS.iter().map(|k| (isa.make)(k.code(), p)).collect();
            assert!(w[0] != w[1] && w[1] != w[2] && w[0] != w[2], "{}: payload {p:#x}", isa.name);
        }
        // Same kind, other payload: another word (the generation is what keeps
        // a restore from reading another store's copy).
        for k in KINDS {
            assert_ne!((isa.make)(k.code(), 1), (isa.make)(k.code(), 2), "{}: {k:?}", isa.name);
        }
    }
}

#[test]
fn code_zero_is_no_marker() {
    for isa in isas() {
        // The flag set, the kind field zero: not one of ours.
        let w = (isa.make)(PageMarker::Compressed.code(), 5);
        let cleared = {
            let kinds = (isa.make)(PageMarker::Compressed.code(), 5) ^ (isa.make)(0, 5);
            w ^ kinds
        };
        assert_eq!((isa.of)(cleared), None, "{}", isa.name);
    }
}

#[test]
fn the_codes_are_the_enums() {
    for k in KINDS {
        assert_eq!(PageMarker::from_code(k.code()), Some(k));
        assert_ne!(k.code(), 0);
    }
    assert_eq!(PageMarker::from_code(0), None);
    assert_eq!(PageMarker::from_code(4), None);
}

/// The COW bit of a leaf is the software bit a marker reuses (riscv64: the
/// flag itself, aarch64: the kind field), so a caller that reads the word
/// without checking validity first (a walker's `user_leaf`) must not take a
/// marker for a COW-shared page and copy a frame that is not there.
#[test]
fn a_marker_is_not_cow() {
    for isa in isas() {
        for k in KINDS {
            for p in PAYLOADS {
                let w = (isa.make)(k.code(), p);
                assert!(!(isa.is_cow)(w), "{}: {k:?}/{p:#x} reads as a COW-shared leaf", isa.name);
            }
        }
        // The check is not too strict: a valid leaf is COW exactly with the bit.
        assert!(!(isa.is_cow)((isa.leaf)()), "{}: a plain leaf is not COW", isa.name);
        assert!((isa.is_cow)((isa.leaf)() | isa.cow_bit), "{}: a COW-shared leaf is COW", isa.name);
    }
}

/// RISC-V: `Pte::is_leaf` does not look at V (it tests R/W/X), so a marker
/// that put its kind in those bits would read as a leaf wherever a caller
/// asks `is_leaf` before `is_valid`.
#[test]
fn riscv64_markers_are_not_leaves_even_without_the_valid_bit() {
    for k in KINDS {
        for p in PAYLOADS {
            let w = crate::mmu::make_marker(k.code(), p);
            assert!(!crate::mmu::Pte(w).is_leaf(), "{k:?}/{p:#x}");
            // RSW bit 8 is the flag, bit 9 (DEMAND) is clear.
            assert_eq!(w & (1 << 8), 1 << 8);
            assert_eq!(w & (1 << 9), 0);
        }
    }
}

/// aarch64: bits 58:55 are the software bits (COW 55, dirty 56, marker flag
/// 57, demand 58), and the output-address field is where the payload sits.
#[test]
fn the_payload_does_not_touch_the_software_bits() {
    for k in KINDS {
        for p in PAYLOADS {
            let w = crate::aarch64_mmu::make_marker(k.code(), p);
            assert_eq!(w & 1, 0, "VALID clear");
            assert_eq!(w & (1 << 57), 1 << 57, "flag is software bit 57");
            assert_eq!(w & (1 << 58), 0, "DEMAND bit clear");
            // The payload sits in bits 47:16: nothing above bit 47 except the kind and the flag.
            assert_eq!(w & !((1u64 << 48) - 1) & !(0b11 << 55) & !(1 << 57), 0, "{k:?}/{p:#x}");
        }
    }
}

/// x86_64: the address field of a non-present entry never names real memory
/// (the L1 Terminal Fault answer): the payload is stored inverted with bits
/// 51:44 set.
#[test]
fn x86_64_payload_is_inverted_and_guarded() {
    use crate::x86_paging::mmu::{make_marker, PHYS_MASK};
    for k in KINDS {
        for p in PAYLOADS {
            let w = make_marker(k.code(), p);
            assert_eq!(w & 1, 0, "P clear");
            assert_eq!(w & (1 << 11), 1 << 11, "flag is available bit 11");
            assert_eq!(w & (1 << 10), 0, "DEMAND bit clear");
            let addr = w & PHYS_MASK;
            assert_eq!(addr >> 44, 0xFF, "bits 51:44 are set");
            // A small payload inverts to an address in the top of the 52-bit
            // space: no RAM there.
            if p < 0x1000_0000 {
                assert!(addr > (1u64 << 51), "{p:#x} names {addr:#x}");
            }
            assert_eq!((addr >> 12) & 0xFFFF_FFFF, u64::from(!p), "inverted payload");
        }
    }
}
