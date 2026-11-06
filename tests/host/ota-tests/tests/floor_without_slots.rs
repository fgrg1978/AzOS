// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The epoch floor without the A/B slots (Kconfig `BOOT_SLOTS` off): BOOTMETA's
//! floor is never raised there, so `floor::trusted` gives a floor only where a
//! backend holds it, and never a zero in place of "no floor". Its own test
//! binary, so it starts with no backend installed (the floor's state is
//! process-wide).

use azos_ota_tests::floor;

fn raise(to: u32) -> Option<u32> {
    Some(to)
}

static BACKEND: floor::Backend = floor::Backend { raise };

#[test]
fn without_slots_the_floor_is_the_backends_or_none() {
    assert!(!floor::active());
    // No slots, no backend: no floor, whatever the volume says.
    for stored in [0, 5] {
        assert_eq!(floor::trusted(stored, false), None, "stored {stored}");
    }
    // The slots raise BOOTMETA's floor: it is the floor, a fresh volume's 0 too.
    assert_eq!(floor::trusted(5, true), Some(5));
    assert_eq!(floor::trusted(0, true), Some(0));
    // A backend that holds 7: the floor is 7 or BOOTMETA's if higher, with or
    // without the slots; never the 0 of a volume without a record.
    floor::install(&BACKEND, 7);
    for raised in [false, true] {
        assert_eq!(floor::trusted(0, raised), Some(7), "raised {raised}");
        assert_eq!(floor::trusted(9, raised), Some(9), "raised {raised}");
    }
}
