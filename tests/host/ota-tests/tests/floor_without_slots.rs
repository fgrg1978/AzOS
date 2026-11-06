// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The epoch floor without the A/B slots (Kconfig `BOOT_SLOTS` off): no floor
//! is raised there, BOOTMETA's nor a backend's, so `floor::trusted` gives none,
//! and never a zero in place of "no floor". Its own test binary, so it starts
//! with no backend installed (the floor's state is process-wide).

use azos_ota_tests::floor;

fn raise(to: u32) -> Option<u32> {
    Some(to)
}

static BACKEND: floor::Backend = floor::Backend { raise };

#[test]
fn without_slots_there_is_no_floor_backend_or_not() {
    assert!(!floor::active());
    // No slots, no backend: no floor, whatever the volume says.
    for stored in [0, 5] {
        assert_eq!(floor::trusted(stored, false), None, "stored {stored}");
    }
    // The slots raise BOOTMETA's floor: it is the floor, a fresh volume's 0 too.
    assert_eq!(floor::trusted(5, true), Some(5));
    assert_eq!(floor::trusted(0, true), Some(0));
    // A backend that holds 7: with the slots the floor is 7 or BOOTMETA's if
    // higher, never the 0 of a volume without a record; without them none, as
    // nothing raises the backend's either.
    floor::install(&BACKEND, 7);
    assert_eq!(floor::trusted(0, true), Some(7));
    assert_eq!(floor::trusted(9, true), Some(9));
    for stored in [0, 9] {
        assert_eq!(floor::trusted(stored, false), None, "stored {stored}");
    }
}
