// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The daemon's two non-I/O decisions: the rate of the records of refused
//! connections, and whether the Domain is short of memory.

use crate::policy::{Pressure, Refusals};

#[test]
fn a_flood_of_refusals_is_one_record_per_window() {
    let mut r = Refusals::new(10_000);
    assert_eq!(r.refused(1_000), Some(1));
    let mut recorded = 0;
    for i in 0..1_000u64 {
        recorded += r.refused(1_001 + i * 5).is_some() as u32; // 5 s of flood
    }
    assert_eq!(recorded, 0);
    // The window ends: the next one carries the held count.
    assert_eq!(r.refused(11_000), Some(1_001));
    assert_eq!(r.refused(11_001), None);
    // At the end of the connection the rest is written, once.
    assert_eq!(r.take_pending(12_000), Some(1));
    assert_eq!(r.take_pending(12_001), None);
}

/// The events a port holds, as the probe drains it.
fn drain(levels: &[u8]) -> impl FnMut() -> Option<u8> + '_ {
    let mut at = 0;
    move || {
        let l = levels.get(at).copied();
        at += 1;
        l
    }
}

#[test]
fn memory_is_short_from_the_warning_level_on() {
    for (level, short) in [(0u8, false), (1, true), (2, true)] {
        let p = Pressure::new();
        assert_eq!(p.short(drain(&[level])), short, "level {level}");
    }
}

/// **Canary.** The kernel reports a CHANGE of level, so an ask that finds the
/// port empty must answer from the level it knew: forget it and the allocator
/// trims once, at the ask that drained the event, and not again while the
/// Domain stays short.
#[test]
fn the_level_is_kept_until_the_next_event() {
    let p = Pressure::new();
    assert!(!p.short(drain(&[])), "nothing was ever reported: normal");
    assert!(p.short(drain(&[1])));
    assert!(p.short(drain(&[])), "still warning: no event since");
    assert!(p.short(drain(&[])));
    assert!(!p.short(drain(&[0])), "back to normal");
    assert!(!p.short(drain(&[])));
}

/// **Canary.** Several events queued between two asks (up and down again)
/// leave the Domain at the last one, not at the highest.
#[test]
fn the_last_of_the_queued_events_is_the_level() {
    let p = Pressure::new();
    assert!(!p.short(drain(&[1, 2, 0])));
    assert!(p.short(drain(&[0, 2, 1])));
}
