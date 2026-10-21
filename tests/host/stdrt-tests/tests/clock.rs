// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The clock offsets `azos_stdrt::time::clock_now` reads from the vDSO page.
//!
//! `time` issues a trap and builds only for `target_os = "azos"`, but its
//! offset reader is `azos_stdrt::pure::page_clock_offsets` (the source file
//! `azos_libsys::vdso_clock_offsets` calls as well): the magic check and the
//! seqlock read are one function, so this file pins both consumers.

use azos_abi::time::{clock_now_with, ClockId, ClockOffsets, ClockWords};
use azos_stdrt::pure::{page_clock_offsets, VDSO_MAGIC};

const OFFSETS: ClockOffsets = ClockOffsets { real: 1_700_000_000_000_000_000, tai: 1_700_000_037_000_000_000, boot: 5 };

fn published() -> ClockWords {
    let words = ClockWords::new();
    words.update(|_| OFFSETS);
    words
}

/// A mapped page (right magic) hands over what the kernel published.
/// **Canary:** a reader that returned `ZERO` always fails this.
#[test]
fn a_page_with_the_magic_publishes_its_offsets() {
    assert_eq!(page_clock_offsets(VDSO_MAGIC, &published()), OFFSETS);
}

/// A page without the magic is not a page: its words mean nothing, every
/// clock reads as the monotonic one. **Canary:** dropping the magic check
/// fails this (the words are non-zero).
#[test]
fn a_page_without_the_magic_reads_as_zero() {
    let words = published();
    for bad in [0, VDSO_MAGIC ^ 1, u32::MAX] {
        assert_eq!(page_clock_offsets(bad, &words), ClockOffsets::ZERO, "magic {bad:#x}");
    }
}

/// `clock_now` is `clock_now_with` over this reader and the monotonic clock:
/// REAL, TAI and BOOT are MONO plus the published word, MONO reads none.
#[test]
fn the_clocks_are_mono_plus_the_published_word() {
    let words = published();
    let at = |id| clock_now_with(id, || 10, || page_clock_offsets(VDSO_MAGIC, &words)).unwrap();
    assert_eq!(at(ClockId::MONO), 10);
    assert_eq!(at(ClockId::REAL), 10 + OFFSETS.real);
    assert_eq!(at(ClockId::TAI), 10 + OFFSETS.tai);
    assert_eq!(at(ClockId::BOOT), 15);
}
