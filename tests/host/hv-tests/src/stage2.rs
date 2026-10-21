// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Stage-2 mapping from the frames of a MemObj, on every ISA.

use crate::fakes::{Frames, Mem};
use crate::glue;
use azos_arch_api::{Hypervisor, StageError, StagePerms, STAGE_PAGE};
use azos_hv::stage2::{map_frames, unmap_range};

/// A guest-physical base every ISA's tables can name (below 2^40).
const GPA: u64 = 0x4000_0000;

fn translate(hv: &dyn Hypervisor, s2: &azos_arch_api::Stage2Root, mem: &Mem, gpa: u64) -> Option<(u64, StagePerms)> {
    hv.stage2_translate(s2, mem, gpa)
}

#[test]
fn every_frame_of_the_object_is_mapped_where_the_guest_expects_it() {
    for (isa, hv) in glue::all() {
        let mut mem = Mem::new();
        let s2 = hv.stage2_create(&mut mem).unwrap();
        let src = Frames::new(5, STAGE_PAGE);
        let n = map_frames(&*hv, &s2, &mut mem, GPA, &src, StagePerms::RW).unwrap();
        assert_eq!(n, 5 * STAGE_PAGE, "{isa}");
        for i in 0..5u64 {
            // The first byte, a middle byte and the last byte of the page.
            for off in [0, 0x123, 0xFFF] {
                let (hpa, p) = translate(&*hv, &s2, &mem, GPA + i * STAGE_PAGE + off).unwrap_or_else(|| panic!("{isa}: page {i} unmapped"));
                assert_eq!(hpa, 0x4000_0000 + i * 0x20_0000 + off, "{isa}: page {i}+{off:#x}");
                assert_eq!(p, StagePerms::RW, "{isa}");
            }
        }
        // Nothing past the object, nothing before it.
        assert!(translate(&*hv, &s2, &mem, GPA + 5 * STAGE_PAGE).is_none(), "{isa}: one page too many");
        assert!(translate(&*hv, &s2, &mem, GPA - STAGE_PAGE).is_none(), "{isa}: one page too early");
    }
}

#[test]
fn a_frame_larger_than_a_stage_page_becomes_consecutive_pages() {
    // aarch64's 16 KiB granule: one MemObj frame, four stage-2 pages.
    for (isa, hv) in glue::all() {
        let mut mem = Mem::new();
        let s2 = hv.stage2_create(&mut mem).unwrap();
        let src = Frames::new(2, 4 * STAGE_PAGE);
        assert_eq!(map_frames(&*hv, &s2, &mut mem, GPA, &src, StagePerms::RX).unwrap(), 8 * STAGE_PAGE, "{isa}");
        for p in 0..8u64 {
            let want = 0x4000_0000 + (p / 4) * 0x20_0000 + (p % 4) * STAGE_PAGE;
            let (hpa, perms) = translate(&*hv, &s2, &mem, GPA + p * STAGE_PAGE).unwrap();
            assert_eq!((hpa, perms), (want, StagePerms::RX), "{isa}: page {p}");
        }
    }
}

#[test]
fn permissions_survive_the_trip_through_each_isas_entry() {
    for perms in [StagePerms::RO, StagePerms::RW, StagePerms::RX, StagePerms { write: true, exec: true }] {
        // Fresh implementations per case: the fake keeps its pages.
        for (isa, hv) in glue::all() {
            let mut mem = Mem::new();
            let s2 = hv.stage2_create(&mut mem).unwrap();
            hv.stage2_map(&s2, &mut mem, GPA, 0x8000_0000, perms).unwrap();
            assert_eq!(translate(&*hv, &s2, &mem, GPA), Some((0x8000_0000, perms)), "{isa}: {perms:?}");
        }
    }
}

#[test]
fn a_map_that_runs_out_of_table_memory_leaves_no_page_behind() {
    // The second 2 MiB of the range needs one more leaf table than the cap
    // allows: the call fails at page 512 and the 512 it had mapped go.
    for (isa, hv) in glue::real() {
        let pages_for_first_2m = {
            let mut m = Mem::new();
            let s2 = hv.stage2_create(&mut m).unwrap();
            map_frames(&*hv, &s2, &mut m, GPA, &Frames::new(512, STAGE_PAGE), StagePerms::RW).unwrap();
            m.live_pages()
        };
        let mut mem = Mem::capped(pages_for_first_2m);
        let s2 = hv.stage2_create(&mut mem).unwrap();
        let err = map_frames(&*hv, &s2, &mut mem, GPA, &Frames::new(1024, STAGE_PAGE), StagePerms::RW).unwrap_err();
        assert_eq!(err.err, StageError::NoMemory, "{isa}");
        assert_eq!(err.at, GPA + 512 * STAGE_PAGE, "{isa}: fails at the first page of the second 2 MiB");
        for p in [0u64, 1, 255, 511] {
            assert!(translate(&*hv, &s2, &mem, GPA + p * STAGE_PAGE).is_none(), "{isa}: page {p} was left mapped");
        }
    }
}

#[test]
fn the_fakes_rollback_covers_the_whole_prefix() {
    let hv = crate::fakes::FakeHv::default();
    *hv.fail_after.lock().unwrap() = Some(7);
    let mut mem = Mem::new();
    let s2 = hv.stage2_create(&mut mem).unwrap();
    let err = map_frames(&hv, &s2, &mut mem, GPA, &Frames::new(20, STAGE_PAGE), StagePerms::RW).unwrap_err();
    assert_eq!((err.err, err.at), (StageError::NoMemory, GPA + 7 * STAGE_PAGE));
    for p in 0..20 {
        assert!(hv.stage2_translate(&s2, &mem, GPA + p * STAGE_PAGE).is_none(), "page {p}");
    }
}

#[test]
fn a_second_mapping_of_the_same_page_is_refused_and_changes_nothing() {
    for (isa, hv) in glue::all() {
        let mut mem = Mem::new();
        let s2 = hv.stage2_create(&mut mem).unwrap();
        hv.stage2_map(&s2, &mut mem, GPA, 0x8000_0000, StagePerms::RW).unwrap();
        assert_eq!(hv.stage2_map(&s2, &mut mem, GPA, 0x9000_0000, StagePerms::RX), Err(StageError::Overlap), "{isa}");
        assert_eq!(translate(&*hv, &s2, &mem, GPA), Some((0x8000_0000, StagePerms::RW)), "{isa}");
    }
}

#[test]
fn addresses_are_checked_before_a_table_is_touched() {
    for (isa, hv) in glue::all() {
        let mut mem = Mem::new();
        let s2 = hv.stage2_create(&mut mem).unwrap();
        let src = Frames::new(1, STAGE_PAGE);
        let live = mem.live_pages();
        // Not a page.
        let e = map_frames(&*hv, &s2, &mut mem, GPA + 0x10, &src, StagePerms::RW).unwrap_err();
        assert_eq!(e.err, StageError::Misaligned, "{isa}");
        // Beyond the guest-physical space.
        let e = map_frames(&*hv, &s2, &mut mem, 1u64 << hv.gpa_bits(), &src, StagePerms::RW).unwrap_err();
        assert_eq!(e.err, StageError::OutOfRange, "{isa}");
        // A range that runs off the end of it.
        let e = map_frames(&*hv, &s2, &mut mem, (1u64 << hv.gpa_bits()) - STAGE_PAGE, &Frames::new(2, STAGE_PAGE), StagePerms::RW)
            .unwrap_err();
        assert_eq!(e.err, StageError::OutOfRange, "{isa}");
        // A frame that is not a multiple of the stage page.
        let e = map_frames(&*hv, &s2, &mut mem, GPA, &Frames::new(1, 100), StagePerms::RW).unwrap_err();
        assert_eq!(e.err, StageError::Misaligned, "{isa}");
        assert_eq!(mem.live_pages(), live, "{isa}: a refused call allocated tables");
    }
}

#[test]
fn unmapping_a_range_counts_what_was_there_and_skips_holes() {
    for (isa, hv) in glue::all() {
        let mut mem = Mem::new();
        let s2 = hv.stage2_create(&mut mem).unwrap();
        map_frames(&*hv, &s2, &mut mem, GPA, &Frames::new(4, STAGE_PAGE), StagePerms::RW).unwrap();
        // Pages 1 and 2 of the four, plus two holes around them.
        let n = unmap_range(&*hv, &s2, &mut mem, GPA + STAGE_PAGE, 2 * STAGE_PAGE).unwrap();
        assert_eq!(n, 2, "{isa}");
        assert!(translate(&*hv, &s2, &mem, GPA + STAGE_PAGE).is_none(), "{isa}");
        assert!(translate(&*hv, &s2, &mem, GPA).is_some(), "{isa}: page 0 went too");
        assert!(translate(&*hv, &s2, &mem, GPA + 3 * STAGE_PAGE).is_some(), "{isa}: page 3 went too");
        let n = unmap_range(&*hv, &s2, &mut mem, GPA, 8 * STAGE_PAGE).unwrap();
        assert_eq!(n, 2, "{isa}: only pages 0 and 3 were left");
        assert_eq!(unmap_range(&*hv, &s2, &mut mem, GPA + 1, STAGE_PAGE), Err(StageError::Misaligned), "{isa}");
    }
}

#[test]
fn destroy_gives_back_every_table_page_and_only_those() {
    for (isa, hv) in glue::real() {
        let mut mem = Mem::new();
        let s2 = hv.stage2_create(&mut mem).unwrap();
        // Three regions in different 1 GiB slots: the interior tables differ.
        for base in [GPA, GPA + (3 << 30), GPA + (7 << 30) + (5 << 21)] {
            map_frames(&*hv, &s2, &mut mem, base, &Frames::new(600, STAGE_PAGE), StagePerms::RW).unwrap();
        }
        assert!(mem.live_pages() > 3, "{isa}");
        hv.stage2_destroy(s2, &mut mem);
        assert!(!mem.leaked(), "{isa}: {} table pages leaked", mem.live_pages());
    }
}

#[test]
fn an_ip_range_wider_than_the_hardware_walks_is_out_of_range() {
    for (isa, hv) in glue::real() {
        let mut mem = Mem::new();
        let s2 = hv.stage2_create(&mut mem).unwrap();
        let top = 1u64 << hv.gpa_bits();
        assert_eq!(hv.stage2_map(&s2, &mut mem, top, 0x8000_0000, StagePerms::RW), Err(StageError::OutOfRange), "{isa}");
        // The last page below the limit maps (x86 loses bit 47: its limit is 47).
        hv.stage2_map(&s2, &mut mem, top - STAGE_PAGE, 0x8000_0000, StagePerms::RW).unwrap_or_else(|e| panic!("{isa}: {e:?}"));
    }
}
