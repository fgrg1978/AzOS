// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The monitor ABI (crates/core/hyp-api): ring cursor rules and id ranges.

use azos_hyp_api::*;

fn v(n: u64) -> Violation {
    Violation { kind: Kind::Stage2Fault as u32, pe: 1, syndrome: n, addr: n, aux: 0 }
}

#[test]
fn ring_reads_in_order_and_ends() {
    let mut r: Ring<4> = Ring::new();
    assert_eq!(r.read(0), None);
    r.push(v(1));
    r.push(v(2));
    assert_eq!(r.read(0), Some((1, v(1))));
    assert_eq!(r.read(1), Some((2, v(2))));
    assert_eq!(r.read(2), None);
}

#[test]
fn overwritten_cursor_jumps_to_oldest() {
    let mut r: Ring<4> = Ring::new();
    for n in 0..6 {
        r.push(v(n));
    }
    assert_eq!(r.read(0), Some((3, v(2))));
    assert_eq!(r.read(5), Some((6, v(5))));
}

#[test]
fn ids_and_words_round_trip() {
    assert!(is_monitor_call(CALL_PROBE) && is_monitor_call(CALL_VIOLATION_READ));
    assert!(!is_monitor_call(0xC400_0003) && !is_monitor_call(0x8400_0000));
    let x = v(7);
    assert_eq!(Violation::from_words(x.word1(), x.syndrome, x.addr, x.aux), x);
    assert_eq!(Kind::from_u32(3), Some(Kind::EntryRefused));
    assert_eq!(Kind::from_u32(9), None);
}

fn desc() -> LockDesc {
    LockDesc {
        text: [0x4020_0000, 0x4040_0000],
        rodata: [0x4040_0000, 0x4050_0000],
        ro_after_init: [0x4050_0000, 0x4050_4000],
        ram: [[0x4000_0000, 0x8000_0000], [0; 2], [0; 2], [0; 2], [0; 2], [0; 2], [0; 2], [0; 2]],
        nram: 1,
        secondary_entry: 0x4020_1000,
        sites: 0,
        nsites: 0,
    }
}

#[test]
fn a_well_formed_lock_descriptor_is_taken() {
    assert_eq!(lock_desc_error(&desc(), 0x4060_0000, 0x4080_0000, &[]), None);
}

#[test]
fn a_lock_descriptor_that_could_unlock_anything_is_refused() {
    let hole = (0x4060_0000, 0x4080_0000);
    let mut d = desc();
    d.text[1] = 0x4061_0000;
    assert!(lock_desc_error(&d, hole.0, hole.1, &[]).is_some(), "text over the monitor");
    let mut d = desc();
    d.rodata = [0x4030_0000, 0x4050_0000];
    assert!(lock_desc_error(&d, hole.0, hole.1, &[]).is_some(), "rodata over text");
    let mut d = desc();
    d.secondary_entry = 0x4048_0000;
    assert!(lock_desc_error(&d, hole.0, hole.1, &[]).is_some(), "entry outside text");
    let mut d = desc();
    d.text[0] += 8;
    assert!(lock_desc_error(&d, hole.0, hole.1, &[]).is_some(), "unaligned");
    let mut d = desc();
    d.nram = 0;
    assert!(lock_desc_error(&d, hole.0, hole.1, &[]).is_some(), "no RAM");
    let mut d = desc();
    d.ram[0] = [0x4100_0000, 0x8000_0000];
    assert!(lock_desc_error(&d, hole.0, hole.1, &[]).is_some(), "text outside RAM");
}

#[test]
fn a_text_site_must_be_an_aligned_word_inside_text() {
    let text = [0x4020_0000, 0x4040_0000];
    assert_eq!(text_site_error(&TextSite { pa: 0x4020_1000, off: 1, on: 2 }, text), None);
    assert!(text_site_error(&TextSite { pa: 0x4020_1002, off: 1, on: 2 }, text).is_some());
    assert!(text_site_error(&TextSite { pa: 0x403f_fffe, off: 1, on: 2 }, text).is_some());
    assert!(text_site_error(&TextSite { pa: 0x4040_0000, off: 1, on: 2 }, text).is_some());
}

fn guarded_pages(ranges: &[[u64; 2]]) -> Guarded {
    let mut g = Guarded::new();
    for r in ranges {
        assert!(g.add(r[0], r[1]));
    }
    g
}

const RAM: [[u64; 2]; 1] = [[0x4000_0000, 0x8000_0000]];
const IMAGE: [[u64; 2]; 3] = [[0x4020_0000, 0x4040_0000], [0x4040_0000, 0x4050_0000], [0x4050_0000, 0x4050_4000]];
const HOLE: (u64, u64) = (0x4060_0000, 0x4080_0000);

#[test]
fn a_guard_request_must_be_whole_free_ram_pages() {
    let g = Guarded::new();
    let e = |pa, n, ram: &[[u64; 2]], image: &[[u64; 2]], g: &Guarded| guard_error(pa, n, ram, image, HOLE.0, HOLE.1, g);
    assert_eq!(e(0x4100_0000, 1, &RAM, &IMAGE, &g), None);
    assert_eq!(e(0x4100_0000, GUARD_PAGES_MAX, &RAM, &IMAGE, &g), None);
    assert!(e(0x4100_0000, GUARD_PAGES_MAX + 1, &RAM, &IMAGE, &g).is_some(), "too many pages");
    assert!(e(0x4100_0000, 0, &RAM, &IMAGE, &g).is_some(), "no pages");
    assert!(e(0x4100_0800, 1, &RAM, &IMAGE, &g).is_some(), "unaligned");
    assert!(e(0x4060_0000, 1, &RAM, &IMAGE, &g).is_some(), "the monitor's own page");
    assert!(e(0x405f_f000, 2, &RAM, &IMAGE, &g).is_some(), "straddling the monitor");
    assert!(e(0x4020_0000, 1, &RAM, &IMAGE, &g).is_some(), "kernel text");
    assert!(e(0x4050_0000, 1, &RAM, &IMAGE, &g).is_some(), "ro_after_init");
    assert!(e(0x3fff_f000, 1, &RAM, &IMAGE, &g).is_some(), "below RAM");
    assert!(e(0x7fff_f000, 2, &RAM, &IMAGE, &g).is_some(), "past RAM");
    assert!(e(u64::MAX - 0xfff, 1, &RAM, &IMAGE, &g).is_some(), "wrapping");
    // Before the lock the kernel has named neither RAM nor its image.
    assert_eq!(e(0x4020_0000, 1, &[], &[], &g), None);
    assert!(e(0x4060_0000, 1, &[], &[], &g).is_some(), "the monitor is known before the lock");
}

#[test]
fn a_page_is_guarded_once() {
    let g = guarded_pages(&[[0x4100_0000, 0x4100_1000], [0x4200_0000, 0x4200_2000]]);
    let e = |pa, n| guard_error(pa, n, &RAM, &IMAGE, HOLE.0, HOLE.1, &g);
    assert!(e(0x4100_0000, 1).is_some());
    assert!(e(0x41ff_f000, 2).is_some(), "overlapping the front of a guarded range");
    assert!(e(0x4200_1000, 1).is_some(), "inside a guarded range");
    assert_eq!(e(0x4100_1000, 1), None, "adjacent is free");
    assert_eq!(e(0x4200_2000, 4), None);
}

#[test]
fn the_guard_table_fills_and_gives_back_the_last_range() {
    let mut g = Guarded::new();
    for i in 0..GUARD_RANGES_MAX as u64 {
        assert!(g.add(i * 0x2000, i * 0x2000 + 0x1000));
    }
    assert!(!g.add(0x100_0000, 0x100_1000), "full");
    g.pop();
    assert!(g.add(0x100_0000, 0x100_1000));
    assert!(g.overlaps(0x100_0800, 0x100_0900));
    assert!(!g.overlaps(0x1000, 0x2000));
}

#[test]
fn the_lock_keeps_what_was_guarded_before_it_out_of_the_image() {
    let hole = (0x4060_0000, 0x4080_0000);
    let clear = [[0x4100_0000, 0x4100_1000]];
    assert_eq!(lock_desc_error(&desc(), hole.0, hole.1, &clear), None);
    assert!(lock_desc_error(&desc(), hole.0, hole.1, &[[0x4020_0000, 0x4020_1000]]).is_some(), "guarded text");
    assert!(lock_desc_error(&desc(), hole.0, hole.1, &[[0x9000_0000, 0x9000_1000]]).is_some(), "guarded device range");
}

#[test]
fn the_call_ids_are_distinct_and_in_the_monitor_range() {
    let ids = [
        CALL_PROBE, CALL_VIOLATION_READ, CALL_LOCK_KERNEL_IMAGE, CALL_LOCK_RO_DATA, CALL_TEXT_PATCH, CALL_GUARD_PAGES,
        CALL_PIN, CALL_KEY_ROOT_SET, CALL_KEY_DERIVE, CALL_SMMU_INIT, CALL_SMMU_ATTACH, CALL_SMMU_FLUSH, CALL_SMMU_EVENT, CALL_ITS_INIT, CALL_ITS_MAP_DEVICE, CALL_ITS_MAP_VECTOR,
    ];
    for (i, a) in ids.iter().enumerate() {
        assert!(is_monitor_call(*a));
        assert!(ids[i + 1..].iter().all(|b| a != b), "{a:#x} twice");
    }
}

#[test]
fn every_invariant_has_its_own_bit_and_a_name() {
    let mut seen = 0u64;
    for (bit, name) in INVARIANT_NAMES {
        assert_eq!(bit.count_ones(), 1, "{name}");
        assert_eq!(seen & bit, 0, "{name} shares a bit");
        seen |= bit;
    }
    assert_eq!(seen, INV_EL2_MMU | INV_HOST_S2 | INV_PSCI | INV_IMAGE_RO | INV_EL1_EXEC_TEXT_ONLY | INV_RO_DATA | INV_GUARDED | INV_PINNED | INV_KEY_ROOTS | INV_SMMU | INV_ITS);
    assert_eq!(Kind::from_u32(5), Some(Kind::SysregRefused));
    assert_eq!(Kind::from_u32(6), Some(Kind::DmaFault));
    assert_eq!(Kind::from_u32(7), Some(Kind::MmioRefused));
    assert_eq!(Kind::from_u32(8), None);
}

#[test]
fn an_smmu_window_is_whole_pages_in_the_monitors_device_map_clear_of_it() {
    let (hole, hole_end) = (0x4060_0000, 0x4080_0000);
    let e = |base, size, max_sid| smmu_init_error(base, size, max_sid, hole, hole_end);
    assert_eq!(e(0x0905_0000, 0x2_0000, 255), None, "QEMU virt's unit");
    assert_eq!(e(0x0905_0000, 0x10_0000, 0), None);
    assert!(e(0x0905_0800, 0x2_0000, 1).is_some(), "unaligned");
    assert!(e(0x0905_0000, 0x1_0000, 1).is_some(), "one page of registers is not the unit");
    assert!(e(0x0905_0000, 0x10_1000, 1).is_some(), "more than the monitor maps");
    assert!(e(0x3ffe_0000, 0x4_0000, 1).is_some(), "past the Device gigabyte");
    assert!(e(u64::MAX - 0xfff, 0x2_0000, 1).is_some(), "wrapping");
    assert!(e(0x0905_0000, 0x2_0000, SMMU_STREAMS_MAX).is_some(), "a stream the table cannot hold");
    // Inside the Device gigabyte nothing of the monitor's can be: a hole there is refused.
    assert!(smmu_init_error(0x0905_0000, 0x2_0000, 1, 0x0906_0000, 0x0907_0000).is_some());
}

#[test]
fn a_stream_attach_names_a_stream_a_mode_and_for_stage_one_a_descriptor_in_ordinary_memory() {
    let mut g = Guarded::new();
    assert!(g.add(0x4100_0000, 0x4100_1000));
    let ram = [[0x4000_0000u64, 0x8000_0000u64]];
    let (hole, hole_end) = (0x4060_0000u64, 0x4080_0000u64);
    let e = |sid, mode, cd| smmu_attach_error(16, sid, mode, cd, &ram, hole, hole_end, &g);
    assert_eq!(e(3, SMMU_BLOCK, 0), None);
    assert_eq!(e(3, SMMU_S2_ONLY, 0), None);
    assert_eq!(e(3, SMMU_NESTED, 0x4200_0040), None);
    assert!(e(16, SMMU_BLOCK, 0).is_some(), "no such stream");
    assert!(e(3, 3, 0).is_some(), "no such mode");
    assert!(e(3, SMMU_BLOCK, 0x4200_0000).is_some(), "a descriptor for a stream with no stage 1");
    assert!(e(3, SMMU_NESTED, 0x4200_0020).is_some(), "unaligned");
    assert!(e(3, SMMU_NESTED, 0x4060_0000).is_some(), "the monitor's own memory");
    assert!(e(3, SMMU_NESTED, 0x4100_0000).is_some(), "guarded memory");
    assert!(e(3, SMMU_NESTED, 0x9000_0000).is_some(), "outside RAM");
    assert!(e(3, SMMU_NESTED, u64::MAX - 63).is_some(), "wrapping");
    // Before the lock RAM is unnamed.
    assert_eq!(smmu_attach_error(16, 3, SMMU_NESTED, 0x9000_0000, &[], hole, hole_end, &g), None);
}

#[test]
fn an_its_and_its_redistributors_are_frames_below_the_device_gigabyte_clear_of_the_monitor() {
    let (hole, hole_end) = (0x4060_0000, 0x4080_0000);
    let e = |its, rd, stride, n| its_init_error(its, rd, stride, n, hole, hole_end);
    assert_eq!(e(0x0808_0000, 0x080a_0000, 0x2_0000, 4), None, "QEMU virt's");
    assert_eq!(e(0x0808_0000, 0x080a_0000, 0x4_0000, 64), None, "a GICv4 stride");
    assert!(e(0x0808_8000, 0x080a_0000, 0x2_0000, 4).is_some(), "ITS unaligned");
    assert!(e(0x0808_0000, 0x080a_0000, 0x1_0000, 4).is_some(), "stride under an RD and an SGI frame");
    assert!(e(0x0808_0000, 0x080a_0000, 0x2_8000, 4).is_some(), "stride not a frame multiple");
    assert!(e(0x0808_0000, 0x080a_0000, 0x2_0000, 0).is_some(), "no redistributor");
    assert!(e(0x0808_0000, 0x080a_0000, 0x2_0000, 65).is_some(), "too many");
    assert!(e(0x0808_0000, 0x3ffe_0000, 0x2_0000, 4).is_some(), "past the Device gigabyte");
    assert!(e(0x0808_0000, 0x0808_0000, 0x2_0000, 4).is_some(), "the ITS over the redistributors");
    assert!(e(u64::MAX - 0xffff, 0x080a_0000, 0x2_0000, 4).is_some(), "wrapping");
    assert!(its_init_error(0x0808_0000, 0x080a_0000, 0x2_0000, 4, 0x0809_0000, 0x080b_0000).is_some(), "over the monitor");
}

#[test]
fn a_vector_names_a_mapped_device_an_event_its_itt_holds_and_an_lpi_the_table_covers() {
    let e = |slot, event, lpi| its_vector_error(2, slot, event, lpi, 8192, 16384);
    assert_eq!(e(1, 7, 8192), None);
    assert_eq!(e(0, 0, 16383), None);
    assert!(e(2, 0, 8192).is_some(), "a slot never mapped");
    assert!(e(0, ITS_EVENTS_MAX, 8192).is_some(), "past the ITT");
    assert!(e(0, 0, 8191).is_some(), "an SPI, not an LPI");
    assert!(e(0, 0, 16384).is_some(), "past the table");
}

#[test]
fn only_a_valid_write_fault_on_a_permission_is_a_store_the_monitor_emulates() {
    // ISV 24, SAS 23:22 = 2 (4 bytes), SRT 20:16 = 5, WnR 6, DFSC 0b001111 (permission, level 3).
    let esr = 0x24 << 26 | 1 << 25 | 1 << 24 | 2 << 22 | 5 << 16 | 1 << 6 | 0b001111;
    assert_eq!(mmio_store(esr), Some((4, 5)));
    assert_eq!(mmio_store(esr | 3 << 22), Some((8, 5)));
    assert_eq!(mmio_store(esr & !(3 << 22)), Some((1, 5)));
    assert_eq!(mmio_store((esr & !(0x1f << 16)) | 31 << 16), Some((4, 31)), "the zero register");
    assert_eq!(mmio_store(esr & !(1 << 24)), None, "no syndrome");
    assert_eq!(mmio_store(esr & !(1 << 6)), None, "a load");
    assert_eq!(mmio_store((esr & !0x3f) | 0b000101), None, "a translation fault");
}

#[test]
fn the_two_lpi_table_pointers_of_a_redistributor_are_not_the_hosts_to_write() {
    for off in 0x70..0x80 {
        assert!(rd_write_refused(off), "{off:#x}");
    }
    for off in [0x0, 0x14, 0x6c, 0x80, 0xffff] {
        assert!(!rd_write_refused(off), "{off:#x}");
    }
    assert!(rd_write_refused(0x1_0070 & 0xffff), "the offset is within the 64 KiB frame");
}
