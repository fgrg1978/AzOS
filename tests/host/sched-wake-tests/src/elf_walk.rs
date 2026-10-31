// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The header walk the loader and the fuzz target share
//! (`elf_bounds::{parse_header, SegWalk, page_copy}`), run for the machine types
//! of all three ISAs. Canaries: `elf-machine-canary`, `elf-entry-align-canary`,
//! `elf-page-copy-canary` (gate rows).

use super::elf_bounds::{
    entry_align, page_copy, parse_header, ImageParams, PageCopy, SegLimits, SegReject, SegWalk, WalkReject,
    EM_AARCH64, EM_RISCV, EM_X86_64, PT_GNU_STACK, PT_LOAD, PT_NOTE,
};

const MACHINES: [u16; 3] = [EM_RISCV, EM_AARCH64, EM_X86_64];
const R: u32 = 4;
const RX: u32 = 5;
const RW: u32 = 6;
const ABI_TYPE: u32 = 0x4157;
const ABI_VER: u32 = 7;

fn params(machine: u16, refuse_exec_headers: bool) -> ImageParams {
    ImageParams {
        machine,
        limits: SegLimits { guard_limit: 0x1_0000, low_max: 0x0200_0000, page_size: 4096 },
        refuse_exec_headers,
        abi_note_type: ABI_TYPE,
        abi_version: ABI_VER,
    }
}

/// `(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz)`.
type Ph = (u32, u32, u64, u64, u64, u64);

/// A 64-bit little-endian image of `len` bytes: the ELF header, then the
/// program headers at offset 64.
fn image(machine: u16, entry: u64, phs: &[Ph], len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    b[4] = 2;
    b[5] = 1;
    b[18..20].copy_from_slice(&machine.to_le_bytes());
    b[24..32].copy_from_slice(&entry.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&(phs.len() as u16).to_le_bytes());
    for (i, &(t, f, off, va, fsz, msz)) in phs.iter().enumerate() {
        let o = 64 + i * 56;
        b[o..o + 4].copy_from_slice(&t.to_le_bytes());
        b[o + 4..o + 8].copy_from_slice(&f.to_le_bytes());
        b[o + 8..o + 16].copy_from_slice(&off.to_le_bytes());
        b[o + 16..o + 24].copy_from_slice(&va.to_le_bytes());
        b[o + 32..o + 40].copy_from_slice(&fsz.to_le_bytes());
        b[o + 40..o + 48].copy_from_slice(&msz.to_le_bytes());
    }
    b
}

fn walk(img: &[u8], machine: u16, refuse_exec_headers: bool) -> (Vec<Result<super::elf_bounds::Segment, WalkReject>>, super::elf_bounds::WalkEnd) {
    let hdr = parse_header(img, machine).expect("the header parses");
    let mut w = SegWalk::new(img, img.len(), hdr, params(machine, refuse_exec_headers));
    let segs: Vec<_> = (&mut w).collect();
    (segs, w.finish())
}

/// One text segment at 0x20_0000 holding its file bytes from offset 0x1000.
fn text(machine: u16, entry: u64) -> Vec<u8> {
    image(machine, entry, &[(PT_LOAD, RX, 0x1000, 0x20_0000, 0x100, 0x100)], 0x2000)
}

#[test]
fn a_foreign_machine_is_refused() {
    for m in MACHINES {
        let img = text(m, 0x20_0000);
        for expect in MACHINES {
            assert_eq!(parse_header(&img, expect).is_some(), m == expect, "image {m:#x} read as {expect:#x}");
        }
    }
}

#[test]
fn an_entry_off_the_instruction_alignment_is_accepted_on_x86_only() {
    for m in MACHINES {
        assert_eq!(entry_align(m), if m == EM_X86_64 { 1 } else { 2 });
        let (_, odd) = walk(&text(m, 0x20_0011), m, true);
        assert_eq!(odd.entry_ok, m == EM_X86_64, "odd entry on machine {m:#x}");
        let (_, even) = walk(&text(m, 0x20_0010), m, true);
        assert!(even.entry_ok, "even entry on machine {m:#x}");
    }
}

#[test]
fn the_entry_must_lie_in_the_file_backed_part_of_an_executable_segment() {
    for m in MACHINES {
        // In the zero-filled tail, a writable segment, a read-only one, below the segment.
        let bss = image(m, 0x20_0200, &[(PT_LOAD, RX, 0x1000, 0x20_0000, 0x100, 0x400)], 0x2000);
        assert!(!walk(&bss, m, true).1.entry_ok);
        for flags in [RW, R, 7] {
            let img = image(m, 0x20_0010, &[(PT_LOAD, flags, 0x1000, 0x20_0000, 0x100, 0x100)], 0x2000);
            assert!(!walk(&img, m, true).1.entry_ok, "flags {flags}");
        }
        assert!(!walk(&text(m, 0x1f_fff0), m, true).1.entry_ok);
        assert!(walk(&text(m, 0x20_00fe), m, true).1.entry_ok);
    }
}

#[test]
fn a_truncated_program_table_refuses_the_image() {
    for m in MACHINES {
        let mut img = image(m, 0x20_0000, &[(PT_LOAD, RX, 0x1000, 0x20_0000, 0x100, 0x100)], 0x2000);
        img[56..58].copy_from_slice(&200u16.to_le_bytes()); // 200 headers claimed, the blob ends first
        let (segs, end) = walk(&img, m, false);
        assert_eq!(segs.last(), Some(&Err(WalkReject::ProgramTable)));
        assert_eq!(segs.iter().filter(|s| s.is_ok()).count(), 1, "the segment that fit is yielded, then the refusal");
        assert!(!end.native);
        // An offset that overflows is the same refusal.
        let mut img = text(m, 0x20_0000);
        img[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(walk(&img, m, true).0, vec![Err(WalkReject::ProgramTable)]);
    }
}

#[test]
fn the_walk_stops_at_its_first_refusal() {
    let m = EM_X86_64;
    let img = image(m, 0x20_0000, &[
        (PT_LOAD, RX, 0x1000, 0x20_0000, 0x100, 0x100),
        (PT_LOAD, R, 0x1100, 0x1_0000 - 0x1000, 0x10, 0x10), // below the guard
        (PT_LOAD, R, 0x1200, 0x30_0000, 0x10, 0x10),
    ], 0x2000);
    let (segs, _) = walk(&img, m, true);
    assert_eq!(segs.len(), 2);
    assert!(segs[0].is_ok());
    assert_eq!(segs[1], Err(WalkReject::Segment(SegReject::NullGuard)));
}

#[test]
fn the_abi_note_and_the_stack_request_are_read_from_the_headers() {
    let m = EM_AARCH64;
    let note = |ver: u32| {
        // One note segment at 0x1800: name "AZOS\0", a 4-byte descriptor.
        let mut img = image(m, 0x20_0000, &[
            (PT_LOAD, RX, 0x1000, 0x20_0000, 0x100, 0x100),
            (PT_NOTE, R, 0x1800, 0, 28, 28),
            (PT_GNU_STACK, RW, 0, 0, 0, 0x8000),
        ], 0x2000);
        let at = 0x1800;
        img[at..at + 4].copy_from_slice(&5u32.to_le_bytes());
        img[at + 4..at + 8].copy_from_slice(&4u32.to_le_bytes());
        img[at + 8..at + 12].copy_from_slice(&ABI_TYPE.to_le_bytes());
        img[at + 12..at + 17].copy_from_slice(b"AZOS\0");
        img[at + 20..at + 24].copy_from_slice(&ver.to_le_bytes());
        img
    };
    let (segs, end) = walk(&note(ABI_VER), m, true);
    assert!(segs.iter().all(|s| s.is_ok()));
    assert!(end.native && end.stack_req == 0x8000 && end.entry_ok);
    assert_eq!(walk(&note(ABI_VER + 1), m, true).0.last(), Some(&Err(WalkReject::AbiVersion)));
    // No note is no refusal, and not native.
    let (_, none) = walk(&text(m, 0x20_0000), m, true);
    assert!(!none.native && none.stack_req == 0);
}

#[test]
fn an_executable_segment_over_the_headers_is_refused_only_when_asked() {
    for m in MACHINES {
        // The text segment's file range starts at 0: the ELF header is in it.
        let img = image(m, 0x20_0000, &[(PT_LOAD, RX, 0, 0x20_0000, 0x1000, 0x1000)], 0x2000);
        assert_eq!(walk(&img, m, true).0, vec![Err(WalkReject::Segment(SegReject::ExecMapsHeaders))]);
        assert!(walk(&img, m, false).0.iter().all(|s| s.is_ok()));
    }
}

#[test]
fn a_page_shared_by_segments_mapped_differently_is_refused_by_the_walk() {
    let m = EM_RISCV;
    let img = image(m, 0x20_0000, &[
        (PT_LOAD, RX, 0x1000, 0x20_0000, 0x100, 0x100),
        (PT_LOAD, R, 0x1100, 0x20_0100, 0x10, 0x10),
    ], 0x2000);
    assert_eq!(walk(&img, m, true).0[1], Err(WalkReject::Segment(SegReject::SharedPageMixedPerms)));
}

#[test]
fn a_segment_that_starts_mid_page_is_copied_to_its_offset_in_the_page() {
    // The segment holds file bytes 0x3000.. at 0x2800..0x2c00: the page at 0x2000 gets them at 0x800.
    assert_eq!(page_copy(0x2000, 0x2800, 0x3000, 0x400, 4096, 0x10000), PageCopy::Copy { dest: 0x800, src: 0x3000, n: 0x400 });
    // A segment that runs on into the next page: the second page gets the rest from its start.
    assert_eq!(page_copy(0x2000, 0x2800, 0x3000, 0x1000, 4096, 0x10000), PageCopy::Copy { dest: 0x800, src: 0x3000, n: 0x800 });
    assert_eq!(page_copy(0x3000, 0x2800, 0x3000, 0x1000, 4096, 0x10000), PageCopy::Copy { dest: 0, src: 0x3800, n: 0x800 });
    // No file byte on the page (the segment's zero-filled tail, or a page before it).
    assert_eq!(page_copy(0x4000, 0x2800, 0x3000, 0x1000, 4096, 0x10000), PageCopy::Nothing);
    assert_eq!(page_copy(0x1000, 0x2800, 0x3000, 0x1000, 4096, 0x10000), PageCopy::Nothing);
    // Bytes past the blob, or an overflowing source, are skipped.
    assert_eq!(page_copy(0x2000, 0x2800, 0x3000, 0x400, 4096, 0x3100), PageCopy::Skipped);
    assert_eq!(page_copy(0x2000, 0x2000, usize::MAX - 8, 0x400, 4096, usize::MAX), PageCopy::Skipped);
}
