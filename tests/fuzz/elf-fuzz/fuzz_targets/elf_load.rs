// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! libFuzzer target: the ELF loader's header walk and per-segment checks.
//!
//! **What is real and what is mirrored.** `load_elf_into`
//! (`crates/core/sched/src/process.rs`) maps every page through `vmm`/`pmm`, which
//! do not build on the host, so the loader itself cannot run here. Its
//! decision function, `elf_bounds::check_pt_load`, is pulled in unchanged
//! (`#[path]`, like `tests/host/sched-wake-tests`). The header reads, the
//! program-header walk and the per-page copy arithmetic around it are
//! restated below from `load_elf`/`load_elf_into` at e8d673e; if those change,
//! this mirror must change with them.
//!
//! Properties asserted for every accepted image:
//!  * every byte the copy loop would read lies inside the blob and inside
//!    the segment's own `[p_offset, p_offset + p_filesz)`;
//!  * every page written lies in `[guard_limit, low_max)`;
//!  * the segment's pages never start below the previous segment's end page
//!    by more than the one page the loader deliberately shares;
//!  * an accepted entry point lies in the file-backed part of an R-X segment.
#![no_main]

#[allow(dead_code)]
#[path = "../../../../crates/core/sched/src/elf_bounds.rs"]
mod elf_bounds;

use elf_bounds::{check_pt_load, SegCheck, SegLimits};
use libfuzzer_sys::fuzz_target;

// `process.rs` / `vmm.rs` at e8d673e.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PAGE_SIZE: usize = 4096;
const LIM: SegLimits = SegLimits { guard_limit: 0x1_0000, low_max: 0x0200_0000, page_size: PAGE_SIZE };
const EM_RISCV: u16 = 0xf3;

fn r16(d: &[u8], o: usize) -> u16 { u16::from_le_bytes([d[o], d[o + 1]]) }
fn r32(d: &[u8], o: usize) -> u32 { u32::from_le_bytes(d[o..o + 4].try_into().unwrap()) }
fn r64(d: &[u8], o: usize) -> u64 { u64::from_le_bytes(d[o..o + 8].try_into().unwrap()) }

fuzz_target!(|elf: &[u8]| {
    if elf.len() < 64 || elf[0..4] != ELF_MAGIC || elf[4] != 2 || elf[5] != 1 { return; }
    if r16(elf, 18) != EM_RISCV { return; }
    let e_entry = r64(elf, 24);
    let e_phoff = r64(elf, 32) as usize;
    let e_phentsize = r16(elf, 54) as usize;
    let e_phnum = r16(elf, 56) as usize;
    if e_phentsize < 56 || e_phnum == 0 { return; }

    let mut prev_seg_end = 0usize;
    let mut prev_page_end = 0usize;
    let mut entry_ok = false;
    for i in 0..e_phnum {
        let Some(ph) = i.checked_mul(e_phentsize).and_then(|x| e_phoff.checked_add(x)) else { return };
        if ph.checked_add(56).map_or(true, |end| end > elf.len()) { return; }
        if r32(elf, ph) != PT_LOAD { continue; }
        let p_flags = r32(elf, ph + 4);
        let p_offset = r64(elf, ph + 8) as usize;
        let p_vaddr = r64(elf, ph + 16) as usize;
        let p_filesz = r64(elf, ph + 32) as usize;
        let p_memsz = r64(elf, ph + 40) as usize;

        let (va_start, va_end) =
            match check_pt_load(p_offset, p_vaddr, p_filesz, p_memsz, elf.len(), prev_seg_end, LIM) {
                SegCheck::Empty => continue,
                SegCheck::Reject(_) => return,
                SegCheck::Load(r) => {
                    assert!(r.seg_end >= prev_seg_end, "segments went backwards");
                    prev_seg_end = r.seg_end;
                    (r.va_start, r.va_end)
                }
            };
        assert!(va_start >= LIM.guard_limit && va_end <= LIM.low_max && va_start < va_end);
        assert_eq!(va_start % PAGE_SIZE, 0);
        assert_eq!(va_end % PAGE_SIZE, 0);
        // Pages may be shared with the previous segment's last page, never more.
        assert!(prev_page_end == 0 || va_start + PAGE_SIZE >= prev_page_end);
        prev_page_end = va_end;

        if p_flags & PF_X != 0 && p_flags & PF_W == 0 {
            let e = e_entry as usize;
            if e >= p_vaddr && e < p_vaddr.saturating_add(p_filesz) { entry_ok = true; }
        }

        // The copy loop, page by page (`load_elf_into`).
        let mut va = va_start;
        while va < va_end {
            let page_end = va.saturating_add(PAGE_SIZE);
            let seg_file_end = p_vaddr.saturating_add(p_filesz);
            let copy_start = va.max(p_vaddr);
            let copy_end = page_end.min(seg_file_end);
            if copy_start < copy_end {
                let dest_off = copy_start - va;
                let seg_off = copy_start - p_vaddr;
                let src_off = p_offset.saturating_add(seg_off);
                let copy_n = copy_end - copy_start;
                if let (Some(src_end), Some(dst_end)) =
                    (src_off.checked_add(copy_n), dest_off.checked_add(copy_n))
                {
                    // The loader skips a copy that fails this guard; for an
                    // ACCEPTED segment it must never have to.
                    assert!(src_end <= elf.len() && dst_end <= PAGE_SIZE, "copy guard tripped");
                    assert!(src_off >= p_offset && src_end <= p_offset + p_filesz);
                    let _ = &elf[src_off..src_end];
                } else {
                    panic!("copy range overflowed for an accepted segment");
                }
            }
            va += PAGE_SIZE;
        }
    }
    if entry_ok {
        // The entry the loader accepts is never in the guard or above the window.
        assert!((e_entry as usize) >= LIM.guard_limit && (e_entry as usize) < LIM.low_max);
    }
});
