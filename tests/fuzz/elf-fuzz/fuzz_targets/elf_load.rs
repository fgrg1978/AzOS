// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! libFuzzer target: the ELF loader's header walk and per-segment checks.
//!
//! **What is real.** `elf_bounds.rs` (`crates/core/sched/src/`) is pulled in
//! unchanged (`#[path]`, like `tests/host/sched-wake-tests`), and it holds
//! everything `load_elf_into` (`process.rs`) decides from an image's bytes:
//! `parse_header`, the program-header walk `SegWalk` (segment bounds, page
//! sharing, the executable-headers rule, the entry point, the ABI note and the
//! stack request) and `page_copy`, the per-page copy arithmetic. The loader maps
//! pages through `vmm`/`pmm`, which do not build on the host, so only that
//! mapping is left out. Each input runs under the machine types of all three
//! ISAs and with the executable-headers rule on and off.
//!
//! Properties asserted for every accepted segment:
//!  * every byte the copy loop would read lies inside the blob and inside
//!    the segment's own `[p_offset, p_offset + p_filesz)`, and no copy is skipped;
//!  * every page written lies in `[guard_limit, low_max)`;
//!  * the segment's pages never start below the previous segment's end page
//!    by more than the one page the loader deliberately shares;
//!  * an accepted entry point lies in the file-backed part of an R-X segment,
//!    inside the window, and has its ISA's instruction alignment.
#![no_main]

#[allow(dead_code)]
#[path = "../../../../crates/core/sched/src/elf_bounds.rs"]
mod elf_bounds;

use elf_bounds::{entry_align, fill_runs, page_copy, page_up, parse_header, ImageParams, PageCopy, SegLimits, SegWalk, EM_AARCH64, EM_RISCV, EM_X86_64};
use libfuzzer_sys::fuzz_target;

const PAGE_SIZE: usize = 4096;
const LIM: SegLimits = SegLimits { guard_limit: 0x1_0000, low_max: 0x0200_0000, page_size: PAGE_SIZE };
const PF_X: u32 = 1;
const PF_W: u32 = 2;

fuzz_target!(|elf: &[u8]| {
    for machine in [EM_RISCV, EM_AARCH64, EM_X86_64] {
        for refuse_exec_headers in [false, true] {
            walk(elf, ImageParams { machine, limits: LIM, refuse_exec_headers, abi_note_type: 1, abi_version: 1 });
        }
    }
});

fn walk(elf: &[u8], params: ImageParams) {
    let Some(hdr) = parse_header(elf, params.machine) else { return };
    let mut w = SegWalk::new(elf, elf.len(), hdr, params);
    let mut prev_seg_end = 0usize;
    let mut prev_page_end = 0usize;
    let mut entry_in_text = false;
    let mut accepted = Vec::new();
    for seg in &mut w {
        let Ok(seg) = seg else { return };
        let r = seg.range;
        accepted.push(seg);
        assert!(r.seg_end >= prev_seg_end, "segments went backwards");
        prev_seg_end = r.seg_end;
        assert!(r.va_start >= LIM.guard_limit && r.va_end <= LIM.low_max && r.va_start < r.va_end);
        assert_eq!(r.va_start % PAGE_SIZE, 0);
        assert_eq!(r.va_end % PAGE_SIZE, 0);
        // Pages may be shared with the previous segment's last page, never more.
        assert!(prev_page_end == 0 || r.va_start + PAGE_SIZE >= prev_page_end);
        prev_page_end = r.va_end;

        if seg.flags & PF_X != 0 && seg.flags & PF_W == 0 {
            let e = hdr.entry as usize;
            if e >= seg.vaddr && e < seg.vaddr.saturating_add(seg.filesz) { entry_in_text = true; }
        }

        // Past the last page holding a file byte there is only zero fill.
        let file_pages_end = r.va_end.min(page_up(seg.vaddr.saturating_add(seg.filesz), PAGE_SIZE));
        let mut va = r.va_start;
        while va < file_pages_end {
            match page_copy(va, seg.vaddr, seg.offset, seg.filesz, PAGE_SIZE, elf.len()) {
                PageCopy::Nothing => {}
                PageCopy::Skipped => panic!("the loader would skip the copy of an accepted segment"),
                PageCopy::Copy { dest, src, n } => {
                    assert!(src >= seg.offset && src + n <= seg.offset + seg.filesz && src + n <= elf.len());
                    assert!(dest + n <= PAGE_SIZE);
                    let _ = &elf[src..src + n];
                }
            }
            va += PAGE_SIZE;
        }
    }
    // The streamed fill writes file bytes only inside the accepted segments, in
    // any chunking of the file: never for a `PT_LOAD` that maps no page.
    for chunk in [64usize, PAGE_SIZE, elf.len()] {
        let mut off = 0usize;
        while off < elf.len() {
            let n = chunk.min(elf.len() - off);
            let ok = fill_runs(elf, elf.len(), hdr, params, off, n, |page, in_page, src, len| {
                assert!(len > 0 && in_page + len <= PAGE_SIZE && src + len <= n, "a run leaves its page or its chunk");
                let at = page + in_page;
                let file = off + src;
                assert!(
                    accepted.iter().any(|s| {
                        let d = at.wrapping_sub(s.vaddr);
                        at >= s.range.va_start && at + len <= s.range.va_end
                            && at >= s.vaddr && at + len <= s.vaddr + s.filesz
                            && file == s.offset + d
                    }),
                    "file bytes at {file:#x} were written to {at:#x}, which no accepted segment's file range holds",
                );
                true
            });
            assert!(ok, "the fill refused headers the walk accepted");
            off += n;
        }
    }
    let end = w.finish();
    if end.entry_ok {
        assert!(entry_in_text, "an entry outside every file-backed R-X segment was accepted");
        // The entry the loader accepts is never in the guard or above the window.
        assert!((hdr.entry as usize) >= LIM.guard_limit && (hdr.entry as usize) < LIM.low_max);
        assert_eq!(hdr.entry % entry_align(params.machine), 0);
    }
}
