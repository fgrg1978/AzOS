// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the copy loops of `crates/core/mm/src/uaccess.rs` (front
// uaccess-pin's fast paths): scalar copies, the eight-word run and the
// word-at-a-time string scan must give byte for byte what a plain copy gives,
// at every length and alignment the kernel can pass, across a page boundary.
//
// Canaries (recorded in the front's report, run by hand: a `cfg` canary here
// would be a mutant compiled into the kernel): `has_zero_byte` answering
// `false` fails the string tests (the scan runs past the NUL); `copy_words`
// skipping its tail fails `copy_lengths_and_alignments_match_a_plain_copy`.

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;
use azos_arch_api::PagePerms;

/// An empty user root: a frame of the arena, zeroed, with no region left
/// over from an earlier test whose root had the same address (`pager`).
fn fresh_root() -> usize {
    let pt = azos_mm::pmm::alloc_page().expect("arena").as_usize();
    unsafe { core::ptr::write_bytes(pt as *mut u8, 0, PAGE_SIZE) };
    azos_mm::pager::forget(pt);
    pt
}

/// Two consecutive user pages, so a copy can cross the boundary.
const VA: usize = 0x50_0000;

/// A page table with two fresh frames at [`VA`]; the frames' host addresses.
fn two_pages() -> (usize, [usize; 2]) {
    let pt = fresh_root();
    let mut f = [0usize; 2];
    for (i, fr) in f.iter_mut().enumerate() {
        *fr = azos_mm::pmm::alloc_page().expect("arena").as_usize();
        azos_mm::vmm::map(pt, VA + i * PAGE_SIZE, *fr, PagePerms::USER_RW).expect("map");
    }
    (pt, f)
}

/// The byte at user offset `off` (0 .. 2 pages) through the frames.
fn at(f: &[usize; 2], off: usize) -> *mut u8 {
    (f[off / PAGE_SIZE] + off % PAGE_SIZE) as *mut u8
}

#[test]
fn copy_lengths_and_alignments_match_a_plain_copy() {
    let _g = serial();
    let (pt, f) = two_pages();
    let mut src = [0u8; 600];
    for (i, b) in src.iter_mut().enumerate() {
        *b = (i * 7 + 3) as u8;
    }
    // Offsets near the page end make the copy cross into the second page.
    for base in [0usize, 1, 3, 8, PAGE_SIZE - 300, PAGE_SIZE - 64, PAGE_SIZE - 5] {
        for len in [0usize, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 63, 64, 65, 127, 128, 200, 513] {
            for s in [0usize, 1, 8] {
                // Out: kernel -> user.
                for off in 0..2 * PAGE_SIZE {
                    unsafe { *at(&f, off) = 0xEE };
                }
                assert!(azos_mm::uaccess::copy_out(pt, VA + base, src[s..].as_ptr(), len));
                for k in 0..len {
                    assert_eq!(unsafe { *at(&f, base + k) }, src[s + k], "out base {base} len {len} src+{s} byte {k}");
                }
                assert_eq!(unsafe { *at(&f, base + len) }, 0xEE, "out wrote past the end (base {base} len {len})");
                // In: user -> kernel.
                let mut dst = [0xCCu8; 600];
                assert!(azos_mm::uaccess::copy_in(pt, dst[s..].as_mut_ptr(), VA + base, len));
                assert_eq!(&dst[s..s + len], &src[s..s + len], "in base {base} len {len} dst+{s}");
                assert!(dst[s + len..].iter().all(|&b| b == 0xCC), "in wrote past the end (base {base} len {len})");
            }
        }
    }
}

#[test]
fn a_string_is_found_at_every_offset_and_across_the_page() {
    let _g = serial();
    let (pt, f) = two_pages();
    for base in [0usize, 1, 5, 8, PAGE_SIZE - 20, PAGE_SIZE - 8, PAGE_SIZE - 1] {
        for slen in 0..40usize {
            for off in 0..2 * PAGE_SIZE {
                unsafe { *at(&f, off) = b'x' };
            }
            for k in 0..slen {
                unsafe { *at(&f, base + k) = b'a' + (k % 26) as u8 };
            }
            unsafe { *at(&f, base + slen) = 0 };
            let mut dst = [0xCCu8; 64];
            assert_eq!(azos_mm::uaccess::cstr_in(pt, &mut dst, VA + base), Some(slen), "base {base} len {slen}");
            for k in 0..slen {
                assert_eq!(dst[k], b'a' + (k % 26) as u8);
            }
            assert_eq!(dst[slen], 0);
            // One byte too few for the string and its NUL: refused.
            let mut short = vec![0u8; slen];
            assert_eq!(azos_mm::uaccess::cstr_in(pt, &mut short, VA + base), None, "base {base} len {slen}: no room");
        }
    }
}

#[test]
fn a_string_running_into_an_unmapped_page_is_refused() {
    let _g = serial();
    let pt = fresh_root();
    let fr = azos_mm::pmm::alloc_page().expect("arena").as_usize();
    azos_mm::vmm::map(pt, VA, fr, PagePerms::USER_RW).expect("map");
    unsafe { core::ptr::write_bytes(fr as *mut u8, b'y', PAGE_SIZE) };
    let mut dst = [0u8; 256];
    assert_eq!(azos_mm::uaccess::cstr_in(pt, &mut dst, VA + PAGE_SIZE - 16), None);
    // Control: the NUL inside the page.
    unsafe { *((fr + PAGE_SIZE - 3) as *mut u8) = 0 };
    assert_eq!(azos_mm::uaccess::cstr_in(pt, &mut dst, VA + PAGE_SIZE - 16), Some(13));
}

/// Every pairing of destination and source alignment (the shifted copy's
/// eight cases and the aligned one), both directions, on runs that leave
/// heads and tails of every length.
#[test]
fn every_alignment_pairing_copies_exactly() {
    let _g = serial();
    let (pt, f) = two_pages();
    let mut src = [0u8; 400];
    for (i, b) in src.iter_mut().enumerate() {
        *b = (i * 13 + 5) as u8;
    }
    for ua in 0..8usize {
        for ka in 0..8usize {
            for len in [64usize, 71, 129, 200] {
                for off in 0..2 * PAGE_SIZE {
                    unsafe { *at(&f, off) = 0xEE };
                }
                assert!(azos_mm::uaccess::copy_out(pt, VA + ua, src[ka..].as_ptr(), len));
                for k in 0..len {
                    assert_eq!(unsafe { *at(&f, ua + k) }, src[ka + k], "out user+{ua} kernel+{ka} len {len} byte {k}");
                }
                assert_eq!(unsafe { *at(&f, ua + len) }, 0xEE);
                let mut dst = [0xCCu8; 400];
                assert!(azos_mm::uaccess::copy_in(pt, dst[ka..].as_mut_ptr(), VA + ua, len));
                assert_eq!(&dst[ka..ka + len], &src[ka..ka + len], "in user+{ua} kernel+{ka} len {len}");
                assert_eq!(dst[ka + len], 0xCC);
            }
        }
    }
}
