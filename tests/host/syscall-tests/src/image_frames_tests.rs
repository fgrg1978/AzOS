// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Wave 14 (SPAWNCACHE): a verified image's kept frames (`azos_mm::
// image_frames`) and the table that keeps them (`image_cache`), on the real
// page tables, refcounts and allocator. Included into `mod handlers`.

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;
use azos_arch_api::PagePerms;
use crate::file_ops::ContentStamp;
use crate::image_cache;
use azos_mm::image_frames::{self, KeptImage};

const CODE_VA: usize = 0x1_0000;
const CODE2_VA: usize = 0x1_1000;
const RODATA_VA: usize = 0x1_2000;
const DATA_VA: usize = 0x1_3000;
const END_VA: usize = 0x1_4000;

fn rx() -> PagePerms { PagePerms { accessed: true, ..PagePerms::USER_RX } }
fn ro() -> PagePerms { PagePerms { accessed: true, ..PagePerms::USER_RO } }
fn rw() -> PagePerms { PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW } }

fn root() -> usize {
    let pt = azos_mm::pmm::alloc_page().expect("arena").as_usize();
    azos_mm::pager::forget(pt);
    pt
}

fn filled(seed: u8) -> usize {
    let p = azos_mm::pmm::alloc_page().expect("arena").as_usize();
    let b = unsafe { core::slice::from_raw_parts_mut(azos_mm::addr::phys_to_virt(p) as *mut u8, PAGE_SIZE) };
    for (i, x) in b.iter_mut().enumerate() { *x = (i as u8).wrapping_mul(7).wrapping_add(seed); }
    p
}

fn bytes(p: usize) -> &'static [u8] {
    unsafe { core::slice::from_raw_parts(azos_mm::addr::phys_to_virt(p) as *const u8, PAGE_SIZE) }
}

/// What a loader leaves for a small image: two code pages, a read-only
/// page, a data page. Returns the root and the four frames.
fn loaded() -> (usize, [usize; 4]) {
    let pt = root();
    let f = [filled(1), filled(2), filled(3), filled(4)];
    azos_mm::vmm::map(pt, CODE_VA, f[0], rx()).unwrap();
    azos_mm::vmm::map(pt, CODE2_VA, f[1], rx()).unwrap();
    azos_mm::vmm::map(pt, RODATA_VA, f[2], ro()).unwrap();
    azos_mm::vmm::map(pt, DATA_VA, f[3], rw()).unwrap();
    (pt, f)
}

fn start() -> std::sync::MutexGuard<'static, ()> {
    let g = serial();
    image_cache::shim_forget_frames();
    g
}

/// **A second space built from a kept image shares the code frames and
/// owns copies of everything else.** Code: the same frames, read-execute,
/// one more reference each. Read-only and data pages: new frames with the
/// same bytes and the same permissions; a store to the copy leaves the
/// first space's page as it was.
///
/// **Canary.** `image-share-all-canary` (every page shared): the data page
/// of the second space is the first space's frame.
#[test]
fn a_kept_image_shares_code_and_copies_the_rest() {
    let _g = start();
    let (pt, f) = loaded();
    let pages = image_frames::capture(pt, CODE_VA, END_VA, 64).expect("kept");
    assert_eq!((pages.pages(), pages.shared()), (4, 2));
    let pt2 = root();
    assert_eq!(image_frames::map_into(&pages, pt2), Some(4));
    for (va, frame) in [(CODE_VA, f[0]), (CODE2_VA, f[1])] {
        assert_eq!(azos_mm::vmm::translate_user(pt2, va, false), Some(frame), "code is shared");
        assert_eq!(azos_mm::vmm::page_getref(frame), 3, "first space, the cache, the second space");
    }
    for (va, frame) in [(RODATA_VA, f[2]), (DATA_VA, f[3])] {
        let copy = azos_mm::vmm::translate_user(pt2, va, false).expect("mapped");
        assert_ne!(copy, frame, "not shared");
        assert_eq!(bytes(copy), bytes(frame), "the same bytes");
    }
    assert_eq!(azos_mm::vmm::translate_user(pt2, RODATA_VA, true), None, "read-only stays read-only");
    let d2 = azos_mm::vmm::translate_user(pt2, DATA_VA, true).expect("data is writable");
    unsafe { *(azos_mm::addr::phys_to_virt(d2) as *mut u8) ^= 0xFF; }
    assert_ne!(bytes(d2)[0], bytes(f[3])[0], "a store to the copy is the copy's own");
}

/// **No frame a kept image shares is writable in any space that maps
/// it, and none can be made so.** Every writable page of the second space
/// is its own frame (count 0); a code page refuses a kernel write for the
/// task, a store fault (no copy-on-write break of code), `mprotect`'s
/// permission change and a lease seal's write give-back.
///
/// **Canary.** `image-share-all-canary`: the data page is a shared frame
/// mapped writable.
#[test]
fn shared_text_is_never_writable() {
    let _g = start();
    let (pt, _) = loaded();
    let pages = image_frames::capture(pt, CODE_VA, END_VA, 64).expect("kept");
    let pt2 = root();
    assert_eq!(image_frames::map_into(&pages, pt2), Some(4));
    for va in (CODE_VA..END_VA).step_by(PAGE_SIZE) {
        if let Some(frame) = azos_mm::vmm::translate_user(pt2, va, true) {
            assert_eq!(azos_mm::vmm::page_getref(frame), 0, "a writable page at {va:#x} is shared");
        }
    }
    for va in [CODE_VA, CODE2_VA] {
        assert!(!azos_mm::vmm::user_write_would_be_permitted(pt2, va));
        assert!(azos_mm::vmm::handle_cow_fault(pt2, va).is_err());
        azos_mm::vmm::protect_user_range(pt2, va, va + PAGE_SIZE, true);
        azos_mm::vmm::set_user_range_write(pt2, va, va + PAGE_SIZE, true);
        assert_eq!(azos_mm::vmm::translate_user(pt2, va, true), None, "{va:#x} became writable");
        assert_eq!(azos_mm::vmm::translate_user(pt, va, true), None);
    }
}

/// **Releasing the kept image leaves what tasks map, and nothing leaks.**
/// The code frames survive the release while both spaces map them, and go
/// back with the last space; templates and the record frame go with the
/// release. At the end the allocator holds exactly what it held before.
#[test]
fn release_keeps_what_is_mapped_and_leaks_nothing() {
    let _g = start();
    let before = azos_mm::shim_pages_in_use();
    let (pt, f) = loaded();
    let pages = image_frames::capture(pt, CODE_VA, END_VA, 64).expect("kept");
    let pt2 = root();
    assert_eq!(image_frames::map_into(&pages, pt2), Some(4));
    image_frames::release(pages);
    assert_eq!(azos_mm::vmm::page_getref(f[0]), 2, "both spaces still map it");
    assert_eq!(bytes(f[0])[1], 1u8.wrapping_add(7), "and it still holds the code");
    azos_mm::vmm::destroy_user_pagetable(pt2);
    azos_mm::vmm::destroy_user_pagetable(pt);
    assert_eq!(azos_mm::shim_pages_in_use(), before, "every frame went back");
}

/// **A capture refuses an image over its frame budget, and keeps nothing.**
#[test]
fn a_capture_over_budget_keeps_nothing() {
    let _g = start();
    let (pt, _) = loaded();
    let used = azos_mm::shim_pages_in_use();
    assert!(image_frames::capture(pt, CODE_VA, END_VA, 4).is_none(), "4 pages + records > 4 frames");
    assert_eq!(azos_mm::shim_pages_in_use(), used);
}

fn stamp(epoch: u64, id: u64) -> ContentStamp { ContentStamp { fs: 1, epoch, id, size: 4096 } }

/// **A kept image serves only its own unchanged bytes.** A lookup under a
/// later epoch (any write of the volume, a mount, an unmount) misses and
/// releases it; one pinned at the time goes with its last unpin.
///
/// **Canary.** `digest-cache-stale-canary` (the epoch is ignored): the old
/// frames serve the later epoch.
#[test]
fn kept_frames_follow_the_write_epoch() {
    if image_cache::FRAME_BUDGET == 0 { return; }
    let _g = start();
    let before = azos_mm::shim_pages_in_use();
    let (pt, _) = loaded();
    let pages = image_frames::capture(pt, CODE_VA, END_VA, image_cache::FRAME_BUDGET).expect("kept");
    image_cache::keep_frames(&stamp(5, 3), &[7u8; 32], pages, KeptImage::default());
    assert_eq!(image_cache::frames_held(), (5, 1));
    let pin = image_cache::frames_for(&stamp(5, 3)).expect("the same bytes");
    assert_eq!(pin.digest, [7u8; 32]);
    assert!(image_cache::frames_for(&stamp(6, 3)).is_none(), "the volume was written since");
    assert_eq!(image_cache::frames_held().0, 5, "pinned: still held");
    drop(pin);
    assert_eq!(image_cache::frames_held(), (0, 0), "released by the last unpin");
    azos_mm::vmm::destroy_user_pagetable(pt);
    assert_eq!(azos_mm::shim_pages_in_use(), before);
}

/// **The table is bounded: past its slots the least recently used image
/// goes, and its frames with it.**
#[test]
fn kept_frames_evict_the_least_recently_used() {
    if image_cache::FRAME_BUDGET < 5 * (image_cache::FRAME_SLOTS as u32 + 1) { return; }
    let _g = start();
    let (pt, _) = loaded();
    for id in 0..=image_cache::FRAME_SLOTS as u64 {
        if id == 2 { assert!(image_cache::frames_for(&stamp(9, 0)).is_some()); }
        let pages = image_frames::capture(pt, CODE_VA, END_VA, 64).expect("kept");
        image_cache::keep_frames(&stamp(9, id), &[id as u8; 32], pages, KeptImage::default());
    }
    assert_eq!(image_cache::frames_held(), (5 * image_cache::FRAME_SLOTS as u32, image_cache::FRAME_SLOTS));
    assert!(image_cache::frames_for(&stamp(9, 1)).is_none(), "1 was the least recently used");
    assert!(image_cache::frames_for(&stamp(9, 0)).is_some(), "0 was touched");
    image_cache::drop_frames();
    assert_eq!(image_cache::frames_held(), (0, 0));
}
