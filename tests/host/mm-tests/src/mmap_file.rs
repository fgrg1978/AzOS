// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the file regions of `crates/core/mm/src/region.rs` (front
//! mmap-file, storage L11 part B): the records a file `mmap` leaves in an
//! address space, as plain data. The fault path that resolves them
//! (`pager.rs`) and the page cache they name (`memobj.rs`) are exercised
//! end to end in `tests/host/syscall-tests/src/mmap_file.rs`; what is here is
//! the arithmetic the rest trusts.
//!
//! * A file region is one piece of one mapping and never folds into a
//!   neighbour (the page cache counts regions), even when the neighbour is the
//!   next pages of the same object with the same permission, where two
//!   anonymous regions would fold.
//! * `file_cut_ok` lets a range take file regions whole and nothing else: a cut
//!   through one (start inside, end inside, or both ends inside) is refused,
//!   anonymous regions in the same range do not matter, and a range clear of a
//!   file region is fine.
//! * A shared file region is not charged: `charged_pages` leaves its pages out
//!   (the cache's frames are system memory) and counts a private file region's
//!   (task-owned copies) like an anonymous one's.
//! * `page_index` of a file region is the object page: `off` plus the distance
//!   from the start, kept by a clip.
//!
//! Canaries (by hand, 2026-10-17; discriminates / does not / did not compile):
//! * `joins` folding file regions: `file_regions_never_fold` red.
//! * `file_cut_ok` always true: `a_cut_takes_file_regions_whole_or_not_at_all` red.
//! * `charged` always true: `a_shared_file_region_is_not_charged` red.
//! * `charged_pages` counting every region: the same row red.
//! * `has_file` answering for regions outside the range: `has_file_looks_only_at_the_range` red.
//! * Does not discriminate: `clip` dropping `shared`/`obj` (`remove_range`'s
//!   remainders are only reached by a cut the pager refuses first; the row
//!   `a_clip_keeps_the_object_page` pins `off`, which a clip computes).
//!
//! Wired into the suite by `mod mmap_file;` in `src/lib.rs`.

#![cfg(test)]

use super::region::{Region, RegionError, RegionSet};

const P: usize = 4096;

fn file(a: usize, b: usize, write: bool, shared: bool, obj: u32, off: usize) -> Region {
    Region::file(a * P, b * P, write, shared, obj, off)
}

fn anon(a: usize, b: usize) -> Region {
    Region::anon(a * P, b * P, true)
}

#[test]
fn file_regions_never_fold() {
    let mut s = RegionSet::<4>::new();
    // The next pages of the same object, same permission, adjacent: two
    // mappings, so two records.
    s.insert(file(10, 12, true, true, 7, 0)).unwrap();
    s.insert(file(12, 14, true, true, 7, 2)).unwrap();
    assert_eq!(s.len(), 2);
    // Private ones neither.
    s.insert(file(20, 22, false, false, 7, 0)).unwrap();
    s.insert(file(22, 24, false, false, 7, 2)).unwrap();
    assert_eq!(s.len(), 4);
    assert_eq!(s.insert(file(30, 31, true, true, 7, 0)), Err(RegionError::Full));
    // Anonymous regions still do.
    let mut a = RegionSet::<4>::new();
    a.insert(anon(10, 12)).unwrap();
    a.insert(anon(12, 14)).unwrap();
    assert_eq!(a.len(), 1);
    // And a protect over file regions leaves them apart.
    s.protect_range(10 * P, 14 * P, false).unwrap();
    assert_eq!(s.len(), 4);
}

#[test]
fn a_cut_takes_file_regions_whole_or_not_at_all() {
    let mut s = RegionSet::<8>::new();
    s.insert(anon(0, 4)).unwrap();
    s.insert(file(10, 14, true, true, 7, 0)).unwrap();
    s.insert(file(20, 24, true, false, 8, 3)).unwrap();
    let ok = |a: usize, b: usize| s.file_cut_ok(a * P, b * P);
    assert!(ok(10, 14), "exactly the region");
    assert!(ok(9, 15), "with room around it");
    assert!(ok(10, 25), "two regions whole");
    assert!(ok(0, 4), "anonymous only");
    assert!(ok(14, 20), "between them");
    assert!(ok(2, 6), "cutting an anonymous region is not this rule's business");
    assert!(!ok(11, 14), "start inside");
    assert!(!ok(10, 13), "end inside");
    assert!(!ok(11, 13), "both ends inside");
    assert!(!ok(12, 22), "one whole, one cut");
    assert!(!ok(0, 11), "anonymous whole, file cut");
}

#[test]
fn a_shared_file_region_is_not_charged() {
    let mut s = RegionSet::<8>::new();
    s.insert(anon(0, 4)).unwrap(); // 4 pages, charged
    s.insert(file(10, 18, true, true, 7, 0)).unwrap(); // 8, the cache's
    s.insert(file(20, 23, true, false, 8, 0)).unwrap(); // 3 private copies, charged
    assert_eq!(s.reserved_pages(), 15);
    assert_eq!(s.charged_pages(), 7);
    assert!(s.as_slice().iter().map(Region::charged).eq([true, false, true]));
}

#[test]
fn has_file_looks_only_at_the_range() {
    let mut s = RegionSet::<8>::new();
    s.insert(anon(0, 4)).unwrap();
    s.insert(file(10, 14, true, true, 7, 0)).unwrap();
    let has = |a: usize, b: usize| s.has_file(a * P, b * P);
    assert!(!has(0, 4));
    assert!(!has(14, 20), "the end is exclusive");
    assert!(!has(0, 10));
    assert!(has(13, 15));
    assert!(has(9, 11));
    assert!(has(0, 100));
}

#[test]
fn a_clip_keeps_the_object_page() {
    let mut s = RegionSet::<8>::new();
    s.insert(file(10, 18, true, true, 7, 5)).unwrap();
    let r = s.find(10 * P).unwrap();
    assert_eq!(r.page_index(10 * P), 5);
    assert_eq!(r.page_index(13 * P + 100), 8);
    // A cut at the front (which the pager refuses for a file region, but the
    // set can do) moves the object page with it.
    s.remove_range(10 * P, 13 * P).unwrap();
    let r = s.find(13 * P).unwrap();
    assert_eq!((r.start, r.off, r.obj, r.shared), (13 * P, 8, 7, true));
}
