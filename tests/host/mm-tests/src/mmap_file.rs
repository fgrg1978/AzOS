// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the file mappings of `crates/core/mm/src/mapping.rs` (front
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
//! * `whole_cut_ok` lets a range take file regions and mappings of a shared
//!   object whole and nothing else: a cut through one (start inside, end
//!   inside, or both ends inside) is refused, anonymous regions in the same
//!   range do not matter, and a range clear of one is fine.
//! * A shared file region or a mapping of a shared object is not charged:
//!   `charged_pages` leaves its pages out (the frames are system memory) and counts a private file region's
//!   (task-owned copies) like an anonymous one's.
//! * `page_index` of a file region is the object page: `off` plus the distance
//!   from the start, kept by a clip.
//!
//! Canaries (by hand; discriminates / does not / did not compile):
//! * `joins` folding file regions: `file_regions_never_fold` red.
//! * `whole_cut_ok` always true: `a_cut_takes_file_regions_whole_or_not_at_all` red.
//! * `charged` always true: `a_shared_file_region_is_not_charged` red.
//! * `charged_pages` counting every region: the same row red.
//! * `has_whole` answering for regions outside the range: `has_whole_looks_only_at_the_range` red.
//! * `joins` folding the neighbouring mappings of one shared object:
//!   `a_shared_object_mapping_never_folds_or_joins_an_anonymous_one` red.
//! * `is_whole` leaving out a shared object's mapping: the cut row and
//!   `has_whole_looks_only_at_the_range` red. `charged` counting it: the charge
//!   row and the fold row red.
//! * Does not discriminate: `clip` dropping `shared`/`obj` (`remove_range`'s
//!   remainders are only reached by a cut the pager refuses first; the row
//!   `a_clip_keeps_the_object_page` pins `off`, which a clip computes).
//!
//! Wired into the suite by `mod mmap_file;` in `src/lib.rs`.

#![cfg(test)]

use super::mapping::{Backing, MapError, MapSet, Mapping};

const P: usize = 4096;

fn file(a: usize, b: usize, write: bool, shared: bool, obj: u32, off: usize) -> Mapping {
    Mapping::file(a * P, b * P, write, shared, obj, off)
}

/// Pages `a..b` of one anonymous object, its page `a` at `a`.
fn anon(a: usize, b: usize) -> Mapping {
    Mapping::anon(a * P, b * P, true, 0x1000, a)
}

#[test]
fn file_regions_never_fold() {
    let mut s = MapSet::<4>::new();
    // The next pages of the same object, same permission, adjacent: two
    // mappings, so two records.
    s.insert(file(10, 12, true, true, 7, 0)).unwrap();
    s.insert(file(12, 14, true, true, 7, 2)).unwrap();
    assert_eq!(s.len(), 2);
    // Private ones neither.
    s.insert(file(20, 22, false, false, 7, 0)).unwrap();
    s.insert(file(22, 24, false, false, 7, 2)).unwrap();
    assert_eq!(s.len(), 4);
    assert_eq!(s.insert(file(30, 31, true, true, 7, 0)), Err(MapError::Full));
    // Anonymous regions still do.
    let mut a = MapSet::<4>::new();
    a.insert(anon(10, 12)).unwrap();
    a.insert(anon(12, 14)).unwrap();
    assert_eq!(a.len(), 1);
    // And a protect over file regions leaves them apart.
    s.protect_range(10 * P, 14 * P, false).unwrap();
    assert_eq!(s.len(), 4);
}

#[test]
fn a_cut_takes_file_regions_whole_or_not_at_all() {
    let mut s = MapSet::<8>::new();
    s.insert(anon(0, 4)).unwrap();
    s.insert(file(10, 14, true, true, 7, 0)).unwrap();
    s.insert(file(20, 24, true, false, 8, 3)).unwrap();
    s.insert(Mapping::obj(30 * P, 34 * P, 9, 0)).unwrap();
    let ok = |a: usize, b: usize| s.whole_cut_ok(a * P, b * P);
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
    assert!(ok(30, 34), "a shared object's mapping, whole");
    assert!(!ok(31, 40), "a shared object's mapping, start inside");
    assert!(!ok(25, 32), "a shared object's mapping, end inside");
}

#[test]
fn a_shared_file_region_is_not_charged() {
    let mut s = MapSet::<8>::new();
    s.insert(anon(0, 4)).unwrap(); // 4 pages, charged
    s.insert(file(10, 18, true, true, 7, 0)).unwrap(); // 8, the cache's
    s.insert(file(20, 23, true, false, 8, 0)).unwrap(); // 3 private copies, charged
    s.insert(Mapping::obj(30 * P, 32 * P, 9, 0)).unwrap(); // 2, the object's
    assert_eq!(s.reserved_pages(), 17);
    assert_eq!(s.charged_pages(), 7);
    assert!(s.as_slice().iter().map(Mapping::charged).eq([true, false, true, false]));
}

#[test]
fn has_whole_looks_only_at_the_range() {
    let mut s = MapSet::<8>::new();
    s.insert(anon(0, 4)).unwrap();
    s.insert(file(10, 14, true, true, 7, 0)).unwrap();
    let has = |a: usize, b: usize| s.has_whole(a * P, b * P);
    assert!(!has(0, 4));
    assert!(!has(14, 20), "the end is exclusive");
    assert!(!has(0, 10));
    assert!(has(13, 15));
    assert!(has(9, 11));
    assert!(has(0, 100));
    let mut o = MapSet::<8>::new();
    o.insert(Mapping::obj(30 * P, 34 * P, 9, 0)).unwrap();
    assert!(o.has_whole(33 * P, 40 * P), "a shared object's mapping counts");
    assert!(o.has_obj(33 * P, 40 * P) && !s.has_obj(0, 100), "and only that is an object's");
    assert!(!o.has_obj(34 * P, 40 * P));
}

#[test]
fn a_shared_object_mapping_never_folds_or_joins_an_anonymous_one() {
    let mut s = MapSet::<8>::new();
    s.insert(Mapping::obj(10 * P, 12 * P, 9, 0)).unwrap();
    s.insert(Mapping::obj(12 * P, 14 * P, 9, 2)).unwrap();
    s.insert(anon(14, 16)).unwrap();
    assert_eq!(s.len(), 3);
    assert_eq!(s.find(11 * P).and_then(|m| m.anon_obj()), None);
    assert!(s.find(11 * P).unwrap().maps_shared_frames());
    assert!(!s.find(15 * P).unwrap().maps_shared_frames());
    // A protect leaves them apart too.
    s.protect_range(10 * P, 14 * P, false).unwrap();
    assert_eq!(s.len(), 3);
}

#[test]
fn a_clip_keeps_the_object_page() {
    let mut s = MapSet::<8>::new();
    s.insert(file(10, 18, true, true, 7, 5)).unwrap();
    let r = s.find(10 * P).unwrap();
    assert_eq!(r.page_index(10 * P), 5);
    assert_eq!(r.page_index(13 * P + 100), 8);
    // A cut at the front (which the pager refuses for a file region, but the
    // set can do) moves the object page with it.
    s.remove_range(10 * P, 13 * P).unwrap();
    let r = s.find(13 * P).unwrap();
    assert_eq!((r.start, r.off, r.backing), (13 * P, 8, Backing::File { obj: 7, shared: true }));
}

// ── Physical ranges (`Backing::Phys`) ────────────────────────────────────────

fn phys(a: usize, b: usize, pa: usize, inherit: bool) -> Mapping {
    Mapping::phys(a * P, b * P, true, pa, azos_arch_api::MemType::Device, inherit)
}

/// A physical range is one piece, goes whole or not at all, is not charged and
/// not folded into a neighbour whose frames are the next ones, and names its
/// frames by the frame number of its start. By hand: `joins`
/// folding two ranges makes the length red; `whole_cut_ok` answering true makes
/// the cut red; `charged` answering true makes the charge red; `has_phys`
/// reading every record makes the last assertion red.
#[test]
fn a_physical_range_goes_whole_and_never_folds() {
    let mut s = MapSet::<4>::new();
    s.insert(phys(10, 12, 0x1000_0000, false)).unwrap();
    s.insert(phys(12, 14, 0x1000_2000, false)).unwrap();
    assert_eq!(s.len(), 2, "two ranges on consecutive frames folded");
    assert!(!s.whole_cut_ok(11 * P, 13 * P), "a cut took a range in part");
    assert!(s.whole_cut_ok(10 * P, 14 * P));
    assert_eq!(s.charged_pages(), 0, "a range was charged to the task");
    assert_eq!(s.find(11 * P).unwrap().page_index(11 * P), (0x1000_0000 >> 12) + 1, "the frame number of the page");
    assert!(s.has_phys(11 * P, 12 * P) && s.has_whole(11 * P, 12 * P));
    assert!(!s.has_phys(14 * P, 15 * P), "a range clear of it");
    s.insert(anon(20, 22)).unwrap();
    assert!(!s.has_phys(20 * P, 22 * P), "an anonymous mapping is not a range");
}

/// What a fork gives the child: the task's own memory and a range that says so,
/// not any other owner's frames. By hand: `inherited` answering
/// `charged` alone makes the range row red; answering true makes the file row red.
#[test]
fn a_fork_inherits_a_range_only_when_it_says_so() {
    assert!(phys(1, 2, 0x1000, true).inherited());
    assert!(!phys(1, 2, 0x1000, false).inherited());
    assert!(anon(1, 2).inherited());
    assert!(file(1, 2, true, false, 7, 0).inherited(), "a private file mapping is the task's own copy");
    assert!(!file(1, 2, true, true, 7, 0).inherited(), "a shared file mapping is the cache's frames");
    assert!(!Mapping::obj(P, 2 * P, 7, 0).inherited());
}
