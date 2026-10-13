// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the type zones of physical frames, `crates/core/mm/src/zone.rs`
//! and the zoned path of `pmm.rs` (Kconfig `PMM_TYPE_ZONES`; the host always
//! runs with the zones on). The property: a frame that held a type never
//! comes back as another.
//!
//! Canary `zone-share-canary` (pmm.rs `zone_free`): a freed zoned frame loses
//! its tag and goes to the buddy lists, so the cross-type rows go red; the
//! rows that only use one zone stay green, which is what makes the first kind
//! discriminate.

use super::{addr::PhysAddr, frame::*, pmm, zone::*};
use azos_arch::mmu::PAGE_SIZE;
use azos_common::error::KernelError;

const MEGA: usize = 2 * 1024 * 1024;
const PAGES: usize = 1024;
const SIZE: usize = PAGES * PAGE_SIZE;

fn serial() -> std::sync::MutexGuard<'static, ()> {
    super::PMM_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn arena_base() -> usize {
    use std::sync::OnceLock;
    static BASE: OnceLock<usize> = OnceLock::new();
    *BASE.get_or_init(|| {
        let raw = vec![0u8; SIZE + MEGA].leak();
        (raw.as_ptr() as usize + MEGA - 1) & !(MEGA - 1)
    })
}

fn init() {
    let base = arena_base();
    assert!(pmm::init(base, SIZE, base));
}

fn take(z: Zone) -> PhysAddr { pmm::alloc_page_zone(z).expect("the arena has free frames") }

/// Every general page the allocator will give, then back; the pages seen.
fn drain_general() -> Vec<usize> {
    let mut v = Vec::new();
    while let Ok(p) = pmm::alloc_page() { v.push(p.as_usize()); }
    v
}

/// The row the canary turns red: a page-table frame, freed, is not among
/// every general page the allocator can still give.
#[test]
fn a_freed_page_table_frame_is_never_handed_out_as_a_general_page() {
    let _g = serial();
    init();
    let free0 = pmm::free_pages();
    let pt = take(Zone::PageTable);
    pmm::free_page(pt).expect("a zoned frame frees");
    assert_eq!(pmm::free_pages(), free0, "the frame is free, counted by its zone");
    let all = drain_general();
    assert!(!all.contains(&pt.as_usize()), "the freed page-table frame came back as a data page");
    assert_eq!(all.len(), free0 - 1, "every other free frame was given");
}

/// The same row on the descriptor: the frame is tagged and held by its zone,
/// not free, and the zone reports it.
#[test]
fn a_freed_zoned_frame_stays_tagged_and_on_its_zone_list() {
    let _g = serial();
    init();
    let pt = take(Zone::PageTable);
    assert_eq!(pmm::frame_zone(pt.as_usize()), Some(Zone::PageTable));
    assert_eq!(pmm::zone_pages(Zone::PageTable), (0, 1));
    pmm::free_page(pt).unwrap();
    assert_eq!(pmm::frame_zone(pt.as_usize()), Some(Zone::PageTable), "the tag survives the free");
    assert_eq!(pmm::frame_state(pt.as_usize()), Some(F_CACHED), "free, in nobody's buddy list");
    assert_eq!(pmm::zone_pages(Zone::PageTable), (1, 1));
}

/// A zone reuses what it freed, zeroed.
#[test]
fn a_zone_takes_its_own_frame_back_zeroed() {
    let _g = serial();
    init();
    let a = take(Zone::Ring);
    unsafe { core::ptr::write_bytes(a.as_usize() as *mut u8, 0xaa, PAGE_SIZE) };
    pmm::free_page(a).unwrap();
    let b = take(Zone::Ring);
    assert_eq!(a, b, "the zone's own frame is what its next allocation gets");
    let page = unsafe { core::slice::from_raw_parts(b.as_usize() as *const u8, PAGE_SIZE) };
    assert!(page.iter().all(|&x| x == 0), "a reused zoned frame is zeroed");
    assert_eq!(pmm::frame_state(b.as_usize()), Some(F_ALLOCATED));
    assert_eq!(pmm::zone_pages(Zone::Ring), (0, 1), "reuse is not growth");
}

/// A frame never moves between zones either.
#[test]
fn a_frame_never_moves_from_one_zone_to_another() {
    let _g = serial();
    init();
    let pt = take(Zone::PageTable);
    pmm::free_page(pt).unwrap();
    let ring = take(Zone::Ring);
    assert_ne!(ring, pt, "a ring got a freed page-table frame");
    pmm::free_page(ring).unwrap();
    assert_eq!(take(Zone::PageTable), pt);
    assert_eq!(take(Zone::Ring), ring);
}

/// With the buddy lists dry a general allocation refuses while a zone still
/// serves its own frame: the sequestering is what keeps it from the general
/// pool, and also what keeps it available to its type.
#[test]
fn a_zone_serves_its_free_frame_while_the_general_pool_is_dry() {
    let _g = serial();
    init();
    let pt = take(Zone::PageTable);
    pmm::free_page(pt).unwrap();
    let all = drain_general();
    assert_eq!(pmm::alloc_page(), Err(KernelError::OutOfMemory));
    assert_eq!(pmm::alloc_page_zone(Zone::Ring), Err(KernelError::OutOfMemory), "no frame of its own, none in the buddy lists");
    assert_eq!(take(Zone::PageTable), pt);
    for p in all { pmm::free_page(PhysAddr::new(p)).unwrap(); }
}

/// Exhaustion is a refusal, never a panic, and gives back cleanly.
#[test]
fn zone_exhaustion_is_a_refusal_and_frees_make_room() {
    let _g = serial();
    init();
    let free0 = pmm::free_pages();
    let mut held = Vec::new();
    while let Ok(p) = pmm::alloc_page_zone(Zone::PageTable) { held.push(p); }
    assert_eq!(held.len(), free0);
    assert_eq!(pmm::zone_pages(Zone::PageTable), (0, free0), "a failed allocation grew nothing");
    assert_eq!(pmm::alloc_page_zone(Zone::PageTable), Err(KernelError::OutOfMemory));
    for p in held.drain(..) { pmm::free_page(p).unwrap(); }
    assert_eq!(pmm::zone_pages(Zone::PageTable), (free0, free0));
    assert_eq!(pmm::free_pages(), free0, "the zone's free frames are free, not leaked");
    assert_eq!(pmm::alloc_page(), Err(KernelError::OutOfMemory), "yet general allocation cannot take them");
    assert!(pmm::alloc_page_zone(Zone::PageTable).is_ok(), "the zone can");
}

/// A zoned frame on its list is free: freeing it again is a double free.
#[test]
fn a_zoned_frame_cannot_be_freed_twice() {
    let _g = serial();
    init();
    let a = take(Zone::PageTable);
    pmm::free_page(a).unwrap();
    assert_eq!(pmm::free_page(a), Err(KernelError::DoubleFree));
    assert_eq!(pmm::zone_pages(Zone::PageTable), (1, 1));
}

/// A second `init` forgets the zones with the descriptors.
#[test]
fn init_forgets_the_zones() {
    let _g = serial();
    init();
    let a = take(Zone::Ring);
    pmm::free_page(a).unwrap();
    init();
    assert_eq!(pmm::zone_pages(Zone::Ring), (0, 0));
    assert_eq!(pmm::frame_zone(a.as_usize()), None);
}

// ---- the list under the bound (zone.rs, over a fixture table) ----

fn table(n: usize) -> FrameTable {
    let descs: &'static mut [FrameDesc] =
        Vec::from_iter((0..n).map(|_| FrameDesc::new(F_ALLOCATED))).leak();
    unsafe { FrameTable::new(descs.as_ptr(), Pfn(0), n) }
}

/// `PMM_ZONE_MAX_PAGES`: a zone at its bound refuses a new frame but not
/// the reuse of one it holds; a failed allocation gives its place back.
#[test]
fn a_bounded_zone_refuses_growth_and_still_reuses() {
    let t = table(8);
    let mut l = ZoneList::new();
    assert!(l.grow(2));
    assert!(l.grow(2));
    assert!(!l.grow(2), "third frame over a bound of 2");
    assert_eq!(l.total(), 2);
    l.ungrow();
    assert!(l.grow(2), "the place a failed allocation gave back");
    t.at(3).flags.store(F_CACHED, core::sync::atomic::Ordering::Relaxed);
    l.push(&t, 3);
    assert_eq!(l.pooled(), 1);
    assert_eq!(l.pop(&t), Some(t.pfn(3)), "reuse needs no room");
    assert_eq!(l.total(), 2, "reuse is not growth");
    assert_eq!(l.pop(&t), None);
    assert!(l.grow(0) && l.grow(0) && l.grow(0), "0 is no bound");
}

/// The tag round trip, and the values no zone has.
#[test]
fn zone_tags_round_trip_and_zero_is_no_zone() {
    for z in Zone::ALL { assert_eq!(Zone::of_tag(z.tag()), Some(z)); assert_eq!(Zone::ALL[z.index()], z); }
    assert_eq!(Zone::of_tag(0), None);
    assert_eq!(Zone::of_tag(ZONES as u32 + 1), None);
}
