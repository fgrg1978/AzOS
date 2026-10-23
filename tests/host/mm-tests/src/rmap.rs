// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the frame half of the object-based reverse map: the owner
//! pair of the descriptor (`FrameDesc::owner`, `owner_idx`, `frame.rs`) and
//! its accessors over the real allocator (`pmm::{frame_owner, set_frame_owner,
//! clear_frame_owner_if}`). The object half (the mapping list, revoke, resize,
//! unmap of a frame) lives in `crates/core/ipc/src/memobj.rs` and is tested
//! there (`tests/host/ipc-tests`): this crate does not link the ipc
//! crate.
//!
//! Canary (by hand, 2026-10-16): `clear_owner_if` clearing whatever record it
//! finds (the compare-and-swap replaced by a store) turns
//! `a_clear_by_a_former_holder_leaves_the_new_holders_record` red; the others
//! stay green, which is what makes it discriminate.

use super::{frame::*, pmm};
use azos_arch::mmu::PAGE_SIZE;

const MEGA: usize = 2 * 1024 * 1024;
const PAGES: usize = 1024;
const SIZE: usize = PAGES * PAGE_SIZE;

fn serial() -> std::sync::MutexGuard<'static, ()> {
    super::PMM_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn init() {
    use std::sync::OnceLock;
    static BASE: OnceLock<usize> = OnceLock::new();
    let base = *BASE.get_or_init(|| {
        let raw = vec![0u8; SIZE + MEGA].leak();
        (raw.as_ptr() as usize + MEGA - 1) & !(MEGA - 1)
    });
    assert!(pmm::init(base, SIZE, base));
}

fn take() -> usize {
    pmm::alloc_page().expect("the arena has free frames").as_usize()
}

/// The owner pair filled the two words of padding: the descriptor is still 32
/// bytes, so the reverse map costs no RAM.
#[test]
fn the_owner_pair_fits_in_the_descriptors_padding() {
    assert_eq!(core::mem::size_of::<FrameDesc>(), 32);
    assert_eq!(core::mem::align_of::<FrameDesc>(), 32);
}

/// A new descriptor and a frame just allocated name no object; the record
/// reads back exactly what was written, per frame.
#[test]
fn a_frame_names_the_object_and_the_page_it_was_given() {
    let _g = serial();
    init();
    let f: Vec<usize> = (0..3).map(|_| take()).collect();
    for &p in &f {
        assert_eq!(pmm::frame_owner(p), None, "nobody holds a fresh frame");
    }
    for (i, &p) in f.iter().enumerate() {
        assert!(pmm::set_frame_owner(p, 0x0100_0007, i as u32));
    }
    for (i, &p) in f.iter().enumerate() {
        assert_eq!(pmm::frame_owner(p), Some((0x0100_0007, i as u32)), "page {i}");
    }
    // Another object's frame is its own record.
    let g = take();
    assert!(pmm::set_frame_owner(g, 0x0200_0001, 0));
    assert_eq!(pmm::frame_owner(g), Some((0x0200_0001, 0)));
    assert_eq!(pmm::frame_owner(f[0]), Some((0x0100_0007, 0)), "untouched");
    for &p in f.iter().chain(&[g]) {
        assert!(pmm::clear_frame_owner_if(p, pmm::frame_owner(p).unwrap().0));
        pmm::free_page(super::addr::PhysAddr::new(p)).unwrap();
    }
}

/// Refusals: owner 0 is "none" and cannot be written; a free frame cannot be
/// given a holder; an unaligned or unmanaged address has no record.
#[test]
fn the_accessors_refuse_what_is_not_an_allocated_managed_frame() {
    let _g = serial();
    init();
    let p = take();
    assert!(!pmm::set_frame_owner(p, 0, 0), "0 means no owner");
    assert_eq!(pmm::frame_owner(p), None);
    assert!(!pmm::set_frame_owner(p + 1, 5, 0), "not frame-aligned");
    assert_eq!(pmm::frame_owner(p + 1), None);
    assert!(!pmm::set_frame_owner(usize::MAX & !(PAGE_SIZE - 1), 5, 0), "not managed");
    assert_eq!(pmm::frame_owner(usize::MAX & !(PAGE_SIZE - 1)), None);
    pmm::free_page(super::addr::PhysAddr::new(p)).unwrap();
    assert!(!pmm::set_frame_owner(p, 5, 0), "a free frame has no holder");
    assert_eq!(pmm::frame_owner(p), None);
}

/// The holder lets go with a compare: a former holder's late clear does not
/// erase the record of the object that has the frame now.
#[test]
fn a_clear_by_a_former_holder_leaves_the_new_holders_record() {
    let _g = serial();
    init();
    let p = take();
    assert!(pmm::set_frame_owner(p, 0x0100_0001, 4));
    assert!(!pmm::clear_frame_owner_if(p, 0x0100_0002), "not this object's frame");
    assert_eq!(pmm::frame_owner(p), Some((0x0100_0001, 4)), "the record stayed");
    assert!(pmm::clear_frame_owner_if(p, 0x0100_0001));
    assert_eq!(pmm::frame_owner(p), None);
    assert!(!pmm::clear_frame_owner_if(p, 0x0100_0001), "already clear");
    pmm::free_page(super::addr::PhysAddr::new(p)).unwrap();
}
