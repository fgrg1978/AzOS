// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SEC-HIGH (audit A.1): a region's reference count must not wrap into a free
//! while a holder still maps the frames (the OpenBSD `shm_nattch` class).
//!
//! The count used to be a `u32` mirror of the holders' `refs`, bumped with an
//! unguarded `fetch_add`, and the frames were freed when it read `0`. Two
//! holders past 2^31 acquires each wrapped it. The count is now the holders'
//! sum taken in `u64` (`memobj::total_refs`); these tests start the holders
//! near `u32::MAX` through `__memobj_set_refs_for_tests`.
//!
//! **Canary** `memobj-refcount-wrap-canary`: `total_refs` truncates to `u32`
//! again, so `a_sum_past_u32_max_frees_nothing` goes red (the frames are freed
//! while two holders still hold references).

use crate::cap::objref;
use crate::cap_store;
use crate::memobj::*;

const A: u32 = 21;
const B: u32 = 22;
const C: u32 = 23;

fn setup() -> std::sync::MutexGuard<'static, ()> {
    let g = crate::harness::serial();
    __memobj_reset_for_tests();
    for tid in [A, B, C] {
        cap_store::reset(tid);
    }
    g
}

/// A region created by `A`: its packed reference and the frame of page 0.
fn create() -> (u32, usize) {
    let cap = memobj_create_cap(A, 1, &MemSpec::anon(MemPerms::ReadWrite)).expect("create");
    let r = cap_store::get(A, cap, crate::cap::CapPerms::READ).expect("resolves");
    let phys = memobj_page_phys_ref(r, 0).unwrap().expect("a frame");
    (r, phys)
}

fn refs(r: u32) -> Option<u32> {
    memobj_info(objref::SHM.idx(r)).map(|(_, n, _)| n)
}

/// A holder at `u32::MAX` is refused one more reference: nothing wraps, nothing
/// is freed, and the count the region reports stays at the bound.
#[test]
fn an_acquire_at_the_bound_is_refused() {
    let _g = setup();
    let (r, phys) = create();
    __memobj_set_refs_for_tests(objref::SHM.idx(r), A, u32::MAX);
    assert_eq!(memobj_acquire_ref(A, r).err(), Some(MemObjError::Closed), "u32::MAX + 1 must be refused");
    assert_eq!(refs(r), Some(u32::MAX));
    assert_eq!(azos_mm::shim_free_count(phys), 0, "the frame is still held");
    // Another task's acquire is not blocked by A's bound, and the sum is not
    // reported past the bound.
    assert!(memobj_acquire_ref(B, r).is_ok());
    assert_eq!(refs(r), Some(u32::MAX), "the sum saturates when reported");
    assert_eq!(azos_mm::shim_free_count(phys), 0);
}

/// Holders whose references add up past 2^32: releases that bring the sum to
/// exactly 2^32 (a wrapped `u32` reads 0) free nothing; the frame goes back
/// when the last reference does.
#[test]
fn a_sum_past_u32_max_frees_nothing() {
    let _g = setup();
    let (r, phys) = create();
    let id = objref::SHM.idx(r);
    __memobj_set_refs_for_tests(id, A, u32::MAX);
    assert!(memobj_acquire_ref(B, r).is_ok());
    assert!(memobj_acquire_ref(C, r).is_ok());
    // A holds 2^32 - 1, B and C one each: 2^32 + 1.
    assert_eq!(memobj_release_holder_ref(B, r), Ok(()));
    // 2^32 now: a wrapped counter reads 0 here and frees A's and C's frame.
    assert_eq!(azos_mm::shim_free_count(phys), 0, "freed while two holders still hold references");
    assert!(memobj_info(id).is_some(), "the region is still live");
    assert_eq!(refs(r), Some(u32::MAX));
    assert_eq!(memobj_release_holder_ref(C, r), Ok(()));
    assert_eq!(azos_mm::shim_free_count(phys), 0);
    assert_eq!(memobj_release_holder_ref(A, r), Ok(()));
    assert_eq!(azos_mm::shim_free_count(phys), 1, "the last reference frees the frame once");
    assert!(memobj_info(id).is_none());
}
