// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The thread registry and the keyed thread-local storage of `azos_stdrt::tls`,
//! driven on the host: the stack pointer is a parameter, the block allocator
//! counts what it hands out, and a destructor logs what it was called with.
//!
//! Canaries (each one was made to fail by breaking the line it guards):
//! * the key generation checks in `key_get` / `live`: a destroyed-then-recreated
//!   key must not see, or destruct, the previous owner's value;
//! * `release` clearing `hi` before `lo` (fails with the window between the two stores widened): a claim racing a release must keep its
//!   range (`slot_churn_keeps_every_range`);
//! * the block free at the end of `run_dtors` (`live_blocks()` returns to 0).

use azos_stdrt::tls::{Dtor, Registry, DTOR_ROUNDS, KEYS_MAX, MAX_THREADS};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::{Cell, RefCell};

thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static FAIL_ALLOC: Cell<bool> = const { Cell::new(false) };
    /// What the destructors were called with, as (tag, value).
    static CALLS: RefCell<Vec<(u8, usize)>> = const { RefCell::new(Vec::new()) };
    /// The registry, the stack pointer and the key a re-arming destructor uses.
    static REARM: Cell<Option<(&'static Registry, usize, usize)>> = const { Cell::new(None) };
}

fn host_alloc(size: usize, align: usize) -> *mut u8 {
    if FAIL_ALLOC.with(|f| f.get()) {
        return std::ptr::null_mut();
    }
    LIVE.with(|l| l.set(l.get() + 1));
    // SAFETY: a non-zero size and a power-of-two alignment (the block's).
    unsafe { alloc(Layout::from_size_align(size, align).unwrap()) }
}

fn host_free(p: *mut u8, size: usize) {
    LIVE.with(|l| l.set(l.get() - 1));
    // SAFETY: `p` came from `host_alloc` with this size; the block's alignment
    // is the one `host_alloc` was asked for (checked by the layout's size).
    unsafe { dealloc(p, Layout::from_size_align(size, 8).unwrap()) }
}

fn live_blocks() -> isize {
    LIVE.with(|l| l.get())
}

fn calls() -> Vec<(u8, usize)> {
    CALLS.with(|c| c.borrow().clone())
}

fn reg() -> &'static Registry {
    Box::leak(Box::new(Registry::new(host_alloc, host_free)))
}

unsafe extern "C" fn dtor_a(v: *mut u8) {
    CALLS.with(|c| c.borrow_mut().push((b'a', v as usize)));
}

unsafe extern "C" fn dtor_b(v: *mut u8) {
    CALLS.with(|c| c.borrow_mut().push((b'b', v as usize)));
}

/// Re-creates its value under the key `REARM` names, one more than it got.
unsafe extern "C" fn dtor_rearm(v: *mut u8) {
    CALLS.with(|c| c.borrow_mut().push((b'r', v as usize)));
    let (r, sp, k) = REARM.with(|a| a.get()).unwrap();
    assert!(r.key_set(sp, k, (v as usize + 1) as *mut u8));
}

const A: (usize, usize) = (0x10_0000, 0x4000);
const B: (usize, usize) = (0x20_0000, 0x4000);
const MAIN_SP: usize = 0x7000_0000;

fn v(n: usize) -> *mut u8 {
    n as *mut u8
}

#[test]
fn a_stack_pointer_finds_its_own_block() {
    let r = reg();
    let k = r.key_create(None).unwrap();
    r.claim(A.0, A.1).unwrap();
    r.claim(B.0, B.1).unwrap();
    assert!(r.key_set(A.0 + 0x100, k, v(0xa1)));
    assert!(r.key_set(B.0 + 0x100, k, v(0xb1)));
    assert!(r.key_set(MAIN_SP, k, v(0x11)));
    // Anywhere inside the range is the same thread; the ends: `lo` is in,
    // `hi` is out.
    assert_eq!(r.key_get(A.0, k), v(0xa1));
    assert_eq!(r.key_get(A.0 + A.1 - 1, k), v(0xa1));
    assert_eq!(r.key_get(B.0 + 0x3fff, k), v(0xb1));
    // One byte below `lo` and `hi` itself are the main thread's.
    assert_eq!(r.key_get(A.0 - 1, k), v(0x11));
    assert_eq!(r.key_get(A.0 + A.1, k), v(0x11));
    assert_eq!(r.key_get(0, k), v(0x11));
    assert_eq!(r.key_get(usize::MAX, k), v(0x11));
    assert_eq!(live_blocks(), 3);
}

#[test]
fn a_thread_that_never_set_sees_null_and_costs_no_block() {
    let r = reg();
    let k = r.key_create(None).unwrap();
    r.claim(A.0, A.1).unwrap();
    assert!(r.key_get(A.0 + 8, k).is_null());
    r.run_dtors(A.0 + 8);
    assert_eq!(live_blocks(), 0);
}

#[test]
fn a_reused_slot_starts_empty_and_the_old_range_is_main() {
    let r = reg();
    let k = r.key_create(Some(dtor_a as Dtor)).unwrap();
    let s = r.claim(A.0, A.1).unwrap();
    assert!(r.key_set(A.0 + 8, k, v(0x1)));
    r.run_dtors(A.0 + 8);
    r.release(s);
    assert_eq!(calls(), vec![(b'a', 0x1)]);
    assert_eq!(live_blocks(), 0);
    // The old stack is nobody's now: its sp is the main thread's.
    assert!(r.key_get(A.0 + 8, k).is_null());
    assert!(r.key_set(A.0 + 8, k, v(0x2)));
    assert!(r.key_get(MAIN_SP, k) == v(0x2));
    // The slot is handed out again, for another range, with no block.
    assert_eq!(r.claim(B.0, B.1), Some(s));
    assert!(r.key_get(B.0 + 8, k).is_null());
    assert!(r.key_set(B.0 + 8, k, v(0x3)));
    assert_eq!(r.key_get(B.0 + 8, k), v(0x3));
    assert_eq!(r.key_get(MAIN_SP, k), v(0x2));
    // And the same range again after a release is a fresh thread too.
    r.run_dtors(B.0 + 8);
    r.release(s);
    assert_eq!(r.claim(B.0, B.1), Some(s));
    assert!(r.key_get(B.0 + 8, k).is_null());
}

#[test]
fn the_registry_holds_max_threads_and_a_release_makes_room() {
    let r = reg();
    for i in 0..MAX_THREADS {
        assert_eq!(r.claim(0x100_0000 + i * 0x10000, 0x1000), Some(i));
    }
    assert_eq!(r.claim(0x900_0000, 0x1000), None);
    r.release(7);
    assert_eq!(r.claim(0x900_0000, 0x1000), Some(7));
    let k = r.key_create(None).unwrap();
    assert!(r.key_set(0x900_0000 + 1, k, v(5)));
    assert!(r.key_get(0x100_0000 + 6 * 0x10000, k).is_null());
    assert_eq!(r.key_get(0x900_0000 + 1, k), v(5));
}

#[test]
fn a_destroyed_then_recreated_key_does_not_see_the_old_value() {
    let r = reg();
    let k1 = r.key_create(Some(dtor_a as Dtor)).unwrap();
    r.claim(A.0, A.1).unwrap();
    let sp = A.0 + 8;
    assert!(r.key_set(sp, k1, v(0xdead)));
    assert!(r.key_set(MAIN_SP, k1, v(0xbeef)));
    r.key_destroy(k1);
    // The index is reused with another destructor.
    let k2 = r.key_create(Some(dtor_b as Dtor)).unwrap();
    assert_eq!(k1 & 0xff, k2 & 0xff, "the lowest free index is reused");
    assert_ne!(k1, k2, "but not the handle");
    // The new key sees nothing on either thread; the old handle sees nothing.
    assert!(r.key_get(sp, k2).is_null());
    assert!(r.key_get(MAIN_SP, k2).is_null());
    assert!(r.key_get(sp, k1).is_null());
    // The old handle cannot write into the new key's slot.
    assert!(!r.key_set(sp, k1, v(0x66)));
    assert!(r.key_get(sp, k2).is_null());
    // Exit: neither destructor runs on the stale values (type confusion).
    r.run_dtors(sp);
    r.run_dtors(MAIN_SP);
    assert_eq!(calls(), vec![]);
    assert_eq!(live_blocks(), 0);
    // The new key works, and its destructor gets its own value only.
    assert!(r.key_set(sp, k2, v(0x42)));
    r.run_dtors(sp);
    assert_eq!(calls(), vec![(b'b', 0x42)]);
}

#[test]
fn a_stale_value_is_replaced_by_the_new_keys_set() {
    let r = reg();
    let k1 = r.key_create(Some(dtor_a as Dtor)).unwrap();
    assert!(r.key_set(MAIN_SP, k1, v(0x1)));
    r.key_destroy(k1);
    let k2 = r.key_create(Some(dtor_b as Dtor)).unwrap();
    assert!(r.key_set(MAIN_SP, k2, v(0x2)));
    assert_eq!(r.key_get(MAIN_SP, k2), v(0x2));
    r.run_dtors(MAIN_SP);
    // Destroying does not destruct: only the live value's destructor ran.
    assert_eq!(calls(), vec![(b'b', 0x2)]);
}

#[test]
fn many_generations_of_one_index_stay_apart() {
    let r = reg();
    let mut seen = Vec::new();
    for n in 0..50usize {
        let k = r.key_create(None).unwrap();
        assert!(!seen.contains(&k));
        assert!(r.key_get(MAIN_SP, k).is_null(), "generation {n} starts empty");
        assert!(r.key_set(MAIN_SP, k, v(0x1000 + n)));
        seen.push(k);
        r.key_destroy(k);
    }
    // A handle that is not live does nothing, twice over.
    r.key_destroy(seen[3]);
    let k = r.key_create(None).unwrap();
    r.key_destroy(seen[3]);
    assert!(r.key_set(MAIN_SP, k, v(7)), "a stale destroy did not take the live key");
    assert_eq!(r.key_get(MAIN_SP, k), v(7));
}

#[test]
fn keys_run_out_at_keys_max_and_a_destroy_makes_room() {
    let r = reg();
    let ks: Vec<usize> = (0..KEYS_MAX).map(|_| r.key_create(None).unwrap()).collect();
    assert!(ks.iter().all(|&k| k != 0));
    assert_eq!(r.key_create(None), None);
    r.key_destroy(ks[40]);
    let k = r.key_create(None).unwrap();
    assert_eq!(k & 0xff, ks[40] & 0xff);
    assert_eq!(r.key_create(None), None);
}

#[test]
fn handles_that_are_not_keys_are_refused() {
    let r = reg();
    for k in [0usize, 0xff, KEYS_MAX + 1, 0x100] {
        assert!(r.key_get(MAIN_SP, k).is_null());
        assert!(!r.key_set(MAIN_SP, k, v(1)));
        r.key_destroy(k);
    }
    // A well-formed handle of a key that was never created.
    assert!(!r.key_set(MAIN_SP, 1, v(1)));
    assert_eq!(live_blocks(), 0);
}

#[test]
fn destructors_run_in_rounds_and_the_rounds_are_bounded() {
    let r = reg();
    let ka = r.key_create(Some(dtor_a as Dtor)).unwrap();
    let kr = r.key_create(Some(dtor_rearm as Dtor)).unwrap();
    let sp = A.0 + 8;
    r.claim(A.0, A.1).unwrap();
    REARM.with(|a| a.set(Some((r, sp, kr))));
    assert!(r.key_set(sp, ka, v(0xa0)));
    assert!(r.key_set(sp, kr, v(0x100)));
    r.run_dtors(sp);
    // `ka` runs once (round 1); the re-arming one is called DTOR_ROUNDS times
    // and the value it leaves after the last round is dropped, the block freed.
    let c = calls();
    assert_eq!(c.iter().filter(|e| e.0 == b'a').count(), 1);
    let rs: Vec<usize> = c.iter().filter(|e| e.0 == b'r').map(|e| e.1).collect();
    assert_eq!(rs, (0..DTOR_ROUNDS).map(|i| 0x100 + i).collect::<Vec<_>>());
    assert_eq!(live_blocks(), 0);
    assert!(r.key_get(sp, kr).is_null());
}

#[test]
fn a_destructor_that_sets_another_keys_value_gets_it_destructed_next_round() {
    let r = reg();
    let kr = r.key_create(Some(dtor_rearm as Dtor)).unwrap();
    let kb = r.key_create(Some(dtor_b as Dtor)).unwrap();
    REARM.with(|a| a.set(Some((r, MAIN_SP, kb))));
    assert!(r.key_set(MAIN_SP, kr, v(0x10)));
    r.run_dtors(MAIN_SP);
    // The re-arm destructor (index 0) set `kb`'s value; round 2 ran `dtor_b` on it.
    assert_eq!(calls(), vec![(b'r', 0x10), (b'b', 0x11)]);
    assert_eq!(live_blocks(), 0);
}

#[test]
fn null_values_and_keys_without_a_destructor_run_nothing() {
    let r = reg();
    let kn = r.key_create(None).unwrap();
    let ka = r.key_create(Some(dtor_a as Dtor)).unwrap();
    assert!(r.key_set(MAIN_SP, kn, v(0x5)));
    assert!(r.key_set(MAIN_SP, ka, v(0)));
    r.run_dtors(MAIN_SP);
    assert_eq!(calls(), vec![]);
    assert_eq!(live_blocks(), 0);
    // A thread that exits twice (or never set anything) has nothing to do.
    r.run_dtors(MAIN_SP);
    assert_eq!(live_blocks(), 0);
}

#[test]
fn an_allocation_failure_is_a_false_not_a_crash() {
    let r = reg();
    let k = r.key_create(None).unwrap();
    FAIL_ALLOC.with(|f| f.set(true));
    assert!(!r.key_set(MAIN_SP, k, v(1)));
    assert!(r.key_get(MAIN_SP, k).is_null());
    FAIL_ALLOC.with(|f| f.set(false));
    assert!(r.key_set(MAIN_SP, k, v(1)));
    assert_eq!(r.key_get(MAIN_SP, k), v(1));
}

#[test]
fn slot_churn_keeps_every_range() {
    // Claims and releases of many threads at once, each with its own range
    // and a unique value: if a release could wipe the `hi` of a claim that
    // took the slot meanwhile, that thread's sp would resolve to the main
    // block, where the others' values land too.
    let r: &'static Registry = reg();
    let k = r.key_create(None).unwrap();
    let hs: Vec<_> = (0..8usize)
        .map(|t| {
            std::thread::spawn(move || {
                let base = 0x1000_0000 + t * 0x10_0000;
                for round in 0..20_000usize {
                    let s = loop {
                        if let Some(s) = r.claim(base, 0x1000) {
                            break s;
                        }
                        std::thread::yield_now();
                    };
                    let sp = base + 0x800;
                    let val = (t << 32) | (round + 1);
                    assert!(r.key_set(sp, k, v(val)));
                    assert_eq!(r.key_get(sp, k), v(val), "thread {t} round {round}");
                    r.run_dtors(sp);
                    r.release(s);
                }
                assert_eq!(live_blocks(), 0);
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    // Nothing leaked into the main block.
    assert!(r.key_get(MAIN_SP, k).is_null());
}
