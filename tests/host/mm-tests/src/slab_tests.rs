// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for `crates/core/mm/src/slab.rs` (wave 15, SLAB), the real file
//! pulled with `#[path]`.
//!
//! The backing here is the host allocator with a byte budget (to make the
//! heap refuse on demand), call counters (the O(1) rows read them), and a
//! per-thread "CPU" that a test sets: one thread per CPU is the kernel's
//! "interrupts off on this CPU" exclusivity, and a single thread switching
//! its CPU at random is a task migrating between operations.
//!
//! Canaries (features of this crate, forwarded into the pulled file):
//!   `slab-freelist-canary`: a slab hands out a freed object without
//!     unlinking it, so it is given twice. `stress_against_model` and
//!     `stress_threads` must go red.
//!   `slab-align-canary`: objects are carved one word past their natural
//!     slot. `every_class_is_aligned` must go red.
//!   `slab-geometry-canary`: a class that is not a multiple of 8. The crate
//!     must FAIL TO COMPILE (the geometry is checked in a const).

use super::slab::{Backing, Params, Slab, MAX_CPUS, NO_CLASS, POISON};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};

thread_local! {
    static CPU: Cell<usize> = const { Cell::new(0) };
}

fn set_cpu(c: usize) { CPU.with(|x| x.set(c)); }

/// The host heap with a budget and counters.
struct HostBacking {
    budget: AtomicUsize,
    outstanding: AtomicUsize,
    allocs: AtomicUsize,
    frees: AtomicUsize,
    /// Tokens say "interrupts were off" (an interrupt handler's view).
    masked: AtomicBool,
}

impl HostBacking {
    fn new(budget: usize) -> Self {
        HostBacking {
            budget: AtomicUsize::new(budget),
            outstanding: AtomicUsize::new(0),
            allocs: AtomicUsize::new(0),
            frees: AtomicUsize::new(0),
            masked: AtomicBool::new(false),
        }
    }
}

unsafe impl Backing for HostBacking {
    fn alloc(&self, size: usize, align: usize) -> *mut u8 {
        self.allocs.fetch_add(1, SeqCst);
        // The layer asks the heap for slabs only (magazines live in slabs of
        // their own): a block aligned to its power-of-two size.
        assert!(size.is_power_of_two() && align == size, "heap asked for {size} B aligned {align}");
        let mut cur = self.outstanding.load(SeqCst);
        loop {
            if cur + size > self.budget.load(SeqCst) { return std::ptr::null_mut(); }
            match self.outstanding.compare_exchange(cur, cur + size, SeqCst, SeqCst) {
                Ok(_) => break,
                Err(v) => cur = v,
            }
        }
        let l = std::alloc::Layout::from_size_align(size, align).unwrap();
        let p = unsafe { std::alloc::alloc(l) };
        assert!(!p.is_null());
        p
    }
    fn free(&self, p: *mut u8, size: usize, align: usize) {
        self.frees.fetch_add(1, SeqCst);
        self.outstanding.fetch_sub(size, SeqCst);
        unsafe { std::alloc::dealloc(p, std::alloc::Layout::from_size_align(size, align).unwrap()) }
    }
    fn irq_off(&self) -> usize { if self.masked.load(SeqCst) { 0 } else { 1 } }
    fn irq_restore(&self, _t: usize) {}
    fn was_on(&self, t: usize) -> bool { t != 0 }
    fn cpu(&self) -> usize { CPU.with(|x| x.get()) }
}

const CLASSES: &[usize] = &[16, 32, 48, 64, 96, 128, 192, 256, 512, 1024, 2048];

struct Small;
impl Params for Small {
    const CLASSES: &'static [usize] = CLASSES;
    const MAG_DEPTH: usize = 8;
    const CPU_CACHE_BYTES: usize = 1 << 20;
    const DEPOT_MAGS: usize = 2;
    const SLAB_BYTES: usize = 4096;
    const MIN_OBJS: usize = 8;
    const KEEP_EMPTY: usize = 1;
    const DEBUG: bool = false;
}

struct Debug;
impl Params for Debug {
    const CLASSES: &'static [usize] = CLASSES;
    const MAG_DEPTH: usize = 4;
    const CPU_CACHE_BYTES: usize = 1 << 20;
    const DEPOT_MAGS: usize = 1;
    const SLAB_BYTES: usize = 4096;
    const MIN_OBJS: usize = 8;
    const KEEP_EMPTY: usize = 0;
    const DEBUG: bool = true;
}

#[cfg(feature = "slab-geometry-canary")]
struct Bad;
#[cfg(feature = "slab-geometry-canary")]
impl Params for Bad {
    const CLASSES: &'static [usize] = &[16, 20];
    const MAG_DEPTH: usize = 4;
    const CPU_CACHE_BYTES: usize = 1 << 20;
    const DEPOT_MAGS: usize = 1;
    const SLAB_BYTES: usize = 4096;
    const MIN_OBJS: usize = 8;
    const KEEP_EMPTY: usize = 0;
    const DEBUG: bool = false;
}
#[cfg(feature = "slab-geometry-canary")]
#[test]
fn geometry_canary() {
    let _ = Slab::<Bad, HostBacking>::G.n;
}

type S = Slab<Small, HostBacking>;

fn new_small(budget: usize) -> Box<S> { Box::new(Slab::new(HostBacking::new(budget))) }

fn class(size: usize, align: usize) -> usize {
    let c = S::class_of(size, align);
    assert_ne!(c, NO_CLASS, "{size} B aligned {align} has no class");
    c
}

#[test]
fn class_lookup_is_smallest_fit() {
    for size in 1..=2048 {
        let c = class(size, 8);
        let g = &S::G;
        assert!(g.size[c] >= size, "size {size} -> class {}", g.size[c]);
        assert!(c == 0 || g.size[c - 1] < size, "size {size} not the smallest fit");
    }
    assert_eq!(S::class_of(2049, 8), NO_CLASS);
    // Alignment above a class's natural one moves up, or to the heap.
    assert_eq!(S::G.size[class(48, 32)], 64);
    assert_eq!(S::G.size[class(16, 1024)], 1024);
    assert_eq!(S::class_of(16, 4096), NO_CLASS);
}

#[test]
fn every_class_is_aligned() {
    set_cpu(0);
    let s = new_small(64 << 20);
    for (i, &size) in CLASSES.iter().enumerate() {
        let mut align = 1;
        while align <= 4096 {
            let c = S::class_of(size, align);
            if c != NO_CLASS {
                let mut v = Vec::new();
                // Enough to carve past the first slab and through a depot trade.
                for _ in 0..64 {
                    let p = unsafe { s.alloc(c, size) };
                    assert!(!p.is_null());
                    assert_eq!(p as usize % align, 0, "class {size} align {align}: {p:p}");
                    assert_eq!(p as usize % S::G.align[c], 0, "class {size} natural alignment");
                    v.push(p);
                }
                for p in v { unsafe { s.free(c, p, size) }; }
                if align <= 16 { assert_eq!(c, i); }
            }
            align *= 2;
        }
    }
}

#[test]
fn fast_path_takes_no_lock_and_no_heap() {
    set_cpu(3);
    let s = new_small(64 << 20);
    let c = class(64, 8);
    let depth = S::G.depth[c];
    // Warm: two magazines on this CPU, both used once.
    let mut v: Vec<_> = (0..2 * depth).map(|_| unsafe { s.alloc(c, 64) }).collect();
    for p in v.drain(..) { unsafe { s.free(c, p, 64) }; }
    let locks = s.stats(c).locks;
    let heap = s.backing().allocs.load(SeqCst);
    for round in 0..10_000 {
        let k = 1 + round % depth;
        for _ in 0..k { v.push(unsafe { s.alloc(c, 64) }); }
        for p in v.drain(..) { unsafe { s.free(c, p, 64) }; }
    }
    assert_eq!(s.stats(c).locks, locks, "an alloc/free within one magazine took the class lock");
    assert_eq!(s.backing().allocs.load(SeqCst), heap, "an alloc/free within one magazine reached the heap");
    // Up to two magazines' worth (the prev swap) still takes no lock.
    for _ in 0..2 * depth { v.push(unsafe { s.alloc(c, 64) }); }
    for p in v.drain(..) { unsafe { s.free(c, p, 64) }; }
    assert_eq!(s.stats(c).locks, locks, "the prev-magazine swap took the class lock");
}

#[test]
fn slow_path_is_bounded_by_one_magazine() {
    set_cpu(1);
    let s = new_small(64 << 20);
    let c = class(32, 8);
    let depth = S::G.depth[c];
    // N allocations cost at most one lock per magazine-full plus one per slab.
    let n = 10 * depth * S::G.objs[c];
    let v: Vec<_> = (0..n).map(|_| unsafe { s.alloc(c, 32) }).collect();
    let st = s.stats(c);
    assert!(st.locks as usize <= n / depth + 3 * st.slabs + 4, "{} locks for {n} allocs", st.locks);
    for p in v { unsafe { s.free(c, p, 32) }; }
}

#[test]
fn cross_cpu_free() {
    let s: Arc<S> = Arc::from(new_small(256 << 20));
    let (tx, rx) = std::sync::mpsc::channel::<Vec<(usize, usize, u8)>>();
    let a = {
        let s = s.clone();
        std::thread::spawn(move || {
            set_cpu(0);
            for round in 0..200u32 {
                let batch: Vec<_> = (0..64).map(|i| {
                    let size = CLASSES[(i + round as usize) % CLASSES.len()];
                    let c = class(size, 8);
                    let p = unsafe { s.alloc(c, size) };
                    assert!(!p.is_null());
                    let b = (round as u8).wrapping_add(i as u8);
                    unsafe { std::ptr::write_bytes(p, b, size) };
                    (p as usize, size, b)
                }).collect();
                tx.send(batch).unwrap();
            }
        })
    };
    let b = {
        let s = s.clone();
        std::thread::spawn(move || {
            set_cpu(1);
            let mut n = 0;
            for batch in rx {
                for (p, size, b) in batch {
                    let p = p as *mut u8;
                    for i in 0..size { assert_eq!(unsafe { *p.add(i) }, b, "object changed in flight"); }
                    unsafe { s.free(class(size, 8), p, size) };
                    n += 1;
                }
            }
            n
        })
    };
    a.join().unwrap();
    assert_eq!(b.join().unwrap(), 200 * 64);
    // Every object is free again: what the layer holds is all cache.
    let held: usize = (0..S::G.n).map(|c| {
        let st = s.stats(c);
        assert_eq!(st.slabs * S::G.objs[c], st.slab_free + st.depot_objs + st.cpu_objs, "class {}: objects lost", st.size);
        st.slabs
    }).sum();
    assert!(held > 0);
}

#[test]
fn exhaustion_refuses_then_reclaim_returns_everything() {
    set_cpu(0);
    let s = new_small(256 << 10);
    let c = class(128, 8);
    let mut v = Vec::new();
    loop {
        let p = unsafe { s.alloc(c, 128) };
        if p.is_null() { break; }
        v.push(p);
        assert!(v.len() < 1 << 20);
    }
    assert!(v.len() > 1000, "only {} objects from 256 KiB", v.len());
    // A refusal is sticky while the heap is full, and never a panic.
    for _ in 0..100 { assert!(unsafe { s.alloc(c, 128) }.is_null()); }
    // Another class cannot get a slab either.
    assert!(unsafe { s.alloc(class(1024, 8), 1024) }.is_null());
    for p in v.drain(..) { unsafe { s.free(c, p, 128) }; }
    let before = s.backing().outstanding.load(SeqCst);
    let got = s.reclaim();
    assert!(got > 0);
    assert_eq!(s.backing().outstanding.load(SeqCst), before - got);
    assert_eq!(s.backing().outstanding.load(SeqCst), 0, "reclaim left memory behind");
    // And the memory serves another class now.
    let p = unsafe { s.alloc(class(1024, 8), 1024) };
    assert!(!p.is_null());
    unsafe { s.free(class(1024, 8), p, 1024) };
}

#[test]
fn empty_slabs_go_back_to_the_heap() {
    set_cpu(0);
    let s = new_small(64 << 20);
    let c = class(256, 8);
    let n = 20 * S::G.objs[c];
    let v: Vec<_> = (0..n).map(|_| unsafe { s.alloc(c, 256) }).collect();
    let peak = s.backing().outstanding.load(SeqCst);
    for p in v { unsafe { s.free(c, p, 256) }; }
    let after = s.backing().outstanding.load(SeqCst);
    // What stays: KEEP_EMPTY slabs plus the slabs of the objects still
    // cached in this CPU's magazines and the depot.
    assert!(after < peak / 2, "freed {n} objects, heap still holds {after} of {peak}");
}

#[test]
fn masked_caller_never_returns_slabs_to_the_heap() {
    set_cpu(2);
    let s = new_small(64 << 20);
    let c = class(512, 8);
    let n = 8 * S::G.objs[c];
    let v: Vec<_> = (0..n).map(|_| unsafe { s.alloc(c, 512) }).collect();
    s.backing().masked.store(true, SeqCst);
    let frees = s.backing().frees.load(SeqCst);
    for p in v { unsafe { s.free(c, p, 512) }; }
    s.reclaim();
    assert_eq!(s.backing().frees.load(SeqCst), frees, "an interrupt-masked free walked the heap");
    s.backing().masked.store(false, SeqCst);
    s.reclaim();
    assert_eq!(s.backing().outstanding.load(SeqCst), 0);
}

#[test]
fn cpu_beyond_the_table_is_served() {
    set_cpu(MAX_CPUS + 5);
    let s = new_small(64 << 20);
    let c = class(64, 8);
    let v: Vec<_> = (0..1000).map(|_| unsafe { s.alloc(c, 64) }).collect();
    let mut sorted = v.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 1000);
    for p in v { unsafe { s.free(c, p, 64) }; }
    assert_eq!(s.stats(c).cpu_objs, 0);
    s.reclaim();
    assert_eq!(s.backing().outstanding.load(SeqCst), 0);
}

/// xorshift: deterministic, no dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 }
    fn below(&mut self, n: usize) -> usize { (self.next() % n as u64) as usize }
}

/// Live objects: start -> (end, fill). No two may overlap; the fill must
/// survive until the free.
fn model_insert(live: &mut BTreeMap<usize, (usize, u8)>, p: usize, size: usize, fill: u8) {
    if let Some((&s0, &(e0, _))) = live.range(..=p).next_back() {
        assert!(e0 <= p, "object {p:#x}+{size} overlaps live {s0:#x}..{e0:#x}");
    }
    if let Some((&s1, _)) = live.range(p..).next() {
        assert!(p + size <= s1, "object {p:#x}+{size} overlaps live {s1:#x}");
    }
    live.insert(p, (p + size, fill));
}

#[test]
fn stress_against_model() {
    let s = new_small(32 << 20);
    let mut rng = Rng(0x9e3779b97f4a7c15);
    let mut live: BTreeMap<usize, (usize, u8)> = BTreeMap::new();
    let mut order: Vec<(usize, usize)> = Vec::new();
    let mut refused = 0;
    for step in 0..400_000u32 {
        set_cpu(rng.below(4));
        if order.is_empty() || (rng.below(100) < 55 && order.len() < 20_000) {
            let size = 1 + rng.below(2048);
            let align = 1 << rng.below(7);
            let c = S::class_of(size, align);
            if c == NO_CLASS { continue; }
            let p = unsafe { s.alloc(c, size) };
            if p.is_null() { refused += 1; continue; }
            assert_eq!(p as usize % align, 0);
            let fill = step as u8;
            unsafe { std::ptr::write_bytes(p, fill, size) };
            model_insert(&mut live, p as usize, size, fill);
            order.push((p as usize, size | (align << 32)));
        } else {
            let i = rng.below(order.len());
            let (p, sa) = order.swap_remove(i);
            let (size, align) = (sa & 0xffff_ffff, sa >> 32);
            let (end, fill) = live.remove(&p).unwrap();
            assert_eq!(end, p + size);
            for k in 0..size { assert_eq!(unsafe { *(p as *const u8).add(k) }, fill, "object {p:#x} corrupted at +{k}"); }
            unsafe { s.free(S::class_of(size, align), p as *mut u8, size) };
        }
        if step % 50_000 == 0 { s.reclaim(); }
    }
    assert_eq!(refused, 0);
    for (p, sa) in order.drain(..) {
        let (size, align) = (sa & 0xffff_ffff, sa >> 32);
        unsafe { s.free(S::class_of(size, align), p as *mut u8, size) };
    }
    for cpu in 0..4 { set_cpu(cpu); s.reclaim(); }
    assert_eq!(s.backing().outstanding.load(SeqCst), 0, "memory leaked through the layers");
}

#[test]
fn stress_threads() {
    let s: Arc<S> = Arc::from(new_small(256 << 20));
    let shared: Arc<Mutex<Vec<(usize, usize, u8)>>> = Arc::new(Mutex::new(Vec::new()));
    let hs: Vec<_> = (0..4).map(|cpu| {
        let s = s.clone();
        let shared = shared.clone();
        std::thread::spawn(move || {
            set_cpu(cpu);
            let mut rng = Rng(0x1234_5678 + cpu as u64);
            let mut mine: Vec<(usize, usize, u8)> = Vec::new();
            for step in 0..100_000u32 {
                match rng.below(10) {
                    0..=4 => {
                        let size = 1 + rng.below(1024);
                        let c = class(size, 8);
                        let p = unsafe { s.alloc(c, size) };
                        assert!(!p.is_null());
                        let fill = (step as u8) ^ (cpu as u8 * 51);
                        unsafe { std::ptr::write_bytes(p, fill, size) };
                        mine.push((p as usize, size, fill));
                    }
                    5 => if let Some(o) = mine.pop() { shared.lock().unwrap().push(o); },
                    _ => {
                        let o = if rng.below(2) == 0 { mine.pop() } else { shared.lock().unwrap().pop() };
                        if let Some((p, size, fill)) = o {
                            for k in 0..size {
                                assert_eq!(unsafe { *(p as *const u8).add(k) }, fill, "object {p:#x} corrupted at +{k}");
                            }
                            unsafe { s.free(class(size, 8), p as *mut u8, size) };
                        }
                    }
                }
            }
            for (p, size, _) in mine { unsafe { s.free(class(size, 8), p as *mut u8, size) }; }
            s.reclaim();
        })
    }).collect();
    for h in hs { h.join().unwrap(); }
    set_cpu(0);
    for (p, size, fill) in shared.lock().unwrap().drain(..) {
        for k in 0..size { assert_eq!(unsafe { *(p as *const u8).add(k) }, fill); }
        unsafe { s.free(class(size, 8), p as *mut u8, size) };
    }
    for cpu in 0..4 { set_cpu(cpu); s.reclaim(); }
    assert_eq!(s.backing().outstanding.load(SeqCst), 0, "memory leaked through the layers");
}

#[test]
fn debug_poisons_freed_objects() {
    set_cpu(0);
    let s: Box<Slab<Debug, HostBacking>> = Box::new(Slab::new(HostBacking::new(64 << 20)));
    let c = Slab::<Debug, HostBacking>::class_of(40, 8);
    let p = unsafe { s.alloc(c, 40) };
    // The red zone between 40 and the class size is filled.
    for i in 40..48 { assert_eq!(unsafe { *p.add(i) }, super::slab::REDZONE); }
    unsafe { s.free(c, p, 40) };
    for i in 0..48 { assert_eq!(unsafe { *p.add(i) }, POISON); }
}

#[test]
#[should_panic(expected = "overrun")]
fn debug_catches_an_overrun() {
    set_cpu(0);
    let s: Box<Slab<Debug, HostBacking>> = Box::new(Slab::new(HostBacking::new(64 << 20)));
    let c = Slab::<Debug, HostBacking>::class_of(40, 8);
    let p = unsafe { s.alloc(c, 40) };
    unsafe { *p.add(41) = 0 };
    unsafe { s.free(c, p, 40) };
}

#[test]
#[should_panic(expected = "written after free")]
fn debug_catches_a_write_after_free() {
    set_cpu(0);
    let s: Box<Slab<Debug, HostBacking>> = Box::new(Slab::new(HostBacking::new(64 << 20)));
    let c = Slab::<Debug, HostBacking>::class_of(64, 8);
    let p = unsafe { s.alloc(c, 64) };
    unsafe { s.free(c, p, 64) };
    unsafe { *p.add(30) = 1 };
    let q = unsafe { s.alloc(c, 64) };
    assert_eq!(p, q, "LIFO magazine returns the same object");
}

/// The kernel's shape (`kheap::inner_alloc`): the inline magazine pop when
/// the table answers, the full path otherwise.
fn k_alloc(s: &S, size: usize, align: usize) -> *mut u8 {
    let c = S::class_fast(size, align);
    if c != NO_CLASS {
        let p = unsafe { s.alloc_fast(c) };
        if !p.is_null() { return p; }
    }
    let c = S::class_of(size, align);
    assert_ne!(c, NO_CLASS);
    unsafe { s.alloc(c, size) }
}

fn k_free(s: &S, p: *mut u8, size: usize, align: usize) {
    let c = S::class_fast(size, align);
    if c != NO_CLASS && unsafe { s.free_fast(c, p) } { return; }
    unsafe { s.free(S::class_of(size, align), p, size) };
}

#[test]
fn inline_path_agrees_with_the_full_one() {
    let s = new_small(64 << 20);
    let mut rng = Rng(0xfeed_beef);
    let mut live: BTreeMap<usize, (usize, u8)> = BTreeMap::new();
    let mut order: Vec<(usize, usize, usize)> = Vec::new();
    for step in 0..200_000u32 {
        set_cpu(rng.below(3));
        if order.is_empty() || (rng.below(100) < 52 && order.len() < 5_000) {
            let size = 1 + rng.below(2048);
            let align = 1 << rng.below(6);
            if S::class_of(size, align) == NO_CLASS { continue; }
            let p = k_alloc(&s, size, align);
            assert!(!p.is_null());
            assert_eq!(p as usize % align, 0);
            unsafe { std::ptr::write_bytes(p, step as u8, size) };
            model_insert(&mut live, p as usize, size, step as u8);
            order.push((p as usize, size, align));
        } else {
            let (p, size, align) = order.swap_remove(rng.below(order.len()));
            let (_, fill) = live.remove(&p).unwrap();
            for k in 0..size { assert_eq!(unsafe { *(p as *const u8).add(k) }, fill); }
            k_free(&s, p as *mut u8, size, align);
        }
    }
    for (p, size, align) in order { k_free(&s, p as *mut u8, size, align); }
    for cpu in 0..3 { set_cpu(cpu); s.reclaim(); }
    assert_eq!(s.backing().outstanding.load(SeqCst), 0);
}

#[test]
fn inline_path_takes_no_lock() {
    set_cpu(5);
    let s = new_small(64 << 20);
    let c = class(32, 8);
    // Warm one magazine.
    let p = k_alloc(&s, 32, 8);
    k_free(&s, p, 32, 8);
    let locks = s.stats(c).locks;
    let heap = s.backing().allocs.load(SeqCst);
    for _ in 0..100_000 {
        let p = unsafe { s.alloc_fast(c) };
        assert!(!p.is_null(), "a warm magazine missed");
        assert!(unsafe { s.free_fast(c, p) }, "a warm magazine had no room");
    }
    assert_eq!(s.stats(c).locks, locks);
    assert_eq!(s.backing().allocs.load(SeqCst), heap);
}

/// The tightest geometry Kconfig admits: every class at depth 1 (the
/// per-CPU cap clamps it), no depot, no kept empties. Every miss runs the
/// flush-and-swap and refusal arms.
struct Tight;
impl Params for Tight {
    const CLASSES: &'static [usize] = CLASSES;
    const MAG_DEPTH: usize = 4;
    const CPU_CACHE_BYTES: usize = 1;
    const DEPOT_MAGS: usize = 0;
    const SLAB_BYTES: usize = 1024;
    const MIN_OBJS: usize = 1;
    const KEEP_EMPTY: usize = 0;
    const DEBUG: bool = false;
}

/// `MAG_DEPTH = 1` itself, with a depot.
struct Depth1;
impl Params for Depth1 {
    const CLASSES: &'static [usize] = &[16, 64, 256];
    const MAG_DEPTH: usize = 1;
    const CPU_CACHE_BYTES: usize = 1 << 20;
    const DEPOT_MAGS: usize = 1;
    const SLAB_BYTES: usize = 1024;
    const MIN_OBJS: usize = 4;
    const KEEP_EMPTY: usize = 1;
    const DEBUG: bool = false;
}

fn stress_generic<P: Params>(seed: u64, budget: usize) {
    let s: Box<Slab<P, HostBacking>> = Box::new(Slab::new(HostBacking::new(budget)));
    for c in 0..Slab::<P, HostBacking>::G.n { assert!(Slab::<P, HostBacking>::G.depth[c] >= 1); }
    let mut rng = Rng(seed);
    let mut live: BTreeMap<usize, (usize, u8)> = BTreeMap::new();
    let mut order: Vec<(usize, usize)> = Vec::new();
    let max = Slab::<P, HostBacking>::G.max;
    for step in 0..150_000u32 {
        set_cpu(rng.below(3));
        if order.is_empty() || (rng.below(100) < 53 && order.len() < 3_000) {
            let size = 1 + rng.below(max);
            let c = Slab::<P, HostBacking>::class_of(size, 8);
            let p = unsafe { s.alloc(c, size) };
            assert!(!p.is_null());
            unsafe { std::ptr::write_bytes(p, step as u8, size) };
            model_insert(&mut live, p as usize, size, step as u8);
            order.push((p as usize, size));
        } else {
            let (p, size) = order.swap_remove(rng.below(order.len()));
            let (_, fill) = live.remove(&p).unwrap();
            for k in 0..size { assert_eq!(unsafe { *(p as *const u8).add(k) }, fill, "corrupted"); }
            unsafe { s.free(Slab::<P, HostBacking>::class_of(size, 8), p as *mut u8, size) };
        }
        if step % 30_000 == 0 { s.reclaim(); }
    }
    for (p, size) in order { unsafe { s.free(Slab::<P, HostBacking>::class_of(size, 8), p as *mut u8, size) }; }
    for cpu in 0..3 { set_cpu(cpu); s.reclaim(); }
    assert_eq!(s.backing().outstanding.load(SeqCst), 0, "memory leaked through the layers");
    // Exhaustion on the tight geometry: refused, never a panic, all back after.
    let s: Box<Slab<P, HostBacking>> = Box::new(Slab::new(HostBacking::new(64 << 10)));
    set_cpu(0);
    let c = Slab::<P, HostBacking>::class_of(64, 8);
    let mut v = Vec::new();
    loop { let p = unsafe { s.alloc(c, 64) }; if p.is_null() { break; } v.push(p); }
    assert!(!v.is_empty());
    for p in v { unsafe { s.free(c, p, 64) }; }
    s.reclaim();
    assert_eq!(s.backing().outstanding.load(SeqCst), 0);
}

#[test]
fn tight_geometry_depth1_no_depot() { stress_generic::<Tight>(0x7171, 64 << 20); }

#[test]
fn depth_one_with_depot() { stress_generic::<Depth1>(0xd1d1, 64 << 20); }
