// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the allocator hardening (Kconfig `SLAB_HARDENED`,
//! `ALLOC_RANDOM`): the real `slab.rs` and `buddy.rs`, pulled with `#[path]`.
//!
//! * Slab: a free object's link is not stored in the clear; a corrupted link,
//!   a corrupted list head, a double free, a wild free and a broken slab-list
//!   unlink each panic (release profile: nothing here is a `debug_assert`); a
//!   plain slab (`HARDENED` off) does not, which is what makes these rows
//!   discriminate. A random carve order differs per seed, repeats for the same
//!   seed, and is a permutation of the slab's objects.
//! * Buddy: a damaged free list panics on unlink; with a seed the list order
//!   differs per seed and no block is lost or handed out twice. The buddy's
//!   switches are the build's (`azos_limits`, the worktree `.config`), so its
//!   rows return early when the build turned them off.
//!
//! No row calls `buddy::stir`: it moves a process-wide seed that every other
//! row's `Buddy` would pick up.

use super::buddy::{Buddy, MAX_ORDER};
use super::frame::*;
use super::slab::{Backing, Params, Slab, SlabHdr, MAX_CPUS};
use std::cell::Cell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};

thread_local! {
    static CPU: Cell<usize> = const { Cell::new(0) };
}
fn set_cpu(c: usize) { CPU.with(|x| x.set(c)); }
/// A CPU the magazine table does not cover: every call goes to the slabs.
fn slab_only() { set_cpu(MAX_CPUS); }

/// The host heap; `entropy` counts up from the seed (0: none, so the
/// layer's own fallback runs).
struct Hb { seed: AtomicU64 }
impl Hb { fn new(seed: u64) -> Self { Hb { seed: AtomicU64::new(seed) } } }

unsafe impl Backing for Hb {
    fn alloc(&self, size: usize, align: usize) -> *mut u8 {
        assert!(size.is_power_of_two() && align == size);
        unsafe { std::alloc::alloc(std::alloc::Layout::from_size_align(size, align).unwrap()) }
    }
    fn free(&self, p: *mut u8, size: usize, align: usize) {
        unsafe { std::alloc::dealloc(p, std::alloc::Layout::from_size_align(size, align).unwrap()) }
    }
    fn irq_off(&self) -> usize { 1 }
    fn irq_restore(&self, _t: usize) {}
    fn was_on(&self, t: usize) -> bool { t != 0 }
    fn cpu(&self) -> usize { CPU.with(|x| x.get()) }
    fn entropy(&self, _irqs_on: bool) -> u64 {
        if self.seed.load(SeqCst) == 0 { 0 } else { self.seed.fetch_add(1, SeqCst) }
    }
}

const CLASSES: &[usize] = &[16, 32, 64, 128, 256, 512, 1024];

macro_rules! params {
    ($name:ident, $hard:expr, $rand:expr, $debug:expr) => {
        struct $name;
        impl Params for $name {
            const CLASSES: &'static [usize] = CLASSES;
            const MAG_DEPTH: usize = 4;
            const CPU_CACHE_BYTES: usize = 1 << 20;
            const DEPOT_MAGS: usize = 1;
            const SLAB_BYTES: usize = 4096;
            const MIN_OBJS: usize = 8;
            const KEEP_EMPTY: usize = 1;
            const DEBUG: bool = $debug;
            const HARDENED: bool = $hard;
            const RANDOM: bool = $rand;
        }
    };
}
params!(Plain, false, false, false);
params!(Hard, true, false, false);
params!(Rand, true, true, false);
params!(RandDebug, true, true, true);

fn new_slab<P: Params>(seed: u64) -> Box<Slab<P, Hb>> { Box::new(Slab::new(Hb::new(seed))) }

fn class<P: Params>(size: usize) -> usize {
    let c = Slab::<P, Hb>::class_of(size, 8);
    assert_ne!(c, super::slab::NO_CLASS);
    c
}

/// The message of the panic `f` raised, or `None` if it returned.
fn panic_of(f: impl FnOnce()) -> Option<String> {
    catch_unwind(AssertUnwindSafe(f)).err().map(|e| {
        e.downcast_ref::<String>().cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    })
}

/// Three live objects of class 64 and two freed (`y` last, so `y` heads the
/// slab's list and links to `x`); every call goes straight to the slabs.
struct Fixture<P: Params> {
    s: Box<Slab<P, Hb>>,
    c: usize,
    x: *mut u8,
    y: *mut u8,
    h: *mut SlabHdr,
}

fn fixture<P: Params>() -> Fixture<P> {
    slab_only();
    let s = new_slab::<P>(0xdead_beef_0001);
    let c = class::<P>(64);
    let v: Vec<*mut u8> = (0..5).map(|_| unsafe { s.alloc(c, 64) }).collect();
    unsafe { s.free(c, v[0], 64); s.free(c, v[1], 64); }
    let h = Slab::<P, Hb>::slab_of(c, v[0]);
    Fixture { s, c, x: v[0], y: v[1], h }
}

fn word_of(p: *mut u8) -> *mut usize { p as *mut usize }

#[test]
fn links_are_not_stored_in_the_clear() {
    let f = fixture::<Hard>();
    let w = unsafe { *word_of(f.y) };
    assert_ne!(w, f.x as usize, "the link to the next free object is stored as is");
    let key = unsafe { (*f.h).key };
    assert_ne!(key, 0);
    assert_eq!(w ^ key ^ (f.y as usize).swap_bytes(), f.x as usize, "link = next ^ key ^ byteswap(address)");
    // Allocation still hands them back in list order, and clears the word.
    let a = unsafe { f.s.alloc(f.c, 64) };
    assert_eq!(a, f.y);
    assert_eq!(unsafe { *word_of(a) }, 0, "a popped object keeps its link word");
    assert_eq!(unsafe { f.s.alloc(f.c, 64) }, f.x);

    // Control: a plain slab stores the pointer.
    let p = fixture::<Plain>();
    assert_eq!(unsafe { *word_of(p.y) }, p.x as usize);
}

#[test]
fn a_corrupted_link_is_caught_on_pop() {
    let f = fixture::<Hard>();
    unsafe { *word_of(f.y) ^= 1 << 40 };
    let m = panic_of(|| { unsafe { f.s.alloc(f.c, 64) }; }).expect("a corrupted link was followed");
    assert!(m.contains("corrupt free list (link)"), "{m}");
    assert!(m.contains(&format!("{:p}", f.y)), "the record names the object: {m}");
    std::mem::forget(f);

    // A flip that decodes to another slot of the slab but not to an object
    // boundary is caught the same way.
    let f = fixture::<Hard>();
    unsafe { *word_of(f.y) ^= 8 };
    assert!(panic_of(|| { unsafe { f.s.alloc(f.c, 64) }; }).is_some());
    std::mem::forget(f);

    // The control does not notice: it pops `y` and keeps the bad link.
    let p = fixture::<Plain>();
    unsafe { *word_of(p.y) ^= 1 << 40 };
    assert_eq!(unsafe { p.s.alloc(p.c, 64) }, p.y);
    std::mem::forget(p);
}

#[test]
fn a_corrupted_list_head_is_caught() {
    let f = fixture::<Hard>();
    unsafe { (*f.h).free = f.y.add(8) as *mut _ };
    let m = panic_of(|| { unsafe { f.s.alloc(f.c, 64) }; }).expect("a misaligned head was handed out");
    assert!(m.contains("corrupt free list (head)"), "{m}");
    std::mem::forget(f);
}

#[test]
fn double_free_and_wild_free_are_caught() {
    let f = fixture::<Hard>();
    // `y` heads the list: freeing it again is the adjacent double free.
    let m = panic_of(|| unsafe { f.s.free(f.c, f.y, 64) }).expect("double free went through");
    assert!(m.contains("double free"), "{m}");
    std::mem::forget(f);

    let f = fixture::<Hard>();
    let m = panic_of(|| unsafe { f.s.free(f.c, f.x.add(8), 64) }).expect("a wild free went through");
    assert!(m.contains("non-object"), "{m}");
    std::mem::forget(f);

    let p = fixture::<Plain>();
    assert!(panic_of(|| unsafe { p.s.free(p.c, p.y, 64) }).is_none(), "the control checks nothing");
    std::mem::forget(p);
}

/// A slab header nothing links to, for the unlink rows.
fn fake_hdr() -> Box<SlabHdr> { unsafe { Box::new(std::mem::zeroed()) } }

fn fill_after_corrupting<P: Params>(prev_side: bool) -> Option<String> {
    slab_only();
    let s = new_slab::<P>(7);
    let c = class::<P>(64);
    let objs = Slab::<P, Hb>::G.objs[c];
    let first = unsafe { s.alloc(c, 64) };
    let h = Slab::<P, Hb>::slab_of(c, first);
    let fake = Box::leak(fake_hdr());
    unsafe { if prev_side { (*h).prev = fake } else { (*h).next = fake } };
    // The last object fills the slab and unlinks it from the partial list.
    let m = panic_of(|| for _ in 1..objs { assert!(!unsafe { s.alloc(c, 64) }.is_null()); });
    std::mem::forget(s);
    m
}

#[test]
fn a_broken_slab_list_unlink_is_caught() {
    for prev_side in [false, true] {
        let m = fill_after_corrupting::<Hard>(prev_side).expect("a broken unlink went through");
        assert!(m.contains("corrupt slab list"), "{m}");
        // The control unlinks whatever the header says.
        assert!(fill_after_corrupting::<Plain>(prev_side).is_none());
    }
}

/// The order a fresh slab of class `size` hands its objects out in, as slot
/// numbers, one allocation at a time (no magazines).
fn carve_order<P: Params>(seed: u64, size: usize) -> Vec<usize> {
    slab_only();
    let s = new_slab::<P>(seed);
    let c = class::<P>(size);
    let g = &Slab::<P, Hb>::G;
    let sb = g.slab_bytes[c];
    let v: Vec<usize> = (0..g.objs[c]).map(|_| unsafe { s.alloc(c, size) } as usize).collect();
    let base = v[0] & !(sb - 1);
    let slots: Vec<usize> = v.iter().map(|&p| {
        assert_eq!(p & !(sb - 1), base, "the slab's objects came from two slabs");
        assert_eq!((p - base) % g.size[c], 0);
        (p - base) / g.size[c]
    }).collect();
    for &p in &v { unsafe { s.free(c, p as *mut u8, size) }; }
    slots
}

fn is_permutation(v: &[usize], n: usize) -> bool {
    let mut s = v.to_vec();
    s.sort_unstable();
    s == (0..n).collect::<Vec<_>>()
}

#[test]
fn carve_order_differs_per_seed_and_stays_correct() {
    let n = Slab::<Rand, Hb>::G.objs[class::<Rand>(16)];
    let plain = carve_order::<Plain>(1, 16);
    assert_eq!(plain, (0..n).collect::<Vec<_>>(), "the control carves in address order");
    let a = carve_order::<Rand>(1, 16);
    let b = carve_order::<Rand>(2, 16);
    assert!(is_permutation(&a, n) && is_permutation(&b, n), "an object was skipped or handed out twice");
    assert_ne!(a, plain, "the random order is the address order");
    assert_ne!(a, b, "two seeds gave one order");
    assert_eq!(a, carve_order::<Rand>(1, 16), "one seed gave two orders");
    // The layer's own fallback (no entropy) is still a permutation; and the
    // other classes too, down to the one that fits few objects.
    assert!(is_permutation(&carve_order::<Rand>(0, 16), n));
    for &size in CLASSES {
        let n = Slab::<Rand, Hb>::G.objs[class::<Rand>(size)];
        for seed in [0u64, 3, 99, 12345] {
            assert!(is_permutation(&carve_order::<Rand>(seed, size), n), "class {size} seed {seed}");
        }
    }
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

/// Random alloc/free over every class and several CPUs, each object tagged
/// and re-read before it is freed: nothing is handed out twice or corrupted.
fn stress<P: Params>(seed: u64) {
    let s = new_slab::<P>(seed);
    let mut r = Lcg(seed ^ 0x5555);
    let mut live: Vec<(*mut u8, usize, usize, u8)> = Vec::new();
    for step in 0..40_000u32 {
        set_cpu(match r.next() % 4 { 0 => 0, 1 => 1, 2 => 5, _ => MAX_CPUS });
        if live.len() < 8 || r.next() % 100 < 55 {
            let size = 1 + (r.next() as usize % 1024);
            let c = class::<P>(size);
            let p = unsafe { s.alloc(c, size) };
            assert!(!p.is_null());
            assert_eq!(p as usize % Slab::<P, Hb>::G.align[c].min(16), 0);
            let tag = (step % 251) as u8 + 1;
            unsafe { std::ptr::write_bytes(p, tag, size) };
            live.push((p, size, c, tag));
        } else {
            let i = r.next() as usize % live.len();
            let (p, size, c, tag) = live.swap_remove(i);
            for k in 0..size { assert_eq!(unsafe { *p.add(k) }, tag, "object overwritten while live"); }
            unsafe { s.free(c, p, size) };
        }
        if step % 5000 == 4999 { set_cpu(0); s.reclaim(); }
    }
    for (p, size, c, tag) in live {
        for k in 0..size { assert_eq!(unsafe { *p.add(k) }, tag); }
        unsafe { s.free(c, p, size) };
    }
    set_cpu(0);
    s.reclaim();
}

#[test]
fn allocation_stays_correct_hardened_and_randomized() {
    stress::<Hard>(1);
    stress::<Rand>(2);
    stress::<Rand>(0);
    stress::<RandDebug>(3);
}

// ── buddy ───────────────────────────────────────────────────────────────

struct Bx { _d: Vec<FrameDesc>, t: FrameTable }

fn bx(n: usize, flags: u32) -> Bx {
    let d: Vec<FrameDesc> = (0..n).map(|_| FrameDesc::new(flags)).collect();
    // SAFETY: the vector is not moved or dropped while `Bx` lives.
    let t = unsafe { FrameTable::new(d.as_ptr(), Pfn(0), n) };
    Bx { _d: d, t }
}

/// `n` frames, the even ones free as order-0 blocks (the odd ones are held,
/// so none merges): `n / 2` blocks on the order-0 list.
fn comb(n: usize) -> (Bx, Buddy) {
    let f = bx(n, F_ALLOCATED);
    let mut b = Buddy::new();
    for i in (0..n).step_by(2) {
        f.t.at(i).flags.store(F_FREE, std::sync::atomic::Ordering::Relaxed);
        b.release(&f.t, Pfn(i), 0);
    }
    (f, b)
}

fn drain(f: &Bx, b: &mut Buddy) -> Vec<usize> {
    let mut v = Vec::new();
    while let Some(p) = b.alloc(&f.t, 0) { v.push(p.0); }
    v
}

#[test]
fn buddy_list_order_follows_the_seed() {
    if !azos_limits::ALLOC_RANDOM { return; }
    let order = |seed: u64| {
        let (f, mut b) = comb(128);
        if seed != 0 { b.reseed(&f.t, seed); }
        let v = drain(&f, &mut b);
        let mut s = v.clone();
        s.sort_unstable();
        s.dedup();
        assert_eq!(s.len(), 64, "a block was lost or handed out twice");
        v
    };
    let plain = order(0);
    let a = order(0x1234_5678_9abc_def1);
    let b = order(0x0fed_cba9_8765_4321);
    assert_ne!(a, plain, "seeding left the list order alone");
    assert_ne!(a, b, "two seeds gave one list order");
    assert_eq!(a, order(0x1234_5678_9abc_def1), "one seed gave two orders");
}

#[test]
fn buddy_random_placement_loses_nothing_and_merges_back() {
    if !azos_limits::ALLOC_RANDOM { return; }
    let n = 1usize << MAX_ORDER.min(8);
    let f = bx(n, F_FREE);
    let mut b = Buddy::new();
    b.release_range(&f.t, Pfn(0), Pfn(n));
    b.reseed(&f.t, 0xabcdef);
    let mut r = Lcg(99);
    let mut live: Vec<(usize, usize)> = Vec::new();
    let mut held = vec![false; n];
    for _ in 0..20_000 {
        if live.is_empty() || r.next() % 100 < 52 {
            let o = (r.next() % 5) as usize;
            if let Some(p) = b.alloc(&f.t, o) {
                for i in p.0..p.0 + (1 << o) {
                    assert!(!held[i], "frame {i} handed out twice");
                    held[i] = true;
                }
                live.push((p.0, o));
            }
        } else {
            let (p, o) = live.swap_remove(r.next() as usize % live.len());
            for i in p..p + (1 << o) {
                held[i] = false;
                f.t.at(i).flags.store(F_FREE, std::sync::atomic::Ordering::Relaxed);
            }
            b.release(&f.t, Pfn(p), o);
        }
        if r.next() % 997 == 0 { b.reseed(&f.t, r.next() | 1); }
    }
    for (p, o) in live {
        for i in p..p + (1 << o) {
            f.t.at(i).flags.store(F_FREE, std::sync::atomic::Ordering::Relaxed);
        }
        b.release(&f.t, Pfn(p), o);
    }
    assert_eq!(b.free_frames(), n);
    assert_eq!(b.blocks(n.trailing_zeros() as usize), 1, "the blocks did not merge back into one");
}

fn unlink_panic(damage: impl FnOnce(&Bx)) -> Option<String> {
    let (f, mut b) = comb(64);
    damage(&f);
    let m = panic_of(|| { b.alloc(&f.t, 0); });
    std::mem::forget(b);
    m
}

fn head_of_comb() -> usize { 62 } // the last even frame pushed heads the list

#[test]
fn buddy_unlink_of_a_damaged_list_panics() {
    use std::sync::atomic::Ordering::Relaxed;
    if !azos_limits::SLAB_HARDENED { return; }
    let h = head_of_comb();
    // The second block does not link back to the head.
    let m = unlink_panic(|f| {
        let next = f.t.at(h).next.load(Relaxed) as usize;
        f.t.at(next).prev.store(3, Relaxed);
    }).expect("an unlink through a bad back-link went through");
    assert!(m.contains("corrupt free list"), "{m}");
    // The descriptor names another order than its list.
    assert!(unlink_panic(|f| f.t.at(h).order.store(2, Relaxed)).is_some());
    // A link past the end of the table.
    assert!(unlink_panic(|f| f.t.at(h).next.store(100_000, Relaxed)).is_some());
    // An unlink in the middle: block `h2` found by merging is not the head
    // its predecessor claims.
    let (f, mut b) = comb(64);
    let mid = f.t.at(h).next.load(Relaxed) as usize;
    let after = f.t.at(mid).next.load(Relaxed) as usize;
    f.t.at(after).prev.store(h as u32, Relaxed);
    // Free the odd frame beside `mid`: it merges with `mid`, unlinking it.
    f.t.at(mid + 1).flags.store(F_FREE, Relaxed);
    let m = panic_of(|| b.release(&f.t, Pfn(mid + 1), 0));
    std::mem::forget(b);
    assert!(m.is_some(), "a merge unlinked a block its neighbour does not link back to");
    // Control: an undamaged list allocates.
    assert!(unlink_panic(|_| {}).is_none());
}
