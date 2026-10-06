// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-CPU magazine cache of fixed size classes in front of the kernel heap
//! (wave 15, SLAB). `kheap.rs` routes every small `GlobalAlloc` request here;
//! large ones, and every request when Kconfig `KHEAP_SLAB` is off, go to the
//! first-fit heap as before.
//!
//! Three layers, after Bonwick's magazines (USENIX 2001) and Linux SLUB:
//!
//! 1. **Per-CPU magazines.** Each CPU holds, per class, a `loaded` and a
//!    `prev` magazine: a stack of free object pointers. Alloc pops `loaded`,
//!    free pushes it; both are O(1), take no lock, and touch only the
//!    calling CPU's line. They run with the CPU's interrupts masked
//!    ([`Backing::irq_off`]), which is what makes them safe against an
//!    interrupt handler that allocates on the same CPU and keeps the task
//!    from migrating mid-operation. That masked window is the fast path
//!    plus, on a miss, at most one magazine's worth of slab work: never a
//!    heap walk (below).
//! 2. **Depot.** Per class, under that class's lock: full magazines (at most
//!    `DEPOT_MAGS`) and empty ones, exchanged with a CPU as in Bonwick: a CPU
//!    whose two magazines are empty takes a full one, a CPU whose two are
//!    full takes an empty one. A depot at its cap is not grown: a full
//!    magazine is flushed back to its slabs instead.
//! 3. **Slabs.** Power-of-two chunks taken from the backing heap, aligned to
//!    their size, objects from the base, a [`SlabHdr`] in the last [`HDR`]
//!    bytes: `ptr & !(slab_bytes - 1)` finds an object's slab on free, with
//!    no lookup table. A slab whose last object comes back is returned to
//!    the heap once its class keeps `KEEP_EMPTY` empty slabs, so memory a
//!    burst of small objects used goes back to the large allocations.
//!
//! Magazines themselves are objects of an internal class ([`MAGC`]) with
//! slabs of their own, so the heap only ever sees slab-sized, slab-aligned
//! blocks from this layer: small magazine blocks scattered between slabs
//! would leave holes every large first-fit allocation then walks past.
//!
//! **Cross-CPU free** needs nothing special: a magazine holds any free object
//! of its class, and slabs are reached only under the class lock.
//!
//! **Heap walks are never made with interrupts masked by this code.** A slab
//! is allocated from the heap with the caller's interrupt state restored
//! first, then the operation starts over (the task may have moved CPU). A
//! caller that arrived with interrupts already masked (an interrupt handler,
//! an `irqsave` section) reaches the heap masked, as it did before this layer
//! existed, and never returns slabs to it; the kernel backing refuses rather
//! than deadlocks when that hart already holds the heap lock.
//!
//! **Refusal stays a refusal.** Every path that cannot get memory returns
//! null; nothing here panics on exhaustion. The debug checks (poison and red
//! zone, `P::DEBUG`) panic on the corruption they find, which is their purpose.
//!
//! The module depends on `core` only and is pulled into `tests/host/mm-tests`
//! with `#[path]`, so the host suite runs this exact code.

use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};

/// Upper bound on classes (table sizes; Kconfig picks how many are used).
pub const MAX_CLASSES: usize = 16;
/// The internal class of magazines (after the last possible user class).
pub const MAGC: usize = MAX_CLASSES;
const NC: usize = MAX_CLASSES + 1;
/// [`Slab::class_of`]'s answer for "not a class: the heap".
pub const NO_CLASS: usize = usize::MAX;
/// Upper bound on CPUs with a magazine cache. A CPU id at or above it is
/// served from the slabs directly, correct but locked.
pub const MAX_CPUS: usize = 8;
/// Largest object size a class may have.
pub const MAX_CLASS_BYTES: usize = 4096;
/// Size-to-class table entries: one per 8 bytes up to the largest class.
const LUT_LEN: usize = MAX_CLASS_BYTES / 8 + 1;
/// Bytes at a slab's end holding its [`SlabHdr`].
pub const HDR: usize = 64;
/// Fill byte of a free object (`P::DEBUG`).
pub const POISON: u8 = 0x6b;
/// Fill byte between the requested size and the class size (`P::DEBUG`).
pub const REDZONE: u8 = 0xbb;

/// What a build chooses (Kconfig in the kernel, anything in host tests).
pub trait Params {
    /// Object sizes, ascending, multiples of 8, at most [`MAX_CLASS_BYTES`].
    const CLASSES: &'static [usize];
    /// Most objects a magazine holds.
    const MAG_DEPTH: usize;
    /// Most bytes one CPU caches in magazines, all classes together; each
    /// class's depth is cut to fit its share (never below 1).
    const CPU_CACHE_BYTES: usize;
    /// Most full magazines one class keeps in the depot.
    const DEPOT_MAGS: usize;
    /// Smallest slab (a power of two); a class gets the smallest power of
    /// two at least this large that holds `MIN_OBJS` objects.
    const SLAB_BYTES: usize;
    /// Fewest objects a slab is made to hold.
    const MIN_OBJS: usize;
    /// Empty slabs one class keeps instead of returning them.
    const KEEP_EMPTY: usize;
    /// Poison free objects and fill red zones; check both.
    const DEBUG: bool;
}

/// Where slabs come from, and the CPU environment.
///
/// # Safety
/// `cpu` must be stable while interrupts are off (`irq_off` .. `irq_restore`)
/// and unique to the calling CPU; `irq_off` and `irq_restore` must order
/// memory accesses (a compiler barrier at least); `alloc` must return null
/// or memory of the size and alignment asked, not otherwise in use.
pub unsafe trait Backing {
    /// Allocate `size` bytes aligned to `align`, or null.
    fn alloc(&self, size: usize, align: usize) -> *mut u8;
    /// Return memory `alloc` gave.
    fn free(&self, p: *mut u8, size: usize, align: usize);
    /// Mask interrupts on this CPU; the token restores the previous state.
    fn irq_off(&self) -> usize;
    /// Restore the state `irq_off` returned.
    fn irq_restore(&self, token: usize);
    /// Whether the token says interrupts were on before `irq_off`.
    fn was_on(&self, token: usize) -> bool;
    /// This CPU's index. Called with interrupts off.
    fn cpu(&self) -> usize;
}

/// The per-class numbers derived from [`Params`] at compile time. Index
/// [`MAGC`] is the magazine class.
pub struct Geometry {
    pub n: usize,
    pub size: [usize; NC],
    pub depth: [usize; NC],
    pub slab_bytes: [usize; NC],
    pub objs: [usize; NC],
    /// Natural alignment of the class's objects.
    pub align: [usize; NC],
    /// Requests aligned to at most this take the table lookup unchecked.
    pub fast_align: usize,
    /// Largest class size.
    pub max: usize,
    /// `(size + 7) / 8` -> smallest class that holds `size`.
    pub lut: [u8; LUT_LEN],
}

const fn slab_for(size: usize, slab: usize, min_objs: usize) -> usize {
    let mut sb = slab;
    while (sb - HDR) / size < min_objs { sb *= 2; }
    sb
}

impl Geometry {
    pub const fn new(classes: &[usize], depth: usize, cpu_cache: usize, slab: usize, min_objs: usize) -> Self {
        let n = classes.len();
        assert!(n >= 1 && n <= MAX_CLASSES, "slab: 1..=16 classes");
        assert!(slab.is_power_of_two() && slab >= 1024, "slab: SLAB_BYTES must be a power of two >= 1024");
        assert!(depth >= 1 && depth <= 1024, "slab: magazine depth 1..=1024");
        assert!(min_objs >= 1 && min_objs <= 256, "slab: 1..=256 objects per slab");
        let mut g = Geometry {
            n,
            size: [0; NC],
            depth: [0; NC],
            slab_bytes: [0; NC],
            objs: [0; NC],
            align: [0; NC],
            fast_align: MAX_CLASS_BYTES,
            max: classes[n - 1],
            lut: [0; LUT_LEN],
        };
        let mut i = 0;
        while i < n {
            let s = classes[i];
            assert!(s >= 8 && s % 8 == 0 && s <= MAX_CLASS_BYTES, "slab: class sizes are multiples of 8 up to 4096");
            assert!(i == 0 || s > classes[i - 1], "slab: class sizes must ascend");
            g.size[i] = s;
            let a = s & s.wrapping_neg();
            g.align[i] = a;
            if a < g.fast_align { g.fast_align = a; }
            let sb = slab_for(s, slab, min_objs);
            g.slab_bytes[i] = sb;
            g.objs[i] = (sb - HDR) / s;
            let mut d = cpu_cache / (n * 2 * s);
            if d > depth { d = depth; }
            if d < 1 { d = 1; }
            g.depth[i] = d;
            i += 1;
        }
        // The magazine class: one object holds the deepest magazine.
        let ms = (Mag::bytes(depth) + 15) & !15;
        g.size[MAGC] = ms;
        g.align[MAGC] = 16;
        g.slab_bytes[MAGC] = slab_for(ms, slab, min_objs);
        g.objs[MAGC] = (g.slab_bytes[MAGC] - HDR) / ms;
        // The lookup: every 8-byte step up to the largest class.
        let mut k = 0;
        let mut c = 0;
        while k < LUT_LEN {
            let need = k * 8;
            while c < n && classes[c] < need { c += 1; }
            g.lut[k] = if c < n { c as u8 } else { u8::MAX };
            k += 1;
        }
        g
    }
}

/// A stack of free objects of one class; the pointers follow the header.
#[repr(C)]
struct Mag {
    n: usize,
    cap: usize,
    next: *mut Mag,
}

impl Mag {
    #[inline(always)]
    unsafe fn objs(m: *mut Mag) -> *mut *mut u8 {
        unsafe { (m as *mut u8).add(core::mem::size_of::<Mag>()) as *mut *mut u8 }
    }
    const fn bytes(depth: usize) -> usize {
        core::mem::size_of::<Mag>() + depth * core::mem::size_of::<usize>()
    }
}

/// `n == cap == 0`: alloc and free both miss on it, and neither writes it.
struct Sentinel(UnsafeCell<Mag>);
unsafe impl Sync for Sentinel {}
static EMPTY_MAG: Sentinel = Sentinel(UnsafeCell::new(Mag { n: 0, cap: 0, next: null_mut() }));

#[inline(always)]
fn sentinel() -> *mut Mag { EMPTY_MAG.0.get() }

/// At the end of every slab.
#[repr(C)]
struct SlabHdr {
    free: *mut FreeObj,
    inuse: usize,
    carved: usize,
    next: *mut SlabHdr,
    prev: *mut SlabHdr,
}
const _: () = assert!(core::mem::size_of::<SlabHdr>() <= HDR);

#[repr(C)]
struct FreeObj { next: *mut FreeObj }

/// One class's depot and slab lists.
struct ClassState {
    /// Slabs with at least one free object (empty ones included).
    partial: *mut SlabHdr,
    /// Empty slabs among `partial`.
    nempty: usize,
    /// All slabs.
    slabs: usize,
    /// Free objects inside slabs (carved or not).
    slab_free: usize,
    full: *mut Mag,
    nfull: usize,
    /// Objects in the full magazines.
    depot_objs: usize,
    empty: *mut Mag,
    nempty_mags: usize,
    /// Times the lock was taken (diagnostic; the host O(1) rows read it).
    locks: u64,
    /// Magazines this class holds (its CPUs' and its depot's).
    mags: usize,
}

struct ClassLock {
    locked: AtomicBool,
    st: UnsafeCell<ClassState>,
}

impl ClassLock {
    const fn new() -> Self {
        ClassLock {
            locked: AtomicBool::new(false),
            st: UnsafeCell::new(ClassState {
                partial: null_mut(), nempty: 0, slabs: 0, slab_free: 0, full: null_mut(), nfull: 0,
                depot_objs: 0, empty: null_mut(), nempty_mags: 0, locks: 0, mags: 0,
            }),
        }
    }
    /// Spin for the lock. Only ever taken with interrupts off, so neither
    /// an interrupt nor a preemption can reach it again on this CPU.
    #[inline]
    #[allow(clippy::mut_from_ref)]
    fn lock(&self) -> &mut ClassState {
        while self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            while self.locked.load(Ordering::Relaxed) { core::hint::spin_loop(); }
        }
        let st = unsafe { &mut *self.st.get() };
        st.locks += 1;
        st
    }
    #[inline]
    fn unlock(&self) { self.locked.store(false, Ordering::Release); }
}

#[repr(C, align(64))]
struct CpuCache {
    loaded: [*mut Mag; MAX_CLASSES],
    prev: [*mut Mag; MAX_CLASSES],
}

struct CpuSlot(UnsafeCell<CpuCache>);

/// A snapshot of one class (racy against other CPUs' magazines).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClassStats {
    pub size: usize,
    pub slabs: usize,
    pub slab_bytes: usize,
    pub slab_free: usize,
    pub depot_full: usize,
    pub depot_objs: usize,
    pub depot_empty: usize,
    pub cpu_objs: usize,
    pub mags: usize,
    pub locks: u64,
}

/// The allocator: per-CPU magazines, depot and slabs for each class of `P`.
pub struct Slab<P: Params, B: Backing> {
    cpus: [CpuSlot; MAX_CPUS],
    classes: [ClassLock; NC],
    backing: B,
    _p: core::marker::PhantomData<P>,
}

// Safety: per-CPU state is touched only by its CPU with interrupts off, and
// class state only under its lock.
unsafe impl<P: Params, B: Backing + Sync> Sync for Slab<P, B> {}
unsafe impl<P: Params, B: Backing + Send> Send for Slab<P, B> {}

/// Slabs to give back once the lock is dropped and interrupts are as the
/// caller had them. The class index travels in the dead slab's `carved`.
struct Release(*mut SlabHdr);

impl<P: Params, B: Backing> Slab<P, B> {
    pub const G: Geometry = Geometry::new(P::CLASSES, P::MAG_DEPTH, P::CPU_CACHE_BYTES, P::SLAB_BYTES, P::MIN_OBJS);

    pub const fn new(backing: B) -> Self {
        // Forces the geometry checks at compile time for this `P`.
        let _ = Self::G.n;
        Slab {
            cpus: [const {
                CpuSlot(UnsafeCell::new(CpuCache {
                    loaded: [EMPTY_MAG.0.get(); MAX_CLASSES],
                    prev: [EMPTY_MAG.0.get(); MAX_CLASSES],
                }))
            }; MAX_CPUS],
            classes: [const { ClassLock::new() }; NC],
            backing,
            _p: core::marker::PhantomData,
        }
    }

    pub fn backing(&self) -> &B { &self.backing }

    /// The class serving `size` bytes aligned to `align`, or [`NO_CLASS`]
    /// (the heap). Any other answer is below `G.n`.
    #[inline(always)]
    pub fn class_of(size: usize, align: usize) -> usize {
        let g = &Self::G;
        if size <= g.max && align <= g.fast_align {
            // In range: (size + 7) >> 3 <= max / 8 < LUT_LEN, and every entry
            // up to max / 8 names a class.
            return unsafe { *g.lut.get_unchecked((size + 7) >> 3) } as usize;
        }
        Self::class_of_aligned(size, align)
    }

    #[inline(never)]
    fn class_of_aligned(size: usize, align: usize) -> usize {
        let g = &Self::G;
        if size > g.max { return NO_CLASS; }
        let mut c = g.lut[(size + 7) >> 3] as usize;
        while c < g.n {
            if g.align[c] >= align { return c; }
            c += 1;
        }
        NO_CLASS
    }

    #[inline(always)]
    fn slab_of(c: usize, p: *mut u8) -> *mut SlabHdr {
        let sb = Self::G.slab_bytes[c];
        ((p as usize & !(sb - 1)) + sb - HDR) as *mut SlabHdr
    }

    /// The class of a request the lookup table answers without a check of
    /// alignment, or [`NO_CLASS`] for every other request (which
    /// [`Self::class_of`] may still place). The kernel's inlined fast path.
    #[inline(always)]
    pub fn class_fast(size: usize, align: usize) -> usize {
        let g = &Self::G;
        if size <= g.max && align <= g.fast_align {
            return unsafe { *g.lut.get_unchecked((size + 7) >> 3) } as usize;
        }
        NO_CLASS
    }

    /// The magazine pop alone: an object of class `c`, or null when this
    /// CPU's `loaded` magazine is empty (the caller then takes [`Self::alloc`]).
    /// No call, no lock. Not for `P::DEBUG` builds (no poison check).
    ///
    /// # Safety
    /// `c < G.n`.
    #[inline(always)]
    pub unsafe fn alloc_fast(&self, c: usize) -> *mut u8 {
        let t = self.backing.irq_off();
        let cpu = self.backing.cpu();
        let mut p = null_mut();
        if cpu < MAX_CPUS {
            unsafe {
                let pc = &mut *self.cpus.get_unchecked(cpu).0.get();
                let m = *pc.loaded.get_unchecked(c);
                let n = (*m).n;
                if n != 0 {
                    (*m).n = n - 1;
                    p = *Mag::objs(m).add(n - 1);
                }
            }
        }
        self.backing.irq_restore(t);
        p
    }

    /// The magazine push alone: true when `p` went into this CPU's `loaded`
    /// magazine, false when it is full (the caller then takes [`Self::free`]).
    /// Not for `P::DEBUG` builds.
    ///
    /// # Safety
    /// As [`Self::free`].
    #[inline(always)]
    pub unsafe fn free_fast(&self, c: usize, p: *mut u8) -> bool {
        let t = self.backing.irq_off();
        let cpu = self.backing.cpu();
        let mut done = false;
        if cpu < MAX_CPUS {
            unsafe {
                let pc = &mut *self.cpus.get_unchecked(cpu).0.get();
                let m = *pc.loaded.get_unchecked(c);
                let n = (*m).n;
                if n < (*m).cap {
                    *Mag::objs(m).add(n) = p;
                    (*m).n = n + 1;
                    done = true;
                }
            }
        }
        self.backing.irq_restore(t);
        done
    }

    /// Allocate one object of class `c` for a request of `req` bytes.
    ///
    /// # Safety
    /// `c` came from [`Self::class_of`] for a request of `req` bytes and is
    /// not [`NO_CLASS`].
    #[inline(always)]
    pub unsafe fn alloc(&self, c: usize, req: usize) -> *mut u8 {
        let t = self.backing.irq_off();
        let cpu = self.backing.cpu();
        if cpu < MAX_CPUS {
            unsafe {
                let pc = &mut *self.cpus.get_unchecked(cpu).0.get();
                let m = *pc.loaded.get_unchecked(c);
                let n = (*m).n;
                if n != 0 {
                    (*m).n = n - 1;
                    let p = *Mag::objs(m).add(n - 1);
                    self.backing.irq_restore(t);
                    if P::DEBUG { Self::debug_on_alloc(c, p, req); }
                    return p;
                }
            }
        }
        let p = unsafe { self.alloc_slow(c, t) };
        if P::DEBUG && !p.is_null() { Self::debug_on_alloc(c, p, req); }
        p
    }

    /// Free an object of class `c` that a request of `req` bytes got.
    ///
    /// # Safety
    /// `p` came from [`Self::alloc`] with this `c` and has not been freed.
    #[inline(always)]
    pub unsafe fn free(&self, c: usize, p: *mut u8, req: usize) {
        if P::DEBUG { Self::debug_on_free(c, p, req); }
        let t = self.backing.irq_off();
        let cpu = self.backing.cpu();
        if cpu < MAX_CPUS {
            unsafe {
                let pc = &mut *self.cpus.get_unchecked(cpu).0.get();
                let m = *pc.loaded.get_unchecked(c);
                let n = (*m).n;
                if n < (*m).cap {
                    *Mag::objs(m).add(n) = p;
                    (*m).n = n + 1;
                    self.backing.irq_restore(t);
                    return;
                }
            }
        }
        unsafe { self.free_slow(c, p, t) }
    }

    /// A magazine object for class `c`, from the magazine slabs, or null
    /// when none is free. Interrupts off; no lock held.
    unsafe fn mag_get(&self, c: usize) -> *mut Mag {
        let mc = &self.classes[MAGC];
        let st = mc.lock();
        let p = unsafe { Self::slab_get(st, MAGC) } as *mut Mag;
        mc.unlock();
        if !p.is_null() {
            unsafe {
                (*p).n = 0;
                (*p).cap = Self::G.depth[c];
                (*p).next = null_mut();
            }
        }
        p
    }

    /// [`Self::mag_get`], and when the magazine slabs are full, one more
    /// magazine slab from the heap, with the caller's interrupt state
    /// restored around it (a slab is allocated like any object's: see the
    /// module doc). Updates `t` across the restore.
    unsafe fn mag_new(&self, c: usize, t: &mut usize) -> *mut Mag {
        let m = unsafe { self.mag_get(c) };
        if !m.is_null() { return m; }
        let on = self.backing.was_on(*t);
        if on { self.backing.irq_restore(*t); }
        let sb = Self::G.slab_bytes[MAGC];
        let slab = self.backing.alloc(sb, sb);
        if on { *t = self.backing.irq_off(); }
        if slab.is_null() { return null_mut(); }
        let mc = &self.classes[MAGC];
        let st = mc.lock();
        unsafe { Self::slab_add(st, MAGC, slab) };
        mc.unlock();
        unsafe { self.mag_get(c) }
    }

    /// Hand a new empty magazine to class `c`'s depot. Interrupts off.
    unsafe fn depot_take_empty(&self, c: usize, m: *mut Mag) {
        let cl = &self.classes[c];
        let st = cl.lock();
        unsafe {
            (*m).next = st.empty;
        }
        st.empty = m;
        st.nempty_mags += 1;
        st.mags += 1;
        cl.unlock();
    }

    /// Everything after a miss on `loaded`. Entered with interrupts off
    /// (token `t`); returns with them restored.
    #[inline(never)]
    unsafe fn alloc_slow(&self, c: usize, mut t: usize) -> *mut u8 {
        let g = &Self::G;
        let cl = &self.classes[c];
        loop {
            let cpu = self.backing.cpu();
            if cpu < MAX_CPUS {
                let pc = unsafe { &mut *self.cpus[cpu].0.get() };
                unsafe {
                    // 1. The previous magazine has objects: swap.
                    let prev = pc.prev[c];
                    if (*prev).n != 0 {
                        pc.prev[c] = pc.loaded[c];
                        pc.loaded[c] = prev;
                        let n = (*prev).n - 1;
                        (*prev).n = n;
                        let p = *Mag::objs(prev).add(n);
                        self.backing.irq_restore(t);
                        return p;
                    }
                    let st = cl.lock();
                    // 2. A full magazine from the depot; both of ours are empty.
                    if !st.full.is_null() {
                        let f = st.full;
                        st.full = (*f).next;
                        st.nfull -= 1;
                        st.depot_objs -= (*f).n;
                        if prev != sentinel() {
                            (*prev).next = st.empty;
                            st.empty = prev;
                            st.nempty_mags += 1;
                        }
                        pc.prev[c] = pc.loaded[c];
                        pc.loaded[c] = f;
                        cl.unlock();
                        let n = (*f).n - 1;
                        (*f).n = n;
                        let p = *Mag::objs(f).add(n);
                        self.backing.irq_restore(t);
                        return p;
                    }
                    // 3. Fill a magazine of ours (or the depot's) from the slabs.
                    let mut m = pc.loaded[c];
                    if m == sentinel() {
                        if prev != sentinel() {
                            m = prev;
                            pc.prev[c] = sentinel();
                        } else if !st.empty.is_null() {
                            m = st.empty;
                            st.empty = (*m).next;
                            st.nempty_mags -= 1;
                        }
                        if m != sentinel() { pc.loaded[c] = m; }
                    }
                    if m != sentinel() {
                        let cap = (*m).cap;
                        let objs = Mag::objs(m);
                        let mut n = (*m).n;
                        while n < cap {
                            let p = Self::slab_get(st, c);
                            if p.is_null() { break; }
                            *objs.add(n) = p;
                            n += 1;
                        }
                        if n != 0 {
                            cl.unlock();
                            n -= 1;
                            (*m).n = n;
                            let p = *objs.add(n);
                            self.backing.irq_restore(t);
                            return p;
                        }
                    } else {
                        let p = Self::slab_get(st, c);
                        if !p.is_null() {
                            cl.unlock();
                            self.backing.irq_restore(t);
                            return p;
                        }
                    }
                    cl.unlock();
                    // 4. Memory: a magazine first if this CPU has none (from
                    //    the magazine slabs, no heap walk when one is free).
                    if pc.loaded[c] == sentinel() {
                        let mag = self.mag_new(c, &mut t);
                        if !mag.is_null() { self.depot_take_empty(c, mag); }
                    }
                }
            } else {
                // No magazines on this CPU: straight from the slabs.
                let st = cl.lock();
                let p = unsafe { Self::slab_get(st, c) };
                cl.unlock();
                if !p.is_null() { self.backing.irq_restore(t); return p; }
            }
            // 5. A slab from the heap, interrupts as the caller had them.
            let on = self.backing.was_on(t);
            if on { self.backing.irq_restore(t); }
            let sb = g.slab_bytes[c];
            let slab = self.backing.alloc(sb, sb);
            if on { t = self.backing.irq_off(); }
            let st = cl.lock();
            if !slab.is_null() {
                unsafe { Self::slab_add(st, c, slab) };
            } else if st.slab_free == 0 && (st.nfull == 0 || cpu >= MAX_CPUS) {
                // Nothing to give: refused. (Another CPU may have freed into
                // the slabs or the depot meanwhile; then the loop serves it.)
                cl.unlock();
                self.backing.irq_restore(t);
                return null_mut();
            }
            cl.unlock();
        }
    }

    /// Everything after `loaded` was full. Entered with interrupts off
    /// (token `t`); returns with them restored.
    #[inline(never)]
    unsafe fn free_slow(&self, c: usize, p: *mut u8, mut t: usize) {
        let cl = &self.classes[c];
        let mut tried = false;
        loop {
            let cpu = self.backing.cpu();
            let mut rel = Release(null_mut());
            if cpu >= MAX_CPUS {
                let st = cl.lock();
                unsafe { Self::slab_put(st, c, p, &mut rel) };
                cl.unlock();
                return self.finish(t, rel);
            }
            let pc = unsafe { &mut *self.cpus[cpu].0.get() };
            unsafe {
                // 1. The previous magazine is empty: swap.
                let prev = pc.prev[c];
                if (*prev).n == 0 && (*prev).cap != 0 {
                    pc.prev[c] = pc.loaded[c];
                    pc.loaded[c] = prev;
                    *Mag::objs(prev) = p;
                    (*prev).n = 1;
                    self.backing.irq_restore(t);
                    return;
                }
                let st = cl.lock();
                let m = pc.loaded[c];
                // 2. Bonwick's exchange: an empty magazine from the depot
                //    becomes `loaded`, the full `loaded` becomes `prev`, and
                //    a non-empty `prev` goes to the depot. With the depot at
                //    its cap, `prev` is flushed to the slabs instead and the
                //    two are swapped, no depot magazine needed.
                if m != sentinel() && prev != sentinel() && st.nfull >= P::DEPOT_MAGS {
                    Self::flush(st, c, prev, &mut rel);
                    cl.unlock();
                    pc.prev[c] = m;
                    pc.loaded[c] = prev;
                    *Mag::objs(prev) = p;
                    (*prev).n = 1;
                    return self.finish(t, rel);
                }
                if !st.empty.is_null() {
                    let e = st.empty;
                    st.empty = (*e).next;
                    st.nempty_mags -= 1;
                    if m != sentinel() {
                        if prev != sentinel() {
                            (*prev).next = st.full;
                            st.full = prev;
                            st.nfull += 1;
                            st.depot_objs += (*prev).n;
                        }
                        pc.prev[c] = m;
                    }
                    pc.loaded[c] = e;
                    cl.unlock();
                    *Mag::objs(e) = p;
                    (*e).n = 1;
                    self.backing.irq_restore(t);
                    return;
                }
                // 3. No empty magazine: make one, once.
                if !tried {
                    cl.unlock();
                    tried = true;
                    let mag = self.mag_new(c, &mut t);
                    if !mag.is_null() { self.depot_take_empty(c, mag); }
                    continue;
                }
                // 4. Back to the slabs: the whole full magazine when there
                //    is one (it is then reused), else just this object.
                if m != sentinel() {
                    Self::flush(st, c, m, &mut rel);
                    cl.unlock();
                    *Mag::objs(m) = p;
                    (*m).n = 1;
                } else {
                    Self::slab_put(st, c, p, &mut rel);
                    cl.unlock();
                }
                return self.finish(t, rel);
            }
        }
    }

    /// Restore interrupts, then give back the slabs on `rel`. With
    /// interrupts masked by the caller (an interrupt handler) the slabs are
    /// kept instead: returning them would walk the heap with interrupts off.
    fn finish(&self, t: usize, rel: Release) {
        self.backing.irq_restore(t);
        if rel.0.is_null() { return; }
        if self.backing.was_on(t) { self.release(rel) } else { self.keep(rel) }
    }

    fn release(&self, rel: Release) {
        let mut h = rel.0;
        while !h.is_null() {
            unsafe {
                let next = (*h).next;
                let sb = Self::G.slab_bytes[(*h).carved];
                let base = (h as usize + HDR) - sb;
                self.backing.free(base as *mut u8, sb, sb);
                h = next;
            }
        }
    }

    /// Put released slabs back as kept empties.
    fn keep(&self, rel: Release) {
        let t = self.backing.irq_off();
        let mut h = rel.0;
        while !h.is_null() {
            unsafe {
                let next = (*h).next;
                let c = (*h).carved;
                let cl = &self.classes[c];
                let st = cl.lock();
                (*h).carved = 0;
                (*h).free = null_mut();
                (*h).inuse = 0;
                st.slabs += 1;
                st.slab_free += Self::G.objs[c];
                Self::partial_push(st, h);
                st.nempty += 1;
                cl.unlock();
                h = next;
            }
        }
        self.backing.irq_restore(t);
    }

    // ── slab layer (class lock held) ────────────────────────────────────────

    unsafe fn partial_push(st: &mut ClassState, h: *mut SlabHdr) {
        unsafe {
            (*h).prev = null_mut();
            (*h).next = st.partial;
            if !st.partial.is_null() { (*st.partial).prev = h; }
            st.partial = h;
        }
    }

    unsafe fn partial_remove(st: &mut ClassState, h: *mut SlabHdr) {
        unsafe {
            if (*h).prev.is_null() { st.partial = (*h).next; } else { (*(*h).prev).next = (*h).next; }
            if !(*h).next.is_null() { (*(*h).next).prev = (*h).prev; }
            (*h).next = null_mut();
            (*h).prev = null_mut();
        }
    }

    unsafe fn slab_add(st: &mut ClassState, c: usize, base: *mut u8) {
        let sb = Self::G.slab_bytes[c];
        let h = (base as usize + sb - HDR) as *mut SlabHdr;
        unsafe {
            (*h).free = null_mut();
            (*h).inuse = 0;
            (*h).carved = 0;
            Self::partial_push(st, h);
        }
        st.slabs += 1;
        st.nempty += 1;
        st.slab_free += Self::G.objs[c];
    }

    unsafe fn slab_get(st: &mut ClassState, c: usize) -> *mut u8 {
        let h = st.partial;
        if h.is_null() { return null_mut(); }
        let g = &Self::G;
        unsafe {
            let p = if !(*h).free.is_null() {
                let o = (*h).free;
                // Canary: the head is handed out but stays on the list.
                #[cfg(not(feature = "slab-freelist-canary"))]
                { (*h).free = (*o).next; }
                o as *mut u8
            } else {
                let sb = g.slab_bytes[c];
                let base = h as usize + HDR - sb;
                // Canary: objects one word past their natural slot.
                let skew = if cfg!(feature = "slab-align-canary") { 8 } else { 0 };
                let o = (base + skew + (*h).carved * g.size[c]) as *mut u8;
                (*h).carved += 1;
                if P::DEBUG { core::ptr::write_bytes(o, POISON, g.size[c]); }
                o
            };
            if (*h).inuse == 0 { st.nempty -= 1; }
            (*h).inuse += 1;
            st.slab_free -= 1;
            if (*h).inuse == g.objs[c] { Self::partial_remove(st, h); }
            p
        }
    }

    unsafe fn slab_put(st: &mut ClassState, c: usize, p: *mut u8, rel: &mut Release) {
        let g = &Self::G;
        let h = Self::slab_of(c, p);
        unsafe {
            let o = p as *mut FreeObj;
            (*o).next = (*h).free;
            (*h).free = o;
            if (*h).inuse == g.objs[c] { Self::partial_push(st, h); }
            (*h).inuse -= 1;
            st.slab_free += 1;
            if (*h).inuse == 0 {
                if st.nempty < P::KEEP_EMPTY {
                    st.nempty += 1;
                } else {
                    Self::slab_drop(st, c, h, rel);
                }
            }
        }
    }

    /// Take an empty slab off its class onto `rel`.
    unsafe fn slab_drop(st: &mut ClassState, c: usize, h: *mut SlabHdr, rel: &mut Release) {
        unsafe {
            Self::partial_remove(st, h);
            st.slabs -= 1;
            st.slab_free -= Self::G.objs[c];
            (*h).carved = c;
            (*h).next = rel.0;
            rel.0 = h;
        }
    }

    /// Every empty slab of a class onto `rel`, the kept ones too.
    unsafe fn drop_empties(st: &mut ClassState, c: usize, rel: &mut Release) {
        let mut h = st.partial;
        while !h.is_null() {
            unsafe {
                let next = (*h).next;
                if (*h).inuse == 0 {
                    st.nempty -= 1;
                    Self::slab_drop(st, c, h, rel);
                }
                h = next;
            }
        }
    }

    unsafe fn flush(st: &mut ClassState, c: usize, m: *mut Mag, rel: &mut Release) {
        unsafe {
            let objs = Mag::objs(m);
            let n = (*m).n;
            let mut i = 0;
            while i < n {
                Self::slab_put(st, c, *objs.add(i), rel);
                i += 1;
            }
            (*m).n = 0;
        }
    }

    /// Give back to the backing everything this CPU and the depots cache:
    /// this CPU's magazines and the depots' full ones are flushed into their
    /// slabs, magazines go back to the magazine slabs, and every empty slab
    /// is returned (the `KEEP_EMPTY` ones too). Other CPUs' magazines are
    /// theirs and are not touched. Called by the kernel heap when the heap
    /// refuses, before its one retry. Returns the bytes given back; 0 with
    /// interrupts masked by the caller, which flushes but returns nothing.
    ///
    /// Each class is done in its own masked window; the heap is written
    /// only with the caller's interrupt state restored.
    pub fn reclaim(&self) -> usize {
        let g = &Self::G;
        let mut bytes = 0;
        let mut c = 0;
        while c <= g.n {
            // The magazine class last, after every class gave its magazines back.
            let k = if c == g.n { MAGC } else { c };
            let t = self.backing.irq_off();
            let cpu = self.backing.cpu();
            let cl = &self.classes[k];
            let mut rel = Release(null_mut());
            let mut mags: *mut Mag = null_mut();
            let st = cl.lock();
            unsafe {
                if k != MAGC {
                    if cpu < MAX_CPUS {
                        let pc = &mut *self.cpus[cpu].0.get();
                        for m in [pc.loaded[k], pc.prev[k]] {
                            if m != sentinel() {
                                Self::flush(st, k, m, &mut rel);
                                (*m).next = mags;
                                mags = m;
                                st.mags -= 1;
                            }
                        }
                        pc.loaded[k] = sentinel();
                        pc.prev[k] = sentinel();
                    }
                    while !st.full.is_null() {
                        let m = st.full;
                        st.full = (*m).next;
                        st.nfull -= 1;
                        st.depot_objs -= (*m).n;
                        Self::flush(st, k, m, &mut rel);
                        (*m).next = mags;
                        mags = m;
                        st.mags -= 1;
                    }
                    while !st.empty.is_null() {
                        let m = st.empty;
                        st.empty = (*m).next;
                        st.nempty_mags -= 1;
                        (*m).next = mags;
                        mags = m;
                        st.mags -= 1;
                    }
                }
                Self::drop_empties(st, k, &mut rel);
            }
            cl.unlock();
            // The magazines back to their slabs (their empties are dropped
            // when the magazine class's own turn comes).
            if !mags.is_null() {
                let mc = &self.classes[MAGC];
                let st = mc.lock();
                let mut m = mags;
                while !m.is_null() {
                    unsafe {
                        let next = (*m).next;
                        Self::slab_put(st, MAGC, m as *mut u8, &mut rel);
                        m = next;
                    }
                }
                mc.unlock();
            }
            if self.backing.was_on(t) {
                let mut h = rel.0;
                while !h.is_null() {
                    unsafe {
                        bytes += g.slab_bytes[(*h).carved];
                        h = (*h).next;
                    }
                }
            }
            self.finish(t, rel);
            c += 1;
        }
        bytes
    }

    /// Bytes held by this layer that no caller owns: free objects in slabs,
    /// the depot and every CPU's magazines (read without their CPUs' masks,
    /// so a snapshot). Magazines and slab headers and tails count as used.
    pub fn cached_bytes(&self) -> usize {
        let mut b = 0;
        let mut c = 0;
        while c < Self::G.n {
            let s = self.stats(c);
            b += (s.slab_free + s.depot_objs + s.cpu_objs) * s.size;
            c += 1;
        }
        b
    }

    /// A snapshot of class `c` ([`MAGC`] for the magazines).
    pub fn stats(&self, c: usize) -> ClassStats {
        let g = &Self::G;
        let t = self.backing.irq_off();
        let cl = &self.classes[c];
        let st = cl.lock();
        st.locks -= 1; // not this read
        let mut s = ClassStats {
            size: g.size[c], slabs: st.slabs, slab_bytes: g.slab_bytes[c], slab_free: st.slab_free,
            depot_full: st.nfull, depot_objs: st.depot_objs, depot_empty: st.nempty_mags,
            cpu_objs: 0, mags: st.mags, locks: st.locks,
        };
        cl.unlock();
        self.backing.irq_restore(t);
        if c < MAX_CLASSES {
            let mut cpu = 0;
            while cpu < MAX_CPUS {
                unsafe {
                    let pc = &*self.cpus[cpu].0.get();
                    s.cpu_objs += core::ptr::read_volatile(&(*pc.loaded[c]).n);
                    s.cpu_objs += core::ptr::read_volatile(&(*pc.prev[c]).n);
                }
                cpu += 1;
            }
        }
        s
    }

    // ── debug: poison and red zone ──────────────────────────────────────────

    #[inline(never)]
    fn debug_on_alloc(c: usize, p: *mut u8, req: usize) {
        let size = Self::G.size[c];
        const W: usize = core::mem::size_of::<usize>();
        let pw = usize::from_ne_bytes([POISON; W]);
        unsafe {
            // A free object is all POISON except the first word, which the
            // slab free list may have used. Objects are word aligned and a
            // whole number of words.
            let mut i = W;
            while i < size {
                if *(p.add(i) as *const usize) != pw {
                    panic!("kheap slab: free object {:p} (class {}) written after free near +{}", p, size, i);
                }
                i += W;
            }
            core::ptr::write_bytes(p.add(req), REDZONE, size - req);
        }
    }

    #[inline(never)]
    fn debug_on_free(c: usize, p: *mut u8, req: usize) {
        let size = Self::G.size[c];
        unsafe {
            let mut i = req;
            while i < size {
                if *p.add(i) != REDZONE {
                    panic!("kheap slab: object {:p} (class {}, {} B asked) overrun at +{}", p, size, req, i);
                }
                i += 1;
            }
            core::ptr::write_bytes(p, POISON, size);
        }
    }
}
