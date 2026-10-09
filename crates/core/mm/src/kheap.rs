// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Kernel heap allocator: `linked_list_allocator` first-fit behind a
/// `SpinLock`, with (Kconfig `KHEAP_SLAB`) a per-CPU size-class cache in
/// front of it for small requests (`slab.rs`).
///
/// Implements `GlobalAlloc` so Rust's `alloc` crate works (Vec, Box, String, etc).
/// Uses our own SpinLock instead of `linked_list_allocator`'s `LockedHeap`
/// to keep the lock implementation consistent across the kernel.
///
/// With `KHEAP_SLAB` off the allocator is exactly the first-fit heap, as it
/// was before wave 15 (kept for comparison). With it on:
///   * a request the size classes cover (`KHEAP_SLAB_CLASS_LIST`, alignment
///     permitting) goes to the cache; anything else to the heap;
///   * a refusal (cache or heap) first has the cache give back what it holds
///     (`Slab::reclaim`), then is retried once, and a second refusal is
///     returned as null: OOM is a refusal, never a panic, as before;
///   * a context that interrupted this same hart inside a heap call (which
///     spins forever with the slab layer off) has its allocation refused and
///     its free deferred to the next heap call. Not inside the few
///     instructions between taking the lock and recording the owner, or
///     between clearing the owner and releasing the lock: there it still
///     spins, as before. Closing those needs a try-lock scheme; clearing the
///     owner after the release instead would let the deferred reschedule
///     the release can run see a stale owner and refuse a task's request.
///
/// Ported from kernel/mm/kheap.c (upgraded from bump to real free-list).

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use linked_list_allocator::Heap;
use azos_arch::ARCH;
use azos_arch_api::Cpu;
use azos_sync::SpinLock;
use crate::slab::{Backing, Params, Slab, NO_CLASS};

struct LockedHeap(SpinLock<Heap>);

/// The hart holding the heap lock, plus one (0: none). Kept on the slab
/// build's heap path only: it is what lets an interrupt-context call refuse
/// instead of spinning on a lock its own hart holds.
static OWNER: AtomicUsize = AtomicUsize::new(0);

/// Frees that found this hart already inside the heap (see `heap_free`): a
/// stack of the freed blocks themselves, drained under the lock. Two words,
/// which is `linked_list_allocator`'s smallest block (`HoleList::min_size`).
#[repr(C)]
struct Deferred {
    next: *mut Deferred,
    /// `size << 8 | log2(align)`.
    packed: usize,
}
static DEFERRED: AtomicPtr<Deferred> = AtomicPtr::new(null_mut());

#[inline(always)]
fn me() -> usize { ARCH.hart_id().wrapping_add(1) }

/// Whether the token from `disable_all` says interrupts were enabled. The
/// encoding is the ISA's: `sstatus.SIE` set on riscv64, `DAIF.I` clear on
/// aarch64 (the bits `restore` writes back).
#[inline(always)]
fn token_on(t: u64) -> bool {
    #[cfg(target_arch = "riscv64")]
    { t & azos_arch::csr::SSTATUS_SIE as u64 != 0 }
    #[cfg(target_arch = "aarch64")]
    { t & azos_arch::sysregs::DAIF_I == 0 }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
    { let _ = t; true }
}

/// Run `f` on the heap under its lock, owner recorded, deferred frees
/// drained first. `None` when this hart already holds the lock (an
/// interrupt landed inside a heap call): the caller refuses or defers.
#[inline(always)]
fn with_heap<R>(f: impl FnOnce(&mut Heap) -> R) -> Option<R> {
    let me = me();
    if OWNER.load(Ordering::Relaxed) == me { return None; }
    let mut g = HEAP.0.lock();
    OWNER.store(me, Ordering::Relaxed);
    if !DEFERRED.load(Ordering::Relaxed).is_null() { drain_deferred(&mut g); }
    let r = f(&mut g);
    OWNER.store(0, Ordering::Relaxed);
    Some(r)
}

/// Free the blocks `heap_free` deferred. Heap lock held. Out of line: it
/// almost never runs, and inline its loop costs every heap call a frame.
#[inline(never)]
fn drain_deferred(g: &mut Heap) {
    let mut d = DEFERRED.swap(null_mut(), Ordering::Acquire);
    while !d.is_null() {
        unsafe {
            let next = (*d).next;
            let p = (*d).packed;
            let l = Layout::from_size_align_unchecked(p >> 8, 1usize << (p & 0xff));
            g.deallocate(core::ptr::NonNull::new_unchecked(d as *mut u8), l);
            d = next;
        }
    }
}

#[inline(always)]
fn heap_alloc(layout: Layout) -> *mut u8 {
    with_heap(|h| h.allocate_first_fit(layout).ok().map_or(null_mut(), |nn| nn.as_ptr()))
        .unwrap_or(null_mut())
}

#[inline(never)]
fn heap_free(ptr: *mut u8, layout: Layout) {
    let done = with_heap(|h| unsafe { h.deallocate(core::ptr::NonNull::new_unchecked(ptr), layout) });
    if done.is_none() {
        let d = ptr as *mut Deferred;
        unsafe {
            (*d).packed = layout.size() << 8 | layout.align().trailing_zeros() as usize;
            let mut head = DEFERRED.load(Ordering::Relaxed);
            loop {
                (*d).next = head;
                match DEFERRED.compare_exchange_weak(head, d, Ordering::Release, Ordering::Relaxed) {
                    Ok(_) => break,
                    Err(h) => head = h,
                }
            }
        }
    }
}

/// Mask interrupts for a magazine operation; the token restores them.
///
/// One instruction on riscv64 (`csrrci`), two on aarch64 (`mrs` + `msr
/// DAIFSet`, IRQ and FIQ as `disable_all`), against `disable_all`'s
/// read-modify-write. Like the arch primitives, the asm has no `nomem`, so
/// the compiler keeps every magazine access inside the window. With
/// `lat-trace` the arch calls are used instead, so the masked-window tracer
/// sees these windows.
#[inline(always)]
fn irq_off() -> usize {
    #[cfg(all(target_arch = "riscv64", not(feature = "lat-trace")))]
    {
        let t: usize;
        unsafe { core::arch::asm!("csrrci {0}, sstatus, 2", out(reg) t, options(nostack)) };
        t
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "lat-trace")))]
    {
        let t: usize;
        unsafe { core::arch::asm!("mrs {0}, DAIF", "msr DAIFSet, #3", out(reg) t, options(nostack, preserves_flags)) };
        t
    }
    #[cfg(any(feature = "lat-trace", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    {
        use azos_arch_api::Interrupts;
        ARCH.disable_all().0 as usize
    }
}

/// Undo [`irq_off`]. Interrupts are masked here, so on riscv64 restoring
/// `SIE` is setting it back when the token had it (`csrs`), and on aarch64
/// the token is the whole of `DAIF`.
#[inline(always)]
fn irq_restore(t: usize) {
    #[cfg(all(target_arch = "riscv64", not(feature = "lat-trace")))]
    unsafe { core::arch::asm!("csrs sstatus, {0}", in(reg) t & azos_arch::csr::SSTATUS_SIE, options(nostack)) };
    #[cfg(all(target_arch = "aarch64", not(feature = "lat-trace")))]
    unsafe { core::arch::asm!("msr DAIF, {0}", in(reg) t, options(nostack, preserves_flags)) };
    #[cfg(any(feature = "lat-trace", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    {
        use azos_arch_api::Interrupts;
        ARCH.restore(azos_arch_api::InterruptState(t as u64));
    }
}

/// The kernel's slab geometry, all from Kconfig.
struct KParams;
impl Params for KParams {
    const CLASSES: &'static [usize] = azos_limits::KHEAP_SLAB_CLASS_LIST;
    const MAG_DEPTH: usize = azos_limits::KHEAP_SLAB_MAG_DEPTH;
    const CPU_CACHE_BYTES: usize = azos_limits::KHEAP_SLAB_CPU_CACHE_KB * 1024;
    const DEPOT_MAGS: usize = azos_limits::KHEAP_SLAB_DEPOT_MAGS;
    const SLAB_BYTES: usize = azos_limits::KHEAP_SLAB_BYTES;
    const MIN_OBJS: usize = azos_limits::KHEAP_SLAB_MIN_OBJS;
    const KEEP_EMPTY: usize = azos_limits::KHEAP_SLAB_KEEP_EMPTY;
    const DEBUG: bool = azos_limits::KHEAP_SLAB_DEBUG;
}

/// Slabs and magazines come from the first-fit heap; the CPU is the hart.
struct KBacking;
unsafe impl Backing for KBacking {
    #[inline]
    fn alloc(&self, size: usize, align: usize) -> *mut u8 {
        heap_alloc(unsafe { Layout::from_size_align_unchecked(size, align) })
    }
    #[inline]
    fn free(&self, p: *mut u8, size: usize, align: usize) {
        heap_free(p, unsafe { Layout::from_size_align_unchecked(size, align) })
    }
    #[inline(always)]
    fn irq_off(&self) -> usize { irq_off() }
    #[inline(always)]
    fn irq_restore(&self, t: usize) { irq_restore(t) }
    #[inline(always)]
    fn was_on(&self, t: usize) -> bool { token_on(t as u64) }
    #[inline(always)]
    fn cpu(&self) -> usize { ARCH.hart_id() }
}

type KSlab = Slab<KParams, KBacking>;
static SLAB: KSlab = Slab::new(KBacking);

// The cache's per-CPU table covers every hart the kernel runs; a hart id
// beyond it would still be served, through the locked path.
const _: () = assert!(crate::slab::MAX_CPUS >= azos_sync::isr_depth::MAX_HARTS);

/// The allocator itself, census excluded.
///
/// Shaped for the common cases: a small request whose class this CPU's
/// magazine can serve is answered inline, with no call and so no stack
/// frame (`alloc_fast`); a large one is one tail call to the heap
/// (`alloc_large`); everything else one tail call to `alloc_small`.
#[inline(always)]
unsafe fn inner_alloc(layout: Layout) -> *mut u8 {
    if !azos_limits::KHEAP_SLAB {
        return HEAP.0
            .lock()
            .allocate_first_fit(layout)
            .ok()
            .map_or(null_mut(), |nn| nn.as_ptr());
    }
    if layout.size() > KSlab::G.max { return alloc_large(layout); }
    if !KParams::DEBUG {
        let c = KSlab::class_fast(layout.size(), layout.align());
        if c != NO_CLASS {
            let p = unsafe { SLAB.alloc_fast(c) };
            if !p.is_null() { return p; }
        }
    }
    alloc_small(layout)
}

/// A request above the largest class: the heap.
#[inline(never)]
fn alloc_large(layout: Layout) -> *mut u8 {
    let p = heap_alloc(layout);
    if !p.is_null() { return p; }
    refused_large(layout)
}

/// The heap refused: the cache gives back what it holds, then one retry.
#[inline(never)]
fn refused_large(layout: Layout) -> *mut u8 {
    if SLAB.reclaim() == 0 { return null_mut(); }
    heap_alloc(layout)
}

/// A small request the inline path did not serve (its magazine was empty,
/// its alignment needs the checked lookup, or `KHEAP_SLAB_DEBUG`).
#[inline(never)]
fn alloc_small(layout: Layout) -> *mut u8 {
    let c = KSlab::class_of(layout.size(), layout.align());
    if c == NO_CLASS { return alloc_large(layout); }
    let p = unsafe { SLAB.alloc(c, layout.size()) };
    if !p.is_null() { return p; }
    // A refusal: the cache gives back what it holds, then one retry.
    if SLAB.reclaim() == 0 { return null_mut(); }
    unsafe { SLAB.alloc(c, layout.size()) }
}

#[inline(always)]
unsafe fn inner_dealloc(ptr: *mut u8, layout: Layout) {
    if !azos_limits::KHEAP_SLAB {
        unsafe {
            HEAP.0.lock().deallocate(core::ptr::NonNull::new_unchecked(ptr), layout);
        }
        return;
    }
    if layout.size() > KSlab::G.max { return heap_free(ptr, layout); }
    if !KParams::DEBUG {
        let c = KSlab::class_fast(layout.size(), layout.align());
        if c != NO_CLASS && unsafe { SLAB.free_fast(c, ptr) } { return; }
    }
    dealloc_small(ptr, layout)
}

/// A small free the inline path did not take.
#[inline(never)]
fn dealloc_small(ptr: *mut u8, layout: Layout) {
    let c = KSlab::class_of(layout.size(), layout.align());
    if c != NO_CLASS {
        unsafe { SLAB.free(c, ptr, layout.size()) };
    } else {
        heap_free(ptr, layout);
    }
}

unsafe impl GlobalAlloc for LockedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Kconfig CHAOS, point `heap-alloc` (test scope only): null, as an
        // exhausted heap answers. Off: a constant `false`.
        if azos_chaos::fire(azos_chaos::Point::HeapAlloc) {
            return null_mut();
        }
        #[cfg(feature = "kheap-census")]
        let t0 = crate::kheap_census::now();
        let p = unsafe { inner_alloc(layout) };
        #[cfg(feature = "kheap-census")]
        {
            let t = crate::kheap_census::now().wrapping_sub(t0);
            crate::kheap_census::on_alloc(layout.size(), layout.align(), t, !p.is_null());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        #[cfg(feature = "kheap-census")]
        let t0 = crate::kheap_census::now();
        unsafe { inner_dealloc(ptr, layout) };
        #[cfg(feature = "kheap-census")]
        crate::kheap_census::on_free(layout.size(), crate::kheap_census::now().wrapping_sub(t0));
    }
}

#[global_allocator]
static HEAP: LockedHeap = LockedHeap(SpinLock::new(Heap::empty()));

/// Initialize the kernel heap.
///
/// # Safety
/// `start` must point to a valid, unused memory region of at least `size` bytes.
/// Must be called exactly once before any heap allocation.
pub unsafe fn init(start: usize, size: usize) {
    unsafe {
        HEAP.0.lock().init(start as *mut u8, size);
    }
}

/// Bytes in use: what the heap has handed out, less what the size-class
/// cache holds free (objects in its slabs, depot and magazines; other
/// CPUs' magazines read as a snapshot). Slab headers and tails and the
/// cache's magazines count as used.
pub fn used() -> usize {
    let h = HEAP.0.lock().used();
    if azos_limits::KHEAP_SLAB { h.saturating_sub(SLAB.cached_bytes()) } else { h }
}

/// Get the total heap size in bytes.
pub fn size() -> usize {
    HEAP.0.lock().size()
}

/// Free bytes: the heap's own plus what the size-class cache holds free.
pub fn free() -> usize {
    size().saturating_sub(used())
}

/// Bytes the size-class cache holds free (0 with `KHEAP_SLAB` off).
pub fn slab_cached() -> usize {
    if azos_limits::KHEAP_SLAB { SLAB.cached_bytes() } else { 0 }
}

/// Boot self-test of the size-class cache, in the kernel's own environment
/// (its interrupt masking, its hart id, the real heap behind it): every
/// class gets enough objects to go through its magazines, the depot and a
/// new slab; each object is checked for its alignment and tagged at both
/// ends. Half are freed and `reclaim` pushes what the cache holds back into
/// the slab free lists, then as many are allocated again, so the second
/// round comes from those lists. Every live tag is then re-read: an object
/// handed out twice, or overlapping another, has had a tag overwritten. All
/// are freed and a last `reclaim` must leave the cache holding nothing.
///
/// Run by `kernel_main` (both ISAs) when `KHEAP_SLAB_DEBUG` is on, on the
/// boot hart before the others start. Returns the objects checked and the
/// bytes the final reclaim gave back, or what failed.
pub fn slab_selftest() -> Result<(usize, usize), &'static str> {
    if !azos_limits::KHEAP_SLAB { return Ok((0, 0)); }
    const N: usize = 192;
    let g = &KSlab::G;
    let mut ptrs = [null_mut::<u8>(); N];
    let mut checked = 0;
    let tag = |c: usize, i: usize| ((c as u64) << 32) | i as u64 | 0xa5a5_0000_0000_0000;
    let mut c = 0;
    while c < g.n {
        let size = g.size[c];
        let lay = Layout::from_size_align(size, 8).map_err(|_| "layout")?;
        let n = N.min(3 * g.depth[c] + g.objs[c] + 1);
        let put = |p: *mut u8, i: usize| unsafe {
            *(p as *mut u64) = tag(c, i);
            *(p.add(size - 8) as *mut u64) = !tag(c, i);
        };
        for (i, p) in ptrs.iter_mut().enumerate().take(n) {
            *p = unsafe { inner_alloc(lay) };
            if p.is_null() { return Err("an allocation was refused"); }
            if (*p as usize) % g.align[c] != 0 { return Err("an object is not aligned to its class"); }
            put(*p, i);
        }
        for (i, p) in ptrs.iter_mut().enumerate().take(n) {
            if i % 2 == 1 { unsafe { inner_dealloc(*p, lay) }; *p = null_mut(); }
        }
        SLAB.reclaim();
        for (i, p) in ptrs.iter_mut().enumerate().take(n) {
            if p.is_null() {
                *p = unsafe { inner_alloc(lay) };
                if p.is_null() { return Err("an allocation was refused"); }
                put(*p, i);
            }
        }
        for (i, p) in ptrs.iter().enumerate().take(n) {
            let ok = unsafe { *(*p as *const u64) == tag(c, i) && *(p.add(size - 8) as *const u64) == !tag(c, i) };
            if !ok { return Err("an object was handed out twice or overlaps another"); }
            checked += 1;
        }
        for p in ptrs.iter().take(n) { unsafe { inner_dealloc(*p, lay) }; }
        c += 1;
    }
    // With interrupts masked (kernel_main runs so) `reclaim` keeps the
    // empty slabs rather than walk the heap; the magazines and depot must be
    // empty all the same.
    let back = SLAB.reclaim();
    let mut c = 0;
    while c < g.n {
        let st = SLAB.stats(c);
        if st.cpu_objs != 0 || st.depot_objs != 0 { return Err("reclaim left objects in a magazine"); }
        c += 1;
    }
    Ok((checked, back))
}

/// `kheap-census` micro-benchmark: the allocator's own alloc, no census.
#[cfg(feature = "kheap-census")]
pub fn bench_raw_alloc(layout: Layout) -> *mut u8 {
    unsafe { inner_alloc(layout) }
}

/// `kheap-census` micro-benchmark: the allocator's own free, no census.
#[cfg(feature = "kheap-census")]
pub fn bench_raw_free(ptr: *mut u8, layout: Layout) {
    unsafe { inner_dealloc(ptr, layout) }
}
