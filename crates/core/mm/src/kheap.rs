// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Kernel heap allocator: a per-CPU size-class cache (`slab.rs`) whose slabs
/// are page blocks of the page allocator, and exact page runs for requests
/// above the largest class. Pages are taken on demand and given back when
/// freed; Kconfig `KERNEL_HEAP_SIZE` is a ceiling on the pages held, not a
/// reservation.
///
/// Implements `GlobalAlloc` so Rust's `alloc` crate works (Vec, Box, String, etc).
/// A refusal (cache, ceiling or page allocator) first has the cache give back
/// what it holds (`Slab::reclaim`), then is retried once, and a second refusal
/// is returned as null: OOM is a refusal, never a panic.
///
/// An interrupt handler may allocate: the slab's own locks are taken with
/// interrupts masked, and so are the page allocator's.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};
use azos_arch::ARCH;
use azos_arch_api::Cpu;
use azos_arch::PAGE_SIZE;
use crate::addr::{phys_to_virt, virt_to_phys, PhysAddr};
use crate::buddy::order_for;
use crate::kheap_guard as guard;
use crate::pmm::{self, Pfn};
use crate::slab::{Backing, Params, Slab, NO_CLASS};

/// Whether the token from `disable_all` says interrupts were enabled. The
/// encoding is the ISA's: `sstatus.SIE` set on riscv64, `DAIF.I` clear on
/// aarch64, `RFLAGS.IF` set on x86_64 (the bits `restore` writes back).
#[inline(always)]
fn token_on(t: u64) -> bool {
    #[cfg(target_arch = "riscv64")]
    { t & azos_arch::cpu::SSTATUS_SIE as u64 != 0 }
    #[cfg(target_arch = "aarch64")]
    { t & azos_arch::sysregs::DAIF_I == 0 }
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    { t & azos_arch::cpu::RFLAGS_IF != 0 || cfg!(feature = "kheap-token-canary") }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", all(target_arch = "x86_64", target_os = "none"))))]
    { let _ = t; true }
}

/// [`token_on`] of a token [`irq_off`] returned: did that call find interrupts
/// enabled. The slab asks it inside its masked window, and an interrupt-context
/// allocation (the answer is no) never restores them around a backing-heap call.
pub fn irq_was_on(t: usize) -> bool { token_on(t as u64) }

/// Mask interrupts for a magazine operation; the token restores them. Also
/// the scheduler's window for reading "which task am I" (`on_this_hart`).
///
/// One instruction on riscv64 (`csrrci`), two on aarch64 (`mrs` + `msr
/// DAIFSet`, IRQ and FIQ as `disable_all`), against `disable_all`'s
/// read-modify-write. Like the arch primitives, the asm has no `nomem`, so
/// the compiler keeps every magazine access inside the window. With
/// `lat-trace` the arch calls are used instead, so the masked-window tracer
/// sees these windows.
#[inline(always)]
pub fn irq_off() -> usize {
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
pub fn irq_restore(t: usize) {
    #[cfg(all(target_arch = "riscv64", not(feature = "lat-trace")))]
    unsafe { core::arch::asm!("csrs sstatus, {0}", in(reg) t & azos_arch::cpu::SSTATUS_SIE, options(nostack)) };
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
    const HARDENED: bool = azos_limits::SLAB_HARDENED;
    const RANDOM: bool = azos_limits::ALLOC_RANDOM;
}

/// Slabs and magazines are page blocks of the page allocator, through the
/// linear map; the CPU is the hart.
struct KBacking;
unsafe impl Backing for KBacking {
    #[inline]
    fn alloc(&self, size: usize, align: usize) -> *mut u8 {
        // A slab is a power of two aligned to its size: the buddy block that
        // holds it is both (a whole page when the slab is smaller).
        debug_assert!(size.is_power_of_two() && align <= size.max(PAGE_SIZE));
        let order = order_for(size.div_ceil(PAGE_SIZE));
        if !take(1 << order) { return null_mut(); }
        match pmm::alloc(order, pmm::ANY_COLOUR, pmm::ANY_NODE) {
            Some(pfn) => phys_to_virt(pfn.phys()) as *mut u8,
            None => { give(1 << order); null_mut() }
        }
    }
    #[inline]
    fn free(&self, p: *mut u8, size: usize, _align: usize) {
        let order = order_for(size.div_ceil(PAGE_SIZE));
        let _ = pmm::free(Pfn::from_phys(virt_to_phys(p as usize)), order);
        give(1 << order);
    }
    #[inline(always)]
    fn irq_off(&self) -> usize { irq_off() }
    #[inline(always)]
    fn irq_restore(&self, t: usize) { irq_restore(t) }
    #[inline(always)]
    fn was_on(&self, t: usize) -> bool { irq_was_on(t) }
    #[inline(always)]
    // percpu-hint: the slab calls it inside its irq_off window
    fn cpu(&self) -> usize { ARCH.hart_id() }

    /// The entropy pool's next two words, one for the slab page and one
    /// stirred into the page allocator's seed (`buddy::stir`), when the pool
    /// is seeded and interrupts are on. The pool lock is a plain spin that an
    /// interrupt handler of this hart could find held by the task it
    /// interrupted, so a caller with interrupts masked never takes it.
    /// Otherwise (early boot, or masked): the timer tick and the hart, which
    /// is not secret but differs per page and per boot, and is not stirred
    /// into the page allocator.
    fn entropy(&self, irqs_on: bool) -> u64 {
        if irqs_on {
            let mut b = [0u8; 16];
            let seeded = {
                let _cs = azos_sync::critical_section();
                azos_crypto::entropy::fill(&mut b)
            };
            if seeded {
                let w = u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                let v = u64::from_ne_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
                azos_crypto::ct::secure_zero(&mut b);
                if azos_limits::ALLOC_RANDOM { crate::buddy::stir(v); }
                if w != 0 { return w; }
            }
        }
        let t = ARCH.now_ticks() ^ (ARCH.hart_id() as u64) << 56;
        t.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1
    }
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

/// A request above the largest class: an exact run of pages, the tail past
/// the request's last page given straight back. Above `PMM_MAX_ORDER` (the
/// largest block the page allocator forms) it is refused.
#[inline(never)]
fn alloc_large(layout: Layout) -> *mut u8 {
    let p = run_alloc(layout);
    if !p.is_null() { return p; }
    refused_large(layout)
}

/// The page allocator or the ceiling refused: the cache gives back what it
/// holds, then one retry.
#[inline(never)]
fn refused_large(layout: Layout) -> *mut u8 {
    if SLAB.reclaim() == 0 { return null_mut(); }
    run_alloc(layout)
}

fn run_pages(layout: Layout) -> usize { layout.size().div_ceil(PAGE_SIZE) }

fn run_alloc(layout: Layout) -> *mut u8 {
    let n = run_pages(layout);
    if !take(n) { return null_mut(); }
    // SAFETY: a heap block's bytes are unspecified until its owner writes them.
    match unsafe { pmm::alloc_contiguous_aligned_uninit(n, layout.align().max(PAGE_SIZE)) } {
        Ok(a) => phys_to_virt(a.as_usize()) as *mut u8,
        Err(_) => { give(n); null_mut() }
    }
}

fn run_free(ptr: *mut u8, layout: Layout) {
    let n = run_pages(layout);
    let _ = pmm::free_run(PhysAddr::new(virt_to_phys(ptr as usize)), n);
    give(n);
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
    if layout.size() > KSlab::G.max { return run_free(ptr, layout); }
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
        run_free(ptr, layout);
    }
}

struct KernelHeap;

unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Kconfig CHAOS, point `heap-alloc` (test scope only): null, as an
        // exhausted heap answers. Off: a constant `false`.
        if azos_chaos::fire(azos_chaos::Point::HeapAlloc) {
            return null_mut();
        }
        #[cfg(feature = "kheap-census")]
        let t0 = crate::kheap_census::now();
        let p = if guard::ENABLED { unsafe { guard::alloc(layout, RAW) } } else { unsafe { inner_alloc(layout) } };
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
        if guard::ENABLED { unsafe { guard::dealloc(ptr, layout, RAW) } } else { unsafe { inner_dealloc(ptr, layout) } };
        #[cfg(feature = "kheap-census")]
        crate::kheap_census::on_free(layout.size(), crate::kheap_census::now().wrapping_sub(t0));
    }
}

/// The allocator under the heap guard (Kconfig `KHEAP_GUARD_*`).
const RAW: guard::Raw = guard::Raw { alloc: inner_alloc, free: inner_dealloc };

#[global_allocator]
static HEAP: KernelHeap = KernelHeap;

/// Pages the heap holds (slabs, magazines and large runs) and the most it may
/// hold (Kconfig `KERNEL_HEAP_SIZE`; 0 until `init`).
static HELD: AtomicUsize = AtomicUsize::new(0);
static CEILING: AtomicUsize = AtomicUsize::new(0);

/// Count `n` more pages against the ceiling; `false` (nothing counted) when
/// they would pass it.
pub(crate) fn take(n: usize) -> bool {
    let ceil = CEILING.load(Ordering::Relaxed);
    let mut h = HELD.load(Ordering::Relaxed);
    loop {
        // Canary `kheap-ceiling-canary`: the ceiling is not checked, so the
        // heap can hold more than KERNEL_HEAP_SIZE.
        if h + n > ceil && !cfg!(feature = "kheap-ceiling-canary") { return false; }
        match HELD.compare_exchange_weak(h, h + n, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(x) => h = x,
        }
    }
}

pub(crate) fn give(n: usize) { HELD.fetch_sub(n, Ordering::Relaxed); }

/// Set the heap's ceiling to `ceiling` bytes. Pages are taken from the page
/// allocator on demand from here on, so this must run after `pmm::init` and
/// before the first heap allocation.
pub fn init(ceiling: usize) {
    CEILING.store(ceiling / PAGE_SIZE, Ordering::Relaxed);
}

/// Bytes the heap holds from the page allocator now.
pub fn held() -> usize { HELD.load(Ordering::Relaxed) * PAGE_SIZE }

/// Bytes in use: what the heap holds, less what the size-class cache holds
/// free (objects in its slabs, depot and magazines; other CPUs' magazines
/// read as a snapshot) and what the heap guard holds in quarantine. Slab
/// headers and tails, the cache's magazines and the unused tail of a large
/// request's last page count as used.
pub fn used() -> usize {
    let h = held().saturating_sub(SLAB.cached_bytes());
    if guard::ENABLED { h.saturating_sub(guard::bytes_held()) } else { h }
}

/// Release the heap guard's quarantine now, checking every block in it: how
/// many it held (0 with the guard off).
pub fn guard_drain() -> usize {
    if guard::ENABLED { unsafe { guard::drain(RAW) } } else { 0 }
}

/// The heap's ceiling in bytes (Kconfig `KERNEL_HEAP_SIZE`).
pub fn size() -> usize {
    CEILING.load(Ordering::Relaxed) * PAGE_SIZE
}

/// Bytes the heap may still take: the ceiling less what is in use.
pub fn free() -> usize {
    size().saturating_sub(used())
}

/// Bytes the size-class cache holds free.
pub fn slab_cached() -> usize { SLAB.cached_bytes() }

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
