// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Physical Memory Manager (PMM): a buddy allocator over per-frame
//! descriptors, with per-hart caches of single frames.
//!
//! * `frame.rs`: [`Pfn`], the 32-byte [`FrameDesc`] and the table that maps a
//!   frame number to it. One descriptor per frame of ALL the RAM `init` is
//!   given, however large; the array is placed in RAM just above the kernel
//!   image and reserves itself.
//! * `buddy.rs`: free blocks of `2^k` frames, `k = 0..=PMM_MAX_ORDER`,
//!   split on allocation and merged on free; and the per-hart cache logic.
//! * This file: the statics (the one lock, the descriptor table, the
//!   caches), the interrupt masking that makes a cache safe, and the kernel's
//!   page API on top.
//!
//! # The two layers of the API
//!
//! [`alloc`]`(order, colour_mask, node)` and [`free`]`(pfn, order)` are the
//! allocator: blocks of `2^order` frames, by frame number, contents
//! unspecified. `colour_mask` and `node` are accepted and ignored for now
//! (both derive from the frame number, `Pfn::colour`, and the topology's node
//! ranges; there is no field to consult). Everything else
//! ([`alloc_page`], [`alloc_contiguous`], [`free_page`], ...) is a caller's
//! convenience over them: physical addresses, zeroing, page-at-a-time frees.
//!
//! # The fast path
//!
//! Once [`enable_cpu_caches`] has run (late boot, after the heap), a
//! single-frame allocation or free touches only the calling hart's cache with
//! interrupts masked for a handful of instructions: no lock, no shared cache
//! line. A hart takes `PMM_PCP_BATCH` frames from the buddy lists when its
//! cache is empty and gives that many back when it holds `PMM_PCP_HIGH`; that
//! is the only time the lock is taken, and then with interrupts as the caller
//! had them: the walk over the lists happens unmasked into a chain of frames,
//! and the chain is spliced onto (or cut from) the cache masked, in a few
//! instructions (the kernel heap's magazines do the same around their depot
//! and slab calls). [`free_pages`] counts cached frames as free. A frame in
//! another hart's cache cannot be had by this one, so an exhausted allocator
//! can refuse with up to `NR_CPUS * PMM_PCP_HIGH` frames "free".
//!
//! Before [`enable_cpu_caches`] there is one hart and no cache: boot-time
//! callers see the exact lists, which is what `reserve_range`,
//! `range_is_free` and `next_free_addr` rely on.

use azos_arch::ArchPlatform as _;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use azos_arch::PAGE_SIZE;
use azos_sync::SpinLock;
use crate::addr::PhysAddr;
use crate::buddy::{order_for, Buddy, Pcp, MAX_ORDER};
use crate::zone::{tag_frame, Zone, ZoneList, ZONES};
pub use crate::frame::Pfn;
use crate::frame::{
    table_bytes, FrameDesc, FrameTable, F_ALLOCATED, F_CACHED, F_COMPRESSED, F_FREE, F_PINNED,
    F_RESERVED, F_SWAPPED,
};
use azos_common::error::{KResult, KernelError};

/// `alloc`'s `colour_mask` meaning "any colour".
pub const ANY_COLOUR: u32 = u32::MAX;
/// `alloc`'s `node` meaning "any node".
pub const ANY_NODE: u32 = u32::MAX;

const MAX_CPUS: usize = azos_limits::NR_CPUS;
const BATCH: usize = azos_limits::PMM_PCP_BATCH as usize;
const HIGH: usize = azos_limits::PMM_PCP_HIGH as usize;
const _: () = assert!(HIGH >= 2 * BATCH, "PMM_PCP_HIGH must be at least twice PMM_PCP_BATCH");

// The cache's per-hart table covers every hart the kernel runs.
#[cfg(target_os = "none")]
const _: () = assert!(MAX_CPUS >= azos_sync::isr_depth::MAX_HARTS);

/// The free lists. Everything that links or unlinks a block holds this.
static BUDDY: SpinLock<Buddy> = SpinLock::new(Buddy::new());

/// The descriptor table, published for lock-free reads: `frame_index` and the
/// COW share count (`cow_table.rs`) run once per user page on every fork.
/// Written only by `init`.
static DESCS: AtomicPtr<FrameDesc> = AtomicPtr::new(core::ptr::null_mut());
static FIRST_PFN: AtomicUsize = AtomicUsize::new(0);
static FRAME_COUNT: AtomicUsize = AtomicUsize::new(0);

/// The type zones' free lists (`zone.rs`), one lock each. Never held across a
/// call into `BUDDY` or the caches: a zoned allocation reserves its place in
/// the zone, drops the lock, takes the frame, and the failure path takes the
/// lock again to give the place back.
static ZONE_LISTS: [SpinLock<ZoneList>; ZONES] = [const { SpinLock::new(ZoneList::new()) }; ZONES];

/// Whether zoned allocation isolates: Kconfig `PMM_TYPE_ZONES`, or a `ktest`
/// kernel (whose zone test needs them whatever the posture), or the host,
/// which has no `.config` of its own and exists to exercise the mechanism.
#[inline(always)]
pub const fn zones_on() -> bool {
    azos_limits::PMM_TYPE_ZONES || cfg!(feature = "ktest") || cfg!(not(target_os = "none"))
}

/// Per-hart caches of single frames, and whether they are in use.
static PCP: [Pcp; MAX_CPUS] = [const { Pcp::new() }; MAX_CPUS];
static PCP_ON: AtomicBool = AtomicBool::new(false);

#[inline(always)]
fn table() -> FrameTable {
    // SAFETY: the three statics describe the array `init` built, which is
    // reserved RAM that lives for the whole boot; before `init` the table is
    // empty.
    unsafe {
        FrameTable::new(
            DESCS.load(Ordering::Relaxed),
            Pfn(FIRST_PFN.load(Ordering::Relaxed)),
            FRAME_COUNT.load(Ordering::Relaxed),
        )
    }
}

/// The descriptor of the frame at `phys`, or `None` when `phys` is unaligned
/// or outside the managed range.
#[inline(always)]
pub(crate) fn desc_of(phys: usize) -> Option<&'static FrameDesc> {
    // SAFETY: the array outlives every caller (see `table`).
    table().of_phys(phys).map(|d| unsafe { &*(d as *const FrameDesc) })
}

/// The index of the frame at `phys` among the managed frames, or `None` if
/// `phys` is unaligned or outside the managed range.
pub fn frame_index(phys: usize) -> Option<usize> {
    if phys & (PAGE_SIZE - 1) != 0 { return None; }
    table().index(Pfn::from_phys(phys))
}

/// The state bits of the frame at `phys` (`frame::F_*`), or `None` when it is
/// not managed.
pub fn frame_state(phys: usize) -> Option<u32> {
    desc_of(phys).map(|d| d.state())
}

/// Set or clear one of the allocated-frame modifiers (`F_PINNED`,
/// `F_COMPRESSED`, `F_SWAPPED`) on the frame at `phys`. `false` when the
/// frame is not managed or not allocated, or `bit` is not a modifier. A
/// pinned frame is refused by `free`.
pub fn set_frame_modifier(phys: usize, bit: u32, on: bool) -> bool {
    if bit == 0 || bit & !(F_PINNED | F_COMPRESSED | F_SWAPPED) != 0 { return false; }
    let Some(d) = desc_of(phys) else { return false };
    let mut cur = d.flags.load(Ordering::Relaxed);
    loop {
        if cur & F_ALLOCATED == 0 { return false; }
        let new = if on { cur | bit } else { cur & !bit };
        match d.flags.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(now) => cur = now,
        }
    }
}

/// The object that holds the frame at `phys` and the frame's page index in it
/// (`FrameDesc::owner`, the reverse map), or `None` for a frame no object holds
/// or one that is not managed.
pub fn frame_owner(phys: usize) -> Option<(u32, u32)> {
    desc_of(phys).and_then(|d| d.owner())
}

/// Record that object `owner` (non-zero) holds the frame at `phys` as its page
/// `idx`. `false` when the frame is not managed or not allocated.
pub fn set_frame_owner(phys: usize, owner: u32, idx: u32) -> bool {
    let Some(d) = desc_of(phys) else { return false };
    if owner == 0 || d.state() & F_ALLOCATED == 0 { return false; }
    d.set_owner(owner, idx);
    true
}

/// Forget the holder of the frame at `phys` if it is `owner`: call it before
/// the frame goes back to the allocator. `true` when the record was `owner`'s.
pub fn clear_frame_owner_if(phys: usize, owner: u32) -> bool {
    desc_of(phys).is_some_and(|d| d.clear_owner_if(owner))
}

/// Initialize the PMM.
///
/// `mem_start`: physical start of RAM (e.g., 0x8000_0000).
/// `mem_size`: total RAM size in bytes: ALL of it, whatever the board's
/// Kconfig says; the descriptor array is sized to it.
/// `kernel_end`: physical address after the last byte of the kernel image.
///
/// The descriptor array is placed at `kernel_end` (rounded up to a frame) and
/// reaches through RAM as far as `mem_size / PAGE_SIZE` descriptors need. Every
/// frame from `mem_start` to the end of the array is `F_RESERVED`; the rest is
/// handed to the buddy lists as maximal aligned blocks. A second call starts
/// over (host tests do this per test with a fresh arena).
///
/// Returns `false`, refusing to initialize the allocator, if `mem_start >
/// kernel_end`, if the range holds no frame, or if the array does not fit in
/// it. The first ordering is impossible on real hardware — the kernel image
/// is loaded INTO the RAM range `mem_start` describes — and can only come
/// from a corrupt or hostile `/memory` node (DTB audit, 2026-09-22): the
/// subtraction `kernel_end - mem_start` used to underflow and, under this
/// kernel's release profile (`overflow-checks = true`, `panic = "abort"`),
/// reset the board with no diagnostic. Refusing beats clamping to a range
/// this function cannot verify against the hardware. On refusal the state is
/// the all-zero one the statics start in: `total_pages() == 0`, so every
/// allocation answers `OutOfMemory`, and every caller already halts loudly on
/// `free_pages() == 0` right after this call (the "[MM] FAILED" markers in
/// `kernel/src/boot/early.rs`).
pub fn init(mem_start: usize, mem_size: usize, kernel_end: usize) -> bool {
    // Forget the previous state first, so a refusal leaves the all-zero one.
    PCP_ON.store(false, Ordering::Relaxed);
    for c in PCP.iter() { c.reset(); }
    for l in ZONE_LISTS.iter() { l.lock().reset(); }
    DESCS.store(core::ptr::null_mut(), Ordering::Relaxed);
    FIRST_PFN.store(0, Ordering::Relaxed);
    FRAME_COUNT.store(0, Ordering::Relaxed);
    BUDDY.lock().reset();

    if mem_start > kernel_end {
        return false;
    }
    let first = (mem_start + PAGE_SIZE - 1) / PAGE_SIZE;
    let end = mem_start.saturating_add(mem_size) / PAGE_SIZE;
    if end <= first {
        return false;
    }
    let count = end - first;
    let array_pa = (kernel_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let array_end = match array_pa.checked_add(table_bytes(count)) {
        Some(e) if e <= end * PAGE_SIZE => e,
        _ => return false,
    };

    // The array is written before anyone can see it, and outside the lock:
    // it is one store pass over a megabyte or more, which lockdep would
    // time as a hold.
    let descs = crate::addr::phys_to_virt(array_pa) as *mut FrameDesc;
    for i in 0..count {
        let flags = if (first + i) * PAGE_SIZE < array_end { F_RESERVED } else { F_FREE };
        // SAFETY: `i < count` descriptors fit between `array_pa` and
        // `array_end`, which the check above put inside the RAM range.
        unsafe { descs.add(i).write(FrameDesc::new(flags)) };
    }
    DESCS.store(descs, Ordering::Relaxed);
    FIRST_PFN.store(first, Ordering::Relaxed);
    FRAME_COUNT.store(count, Ordering::Relaxed);

    let t = table();
    BUDDY.lock().release_range(&t, Pfn::from_phys(array_end), Pfn(end));
    true
}

/// Start using the per-hart caches. Call once, on the boot hart, after the
/// kernel heap is reserved (so the boot-time `reserve_range`/`range_is_free`
/// calls saw exact lists) and before any other hart allocates. A no-op on the
/// host, where there is no hart to key a cache by.
pub fn enable_cpu_caches() {
    #[cfg(target_os = "none")]
    PCP_ON.store(true, Ordering::Release);
}

/// The calling hart's cache, with interrupts masked for the closure and the
/// closure free to take the lock: boot-time use only (`flush_local_cache`).
/// `None` when the caches are off or the hart has none.
#[cfg(target_os = "none")]
#[inline(always)]
fn with_cache<R>(f: impl FnOnce(&Pcp, &FrameTable) -> R) -> Option<R> {
    use azos_arch::ARCH;
    use azos_arch_api::Cpu;
    if !PCP_ON.load(Ordering::Relaxed) { return None; }
    let tok = crate::kheap::irq_off();
    let cpu = ARCH.hart_id();
    let r = if cpu < MAX_CPUS { Some(f(&PCP[cpu], &table())) } else { None };
    crate::kheap::irq_restore(tok);
    r
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
fn with_cache<R>(_f: impl FnOnce(&Pcp, &FrameTable) -> R) -> Option<R> { None }

/// One frame from the calling hart's cache, refilled from the lists when it
/// is empty. `None`: the caches are off, or the lists are dry.
#[cfg(target_os = "none")]
#[inline(always)]
fn cache_alloc() -> Option<Pfn> {
    use azos_arch::ARCH;
    use azos_arch_api::Cpu;
    use crate::kheap::{irq_off, irq_restore};
    if !PCP_ON.load(Ordering::Relaxed) { return None; }
    let t = table();
    let tok = irq_off();
    let cpu = ARCH.hart_id();
    if cpu >= MAX_CPUS {
        irq_restore(tok);
        return None;
    }
    if let Some(p) = PCP[cpu].pop(&t) {
        irq_restore(tok);
        return Some(p);
    }
    irq_restore(tok);
    // A miss: a batch off the lists under the lock, interrupts as they were.
    let chain = BUDDY.lock().take_chain(&t, BATCH);
    if chain.len() == 0 { return None; }
    // Masked again: the hart may have changed while unmasked, so the cache
    // is this hart's, looked up afresh (every hart id is below MAX_CPUS).
    let tok = irq_off();
    let cpu = ARCH.hart_id();
    if cpu >= MAX_CPUS {
        irq_restore(tok);
        BUDDY.lock().release_chain(&t, chain);
        return None;
    }
    PCP[cpu].splice(&t, chain);
    let p = PCP[cpu].pop(&t);
    irq_restore(tok);
    p
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
fn cache_alloc() -> Option<Pfn> { None }

/// Keep the frame at array index `idx` (claimed `F_CACHED` by `claim`) in the
/// calling hart's cache; when the cache is full, `PMM_PCP_BATCH` of its
/// frames go back to the lists with it. `false`: the caches are off.
#[cfg(target_os = "none")]
#[inline(always)]
fn cache_free(idx: usize) -> bool {
    use azos_arch::ARCH;
    use azos_arch_api::Cpu;
    use crate::kheap::{irq_off, irq_restore};
    if !PCP_ON.load(Ordering::Relaxed) { return false; }
    let t = table();
    let tok = irq_off();
    let cpu = ARCH.hart_id();
    if cpu >= MAX_CPUS {
        irq_restore(tok);
        return false;
    }
    let pcp = &PCP[cpu];
    if pcp.len() < HIGH {
        pcp.push(&t, idx);
        irq_restore(tok);
        return true;
    }
    let mut chain = pcp.detach(&t, BATCH);
    irq_restore(tok);
    chain.push_front(&t, idx);
    BUDDY.lock().release_chain(&t, chain);
    true
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
fn cache_free(_idx: usize) -> bool { false }

/// Allocate a block of `2^order` frames: the frame number of its first frame,
/// or `None` when no block that size can be made. The block is naturally
/// aligned (its first frame number is a multiple of `2^order`). Contents are
/// unspecified: [`alloc_page`] and friends zero.
///
/// `colour_mask` (bit `c` set: colour `c` acceptable) and `node` are the
/// placement hooks of the plan; both are ignored for now.
pub fn alloc(order: usize, _colour_mask: u32, _node: u32) -> Option<Pfn> {
    if order == 0 {
        if let Some(p) = cache_alloc() { return Some(p); }
    }
    BUDDY.lock().alloc(&table(), order)
}

/// Check that `[pfn, pfn + 2^order)` is managed and every frame is one `free`
/// may take, then claim them all (`F_CACHED`: free, in nobody's list yet).
fn claim(pfn: Pfn, order: usize) -> KResult<()> {
    let t = table();
    if order > MAX_ORDER { return Err(KernelError::InvalidArg); }
    if pfn.0 & ((1 << order) - 1) != 0 { return Err(KernelError::NotAligned); }
    let Some(i0) = t.index(pfn) else { return Err(KernelError::InvalidArg) };
    if i0 + (1 << order) > t.len() { return Err(KernelError::InvalidArg); }
    for i in i0..i0 + (1 << order) {
        let f = t.at(i).state();
        if f & (F_FREE | F_CACHED) != 0 { return Err(KernelError::DoubleFree); }
        if f & F_PINNED != 0 { return Err(KernelError::InvalidArg); }
        if f & (F_RESERVED | F_ALLOCATED) == 0 { return Err(KernelError::InvalidArg); }
    }
    for i in i0..i0 + (1 << order) {
        let d = t.at(i);
        let f = d.state();
        let ok = f & (F_FREE | F_CACHED | F_PINNED) == 0
            && d.flags.compare_exchange(f, F_CACHED, Ordering::AcqRel, Ordering::Relaxed).is_ok();
        if !ok {
            // Lost a race with another free of the same frame: put back what
            // this call already claimed.
            for j in i0..i {
                t.at(j).flags.store(F_ALLOCATED, Ordering::Relaxed);
            }
            return Err(KernelError::DoubleFree);
        }
    }
    Ok(())
}

/// Give back the block [`alloc`] returned: `free(pfn, order)` with the order
/// it was allocated with. A frame may also be given back alone, in any
/// number of calls, whatever order it was allocated with (the block is then
/// released a frame at a time and merges back as its frames arrive).
///
/// `NotAligned` when `pfn` is not a multiple of `2^order`; `InvalidArg` for a
/// frame that is not managed, pinned, or neither allocated nor reserved;
/// `DoubleFree` for one already free.
pub fn free(pfn: Pfn, order: usize) -> KResult<()> {
    claim(pfn, order)?;
    let t = table();
    let i0 = t.index(pfn).expect("claimed");
    if order == 0 && zone_free(&t, i0) {
        return Ok(());
    }
    if order == 0 && cache_free(i0) {
        return Ok(());
    }
    for i in i0..i0 + (1 << order) {
        t.at(i).flags.store(F_FREE, Ordering::Relaxed);
    }
    BUDDY.lock().release(&t, pfn, order);
    Ok(())
}

/// Keep a zoned frame (`claim`ed, array index `idx`) on its zone's list.
/// `false`: the frame has no zone, and the caller frees it as usual.
///
/// Canary `zone-share-canary`: the tag is dropped and the frame goes to the
/// cache and the buddy lists, so the next general allocation can be handed a
/// page-table frame (the cross-type reuse the zones exist to stop).
#[inline]
fn zone_free(t: &FrameTable, idx: usize) -> bool {
    if !zones_on() { return false; }
    let d = t.at(idx);
    let tag = d.zone.load(Ordering::Relaxed);
    if tag == 0 { return false; }
    if cfg!(feature = "zone-share-canary") {
        d.zone.store(0, Ordering::Relaxed);
        return false;
    }
    let Some(z) = Zone::of_tag(tag) else { return false };
    ZONE_LISTS[z.index()].lock().push(t, idx);
    true
}

/// Allocate a zeroed 4 KiB frame of the type zone `z`.
///
/// The zone's own free list first (a frame this zone owned before, tagged and
/// never given to another type), else a fresh frame tagged on the way out.
/// `free_page` needs no zone: the tag is on the frame, and a tagged frame goes
/// back to its zone. `OutOfMemory` when the zone is at Kconfig
/// `PMM_ZONE_MAX_PAGES` with no free frame (other zones and general
/// allocation are unaffected), or the buddy lists are dry. With
/// `PMM_TYPE_ZONES` off this is [`alloc_page`].
///
/// A zone's free frames are counted by [`free_pages`] (they are not leaked)
/// and by [`zone_pages`], which says how many of the free ones only the zone
/// can take.
pub fn alloc_page_zone(z: Zone) -> KResult<PhysAddr> {
    if !zones_on() { return alloc_page(); }
    let t = table();
    {
        let mut l = ZONE_LISTS[z.index()].lock();
        if let Some(p) = l.pop(&t) {
            drop(l);
            let a = PhysAddr::new(p.phys());
            zero_new_page(a);
            return Ok(a);
        }
        if !l.grow(azos_limits::PMM_ZONE_MAX_PAGES as usize) {
            return Err(KernelError::OutOfMemory);
        }
    }
    match alloc_page_raw() {
        Ok(a) => {
            tag_frame(&t, Pfn::from_phys(a.as_usize()), z);
            zero_new_page(a);
            Ok(a)
        }
        Err(e) => {
            ZONE_LISTS[z.index()].lock().ungrow();
            Err(e)
        }
    }
}

/// `(free, total)` frames of zone `z`: those on its list and those it owns
/// (free and handed out).
pub fn zone_pages(z: Zone) -> (usize, usize) {
    let l = ZONE_LISTS[z.index()].lock();
    (l.pooled(), l.total())
}

/// The zone the frame at `phys` belongs to; `None` for a frame that is
/// unzoned or not managed.
pub fn frame_zone(phys: usize) -> Option<Zone> {
    desc_of(phys).and_then(|d| Zone::of_tag(d.zone.load(Ordering::Relaxed)))
}

/// Give this hart's cached frames back to the lists. Boot time only (it
/// takes the lock with interrupts masked).
fn flush_local_cache() {
    let _ = with_cache(|pcp, t| {
        let all = pcp.detach(t, pcp.len());
        BUDDY.lock().release_chain(t, all);
    });
}

/// Allocate a single 4 KiB physical page.
/// Returns the physical address of the page, or `OutOfMemory`.
pub fn alloc_page() -> KResult<PhysAddr> {
    let addr = alloc_page_raw()?;
    zero_new_page(addr);
    Ok(addr)
}

/// Allocate a single 4 KiB physical page WITHOUT zeroing it.
///
/// For a caller that is about to overwrite every byte anyway —
/// `mm::cow::handle_cow_fault`'s break, which `copy_nonoverlapping`s the
/// whole page immediately after allocating it (U09-11). `alloc_page`'s
/// zero is there for the callers that DON'T immediately overwrite the
/// whole page (a demand-paged anonymous page, which must not hand a task
/// a stale sibling's bytes); a COW break already has real data to put
/// there, so `alloc_page`'s ~1500-instruction `write_bytes` was pure waste
/// on that path — 8 KiB written to produce 4 KiB of live data. Marked
/// `unsafe`: the caller must overwrite the page before anything reads it,
/// same contract `MaybeUninit` documents for the same reason.
///
/// # Safety
/// The caller must fully initialise the returned page (e.g. via
/// `copy_nonoverlapping`) before any code — including a fault handler
/// re-entering with the same physical address after a `free_page` — can
/// read from it. Handing this page to userspace, or reading it back,
/// before that write happens leaks whatever physical RAM previously held.
pub unsafe fn alloc_page_uninit() -> KResult<PhysAddr> {
    alloc_page_raw()
}

/// Allocate `n` physically contiguous, zeroed 4 KiB pages; returns the
/// physical address of the first.
///
/// For a device that is told one base address and then reads or writes the
/// whole block (the legacy virtio-mmio queue: one PFN for descriptor table,
/// avail ring and used ring). Consecutive `alloc_page` calls do NOT give that.
///
/// A buddy block of the order that holds `n` pages is taken and the pages
/// past `n` go straight back, so the run is aligned to a power of two and
/// at most `2^PMM_MAX_ORDER` pages. The pages are zeroed after the lock is
/// dropped (see `zero_new_page`). Each page is released with `free_page`,
/// one call per page, and merges back as they arrive. `n == 0` is
/// `InvalidArg`; no such block is `OutOfMemory`, with nothing claimed.
pub fn alloc_contiguous(n: usize) -> KResult<PhysAddr> {
    alloc_run(n, 0)
}

/// [`alloc_contiguous`] whose run starts at a physical address that is a
/// multiple of `align` (a power of two, at least `PAGE_SIZE`). For the
/// boot-time 2 MiB-leaf regions (Kconfig `LOCKED_HUGE_LEAVES`): a level-1
/// leaf needs its physical base aligned to the leaf size, and a buddy block
/// of that order is aligned to it by construction (frame numbers are
/// absolute). `OutOfMemory` with nothing claimed when no such block exists.
pub fn alloc_contiguous_aligned(n: usize, align: usize) -> KResult<PhysAddr> {
    if n == 0 || !align.is_power_of_two() || align < PAGE_SIZE {
        return Err(KernelError::InvalidArg);
    }
    alloc_run(n, order_for(align / PAGE_SIZE))
}

/// [`alloc_contiguous_aligned`] WITHOUT zeroing: for a superpage reservation
/// (`crate::resv`), which hands the run's frames out one at a time and zeroes
/// each with [`zero_frame`] when it does, so the first fault of a 2 MiB block
/// does not pay for zeroing all of it. Each frame is `F_ALLOCATED` and is
/// returned with `free_page`, one call per frame, as after the zeroing form.
///
/// # Safety
/// No frame of the run may reach a reader (ring 3 above all) before it has
/// been zeroed or fully overwritten: its bytes are whatever RAM held.
pub unsafe fn alloc_contiguous_aligned_uninit(n: usize, align: usize) -> KResult<PhysAddr> {
    if n == 0 || !align.is_power_of_two() || align < PAGE_SIZE {
        return Err(KernelError::InvalidArg);
    }
    claim_run(n, order_for(align / PAGE_SIZE))
}

fn claim_run(n: usize, min_order: usize) -> KResult<PhysAddr> {
    if n == 0 {
        return Err(KernelError::InvalidArg);
    }
    let pfn = BUDDY.lock().alloc_run(&table(), n, min_order).ok_or(KernelError::OutOfMemory)?;
    Ok(PhysAddr::new(pfn.phys()))
}

fn alloc_run(n: usize, min_order: usize) -> KResult<PhysAddr> {
    let addr = claim_run(n, min_order)?;
    for i in 0..n {
        zero_new_page(PhysAddr::new(addr.as_usize() + i * PAGE_SIZE));
    }
    Ok(addr)
}

/// The allocation half of `alloc_page`, shared with `alloc_page_uninit`.
/// Returns a freshly claimed (but NOT zeroed) page.
/// Kconfig CHAOS, point `frame-alloc`: an injected failure answers
/// `OutOfMemory` exactly as an empty allocator does, before any list is
/// touched. Off, the check is a constant `false`.
#[inline(always)]
fn alloc_page_raw() -> KResult<PhysAddr> {
    if azos_chaos::fire(azos_chaos::Point::FrameAlloc) {
        // Gate canary `canary=chaos-leak`: the failure path loses a frame,
        // which the `chaos_frame_alloc_no_leak` ktest must catch.
        if azos_chaos::leak_canary() {
            let _ = alloc(0, ANY_COLOUR, ANY_NODE);
        }
        return Err(KernelError::OutOfMemory);
    }
    alloc(0, ANY_COLOUR, ANY_NODE).map(|p| PhysAddr::new(p.phys())).ok_or(KernelError::OutOfMemory)
}

/// Zero a freshly allocated page, with no list or lock held (the frame is
/// `F_ALLOCATED` already, so no second caller on this hart or another can be
/// handed it while it is being zeroed). Zeroing used to run under the
/// allocator's lock until it was moved out: a 4 KiB `write_bytes` is
/// roughly 1500 RV64 instructions, and every other hart's fork/exec/fault
/// allocation was serialized behind it.
///
/// Dispatches to `cbo.zero` when a boot-time probe
/// confirmed it (see `azos_arch::cache`), and to plain `write_bytes`
/// otherwise.
fn zero_new_page(addr: PhysAddr) {
    unsafe {
        // `addr` is PHYSICAL. The CPU reaches it through the kernel's own
        // mapping, which is identity on riscv64 and the upper half on
        // aarch64 — zeroing through the raw physical number worked only
        // while a task's TTBR0 happened to still identity-map RAM, and
        // stopped the moment a user page table was installed.
        azos_arch::ARCH.zero_memory(crate::addr::phys_to_virt(addr.as_usize()), PAGE_SIZE);
    }
}

/// Zero a frame obtained from [`alloc_contiguous_aligned_uninit`] just before
/// it is handed out.
pub fn zero_frame(addr: PhysAddr) {
    zero_new_page(addr)
}

/// Free a single 4 KiB physical page.
pub fn free_page(addr: PhysAddr) -> KResult<()> {
    let phys = addr.as_usize();
    if phys < table().first().phys() {
        return Err(KernelError::InvalidArg);
    }
    if !addr.is_page_aligned() {
        return Err(KernelError::NotAligned);
    }
    free(Pfn::from_phys(phys), 0)
}

/// Get the total number of managed pages: every frame of the RAM `init` was
/// given, reserved ones included.
pub fn total_pages() -> usize {
    FRAME_COUNT.load(Ordering::Relaxed)
}

/// Get the number of currently free pages: the buddy lists, every hart's
/// cache and every type zone's free list. Like a frame in another hart's
/// cache, a zone's free frame is counted free yet out of reach of the other
/// types: a refusing general allocation can leave up to the zones' high-water
/// mark "free" (`zone_pages` tells how much).
pub fn free_pages() -> usize {
    let mut n = BUDDY.lock().free_frames();
    if PCP_ON.load(Ordering::Relaxed) {
        for c in PCP.iter() { n += c.len(); }
    }
    if zones_on() {
        for l in ZONE_LISTS.iter() { n += l.lock().pooled(); }
    }
    n
}

/// Get the number of currently used pages (reserved ones included).
pub fn used_pages() -> usize {
    total_pages() - free_pages()
}

/// Free blocks of exactly `order` in the lists (the caches are not blocks).
pub fn free_blocks(order: usize) -> usize {
    BUDDY.lock().blocks(order)
}

/// Reserve a range of physical memory in the PMM (take what is free in it
/// out of the lists and mark it `F_RESERVED`; frames in use stay as they are).
///
/// Used after `kheap::init()` to prevent PMM from handing out heap pages
/// to later callers (e.g. VirtIO DMA buffers). Boot-time: it first returns
/// this hart's cached frames to the lists, and frames in another hart's cache
/// are not touched.
pub fn reserve_range(start: usize, size: usize) {
    flush_local_cache();
    let lo = Pfn::from_phys(start);
    let hi = Pfn::from_phys(start.saturating_add(size).saturating_add(PAGE_SIZE - 1));
    BUDDY.lock().carve(&table(), lo, hi);
}

/// Is every page of `[start, start + size)` managed by the PMM and free?
///
/// For a caller that takes a whole range as one block, the kernel heap above
/// all: `reserve_range` skips pages already in use and stops at the end of
/// RAM without a word, so a range it "reserved" can still hold another
/// owner's page (the boot stack once sat inside the heap) or none at all.
/// A frame in a hart's cache is not free here.
pub fn range_is_free(start: usize, size: usize) -> bool {
    flush_local_cache();
    let t = table();
    let first = Pfn::from_phys(start);
    let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    let Some(off) = first.0.checked_sub(t.first().0) else { return false };
    if off.saturating_add(pages) > t.len() { return false; }
    (off..off + pages).all(|i| t.at(i).state() == F_FREE)
}

/// Return the physical address of the first free page.
///
/// Used to determine where the kernel heap should start after vmm::init()
/// has allocated all page table pages from the PMM.
pub fn next_free_addr() -> usize {
    flush_local_cache();
    let t = table();
    match (0..t.len()).find(|&i| t.at(i).state() == F_FREE) {
        Some(i) => t.pfn(i).phys(),
        // No free pages — return end of managed range
        None => t.end().phys(),
    }
}

/// The lowest page-aligned physical address from which `bytes` of
/// consecutive frames are all free, or `None`. The kernel heap is one block
/// ([`kheap`](crate::kheap)), and where the image is not at the start of RAM
/// (x86_64 under Limine) the first free frame may sit in a gap too small for
/// it; where the image is at the start the answer is [`next_free_addr`].
pub fn first_free_run(bytes: usize) -> Option<usize> {
    flush_local_cache();
    let t = table();
    let need = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    let (mut run, mut start) = (0usize, 0usize);
    for i in 0..t.len() {
        if t.at(i).state() == F_FREE {
            if run == 0 {
                start = i;
            }
            run += 1;
            if run >= need {
                return Some(t.pfn(start).phys());
            }
        } else {
            run = 0;
        }
    }
    None
}

// ── The boot-reserved DMA pool ─────────────────────────────────────────────

static DMA_POOL_BASE: AtomicUsize = AtomicUsize::new(0);
static DMA_POOL_PAGES: AtomicUsize = AtomicUsize::new(0);

/// Reserve the DMA pool: `pages` physically contiguous frames taken out of the
/// allocator once, at boot, before anything can fragment it
/// (`alloc_contiguous`, the mechanism). Returns its physical base.
///
/// Reserve only: nothing allocates from the pool yet. It is one number
/// memory admission can count, where growing on demand could fail at run
/// time from fragmentation. A second call is refused (`InvalidArg`), so the pool cannot be replaced by
/// one of another size after admission counted it. `pages == 0` reserves
/// nothing and succeeds.
pub fn reserve_dma_pool(pages: usize) -> KResult<PhysAddr> {
    if DMA_POOL_PAGES.load(Ordering::Acquire) != 0 {
        return Err(KernelError::InvalidArg);
    }
    if pages == 0 {
        return Ok(PhysAddr::new(0));
    }
    // Boot-time admission: frames this hart just freed sit in its cache, not
    // in the buddy lists, and a run is only found among the lists. Without
    // this a pool admitted again after a refused candidate (the frames of the
    // first reservation's neighbours given back) found no run of its length.
    flush_local_cache();
    let base = alloc_contiguous(pages)?;
    DMA_POOL_BASE.store(base.as_usize(), Ordering::Release);
    DMA_POOL_PAGES.store(pages, Ordering::Release);
    Ok(base)
}

/// Undo [`reserve_dma_pool`]: every frame goes back to the allocator and the
/// pool is unset. For boot admission only, when the topology the pool was
/// reserved for is refused before it is installed; nothing has been given a
/// frame of the pool yet.
pub fn release_dma_pool() {
    let pages = DMA_POOL_PAGES.swap(0, Ordering::AcqRel);
    let base = DMA_POOL_BASE.swap(0, Ordering::AcqRel);
    for i in 0..pages {
        let _ = free_page(PhysAddr::new(base + i * PAGE_SIZE));
    }
}

/// `(physical base, pages)` of the DMA pool; `(0, 0)` before it is reserved.
pub fn dma_pool() -> (usize, usize) {
    (DMA_POOL_BASE.load(Ordering::Acquire), DMA_POOL_PAGES.load(Ordering::Acquire))
}
