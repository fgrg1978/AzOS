// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Typed kernel object caches: `Cache<T>` hands out objects of one type from
//! blocks of the page allocator, so an object freed as `T` is only ever
//! reissued as `T`. Memory is not zeroed or typed beyond that: a caller
//! initialises what it takes (`alloc_zeroed` for the all-zero fresh state).
//!
//! A block is a run of pages whose base is aligned to the next power of two
//! of its size, with a header at the base: `ptr & !(BLOCK - 1)` finds it on
//! free, and the header's tag (the owning cache's address) refuses an object
//! that belongs to another cache. One object per block for the large tables,
//! many for small types. Blocks count against the heap ceiling
//! (`KERNEL_HEAP_SIZE`), like slab pages.
//!
//! * **Retained** caches (the security tables) never return a block to the
//!   page allocator.
//! * Other caches return a block once every object in it is free.
//! * **Preload** (`MM_PRELOAD_CACHES`): `preload(n)` fills the cache to `n`
//!   objects and seals it, so it never grows afterwards.
//!
//! The lock is a leaf taken with interrupts masked and never held across a
//! call into the page allocator.

use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ptr::{null_mut, write_bytes};
use core::sync::atomic::{AtomicUsize, Ordering};
use azos_arch::PAGE_SIZE;
use azos_arch_api::tlb_gen::{SpaceTable, SPACE_SLOTS};
use azos_sync::SpinLock;
use crate::addr::{phys_to_virt, virt_to_phys, PhysAddr};
use crate::{kheap, pmm};

/// Whether the boot caches are filled and sealed at boot: Kconfig
/// `MM_PRELOAD_CACHES`, or a `ktest` kernel (so the dev presets exercise it).
/// Canary `kmem-preload-canary`: never.
pub const PRELOAD: bool =
    (azos_limits::MM_PRELOAD_CACHES || cfg!(feature = "ktest")) && !cfg!(feature = "kmem-preload-canary");

#[repr(C)]
struct Block {
    tag: usize,
    used: usize,
}

#[repr(C)]
struct Obj {
    next: *mut Obj,
}

struct State {
    free: *mut Obj,
    sealed: bool,
}

// SAFETY: the free list is reached only under the cache's lock.
unsafe impl Send for State {}

pub struct Cache<T> {
    st: SpinLock<State>,
    blocks: AtomicUsize,
    retain: bool,
    _t: PhantomData<fn() -> T>,
}

impl<T> Cache<T> {
    const A: usize = if align_of::<T>() > align_of::<Obj>() { align_of::<T>() } else { align_of::<Obj>() };
    const STRIDE: usize = {
        assert!(size_of::<T>() >= size_of::<Obj>());
        assert!(Self::A <= PAGE_SIZE);
        size_of::<T>().next_multiple_of(Self::A)
    };
    const HDR: usize = size_of::<Block>().next_multiple_of(Self::A);
    const PAGES: usize = (Self::HDR + Self::STRIDE).div_ceil(PAGE_SIZE);
    const BLOCK: usize = (Self::PAGES * PAGE_SIZE).next_power_of_two();
    const PER: usize = (Self::PAGES * PAGE_SIZE - Self::HDR) / Self::STRIDE;

    /// A cache whose empty blocks go back to the page allocator.
    pub const fn new() -> Self {
        Self { st: SpinLock::new(State { free: null_mut(), sealed: false }), blocks: AtomicUsize::new(0), retain: false, _t: PhantomData }
    }

    /// A cache whose blocks are never given back: a stale pointer to a `T`
    /// can only ever meet another `T`.
    pub const fn retained() -> Self {
        Self { st: SpinLock::new(State { free: null_mut(), sealed: false }), blocks: AtomicUsize::new(0), retain: true, _t: PhantomData }
    }

    #[inline]
    fn tag(&self) -> usize { self as *const Self as usize }

    #[inline]
    fn block_of(p: usize) -> *mut Block { (p & !(Self::BLOCK - 1)) as *mut Block }

    /// Take one more block from the page allocator and file its objects.
    fn grow(&self) -> bool {
        if !kheap::take(Self::PAGES) { return false; }
        let base = match pmm::alloc_contiguous_aligned(Self::PAGES, Self::BLOCK) {
            Ok(a) => phys_to_virt(a.as_usize()) as *mut u8,
            Err(_) => { kheap::give(Self::PAGES); return false; }
        };
        // SAFETY: the run is ours, zeroed, and BLOCK-aligned; the objects lie
        // inside its first PAGES pages.
        unsafe {
            (*(base as *mut Block)).tag = self.tag();
            let mut st = self.st.lock_irqsave();
            for i in (0..Self::PER).rev() {
                let o = base.add(Self::HDR + i * Self::STRIDE) as *mut Obj;
                (*o).next = st.free;
                st.free = o;
            }
        }
        self.blocks.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// One object, its bytes unspecified; null when the cache is sealed and
    /// empty, or the ceiling or the page allocator refuses.
    pub fn alloc(&self) -> *mut T {
        loop {
            {
                let mut st = self.st.lock_irqsave();
                let o = st.free;
                if !o.is_null() {
                    // SAFETY: a free object's first word is the link, and its
                    // block header is at the block's base.
                    unsafe {
                        st.free = (*o).next;
                        (*Self::block_of(o as usize)).used += 1;
                    }
                    return o.cast();
                }
                if st.sealed { return null_mut(); }
            }
            if !self.grow() { return null_mut(); }
        }
    }

    /// [`Self::alloc`] with every byte zero.
    pub fn alloc_zeroed(&self) -> *mut T {
        let p = self.alloc();
        // SAFETY: `p` is a whole object of this cache.
        if !p.is_null() { unsafe { write_bytes(p, 0, 1) }; }
        p
    }

    /// Give an object back. False, with nothing changed, when it is not one
    /// of this cache's (the block's tag is another cache's) or is not in use.
    /// Canary `kmem-cache-cross-type-canary`: the tag is not compared, so
    /// another type's object is filed here and reissued.
    ///
    /// # Safety
    /// `p` came from some cache's `alloc` and nothing uses it any more.
    pub unsafe fn try_free(&self, p: *mut T) -> bool {
        let b = Self::block_of(p as usize);
        // SAFETY: per the contract `p` lies in a cache block, whose base holds the header.
        unsafe {
            if (*b).tag != self.tag() && !cfg!(feature = "kmem-cache-cross-type-canary") { return false; }
            let mut release = false;
            {
                let mut st = self.st.lock_irqsave();
                if (*b).used == 0 { return false; }
                (*b).used -= 1;
                let o = p as *mut Obj;
                (*o).next = st.free;
                st.free = o;
                if (*b).used == 0 && !self.retain && !st.sealed {
                    let mut link: *mut *mut Obj = &mut st.free;
                    while !(*link).is_null() {
                        let q = *link;
                        if Self::block_of(q as usize) == b { *link = (*q).next; } else { link = &mut (*q).next; }
                    }
                    release = true;
                }
            }
            if release {
                self.blocks.fetch_sub(1, Ordering::Relaxed);
                let _ = pmm::free_run(PhysAddr::new(virt_to_phys(b as usize)), Self::PAGES);
                kheap::give(Self::PAGES);
            }
        }
        true
    }

    /// Give an object back; a foreign pointer is a kernel bug.
    ///
    /// # Safety
    /// As [`Self::try_free`].
    pub unsafe fn free(&self, p: *mut T) {
        // SAFETY: forwarded.
        if !unsafe { self.try_free(p) } { panic!("kmem cache: object freed to a cache it is not from"); }
    }

    /// Fill the cache to at least `n` objects and seal it: it takes no more
    /// pages afterwards. False when the pages were not there.
    pub fn preload(&self, n: usize) -> bool {
        while self.blocks.load(Ordering::Relaxed) * Self::PER < n {
            if !self.grow() { return false; }
        }
        self.st.lock_irqsave().sealed = true;
        true
    }

    pub fn is_sealed(&self) -> bool { self.st.lock_irqsave().sealed }

    /// Pages this cache holds.
    pub fn held_pages(&self) -> usize { self.blocks.load(Ordering::Relaxed) * Self::PAGES }
}

type Spaces = SpaceTable<SPACE_SLOTS>;
static SPACE_CACHE: Cache<Spaces> = Cache::new();

/// Allocate the TLB per-space record and give it to `tlb_gen::SPACES`. Boot,
/// after `kheap::init` and before the first user switch.
pub fn init_spaces() {
    let p = SPACE_CACHE.alloc();
    assert!(!p.is_null(), "tlb space table: no memory");
    // SAFETY: `p` is a whole object, owned for the life of the kernel;
    // `reset` stores every field.
    unsafe {
        (*p).reset(1);
        azos_arch_api::tlb_gen::SPACES.install(&*p);
    }
    if PRELOAD { SPACE_CACHE.preload(1); }
}

/// Whether the TLB record's cache is filled and sealed.
pub fn spaces_sealed() -> bool { SPACE_CACHE.is_sealed() }
