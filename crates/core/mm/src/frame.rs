// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The frame descriptor table: one 32-byte [`FrameDesc`] per physical frame of
//! ALL the RAM the firmware reported, indexed by frame number.
//!
//! This file knows nothing about allocation. It owns three things: the
//! [`Pfn`] type, the descriptor layout and its state bits, and [`FrameTable`],
//! the view of the array that turns a frame number into its descriptor. The
//! buddy lists and the per-hart caches (`buddy.rs`) and the COW share count
//! (`cow_table.rs`) are written over it; the table itself is placed and
//! filled by `pmm::init`.
//!
//! # What a descriptor holds
//!
//! | field      | meaning                                                      |
//! |------------|--------------------------------------------------------------|
//! | `refcount` | COW share count; `0` = untracked, a single holder             |
//! | `flags`    | exactly the state bits below                                  |
//! | `order`    | on the head of a free block, the block's order                |
//! | `next/prev`| free-list (and per-hart cache) links, as table indexes        |
//! | `zone`     | the type zone the frame belongs to (`zone.rs`); `0` = none    |
//! | `owner`    | the object that holds the frame (opaque to this file); `0` = none |
//! | `owner_idx`| the frame's page index inside that object                     |
//!
//! `owner` and `owner_idx` are the reverse map: from a frame to the one object
//! that holds it and the place it has there, so that whoever needs every
//! mapping of a frame (a reclaimer, a revoke of one page) asks the object
//! instead of scanning page tables. This file does not interpret the value: the
//! memory-object table (`ipc/src/memobj.rs`) writes its packed
//! `(index, generation)` reference, which goes stale on its own when the object
//! is freed. A frame two objects share (a COW clone) names the object that
//! allocated it until that object lets go of it; the other sharer's mapping is
//! found through the sharer's own list. The writers clear the field before the
//! frame goes back to the allocator, so a free frame never names an object.
//!
//! There is **no colour and no node field**: the cache colour of a frame is
//! `pfn & (colours - 1)` and its memory node is a function of its address
//! (the topology's node ranges), so both are derived, and a field would only
//! be a second copy to keep equal.
//!
//! # Cost
//!
//! 32 B per frame (eight words, exactly the alignment; the owner pair filled
//! the two words the padding left, so the reverse map costs no RAM): 0.78 % of
//! RAM at 4 KiB frames. The array lives in RAM, just above the kernel image
//! (`pmm::init`), and is itself reserved. There is no Domain field: nothing
//! reads a frame's Domain, and the Domain's budget counts pages.
//!
//! # Concurrency
//!
//! Every field is an atomic accessed with `Relaxed` ordering, which is a plain
//! load or store on every target. The free-list fields are written only under
//! the buddy lock (or by the one hart that owns a cache, interrupts off); the
//! `refcount` is the only field two harts race on without a lock, and it is
//! only ever changed by compare-and-swap.

use core::sync::atomic::{AtomicU32, Ordering};
use azos_arch::PAGE_SIZE;

const PAGE_SHIFT: usize = PAGE_SIZE.trailing_zeros() as usize;

/// A physical frame number: the physical address divided by the frame size.
/// Absolute (from physical address 0), never relative to where RAM starts, so
/// a buddy block of order `k` is naturally aligned to `2^k` frames in the
/// physical address space, which is what a 2 MiB leaf needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Pfn(pub usize);

impl Pfn {
    /// The frame holding physical address `pa` (rounded down).
    #[inline(always)]
    pub const fn from_phys(pa: usize) -> Pfn { Pfn(pa >> PAGE_SHIFT) }
    /// The physical address of the frame's first byte.
    #[inline(always)]
    pub const fn phys(self) -> usize { self.0 << PAGE_SHIFT }
    /// The cache colour: the low bits of the frame number. `colours` is a
    /// power of two. Derived, never stored.
    #[inline(always)]
    pub const fn colour(self, colours: usize) -> usize { self.0 & (colours - 1) }
}

/// In the buddy lists, owned by nobody.
pub const F_FREE: u32 = 1 << 0;
/// Handed out by the allocator.
pub const F_ALLOCATED: u32 = 1 << 1;
/// Never allocatable: the kernel image, the descriptor array, the heap, memory
/// map holes, the panic record region. `free` accepts a reserved frame (a
/// frame taken with `reserve_range` and given back, such as the DMA pool's).
pub const F_RESERVED: u32 = 1 << 2;
/// Allocated and not to be freed or moved while the bit is set (modifier).
pub const F_PINNED: u32 = 1 << 3;
/// Allocated, its contents held compressed elsewhere (modifier).
pub const F_COMPRESSED: u32 = 1 << 4;
/// Allocated, its contents written to swap (modifier).
pub const F_SWAPPED: u32 = 1 << 5;
/// Free, but held in a hart's page cache: counted free, not in a buddy list.
pub const F_CACHED: u32 = 1 << 6;

/// End of a list, and "no such frame".
pub const NIL: u32 = u32::MAX;
/// `order` of a frame that does not head a free block.
pub const NOT_HEAD: u32 = u32::MAX;

/// The per-frame record. See the module docs for the fields.
#[repr(C, align(32))]
pub struct FrameDesc {
    pub(crate) refcount: AtomicU32,
    pub(crate) flags: AtomicU32,
    pub(crate) order: AtomicU32,
    pub(crate) next: AtomicU32,
    pub(crate) prev: AtomicU32,
    /// `zone::Zone` tag: set when a zoned allocation first takes the frame,
    /// never cleared (a tagged frame is never given back to the buddy lists).
    pub(crate) zone: AtomicU32,
    /// Reverse map: the holder object's reference (opaque here, `0` = none).
    pub(crate) owner: AtomicU32,
    /// Reverse map: the frame's page index inside its holder object.
    pub(crate) owner_idx: AtomicU32,
}

const _: () = assert!(core::mem::size_of::<FrameDesc>() == 32);
const _: () = assert!(core::mem::align_of::<FrameDesc>() == 32);

impl FrameDesc {
    /// A descriptor in state `flags`, unshared.
    pub const fn new(flags: u32) -> FrameDesc {
        FrameDesc {
            refcount: AtomicU32::new(0),
            flags: AtomicU32::new(flags),
            order: AtomicU32::new(NOT_HEAD),
            next: AtomicU32::new(NIL),
            prev: AtomicU32::new(NIL),
            zone: AtomicU32::new(0),
            owner: AtomicU32::new(0),
            owner_idx: AtomicU32::new(0),
        }
    }
    /// The state bits.
    #[inline(always)]
    pub fn state(&self) -> u32 { self.flags.load(Ordering::Relaxed) }
    /// The COW share count; `0` is untracked.
    #[inline(always)]
    pub fn refcount(&self) -> u32 { self.refcount.load(Ordering::Relaxed) }

    /// The holder object and the page index in it, or `None` for a frame no
    /// object holds.
    #[inline(always)]
    pub fn owner(&self) -> Option<(u32, u32)> {
        // The index is written first and the owner last (`set_owner`), so a
        // non-zero owner read here has its index in place.
        match self.owner.load(Ordering::Acquire) {
            0 => None,
            o => Some((o, self.owner_idx.load(Ordering::Relaxed))),
        }
    }

    /// Record that object `owner` (non-zero) holds this frame as its page
    /// `idx`. The caller holds the object's lock, which is what serialises
    /// the writers of one frame.
    #[inline(always)]
    pub fn set_owner(&self, owner: u32, idx: u32) {
        debug_assert!(owner != 0);
        self.owner_idx.store(idx, Ordering::Relaxed);
        self.owner.store(owner, Ordering::Release);
    }

    /// Forget the holder, but only when it is `owner`: the frame is being let
    /// go of by `owner`, and a frame another object has since taken keeps its
    /// own record. `true` when the record was `owner`'s and is gone.
    #[inline(always)]
    pub fn clear_owner_if(&self, owner: u32) -> bool {
        self.owner.compare_exchange(owner, 0, Ordering::AcqRel, Ordering::Relaxed).is_ok()
    }
}

/// The descriptor array: where it is, which frame number its first entry
/// describes, and how many entries it has.
#[derive(Clone, Copy)]
pub struct FrameTable {
    descs: *const FrameDesc,
    first: usize,
    count: usize,
}

// SAFETY: the table is a view of an array of atomics that lives for the whole
// boot (it is carved out of RAM no allocator will ever hand out).
unsafe impl Send for FrameTable {}
unsafe impl Sync for FrameTable {}

impl FrameTable {
    /// The empty table: no frame is managed.
    pub const EMPTY: FrameTable = FrameTable { descs: core::ptr::null(), first: 0, count: 0 };

    /// The table over `count` descriptors at `descs`, the first describing
    /// frame `first`.
    ///
    /// # Safety
    /// `descs` must point at `count` initialised [`FrameDesc`]s that stay valid
    /// and are not moved for as long as the table (or a copy) is used.
    pub const unsafe fn new(descs: *const FrameDesc, first: Pfn, count: usize) -> FrameTable {
        FrameTable { descs, first: first.0, count }
    }

    /// Frames described.
    #[inline(always)]
    pub fn len(&self) -> usize { self.count }
    /// The first frame described.
    #[inline(always)]
    pub fn first(&self) -> Pfn { Pfn(self.first) }
    /// One past the last frame described.
    #[inline(always)]
    pub fn end(&self) -> Pfn { Pfn(self.first + self.count) }

    /// The array index of `pfn`, or `None` outside the table.
    #[inline(always)]
    pub fn index(&self, pfn: Pfn) -> Option<usize> {
        let i = pfn.0.wrapping_sub(self.first);
        // Canary `frame-index-canary`: frames pair up on one descriptor.
        let at = if cfg!(feature = "frame-index-canary") { i & !1 } else { i };
        if i < self.count { Some(at) } else { None }
    }

    /// The frame an array index describes.
    #[inline(always)]
    pub fn pfn(&self, idx: usize) -> Pfn { Pfn(self.first + idx) }

    /// The descriptor at array index `idx`; `idx < len()`.
    #[inline(always)]
    pub fn at(&self, idx: usize) -> &FrameDesc {
        debug_assert!(idx < self.count);
        // SAFETY: `new`'s contract, and the caller's bound.
        unsafe { &*self.descs.add(idx) }
    }

    /// The descriptor of `pfn`, or `None` outside the table.
    #[inline(always)]
    pub fn get(&self, pfn: Pfn) -> Option<&FrameDesc> {
        self.index(pfn).map(|i| self.at(i))
    }

    /// The descriptor of the frame holding physical address `pa`, or `None`
    /// when `pa` is not frame-aligned or not managed.
    #[inline(always)]
    pub fn of_phys(&self, pa: usize) -> Option<&FrameDesc> {
        if pa & (PAGE_SIZE - 1) != 0 { return None; }
        self.get(Pfn::from_phys(pa))
    }
}

/// Bytes of descriptor array for `frames` frames, rounded up to whole frames.
pub const fn table_bytes(frames: usize) -> usize {
    (frames * core::mem::size_of::<FrameDesc>() + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}
