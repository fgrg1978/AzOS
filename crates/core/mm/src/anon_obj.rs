// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The unnamed anonymous object behind a private `mmap`: its pages' slots
//! ([`crate::slot`]), owned by one address space and reached only through its
//! mappings (`crate::mapping`), with no capability and no table slot.
//!
//! **Pages are numbered by address.** The page of an object a mapping maps at
//! `va` is `va >> PAGE_SHIFT`, as Linux numbers an anonymous VMA's pages: the
//! object has one mapper, so the number is unique, and a new mapping next to
//! one of the object's, below it or above it, continues the object's pages
//! and folds into that record. A page no mapping covers has an `Empty` slot.
//!
//! **Slots.** [`SLOTS_INLINE`] pages from the first one the object was made
//! for (Kconfig `MM_SLOTS_INLINE`) have their words inside the object. The
//! others sit in 4 KiB chunks of [`PER_CHUNK`] words: the first [`NEAR`]
//! chunks from the object's first one through pointers in the object, the rest
//! of a window of [`PER_CHUNK`] chunks around it (half below, half above)
//! through one directory page. Chunks and the directory are allocated on the
//! first touch of a page they hold and charged to the space's Domain within
//! its limit ([`crate::vmm::TableCharge::Take`]: kernel memory the
//! reservation did not count, so a touch past the limit is refused for it);
//! an absent chunk is a run of `Empty` slots. A `munmap` that leaves no
//! mapping of the object over a chunk's pages frees the chunk. A mapping that would
//! leave the window ([`AnonObj::holds`]) gets an object of its own.
//!
//! **Locking.** The object has one mapper, its space, so the space's lock is
//! its lock: every slot word is written under it, which is also what keeps the
//! object alive (a mapping names it under that lock, and the object goes only
//! when no mapping does). The two exceptions: `munmap`'s empty of the slots
//! of a range no mapping names any more, which nothing else reaches, and a
//! fork's clone writing the slots of the child's object, whose space no task
//! runs on yet (under the group's layout lock). Chunks are allocated before the
//! lock is taken and installed under it ([`Spare`]).
//!
//! **Frames.** A `Frame` slot and the page-table leaf of its page name the same
//! frame: the leaf is written when the slot becomes `Frame` and cleared when
//! it stops being one, and a copy-on-write break moves both. A fork's clone
//! (`pager::fork_clone`) gives the child's object the same `Frame` word and
//! leaf, read-only on both sides, with one more reference on the frame. The leaf sweep of
//! `munmap` and of the space's end frees the frame (`vmm::unmap_user_range_and_free`,
//! `vmm::destroy_user_pagetable_skip_range`); the object never frees one, so a
//! frame is freed once.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use azos_arch::PAGE_SIZE;
use azos_common::error::{KResult, KernelError};

use crate::addr::{phys_to_virt, virt_to_phys, PhysAddr};
use crate::cache::Cache;
use crate::slot;
use crate::vmm::{self, TableCharge};
use crate::pmm;

/// Slots held inside the object (Kconfig `MM_SLOTS_INLINE`).
pub const SLOTS_INLINE: usize = azos_limits::MM_SLOTS_INLINE as usize;
/// Slot words in one chunk page.
pub const PER_CHUNK: usize = PAGE_SIZE / 8;
/// Chunks reached through the object itself, from its first one on: an object
/// within `SLOTS_INLINE + NEAR * PER_CHUNK` pages of its start needs no
/// directory.
pub const NEAR: usize = 4;
/// Chunks of the directory's window below the object's first chunk.
const BELOW: usize = PER_CHUNK / 2;

#[repr(C)]
pub struct AnonObj {
    /// The first page of the inline slots.
    ibase: usize,
    /// The chunk the near pointers and the directory's window are counted from.
    cbase: usize,
    /// Kernel address of the directory page, 0 while there is none.
    dir: AtomicUsize,
    /// The child's object while a fork copies the space (`pager::fork_clone`,
    /// under the group's layout lock): the mappings of one object in the parent
    /// map one object in the child.
    twin: AtomicUsize,
    near: [AtomicUsize; NEAR],
    inline: [AtomicU64; SLOTS_INLINE],
}

static OBJS: Cache<AnonObj> = Cache::new();

/// Where page `i`'s slot lives.
#[derive(Clone, Copy)]
enum Place {
    Inline(usize),
    /// Near chunk, word.
    Near(usize, usize),
    /// Directory entry, word.
    Dir(usize, usize),
}

/// The object a mapping names.
///
/// # Safety
/// `h` is the handle of a live object: read from a mapping of its space with
/// that space's lock held, or the caller's own until it maps it.
#[inline(always)]
pub unsafe fn get<'a>(h: usize) -> &'a AnonObj {
    // SAFETY: per the contract.
    unsafe { &*(h as *const AnonObj) }
}

/// A new object whose pages `first..first + pages` (page numbers: module doc)
/// a first mapping maps, every slot `Empty`; its handle. `None` when the cache
/// has no memory.
pub fn create(first: usize, pages: usize) -> Option<usize> {
    let p = OBJS.alloc_zeroed();
    if p.is_null() {
        return None;
    }
    // SAFETY: a whole zeroed object of the cache, ours.
    unsafe {
        (*p).ibase = first;
        (*p).cbase = first / PER_CHUNK;
    }
    // SAFETY: just made.
    if !unsafe { get(p as usize) }.holds(first, first + pages) {
        // SAFETY: never handed out.
        unsafe { OBJS.free(p) };
        return None;
    }
    Some(p as usize)
}

/// An empty object whose slots are placed as `o`'s: a fork's child's copy,
/// which holds every page `o` holds.
pub fn create_twin(o: &AnonObj) -> Option<usize> {
    let p = OBJS.alloc_zeroed();
    if p.is_null() {
        return None;
    }
    // SAFETY: a whole zeroed object of the cache, ours.
    unsafe {
        (*p).ibase = o.ibase;
        (*p).cbase = o.cbase;
    }
    Some(p as usize)
}

/// Free the object `h` and its slot pages, returning their charge to `root`.
/// What its slots name is not touched (module doc: the leaf sweep frees frames,
/// the pool's entries go with the space's key).
///
/// # Safety
/// No mapping names `h` any more and no thread holds a reference to it.
pub unsafe fn destroy(h: usize, root: usize) {
    // SAFETY: the caller's.
    let o = unsafe { get(h) };
    for c in o.near.iter().map(|c| c.load(Ordering::Acquire)).filter(|&c| c != 0) {
        free_page(root, c);
    }
    if let Some(d) = o.dir() {
        for c in d.iter().map(|c| c.load(Ordering::Acquire)).filter(|&c| c != 0) {
            free_page(root, c);
        }
        free_page(root, o.dir.load(Ordering::Acquire));
    }
    // SAFETY: from this cache, unused (the contract).
    unsafe { OBJS.free(h as *mut AnonObj) };
}

/// Free a chunk [`AnonObj::take_chunk`] unhooked, its charge back to `root`.
pub fn free_chunk(root: usize, va: usize) {
    free_page(root, va);
}

fn free_page(root: usize, va: usize) {
    let _ = pmm::free_page(PhysAddr::new(virt_to_phys(va)));
    let _ = vmm::table_charge(root, TableCharge::Return);
}

/// Zeroed pages for the chunks a slot install may need, taken before the
/// space's lock is; what the install did not use goes back when this drops.
pub struct Spare {
    root: usize,
    pages: [usize; 2],
    n: usize,
}

impl Spare {
    /// `n` (at most 2) pages charged to `root` within its Domain's limit.
    /// `QuotaRefused` when the limit refuses one, `OutOfMemory` when the
    /// allocator has none: nothing is held then.
    #[inline]
    pub fn take(root: usize, n: usize) -> KResult<Self> {
        let s = Spare { root, pages: [0; 2], n: 0 };
        if n == 0 {
            return Ok(s);
        }
        s.fill(n)
    }

    #[cold]
    fn fill(mut self, n: usize) -> KResult<Self> {
        let s = &mut self;
        while s.n < n.min(2) {
            // Canary `slot-chunk-promised-canary`: charged whatever the
            // Domain's limit says, as a table a first touch needs is.
            let take = if cfg!(feature = "slot-chunk-promised-canary") { TableCharge::Promised } else { TableCharge::Take };
            if !vmm::table_charge(s.root, take) {
                return Err(KernelError::QuotaRefused);
            }
            match pmm::alloc_page() {
                Ok(p) => {
                    s.pages[s.n] = phys_to_virt(p.as_usize());
                    s.n += 1;
                }
                Err(_) => {
                    let _ = vmm::table_charge(s.root, TableCharge::Return);
                    return Err(KernelError::OutOfMemory);
                }
            }
        }
        Ok(self)
    }

    fn pop(&mut self) -> Option<usize> {
        if self.n == 0 {
            return None;
        }
        self.n -= 1;
        Some(core::mem::take(&mut self.pages[self.n]))
    }
}

impl Drop for Spare {
    #[inline]
    fn drop(&mut self) {
        if self.n != 0 {
            self.give_back();
        }
    }
}

impl Spare {
    #[cold]
    fn give_back(&mut self) {
        while let Some(va) = self.pop() {
            free_page(self.root, va);
        }
    }
}

/// Words `k..k + n` of the chunk page at `chunk` (none while there is none).
#[inline(always)]
fn chunk_run<'a>(chunk: usize, k: usize, n: usize) -> Option<&'a [AtomicU64]> {
    if chunk == 0 {
        return None;
    }
    // SAFETY: a chunk page of a live object, `PER_CHUNK` words.
    let words: &[AtomicU64; PER_CHUNK] = unsafe { &*(chunk as *const [AtomicU64; PER_CHUNK]) };
    words.get(k..k.checked_add(n)?)
}

/// The word `k` of the chunk page at `chunk`.
///
/// # Safety
/// `chunk` is a chunk page of a live object.
#[inline(always)]
unsafe fn word_in<'a>(chunk: usize, k: usize) -> &'a AtomicU64 {
    // SAFETY: a chunk is `PER_CHUNK` words and `k < PER_CHUNK`.
    unsafe { &(*(chunk as *const [AtomicU64; PER_CHUNK]))[k] }
}

impl AnonObj {
    #[inline(always)]
    fn place(&self, i: usize) -> Option<Place> {
        let j = i.wrapping_sub(self.ibase);
        if j < SLOTS_INLINE {
            return Some(Place::Inline(j));
        }
        let (c, k) = (i / PER_CHUNK, i % PER_CHUNK);
        let r = c.wrapping_sub(self.cbase);
        if r < NEAR {
            return Some(Place::Near(r, k));
        }
        let d = r.wrapping_add(BELOW);
        (d < PER_CHUNK).then_some(Place::Dir(d, k))
    }

    /// Has every page of `[lo, hi)` a place for its slot? A mapping of the
    /// object over those pages may be made only then.
    pub fn holds(&self, lo: usize, hi: usize) -> bool {
        lo < hi && self.place(lo).is_some() && self.place(hi - 1).is_some()
    }

    #[inline(always)]
    fn dir(&self) -> Option<&[AtomicUsize; PER_CHUNK]> {
        let d = self.dir.load(Ordering::Acquire);
        // SAFETY: a directory page the object installed, freed only with it.
        (d != 0).then(|| unsafe { &*(d as *const [AtomicUsize; PER_CHUNK]) })
    }

    /// The slot of page `i`, if it has storage yet (none: `Empty`).
    #[inline(always)]
    pub fn slot(&self, i: usize) -> Option<&AtomicU64> {
        let chunk = match self.place(i)? {
            Place::Inline(j) => return Some(&self.inline[j]),
            Place::Near(r, k) => (self.near[r].load(Ordering::Acquire), k),
            Place::Dir(d, k) => (self.dir()?[d].load(Ordering::Acquire), k),
        };
        // SAFETY: a chunk page of this object.
        (chunk.0 != 0).then(|| unsafe { word_in(chunk.0, chunk.1) })
    }

    /// The slots of pages `i..i + n` as one run, when all of them have storage
    /// in one place: the inline slots, or one chunk. `None` otherwise (a run
    /// that crosses from the inline slots into a chunk, or a chunk not there).
    #[inline]
    pub fn run(&self, i: usize, n: usize) -> Option<&[AtomicU64]> {
        let last = i.checked_add(n.checked_sub(1)?)?;
        match (self.place(i)?, self.place(last)?) {
            (Place::Inline(a), Place::Inline(_)) => self.inline.get(a..a + n),
            (Place::Near(r, k), Place::Near(q, _)) if r == q => chunk_run(self.near[r].load(Ordering::Acquire), k, n),
            (Place::Dir(d, k), Place::Dir(e, _)) if d == e => chunk_run(self.dir()?[d].load(Ordering::Acquire), k, n),
            _ => None,
        }
    }

    /// The word of page `i`'s slot and the pages a [`Spare`] needs for
    /// [`Self::slot_fill`] of it, read under the space's lock.
    #[inline(always)]
    pub fn look(&self, i: usize) -> (u64, usize) {
        let (chunk, k) = match self.place(i) {
            Some(Place::Inline(j)) => return (self.inline[j].load(Ordering::Relaxed), 0),
            Some(Place::Near(r, k)) => (self.near[r].load(Ordering::Acquire), k),
            Some(Place::Dir(d, k)) => match self.dir() {
                None => return (slot::EMPTY, 2),
                Some(dir) => (dir[d].load(Ordering::Acquire), k),
            },
            None => return (slot::EMPTY, 0),
        };
        if chunk == 0 {
            return (slot::EMPTY, 1);
        }
        // SAFETY: a chunk page of this object.
        (unsafe { word_in(chunk, k) }.load(Ordering::Relaxed), 0)
    }

    /// Pages a [`Spare`] needs for [`Self::slot_fill`] of page `i`.
    #[inline]
    pub fn missing(&self, i: usize) -> usize {
        self.look(i).1
    }

    /// The slot of page `i`, its storage installed from `spare` when it has
    /// none. Under the space's lock. `None` when `spare` is short or the page
    /// has no place ([`Self::holds`]).
    #[inline]
    pub fn slot_fill(&self, i: usize, spare: &mut Spare) -> Option<&AtomicU64> {
        match self.place(i)? {
            Place::Inline(_) => {}
            Place::Near(r, _) => {
                if self.near[r].load(Ordering::Acquire) == 0 {
                    self.near[r].store(spare.pop()?, Ordering::Release);
                }
            }
            Place::Dir(d, _) => {
                if self.dir.load(Ordering::Acquire) == 0 {
                    self.dir.store(spare.pop()?, Ordering::Release);
                }
                let dir = self.dir()?;
                if dir[d].load(Ordering::Acquire) == 0 {
                    dir[d].store(spare.pop()?, Ordering::Release);
                }
            }
        }
        self.slot(i)
    }

    /// Call `f(i, slot)` for every page in `[lo, hi)` that has slot storage.
    pub fn for_each(&self, lo: usize, hi: usize, mut f: impl FnMut(usize, &AtomicU64)) {
        for i in lo..hi {
            if let Some(s) = self.slot(i) {
                f(i, s);
            }
        }
    }

    /// Unhook the chunk of page numbers `c * PER_CHUNK ..` (the slots of a range
    /// no mapping of the object covers any more: all empty), for the caller to
    /// free once the space's lock is dropped ([`free_chunk`]). Under that lock.
    pub fn take_chunk(&self, c: usize) -> Option<usize> {
        let r = c.wrapping_sub(self.cbase);
        let p = if r < NEAR {
            self.near[r].swap(0, Ordering::AcqRel)
        } else {
            let d = r.wrapping_add(BELOW);
            if d >= PER_CHUNK {
                return None;
            }
            self.dir()?[d].swap(0, Ordering::AcqRel)
        };
        (p != 0).then_some(p)
    }

    /// The twin a fork gave the object, 0 when none (`pager::fork_clone`).
    pub fn twin(&self) -> usize {
        self.twin.load(Ordering::Relaxed)
    }

    pub fn set_twin(&self, h: usize) {
        self.twin.store(h, Ordering::Relaxed);
    }
}
