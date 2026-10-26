// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! `kmalloc` family over a caller-provided arena.
//!
//! The server has no global allocator, so the arena is a byte slice the
//! caller owns (a `static` buffer in lxsrv, a stack array in the tests).
//! The allocator is first-fit over an implicit list of blocks with boundary
//! tags: every block starts with a 16-byte header holding its own size (with
//! an "allocated" bit) and the size of the block before it. The back-link is
//! what makes coalescing with the *previous* neighbour O(1) without a footer.
//!
//! Robustness over speed: `kfree`, `ksize` and `krealloc` never trust a
//! header at the address the caller passes. They walk the block list from the
//! start (O(blocks)) to prove the pointer is the payload of a live block. A
//! driver bug (double free, interior pointer, pointer from elsewhere) is
//! therefore reported and counted, and the heap is left untouched. The walk is
//! the price of that guarantee; L0 favours detection over throughput.

use core::marker::PhantomData;
use core::ptr::NonNull;

/// Minimum payload alignment, as Linux's `ARCH_KMALLOC_MINALIGN` on the
/// 64-bit targets AzOS runs on (cache-line DMA safety is a separate matter).
pub const ARCH_KMALLOC_MINALIGN: usize = 16;

/// The pointer `kmalloc(0)` returns: non-null, distinct from every real
/// allocation, never dereferenceable, and accepted by `kfree`. Same value as
/// Linux so a driver that compares against it sees what it expects.
pub const ZERO_SIZE_PTR: *mut u8 = 16 as *mut u8;

/// Byte written over freed payloads, so a use-after-free reads a recognisable
/// pattern instead of plausible stale data.
pub const POISON_FREE: u8 = 0x6b;

/// Allocation flags (`gfp_t`). In the run-to-completion loop nothing ever
/// sleeps for memory, so only `__GFP_ZERO` changes behaviour; the others are
/// accepted so driver call sites translate one-to-one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gfp(pub u32);

impl Gfp {
    /// Zero the returned memory.
    pub const ZERO: Gfp = Gfp(0x100);
    /// `GFP_KERNEL`: may sleep (never does here).
    pub const KERNEL: Gfp = Gfp(0x1);
    /// `GFP_ATOMIC`: must not sleep.
    pub const ATOMIC: Gfp = Gfp(0x2);

    /// Union of two flag sets.
    pub const fn or(self, other: Gfp) -> Gfp {
        Gfp(self.0 | other.0)
    }

    /// True if every bit of `other` is set in `self`.
    pub const fn contains(self, other: Gfp) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Why a pointer was rejected by `kfree`/`ksize`/`krealloc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreeError {
    /// The pointer lies in memory that is currently free: a double free (or
    /// a free of an already-coalesced block's old payload).
    DoubleFree,
    /// The pointer is inside a live allocation but not at its start.
    NotBlockStart,
    /// The pointer is outside the arena: this allocator never handed it out.
    Foreign,
}

/// Allocator counters. A gate can assert the error counters are zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemStats {
    /// Usable bytes currently allocated (sum of `ksize` of live blocks).
    pub in_use: usize,
    /// Highest `in_use` seen.
    pub peak: usize,
    /// Successful allocations (excluding `ZERO_SIZE_PTR`).
    pub allocs: u64,
    /// Successful frees.
    pub frees: u64,
    /// Allocations that returned `None`.
    pub failures: u64,
    /// Frees rejected as [`FreeError::DoubleFree`].
    pub double_frees: u64,
    /// Frees rejected as [`FreeError::NotBlockStart`] or [`FreeError::Foreign`].
    pub invalid_frees: u64,
}

const HDR: usize = 16;
const MIN_BLOCK: usize = 32;
const ALLOC_BIT: u64 = 1;

/// The allocator. Holds the arena as a raw pointer taken once from the
/// caller's `&mut [u8]`: handing out raw pointers and then re-borrowing the
/// slice for every header access would, under Rust's aliasing rules,
/// invalidate the pointers already given to drivers.
pub struct Heap<'a> {
    base: *mut u8,
    len: usize,
    stats: MemStats,
    _arena: PhantomData<&'a mut [u8]>,
}

const fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

impl<'a> Heap<'a> {
    /// Build a heap over `arena`. The start is aligned up to 16 bytes and the
    /// length truncated to a multiple of 16; an arena too small for one block
    /// yields a heap where every allocation fails.
    pub fn new(arena: &'a mut [u8]) -> Self {
        let start = arena.as_mut_ptr();
        let skip = align_up(start as usize, ARCH_KMALLOC_MINALIGN) - start as usize;
        let usable = arena.len().saturating_sub(skip) & !(ARCH_KMALLOC_MINALIGN - 1);
        // SAFETY: skip <= 15 and, when it exceeds len, usable is 0 and base is
        // never dereferenced; otherwise base is inside the arena.
        let base = if usable >= MIN_BLOCK { unsafe { start.add(skip) } } else { start };
        let mut h = Heap {
            base,
            len: if usable >= MIN_BLOCK { usable } else { 0 },
            stats: MemStats::default(),
            _arena: PhantomData,
        };
        if h.len != 0 {
            h.set_size(0, h.len, false);
            h.set_prev(0, 0);
        }
        h
    }

    /// Counters.
    pub fn stats(&self) -> MemStats {
        self.stats
    }

    /// Usable arena length in bytes (headers included).
    pub fn capacity(&self) -> usize {
        self.len
    }

    /// Largest single allocation that could succeed right now.
    pub fn largest_free(&self) -> usize {
        let mut best = 0;
        let mut o = 0;
        while o < self.len {
            let s = self.size(o);
            if !self.is_alloc(o) && s - HDR > best {
                best = s - HDR;
            }
            o += s;
        }
        best
    }

    fn rd(&self, off: usize) -> u64 {
        debug_assert!(off + 8 <= self.len && off.is_multiple_of(8));
        // SAFETY: off is a header offset inside the arena, 8-aligned because
        // base is 16-aligned and every block size is a multiple of 16.
        unsafe { (self.base.add(off) as *const u64).read() }
    }

    fn wr(&mut self, off: usize, v: u64) {
        debug_assert!(off + 8 <= self.len && off.is_multiple_of(8));
        // SAFETY: as in `rd`.
        unsafe { (self.base.add(off) as *mut u64).write(v) }
    }

    fn size(&self, o: usize) -> usize {
        (self.rd(o) & !(ALLOC_BIT | 0xe)) as usize
    }

    fn is_alloc(&self, o: usize) -> bool {
        self.rd(o) & ALLOC_BIT != 0
    }

    fn prev(&self, o: usize) -> usize {
        self.rd(o + 8) as usize
    }

    fn set_size(&mut self, o: usize, size: usize, alloc: bool) {
        self.wr(o, size as u64 | if alloc { ALLOC_BIT } else { 0 });
    }

    fn set_prev(&mut self, o: usize, prev: usize) {
        self.wr(o + 8, prev as u64);
    }

    /// Fix the back-link of the block following `o`, if there is one.
    fn relink_next(&mut self, o: usize) {
        let n = o + self.size(o);
        if n < self.len {
            let s = self.size(o);
            self.set_prev(n, s);
        }
    }

    fn payload(&self, o: usize) -> NonNull<u8> {
        // SAFETY: o + HDR is inside the arena for every block.
        unsafe { NonNull::new_unchecked(self.base.add(o + HDR)) }
    }

    /// Prove `ptr` is the payload of a live block by walking the list;
    /// returns the block offset. Never reads a header at `ptr` itself.
    fn find_live(&self, ptr: *mut u8) -> Result<usize, FreeError> {
        let addr = ptr as usize;
        let lo = self.base as usize;
        if self.len == 0 || addr < lo || addr >= lo + self.len {
            return Err(FreeError::Foreign);
        }
        let off = addr - lo;
        let mut o = 0;
        while o < self.len {
            let s = self.size(o);
            if off < o + s {
                let alloc = self.is_alloc(o);
                return match (alloc, off == o + HDR) {
                    (true, true) => Ok(o),
                    (true, false) => Err(FreeError::NotBlockStart),
                    (false, _) => Err(FreeError::DoubleFree),
                };
            }
            o += s;
        }
        Err(FreeError::Foreign)
    }

    fn record_free_error(&mut self, e: FreeError) -> FreeError {
        match e {
            FreeError::DoubleFree => self.stats.double_frees += 1,
            FreeError::NotBlockStart | FreeError::Foreign => self.stats.invalid_frees += 1,
        }
        e
    }

    fn account_alloc(&mut self, payload: usize) {
        self.stats.allocs += 1;
        self.stats.in_use += payload;
        if self.stats.in_use > self.stats.peak {
            self.stats.peak = self.stats.in_use;
        }
    }

    /// Bytes a request occupies including the header, or None on overflow.
    fn block_need(&self, size: usize) -> Option<usize> {
        if size > self.len {
            return None;
        }
        Some((align_up(size, ARCH_KMALLOC_MINALIGN) + HDR).max(MIN_BLOCK))
    }

    /// Shrink allocated block `o` to `need` bytes if the tail is big enough
    /// to stand alone as a free block; the tail is merged with a free
    /// successor so the "no two adjacent free blocks" invariant holds.
    fn split_tail(&mut self, o: usize, need: usize) {
        let s = self.size(o);
        if s - need < MIN_BLOCK {
            return;
        }
        self.set_size(o, need, true);
        let t = o + need;
        let mut tsize = s - need;
        let n = t + tsize;
        if n < self.len && !self.is_alloc(n) {
            tsize += self.size(n);
        }
        self.set_size(t, tsize, false);
        self.set_prev(t, need);
        self.relink_next(t);
    }

    /// `kmalloc`: 16-byte aligned memory, `None` on exhaustion.
    /// `size == 0` returns [`ZERO_SIZE_PTR`].
    pub fn kmalloc(&mut self, size: usize, gfp: Gfp) -> Option<NonNull<u8>> {
        self.kmalloc_aligned(size, ARCH_KMALLOC_MINALIGN, gfp)
    }

    /// `kzalloc`: `kmalloc` with `__GFP_ZERO`.
    pub fn kzalloc(&mut self, size: usize, gfp: Gfp) -> Option<NonNull<u8>> {
        self.kmalloc(size, gfp.or(Gfp::ZERO))
    }

    /// `kmalloc` with a power-of-two alignment (values below 16 are raised
    /// to 16). A non-power-of-two `align` fails and counts as a failure.
    pub fn kmalloc_aligned(&mut self, size: usize, align: usize, gfp: Gfp) -> Option<NonNull<u8>> {
        if size == 0 {
            return NonNull::new(ZERO_SIZE_PTR);
        }
        if !align.is_power_of_two() {
            self.stats.failures += 1;
            return None;
        }
        let align = align.max(ARCH_KMALLOC_MINALIGN);
        let need = match self.block_need(size) {
            Some(n) => n,
            None => {
                self.stats.failures += 1;
                return None;
            }
        };
        let mut o = 0;
        while o < self.len {
            let s = self.size(o);
            if !self.is_alloc(o) {
                let payload = self.base as usize + o + HDR;
                let mut gap = align_up(payload, align) - payload;
                // A leading gap must be able to stand alone as a free block.
                while gap != 0 && gap < MIN_BLOCK {
                    gap += align;
                }
                if gap + need <= s {
                    let b = if gap == 0 {
                        o
                    } else {
                        // Leading gap stays free; its predecessor is allocated
                        // (no adjacent free blocks), so no merge is needed.
                        self.set_size(o, gap, false);
                        let b = o + gap;
                        self.set_size(b, s - gap, false);
                        self.set_prev(b, gap);
                        self.relink_next(b);
                        b
                    };
                    let bs = self.size(b);
                    self.set_size(b, bs, true);
                    self.split_tail(b, need);
                    let usable = self.size(b) - HDR;
                    let p = self.payload(b);
                    if gfp.contains(Gfp::ZERO) {
                        // SAFETY: [p, p+usable) is this block's payload.
                        unsafe { p.as_ptr().write_bytes(0, usable) };
                    }
                    self.account_alloc(usable);
                    return Some(p);
                }
            }
            o += s;
        }
        self.stats.failures += 1;
        None
    }

    /// `kfree`. Null and [`ZERO_SIZE_PTR`] are accepted no-ops. A pointer
    /// this heap did not hand out (or already took back) is rejected,
    /// counted, and leaves the heap unchanged.
    pub fn kfree(&mut self, ptr: *mut u8) -> Result<(), FreeError> {
        if ptr.is_null() || ptr == ZERO_SIZE_PTR {
            return Ok(());
        }
        let o = self.find_live(ptr).map_err(|e| self.record_free_error(e))?;
        let s = self.size(o);
        self.stats.in_use -= s - HDR;
        self.stats.frees += 1;
        // SAFETY: the payload of a live block, about to become free.
        unsafe { self.base.add(o + HDR).write_bytes(POISON_FREE, s - HDR) };
        let mut start = o;
        let mut size = s;
        let n = o + s;
        if n < self.len && !self.is_alloc(n) {
            size += self.size(n);
        }
        if o != 0 {
            let p = o - self.prev(o);
            if !self.is_alloc(p) {
                start = p;
                size += self.size(p);
            }
        }
        self.set_size(start, size, false);
        self.relink_next(start);
        Ok(())
    }

    /// `ksize`: usable size of a live allocation (>= the requested size).
    /// Null and [`ZERO_SIZE_PTR`] give 0.
    pub fn ksize(&self, ptr: *mut u8) -> Result<usize, FreeError> {
        if ptr.is_null() || ptr == ZERO_SIZE_PTR {
            return Ok(0);
        }
        let o = self.find_live(ptr)?;
        Ok(self.size(o) - HDR)
    }

    /// `krealloc`. `Ok(None)` means out of memory and the old block is
    /// untouched; `Err` means `ptr` was not a live allocation (counted).
    /// Null / [`ZERO_SIZE_PTR`] behave as `kmalloc`; `new_size == 0` frees
    /// and returns [`ZERO_SIZE_PTR`]. With `__GFP_ZERO`, bytes past the old
    /// usable size are zeroed on growth. Alignment above 16 is not
    /// preserved when the block has to move.
    pub fn krealloc(
        &mut self,
        ptr: *mut u8,
        new_size: usize,
        gfp: Gfp,
    ) -> Result<Option<NonNull<u8>>, FreeError> {
        if ptr.is_null() || ptr == ZERO_SIZE_PTR {
            return Ok(self.kmalloc(new_size, gfp));
        }
        let o = self.find_live(ptr).map_err(|e| self.record_free_error(e))?;
        if new_size == 0 {
            self.kfree(ptr)?;
            return Ok(NonNull::new(ZERO_SIZE_PTR));
        }
        let old_usable = self.size(o) - HDR;
        if new_size <= old_usable {
            return Ok(NonNull::new(ptr));
        }
        let need = match self.block_need(new_size) {
            Some(n) => n,
            None => {
                self.stats.failures += 1;
                return Ok(None);
            }
        };
        // Grow in place by absorbing a free successor.
        let s = self.size(o);
        let n = o + s;
        if n < self.len && !self.is_alloc(n) && s + self.size(n) >= need {
            let merged = s + self.size(n);
            self.set_size(o, merged, true);
            self.relink_next(o);
            self.split_tail(o, need);
            let usable = self.size(o) - HDR;
            self.stats.in_use += usable - old_usable;
            if self.stats.in_use > self.stats.peak {
                self.stats.peak = self.stats.in_use;
            }
            if gfp.contains(Gfp::ZERO) {
                // SAFETY: the grown part of this live block's payload.
                // Written through the arena's own pointer, never the
                // caller's: `ptr` was only compared, never dereferenced.
                unsafe { self.base.add(o + HDR + old_usable).write_bytes(0, usable - old_usable) };
            }
            return Ok(NonNull::new(ptr));
        }
        let fresh = match self.kmalloc(new_size, gfp) {
            Some(p) => p,
            None => return Ok(None),
        };
        // SAFETY: two distinct live blocks of this arena (validated above);
        // old_usable <= the new block's usable size.
        unsafe { core::ptr::copy_nonoverlapping(self.base.add(o + HDR), fresh.as_ptr(), old_usable) };
        self.kfree(ptr)?;
        Ok(Some(fresh))
    }

    /// Walk the block list and check every invariant: sizes are multiples
    /// of 16 and at least the minimum, back-links match, no two free blocks
    /// are adjacent, the blocks tile the arena exactly, and `in_use` equals
    /// the live payload total. Cheap enough for a debug gate.
    pub fn verify(&self) -> bool {
        let mut o = 0;
        let mut prev_size = 0;
        let mut prev_free = false;
        let mut live = 0;
        while o < self.len {
            let s = self.size(o);
            if s < MIN_BLOCK || !s.is_multiple_of(ARCH_KMALLOC_MINALIGN) || o + s > self.len {
                return false;
            }
            if self.prev(o) != prev_size {
                return false;
            }
            let free = !self.is_alloc(o);
            if free && prev_free {
                return false;
            }
            if !free {
                live += s - HDR;
            }
            prev_free = free;
            prev_size = s;
            o += s;
        }
        o == self.len && live == self.stats.in_use
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(64))]
    struct Arena([u8; 4096]);

    fn arena() -> Box<Arena> {
        Box::new(Arena([0u8; 4096]))
    }

    #[test]
    fn alloc_is_aligned_and_usable() {
        let mut a = arena();
        let mut h = Heap::new(&mut a.0);
        assert_eq!(h.capacity(), 4096);
        let p = h.kmalloc(10, Gfp::KERNEL).unwrap();
        assert_eq!(p.as_ptr() as usize % 16, 0);
        assert_eq!(h.ksize(p.as_ptr()), Ok(16));
        unsafe { p.as_ptr().write_bytes(0xaa, 16) };
        assert!(h.verify());
        assert_eq!(h.stats().in_use, 16);
        h.kfree(p.as_ptr()).unwrap();
        assert_eq!(h.stats().in_use, 0);
        assert!(h.verify());
        assert_eq!(h.largest_free(), 4096 - HDR);
    }

    #[test]
    fn unaligned_arena_start_is_aligned_up() {
        let mut a = arena();
        let mut h = Heap::new(&mut a.0[3..]);
        // 4093 bytes from offset 3: skip 13, keep 4080.
        assert_eq!(h.capacity(), 4080);
        let p = h.kmalloc(1, Gfp::KERNEL).unwrap();
        assert_eq!(p.as_ptr() as usize % 16, 0);
        assert!(h.verify());
    }

    #[test]
    fn tiny_arena_fails_every_allocation() {
        let mut a = [0u8; 20];
        let mut h = Heap::new(&mut a);
        assert!(h.kmalloc(1, Gfp::KERNEL).is_none());
        assert_eq!(h.stats().failures, 1);
        assert_eq!(h.kfree(a_ptr()), Err(FreeError::Foreign));
    }

    fn a_ptr() -> *mut u8 {
        0x1000 as *mut u8
    }

    #[test]
    fn kzalloc_zeroes_reused_memory() {
        let mut a = arena();
        let mut h = Heap::new(&mut a.0);
        let p = h.kmalloc(64, Gfp::KERNEL).unwrap();
        unsafe { p.as_ptr().write_bytes(0xff, 64) };
        h.kfree(p.as_ptr()).unwrap();
        let q = h.kzalloc(64, Gfp::KERNEL).unwrap();
        assert_eq!(q, p, "first fit reuses the same block");
        let s = unsafe { core::slice::from_raw_parts(q.as_ptr(), 64) };
        assert!(s.iter().all(|&b| b == 0));
    }

    #[test]
    fn freed_memory_is_poisoned() {
        let mut a = arena();
        let mut h = Heap::new(&mut a.0);
        let p = h.kmalloc(64, Gfp::KERNEL).unwrap();
        let _keep = h.kmalloc(16, Gfp::KERNEL).unwrap();
        h.kfree(p.as_ptr()).unwrap();
        let s = unsafe { core::slice::from_raw_parts(p.as_ptr(), 64) };
        assert!(s.iter().all(|&b| b == POISON_FREE));
    }

    #[test]
    fn exhaustion_returns_none_and_counts() {
        let mut a = arena();
        let mut h = Heap::new(&mut a.0);
        let big = h.kmalloc(4096 - HDR, Gfp::KERNEL).unwrap();
        assert!(h.kmalloc(1, Gfp::KERNEL).is_none());
        assert!(h.kmalloc(usize::MAX, Gfp::KERNEL).is_none());
        assert_eq!(h.stats().failures, 2);
        h.kfree(big.as_ptr()).unwrap();
        assert!(h.kmalloc(4097, Gfp::KERNEL).is_none());
        assert_eq!(h.stats().failures, 3);
        assert!(h.verify());
    }

    #[test]
    fn coalescing_restores_one_free_block_in_any_order() {
        for order in [[0, 1, 2], [2, 1, 0], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1]] {
            let mut a = arena();
            let mut h = Heap::new(&mut a.0);
            let ps = [
                h.kmalloc(100, Gfp::KERNEL).unwrap(),
                h.kmalloc(200, Gfp::KERNEL).unwrap(),
                h.kmalloc(300, Gfp::KERNEL).unwrap(),
            ];
            for i in order {
                h.kfree(ps[i].as_ptr()).unwrap();
                assert!(h.verify(), "order {:?}", order);
            }
            assert_eq!(h.largest_free(), 4096 - HDR, "order {:?}", order);
            assert_eq!(h.stats().in_use, 0);
        }
    }

    #[test]
    fn first_fit_takes_the_lowest_hole() {
        let mut a = arena();
        let mut h = Heap::new(&mut a.0);
        let p0 = h.kmalloc(64, Gfp::KERNEL).unwrap();
        let _p1 = h.kmalloc(64, Gfp::KERNEL).unwrap();
        let p2 = h.kmalloc(64, Gfp::KERNEL).unwrap();
        let _p3 = h.kmalloc(64, Gfp::KERNEL).unwrap();
        h.kfree(p2.as_ptr()).unwrap();
        h.kfree(p0.as_ptr()).unwrap();
        assert_eq!(h.kmalloc(32, Gfp::KERNEL).unwrap(), p0);
    }

    #[test]
    fn double_free_is_detected_and_heap_unchanged() {
        let mut a = arena();
        let mut h = Heap::new(&mut a.0);
        let p = h.kmalloc(64, Gfp::KERNEL).unwrap();
        let q = h.kmalloc(64, Gfp::KERNEL).unwrap();
        h.kfree(p.as_ptr()).unwrap();
        let before = h.stats();
        assert_eq!(h.kfree(p.as_ptr()), Err(FreeError::DoubleFree));
        assert_eq!(h.stats().in_use, before.in_use);
        assert_eq!(h.stats().double_frees, 1);
        assert!(h.verify());
        // Canary: the heap still works after the detected bug.
        assert!(h.kmalloc(64, Gfp::KERNEL).is_some());
        assert_eq!(h.ksize(q.as_ptr()), Ok(64));
    }

    #[test]
    fn double_free_after_coalescing_is_still_detected() {
        let mut a = arena();
        let mut h = Heap::new(&mut a.0);
        let p = h.kmalloc(64, Gfp::KERNEL).unwrap();
        let q = h.kmalloc(64, Gfp::KERNEL).unwrap();
        h.kfree(p.as_ptr()).unwrap();
        h.kfree(q.as_ptr()).unwrap(); // q merges into p's free block
        assert_eq!(h.kfree(q.as_ptr()), Err(FreeError::DoubleFree));
        assert!(h.verify());
    }

    #[test]
    fn interior_and_foreign_pointers_are_rejected() {
        let mut a = arena();
        let mut h = Heap::new(&mut a.0);
        let p = h.kmalloc(64, Gfp::KERNEL).unwrap();
        let interior = unsafe { p.as_ptr().add(16) };
        assert_eq!(h.kfree(interior), Err(FreeError::NotBlockStart));
        assert_eq!(h.ksize(interior), Err(FreeError::NotBlockStart));
        let mut other = [0u8; 32];
        assert_eq!(h.kfree(other.as_mut_ptr()), Err(FreeError::Foreign));
        assert_eq!(h.stats().invalid_frees, 2);
        assert_eq!(h.stats().in_use, 64);
        assert!(h.verify());
        h.kfree(p.as_ptr()).unwrap();
    }

    #[test]
    fn zero_size_pointer_semantics() {
        let mut a = arena();
        let mut h = Heap::new(&mut a.0);
        let z = h.kmalloc(0, Gfp::KERNEL).unwrap();
        assert_eq!(z.as_ptr(), ZERO_SIZE_PTR);
        assert_eq!(h.kzalloc(0, Gfp::KERNEL).unwrap().as_ptr(), ZERO_SIZE_PTR);
        assert_eq!(h.stats().allocs, 0);
        assert_eq!(h.ksize(ZERO_SIZE_PTR), Ok(0));
        assert_eq!(h.kfree(ZERO_SIZE_PTR), Ok(()));
        assert_eq!(h.kfree(core::ptr::null_mut()), Ok(()));
        let r = h.krealloc(ZERO_SIZE_PTR, 32, Gfp::KERNEL).unwrap().unwrap();
        assert_eq!(h.ksize(r.as_ptr()), Ok(32));
        let z2 = h.krealloc(r.as_ptr(), 0, Gfp::KERNEL).unwrap().unwrap();
        assert_eq!(z2.as_ptr(), ZERO_SIZE_PTR);
        assert_eq!(h.stats().in_use, 0);
        assert!(h.verify());
    }

    #[test]
    fn aligned_allocation() {
        let mut a = arena();
        let mut h = Heap::new(&mut a.0);
        let _p = h.kmalloc(8, Gfp::KERNEL).unwrap();
        for align in [32usize, 64, 256, 1024] {
            let q = h.kmalloc_aligned(40, align, Gfp::KERNEL).unwrap();
            assert_eq!(q.as_ptr() as usize % align, 0, "align {}", align);
            assert!(h.verify());
            h.kfree(q.as_ptr()).unwrap();
            assert!(h.verify());
        }
        assert!(h.kmalloc_aligned(8, 48, Gfp::KERNEL).is_none());
        // Small alignments are raised to the minimum.
        let r = h.kmalloc_aligned(8, 4, Gfp::KERNEL).unwrap();
        assert_eq!(r.as_ptr() as usize % 16, 0);
    }

    #[test]
    fn krealloc_shrink_grow_in_place_and_move() {
        let mut a = arena();
        let mut h = Heap::new(&mut a.0);
        let p = h.kmalloc(64, Gfp::KERNEL).unwrap();
        for i in 0..64u8 {
            unsafe { p.as_ptr().add(i as usize).write(i) };
        }
        // Shrink: same pointer.
        assert_eq!(h.krealloc(p.as_ptr(), 10, Gfp::KERNEL), Ok(Some(p)));
        // Grow in place: successor is free.
        let g = h.krealloc(p.as_ptr(), 200, Gfp::KERNEL.or(Gfp::ZERO)).unwrap().unwrap();
        assert_eq!(g, p);
        assert_eq!(h.ksize(g.as_ptr()), Ok(208));
        let s = unsafe { core::slice::from_raw_parts(g.as_ptr(), 208) };
        assert!(s[..64].iter().enumerate().all(|(i, &b)| b == i as u8));
        assert!(s[64..].iter().all(|&b| b == 0));
        assert!(h.verify());
        // Block the successor, then grow: must move and copy.
        let wall = h.kmalloc(16, Gfp::KERNEL).unwrap();
        let m = h.krealloc(g.as_ptr(), 500, Gfp::KERNEL).unwrap().unwrap();
        assert_ne!(m, g);
        let s = unsafe { core::slice::from_raw_parts(m.as_ptr(), 64) };
        assert!(s.iter().enumerate().all(|(i, &b)| b == i as u8));
        assert_eq!(h.kfree(g.as_ptr()), Err(FreeError::DoubleFree));
        assert!(h.verify());
        h.kfree(wall.as_ptr()).unwrap();
        h.kfree(m.as_ptr()).unwrap();
        assert_eq!(h.stats().in_use, 0);
        assert!(h.verify());
    }

    #[test]
    fn krealloc_failure_keeps_the_old_block() {
        let mut a = arena();
        let mut h = Heap::new(&mut a.0);
        let p = h.kmalloc(64, Gfp::KERNEL).unwrap();
        let _wall = h.kmalloc(16, Gfp::KERNEL).unwrap();
        assert_eq!(h.krealloc(p.as_ptr(), 8000, Gfp::KERNEL), Ok(None));
        assert_eq!(h.ksize(p.as_ptr()), Ok(64));
        assert!(h.verify());
        let mut other = [0u8; 16];
        assert_eq!(h.krealloc(other.as_mut_ptr(), 8, Gfp::KERNEL), Err(FreeError::Foreign));
    }

    #[test]
    fn peak_tracks_high_water_mark() {
        let mut a = arena();
        let mut h = Heap::new(&mut a.0);
        let p = h.kmalloc(1000, Gfp::KERNEL).unwrap();
        let q = h.kmalloc(500, Gfp::KERNEL).unwrap();
        h.kfree(p.as_ptr()).unwrap();
        h.kfree(q.as_ptr()).unwrap();
        let s = h.stats();
        assert_eq!(s.in_use, 0);
        assert_eq!(s.peak, 1008 + 512);
        assert_eq!((s.allocs, s.frees), (2, 2));
    }

    #[test]
    fn randomized_churn_keeps_invariants() {
        let mut a = arena();
        let mut h = Heap::new(&mut a.0);
        let mut live: Vec<(NonNull<u8>, u8, usize)> = Vec::new();
        let mut seed = 0x1234_5678u32;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        for step in 0..4000 {
            let r = rnd();
            if r % 3 != 0 || live.is_empty() {
                let size = (r as usize >> 4) % 300 + 1;
                if let Some(p) = h.kmalloc(size, Gfp::KERNEL) {
                    let tag = step as u8;
                    unsafe { p.as_ptr().write_bytes(tag, size) };
                    live.push((p, tag, size));
                }
            } else {
                let i = (r as usize >> 8) % live.len();
                let (p, tag, size) = live.swap_remove(i);
                let s = unsafe { core::slice::from_raw_parts(p.as_ptr(), size) };
                assert!(s.iter().all(|&b| b == tag), "step {}: block overwritten", step);
                h.kfree(p.as_ptr()).unwrap();
            }
            assert!(h.verify(), "step {}", step);
        }
        for (p, _, _) in live {
            h.kfree(p.as_ptr()).unwrap();
        }
        assert_eq!(h.largest_free(), 4096 - HDR);
    }
}
