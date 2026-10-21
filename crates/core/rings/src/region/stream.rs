// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The byte ring: one producer, one consumer, a stream of bytes.
//!
//! The other region forms move items (a word, a request, a framed payload).
//! A POSIX pipe moves bytes, and a reader may take any prefix of what a
//! writer put in, so the indices here count **bytes**: `head - tail`
//! (wrapping `u32`) is the number of bytes in the ring, the capacity is a
//! power of two no larger than 2^31, and a side moves its index once per call
//! by however many bytes it copied. The header, the Dekker handshake and the
//! wake decisions are the ones of [`super::SpscRing`] (one definition, in
//! `mod.rs`); only the unit of an index step differs.
//!
//! # Layout
//!
//! The header of [`super::SpscRing`] (`RING_HEAD`, `RING_TAIL`,
//! `RING_CONS_WAIT`, `RING_PROD_WAIT`, one 64-byte line each, then
//! `RING_SLOTS`), and `cap` data bytes at [`super::RING_SLOTS`]. Byte `i` of
//! the stream is at `RING_SLOTS + (i & (cap - 1))`. The words of the header
//! that no ring protocol uses (the first 64 bytes of each line past the
//! index) are the owner's: `azos_bytepipe` keeps its end counts and its
//! sleep events there.
//!
//! No `ecall` here: the side that must enter the kernel is told so
//! ([`RingStep::DoneWake`], [`RingSleep::Wait`]).

use super::{
    ring_init, ring_len, ring_pop_release_n, ring_pop_reserve, ring_push_publish_n,
    ring_push_reserve, ring_word, RingStep, RING_CONS_WAIT, RING_HEAD, RING_PROD_WAIT, RING_SLOTS,
    RING_TAIL,
};
use core::sync::atomic::{fence, Ordering};

/// A view of one byte ring at `base` (a mapping at least
/// [`SpscStream::bytes`] long, 64-byte aligned).
#[derive(Clone, Copy, Debug)]
pub struct SpscStream {
    pub base: usize,
    /// Data bytes; a power of two.
    pub cap: u32,
}

impl SpscStream {
    /// Bytes a ring of `cap` data bytes occupies.
    pub const fn bytes(cap: u32) -> usize {
        RING_SLOTS + cap as usize
    }

    /// Zero the header. Called once, by the side that creates the region,
    /// before the other side maps it.
    pub fn init(&self) {
        ring_init(self.base)
    }

    /// Bytes in the ring now (a snapshot).
    pub fn len(&self) -> u32 {
        ring_len(self.base)
    }

    /// Is the ring empty now (a snapshot)?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes of room now (a snapshot; only the producer can only make it
    /// smaller, so for the producer it is a lower bound).
    pub fn free(&self) -> u32 {
        self.cap.saturating_sub(self.len())
    }

    /// Producer: append as many bytes of `src` as fit (all of them or the
    /// room left, whichever is less) and publish them with one head store.
    /// `(0, Blocked)` when the ring is full or `src` is empty.
    pub fn write(&self, src: &[u8]) -> (usize, RingStep) {
        // SAFETY: `at(pos)` addresses the data area, `len` bytes of it
        // (`write_by` never passes a span that crosses the end).
        self.write_by(src, |pos, s| unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), (self.base + RING_SLOTS + pos) as *mut u8, s.len())
        })
    }

    /// Consumer: take up to `dst.len()` of the oldest bytes and release them
    /// with one tail store. `(0, Blocked)` when the ring is empty or `dst`
    /// is empty.
    pub fn read(&self, dst: &mut [u8]) -> (usize, RingStep) {
        // SAFETY: as in `write`.
        self.read_by(dst, |pos, d| unsafe {
            core::ptr::copy_nonoverlapping((self.base + RING_SLOTS + pos) as *const u8, d.as_mut_ptr(), d.len())
        })
    }

    /// [`SpscStream::write`] for a region whose data pages are not one flat
    /// run (`scatter`: the frames of a region the kernel views through its
    /// direct map). The header is at `self.base`, the first frame's start.
    ///
    /// # Safety
    /// `scatter` covers the region this ring lives in (its first frame is at
    /// `self.base`, and the ring's [`SpscStream::bytes`] lie within it).
    pub unsafe fn write_scattered(&self, src: &[u8], scatter: &Scatter) -> (usize, RingStep) {
        // SAFETY: the contract; `write_by` keeps `pos + len <= cap`.
        self.write_by(src, |pos, s| unsafe { scatter.put(RING_SLOTS + pos, s) })
    }

    /// [`SpscStream::read`] for a scattered region; see [`SpscStream::write_scattered`].
    ///
    /// # Safety
    /// As [`SpscStream::write_scattered`].
    pub unsafe fn read_scattered(&self, dst: &mut [u8], scatter: &Scatter) -> (usize, RingStep) {
        // SAFETY: as in `write_scattered`.
        self.read_by(dst, |pos, d| unsafe { scatter.get(RING_SLOTS + pos, d) })
    }

    /// The producer's step with the copy left to `put(pos, bytes)`: `bytes`
    /// go to ring positions `[pos, pos + bytes.len())`, never across the end
    /// of the data area (a wrap is two calls).
    #[inline(always)]
    fn write_by(&self, src: &[u8], put: impl Fn(usize, &[u8])) -> (usize, RingStep) {
        let Some(h) = ring_push_reserve(self.base, self.cap) else { return (0, RingStep::Blocked) };
        let t = ring_word(self.base, RING_TAIL).load(Ordering::Acquire);
        let room = self.cap - h.wrapping_sub(t).min(self.cap);
        let n = (room as usize).min(src.len());
        if n == 0 {
            return (0, RingStep::Blocked);
        }
        let start = (h & (self.cap - 1)) as usize;
        let first = n.min(self.cap as usize - start);
        // Bytes [h, h + n) are producer-owned until the head store below
        // publishes them; both spans lie inside the data area.
        put(start, &src[..first]);
        if n > first {
            put(0, &src[first..n]);
        }
        (n, ring_push_publish_n(self.base, h, n as u32))
    }

    /// The consumer's step with the copy left to `get(pos, out)`; see
    /// [`SpscStream::write_by`].
    #[inline(always)]
    fn read_by(&self, dst: &mut [u8], get: impl Fn(usize, &mut [u8])) -> (usize, RingStep) {
        let Some(t) = ring_pop_reserve(self.base) else { return (0, RingStep::Blocked) };
        let h = ring_word(self.base, RING_HEAD).load(Ordering::Acquire);
        let avail = h.wrapping_sub(t).min(self.cap);
        let n = (avail as usize).min(dst.len());
        if n == 0 {
            return (0, RingStep::Blocked);
        }
        let start = (t & (self.cap - 1)) as usize;
        let first = n.min(self.cap as usize - start);
        // Bytes [t, t + n) were published by the producer's Release on head
        // and are consumer-owned until the tail store below.
        get(start, &mut dst[..first]);
        if n > first {
            get(0, &mut dst[first..n]);
        }
        (n, ring_pop_release_n(self.base, t, n as u32))
    }

    /// A consumer that is about to sleep on a condition of its own (not only
    /// "the ring is empty") says so: set the flag, then the fence. The caller
    /// re-checks its condition after this call and before it sleeps; the
    /// waker's half is a publishing
    /// [`SpscStream::write`] or [`SpscStream::read`]. The flag is **not** withdrawn by a woken
    /// sleeper: with more than one sleeper it would hide the others from the
    /// waker, which clears it itself.
    pub fn announce_consumer(&self) {
        ring_word(self.base, RING_CONS_WAIT).store(1, Ordering::Relaxed);
        fence(Ordering::SeqCst);
    }

    /// The producer's [`SpscStream::announce_consumer`].
    pub fn announce_producer(&self) {
        ring_word(self.base, RING_PROD_WAIT).store(1, Ordering::Relaxed);
        fence(Ordering::SeqCst);
    }
}

/// Most frames a [`Scatter`] holds (the pipe regions the kernel views are a
/// handful of pages: the default is five).
pub const SCATTER_MAX: usize = 16;

/// The frames of a region that is not one flat run, as the address of each
/// page's first byte (the kernel's direct map of a ring-3 region, whose
/// frames are one per page). Byte `off` of the region is
/// `frames[off / page] + off % page`.
#[derive(Clone, Copy, Debug)]
pub struct Scatter {
    page: usize,
    n: usize,
    frames: [usize; SCATTER_MAX],
}

impl Scatter {
    /// The frames at `frames` (each the start of `page` bytes, `page` a power
    /// of two). `None` for no frame, more than [`SCATTER_MAX`], a first frame
    /// that is not 64-byte aligned or a page size that is not a power of two.
    pub fn new(page: usize, frames: &[usize]) -> Option<Scatter> {
        if !page.is_power_of_two() || frames.is_empty() || frames.len() > SCATTER_MAX || frames[0] % 64 != 0 {
            return None;
        }
        let mut f = [0usize; SCATTER_MAX];
        f[..frames.len()].copy_from_slice(frames);
        Some(Scatter { page, n: frames.len(), frames: f })
    }

    /// The first frame's start: where the header is.
    pub fn first(&self) -> usize {
        self.frames[0]
    }

    /// Bytes the frames hold.
    pub fn bytes(&self) -> usize {
        self.page * self.n
    }

    /// Copy `src` to region offset `off`, page by page. Bytes past the last
    /// frame are not written.
    ///
    /// # Safety
    /// Every frame is valid for `page` writable bytes and the span is not
    /// used by another writer.
    unsafe fn put(&self, mut off: usize, mut src: &[u8]) {
        while !src.is_empty() {
            let Some(&frame) = self.frames[..self.n].get(off / self.page) else { return };
            let at = off % self.page;
            let k = src.len().min(self.page - at);
            // SAFETY: the contract; `at + k <= page`.
            unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), (frame + at) as *mut u8, k) };
            src = &src[k..];
            off += k;
        }
    }

    /// Copy region offset `off` into `dst`, page by page; the mirror of `put`.
    ///
    /// # Safety
    /// Every frame is valid for `page` readable bytes.
    unsafe fn get(&self, mut off: usize, mut dst: &mut [u8]) {
        while !dst.is_empty() {
            let Some(&frame) = self.frames[..self.n].get(off / self.page) else { return };
            let at = off % self.page;
            let k = dst.len().min(self.page - at);
            // SAFETY: the contract; `at + k <= page`.
            unsafe { core::ptr::copy_nonoverlapping((frame + at) as *const u8, dst.as_mut_ptr(), k) };
            let (_, rest) = dst.split_at_mut(k);
            dst = rest;
            off += k;
        }
    }
}
