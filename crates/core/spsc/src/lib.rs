// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Single-producer/single-consumer rings in one shared-memory region, with a
//! notify doorbell that rings only when the other side said it may be asleep.
//!
//! **Both sides compile this crate, so the layout is a contract.** Until wave
//! 11 the ring lived in `azos_libsys` and both ends were ring-3 tasks.
//! SHMRING (wave 11) adds a KERNEL producer — camera frames and LiDAR scans
//! published into a `Cap<Shm>` region a ring-3 consumer maps — so the header
//! offsets, the slot formats and the wake decisions moved here, where the
//! kernel's `azos_ipc::stream_ring` and libsys (which re-exports every
//! item, so `azos_libsys::SpscRing` still resolves) both use them.
//!
//! Three slot forms share one index protocol:
//! * [`SpscRing`] — one `u64` per slot (wave 6).
//! * [`SpscSlots`] — `W` words per slot (a 64-byte driver request).
//! * [`SpscBytes`] — fixed-size byte slots carrying a variable-length payload
//!   behind a [`SlotInfo`] header (frames, scans), produced by a
//!   [`BytesProducer`] that keeps its own head and never blocks.
//!
//! No `ecall` here: every decision is pure, and the side that must enter the
//! kernel is told so (`RingStep::DoneWake`, `RingSleep::Wait`).

#![no_std]

// ---------------------------------------------------------------------------
// SPSC ring over shared memory (wave 6, rung 3)
// ---------------------------------------------------------------------------
//
// One producer task, one consumer task, one shared-memory region both have
// mapped (`SYS_SHM_MAP_TYPED`). The two indices are free-running `u32`s, so
// `head - tail` (wrapping) is the fill level and the capacity must be a power
// of two no larger than 2^31.
//
// **No kernel entry while the ring is neither empty nor full.** The only
// syscalls are `SYS_NOTIFY_WAIT` when a side must sleep (consumer on empty,
// producer on full) and `SYS_NOTIFY_WAKE` when the OTHER side has said it
// may be sleeping (its `*_wait` flag). Both decisions are made here, in pure
// code the host suite drives; `lib.rs` only issues the calls these functions
// ask for.
//
// **Lost wakeups** are closed twice. In ring 3, Dekker-style: a sleeper
// stores its flag, fences, re-reads the index; a waker stores the index,
// fences, reads the flag — at least one of the two sees the other. In the
// kernel, `SYS_NOTIFY_WAIT` compares the index word with the value the
// sleeper last saw under the same lock `SYS_NOTIFY_WAKE` takes, so a wake
// that raced the flag still makes the wait return at once.

/// Header layout, one field per 64-byte line so the two sides do not share one.
pub const RING_HEAD: usize = 0;
pub const RING_TAIL: usize = 64;
pub const RING_CONS_WAIT: usize = 128;
pub const RING_PROD_WAIT: usize = 192;
pub const RING_SLOTS: usize = 256;

/// A view of one ring at `base` (a user address inside a shared mapping).
#[derive(Clone, Copy)]
pub struct SpscRing {
    pub base: usize,
    /// Slots (u64 each); a power of two.
    pub cap: u32,
}

/// What the side that just moved an index must do next.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RingStep {
    /// Done, no kernel entry.
    Done,
    /// Done, and the other side announced it may be asleep: issue
    /// `SYS_NOTIFY_WAKE` on `addr` (the index word it waits on).
    DoneWake { addr: usize },
    /// Could not move (full for a push, empty for a pop).
    Blocked,
}

/// What a side that found the ring blocked must do after announcing itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RingSleep {
    /// The index moved while announcing: retry, no kernel entry.
    Retry,
    /// Sleep: `SYS_NOTIFY_WAIT(addr, expected)`.
    Wait { addr: usize, expected: u32 },
}

// The index protocol, shared by every slot width. A ring is its header at
// `base` (the four words above) and `cap` slots of `slot_bytes` after it; the
// functions below move the indices and the flags and leave the slot copy to
// the caller, between "reserve" and "publish", so the Dekker protocol exists
// once whatever a slot holds.

#[inline(always)]
pub(crate) fn ring_word(base: usize, off: usize) -> &'static core::sync::atomic::AtomicU32 {
    // SAFETY: `base` is the start of a mapping at least `bytes(cap)` long,
    // 64-byte aligned (the constructor's contract), shared with exactly one
    // other task that uses the same layout.
    unsafe { &*((base + off) as *const core::sync::atomic::AtomicU32) }
}

pub(crate) fn ring_init(base: usize) {
    use core::sync::atomic::Ordering::Relaxed;
    for off in [RING_HEAD, RING_TAIL, RING_CONS_WAIT, RING_PROD_WAIT] {
        ring_word(base, off).store(0, Relaxed);
    }
}

pub(crate) fn ring_len(base: usize) -> u32 {
    use core::sync::atomic::Ordering::Acquire;
    ring_word(base, RING_HEAD).load(Acquire).wrapping_sub(ring_word(base, RING_TAIL).load(Acquire))
}

/// Producer: the index to fill, or `None` when the ring is full.
#[inline(always)]
pub(crate) fn ring_push_reserve(base: usize, cap: u32) -> Option<u32> {
    use core::sync::atomic::Ordering::*;
    let h = ring_word(base, RING_HEAD).load(Relaxed);
    let t = ring_word(base, RING_TAIL).load(Acquire);
    if h.wrapping_sub(t) >= cap { None } else { Some(h) }
}

/// Producer: slot `h` is written; publish it and say whether to wake.
#[inline(always)]
pub(crate) fn ring_push_publish(base: usize, h: u32) -> RingStep {
    use core::sync::atomic::{fence, Ordering::*};
    ring_word(base, RING_HEAD).store(h.wrapping_add(1), Release);
    // Dekker: the head store above before the flag load below.
    fence(SeqCst);
    // A swap, not load-then-store: a plain `store(0)` landing late could
    // erase the flag of the consumer's NEXT sleep, and that sleeper would
    // then miss every wake until its timeout. The load first keeps the
    // common case (nobody asleep) free of an atomic read-modify-write.
    let f = ring_word(base, RING_CONS_WAIT);
    if f.load(Relaxed) != 0 && f.swap(0, AcqRel) != 0 {
        return RingStep::DoneWake { addr: base + RING_HEAD };
    }
    RingStep::Done
}

/// Consumer: the index to read, or `None` when the ring is empty.
#[inline(always)]
pub(crate) fn ring_pop_reserve(base: usize) -> Option<u32> {
    use core::sync::atomic::Ordering::*;
    let t = ring_word(base, RING_TAIL).load(Relaxed);
    // Acquire: pairs with the producer's Release on head, so slot `t` is
    // fully written before it is read.
    let h = ring_word(base, RING_HEAD).load(Acquire);
    if h == t { None } else { Some(t) }
}

/// Consumer: slot `t` is read; release it and say whether to wake.
#[inline(always)]
pub(crate) fn ring_pop_release(base: usize, t: u32) -> RingStep {
    use core::sync::atomic::{fence, Ordering::*};
    ring_word(base, RING_TAIL).store(t.wrapping_add(1), Release);
    fence(SeqCst);
    let f = ring_word(base, RING_PROD_WAIT);
    if f.load(Relaxed) != 0 && f.swap(0, AcqRel) != 0 {
        return RingStep::DoneWake { addr: base + RING_TAIL };
    }
    RingStep::Done
}

pub(crate) fn ring_consumer_sleep(base: usize) -> RingSleep {
    use core::sync::atomic::{fence, Ordering::*};
    let t = ring_word(base, RING_TAIL).load(Relaxed);
    ring_word(base, RING_CONS_WAIT).store(1, Relaxed);
    fence(SeqCst);
    let h = ring_word(base, RING_HEAD).load(Acquire);
    if h != t {
        ring_word(base, RING_CONS_WAIT).store(0, Relaxed);
        return RingSleep::Retry;
    }
    RingSleep::Wait { addr: base + RING_HEAD, expected: h }
}

pub(crate) fn ring_producer_sleep(base: usize, cap: u32) -> RingSleep {
    use core::sync::atomic::{fence, Ordering::*};
    let h = ring_word(base, RING_HEAD).load(Relaxed);
    ring_word(base, RING_PROD_WAIT).store(1, Relaxed);
    fence(SeqCst);
    let t = ring_word(base, RING_TAIL).load(Acquire);
    if h.wrapping_sub(t) < cap {
        ring_word(base, RING_PROD_WAIT).store(0, Relaxed);
        return RingSleep::Retry;
    }
    RingSleep::Wait { addr: base + RING_TAIL, expected: t }
}

impl SpscRing {
    /// Bytes a ring of `cap` slots occupies.
    pub const fn bytes(cap: u32) -> usize { RING_SLOTS + cap as usize * 8 }

    #[inline(always)]
    fn slot(&self, i: u32) -> *mut u64 {
        (self.base + RING_SLOTS + ((i & (self.cap - 1)) as usize) * 8) as *mut u64
    }

    /// Zero the header. Called once, by the side that creates the region,
    /// before the other side maps it.
    pub fn init(&self) { ring_init(self.base) }

    /// Items in the ring now (a snapshot).
    pub fn len(&self) -> u32 { ring_len(self.base) }

    /// Producer: append `v` if there is room.
    #[inline(always)]
    pub fn try_push(&self, v: u64) -> RingStep {
        let Some(h) = ring_push_reserve(self.base, self.cap) else { return RingStep::Blocked };
        // SAFETY: slot `h` is producer-owned until `head` passes it.
        unsafe { core::ptr::write_volatile(self.slot(h), v) };
        ring_push_publish(self.base, h)
    }

    /// Consumer: take the oldest item if there is one.
    #[inline(always)]
    pub fn try_pop(&self) -> (RingStep, u64) {
        let Some(t) = ring_pop_reserve(self.base) else { return (RingStep::Blocked, 0) };
        // SAFETY: slot `t` was published by the producer's Release on head.
        let v = unsafe { core::ptr::read_volatile(self.slot(t)) };
        (ring_pop_release(self.base, t), v)
    }

    /// Consumer found the ring empty: announce, re-check, and say whether to sleep.
    pub fn consumer_sleep(&self) -> RingSleep { ring_consumer_sleep(self.base) }

    /// Producer found the ring full: announce, re-check, and say whether to sleep.
    pub fn producer_sleep(&self) -> RingSleep { ring_producer_sleep(self.base, self.cap) }

    /// The consumer is awake again (its wait returned, for whatever reason):
    /// withdraw its announcement so the producer does not pay a wake for a
    /// sleeper that is not there.
    pub fn consumer_woke(&self) {
        ring_word(self.base, RING_CONS_WAIT).store(0, core::sync::atomic::Ordering::Relaxed);
    }

    /// The producer is awake again; see [`SpscRing::consumer_woke`].
    pub fn producer_woke(&self) {
        ring_word(self.base, RING_PROD_WAIT).store(0, core::sync::atomic::Ordering::Relaxed);
    }
}

/// [`SpscRing`] with `W`-word slots: the same header, the same index protocol
/// and the same wake decisions, for a request that does not fit in one `u64`
/// (a driver request's 64-byte payload is `SpscSlots<8>`).
///
/// A slot is copied as `W` aligned words, so `base` must be 8-byte aligned
/// (it is 64-byte aligned by the header's contract already).
#[derive(Clone, Copy)]
pub struct SpscSlots<const W: usize> {
    pub base: usize,
    /// Slots (`W` words each); a power of two.
    pub cap: u32,
}

impl<const W: usize> SpscSlots<W> {
    /// Bytes a ring of `cap` slots occupies.
    pub const fn bytes(cap: u32) -> usize { RING_SLOTS + cap as usize * W * 8 }

    #[inline(always)]
    fn slot(&self, i: u32) -> *mut [u64; W] {
        (self.base + RING_SLOTS + ((i & (self.cap - 1)) as usize) * W * 8) as *mut [u64; W]
    }

    /// Zero the header; see [`SpscRing::init`].
    pub fn init(&self) { ring_init(self.base) }

    /// Items in the ring now (a snapshot).
    pub fn len(&self) -> u32 { ring_len(self.base) }

    /// Producer: append `item` if there is room.
    #[inline(always)]
    pub fn try_push(&self, item: &[u64; W]) -> RingStep {
        let Some(h) = ring_push_reserve(self.base, self.cap) else { return RingStep::Blocked };
        // SAFETY: slot `h` is producer-owned until `head` passes it; the
        // Release on head in `ring_push_publish` orders this copy before it.
        // Word by word: a volatile store of a whole array may be lowered to a
        // byte-wise `memcpy` call.
        let s = self.slot(h) as *mut u64;
        for (i, w) in item.iter().enumerate() {
            unsafe { core::ptr::write_volatile(s.add(i), *w) };
        }
        ring_push_publish(self.base, h)
    }

    /// Consumer: take the oldest item into `out` if there is one.
    #[inline(always)]
    pub fn try_pop(&self, out: &mut [u64; W]) -> RingStep {
        let Some(t) = ring_pop_reserve(self.base) else { return RingStep::Blocked };
        // SAFETY: slot `t` was published by the producer's Release on head.
        let s = self.slot(t) as *const u64;
        for (i, w) in out.iter_mut().enumerate() {
            *w = unsafe { core::ptr::read_volatile(s.add(i)) };
        }
        ring_pop_release(self.base, t)
    }

    /// See [`SpscRing::consumer_sleep`].
    pub fn consumer_sleep(&self) -> RingSleep { ring_consumer_sleep(self.base) }

    /// See [`SpscRing::producer_sleep`].
    pub fn producer_sleep(&self) -> RingSleep { ring_producer_sleep(self.base, self.cap) }

    /// See [`SpscRing::consumer_woke`].
    pub fn consumer_woke(&self) {
        ring_word(self.base, RING_CONS_WAIT).store(0, core::sync::atomic::Ordering::Relaxed);
    }

    /// See [`SpscRing::producer_woke`].
    pub fn producer_woke(&self) {
        ring_word(self.base, RING_PROD_WAIT).store(0, core::sync::atomic::Ordering::Relaxed);
    }
}

mod bytes;
pub use bytes::*;
