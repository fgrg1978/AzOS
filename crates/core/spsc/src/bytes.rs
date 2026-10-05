// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Byte-slot rings: fixed-size slots, variable-length payloads (wave 11,
//! SHMRING). The stream form a kernel producer publishes camera frames and
//! LiDAR scans into.
//!
//! # Layout
//!
//! The ring header of [`crate::SpscRing`] (head, tail, the two wait flags,
//! one 64-byte line each), plus, in the head's line (producer written):
//! [`RING_DROPS`], [`RING_WAKES`], and the geometry ([`RING_GEOM_CAP`],
//! [`RING_GEOM_SLOT_BYTES`]) a consumer builds its view from. Slot `i` starts at `RING_SLOTS + (i & (cap - 1)) * slot_bytes`
//! and holds a [`SlotInfo`] ([`SLOT_HDR_BYTES`]: `len` u32, `seq` u32,
//! `acq_ns` u64, little-endian as the machine stores them) and then `len`
//! payload bytes.
//!
//! # Drop policy: the NEWEST item is dropped when the ring is full
//!
//! The producer never blocks and never waits for the consumer. A push into a
//! full ring is refused, counted in [`RING_DROPS`], and the item's `seq` is
//! consumed, so the consumer sees the gap. Dropping the OLDEST instead would
//! need the producer to advance the consumer's tail, which in an SPSC ring
//! races the consumer reading that very slot: it needs a lock or a CAS
//! protocol on the consumer's index, i.e. the consumer could make the
//! producer retry — the property this ring exists to rule out. A consumer
//! that drains in batches gets the newest data again from its next drain on.
//!
//! # Trust boundary (the producer is the kernel, the consumer is ring 3)
//!
//! The consumer maps the region read-write: it must store its tail and its
//! wait flag. Everything it can write is therefore untrusted by the
//! producer, and [`BytesProducer`] is written so that a hostile or broken
//! consumer can only damage its own stream:
//! * the head lives in the producer ([`BytesProducer`]'s own field) and is
//!   only ever *stored* to the shared word, never read back from it;
//! * the tail is read as an untrusted number: `head - tail` (wrapping) at or
//!   above `cap` means "full", whatever produced it — a garbage tail makes
//!   the producer drop, never write outside a slot;
//! * every slot address is `RING_SLOTS + (index & (cap - 1)) * slot_bytes`,
//!   with `cap` and `slot_bytes` held by the producer, so it is inside the
//!   region by construction, and a payload is clamped to the slot;
//! * nothing the producer reads from the region is used as an address,
//!   length or count for any memory outside it.
//!
//! Under the owner's decision of 2026-10-03 (wave 11), holding the stream's
//! `Cap<Shm>` IS the authority to read it: no per-frame capability check
//! runs, unlike `SYS_SENSOR_READ_TYPED`, which checks its `Cap<Sensor>` on
//! every call. The check happens once, when the capability is granted.

use crate::{
    ring_consumer_sleep, ring_init, ring_len, ring_pop_release, ring_pop_reserve,
    ring_producer_sleep, ring_push_publish, ring_word, RingSleep, RingStep, RING_CONS_WAIT,
    RING_PROD_WAIT, RING_SLOTS, RING_TAIL,
};
use core::sync::atomic::Ordering;

/// Items the producer refused because the ring was full (u32, in the head's
/// line, producer written).
pub const RING_DROPS: usize = 8;
/// Doorbells the producer has asked for (u32, head's line, producer
/// written): what a consumer reads to see the suppression work.
pub const RING_WAKES: usize = 12;
/// The ring's geometry, written by [`BytesProducer::new`] so a consumer that
/// only has the mapping can build its view ([`SpscBytes::from_header`]):
/// slots (u32) and bytes per slot (u32).
pub const RING_GEOM_CAP: usize = 16;
/// See [`RING_GEOM_CAP`].
pub const RING_GEOM_SLOT_BYTES: usize = 20;
/// Bytes of [`SlotInfo`] at the start of every byte slot.
pub const SLOT_HDR_BYTES: usize = 16;

/// The header of one byte slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlotInfo {
    /// Payload bytes the producer wrote (at most the slot's payload room).
    pub len: u32,
    /// The producer's sequence number: consecutive unless items were dropped.
    pub seq: u32,
    /// When the item was acquired (the producer's clock; 0 = unknown).
    pub acq_ns: u64,
}

/// A view of one byte-slot ring at `base` (a mapping at least
/// [`SpscBytes::bytes`] long, 64-byte aligned).
#[derive(Clone, Copy, Debug)]
pub struct SpscBytes {
    pub base: usize,
    /// Slots; a power of two.
    pub cap: u32,
    /// Bytes per slot, header included; a multiple of 8.
    pub slot_bytes: u32,
}

impl SpscBytes {
    /// Bytes a ring of `cap` slots of `slot_bytes` occupies.
    pub const fn bytes(cap: u32, slot_bytes: u32) -> usize {
        RING_SLOTS + cap as usize * slot_bytes as usize
    }

    /// Payload room in one slot.
    pub const fn payload_max(&self) -> usize { self.slot_bytes as usize - SLOT_HDR_BYTES }

    #[inline(always)]
    fn slot(&self, i: u32) -> usize {
        self.base + RING_SLOTS + ((i & (self.cap - 1)) as usize) * self.slot_bytes as usize
    }

    /// Zero the header (drop and wake counts included) and describe the
    /// geometry in it ([`RING_GEOM_CAP`]).
    pub fn init(&self) {
        ring_init(self.base);
        for off in [RING_DROPS, RING_WAKES] {
            ring_word(self.base, off).store(0, Ordering::Relaxed);
        }
        ring_word(self.base, RING_GEOM_CAP).store(self.cap, Ordering::Relaxed);
        ring_word(self.base, RING_GEOM_SLOT_BYTES).store(self.slot_bytes, Ordering::Release);
    }

    /// Items in the ring now (a snapshot).
    pub fn len(&self) -> u32 { ring_len(self.base) }

    /// Is the ring empty now (a snapshot)?
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// The view a producer described in the header at `base`, if it is a
    /// sane ring that fits in `mapped` bytes: `cap` a power of two, slots a
    /// multiple of 8 bytes and larger than their header. The consumer's
    /// constructor: it needs nothing but the mapping.
    pub fn from_header(base: usize, mapped: usize) -> Option<SpscBytes> {
        if mapped < RING_SLOTS {
            return None;
        }
        let cap = ring_word(base, RING_GEOM_CAP).load(Ordering::Acquire);
        let slot_bytes = ring_word(base, RING_GEOM_SLOT_BYTES).load(Ordering::Acquire);
        let ok = cap.is_power_of_two()
            && slot_bytes % 8 == 0
            && slot_bytes as usize > SLOT_HDR_BYTES
            && (cap as u64) * (slot_bytes as u64) + RING_SLOTS as u64 <= mapped as u64;
        ok.then_some(SpscBytes { base, cap, slot_bytes })
    }

    /// Doorbells the producer has asked for so far ([`RING_WAKES`]).
    pub fn wakes(&self) -> u32 { ring_word(self.base, RING_WAKES).load(Ordering::Relaxed) }

    /// Items the producer has dropped since [`SpscBytes::init`].
    pub fn drops(&self) -> u32 { ring_word(self.base, RING_DROPS).load(Ordering::Relaxed) }

    /// Consumer: copy the oldest item's payload into `out` (truncated to
    /// `out`'s length) and release its slot. `RingStep::Blocked` when empty.
    pub fn try_pop(&self, out: &mut [u8]) -> (RingStep, SlotInfo) {
        let Some(t) = ring_pop_reserve(self.base) else { return (RingStep::Blocked, SlotInfo::default()) };
        let s = self.slot(t);
        // SAFETY: slot `t` was published by the producer's Release on head
        // and is consumer-owned until the tail passes it.
        let info = unsafe {
            SlotInfo {
                len: core::ptr::read_volatile(s as *const u32),
                seq: core::ptr::read_volatile((s + 4) as *const u32),
                acq_ns: core::ptr::read_volatile((s + 8) as *const u64),
            }
        };
        let n = (info.len as usize).min(self.payload_max()).min(out.len());
        // SAFETY: `n` is within the slot's payload room and `out`.
        unsafe { core::ptr::copy_nonoverlapping((s + SLOT_HDR_BYTES) as *const u8, out.as_mut_ptr(), n) };
        (ring_pop_release(self.base, t), info)
    }

    /// Consumer found the ring empty: see [`crate::SpscRing::consumer_sleep`].
    pub fn consumer_sleep(&self) -> RingSleep { ring_consumer_sleep(self.base) }

    /// See [`crate::SpscRing::consumer_woke`].
    pub fn consumer_woke(&self) {
        ring_word(self.base, RING_CONS_WAIT).store(0, Ordering::Relaxed);
    }
}

/// What one [`BytesProducer::push_with`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Publish {
    /// Published; the consumer is awake.
    Done,
    /// Published, and the consumer announced it may be asleep: ring the
    /// doorbell on the head word ([`crate::RING_HEAD`], offset 0 of the ring).
    Wake,
    /// The ring was full: the item was dropped (drop-newest, see the module
    /// doc) and counted.
    Dropped,
}

/// The producing side of a [`SpscBytes`] ring, holding its own head, its
/// sequence number and its drop count: nothing it reads from the shared
/// region decides an address (module doc, "Trust boundary").
#[derive(Debug)]
pub struct BytesProducer {
    ring: SpscBytes,
    head: u32,
    seq: u32,
    drops: u32,
    wakes: u32,
}

impl BytesProducer {
    /// Take over `ring` and reset it: header zeroed, head and counts at 0.
    pub fn new(ring: SpscBytes) -> Self {
        ring.init();
        BytesProducer { ring, head: 0, seq: 0, drops: 0, wakes: 0 }
    }

    /// The ring this producer writes.
    pub fn ring(&self) -> &SpscBytes { &self.ring }

    /// Items dropped so far (the value stored at [`RING_DROPS`]).
    pub fn drops(&self) -> u32 { self.drops }

    /// Doorbells asked for so far ([`Publish::Wake`] answers).
    pub fn wakes(&self) -> u32 { self.wakes }

    /// Items published or dropped so far (the next `seq`).
    pub fn seq(&self) -> u32 { self.seq }

    /// Publish one item: `fill(dst, room)` writes at most `room` payload
    /// bytes at `dst` (inside the slot) and returns how many it wrote. Never
    /// blocks: a full ring drops this item (`Publish::Dropped`, `fill` not
    /// called).
    pub fn push_with(&mut self, acq_ns: u64, fill: impl FnOnce(*mut u8, usize) -> usize) -> Publish {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        // The tail is the consumer's word: untrusted. Anything at or past
        // `cap` ahead of OUR head — a full ring or garbage — is "full".
        let tail = ring_word(self.ring.base, RING_TAIL).load(Ordering::Acquire);
        if self.head.wrapping_sub(tail) >= self.ring.cap {
            self.drops = self.drops.wrapping_add(1);
            ring_word(self.ring.base, RING_DROPS).store(self.drops, Ordering::Relaxed);
            return Publish::Dropped;
        }
        let s = self.ring.slot(self.head);
        let room = self.ring.payload_max();
        let len = fill((s + SLOT_HDR_BYTES) as *mut u8, room).min(room);
        // SAFETY: the slot lies inside the region (index masked by our own
        // `cap`, our own `slot_bytes`) and is producer-owned until the head
        // store below publishes it.
        unsafe {
            core::ptr::write_volatile(s as *mut u32, len as u32);
            core::ptr::write_volatile((s + 4) as *mut u32, seq);
            core::ptr::write_volatile((s + 8) as *mut u64, acq_ns);
        }
        let h = self.head;
        self.head = h.wrapping_add(1);
        match ring_push_publish(self.ring.base, h) {
            RingStep::DoneWake { .. } => {
                self.wakes = self.wakes.wrapping_add(1);
                ring_word(self.ring.base, RING_WAKES).store(self.wakes, Ordering::Relaxed);
                Publish::Wake
            }
            _ => Publish::Done,
        }
    }

    /// Is the ring full now (from this producer's head and the consumer's
    /// tail)? A producer that may wait — a ring-3 one, never the kernel —
    /// checks this and sleeps ([`BytesProducer::producer_sleep`]) rather
    /// than push into a drop.
    pub fn is_full(&self) -> bool {
        let tail = ring_word(self.ring.base, RING_TAIL).load(Ordering::Acquire);
        self.head.wrapping_sub(tail) >= self.ring.cap
    }

    /// A waiting producer found the ring full: announce, re-check, and say
    /// whether to sleep (on the tail word), as [`crate::SpscRing::producer_sleep`].
    /// The consumer's pop then answers `RingStep::DoneWake` on the tail.
    pub fn producer_sleep(&self) -> RingSleep { ring_producer_sleep(self.ring.base, self.ring.cap) }

    /// The producer is awake again; see [`crate::SpscRing::producer_woke`].
    pub fn producer_woke(&self) {
        ring_word(self.ring.base, RING_PROD_WAIT).store(0, Ordering::Relaxed);
    }

    /// [`BytesProducer::push_with`] copying `src` (truncated to the slot).
    pub fn push(&mut self, acq_ns: u64, src: &[u8]) -> Publish {
        self.push_with(acq_ns, |dst, room| {
            let n = src.len().min(room);
            // SAFETY: `dst` has `room` bytes inside the slot.
            unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, n) };
            n
        })
    }
}
