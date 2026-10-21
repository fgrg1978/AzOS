// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! [`Queue`]: SPSC, backpressured, every item consumed exactly once.
//!
//! A `Queue` is the in-process instance of the [`crate::region`] ring: its
//! fields are laid out exactly like a region ring (one index per 64-byte line,
//! the slots at [`RING_SLOTS`]) and every index and wake decision is the
//! region's own (`ring_push_reserve`/`ring_push_publish`/`ring_pop_reserve`/
//! `ring_pop_commit`), called with the queue's address as the ring base. There
//! is no second SPSC protocol in this crate: a change to the Dekker handshake
//! lands in `region` and both forms follow. What a `Queue` adds is a typed slot
//! (`T: Copy`, capacity a const generic), the full policy and the claim flags.

use crate::region::{
    ring_consumer_sleep, ring_len, ring_pop_commit, ring_pop_reserve, ring_push_publish, ring_push_reserve,
    ring_word, RingSleep, RingStep, RING_CONS_WAIT, RING_HEAD, RING_PROD_WAIT, RING_SLOTS, RING_TAIL,
};
use crate::{Doorbell, Pad, CLAIM_CONSUMER, CLAIM_PRODUCER};
use core::cell::UnsafeCell;
use core::mem::{offset_of, MaybeUninit};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// What the producer meets when the queue is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Full {
    /// The item comes back to the caller, who blocks or retries.
    Backpressure,
    /// The item is dropped and counted ([`Queue::dropped`]).
    DropNewest,
}

/// What [`Producer::push`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Push<T> {
    Pushed,
    /// `Backpressure` and no room: the item is handed back.
    Full(T),
    /// `DropNewest` and no room: the item was dropped.
    Dropped,
}

/// `N` slots (a power of two, like a region ring's `cap`), laid out as a
/// region ring: the four index words each on a line of their own, then the
/// slots.
#[repr(C, align(64))]
pub struct Queue<T: Copy, const N: usize, D: Doorbell = ()> {
    head: Pad<AtomicU32>,
    tail: Pad<AtomicU32>,
    cons_wait: Pad<AtomicU32>,
    prod_wait: Pad<AtomicU32>,
    slots: UnsafeCell<[MaybeUninit<T>; N]>,
    claims: AtomicU32,
    policy: u32,
    dropped: AtomicU64,
    bell: D,
}

unsafe impl<T: Copy + Send, const N: usize, D: Doorbell + Sync> Sync for Queue<T, N, D> {}
unsafe impl<T: Copy + Send, const N: usize, D: Doorbell + Send> Send for Queue<T, N, D> {}

impl<T: Copy, const N: usize> Queue<T, N, ()> {
    pub const fn new(full: Full) -> Self {
        Self::with_bell(full, ())
    }
}

impl<T: Copy, const N: usize, D: Doorbell> Queue<T, N, D> {
    /// `bell` rings after a push, but only when the consumer announced
    /// ([`Consumer::sleep`]) that it may be asleep: the region's rule.
    pub const fn with_bell(full: Full, bell: D) -> Self {
        // The region contract, checked where the fields are declared.
        const {
            assert!(offset_of!(Queue<T, N, D>, head) == RING_HEAD);
            assert!(offset_of!(Queue<T, N, D>, tail) == RING_TAIL);
            assert!(offset_of!(Queue<T, N, D>, cons_wait) == RING_CONS_WAIT);
            assert!(offset_of!(Queue<T, N, D>, prod_wait) == RING_PROD_WAIT);
            assert!(offset_of!(Queue<T, N, D>, slots) == RING_SLOTS);
        };
        assert!(N.is_power_of_two() && N as u64 <= 1 << 31, "a queue's capacity is a power of two");
        Queue {
            head: Pad(AtomicU32::new(0)),
            tail: Pad(AtomicU32::new(0)),
            cons_wait: Pad(AtomicU32::new(0)),
            prod_wait: Pad(AtomicU32::new(0)),
            slots: UnsafeCell::new([MaybeUninit::uninit(); N]),
            claims: AtomicU32::new(0),
            policy: full as u32,
            dropped: AtomicU64::new(0),
            bell,
        }
    }

    /// The ring base the region protocol works from.
    #[inline(always)]
    fn base(&self) -> usize {
        self as *const Self as usize
    }

    #[inline(always)]
    fn slot(&self, i: u32) -> *mut MaybeUninit<T> {
        (self.slots.get() as *mut MaybeUninit<T>).wrapping_add((i as usize) & (N - 1))
    }

    pub fn policy(&self) -> Full {
        if self.policy == Full::DropNewest as u32 {
            Full::DropNewest
        } else {
            Full::Backpressure
        }
    }

    /// Items waiting.
    pub fn len(&self) -> usize {
        ring_len(self.base()) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Items `DropNewest` discarded.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// The one producer. `None` if it is already out.
    pub fn producer(&self) -> Option<Producer<'_, T, N, D>> {
        let old = self.claims.fetch_or(CLAIM_PRODUCER, Ordering::AcqRel);
        if old & CLAIM_PRODUCER != 0 {
            return None;
        }
        Some(Producer { q: self })
    }

    /// The one consumer. `None` if it is already out.
    pub fn consumer(&self) -> Option<Consumer<'_, T, N, D>> {
        let old = self.claims.fetch_or(CLAIM_CONSUMER, Ordering::AcqRel);
        if old & CLAIM_CONSUMER != 0 {
            return None;
        }
        Some(Consumer { q: self })
    }
}

/// The only handle that can push. Not `Clone`.
pub struct Producer<'a, T: Copy, const N: usize, D: Doorbell = ()> {
    q: &'a Queue<T, N, D>,
}

impl<T: Copy, const N: usize, D: Doorbell> Producer<'_, T, N, D> {
    pub fn push(&mut self, v: T) -> Push<T> {
        let q = self.q;
        let base = q.base();
        // Canary: a full queue overwrites its oldest slot instead of refusing.
        #[cfg(feature = "canary-queue-overwrites")]
        let reserved = Some(ring_word(base, RING_HEAD).load(Ordering::Relaxed));
        #[cfg(not(feature = "canary-queue-overwrites"))]
        let reserved = ring_push_reserve(base, N as u32);
        let Some(h) = reserved else {
            return match q.policy() {
                Full::Backpressure => Push::Full(v),
                Full::DropNewest => {
                    q.dropped.fetch_add(1, Ordering::Relaxed);
                    Push::Dropped
                }
            };
        };
        // Safety: slot `h` is not visible to the consumer until the head
        // store in `ring_push_publish`, and only this producer writes it.
        unsafe { q.slot(h).write(MaybeUninit::new(v)) };
        if let RingStep::DoneWake { .. } = ring_push_publish(base, h) {
            q.bell.ring(h.wrapping_add(1) as u64);
        }
        Push::Pushed
    }

    /// `push`, calling `wait` and retrying while a `Backpressure` queue is
    /// full: the producer that blocks. Under `DropNewest` this never waits.
    pub fn push_wait(&mut self, mut v: T, mut wait: impl FnMut()) -> Push<T> {
        loop {
            match self.push(v) {
                Push::Full(back) => {
                    v = back;
                    wait();
                }
                done => return done,
            }
        }
    }
}

impl<T: Copy, const N: usize, D: Doorbell> Drop for Producer<'_, T, N, D> {
    fn drop(&mut self) {
        self.q.claims.fetch_and(!CLAIM_PRODUCER, Ordering::AcqRel);
    }
}

/// The only handle that can pop. Not `Clone`.
pub struct Consumer<'a, T: Copy, const N: usize, D: Doorbell = ()> {
    q: &'a Queue<T, N, D>,
}

impl<T: Copy, const N: usize, D: Doorbell> Consumer<'_, T, N, D> {
    pub fn pop(&mut self) -> Option<T> {
        let q = self.q;
        let base = q.base();
        let t = ring_pop_reserve(base)?;
        // Safety: the head load in `ring_pop_reserve` made the producer's slot
        // write visible, and the producer will not reuse the slot before the
        // tail store in `ring_pop_commit`.
        let v = unsafe { q.slot(t).read().assume_init() };
        ring_pop_commit(base, t);
        Some(v)
    }

    /// The queue is empty and this consumer is about to sleep: announce it
    /// (so the next push rings the bell), re-check, and say whether to sleep
    /// or retry. See [`crate::region::RingSleep`].
    pub fn sleep(&mut self) -> RingSleep {
        ring_consumer_sleep(self.q.base())
    }

    /// Awake again, for whatever reason: withdraw the announcement.
    pub fn woke(&mut self) {
        ring_word(self.q.base(), RING_CONS_WAIT).store(0, Ordering::Relaxed);
    }
}

impl<T: Copy, const N: usize, D: Doorbell> Drop for Consumer<'_, T, N, D> {
    fn drop(&mut self) {
        self.q.claims.fetch_and(!CLAIM_CONSUMER, Ordering::AcqRel);
    }
}
