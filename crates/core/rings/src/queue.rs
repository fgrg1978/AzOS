// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! [`Queue`]: SPSC, backpressured, every item consumed exactly once.

use crate::{Doorbell, Header, CLAIM_CONSUMER, CLAIM_PRODUCER};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU64, Ordering};

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

pub struct Queue<T: Copy, const N: usize, D: Doorbell = ()> {
    hdr: Header,
    dropped: AtomicU64,
    slots: UnsafeCell<[MaybeUninit<T>; N]>,
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
    pub const fn with_bell(full: Full, bell: D) -> Self {
        assert!(N >= 1);
        Queue {
            hdr: Header::new(full as u32),
            dropped: AtomicU64::new(0),
            slots: UnsafeCell::new([MaybeUninit::uninit(); N]),
            bell,
        }
    }

    pub fn policy(&self) -> Full {
        if self.hdr.policy == Full::DropNewest as u32 {
            Full::DropNewest
        } else {
            Full::Backpressure
        }
    }

    /// Items waiting.
    pub fn len(&self) -> usize {
        let t = self.hdr.tail.0.load(Ordering::Acquire);
        (self.hdr.head.0.load(Ordering::Acquire) - t) as usize
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
        let old = self.hdr.claims.fetch_or(CLAIM_PRODUCER, Ordering::AcqRel);
        if old & CLAIM_PRODUCER != 0 {
            return None;
        }
        Some(Producer { q: self })
    }

    /// The one consumer. `None` if it is already out.
    pub fn consumer(&self) -> Option<Consumer<'_, T, N, D>> {
        let old = self.hdr.claims.fetch_or(CLAIM_CONSUMER, Ordering::AcqRel);
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
        let head = q.hdr.head.0.load(Ordering::Relaxed);
        let tail = q.hdr.tail.0.load(Ordering::Acquire);
        let full = head - tail == N as u64;
        // Canary: a full queue overwrites its oldest slot instead of refusing.
        #[cfg(feature = "canary-queue-overwrites")]
        let full = false;
        if full {
            return match q.policy() {
                Full::Backpressure => Push::Full(v),
                Full::DropNewest => {
                    q.dropped.fetch_add(1, Ordering::Relaxed);
                    Push::Dropped
                }
            };
        }
        // Safety: slot `head % N` is not visible to the consumer until the
        // head store below, and only this producer writes it.
        unsafe { (q.slots.get() as *mut MaybeUninit<T>).add((head % N as u64) as usize).write(MaybeUninit::new(v)) };
        q.hdr.head.0.store(head + 1, Ordering::Release);
        q.bell.ring(head + 1);
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
        self.q.hdr.claims.fetch_and(!CLAIM_PRODUCER, Ordering::AcqRel);
    }
}

/// The only handle that can pop. Not `Clone`.
pub struct Consumer<'a, T: Copy, const N: usize, D: Doorbell = ()> {
    q: &'a Queue<T, N, D>,
}

impl<T: Copy, const N: usize, D: Doorbell> Consumer<'_, T, N, D> {
    pub fn pop(&mut self) -> Option<T> {
        let q = self.q;
        let tail = q.hdr.tail.0.load(Ordering::Relaxed);
        if tail == q.hdr.head.0.load(Ordering::Acquire) {
            return None;
        }
        // Safety: the head load above made the producer's slot write visible,
        // and the producer will not reuse the slot before the tail store.
        let v = unsafe { (*(q.slots.get() as *const MaybeUninit<T>).add((tail % N as u64) as usize)).assume_init() };
        q.hdr.tail.0.store(tail + 1, Ordering::Release);
        Some(v)
    }
}

impl<T: Copy, const N: usize, D: Doorbell> Drop for Consumer<'_, T, N, D> {
    fn drop(&mut self) {
        self.q.hdr.claims.fetch_and(!CLAIM_CONSUMER, Ordering::AcqRel);
    }
}
