// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A kernel object made on first use, outside every lock: the first caller
//! allocates and zeroes it, a concurrent one waits for that to finish with
//! no lock held, and later ones read one pointer. For tables too large to
//! zero under a spinlock's hold bound.

use core::ptr::{null_mut, write_bytes};
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

const EMPTY: u8 = 0;
const MAKING: u8 = 1;
const READY: u8 = 2;

pub struct OnceObj<T> {
    state: AtomicU8,
    p: AtomicPtr<T>,
}

impl<T> OnceObj<T> {
    pub const fn new() -> Self {
        Self { state: AtomicU8::new(EMPTY), p: AtomicPtr::new(null_mut()) }
    }

    /// The object, made from `alloc` (zeroed here) if it is not yet; null
    /// when `alloc` refused, and the next call tries again. Never call it
    /// with a spinlock held or from an interrupt handler: a concurrent first
    /// use waits for the maker.
    pub fn get(&self, alloc: impl FnOnce() -> *mut T) -> *mut T {
        self.get_with(alloc, |_| {})
    }

    /// [`Self::get`] with `init` run on the zeroed object before it is
    /// published, for a table whose empty state is not all-zero. It writes
    /// each element in place: a whole-table value would be built on the stack.
    pub fn get_with(&self, alloc: impl FnOnce() -> *mut T, init: impl FnOnce(*mut T)) -> *mut T {
        loop {
            match self.state.load(Ordering::Acquire) {
                READY => return self.p.load(Ordering::Relaxed),
                MAKING => core::hint::spin_loop(),
                _ => {
                    if self.state.compare_exchange(EMPTY, MAKING, Ordering::Acquire, Ordering::Relaxed).is_err() {
                        continue;
                    }
                    let p = alloc();
                    if p.is_null() {
                        self.state.store(EMPTY, Ordering::Release);
                        return p;
                    }
                    // SAFETY: `alloc` handed over a whole, unused `T`.
                    unsafe { write_bytes(p, 0, 1) };
                    init(p);
                    self.p.store(p, Ordering::Relaxed);
                    self.state.store(READY, Ordering::Release);
                    return p;
                }
            }
        }
    }

    /// The object if it is made, null otherwise.
    pub fn peek(&self) -> *mut T {
        if self.state.load(Ordering::Acquire) == READY { self.p.load(Ordering::Relaxed) } else { null_mut() }
    }
}

// SAFETY: the pointer is published once with Release and read with Acquire;
// what it points to is guarded by its user's own lock.
unsafe impl<T> Sync for OnceObj<T> {}

/// A large array reached through a pointer, made by [`OnceObj`], that a lock's
/// guarded state holds: the guard derefs to the array as an inline one did.
/// The pointer is set before the first deref (the table's `lock`).
pub struct ArrPtr<A>(*mut A);

impl<A> ArrPtr<A> {
    pub const fn null() -> Self { Self(null_mut()) }
    pub fn is_null(&self) -> bool { self.0.is_null() }
    pub fn set(&mut self, p: *mut A) { self.0 = p; }
}

impl<A> core::ops::Deref for ArrPtr<A> {
    type Target = A;
    #[inline(always)]
    fn deref(&self) -> &A {
        // SAFETY: set from a live `OnceObj` object before the lock is handed out; never freed.
        unsafe { &*self.0 }
    }
}

impl<A> core::ops::DerefMut for ArrPtr<A> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut A {
        // SAFETY: as `deref`; the lock that guards `self` is held.
        unsafe { &mut *self.0 }
    }
}

// SAFETY: the array is reached only under the lock that holds this pointer.
unsafe impl<A> Send for ArrPtr<A> {}
