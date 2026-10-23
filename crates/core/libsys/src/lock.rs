// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! [`Lock`]: the one way a ring-3 program shares a static.
//!
//! A program keeps state in a static when it is too big for its stack (a
//! service's tables) or when a second thread must reach it (a driver's timer
//! thread). Both used to be a `static` of a local `UnsafeCell` wrapper with an
//! `unsafe impl Sync` and an `unsafe` dereference per use, each with its own
//! argument for why no two references overlap. A [`Lock`] makes that argument
//! once: a flag taken with a compare-exchange admits one [`LockGuard`] at a
//! time, and a program that owns the static for the rest of its life says so
//! with [`LockGuard::leak`], after which no other guard can be had.
//!
//! A contended `lock` yields the CPU until the holder lets go (the holders'
//! critical sections are a few calls long); there is no queue and no
//! priority inheritance, which a program that needs them asks the kernel for
//! (a futex).

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// A `T` behind a yield-while-held lock; `const`-constructible for a static.
pub struct Lock<T> {
    held: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: `data` is reached only through a `LockGuard` (or the reference a
// leaked guard returns), and `held` admits one at a time.
unsafe impl<T: Send> Sync for Lock<T> {}

/// Exclusive access to a [`Lock`]'s value; dropping it releases the lock.
pub struct LockGuard<'a, T> {
    lock: &'a Lock<T>,
    /// A guard is `Sync` only for a `T` that is (it hands out `&T`), as a
    /// `&mut T` is.
    _t: PhantomData<&'a mut T>,
}

impl<T> Lock<T> {
    /// An unlocked `v`.
    pub const fn new(v: T) -> Self {
        Self { held: AtomicBool::new(false), data: UnsafeCell::new(v) }
    }

    /// Take the lock, yielding while another thread holds it.
    pub fn lock(&self) -> LockGuard<'_, T> {
        while self.held.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            crate::yield_now();
        }
        LockGuard { lock: self, _t: PhantomData }
    }
}

impl<'a, T> LockGuard<'a, T> {
    /// Keep the lock for good and get the value for as long as the lock lives
    /// (`'static` for a static): the shape of a program that owns its state
    /// for the rest of its life. Every later [`Lock::lock`] waits forever, so
    /// the reference stays the only one.
    pub fn leak(self) -> &'a mut T {
        let lock = self.lock;
        core::mem::forget(self);
        // SAFETY: the flag is held and is never cleared again (the guard's
        // `Drop` does not run), so this is the one reference to `data`.
        unsafe { &mut *lock.data.get() }
    }
}

impl<T> Deref for LockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: this guard holds the flag (`Lock::lock`).
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for LockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for LockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.held.store(false, Ordering::Release);
    }
}
