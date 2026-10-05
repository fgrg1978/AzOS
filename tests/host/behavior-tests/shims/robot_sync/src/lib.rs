// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_sync`, for the real `domains/robot/robot/src/motor.rs`
//! only. A copy of `tests/host/syscall-tests/shims/robot_sync`, scoped to
//! `tests/host/behavior-tests`' own motor-gate/record suite (Q1.3/Q1.4,
//! 2026-09-25) for the identical reason that one exists.
//!
//! **Why not `cap_test_sync`.** That stand-in (this crate's sibling
//! `../../cap-tests/shims/sync`, aliased as `azos_sync` everywhere else
//! in `tests/host/behavior-tests`) is backed by `std::sync::Mutex` and
//! deliberately has no `get_mut_unchecked`, the panic-path escape hatch
//! `motor_stop_panic` calls; its own note says a module that needs it should
//! get a lock backed by `UnsafeCell` rather than a cast. This is that lock,
//! scoped to the one shim crate that needs it so the fourteen-plus crates
//! sharing `cap_test_sync` are untouched.
//!
//! Mutual exclusion is a `Mutex<()>` beside the data. `get_mut_unchecked`
//! bypasses it, exactly as the real one bypasses the spinlock, under the same
//! safety contract. No test calls it: `motor_stop_panic` is compiled, not
//! run.

use std::cell::UnsafeCell;
use std::ops::{Deref, DerefMut};
use std::sync::{Mutex, MutexGuard};

pub struct SpinLock<T> {
    held: Mutex<()>,
    data: UnsafeCell<T>,
}

// Same bounds as the real `SpinLock`: access to `data` is serialised by
// `held`, except through `get_mut_unchecked`, whose caller takes that on.
unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

pub struct Guard<'a, T> {
    _held: MutexGuard<'a, ()>,
    data: &'a UnsafeCell<T>,
}

impl<T> Deref for Guard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: `_held` serialises every guard of this lock.
        unsafe { &*self.data.get() }
    }
}

impl<T> DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above, and `&mut self` makes this the only borrow.
        unsafe { &mut *self.data.get() }
    }
}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self { held: Mutex::new(()), data: UnsafeCell::new(data) }
    }

    /// Poison is recovered, as in `cap_test_sync`: a test that panics while
    /// holding the lock fails alone instead of hanging the binary.
    pub fn lock(&self) -> Guard<'_, T> {
        Guard { _held: self.held.lock().unwrap_or_else(|e| e.into_inner()), data: &self.data }
    }

    /// # Safety
    /// As the real one: the caller must ensure no concurrent access.
    pub unsafe fn get_mut_unchecked(&self) -> &mut T {
        &mut *self.data.get()
    }
}
