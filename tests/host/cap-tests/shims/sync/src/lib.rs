// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_sync`.
//!
//! **WHY this exists.** `crates/core/ipc/src/cap_store.rs` sits on
//! `azos_sync::SpinLock`, and the real `SpinLock` calls
//! `azos_arch::csr` (RV64 `sstatus` reads/writes in inline asm). That
//! cannot be compiled or executed on the host, so the `#[path]` trick this
//! crate already uses for `cap.rs` stops at the first `SpinLock`. This crate
//! provides the same *surface* backed by a
//! `std::sync::Mutex`, and is pulled in under the name `azos_sync` via a
//! Cargo dependency rename — the kernel never sees it.
//!
//! Deliberate difference: poison recovery. A test that panics while holding
//! the lock would leave a real spinlock latched forever and hang the whole
//! test binary; recovering the inner value turns that into one failed test.

use std::ops::{Deref, DerefMut};
use std::sync::{Mutex, MutexGuard};

pub struct SpinLock<T> {
    inner: Mutex<T>,
}

// Same guarantees the real guard offers, expressed over std's guard.
pub struct Guard<'a, T> {
    inner: MutexGuard<'a, T>,
}

/// The real crate has two guard types (plain and IRQ-saving). On the host
/// there are no interrupts to save, so both alias one implementation.
pub type SpinLockGuard<'a, T> = Guard<'a, T>;
pub type IrqSaveGuard<'a, T> = Guard<'a, T>;

impl<T> Deref for Guard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self { inner: Mutex::new(data) }
    }

    pub fn lock(&self) -> Guard<'_, T> {
        Guard { inner: self.inner.lock().unwrap_or_else(|e| e.into_inner()) }
    }

    /// No interrupts on the host — identical to `lock()`.
    pub fn lock_irqsave(&self) -> Guard<'_, T> {
        self.lock()
    }

    pub fn try_lock(&self) -> Option<Guard<'_, T>> {
        match self.inner.try_lock() {
            Ok(g) => Some(Guard { inner: g }),
            Err(std::sync::TryLockError::Poisoned(e)) => {
                Some(Guard { inner: e.into_inner() })
            }
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    }

    pub fn try_lock_irqsave(&self) -> Option<Guard<'_, T>> {
        self.try_lock()
    }

}

// NOTE: the real `SpinLock` also has `get_mut_unchecked()` (the panic-path
// escape hatch). It is deliberately absent here: none of the modules this
// suite compiles calls it, and a faithful stand-in would have to cast a
// shared reference to a mutable one, which is UB on the host and rejected by
// `invalid_reference_casting`. If a future module needs it, back this type
// with `UnsafeCell` instead of `Mutex` rather than casting.

/// The real crate exposes `azos_sync::spinlock::SpinLock` as well as the
/// root re-export; `cap_store.rs` uses the module path.
/// A stand-in for `PiMutex`, and honest about which half it models.
///
/// It models MUTUAL EXCLUSION, which is all any test in these suites relies on
/// — the driver crates (`crates/drivers/*`)'s block driver takes one, and those tests exercise the
/// driver, not the lock. It does NOT model priority inheritance, donation
/// counting, or the yield-instead-of-spin behaviour, because there is no
/// scheduler here to inherit anything from.
///
/// So: a test that wants to assert something about PI must NOT use this. The
/// real `PiMutex` is host-buildable and `tests/host/ipc-lease-tests` exercises the
/// donation protocol against it directly; that is where such a test belongs.
pub mod pi_mutex {
    use super::{Guard, SpinLock};

    pub struct PiMutex<T> {
        inner: SpinLock<T>,
    }

    pub type PiMutexGuard<'a, T> = Guard<'a, T>;

    impl<T> PiMutex<T> {
        pub const fn new(data: T) -> Self {
            Self { inner: SpinLock::new(data) }
        }
        pub fn lock(&self) -> Guard<'_, T> {
            self.inner.lock()
        }
        pub fn try_lock(&self) -> Option<Guard<'_, T>> {
            self.inner.try_lock()
        }
    }
}

pub mod spinlock {
    pub use super::{Guard, IrqSaveGuard, SpinLock, SpinLockGuard};
}

/// The real `WaitQueue`'s `wait_if`/`wake_all` surface. The host has no
/// scheduler to block on, so `wait_if` yields the thread when the condition
/// still holds (the caller re-checks in a loop, exactly as it must against
/// the real queue's spurious returns); `wake_all` has nobody to wake.
pub mod waitqueue {
    pub struct WaitQueue;

    impl WaitQueue {
        pub const fn new() -> Self { WaitQueue }
        pub fn wait_if(&self, should_sleep: impl Fn() -> bool) {
            if should_sleep() { std::thread::yield_now(); }
        }
        pub fn wake_all(&self) -> usize { 0 }
    }

    /// No scheduler: the real one's pre-registration answer.
    pub fn caller_tid() -> u32 { u32::MAX }
}
