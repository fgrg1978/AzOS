// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_sync`.
//!
//! **WHY this exists.** `crates/core/ipc/src/{lease,port,shm,io_ring}.rs` all sit on
//! `azos_sync::SpinLock`, and the real `SpinLock` calls
//! `azos_arch::csr` (RV64 `sstatus` reads/writes in inline asm) from
//! `lock_irqsave()`. That cannot be compiled or executed on the host, so the
//! `#[path]` trick used by `tests/host/cap-tests` stops at the first
//! `lock_irqsave()`. This crate provides the same *surface* backed by a
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
pub mod spinlock {
    pub use super::{Guard, IrqSaveGuard, SpinLock, SpinLockGuard};
}
