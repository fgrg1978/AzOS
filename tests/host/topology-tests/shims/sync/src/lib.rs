// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_sync`.
//!
//! **WHY this exists.** `crates/core/ipc/src/cap_store.rs` sits on
//! `azos_sync::SpinLock`, and the real `SpinLock` calls
//! `azos_arch::csr` (RV64 `sstatus` reads/writes in inline asm). That
//! cannot be compiled or executed on the host, so the `#[path]` trick this
//! crate uses for `cap.rs`/`cap_store.rs` (to test the P1 topology→cap_store
//! bridge — see `crates/core/ipc/src/cap_seed.rs`) stops at the first
//! `SpinLock`. This crate provides the same *surface* backed by a
//! `std::sync::Mutex`, pulled in under the name `azos_sync` via a Cargo
//! dependency rename — the kernel never sees it.
//!
//! Identical to `tests/host/cap-tests/shims/sync` (copied, not path-shared —
//! each `*-tests` crate owns its shims by convention in this tree).

use std::ops::{Deref, DerefMut};
use std::sync::{Mutex, MutexGuard};

pub struct SpinLock<T> {
    inner: Mutex<T>,
}

pub struct Guard<'a, T> {
    inner: MutexGuard<'a, T>,
}

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

pub mod spinlock {
    pub use super::{Guard, IrqSaveGuard, SpinLock, SpinLockGuard};
}
