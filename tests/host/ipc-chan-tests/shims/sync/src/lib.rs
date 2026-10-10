// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_sync`.
//!
//! The real crate calls `azos_arch::csr` (`crates/core/sync/src/spinlock.rs:15`)
//! to save and restore `sstatus.SIE`, which exists only on RISC-V, so
//! `azos_sync` cannot be built for the developer host. The kernel modules
//! that `tests/host/ipc-chan-tests` pulls in with `#[path]` need `SpinLock` and
//! nothing else from it.
//!
//! This crate's *library* is named `azos_sync` (see `[lib] name` in
//! `Cargo.toml`) so those sources resolve `use azos_sync::SpinLock;`
//! without being edited. Mutual-exclusion semantics match the real lock; the
//! interrupt discipline is absent, and nothing under test depends on it.
//!
//! Used by exactly one crate. Do not depend on it from anything that ships.

use std::sync::{Mutex, MutexGuard};

pub struct SpinLock<T> {
    inner: Mutex<T>,
}

impl<T> SpinLock<T> {
    pub const fn new(v: T) -> Self {
        Self { inner: Mutex::new(v) }
    }

    /// Lock poisoning is deliberately ignored: one failing test must not turn
    /// every later test in the process into an unrelated failure.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The kernel variant additionally clears `sstatus.SIE`. There are no
    /// interrupts here, so it degrades to a plain lock.
    pub fn lock_irqsave(&self) -> MutexGuard<'_, T> {
        self.lock()
    }
}

/// The kernel's guard type, as `cap_store` names it.
pub type SpinLockGuard<'a, T> = MutexGuard<'a, T>;

pub mod spinlock {
    pub use super::{SpinLock, SpinLockGuard};
}
