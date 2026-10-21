// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_sync`, used only by `tests/host/trap-tests`: the one
//! name `domain.rs` takes from it, `spinlock::SpinLock`, over a `std` mutex.
//! Mutual exclusion only (no interrupts, no preemption count on the host), and
//! it recovers from poison so one failed test cannot latch the lock for the rest.
pub mod spinlock {
    pub struct SpinLock<T> {
        inner: std::sync::Mutex<T>,
    }

    impl<T> SpinLock<T> {
        pub const fn new(data: T) -> Self {
            Self { inner: std::sync::Mutex::new(data) }
        }

        pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
            self.inner.lock().unwrap_or_else(|e| e.into_inner())
        }
    }
}
