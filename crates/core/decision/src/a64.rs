// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `AtomicU64` on every target.
//!
//! Targets with 64-bit atomics use the core type, unchanged. AzOS-micro
//! (riscv32imac) has none, so there the same four operations the ring, the
//! journal and the counters use (`load`, `store`, `fetch_add`, `swap`) run
//! under one spin flag. The micro image builds this crate without `on` and
//! `durable`, so no path of it takes the flag in interrupt context; the flag
//! only keeps the type honest (a 64-bit read is never torn).

#[cfg(target_has_atomic = "64")]
pub(crate) use core::sync::atomic::AtomicU64;

#[cfg(not(target_has_atomic = "64"))]
pub(crate) use fallback::AtomicU64;

#[cfg(not(target_has_atomic = "64"))]
mod fallback {
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicBool, Ordering};

    static LOCK: AtomicBool = AtomicBool::new(false);

    pub(crate) struct AtomicU64(UnsafeCell<u64>);
    // SAFETY: every access to the cell holds `LOCK`.
    unsafe impl Sync for AtomicU64 {}

    impl AtomicU64 {
        pub(crate) const fn new(v: u64) -> AtomicU64 {
            AtomicU64(UnsafeCell::new(v))
        }
        fn with<R>(&self, f: impl FnOnce(&mut u64) -> R) -> R {
            while LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
                core::hint::spin_loop();
            }
            // SAFETY: `LOCK` is held.
            let r = f(unsafe { &mut *self.0.get() });
            LOCK.store(false, Ordering::Release);
            r
        }
        pub(crate) fn load(&self, _: Ordering) -> u64 {
            self.with(|v| *v)
        }
        pub(crate) fn store(&self, x: u64, _: Ordering) {
            self.with(|v| *v = x)
        }
        pub(crate) fn fetch_add(&self, x: u64, _: Ordering) -> u64 {
            self.with(|v| {
                let old = *v;
                *v = old.wrapping_add(x);
                old
            })
        }
        pub(crate) fn swap(&self, x: u64, _: Ordering) -> u64 {
            self.with(|v| core::mem::replace(v, x))
        }
    }
}
