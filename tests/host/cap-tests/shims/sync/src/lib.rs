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
/// A stand-in for `kmutex::Mutex`, and honest about which half it models.
///
/// It models MUTUAL EXCLUSION, which is all any test in these suites relies on
/// — the driver crates (`crates/drivers/*`)'s block driver takes one, and those tests exercise the
/// driver, not the lock. It does NOT model priority inheritance, parking, the
/// owner-died hand-over or the held count, because there is no scheduler here
/// to inherit anything from.
///
/// So: a test that wants to assert something about PI must NOT use this. The
/// real `Mutex` is host-buildable and `tests/host/sync-tests` exercises it
/// directly; that is where such a test belongs.
pub mod kmutex {
    use super::{Guard, SpinLock};

    pub struct Mutex<T> {
        inner: SpinLock<T>,
    }

    pub type MutexGuard<'a, T> = Guard<'a, T>;

    impl<T> Mutex<T> {
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

/// The real `lockdep`'s calls the driver crates make
/// (`crates/core/sync/src/lockdep.rs`). The host has no scheduler and no
/// lockdep: they check nothing.
pub mod lockdep {
    pub const ON: bool = false;
    /// The log-flush task's lockdep printer (the flusher reads it).
    pub const DRAIN_IN_LOG: bool = false;
    pub fn might_sleep(_what: &'static str) {}
    pub fn might_wait_device(_what: &'static str) {}
}

/// The real `Claim`'s surface (`crates/core/sync/src/claim.rs`): one owner
/// at a time over std primitives (a thread that finds it owned waits for the
/// release). No scheduler, so no holder is counted for a panic path.
pub mod claim {
    use std::cell::UnsafeCell;
    use std::sync::{Condvar, Mutex};

    pub struct Claim<T> {
        busy: Mutex<bool>,
        released: Condvar,
        data: UnsafeCell<T>,
    }

    // SAFETY: `data` is only reached through a `ClaimGuard`, and `busy`
    // admits one guard at a time.
    unsafe impl<T: Send> Sync for Claim<T> {}

    pub struct ClaimGuard<'a, T> {
        claim: &'a Claim<T>,
    }

    impl<T> Claim<T> {
        pub const fn new(data: T) -> Self {
            Self { busy: Mutex::new(false), released: Condvar::new(), data: UnsafeCell::new(data) }
        }
        pub fn acquire(&self) -> ClaimGuard<'_, T> {
            let mut b = self.busy.lock().unwrap_or_else(|e| e.into_inner());
            while *b {
                b = self.released.wait(b).unwrap_or_else(|e| e.into_inner());
            }
            *b = true;
            ClaimGuard { claim: self }
        }
    }

    impl<T> std::ops::Deref for ClaimGuard<'_, T> {
        type Target = T;
        fn deref(&self) -> &T {
            // SAFETY: this guard is the one owner.
            unsafe { &*self.claim.data.get() }
        }
    }

    impl<T> std::ops::DerefMut for ClaimGuard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            // SAFETY: as in `deref`.
            unsafe { &mut *self.claim.data.get() }
        }
    }

    impl<T> Drop for ClaimGuard<'_, T> {
        fn drop(&mut self) {
            *self.claim.busy.lock().unwrap_or_else(|e| e.into_inner()) = false;
            self.claim.released.notify_one();
        }
    }
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

/// The real `waitgraph` surface FAT32's claim donation names (FX12), with
/// `WAIT_GRAPH` n: `ENABLED` is false and `DonorNode` is `()`, so no graph
/// call is reached; the y-only items exist only to type-check.
pub mod waitgraph {
    pub const ENABLED: bool = false;
    pub type TaskId = u32;
    pub struct PiWaiters;
    impl PiWaiters {
        pub fn owner(&self) -> Option<TaskId> { None }
        pub fn set_owner(&self, _: Option<TaskId>) {}
    }
    pub struct PendingBlock;
    #[derive(Debug)]
    pub enum WaitError { NoOwner }
    pub enum UnblockReason { Acquired }
    pub fn block_prepare(_: TaskId, _: &PiWaiters) -> Result<PendingBlock, WaitError> { Err(WaitError::NoOwner) }
    pub fn block_commit(_: PendingBlock) -> Result<(), WaitError> { Err(WaitError::NoOwner) }
    pub fn unblock(_: TaskId, _: &PiWaiters, _: UnblockReason) {}
    pub fn release(_: TaskId, _: &PiWaiters) -> Option<TaskId> { None }
    pub struct NodeSel<const Y: bool>;
    pub trait SelectNode { type Node; const CLAIM: Self::Node; }
    impl SelectNode for NodeSel<false> { type Node = (); const CLAIM: () = (); }
    pub type DonorNode = <NodeSel<ENABLED> as SelectNode>::Node;
}

/// The real `preempt::critical_section` surface. The host has no preemption
/// counter; the guard is a unit (threads stay preemptible, which only makes
/// the lock-free code under test face more interleavings, never fewer).
pub mod preempt {
    pub struct PreemptGuard;
    pub fn critical_section() -> PreemptGuard { PreemptGuard }
}
