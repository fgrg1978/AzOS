// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sleeping adaptive kernel mutex (wave 15 N8), the first client of the
//! wait graph (`waitgraph`, N7).
//!
//! **Interface only.** The bodies are `todo!()`; front N8 implements them
//! and then retires `PiMutex`'s yield loop and moves the FAT32 and
//! virtio-blk paths off `SpinLock`. Kconfig `KMUTEX` (default n, depends on
//! `WAIT_GRAPH`) gates the call-site migration, not this type.
//!
//! # Semantics (fixed)
//!
//! * Owner-held, not recursive, released by the owner only (lockdep and a
//!   debug assert check it). Fair to urgency, not FIFO: waiters queue in the
//!   object's `PiWaiters` by effective attribute.
//! * **Fast path**: one compare-and-swap of the owner word (0 -> TaskId),
//!   no graph call, no lockdep beyond the held-stack push. Unlock: one CAS
//!   back to 0 when the waiters bit is clear.
//! * **Adaptive spin**: on contention, spin at most `KMUTEX_ADAPTIVE_SPIN`
//!   spin-hint iterations, and only while the owner is on a CPU
//!   (`SchedPi::on_cpu`) and the spinner has no pending reschedule. 0 never
//!   spins (uniprocessor and embedded defaults). An RT spinner and an RT
//!   owner on different CPUs is the F7 case (lockdep `RT_CROSS_CPU`).
//! * **Slow path**: set the waiters bit, `waitgraph::block_on`, sleep, and on
//!   wake retry the acquire. Unlock with waiters: clear the owner,
//!   `waitgraph::release` (unboost), wake the top waiter, which competes;
//!   a task strictly more urgent than the top waiter may take the lock first
//!   (Linux rt_mutex lock stealing), nobody else may.
//! * **F1 (owner, 09-10)**: a mutex is never held across a device wait. A
//!   path that waits for a device in the middle of a critical section
//!   releases the mutex around the wait with [`MutexGuard::unlocked_for_io`]
//!   or [`MutexGuard::unlock_for_io`] / [`IoUnlocked::relock`]; the
//!   critical section must revalidate what it read before the wait.
//!   `lockdep::might_wait_device` reports a `Mutex` still held there (N8
//!   adds `lockdep::Kind::Mutex = 5` and lists it with the PiMutex in that
//!   check).
//!
//! # Context
//!
//! `lock` and the guard's relock: task context, preemption on, no SpinLock
//! held (`lockdep::might_sleep`). `try_lock`: also with SpinLocks held and
//! preemption off, never in an interrupt handler (an interrupt has no
//! owner identity to boost). Unlock: wherever the lock was taken.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};

use crate::waitgraph::{EdgeKind, PiWaiters};

/// Kconfig `KMUTEX_ADAPTIVE_SPIN`: the most spin-hint iterations a
/// contender spends while the owner runs before it blocks. 0: block at once.
pub const ADAPTIVE_SPIN: usize = azos_limits::KMUTEX_ADAPTIVE_SPIN;

/// Kconfig `KMUTEX`: call sites use `Mutex` instead of `PiMutex` and the
/// FAT32/virtio-blk SpinLocks. n: this type exists but nothing uses it.
pub const ENABLED: bool = azos_limits::KMUTEX;

/// A sleeping, priority-inheriting, adaptive mutual-exclusion lock.
pub struct Mutex<T: ?Sized> {
    /// The object's node in the wait graph (`EdgeKind::Mutex`). Owner and
    /// waiters bit live in its state; N8 may move the owner word out for
    /// the fast-path CAS.
    waiters: PiWaiters,
    data: UnsafeCell<T>,
}

// SAFETY: access to `data` is serialised by the lock (contract above).
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    /// An unlocked mutex holding `v`. `const`, so a `static` needs no init.
    /// The lockdep class is the caller's site (N8 adds the class field
    /// behind the `lockdep` feature, like `SpinLock`).
    #[track_caller]
    pub const fn new(v: T) -> Self {
        Mutex { waiters: PiWaiters::new(EdgeKind::Mutex), data: UnsafeCell::new(v) }
    }

    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Acquire, sleeping if needed (fast path, adaptive spin, slow path as
    /// in the module doc). Task context, no SpinLock held. Cost: fast path
    /// one CAS; slow path one graph block, O(PI_MAX_DEPTH).
    #[track_caller]
    pub fn lock(&self) -> MutexGuard<'_, T> {
        todo!("N8")
    }

    /// Acquire only if free right now; never spins or sleeps. Any context
    /// but an interrupt handler. One CAS.
    #[track_caller]
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        todo!("N8")
    }

    /// Owned by someone right now (racy hint; diagnostics and asserts).
    pub fn is_locked(&self) -> bool {
        self.waiters.owner().is_some()
    }

    /// The wait-graph node, for clients that name this mutex in a
    /// `blocked_on` report or a trace.
    pub fn wait_node(&self) -> &PiWaiters {
        &self.waiters
    }

    /// Exclusive access without locking (the borrow proves no guard exists).
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

/// Proof that the current task owns a [`Mutex`]. Unlocks on drop. Not
/// `Send`: the owner releases it.
pub struct MutexGuard<'a, T: ?Sized> {
    lock: &'a Mutex<T>,
    _not_send: core::marker::PhantomData<*const ()>,
}

impl<'a, T: ?Sized> MutexGuard<'a, T> {
    /// F1: release the mutex, run `wait` (a device wait: block I/O
    /// completion, a virtio queue drain), and re-acquire before returning.
    /// The `&mut self` borrow means no reference into the data survives the
    /// gap; the caller revalidates any state it read before. Task context,
    /// no other lock held during `wait`. Cost: one unlock + one lock.
    pub fn unlocked_for_io<R>(&mut self, _what: &'static str, _wait: impl FnOnce() -> R) -> R {
        todo!("N8")
    }

    /// F1, split form for waits that cannot be a closure: release now; the
    /// returned token re-acquires with [`IoUnlocked::relock`]. Dropping the
    /// token without relocking is allowed (the critical section ended).
    pub fn unlock_for_io(self) -> IoUnlocked<'a, T> {
        todo!("N8")
    }
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard proves ownership.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard proves exclusive ownership.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    /// Unlock: fast path one CAS; with waiters, `waitgraph::release` and a
    /// wake of the top waiter.
    fn drop(&mut self) {
        todo!("N8")
    }
}

/// A [`Mutex`] released around a device wait by [`MutexGuard::unlock_for_io`].
#[must_use = "relock() it, or drop it if the critical section is over"]
pub struct IoUnlocked<'a, T: ?Sized> {
    lock: &'a Mutex<T>,
}

impl<'a, T: ?Sized> IoUnlocked<'a, T> {
    /// Re-acquire (may sleep, same contract as `Mutex::lock`).
    #[track_caller]
    pub fn relock(self) -> MutexGuard<'a, T> {
        self.lock.lock()
    }
}
