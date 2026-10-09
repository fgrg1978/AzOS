// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A sleeping lock WITHOUT priority inheritance: the lock a holder may keep
//! across a device wait (owner rule F1, `rfcs/survey/MUTEX.md`).
//!
//! A `PiMutex` boosts its owner to its best waiter's priority. Held across
//! disk I/O, that boost lands on a task that is waiting on hardware, and
//! every real-time waiter inherits the device's latency. So no `PiMutex` is
//! held across a device wait, for any task; what must exclude across one is
//! a `SleepLock`. Real-time tasks never do block I/O (`RT_BLOCK_IO_CHECK`),
//! so they never wait on a holder that is doing it through one of these.
//!
//! A contended caller sleeps on the lock's `WaitQueue` until the holder's
//! release bumps `gen` (re-checked under the queue's lock: no lost wakeup).
//! The holder is counted in a per-TID table ([`held_by`]) the panic path adds
//! to its containment predicate: a contained task that took one of these
//! with it would stop every later user of the lock, the same rule as a held
//! `PiMutex`.
//!
//! The trade-off (FreeBSD `sx`, Linux `mutex` without `rt_mutex`): a
//! low-priority holder preempted by a mid-priority task delays a
//! higher-priority waiter without a boost.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::pi_mutex::HeldTable;
use crate::waitqueue::WaitQueue;

/// Every `SleepLock` acquisition not yet released, per task.
static SLEEP_HELD: HeldTable = HeldTable::new();

/// `SleepLock`s (and claims counted with [`note_acquired`]) task `tid` holds.
pub fn held_by(tid: u32) -> u32 {
    if tid == 0 { return 0; }
    SLEEP_HELD.held_by(tid)
}

/// Count an exclusion that is not a `SleepLock` but obeys the same rule
/// (held across a device wait, no PI) for the panic path. Undo with
/// [`note_released`] by the same task.
pub fn note_acquired(tid: u32) {
    if tid != 0 { let _ = SLEEP_HELD.raise(tid); }
}

/// Undo one [`note_acquired`].
pub fn note_released(tid: u32) {
    if tid != 0 { SLEEP_HELD.lower(tid); }
}

/// A sleeping lock without priority inheritance (see the module docs).
pub struct SleepLock<T> {
    busy:  AtomicBool,
    owner: AtomicU32,
    gen:   AtomicU32,
    wq:    WaitQueue,
    /// Lockdep class: the constructor's call site (`lockdep` feature only).
    #[cfg(feature = "lockdep")]
    class: crate::lockdep::LockClass,
    data:  UnsafeCell<T>,
}

// SAFETY: `data` is only reached through a `SleepLockGuard`, and `busy`
// admits one guard at a time.
unsafe impl<T: Send> Sync for SleepLock<T> {}

/// The holder's access to a [`SleepLock`]; dropping it releases the lock.
pub struct SleepLockGuard<'a, T> {
    lock: &'a SleepLock<T>,
}

impl<T> SleepLock<T> {
    #[cfg_attr(feature = "lockdep", track_caller)]
    pub const fn new(v: T) -> Self {
        Self {
            busy:  AtomicBool::new(false),
            owner: AtomicU32::new(0),
            gen:   AtomicU32::new(0),
            wq:    WaitQueue::new(),
            #[cfg(feature = "lockdep")]
            class: crate::lockdep::LockClass::here(crate::lockdep::Kind::Sleep),
            data:  UnsafeCell::new(v),
        }
    }

    /// Take the lock, sleeping (no boost to the holder) while it is taken.
    #[cfg_attr(feature = "lockdep", track_caller)]
    pub fn lock(&self) -> SleepLockGuard<'_, T> {
        #[cfg(feature = "lockdep")]
        {
            crate::lockdep::might_sleep("SleepLock::lock");
            crate::lockdep::check(&self.class, self as *const Self as usize,
                crate::lockdep::Kind::Sleep, core::panic::Location::caller());
        }
        loop {
            let gen = self.gen.load(Ordering::SeqCst);
            if self.busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                let tid = crate::waitqueue::caller_tid();
                self.owner.store(tid, Ordering::Relaxed);
                note_acquired(tid);
                #[cfg(feature = "lockdep")]
                crate::lockdep::acquired(&self.class, self as *const Self as usize,
                    crate::lockdep::Kind::Sleep, false, core::panic::Location::caller());
                return SleepLockGuard { lock: self };
            }
            self.wq.wait_if(|| self.gen.load(Ordering::SeqCst) == gen);
        }
    }

    /// Whether task `tid` holds this lock.
    pub fn held_by(&self, tid: u32) -> bool {
        tid != 0 && self.busy.load(Ordering::Acquire) && self.owner.load(Ordering::Relaxed) == tid
    }
}

impl<T> core::ops::Deref for SleepLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: this guard is the one holder (`SleepLock::lock`).
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> core::ops::DerefMut for SleepLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SleepLockGuard<'_, T> {
    fn drop(&mut self) {
        #[cfg(feature = "lockdep")]
        crate::lockdep::release(self.lock as *const SleepLock<T> as usize);
        let tid = self.lock.owner.swap(0, Ordering::Relaxed);
        note_released(tid);
        self.lock.busy.store(false, Ordering::Release);
        self.lock.gen.fetch_add(1, Ordering::SeqCst);
        self.lock.wq.wake_all();
    }
}
