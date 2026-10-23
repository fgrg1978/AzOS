// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A claim: exclusive ownership of one resource that its owner keeps across
//! a wait for a device (owner rule F1).
//!
//! # Why this is not a lock
//!
//! No `Mutex` is held across a device wait, for any task: the mutex would
//! boost an owner that is waiting on hardware and every real-time waiter
//! would inherit the device's latency. What must still exclude across such a
//! wait (the image buffer a file read fills, the position of a stream, the
//! flight recorder's flush) is not a critical section but the ownership of a
//! resource, and ownership is data. A [`Claim`] keeps it in a kernel mutex
//! ([`crate::kmutex::Mutex`]) that is held only for the instant of taking or
//! giving the claim; the owner then works with the mutex released, and a
//! contender sleeps on the claim's wait queue with the mutex released too
//! (`unlock_for_io`, then `relock`). This is the shape of the FAT32 sector
//! claims, the virtio-blk slot claims and the SD/eMMC request queue.
//!
//! Consequences, by design:
//!
//! * lockdep sees a `Mutex` only for the instant of the exchange, so a claim
//!   held across a device wait is the allowed shape and a `Mutex` held there
//!   (the canary, [`canary_mutex_held`]) is reported as such
//!   (`might_wait_device`, rule F1);
//! * a claim is not a lockdep class: no order check between claims and other
//!   locks (a claim is held across waits, so an order between it and a lock
//!   is a property of its users, documented where they are);
//! * a contender sleeps without boosting the owner. Real-time tasks never do
//!   block I/O (`RT_BLOCK_IO_CHECK`), so they never wait on an owner that is
//!   doing it through a claim; a claim is for non-real-time work;
//! * taking or giving a claim may sleep (the exchange mutex is contended for
//!   a few instructions): task context, no SpinLock held, as `Mutex::lock`.
//!
//! The owner is counted per task in a table ([`held_by`]) the panic path adds
//! to its containment predicate: a contained task that took a claim with it
//! would stop every later user of the resource, the same rule as a held
//! `Mutex`. A claim whose owner exited stays taken (a kernel bug), only the
//! count is dropped ([`held_forget`]).

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use crate::held::HeldTable;
use crate::kmutex::{Mutex, MutexGuard};
use crate::waitqueue::WaitQueue;

/// Every claim taken and not yet given back, per task.
static CLAIM_HELD: HeldTable = HeldTable::new();

/// Claims task `tid` owns.
pub fn held_by(tid: u32) -> u32 {
    if tid == 0 { return 0; }
    CLAIM_HELD.held_by(tid)
}

/// Task `tid` exited (scheduler exit paths, beside
/// [`crate::held::held_forget`]): its claims leave the table, so the panic
/// path's containment predicate never counts a dead owner and stale entries
/// never fill the table (owner decision 10-10). A claim it died owning
/// stays taken; only the count is dropped. O(`PI_HELD_SLOTS`). Runtime
/// canary `canary=claim-held-keeps-dead` skips it.
pub fn held_forget(tid: u32) {
    if tid == 0 || CANARY_HELD_KEEPS_DEAD.load(Ordering::Relaxed) {
        return;
    }
    CLAIM_HELD.forget(tid);
}

static CANARY_HELD_KEEPS_DEAD: AtomicBool = AtomicBool::new(false);

/// Arm the `claim-held-keeps-dead` canary (boot, from the command line): a
/// dead owner's claims stay counted; ktest
/// `claim_dead_owner_leaves_the_held_table` goes red.
pub fn canary_held_keeps_dead() {
    CANARY_HELD_KEEPS_DEAD.store(true, Ordering::Relaxed);
}

/// The address of the one claim the `claim-mutex-held` canary is armed for,
/// 0 when it is off.
static CANARY_MUTEX_HELD: AtomicUsize = AtomicUsize::new(0);

/// Arm the `claim-mutex-held` canary for the claim at `claim_addr` (the
/// ktest `claim_holds_no_mutex_across_a_device_wait` with `canary=claim-mutex-held`
/// for its own claim, the kernel feature `exec-bounce-pi-canary` for
/// `EXEC_BOUNCE`): its owner keeps the claim's exchange mutex for as long as
/// it owns the claim, so a `Mutex` is held across every device wait the owner
/// makes (rule F1 broken). Lockdep notes it at `might_wait_device`, the ktest
/// goes red and the `lat-fat` smoke counts the I/O under the mutex. One claim
/// at a time, so the canary reaches no other user of claims.
pub fn canary_mutex_held(claim_addr: usize) {
    CANARY_MUTEX_HELD.store(claim_addr, Ordering::Relaxed);
}

/// The claim's state, under the exchange mutex.
struct State {
    busy:  bool,
    /// The owner's TID while `busy`, else 0.
    owner: u32,
}

/// One resource, `T`, owned by one task at a time (see the module docs).
///
/// `repr(C)` with the exchange mutex first: the claim's address is its
/// mutex's, so a canary report naming the held `Mutex` names the claim.
#[repr(C)]
pub struct Claim<T> {
    st:   Mutex<State>,
    /// Bumped at every release, under the mutex; a contender sleeps while it
    /// is the value it saw when it found the claim taken (no lost wakeup:
    /// the queue re-checks it under its own lock).
    gen:  AtomicU32,
    wq:   WaitQueue,
    data: UnsafeCell<T>,
}

// SAFETY: `data` is only reached through a `ClaimGuard`, and `State::busy`
// admits one guard at a time.
unsafe impl<T: Send> Sync for Claim<T> {}

/// The owner's access to a [`Claim`]; dropping it gives the claim back.
pub struct ClaimGuard<'a, T> {
    claim: &'a Claim<T>,
    /// The exchange mutex, kept only by the `claim-mutex-held` canary.
    held:  Option<MutexGuard<'a, State>>,
}

impl<T> Claim<T> {
    /// An unowned claim of `v`. The exchange mutex's lockdep class is the
    /// caller's site.
    #[track_caller]
    pub const fn new(v: T) -> Self {
        Self {
            st:   Mutex::new(State { busy: false, owner: 0 }),
            gen:  AtomicU32::new(0),
            wq:   WaitQueue::new(),
            data: UnsafeCell::new(v),
        }
    }

    /// Take the claim, sleeping (no boost to the owner, the exchange mutex
    /// released while asleep) until it is free.
    #[track_caller]
    pub fn acquire(&self) -> ClaimGuard<'_, T> {
        let mut g = self.st.lock();
        while g.busy {
            let seen = self.gen.load(Ordering::SeqCst);
            // F1: nothing is held while this task waits for the owner.
            let parked = g.unlock_for_io();
            self.wq.wait_if_for(crate::waitstat::Site::Claim, || self.gen.load(Ordering::SeqCst) == seen);
            g = parked.relock();
        }
        self.own(g)
    }

    /// Take the claim if it is free; `None`, without waiting, if it is owned.
    /// For a resource whose contender is refused rather than queued (the OTA
    /// switch's manifest buffers: a second switch is answered busy).
    #[track_caller]
    pub fn try_acquire(&self) -> Option<ClaimGuard<'_, T>> {
        let g = self.st.lock();
        if g.busy {
            return None;
        }
        Some(self.own(g))
    }

    /// Mark the claim owned by the caller; `g` is the exchange mutex, held,
    /// with the claim free.
    fn own<'a>(&'a self, mut g: MutexGuard<'a, State>) -> ClaimGuard<'a, T> {
        let tid = crate::waitqueue::caller_tid();
        g.busy = true;
        g.owner = tid;
        if tid != 0 { let _ = CLAIM_HELD.raise(tid); }
        if CANARY_MUTEX_HELD.load(Ordering::Relaxed) == self as *const Self as usize {
            return ClaimGuard { claim: self, held: Some(g) };
        }
        drop(g);
        ClaimGuard { claim: self, held: None }
    }
}

impl<T> core::ops::Deref for ClaimGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: this guard is the one owner (`Claim::acquire`).
        unsafe { &*self.claim.data.get() }
    }
}

impl<T> core::ops::DerefMut for ClaimGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`.
        unsafe { &mut *self.claim.data.get() }
    }
}

impl<T> Drop for ClaimGuard<'_, T> {
    fn drop(&mut self) {
        let c = self.claim;
        let mut g = match self.held.take() {
            Some(g) => g,
            None => c.st.lock(),
        };
        let tid = g.owner;
        g.busy = false;
        g.owner = 0;
        c.gen.fetch_add(1, Ordering::SeqCst);
        drop(g);
        if tid != 0 { CLAIM_HELD.lower(tid); }
        c.wq.wake_all();
    }
}
