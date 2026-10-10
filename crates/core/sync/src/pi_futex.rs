// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PI futexes on the wait graph (wave 15 N10): the seam between the futex
//! table's per-bucket `pi_state` slot (N9) and the graph (N7).
//!
//! **Interface only.** N10 implements [`PiFutexOps`]; N9's bucket code calls
//! it through the two traits below and needs no other change. Kconfig
//! `FUTEX_PI` (default n, depends on `WAIT_GRAPH`): n, the PI operations
//! return `ENOSYS` exactly as today.
//!
//! # The word (Linux protocol, bit-exact)
//!
//! `TID | FUTEX_WAITERS | FUTEX_OWNER_DIED`. 0 is free. User space takes a
//! free word with `cmpxchg(0 -> TID)` and releases an uncontended one with
//! `cmpxchg(TID -> 0)`; the kernel is entered only when that fails. The
//! kernel sets `FUTEX_WAITERS` before a waiter sleeps, so the owner's
//! user-space release fails and enters `UNLOCK_PI`. Constants equal
//! `azos_abi::ROBUST_*` and `azos_linux_abi::robust::FUTEX_*` (N10 adds the
//! `const` assertion where both crates are visible).
//!
//! # Operations (Linux semantics, `man 2 futex`)
//!
//! * `LOCK_PI`: no TID in the word -> take it (`TID | (word & OWNER_DIED)`:
//!   the bit is kept, user space reports `EOWNERDEAD` from it), return 0.
//!   Owned -> attach/create the `pi_state` (owner = word's TID, `ESRCH` if
//!   no such task in the caller's futex namespace), set `FUTEX_WAITERS`,
//!   block on the graph (`EdgeKind::FutexPi`), sleep; `EDEADLK` on a cycle
//!   or when the caller is the owner; `ETIMEDOUT` (absolute
//!   `CLOCK_REALTIME`, or `CLOCK_MONOTONIC` for `LOCK_PI2`); `EINTR` never
//!   (the call restarts).
//! * `TRYLOCK_PI`: as `LOCK_PI` without sleeping: `EAGAIN` if owned. Also
//!   takes over an `OWNER_DIED` word with no live owner.
//! * `UNLOCK_PI`: caller must own the word (`EPERM` otherwise). No waiters
//!   -> word = 0. Waiters -> ownership passes to the top waiter **in the
//!   kernel**: word = `new TID | FUTEX_WAITERS if more remain`, the graph
//!   unboosts the caller, the new owner wakes already holding the lock.
//! * `WAIT_REQUEUE_PI` (cond var wait, `uaddr` -> PI `uaddr2`) and
//!   `CMP_REQUEUE_PI` (`nr_wake` must be 1, `uaddr != uaddr2`, else
//!   `EINVAL`): the waker atomically tries to take `uaddr2` for the top
//!   waiter (it wakes owning it), and moves the rest onto `uaddr2`'s
//!   `pi_state` as graph waiters without waking them (no thundering herd).
//! * Owner died: the exit path's robust-list walk calls
//!   [`PiFutexOps::owner_died`] for every PI word the dying task owns: the
//!   word gets `FUTEX_OWNER_DIED`, ownership passes to the top waiter as in
//!   `UNLOCK_PI` (it returns with the bit set; user space sees
//!   `EOWNERDEAD`), or the word stays `OWNER_DIED` with no TID when nobody
//!   waits.
//!
//! # Locking
//!
//! Bucket SpinLock (N9) -> `PiWaiters` wait lock (N7) -> per-task PI lock ->
//! run-queue lock. The enqueue happens under the bucket lock
//! (`waitgraph::block_prepare`), the walk after it is dropped
//! (`waitgraph::block_commit`), the sleep last. A `pi_state` is freed only
//! after a grace period (`call_rcu`) once its last waiter left.

use crate::waitgraph::{PendingBlock, TaskId};

/// Kconfig `FUTEX_PI`.
pub const ENABLED: bool = azos_limits::FUTEX_PI;

/// The owner's TID (Linux `FUTEX_TID_MASK`).
pub const FUTEX_TID_MASK: u32 = 0x3FFF_FFFF;
/// The last owner died holding the word (Linux `FUTEX_OWNER_DIED`).
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
/// Someone may sleep on the word; unlock must enter the kernel (Linux
/// `FUTEX_WAITERS`).
pub const FUTEX_WAITERS: u32 = 0x8000_0000;

/// The owner TID a word names, `None` for 0.
#[inline]
pub const fn word_owner(w: u32) -> Option<u32> {
    let t = w & FUTEX_TID_MASK;
    if t == 0 { None } else { Some(t) }
}

/// The word an in-kernel handover writes: the new owner, `FUTEX_WAITERS` if
/// more waiters remain, and `FUTEX_OWNER_DIED` only for a handover from
/// [`PiFutexOps::owner_died`] (`UNLOCK_PI` clears it, as Linux does).
#[inline]
pub const fn handover_word(new_owner: u32, more_waiters: bool, owner_died: bool) -> u32 {
    (new_owner & FUTEX_TID_MASK)
        | if more_waiters { FUTEX_WAITERS } else { 0 }
        | if owner_died { FUTEX_OWNER_DIED } else { 0 }
}

/// A `pi_state` in N10's pool: what N9's per-bucket slot stores. Raw value
/// 0 is reserved for "empty", so N9 may keep the slot as a plain `u32`
/// (`PiStateId::from_raw`/`raw`) or as `Option<PiStateId>`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PiStateId(core::num::NonZeroU32);

impl PiStateId {
    pub const fn from_raw(v: u32) -> Option<Self> {
        match core::num::NonZeroU32::new(v) {
            Some(n) => Some(PiStateId(n)),
            None => None,
        }
    }

    pub const fn raw(self) -> u32 {
        self.0.get()
    }
}

/// A fault reading or writing the user word (unmapped, not writable):
/// `EFAULT` to user space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UserFault;

/// What N9 lends the PI code for one futex key, **under its bucket lock**.
/// N9 implements it on its bucket guard; N10 never sees the bucket layout.
pub trait PiBucket {
    /// The `pi_state` slot of THIS futex key (0 = none): one per key/entry
    /// in the bucket, never one shared by the whole bucket.
    fn pi_slot(&mut self) -> &mut u32;
    /// Atomic read of the user word, faults reported, no sleep (the bucket
    /// lock is a SpinLock: N9 pre-faults the page before taking it, as
    /// Linux's `fault_in_user_writeable` retry loop does).
    fn read_word(&self) -> Result<u32, UserFault>;
    /// Atomic compare-and-exchange on the user word; returns the value seen.
    fn cmpxchg_word(&mut self, expected: u32, new: u32) -> Result<u32, UserFault>;
    /// The TID of a task in the caller's futex namespace, as a scheduler
    /// slot, or `None` (`ESRCH`).
    fn task_of_tid(&self, tid: u32) -> Option<TaskId>;
}

/// Result of the under-lock half of `LOCK_PI` / `WAIT_REQUEUE_PI`.
#[must_use]
pub enum LockPiStep {
    /// The caller owns the word now; return 0.
    Acquired,
    /// The caller is enqueued; N9 drops the bucket lock, then calls
    /// `waitgraph::block_commit(pending)`, then sleeps until woken or the
    /// timeout, then calls [`PiFutexOps::lock_pi_finish`].
    Block(PendingBlock),
    /// Return `-errno` (EAGAIN for TRYLOCK_PI owned, EDEADLK, ESRCH,
    /// EFAULT, EINVAL).
    Err(i32),
}

/// The PI futex operations N9's dispatcher calls. **Implemented by N10.**
///
/// Every `&mut dyn PiBucket` argument is valid only under that bucket's
/// lock; no method sleeps; each is O(1) plus the graph's O(W) enqueue.
pub trait PiFutexOps: Sync {
    /// `LOCK_PI`, `LOCK_PI2` and `TRYLOCK_PI` (`try_only`), under the lock.
    fn lock_pi_prepare(&self, b: &mut dyn PiBucket, me: TaskId, try_only: bool) -> LockPiStep;

    /// After the sleep, under the bucket lock again: if the caller now owns
    /// the word, fix the word (`TID | WAITERS if more`, `OWNER_DIED` kept
    /// when the handover came from `owner_died`) and return 0; on timeout
    /// leave the graph (`UnblockReason::Timeout`) and return `-ETIMEDOUT`
    /// (unless ownership arrived meanwhile: then 0, as Linux).
    fn lock_pi_finish(&self, b: &mut dyn PiBucket, me: TaskId, timed_out: bool) -> i32;

    /// `UNLOCK_PI`, under the lock. Returns the task to wake (the new
    /// owner), which N9 wakes after dropping the lock, or `-errno`.
    fn unlock_pi(&self, b: &mut dyn PiBucket, me: TaskId) -> Result<Option<TaskId>, i32>;

    /// `CMP_REQUEUE_PI` with both buckets locked (N9 locks them in address
    /// order). `cmpval` is checked against `from`'s word first (`EAGAIN`).
    /// Returns (woken-and-owning, requeued) counts, or `-errno`.
    fn cmp_requeue_pi(
        &self,
        from: &mut dyn PiBucket,
        to: &mut dyn PiBucket,
        cmpval: u32,
        nr_requeue: u32,
    ) -> Result<(u32, u32), i32>;

    /// The robust-list walk found a PI word `dead` owned: set
    /// `FUTEX_OWNER_DIED` and hand over as `UNLOCK_PI` does. Returns the
    /// task to wake. Called from the exit path, task context, bucket locked.
    fn owner_died(&self, b: &mut dyn PiBucket, dead: TaskId) -> Result<Option<TaskId>, i32>;
}

/// Install N10's implementation. Called once at boot when `FUTEX_PI` is y;
/// N9's dispatcher reads [`ops`] and returns `ENOSYS` while it is `None`.
pub fn register(_ops: &'static dyn PiFutexOps) {
    todo!("N10")
}

/// The registered implementation, if any. Any context. O(1).
pub fn ops() -> Option<&'static dyn PiFutexOps> {
    if !ENABLED {
        return None;
    }
    todo!("N10")
}
