// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Futex wait, wake and requeue (wave 13, THREADS; wave 15 N9): the kernel
//! side of the table in [`crate::futex_table`].
//!
//! The native calls (`SYS_FUTEX_WAIT`/`WAKE`) and the Linux `futex` with
//! `FUTEX_PRIVATE_FLAG` file a [`Key::Private`] under the caller's process
//! id; a Linux futex without the flag on a word of a shm region files a
//! [`Key::Shared`] (Kconfig `FUTEX_SHARED`), the key the native notify calls
//! use, so both meet. The no-lost-wake argument is the table's.
//!
//! A waiter blocks on `WaitReason::Timer(deadline)` and a wake addresses it
//! by TID with that reason. A forced stop (`exit_group`, a kill) wakes it
//! through the same wake; it answers `EINTR` and the stop takes it at its
//! syscall boundary. Under the Linux personality a signal to deliver ends
//! the wait with `EINTR` as well, as on Linux.

use core::sync::atomic::{AtomicBool, Ordering};

pub use crate::futex_table::Key;
use crate::futex_table::{self as ft, FutexEnv, WaitResult};
use crate::task::WaitReason;

/// Linux errno values the calls answer with (the native ABI uses the same).
pub const EAGAIN: i64 = 11;
pub const EINTR: i64 = 4;
pub const EFAULT: i64 = 14;
pub const EINVAL: i64 = 22;
pub const ENOSYS: i64 = 38;
pub const ETIMEDOUT: i64 = 110;

/// The kernel's environment: block on the timer reason, wake by TID.
struct KernelEnv;

impl FutexEnv for KernelEnv {
    fn now(&self) -> u64 {
        azos_drv_sys::timebase::now()
    }
    fn block(&self, deadline: u64) -> bool {
        crate::wait::task_block_outcome(WaitReason::Timer(deadline)) == crate::wait::BlockOutcome::Refused
    }
    fn wake(&self, tid: u32, _deadline: u64) {
        crate::scheduler::wake_task_by_tid(tid, &|r| matches!(r, WaitReason::Timer(_)));
    }
    fn stopped(&self) -> bool {
        // A forced stop, or (Linux personality) a signal to deliver: Linux
        // ends a futex wait with EINTR then (plan note CB 09-10).
        crate::scheduler::current_stop_request().is_some()
            || (azos_limits::LINUX_ABI && crate::scheduler::signal::current_deliverable())
    }
}

/// Runtime canary `canary=futex-requeue-wake-all`: a requeue wakes every
/// waiter and moves none (the herd a requeue exists to avoid).
static CANARY_REQUEUE_WAKE_ALL: AtomicBool = AtomicBool::new(false);

/// Arm the `futex-requeue-wake-all` canary (boot only).
pub fn canary_requeue_wake_all() {
    CANARY_REQUEUE_WAKE_ALL.store(true, Ordering::Relaxed);
}

/// The calling task's private key for user address `addr`.
pub fn private_key(addr: u64) -> Option<Key> {
    let idx = crate::scheduler::current_slot()?;
    let tid = crate::scheduler::current_task_tid();
    Some(Key::Private { domain: crate::group::proc_of(idx, tid), addr })
}

fn errno(r: WaitResult) -> i64 {
    match r {
        WaitResult::Woken | WaitResult::OwnerDied => 0,
        WaitResult::TimedOut => -ETIMEDOUT,
        WaitResult::ValueChanged | WaitResult::NoSpace => -EAGAIN,
        WaitResult::Fault => -EFAULT,
        WaitResult::Refused | WaitResult::Stopped => -EINTR,
    }
}

/// Wait on `key` while `read()` holds `expected`, until a wake, the absolute
/// deadline (timer ticks; `None`: none) or a forced stop. Returns 0 (woken),
/// `-EAGAIN` (the word differs), `-ETIMEDOUT`, `-EINTR` or `-EFAULT`.
pub fn wait_key(key: Key, expected: u32, deadline: Option<u64>, read: &dyn Fn() -> Option<u32>) -> i64 {
    // Read before taking the lock as well: a word that is not readable is
    // refused without the table held, and the read under the lock is then
    // of a page already resolved.
    if read().is_none() {
        return -EFAULT;
    }
    let tid = crate::scheduler::current_task_tid();
    errno(ft::wait_key(&KernelEnv, tid, key, read, expected, deadline.unwrap_or(u64::MAX)))
}

/// Wait on the user word at `addr` (the caller's private key) while it holds
/// `expected`. `read` reads a user word (`None`: not readable).
pub fn wait(addr: u64, expected: u32, deadline: Option<u64>, read: &dyn Fn(u64) -> Option<u32>) -> i64 {
    if addr & 3 != 0 {
        return -EFAULT;
    }
    let Some(key) = private_key(addr) else { return -EFAULT };
    wait_key(key, expected, deadline, &|| read(addr))
}

/// Wake at most `n` waiters on `key`. Returns how many were woken.
pub fn wake_key(key: Key, n: u32) -> i64 {
    // Gate canary only: a wake that wakes nobody (the joins and the contended
    // locks of the thread rows never return).
    if cfg!(feature = "futex-wake-noop-canary") {
        return 0;
    }
    ft::wake_key(&KernelEnv, key, n, false) as i64
}

/// Wake at most `n` waiters on the current process's word at `addr`.
pub fn wake(addr: u64, n: u32) -> i64 {
    match private_key(addr) {
        Some(k) => wake_key(k, n),
        None => 0,
    }
}

/// [`wake`] for process `proc_id` (the exit path's clear-tid wake, which runs
/// as the exiting member).
pub fn wake_in(proc_id: u32, addr: u64, n: u32) -> i64 {
    wake_key(Key::Private { domain: proc_id, addr }, n)
}

/// Linux `FUTEX_REQUEUE` (`cmp` `None`) / `FUTEX_CMP_REQUEUE`: wake up to
/// `nr_wake` waiters on `from`, move up to `nr_requeue` more to `to`.
/// Returns `(woken, moved)`, `-EAGAIN` when `read()` does not hold `cmp`, `-ENOSYS` with
/// Kconfig `FUTEX_REQUEUE` off.
pub fn requeue(
    from: Key, to: Key, nr_wake: u32, nr_requeue: u32, cmp: Option<u32>, read: &dyn Fn() -> Option<u32>,
) -> Result<(u32, u32), i64> {
    if !ft::REQUEUE {
        return Err(-ENOSYS);
    }
    if !from.same_kind(&to) {
        return Err(-EINVAL);
    }
    let wake_all = CANARY_REQUEUE_WAKE_ALL.load(Ordering::Relaxed);
    ft::requeue_key(&KernelEnv, from, to, nr_wake, nr_requeue, cmp.map(|c| (read, c)), wake_all)
        .map_err(errno)
}
