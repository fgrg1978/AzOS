// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Futex wait and wake (wave 13, THREADS): the blocking half of user-space
//! locks, keyed by (process id, user address).
//!
//! Only process-private futexes: the key is the waiter's process id
//! (`group::proc_of`) and the word's user virtual address, so the members of
//! one thread group meet on a word and nothing outside the group can. A
//! "shared" futex (Linux without `FUTEX_PRIVATE_FLAG`) is served the same
//! way: two processes sharing a word through shared memory do not meet.
//!
//! # No lost wake
//!
//! [`wait`] checks the word and enqueues itself under the table lock; [`wake`]
//! takes the same lock to find its waiters. A waker that stored the new value
//! before the check makes the check fail (`EAGAIN`); one that stores after it
//! finds the waiter queued. The waiter then blocks on `WaitReason::Timer`
//! with its deadline, and the waker's TID-directed wake stamps
//! `wake_pending` if the waiter has not reached its block yet, so the block
//! returns at once (`scheduler::wake_task_by_tid`). The waiter re-checks its
//! entry after every return, so a spurious return costs a loop.
//!
//! A forced stop (`exit_group`, a kill) wakes the waiter through the same
//! `Timer` wake; it answers `EINTR` and the stop takes it at its syscall
//! boundary.
//!
//! The table is a leaf lock and holds at most one entry per task.

use azos_sync::spinlock::SpinLock;

use crate::task::{WaitReason, MAX_TASKS};

/// Linux errno values the calls answer with (the native ABI uses the same).
pub const EAGAIN: i64 = 11;
pub const EINTR: i64 = 4;
pub const EFAULT: i64 = 14;
pub const ETIMEDOUT: i64 = 110;

const FREE: u8 = 0;
const WAITING: u8 = 1;
const WOKEN: u8 = 2;

#[derive(Clone, Copy)]
struct Waiter {
    state: u8,
    tid: u32,
    proc_id: u32,
    addr: u64,
}

const W_FREE: Waiter = Waiter { state: FREE, tid: 0, proc_id: 0, addr: 0 };

static TABLE: SpinLock<[Waiter; MAX_TASKS]> = SpinLock::new([W_FREE; MAX_TASKS]);

/// Wait on the user word at `addr` while it holds `expected`, until a
/// [`wake`] for it, the absolute deadline `deadline` (timer ticks; `None`:
/// none) or a forced stop. `read` reads the word (`None`: not readable).
/// Returns 0 (woken), `-EAGAIN` (the word differs), `-ETIMEDOUT`, `-EINTR`
/// or `-EFAULT`.
pub fn wait(addr: u64, expected: u32, deadline: Option<u64>, read: &dyn Fn(u64) -> Option<u32>) -> i64 {
    if addr & 3 != 0 {
        return -EFAULT;
    }
    let Some(idx) = crate::scheduler::current_slot() else { return -EFAULT };
    let tid = crate::scheduler::current_task_tid();
    let proc_id = crate::group::proc_of(idx, tid);
    // Read before taking the lock as well: a word that is not readable is
    // refused without the table held, and the read under the lock below is
    // then of a page already resolved.
    if read(addr).is_none() {
        return -EFAULT;
    }
    let slot = {
        let mut t = TABLE.lock();
        match read(addr) {
            None => return -EFAULT,
            Some(v) if v != expected => return -EAGAIN,
            Some(_) => {}
        }
        let Some(i) = t.iter().position(|w| w.state == FREE) else { return -EAGAIN };
        t[i] = Waiter { state: WAITING, tid, proc_id, addr };
        i
    };
    let until = deadline.unwrap_or(u64::MAX);
    loop {
        {
            let mut t = TABLE.lock();
            let w = &mut t[slot];
            if w.state == WOKEN {
                *w = W_FREE;
                return 0;
            }
            let stop = crate::scheduler::current_stop_request().is_some();
            let late = deadline.is_some() && azos_drv_sys::timebase::now() >= until;
            if stop || late {
                *w = W_FREE;
                return if stop { -EINTR } else { -ETIMEDOUT };
            }
        }
        if crate::wait::task_block_outcome(WaitReason::Timer(until)) == crate::wait::BlockOutcome::Refused {
            // A critical section is open on this hart: no wait is possible.
            let mut t = TABLE.lock();
            let woken = t[slot].state == WOKEN;
            t[slot] = W_FREE;
            return if woken { 0 } else { -EINTR };
        }
    }
}

/// Wake at most `n` waiters on the current process's word at `addr`.
/// Returns how many were woken.
pub fn wake(addr: u64, n: u32) -> i64 {
    let Some(idx) = crate::scheduler::current_slot() else { return 0 };
    let proc_id = crate::group::proc_of(idx, crate::scheduler::current_task_tid());
    wake_in(proc_id, addr, n)
}

/// [`wake`] for process `proc_id` (the exit path's clear-tid wake, which runs
/// as the exiting member).
pub fn wake_in(proc_id: u32, addr: u64, n: u32) -> i64 {
    // Gate canary only: a wake that wakes nobody (the joins and the contended
    // locks of the thread rows never return).
    if cfg!(feature = "futex-wake-noop-canary") {
        return 0;
    }
    let mut tids = [0u32; 16];
    let mut woken = 0i64;
    loop {
        let mut k = 0usize;
        {
            let mut t = TABLE.lock();
            for w in t.iter_mut() {
                if woken + k as i64 >= n as i64 || k == tids.len() {
                    break;
                }
                if w.state == WAITING && w.proc_id == proc_id && w.addr == addr {
                    w.state = WOKEN;
                    tids[k] = w.tid;
                    k += 1;
                }
            }
        }
        for &tid in &tids[..k] {
            crate::scheduler::wake_task_by_tid(tid, &|r| matches!(r, WaitReason::Timer(_)));
        }
        woken += k as i64;
        if k < tids.len() || woken >= n as i64 {
            return woken;
        }
    }
}
