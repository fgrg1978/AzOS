// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// WaitQueue — lightweight sleep/wake mechanism for blocking synchronization.
///
/// Tasks that call `wait()` are put to sleep (Blocked state) and removed
/// from the scheduler's ready queue. `wake_one()` / `wake_all()` move
/// them back to Ready.
///
/// # Scheduler decoupling
///
/// The sync crate cannot depend on the sched crate (sched depends on sync).
/// Instead, block/wake operations go through function pointers registered at
/// boot via `wq_set_callbacks()`. Before registration, `wait()` degrades to
/// a spinloop (safe for early boot).
///
/// # Protocol
///
/// The WaitQueue holds a fixed-size array of waiting task IDs. When a task
/// calls `wait()`:
///   1. Its TID is added to the waiters array.
///   2. The scheduler callback blocks the task (Blocked state).
///   3. On `wake_one()` / `wake_all()`, the wake callback is called for
///      each waiter TID, moving them back to Ready.
///
/// The internal lock is `crate::spinlock::SpinLock` (K-C29). This used to be
/// a hand-rolled TTAS spin — a bare `AtomicBool` plus `compare_exchange_weak`
/// plus `core::hint::spin_loop()`, with no preempt guard at all. That is
/// exactly the defect `SpinLock` itself was fixed for: the timer tick could
/// preempt whichever task held `lock`, and a higher-priority task on the same
/// hart calling `wait()`/`wake_one()`/`wake_all()`/`len()` would then spin on
/// it forever, because this kernel's strict, non-aging priority dispatch
/// never lets the (descheduled) holder run again. Routing through `SpinLock`
/// gives the internal lock that fix for free — see `spinlock.rs` for the
/// mechanism — instead of re-deriving a second, subtly different copy of it
/// here.

use core::sync::atomic::{AtomicUsize, Ordering};
use crate::spinlock::SpinLock;

/// Maximum number of tasks that can wait on a single WaitQueue simultaneously.
const WAITQUEUE_CAPACITY: usize = 16;

/// Callback: block the current task. fn() — puts calling task to Blocked.
pub static WQ_BLOCK_FN: AtomicUsize = AtomicUsize::new(0);

/// Callback: wake a specific task by TID. fn(tid: u32).
pub static WQ_WAKE_FN: AtomicUsize = AtomicUsize::new(0);
/// Who is asking — the CALLER's task id, read per CPU.
///
/// **Not `pi_mutex::CURRENT_TID`.** That is a single global the scheduler
/// overwrites on every context switch on ANY core, so with more than one
/// core a task could enqueue itself under the id of whatever task another
/// core happened to switch to. The wake then went to that other task and
/// the real waiter slept forever — measured on aarch64 with `-smp 2`
/// (2026-09-24): the waiter blocked, the producer woke it a hundred times,
/// and it never resumed.
static WQ_TID_FN: AtomicUsize = AtomicUsize::new(0);

/// Register scheduler callbacks for WaitQueue block/wake.
/// Must be called once during kernel init, before any WaitQueue usage.
pub fn wq_set_callbacks(block_fn: fn(), wake_fn: fn(u32), tid_fn: fn() -> u32) {
    WQ_BLOCK_FN.store(block_fn as usize, Ordering::Release);
    WQ_WAKE_FN.store(wake_fn as usize, Ordering::Release);
    WQ_TID_FN.store(tid_fn as usize, Ordering::Release);
}

/// The waiters array + count, protected by `WaitQueue::inner`.
///
/// `pub(crate)`, matching `WaitQueue::inner` itself — see that field's doc
/// for why `tests/host/sync-tests` needs to reach in.
pub(crate) struct WaitQueueInner {
    waiters: [u32; WAITQUEUE_CAPACITY],
    count:   usize,
}

/// A queue of tasks waiting for a condition to become true.
pub struct WaitQueue {
    /// `lock_irqsave()`, not `lock()`, at every call site below: this type's
    /// one production consumer, `Completion::complete()`
    /// (`crates/core/sync/src/completion.rs`), documents itself as callable from
    /// an IRQ handler. `SpinLock::lock()`'s own doc says to use the irqsave
    /// variant whenever that is true, and `CpuLockGuard` in
    /// `crates/core/sched/src/scheduler.rs` documents why mixing a plain spin with
    /// an irqsave spin on the *same* lock is not an option: an IRQ on the
    /// local hart could preempt a plain-spin holder and then spin forever
    /// waiting for itself.
    ///
    /// `pub(crate)`, not private: `tests/host/sync-tests` pulls this file in via
    /// `#[path]` as part of its own crate (see that crate's doc), and needs
    /// to reach `inner` directly to prove the guard is held for the right
    /// duration — `pub(crate)` grants that without widening visibility
    /// outside `azos_sync` itself in a normal build.
    pub(crate) inner: SpinLock<WaitQueueInner>,
}

impl WaitQueue {
    /// Create a new empty WaitQueue. Usable as `static`.
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::new(WaitQueueInner {
                waiters: [0; WAITQUEUE_CAPACITY],
                count:   0,
            }),
        }
    }

    /// Sleep the current task on this WaitQueue.
    ///
    /// The task is blocked until another task calls `wake_one()` or
    /// `wake_all()` on this queue.
    ///
    /// If scheduler callbacks are not yet registered (early boot), this
    /// degrades to a no-op spin — the caller must handle the fallback.
    pub fn wait(&mut self) {
        let tid = caller_tid();
        if tid == u32::MAX {
            // No scheduler running — spin fallback.
            core::hint::spin_loop();
            return;
        }

        // Add ourselves to the waiters list. Scoped so the guard — and the
        // preemption it holds off — drops here, BEFORE blocking: the wake
        // path also needs this lock, and blocking is a call into the
        // scheduler, not something to do mid-critical-section.
        {
            let mut inner = self.inner.lock_irqsave();
            if inner.count < WAITQUEUE_CAPACITY {
                let slot = inner.count;
                inner.waiters[slot] = tid;
                inner.count = slot + 1;
            }
        }

        // Block via scheduler callback.
        let block_ptr = WQ_BLOCK_FN.load(Ordering::Acquire);
        if block_ptr != 0 {
            let block_fn: fn() = unsafe { core::mem::transmute(block_ptr) };
            block_fn();
            // Returns here when woken.
        }
    }

    /// Enqueue and block, but only if `should_sleep()` still holds **under the
    /// queue's own lock**.
    ///
    /// # The lost wakeup this closes
    ///
    /// [`wait`](Self::wait) enqueues unconditionally, so a caller doing the
    /// natural thing —
    ///
    /// ```text
    /// while !done.load(Acquire) {   // (1) reads false
    ///     wq.wait();                // (3) enqueues, then blocks
    /// }
    /// ```
    ///
    /// — races a waker that runs entirely between (1) and (3):
    ///
    /// ```text
    /// done.store(true, Release);    // (2a)
    /// wq.wake_all();                // (2b) queue is empty; wakes nobody
    /// ```
    ///
    /// The waiter then blocks with the condition already satisfied and nobody
    /// left to wake it. `Completion::wait` had exactly that shape.
    ///
    /// Re-checking under `inner` closes it, because `wake_all`/`wake_one` take
    /// the same lock: either this call observes the condition already false and
    /// returns without sleeping, or it is enqueued before the waker can look at
    /// the queue.
    ///
    /// # What it does NOT close
    ///
    /// The window between releasing `inner` and entering the scheduler's block
    /// callback is unchanged, and is the scheduler's contract to honour — a
    /// wake landing there must not be lost. `wait` has the same window; this is
    /// not a new exposure.
    ///
    /// # The closure runs under a lock with preemption disabled
    ///
    /// `lock_irqsave` is held across it, so `should_sleep` must be a cheap,
    /// non-blocking predicate — an atomic load, not another lock and never
    /// anything that can yield. Passing something that blocks here deadlocks
    /// the waker.
    pub fn wait_if(&mut self, should_sleep: impl Fn() -> bool) {
        let tid = caller_tid();
        if tid == u32::MAX {
            // No scheduler running — spin fallback, as in `wait`.
            core::hint::spin_loop();
            return;
        }

        {
            let mut inner = self.inner.lock_irqsave();
            // The re-check and the enqueue are one critical section. This is
            // the whole point of the function.
            if !should_sleep() {
                return;
            }
            if inner.count < WAITQUEUE_CAPACITY {
                let slot = inner.count;
                inner.waiters[slot] = tid;
                inner.count = slot + 1;
            }
        }

        let block_ptr = WQ_BLOCK_FN.load(Ordering::Acquire);
        if block_ptr != 0 {
            let block_fn: fn() = unsafe { core::mem::transmute(block_ptr) };
            block_fn();
        }
    }

    /// Wake one waiting task (FIFO order).
    /// Returns `true` if a task was woken, `false` if the queue was empty.
    pub fn wake_one(&mut self) -> bool {
        let tid = {
            let mut inner = self.inner.lock_irqsave();
            if inner.count == 0 {
                return false;
            }
            let tid = inner.waiters[0];
            // Shift remaining waiters forward.
            for i in 1..inner.count {
                inner.waiters[i - 1] = inner.waiters[i];
            }
            inner.count -= 1;
            tid
        };

        do_wake(tid);
        true
    }

    /// Wake all waiting tasks.
    /// Returns the number of tasks woken.
    pub fn wake_all(&mut self) -> usize {
        let (n, tids) = {
            let mut inner = self.inner.lock_irqsave();
            let n = inner.count;
            // Copy TIDs out before releasing the lock.
            let mut tids = [0u32; WAITQUEUE_CAPACITY];
            tids[..n].copy_from_slice(&inner.waiters[..n]);
            inner.count = 0;
            (n, tids)
        };

        for i in 0..n {
            do_wake(tids[i]);
        }
        n
    }

    /// Returns the number of tasks currently waiting.
    pub fn len(&self) -> usize {
        self.inner.lock_irqsave().count
    }

    /// Returns `true` if no tasks are waiting.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Call the scheduler's wake callback for a single TID.
fn do_wake(tid: u32) {
    let wake_ptr = WQ_WAKE_FN.load(Ordering::Acquire);
    if wake_ptr != 0 {
        let wake_fn: fn(u32) = unsafe { core::mem::transmute(wake_ptr) };
        wake_fn(tid);
    }
}

/// Read current task TID from the PI mutex identity atomics.
/// Returns u32::MAX if no scheduler is running.
fn current_task_tid() -> u32 {
    crate::pi_mutex::CURRENT_TID.load(Ordering::Relaxed)
}

/// The caller's own task id: the registered per-CPU accessor when there is
/// one, and the single global only as a pre-registration fallback.
fn caller_tid() -> u32 {
    let ptr = WQ_TID_FN.load(Ordering::Acquire);
    if ptr != 0 {
        let f: fn() -> u32 = unsafe { core::mem::transmute(ptr) };
        return f();
    }
    current_task_tid()
}
