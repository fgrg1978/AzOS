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
///
/// # Two kinds of sleep
///
/// [`wait_if`](WaitQueue::wait_if) sleeps until a wake and nothing else bounds
/// it. It is for the sleeps whose wake is **proven** at the call site: the
/// waker publishes the condition (a counter, a word) *before* it wakes, and
/// the waiter re-checks that condition under this queue's own lock *after* it
/// is listed, so either the re-check sees the event or the waker finds the
/// waiter listed. Each such site says so in a comment (the lock, the idle
/// workers). What the proof cannot cover is a wake that is popped and not
/// delivered by the scheduler's side; for a sleep that waits for another task
/// or a device that is not a risk worth an unbounded hang, so
/// [`wait_if_for`](WaitQueue::wait_if_for) sleeps on a timer for at most one
/// slice (`waitstat::SLICE_NS`), is woken early as before, and counts the
/// slices that ended with no wake (`waitstat`), per site, for the board to
/// read.

use crate::spinlock::SpinLock;
use crate::waitstat::{self, Site};

/// Maximum number of tasks that can wait on a single WaitQueue simultaneously.
const WAITQUEUE_CAPACITY: usize = 16;

azos_common::ro_hook! {
    /// Callback: block the current task. fn() — puts calling task to Blocked.
    static WQ_BLOCK_FN: fn();
}

azos_common::ro_hook! {
    /// Callback: wake a specific task by TID. fn(tid: u32).
    static WQ_WAKE_FN: fn(u32);
}
azos_common::ro_hook! {
/// Who is asking — the CALLER's task id, read per CPU. A single global
/// the scheduler overwrote on every context switch on ANY core let a task
/// enqueue itself under the id of whatever task another core had just
/// switched to; the wake then went to that other task and the real waiter
/// slept forever (measured on aarch64 with `-smp 2`, 2026-09-24). So the id
/// is only ever read through this per-CPU accessor.
static WQ_TID_FN: fn() -> u32;
}

/// How a timed block ended ([`wq_set_timed_callbacks`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Slept {
    /// The scheduler refused to block (a critical section is open on this
    /// hart): no time passed and no event occurred.
    Refused,
    /// The task blocked or consumed a pending wake, and the deadline had not
    /// passed when it came back.
    Woken,
    /// The deadline had passed when it came back.
    Expired,
}

azos_common::ro_hook! {
    /// Callback: block the current task on a timer for at most the given
    /// nanoseconds (a TID wake ends it early). fn(slice_ns) -> how it ended.
    static WQ_BLOCK_FOR_FN: fn(u64) -> Slept;
}

azos_common::ro_hook! {
    /// Callback: wake a task that blocked through [`WQ_BLOCK_FOR_FN`], by TID.
    /// It is blocked on a timer, not on the wait queue reason, so the plain
    /// wake callback does not reach it.
    static WQ_WAKE_TIMED_FN: fn(u32);
}

/// Register the timed block and its wake (see [`WaitQueue::wait_if_for`]).
/// Without them `wait_if_for` is `wait_if`.
pub fn wq_set_timed_callbacks(block_for_fn: fn(u64) -> Slept, wake_timed_fn: fn(u32)) {
    WQ_WAKE_TIMED_FN.set(wake_timed_fn);
    WQ_BLOCK_FOR_FN.set(block_for_fn);
}

/// Forget the timed callbacks: host tests that must see `wait_if_for` without
/// them (hosted builds only; a bare-metal hook is set once).
#[cfg(not(target_os = "none"))]
pub fn wq_clear_timed_callbacks() {
    WQ_BLOCK_FOR_FN.clear_for_tests();
    WQ_WAKE_TIMED_FN.clear_for_tests();
}

/// Set in a waiter list entry whose sleeper blocked on a timer: its wake goes
/// through [`WQ_WAKE_TIMED_FN`]. A task id never has it (`is_task`).
const TIMED: u32 = 1 << 31;

/// Register scheduler callbacks for WaitQueue block/wake.
/// Must be called once during kernel init, before any WaitQueue usage.
pub fn wq_set_callbacks(block_fn: fn(), wake_fn: fn(u32), tid_fn: fn() -> u32) {
    WQ_BLOCK_FN.set(block_fn);
    WQ_WAKE_FN.set(wake_fn);
    WQ_TID_FN.set(tid_fn);
}

/// The waiters array + count, protected by `WaitQueue::inner`.
///
/// `pub(crate)`, matching `WaitQueue::inner` itself — see that field's doc
/// for why `tests/host/sync-tests` needs to reach in.
pub(crate) struct WaitQueueInner {
    pub(crate) waiters: [u32; WAITQUEUE_CAPACITY],
    pub(crate) count:   usize,
}

/// A queue of tasks waiting for a condition to become true.
pub struct WaitQueue {
    /// `lock_irqsave()`, not `lock()`, at every call site below: a waker
    /// of this type (the virtio-blk completion, for one) may run in an IRQ
    /// handler. `SpinLock::lock()`'s own doc says to use the irqsave
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
    /// Create a new empty WaitQueue. Usable as `static`. With lockdep compiled
    /// in, the call site is its inner lock's class.
    #[cfg_attr(feature = "lockdep", track_caller)]
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
    #[cfg_attr(feature = "lockdep", track_caller)]
    pub fn wait(&self) {
        let tid = caller_tid();
        if !is_task(tid) {
            // No scheduler running, or no task to wake — spin fallback.
            core::hint::spin_loop();
            return;
        }
        crate::lockdep::might_sleep("WaitQueue::wait");

        // Add ourselves to the waiters list. Scoped so the guard — and the
        // preemption it holds off — drops here, BEFORE blocking: the wake
        // path also needs this lock, and blocking is a call into the
        // scheduler, not something to do mid-critical-section.
        {
            let mut inner = self.inner.lock_irqsave();
            // A full queue would block a task no wake can reach (it used to:
            // the 17th waiter slept with no entry). Return instead; `wait`
            // is a "something may have changed" sleep, so the caller looks
            // again, as it does after any wake.
            if inner.count >= WAITQUEUE_CAPACITY {
                return;
            }
            let slot = inner.count;
            inner.waiters[slot] = tid;
            inner.count = slot + 1;
        }

        self.block_and_leave(tid);
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
    /// left to wake it.  A one-shot completion flag had exactly that shape.
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
    /// # The sleep has no deadline
    ///
    /// A wake that pops a waiter and does not reach it leaves the task asleep
    /// for good, and nothing bounds this sleep. One such hang is on record
    /// and its cause is NOT found: an OTA receive with QEMU paused (`SIGSTOP`,
    /// 20-10) left `ota-recv` blocked in a block read with the queue empty
    /// and the request layer's epoch 300 signals on. This file accounts for
    /// three ways a wake is dropped, fixed here (a stale entry that a later
    /// `wake_one` pops instead of the sleeper; a full queue that blocked with
    /// no entry; TID 0, which no wake reaches); none is shown to be that hang,
    /// and the scheduler's side of the hand-off (a stamp left on a task that
    /// blocks on another reason first; `reap_orphaned_stamp` needing a timer
    /// tick) is not ruled out. So a caller uses this function only where the
    /// wake is proven at the site (module doc, "Two kinds of sleep"), and
    /// [`wait_if_for`](Self::wait_if_for) everywhere else. The block request
    /// layer sleeps on a timer of its own (`queue::Sleepers`), so the hang on
    /// record cannot recur there as a hang.
    ///
    /// # The closure runs under a lock with preemption disabled
    ///
    /// `lock_irqsave` is held across it, so `should_sleep` must be a cheap,
    /// non-blocking predicate — an atomic load, not another lock and never
    /// anything that can yield. Passing something that blocks here deadlocks
    /// the waker.
    #[cfg_attr(feature = "lockdep", track_caller)]
    pub fn wait_if(&self, should_sleep: impl Fn() -> bool) {
        let tid = caller_tid();
        if !is_task(tid) {
            // No scheduler running, or no task to wake — spin fallback, as
            // in `wait`.
            core::hint::spin_loop();
            return;
        }
        crate::lockdep::might_sleep("WaitQueue::wait_if");

        {
            let mut inner = self.inner.lock_irqsave();
            // The re-check and the enqueue are one critical section. This is
            // the whole point of the function.
            if !should_sleep() {
                return;
            }
            // A full queue would block a task no wake can reach. A
            // `wait_if` caller re-checks its condition in a loop, so return
            // instead: it retries (a spin) rather than sleeping forever.
            if inner.count >= WAITQUEUE_CAPACITY {
                return;
            }
            let slot = inner.count;
            inner.waiters[slot] = tid;
            inner.count = slot + 1;
        }

        self.block_and_leave(tid);
    }

    /// [`wait_if`](Self::wait_if) that sleeps on a timer for at most one slice
    /// (`waitstat::SLICE_NS`, Kconfig `WAIT_SLICE_US`): a wake ends it early as
    /// before, and a wake that never comes costs the caller a slice and not
    /// the task. The caller re-checks its condition in a loop, as it does after
    /// any return from `wait_if`.
    ///
    /// A sleep that ends at its deadline with the caller's entry still listed
    /// (so no waker popped it) is counted for `site` (`waitstat`); if the
    /// condition (`should_sleep` now false) had become true by then, the wake
    /// that should have ended the sleep did not come within the slice: a lost
    /// wake, the signature the kernel exports for a board boot to read.
    ///
    /// Without the timed callbacks ([`wq_set_timed_callbacks`]) this is
    /// `wait_if`. Same contract for `should_sleep`: it runs under the queue's
    /// lock with preemption off, so a cheap atomic predicate.
    #[cfg_attr(feature = "lockdep", track_caller)]
    pub fn wait_if_for(&self, site: Site, should_sleep: impl Fn() -> bool) {
        let (Some(block_for), Some(_)) = (WQ_BLOCK_FOR_FN.get(), WQ_WAKE_TIMED_FN.get()) else {
            return self.wait_if(should_sleep);
        };
        let tid = caller_tid();
        if !is_task(tid) {
            core::hint::spin_loop();
            return;
        }
        crate::lockdep::might_sleep("WaitQueue::wait_if_for");

        {
            let mut inner = self.inner.lock_irqsave();
            if !should_sleep() {
                return;
            }
            // Full: return and let the caller look again, as `wait_if` does.
            if inner.count >= WAITQUEUE_CAPACITY {
                return;
            }
            let slot = inner.count;
            inner.waiters[slot] = tid | TIMED;
            inner.count = slot + 1;
        }

        let slept = block_for(waitstat::SLICE_NS);
        let listed = self.leave(tid);
        if slept == Slept::Expired && listed {
            let lost = {
                let _g = self.inner.lock_irqsave();
                !should_sleep()
            };
            waitstat::note_expiry(site, lost);
        }
    }

    /// Block through the scheduler callback, then take `tid` off the list.
    ///
    /// **Why the second half.** Returning from the block does not mean a wake
    /// popped this task: a wake stamped earlier and left unconsumed (an
    /// interrupt wake that found the task not yet asleep), or a block the
    /// scheduler refused (`block_current` inside a critical section), return
    /// at once with the entry still listed. A stale entry is a hazard to the
    /// *next* sleeper, not to this one: `wake_one` pops it and delivers the
    /// wake to a task that is not asleep here — it is stamped, or ignored
    /// when blocked on something else — while the waiter that needed the wake
    /// stays asleep: a wake that popped a waiter without reaching it. Stale
    /// entries also fill the 16 slots, after which every `wait_if` returns
    /// without sleeping. A task has one registration at a time, so every
    /// entry with its TID is its own, and it removes them all.
    fn block_and_leave(&self, tid: u32) {
        if let Some(block_fn) = WQ_BLOCK_FN.get() {
            block_fn();
            // Returns here when woken.
        }
        self.leave(tid);
    }

    /// Take `tid`'s entries off the list; whether it had any, that is
    /// whether no waker had popped it.
    fn leave(&self, tid: u32) -> bool {
        let mut inner = self.inner.lock_irqsave();
        let n = inner.count;
        let mut kept = 0;
        for i in 0..n {
            let w = inner.waiters[i];
            if w & !TIMED != tid {
                inner.waiters[kept] = w;
                kept += 1;
            }
        }
        inner.count = kept;
        kept != n
    }

    /// Wake one waiting task (FIFO order).
    /// Returns `true` if a task was woken, `false` if the queue was empty.
    pub fn wake_one(&self) -> bool {
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
    pub fn wake_all(&self) -> usize {
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

/// Call the scheduler's wake callback for one list entry: a plain sleeper's
/// through [`WQ_WAKE_FN`], a timed one's ([`TIMED`]) through
/// [`WQ_WAKE_TIMED_FN`].
fn do_wake(entry: u32) {
    if entry & TIMED != 0 {
        if let Some(wake_fn) = WQ_WAKE_TIMED_FN.get() {
            wake_fn(entry & !TIMED);
        }
    } else if let Some(wake_fn) = WQ_WAKE_FN.get() {
        wake_fn(entry);
    }
}

/// `tid` names a task a wake can reach: not "no scheduler" (`u32::MAX`) and
/// not 0, which `current_task_tid` answers on a CPU with no current task and
/// `idx_for_tid` never matches, so a wake popped under it is dropped. Not
/// [`TIMED`] either: that bit marks a list entry.
fn is_task(tid: u32) -> bool {
    tid != 0 && tid & TIMED == 0
}

/// The caller's own task id: the registered per-CPU accessor's answer, or
/// `u32::MAX` (no task) before one is registered.
pub fn caller_tid() -> u32 {
    match WQ_TID_FN.get() {
        Some(f) => f(),
        None => u32::MAX,
    }
}
