// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Completion — one-shot event signaling primitive.
///
/// A task calls `wait()` to sleep until another task (or IRQ handler)
/// calls `complete()`. Unlike a spinlock, the waiter releases the CPU
/// entirely while waiting.
///
/// Typical uses:
/// - Wait for driver init to finish before reading sensors.
/// - Wait for a DMA or SPI transfer to complete.
/// - Wait for a response from the brain server.
///
/// A Completion can be `complete()`-ed before anyone `wait()`-s — the
/// next `wait()` returns immediately without blocking.
///
/// # Reuse
///
/// Call `reset()` to reuse a Completion for another event cycle.

use core::sync::atomic::{AtomicBool, Ordering};
use crate::waitqueue::WaitQueue;

/// A one-shot completion event.
pub struct Completion {
    done: AtomicBool,
    wq:   WaitQueue,
}

// Safety: Completion uses AtomicBool + WaitQueue (both internally synced).
unsafe impl Send for Completion {}
unsafe impl Sync for Completion {}

impl Completion {
    /// Create a new incomplete Completion. Usable as `static`.
    pub const fn new() -> Self {
        Self {
            done: AtomicBool::new(false),
            wq:   WaitQueue::new(),
        }
    }

    /// Wait for the completion to be signaled.
    ///
    /// If `complete()` was already called, returns immediately.
    /// Otherwise, blocks the current task until `complete()` is called.
    pub fn wait(&mut self) {
        // Fast path: already completed.
        if self.done.load(Ordering::Acquire) {
            return;
        }

        // Slow path. `wait_if`, not `wait`, and the difference is a lost
        // wakeup rather than a style preference.
        //
        // With `wait()` the sequence was: read `done` as false, then enqueue.
        // A `complete()` running entirely between those two — `store(true)`
        // then `wake_all()` on a queue this task had not joined yet — woke
        // nobody, and this task then blocked with the completion already
        // signalled and no one left to signal it. Permanently.
        //
        // `wait_if` re-checks the predicate while holding the queue lock that
        // `wake_all` also takes, so the check and the enqueue are one critical
        // section: either `done` is already true and this returns without
        // sleeping, or the waker cannot get past the lock without seeing this
        // task in the queue.
        //
        // The outer loop stays: it handles a wake that arrives for another
        // reason, which the queue does not produce today.
        //
        // Destructured so `done` and `wq` are borrowed separately — the
        // closure needs the first while `wait_if` needs `&mut` on the second.
        let Self { done, wq } = self;
        while !done.load(Ordering::Acquire) {
            wq.wait_if(|| !done.load(Ordering::Acquire));
        }
    }

    /// Signal the completion, waking all waiters.
    ///
    /// Safe to call from any context including IRQ handlers
    /// (wake_all only touches atomics + scheduler wake callback).
    pub fn complete(&mut self) {
        self.done.store(true, Ordering::Release);
        self.wq.wake_all();
    }

    /// Returns `true` if the completion has been signaled.
    pub fn is_complete(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    /// Reset the completion for reuse.
    ///
    /// Must only be called when no tasks are waiting (i.e., after all
    /// waiters have observed `complete()` and resumed).
    pub fn reset(&mut self) {
        self.done.store(false, Ordering::Release);
    }
}
