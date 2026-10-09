// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-CPU deferred-wake list: a lock-free multi-producer, single-consumer
//! intrusive list of task slots (`SCHED_REMOTE_WAKE_DEFER`).
//!
//! A wake that targets another CPU's ready queue used to spin on that CPU's
//! `CPU_LOCKS` word with interrupts masked, from any context, the timer ISR
//! included. That spin is unbounded by anything this hart controls: the
//! holder may not run until this hart stops (QEMU `-icount` runs the harts
//! one at a time; a preempted vCPU behaves the same). When the target's lock
//! is held the waker now pushes the slot here instead and rings the target's
//! doorbell; the target enqueues it on its own queue, with its own lock, at
//! its next `do_schedule` (the doorbell's reschedule leads there). This is
//! the shape of Linux's `ttwu_queue_wakelist` / `sched_ttwu_pending`.
//!
//! One link per task slot is enough: a slot is pushed only by the waker that
//! won its Blocked→Ready transition, and it cannot block again (so cannot be
//! woken, so cannot be pushed again) before the drain has queued it and it
//! has run. Push is one CAS loop on the head; the drain takes the whole list
//! with one swap and reverses it, so slots come out in push order (the
//! same-priority FIFO order a direct enqueue would have produced).
//!
//! In its own file, with no dependency, so `tests/host/sched-wake-tests`
//! compiles it unmodified.

use core::sync::atomic::{AtomicU32, Ordering};

/// The empty link / empty list.
pub const NIL: u32 = u32::MAX;

/// Push `slot` onto the list headed by `head`, linking through `next`.
/// Release: the waker's writes to the task (state, `tp`, reason) are
/// visible to the drain that takes this entry.
#[inline]
pub fn push(head: &AtomicU32, next: &[AtomicU32], slot: usize) {
    let me = slot as u32;
    let mut h = head.load(Ordering::Relaxed);
    loop {
        next[slot].store(h, Ordering::Relaxed);
        match head.compare_exchange_weak(h, me, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return,
            Err(cur) => h = cur,
        }
    }
}

/// Is the list empty? One relaxed load: a hint for "a drain has work" and
/// for keeping later direct wakes behind earlier deferred ones.
#[inline(always)]
pub fn is_empty(head: &AtomicU32) -> bool {
    head.load(Ordering::Relaxed) == NIL
}

/// Take every entry and call `f` on each, oldest push first. Only the
/// list's owner (the target CPU) calls this. Returns the number taken.
#[inline]
pub fn drain(head: &AtomicU32, next: &[AtomicU32], mut f: impl FnMut(usize)) -> usize {
    if is_empty(head) {
        return 0;
    }
    // Acquire pairs with every push's Release.
    let mut cur = head.swap(NIL, Ordering::Acquire);
    // Reverse the LIFO chain in place: the links are ours now.
    let mut prev = NIL;
    while cur != NIL {
        let n = next[cur as usize].load(Ordering::Relaxed);
        next[cur as usize].store(prev, Ordering::Relaxed);
        prev = cur;
        cur = n;
    }
    let mut taken = 0;
    cur = prev;
    while cur != NIL {
        // Read the link before `f`: once queued the slot can run, block and
        // be pushed again (rewriting its link) on another CPU.
        let n = next[cur as usize].load(Ordering::Relaxed);
        f(cur as usize);
        taken += 1;
        cur = n;
    }
    taken
}
