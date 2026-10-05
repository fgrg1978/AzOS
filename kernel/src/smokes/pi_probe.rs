// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! K-A14 probe — proves the PiMutex donation protocol on a SINGLE hart.
//!
//! The scenario is the one the old spinning implementation could not survive:
//! a low-priority holder and a higher-priority waiter pinned to the same CPU.
//! The holder does a fixed slab of work WITHOUT yielding, so the only way it
//! can ever reach its `release()` is if the waiter gives up the hart from
//! inside `lock()`. With the old spin-to-completion loop this deadlocked
//! outright; the boost was correct and useless, because the boosted task had
//! no CPU to run on.
//!
//! Asserts three things, not just liveness:
//!   1. the waiter eventually acquires (no hang),
//!   2. the holder was actually boosted to the waiter's priority while it held
//!      the lock — i.e. inheritance happened, rather than the waiter simply
//!      out-waiting it,
//!   3. the holder is back at its base priority afterwards, which is what
//!      proves donations and restores balanced.

use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use azos_sched::{
    task_create_affinity, task_exit, current_task_tid, task_priority,
    wq_block_current, wq_wake_by_tid,
};
use azos_sync::pi_mutex::PiMutex;

pub const PROBE_PRIO: u32 = 1;   // runner; blocks immediately, never spins
// Both must outrank the standing tasks or they never run: rt-motor and
// flight-ctrl sit at priority 8 in the RT band (not timer-preempted), so
// anything numerically above 8 is starved on CPU0. The i3 probe picks its
// bands for the same reason. What matters for this test is only that the
// waiter outranks the holder.
const WAITER_PRIO:    u32 = 4;   // contends, higher priority than the holder
const HOLDER_PRIO:    u32 = 6;   // owns the mutex, deliberately lower
const CPU0: i8 = 0;              // same hart: the whole point of the test

/// Enough work that the waiter is certainly contending while we hold the
/// lock, but bounded so a regression FAILs instead of hanging the board.
const HOLD_WORK: u32 = 2_000_000;

static M: PiMutex<u32> = PiMutex::new(0);

static RUNNER_TID: AtomicU32  = AtomicU32::new(0);
static HOLDER_TID: AtomicU32  = AtomicU32::new(0);
static ACQUIRED:   AtomicBool = AtomicBool::new(false);
/// Set by the waiter immediately before it calls `lock()`. The holder waits
/// for it before starting its no-yield work, so contention is guaranteed
/// rather than hoped for. Without this the test is a race against timer
/// granularity: under load the tick that would schedule the higher-priority
/// waiter arrives late, the holder finishes uncontended, no donation ever
/// happens, and a perfectly good implementation reports "no-boost".
static CONTENDING: AtomicBool = AtomicBool::new(false);
/// Best (numerically lowest) priority the holder saw while it held the lock.
static PRIO_WHILE_HELD: AtomicU32 = AtomicU32::new(u32::MAX);
/// Holder's priority immediately after `release()`, sampled by the holder
/// itself. Read from the runner instead and you race the reaper: the task
/// is usually already gone and `task_priority` returns None.
static PRIO_AFTER_RELEASE: AtomicU32 = AtomicU32::new(u32::MAX);

fn holder_entry(_: usize) {
    HOLDER_TID.store(current_task_tid(), Ordering::SeqCst);

    let g = M.lock();

    // Spawn the contender only after we own the lock. Doing the ordering
    // this way removes every busy-wait from the probe: no task ever spins
    // waiting for another to reach a phase. The waiter is higher priority,
    // so it preempts us the instant it is created and goes straight into
    // contention.
    let _ = task_create_affinity("pi-waiter", waiter_entry, 0, WAITER_PRIO, CPU0);

    // Setup, not the test: wait until the waiter is actually about to
    // contend. It outranks us and preempts us at its creation, so the
    // first look normally finds the flag set and nothing sleeps; the
    // sleep-poll and its ceiling (an unbounded yield loop before) only
    // matter if it did not. The measured section below is the one that
    // must make progress without us ever giving up the hart.
    if !azos_syscall::sleep::wait_until_ms(10_000, 1, || CONTENDING.load(Ordering::SeqCst)) {
        crate::kprintln!("[PISMOKE] FAIL setup: the waiter never contended in 10 s");
    }

    // Deliberately NO yield in here. The waiter must be the one to give up
    // the hart, from inside lock(). With the old spin-to-completion mutex
    // this never happened and the scenario deadlocked.
    // Sample repeatedly and keep the best (numerically lowest) priority
    // seen. A single sample at a fixed point is a race against when the
    // waiter happens to donate — it can easily land before the donation
    // and report "no boost" for a working implementation.
    let me = current_task_tid();
    let mut acc: u32 = 0;
    for i in 0..HOLD_WORK {
        acc = acc.wrapping_add(i);
        if i % 4_096 == 0 {
            if let Some(now) = task_priority(me) {
                let _ = PRIO_WHILE_HELD.fetch_update(
                    Ordering::SeqCst, Ordering::SeqCst,
                    |best| if now < best { Some(now) } else { None });
            }
        }
    }
    core::hint::black_box(acc);

    drop(g);
    PRIO_AFTER_RELEASE.store(
        task_priority(me).unwrap_or(u32::MAX), Ordering::SeqCst);
    task_exit();
}

fn waiter_entry(_: usize) {
    CONTENDING.store(true, Ordering::SeqCst);
    let g = M.lock();                 // must not hang
    ACQUIRED.store(true, Ordering::SeqCst);
    drop(g);
    wq_wake_by_tid(RUNNER_TID.load(Ordering::SeqCst));
    task_exit();
}

pub fn runner(_: usize) {
    RUNNER_TID.store(current_task_tid(), Ordering::SeqCst);
    let _ = task_create_affinity("pi-holder", holder_entry, 0, HOLDER_PRIO, CPU0);

    // Block, do not yield: this task is the highest priority in the system,
    // so yielding would just reschedule us and starve the very tasks we are
    // waiting for. Blocking removes us from the ready set entirely.
    while !ACQUIRED.load(Ordering::SeqCst) {
        wq_block_current();
    }

    let held  = PRIO_WHILE_HELD.load(Ordering::SeqCst);
    let after = PRIO_AFTER_RELEASE.load(Ordering::SeqCst);

    // Lower number = higher priority, so the donation landed iff the
    // holder's priority reached at least the waiter's level.
    if held > WAITER_PRIO {
        crate::kprintln!("[PISMOKE] FAIL no-boost held={} want<={}", held, WAITER_PRIO);
    } else if after != HOLDER_PRIO {
        // The donation must be undone exactly once. A value still at the
        // boosted level means a leaked boost; anything else means the
        // counter drifted.
        crate::kprintln!("[PISMOKE] FAIL not-restored after={} want={}",
                         after, HOLDER_PRIO);
    } else {
        crate::kprintln!("[PISMOKE] PASS boosted {}->{}, restored to {}",
                         HOLDER_PRIO, held, after);
    }
    task_exit();
}
