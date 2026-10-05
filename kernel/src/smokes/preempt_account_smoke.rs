// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 13 (RT7): a tick that lands while a task holds a `SpinLock` is a
//! preemption, deferred to the guard's drop — and is counted as one
//! (`preempt-account-smoke`).
//!
//! On hart [`HART`], a spinner at the same priority stays Ready while the
//! measured task holds a `SpinLock` (interrupts on) for [`HOLD_MS`]: every
//! tick in that window finds the hart in a critical section and records a
//! debt (`tick_admit`'s Defer arm); the drop pays it with a switch to the
//! spinner. The measured task's own counts across the hold must read
//! `preempted +N (N >= 1)` and `voluntary +0`: it never yielded or blocked.
//! Before wave 13 the debt was paid through `task_yield` and counted as
//! voluntary, so `SYS_TASKINFO`'s preempted count (vsbench's batch8 bound)
//! missed every tick that landed in a lock. One line:
//! `[PACCT] PASS voluntary +0 preempted +N` or `[PACCT] FAIL ...`.

use core::sync::atomic::{AtomicBool, Ordering};

use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};

const HART: i8 = 1;
const SETTLE_MS: u64 = 1_500;
const HOLD_MS: u64 = 30;

static STOP: AtomicBool = AtomicBool::new(false);
static LOCK: azos_sync::SpinLock<u32> = azos_sync::SpinLock::new(0);

fn ms(n: u64) -> u64 {
    n * (TIMER_FREQ / 1000)
}

pub(crate) fn spawn() {
    azos_sched::task_create_affinity("pacct-spin", spinner, 0,
        azos_sched::DEFAULT_PRIORITY, HART);
    azos_sched::task_create_affinity("pacct-hold", holder, 0,
        azos_sched::DEFAULT_PRIORITY, HART);
}

fn spinner(_: usize) {
    while !STOP.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
}

fn holder(_: usize) {
    let t = now() + ms(SETTLE_MS);
    while now() < t {
        azos_sched::task_block(azos_sched::WaitReason::Timer(t));
    }
    let (v0, p0) = azos_sched::scheduler::current_task_switches();
    {
        let mut g = LOCK.lock();
        let end = now() + ms(HOLD_MS);
        while now() < end {
            *g = g.wrapping_add(1);
            core::hint::spin_loop();
        }
    } // the deferred preemption is paid here
    let (v1, p1) = azos_sched::scheduler::current_task_switches();
    STOP.store(true, Ordering::Release);
    let (dv, dp) = (v1.wrapping_sub(v0), p1.wrapping_sub(p0));
    if dv == 0 && dp >= 1 {
        kprintln!("[PACCT] PASS voluntary +{} preempted +{}", dv, dp);
    } else {
        kprintln!("[PACCT] FAIL voluntary +{} preempted +{} (want +0 / >= +1)", dv, dp);
    }
}
