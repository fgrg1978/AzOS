// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 13 (RT7): a tick that lands while a task holds a `SpinLock` is a
//! preemption, deferred to the guard's drop — and is counted as one
//! (`preempt-account-smoke`).
//!
//! On hart [`HART`], a spinner at the same priority stays Ready while the
//! measured task holds a `SpinLock` (interrupts on) until a tick finds the
//! spinner should run and, the hart being in a critical section, records a
//! debt (`tick_admit`'s Defer arm), or [`HOLD_MAX_MS`] passes; the drop pays
//! the debt with a switch to the spinner. The hold ends on the debt, not on
//! a fixed time: under EEVDF a tick records one only once the spinner beats
//! the holder, which a holder woken with lag credit (up to two lag limits,
//! 20 ms at 100 Hz) plus a slice does not do inside a short fixed hold. The measured task's own counts across the hold must read
//! `preempted +N (N >= 1)` and `voluntary +0`: it never yielded or blocked.
//! Before wave 13 the debt was paid through `task_yield` and counted as
//! voluntary, so `DOMAIN_TASKINFO`'s preempted count (vsbench's batch8 bound)
//! missed every tick that landed in a lock. One line:
//! `[PACCT] PASS voluntary +0 preempted +N` or `[PACCT] FAIL ...`.

use core::sync::atomic::{AtomicBool, Ordering};

use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};

const HART: i8 = 1;
const SETTLE_MS: u64 = 1_500;
/// The longest the holder waits for a deferred tick, in ms.
const HOLD_MAX_MS: u64 = 1_000;

static STOP: AtomicBool = AtomicBool::new(false);
/// For the ktest verdict ([`sched_deferred_tick_counted_as_preemption`]):
/// the holder's voluntary and preempted deltas across the hold, `u32::MAX`
/// until it measured them.
static DV: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
static DP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
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
        // Held across ticks on purpose (the scenario): not a hold lockdep
        // bounds by LOCK_MAX_HOLD_US.
        azos_sync::lockdep::hold_unbounded();
        let end = now() + ms(HOLD_MAX_MS);
        while !azos_sync::preempt::need_resched() && now() < end {
            *g = g.wrapping_add(1);
            core::hint::spin_loop();
        }
    } // the deferred preemption is paid here
    let (v1, p1) = azos_sched::scheduler::current_task_switches();
    STOP.store(true, Ordering::Release);
    let (dv, dp) = (v1.wrapping_sub(v0), p1.wrapping_sub(p0));
    DP.store(dp as u32, Ordering::Release);
    DV.store(dv as u32, Ordering::Release);
    if dv == 0 && dp >= 1 {
        kprintln!("[PACCT] PASS voluntary +{} preempted +{}", dv, dp);
    } else {
        kprintln!("[PACCT] FAIL voluntary +{} preempted +{} (want +0 / >= +1)", dv, dp);
    }
}

// A tick deferred by a SpinLock is a preemption: on CPU 1, a task holds a
// SpinLock with interrupts on while a same-priority spinner is Ready, until
// a tick defers a switch to it; that debt is paid at the guard's drop and must
// count as `preempted +N (N >= 1)`, `voluntary +0` (the rows `sched:
// deferred tick counted (rv|arm)`, `[PACCT] PASS voluntary +0 preempted
// +N`). Both tasks are pinned to CPU 1, so `-smp 4` runs the scenario the
// rows ran at `-smp 2`. Canary (2026-10-04, by hand, reverted): the
// deferred-resched callback back to `task_yield` gave 3 of 3 boots
// "voluntary +1 preempted +0".
#[cfg(feature = "ktest")]
azos_ktest::ktest_late! {
    fn sched_deferred_tick_counted_as_preemption() {
        if azos_percpu::nr_cpu_ids() < 2 {
            return Err("needs 2 CPUs (the scenario runs on CPU 1)");
        }
        spawn();
        crate::ktest::wait("the holder did not measure", || DV.load(Ordering::Acquire) != u32::MAX)?;
        let (dv, dp) = (DV.load(Ordering::Acquire), DP.load(Ordering::Acquire));
        if dv != 0 {
            Err("the holder was counted as switching voluntarily across the hold")
        } else if dp == 0 {
            Err("no preemption counted for the ticks deferred by the lock")
        } else {
            Ok(())
        }
    }
}
