// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! pi-flush-smoke: the flight recorder's `LOG_FILE` PiMutex, contended on one
//! hart of an SMP machine by the two tasks that contend it in production.
//!
//! `sys-wdt` (priority 11, pinned to hart 2) calls `logger_flush` every
//! ~500 ms. `behavior` (14, also hart 2) calls it through
//! `log_safety_violation_durable` when a brain e-stop lands. If the tick that
//! wakes `sys-wdt` falls inside `behavior`'s flush, `sys-wdt` preempts the
//! owner and waits on the mutex: it must donate to the owner, or the owner
//! loses every yield to it and neither runs again — the camera row's
//! intermittent phase-5 stall, where neither task printed another line after
//! the e-stop. Here a priority-14 flusher pinned to hart 2 holds the mutex
//! most of the time, so `sys-wdt` lands inside it on nearly every wake. The
//! flusher must finish `FLUSHES` flushes; a watcher on another hart reports
//! the count it reached if it does not. Before the `pi_mutex` fixes it
//! stopped within 13 flushes on every boot (3/3); with only some of the three
//! holes `pi_mutex.rs` documents closed (wrong owner, donation lost on
//! re-acquisition, lock held with no owner recorded) it still stopped on
//! every boot, after 3 to 308.

use core::sync::atomic::{AtomicU32, Ordering};
use crate::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};
use azos_sched::{task_block, task_create_affinity, task_exit, WaitReason};

const FLUSHES: u32 = 2000;
const HART: i8 = 2;
const WATCH_SECS: u64 = 90;
static DONE: AtomicU32 = AtomicU32::new(0);

pub fn spawn() {
    task_create_affinity("pi-flusher", flusher, 0, azos_sched::BEHAVIOR_PRIORITY, HART);
    task_create_affinity("pi-watch", watcher, 0, 5, 1);
    kprintln!("[PIFLUSH] flusher (prio {}) and sys-wdt share hart {}", azos_sched::BEHAVIOR_PRIORITY, HART);
}

fn flusher(_: usize) {
    task_block(WaitReason::Timer(now() + 3 * TIMER_FREQ));
    if !azos_actuation::logger::logger_active() {
        kprintln!("[PIFLUSH] FAIL no flight recorder on this boot (no disk?)");
        task_exit();
    }
    for i in 0..FLUSHES {
        azos_actuation::logger::log_error(0x7E, 0x7E, i);
        let _ = azos_actuation::logger::logger_flush();
        DONE.store(i + 1, Ordering::Release);
    }
    task_exit();
}

fn watcher(_: usize) {
    let deadline = now() + WATCH_SECS * TIMER_FREQ;
    while now() < deadline && DONE.load(Ordering::Acquire) < FLUSHES {
        task_block(WaitReason::Timer(now() + TIMER_FREQ / 2));
    }
    let d = DONE.load(Ordering::Acquire);
    if d >= FLUSHES {
        kprintln!("[PIFLUSH] PASS {} flushes on sys-wdt's hart", d);
    } else {
        kprintln!("[PIFLUSH] FAIL the flusher stopped at {} of {} flushes in {} s", d, FLUSHES, WATCH_SECS);
    }
    task_exit();
}
