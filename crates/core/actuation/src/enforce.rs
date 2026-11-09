// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The enforcement task: every [`azos_ext_api::Enforcer`] the installed
//! extensions register, each at its period, in one kernel task. What it runs
//! enforces (latches the e-stop, records why); choosing a motion is ring 3's.

use azos_drv_sys::timebase::{freq, now};

/// Its priority: in the real-time band with the system watchdog, below the
/// effect loops it never preempts.
pub const ENFORCE_PRIORITY: u32 = azos_sched::WATCHDOG_PRIORITY;

/// The most enforcers the task tracks: each manifest asserts its own count
/// against it at build time (`azos_ext_api::enforcers_in`), the boot their sum.
pub const MAX_ENFORCERS: usize = 8;

/// How many enforcers the installed manifests register.
pub fn enforcer_count() -> usize {
    let mut n = 0;
    crate::providers::each_enforcer(|_| n += 1);
    n
}

/// The task body: run each enforcer when its period is due, sleep to the
/// soonest next one.
pub fn enforce_task(_: usize) {
    let mut due = [0u64; MAX_ENFORCERS];
    loop {
        let t = now();
        let mut next = u64::MAX;
        let mut i = 0;
        crate::providers::each_enforcer(|e| {
            if i < MAX_ENFORCERS {
                if t >= due[i] {
                    (e.tick)(t);
                    due[i] = t + (freq() * e.period_ms.max(1) as u64 / 1000).max(1);
                }
                next = next.min(due[i]);
            }
            i += 1;
        });
        if next == u64::MAX {
            next = t + freq();
        }
        azos_sched::task_block(azos_sched::WaitReason::Timer(next));
    }
}
