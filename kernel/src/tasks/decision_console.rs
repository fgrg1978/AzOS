// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The decision ring on the console (Kconfig `DECISION_RECORDS_CONSOLE`).
//!
//! `why` asks a service for the records; a machine with only a console, and a
//! gate row that holds a boot's verdicts to account, read them here. The task
//! is a reader of the ring like any other: a record the writers overwrote
//! before it looked is counted on a line of its own, never made up.

use azos_sched::WaitReason;

use crate::kprintln;

const POLL_MS: u64 = 50;

fn decision_console_task(_: usize) {
    let poll = POLL_MS * (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    let mut next = 1u64;
    loop {
        let end = azos_drv_sys::timebase::now() + poll;
        while azos_drv_sys::timebase::now() < end {
            azos_sched::task_block(WaitReason::Timer(end));
        }
        let last = azos_decision::total();
        let mut lost = 0u64;
        while next <= last {
            match azos_decision::get(next) {
                Some(r) => {
                    let name = r.rule_info().map_or("?", |i| i.name);
                    kprintln!("[DECISION] {} {} subject={} n={},{},{}", name, r.verdict_name(), r.subject, r.n[0], r.n[1], r.n[2]);
                }
                None => lost += 1,
            }
            next += 1;
        }
        if lost != 0 {
            kprintln!("[DECISION] lost {} records to the ring", lost);
        }
    }
}

/// Create the task: below the real-time band, on any CPU.
pub(crate) fn create_decision_console_task() {
    azos_sched::task_create("decision-console", decision_console_task, 0, azos_limits::MM_RECLAIM_PRIORITY as u32);
}
