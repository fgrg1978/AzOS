// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A task-context kernel line is never dropped behind a console owner (XC).
//!
//! The runner holds the console as a ring-3 writer does between two of its
//! lines (`uart::console_hold`) and fills the deferred buffer until less
//! than `LINE_RESERVE` is free. A probe task (not RT, no lock held) then
//! prints one line. Before XC it appended into the full buffer and the line
//! was dropped (`[CONSOLE] dropped ...`): on x86_64 that took the ktest-late
//! runner's own `ok N` lines behind the RT console probe, 1 boot in 3. Now
//! the probe waits for the console's line lock and its line goes out after
//! the hold. The verdict is the drop counter and the probe's own wait.
//!
//! Runtime canary: `canary=console-drop` takes the wait away from the probe
//! (only it): its line is dropped and the test says `not ok`.

use core::sync::atomic::{AtomicBool, Ordering};

static DONE: AtomicBool = AtomicBool::new(false);

fn console_wait_probe(_: usize) {
    let tid = azos_sched::current_task_tid();
    if canary!("console-drop") {
        crate::canary_rt::CONSOLE_DROP_TID.store(tid, Ordering::SeqCst);
    }
    azos_drv_sys::uart::console_watch(tid);
    azos_drv_sys::kprintln!("[CONSOLE-WAIT] probe line from task context: waited for, never dropped");
    crate::canary_rt::CONSOLE_DROP_TID.store(0, Ordering::SeqCst);
    DONE.store(true, Ordering::Release);
}

#[cfg(feature = "ktest")]
azos_ktest::ktest_late! {
    fn console_task_line_waits_never_drops() {
        DONE.store(false, Ordering::SeqCst);
        let dropped0 = azos_drv_sys::uart::console_defer_stats().1;
        let held = azos_drv_sys::uart::console_hold(|| -> Result<(), &'static str> {
            let mut n = 0u32;
            loop {
                let (free, owned) = azos_drv_sys::uart::console_defer_room();
                if !owned {
                    return Err("the hold did not own the console");
                }
                if free < azos_drv_sys::console_defer::LINE_RESERVE {
                    break;
                }
                // 48 bytes: always fits in the LINE_RESERVE left, never drops.
                azos_drv_sys::kprintln!("[CONSOLE-WAIT] filler {:05} behind the hold", n);
                n += 1;
                if n > 100_000 {
                    return Err("the deferred buffer never filled");
                }
            }
            azos_sched::task_create_affinity("console-wait-probe", console_wait_probe, 0,
                                             azos_sched::DEFAULT_PRIORITY, -1);
            // The probe either waits for this hold (the fix) or returns
            // after dropping its line (the canary).
            crate::ktest::wait("the probe neither waited for the console nor returned", || {
                DONE.load(Ordering::Acquire) || azos_drv_sys::uart::console_watched_waited()
            })
        });
        held?;
        crate::ktest::wait("the probe did not finish after the hold", || DONE.load(Ordering::Acquire))?;
        let waited = azos_drv_sys::uart::console_watched_waited();
        azos_drv_sys::uart::console_watch(0);
        if azos_drv_sys::uart::console_defer_stats().1 != dropped0 {
            Err("a kernel line was dropped behind the console owner")
        } else if !waited {
            Err("the probe's line did not wait for the console")
        } else {
            Ok(())
        }
    }
}
