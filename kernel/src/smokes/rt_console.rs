// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A real-time task's kernel log lines only append to the console (wave 15,
//! IO-QUEUES-AUDIT row C2; Kconfig `CONSOLE_RT_APPEND_ONLY`).
//!
//! A probe task in the RT band prints a burst of kernel lines (more bytes
//! than the UART TX ring and the deferred buffer hold together). Before wave
//! 15 such a caller that found deferred output took the console over and
//! drained it in its own time, waiting for the wire. Now every line goes
//! through the append-only path (counted by `uart::rt_console_counts`) and
//! none reaches the call that waits for the wire, where the dev check
//! (Kconfig `RT_CONSOLE_WIRE_CHECK`, on in the QEMU dev configs) would panic
//! naming the task. Whether a given line met a full ring depends on how fast
//! the emulated UART drains; the protocol cases (full ring, residual, no TX
//! interrupt, overflow) are the host tests' (`tests/host/drivers-tests`,
//! `console_ownership::an_rt_*`).
//!
//! It then makes ring-3 console writes through `uart::console_write_ring3`
//! (what `sys_write` to fd 1/2 calls): they take the same append-only path.
//!
//! Runtime canaries: `canary=rt-console-own` tells the probe's kernel lines
//! to wait for the wire, `canary=rt-console-own-user` only its ring-3
//! writes (after the kernel lines are out); either way the check stops the
//! kernel in this test (`not ok`).

use core::sync::atomic::{AtomicU32, Ordering};

/// Lines the probe prints: ~100 B each, past the TX ring and the deferred
/// buffer together at their QEMU defaults (Kconfig CONSOLE_TX_RING_BYTES,
/// CONSOLE_DEFER_BYTES).
const LINES: u32 = 160;

/// Ring-3 console writes the probe makes through `uart::console_write_ring3`.
const USER_WRITES: u32 = 40;

static APPENDED: AtomicU32 = AtomicU32::new(0);
static USER_APPENDED: AtomicU32 = AtomicU32::new(0);
static WAITS: AtomicU32 = AtomicU32::new(u32::MAX);
static BASE_PRIO: AtomicU32 = AtomicU32::new(0);

fn rt_console_probe(_: usize) {
    BASE_PRIO.store(azos_sched::scheduler::current_task_base_priority(), Ordering::SeqCst);
    if canary!("rt-console-own") {
        crate::canary_rt::RT_CONSOLE_TID.store(azos_sched::current_task_tid(), Ordering::SeqCst);
    }
    let (lines0, user0, waits0) = azos_drv_sys::uart::rt_console_counts();
    for i in 0..LINES {
        azos_drv_sys::kprintln!(
            "[RT-CONSOLE] probe line {:03} from the RT band: appended, never waits for the wire",
            i
        );
    }
    // The ring-3 entry point (`sys_write` to fd 1/2 calls exactly this).
    if canary!("rt-console-own-user") {
        crate::canary_rt::RT_CONSOLE_TID.store(azos_sched::current_task_tid(), Ordering::SeqCst);
    }
    for i in 0..USER_WRITES {
        let mut line = *b"[RT-CONSOLE] ring-3 write 000 from the RT band: appended\n";
        line[26] = b'0' + (i / 100) as u8;
        line[27] = b'0' + (i / 10 % 10) as u8;
        line[28] = b'0' + (i % 10) as u8;
        azos_drv_sys::uart::console_write_ring3(&line);
    }
    let (lines1, user1, waits1) = azos_drv_sys::uart::rt_console_counts();
    APPENDED.store(lines1.wrapping_sub(lines0), Ordering::SeqCst);
    USER_APPENDED.store(user1.wrapping_sub(user0), Ordering::SeqCst);
    WAITS.store(waits1.wrapping_sub(waits0), Ordering::SeqCst);
    crate::canary_rt::RT_CONSOLE_TID.store(0, Ordering::SeqCst);
}

#[cfg(feature = "ktest")]
azos_ktest::ktest_late! {
    fn console_rt_lines_only_append() {
        crate::ktest::probe("rt-console-probe", rt_console_probe, 0, azos_sched::RT_MOTOR_PRIORITY, -1)?;
        if BASE_PRIO.load(Ordering::SeqCst) >= azos_sched::RT_PRIORITY_THRESHOLD {
            Err("the probe did not run in the RT band")
        } else if !azos_limits::CONSOLE_RT_APPEND_ONLY {
            Ok(()) // the option is off: nothing to check
        } else if APPENDED.load(Ordering::SeqCst) < LINES {
            Err("an RT task's kernel line did not take the append-only path")
        } else if USER_APPENDED.load(Ordering::SeqCst) < USER_WRITES {
            Err("an RT task's ring-3 console write did not take the append-only path")
        } else if WAITS.load(Ordering::SeqCst) != 0 {
            Err("an RT task's kernel line waited for the console wire")
        } else {
            Ok(())
        }
    }
}
