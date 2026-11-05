// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The INA219's in-kernel host task (the row of `INADRV.ELF` says `place =
//! "kernel"`, Kconfig `DRV_INA219_PLACEMENT = kernel`).
//!
//! The ring-3 host's loop (`userspace/drivers/ina_drv`), in a kernel task:
//! one sample per 1 / `INA219_POLL_HZ`, against the clock, the chip's
//! configuration retried every period until it is accepted. The chip logic
//! and what callers read are `azos_drv_sensor::ina219::kernel_host`.

/// The host task: created by `kernel_main` when the INA219 is placed in the
/// kernel. Never returns.
pub(crate) fn ina219_host_task(_: usize) {
    use crate::kprintln;
    use azos_drv_sensor::ina219::kernel_host::{KernelHost, SAMPLE_PERIOD_TICKS};
    use azos_drv_sys::timebase::now;
    let tid = azos_sched::current_task_tid();
    let mut host = KernelHost::new();
    // The chip-logic source this host runs (`tools/lint/chip_source_check.py`).
    kprintln!("[INA219] kernel host tid={}: {}", tid,
              core::str::from_utf8(azos_drv_sensor::ina219::SOURCE_MARKER).unwrap_or("?"));
    if host.sample(now(), tid) {
        kprintln!("[INA219] kernel host tid={}: chip configured, sampling", tid);
    } else {
        kprintln!("[INA219] kernel host tid={}: chip did not accept its configuration, retrying", tid);
    }
    let mut next = now() + SAMPLE_PERIOD_TICKS;
    loop {
        // To the deadline: a block can end early (a stale wake stamp).
        while now() < next {
            azos_sched::task_block(azos_sched::WaitReason::Timer(next));
        }
        let t = now();
        host.sample(t, tid);
        next += SAMPLE_PERIOD_TICKS;
        // Fell behind (a long preemption): resynchronise, no burst.
        if next <= t {
            next = t + SAMPLE_PERIOD_TICKS;
        }
    }
}
