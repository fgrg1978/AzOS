// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 11 (DRVPLACE): the INA219's in-kernel host task (Kconfig
//! `DRV_INA219_PLACEMENT = kernel`, feature `ina219-kernel`).
//!
//! The ring-3 host's loop (`userspace/drivers/ina_drv`), in a kernel task:
//! one sample per 1 / `INA219_POLL_HZ`, against the clock, the chip's
//! configuration retried every period until it is accepted. The chip logic
//! and what callers read are `azos_drv_sensor::ina219::kernel_host`.

// The placement is chosen once, by Kconfig, and both crates must have been
// told: the drivers crate (which host answers the kernel API) and the
// topology (whether the ring-3 host's row, `INADRV.ELF` with its
// `Cap<I2c>` on the chip, is declared). A kernel placement that still
// declares the ring-3 host does not link. `ina219-placement-canary` skips
// this check on purpose, so the gate row can show that the boot check below
// catches the same mismatch.
#[cfg(not(feature = "ina219-placement-canary"))]
const _: () = assert!(
    azos_drv_sensor::ina219::IN_KERNEL != azos_topology::builder::INADRV_ROW,
    "DRV_INA219_PLACEMENT: the drivers crate and the topology disagree -- the INA219 \
     is placed in the kernel while the topology still declares its ring-3 host \
     INADRV.ELF (or neither host exists). Enable the kernel feature `ina219-kernel`, \
     which forwards to both.",
);

/// The host task: created by `kernel_main` when the INA219 is placed in the
/// kernel. Never returns.
#[cfg(feature = "ina219-kernel")]
pub(crate) fn ina219_host_task(_: usize) {
    use crate::kprintln;
    use azos_drv_sensor::ina219::kernel_host::{KernelHost, SAMPLE_PERIOD_TICKS};
    use azos_drv_sys::timebase::now;
    let tid = azos_sched::current_task_tid();
    let mut host = KernelHost::new();
    // The chip-logic source this host runs (`tools/chip_source_check.py`).
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
