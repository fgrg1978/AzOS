// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 12 (DRVPLACE): the buzzer's in-kernel host task, running while the
//! driver is placed in the kernel (its row's `place`, Kconfig
//! `DRV_BUZZER_PLACEMENT` at boot, and a later move: `crate::buzzer`).
//!
//! The ring-3 host's timer thread (`userspace/drivers/buzz_drv`) without the
//! requests: callers play through `azos_drv_actuator::buzzer::KernelBuzzer`
//! directly, and this task only advances the timed steps, parked until the
//! current one is due (or until a call wakes it).

/// How a buzzer call wakes this task (`buzzer::host_step`'s `wake`).
fn wake_host(tid: u32) {
    azos_sched::scheduler::wake_task_by_tid(
        tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
}

/// Longest park with nothing timed: a lost wake costs at most this.
const IDLE_PARK_MS: u64 = 1_000;

/// The host task: created by `kernel_main` when the buzzer starts in the
/// kernel, and by a move into the kernel. Never returns.
pub(crate) fn buzzer_host_task(_: usize) {
    use crate::kprintln;
    use azos_drv_actuator::buzzer::{host_step, SOURCE_MARKER};
    use azos_drv_sys::timebase::{now, TIMER_FREQ};
    let tid = azos_sched::current_task_tid();
    let mut park = host_step(tid, wake_host);
    kprintln!("[BUZZER] kernel host tid={}: serving ({})",
              tid, core::str::from_utf8(SOURCE_MARKER).unwrap_or("?"));
    loop {
        let ms = if park == 0 { IDLE_PARK_MS } else { park as u64 };
        let until = now() + ms * (TIMER_FREQ / 1000);
        // One block: a call's wake ends it early on purpose (a new sound may
        // be due sooner); `host_step` then re-reads the park.
        if now() < until {
            azos_sched::task_block(azos_sched::WaitReason::Timer(until));
        }
        // Wave 13 smoke: a panic in the host, holding no lock.
        #[cfg(feature = "drv-contain-smoke")]
        if crate::smokes::drv_contain_smoke::take_panic_request() {
            panic!("drv-contain-smoke: deliberate panic in the buzzer's kernel host");
        }
        park = host_step(tid, wake_host);
    }
}
