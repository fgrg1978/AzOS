// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 12 (DRVPLACE): the buzzer's in-kernel host task (Kconfig
//! `DRV_BUZZER_PLACEMENT = kernel`, feature `buzzer-kernel`).
//!
//! The ring-3 host's loop (`userspace/drivers/buzz_drv`) without the
//! requests: callers play through `azos_drv_actuator::buzzer::kernel_host`
//! directly, and this task only advances the timed steps, parked until the
//! current one is due (or until a call wakes it).

// The placement is chosen once, by Kconfig, and both crates must have been
// told: the drivers crate (which host answers the kernel API) and the
// topology (whether the ring-3 host's row, `BUZZDRV.ELF` with its `Cap<Pwm>`
// on channel 5, is declared). A kernel placement that still declares the
// ring-3 host does not link.
const _: () = assert!(
    azos_drv_actuator::buzzer::IN_KERNEL != azos_topology::builder::BUZZDRV_ROW,
    "DRV_BUZZER_PLACEMENT: the drivers crate and the topology disagree -- the buzzer \
     is placed in the kernel while the topology still declares its ring-3 host \
     BUZZDRV.ELF (or neither host exists). Enable the kernel feature `buzzer-kernel`, \
     which forwards to both.",
);

/// How a buzzer call wakes this task (`kernel_host::host_step`'s `wake`).
#[cfg(feature = "buzzer-kernel")]
fn wake_host(tid: u32) {
    azos_sched::scheduler::wake_task_by_tid(
        tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
}

/// Longest park with nothing timed: a lost wake costs at most this.
#[cfg(feature = "buzzer-kernel")]
const IDLE_PARK_MS: u64 = 1_000;

/// The host task: created by `kernel_main` when the buzzer is placed in the
/// kernel. Never returns.
#[cfg(feature = "buzzer-kernel")]
pub(crate) fn buzzer_host_task(_: usize) {
    use crate::kprintln;
    use azos_drv_actuator::buzzer::kernel_host::{host_step, SOURCE_MARKER};
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
