// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! OTA/boot-count smokes: orderly reboot and the safe-mode probe.

use crate::*;

/// `orderly-reboot-smoke`: whether this boot's volume had no BOOTMETA.A/.B
/// record (boot 1 of the gate row's two).
#[cfg(feature = "orderly-reboot-smoke")]
pub(crate) static ORDERLY_SMOKE_FRESH: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Gate row `boot count: orderly reboot`. On a fresh
/// volume, a few seconds into the boot — long before sys-wdt's 30 s mark —
/// call `reboot_orderly`, the handler of the `power` interface's `reboot` (a
/// kernel task needs no capability), so the reboot takes the path a ring-3
/// `power reboot` takes. The
/// next boot of the same volume must read 0 unconfirmed boots, not 1. On a
/// volume that has a record, do nothing: that is boot 2.
#[cfg(feature = "orderly-reboot-smoke")]
pub(crate) fn orderly_reboot_smoke_task(_: usize) {
    use core::sync::atomic::Ordering;
    if !ORDERLY_SMOKE_FRESH.load(Ordering::Acquire) {
        return;
    }
    let t = azos_drv_sys::timebase::now() + 3 * azos_drv_sys::timebase::TIMER_FREQ;
    azos_sched::task_block(azos_sched::WaitReason::Timer(t));
    let up_ms = azos_drv_sys::timebase::now() / (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    kprintln!("[ORDERLY] smoke: sys_reboot at {} ms of uptime, before the boot is confirmed", up_ms);
    azos_syscall::handlers::reboot_orderly();
}

/// Gate rows `power-off: the kernel's sync keeps a written file` (owner
/// decision 2026-10-23, Q1). Waits past sys-wdt's boot-good mark (an
/// unconfirmed boot's OTA void syncs the volume by itself and would hide a
/// missing sync), writes `/fat/DURSMOKE.TXT` through the VFS (a close only
/// queues it in the write-back cache), and calls `power_off_orderly` at once:
/// microseconds, not `FS_WRITEBACK_MAX_AGE_MS`, so only the orderly path's
/// own sync can put the file on the medium. The host reads the volume back.
#[cfg(feature = "power-off-durability-smoke")]
pub(crate) fn power_off_durability_smoke_task(_: usize) {
    use azos_drv_sys::timebase::{now, TIMER_FREQ};
    const BODY: &[u8] = b"durable-ok\n";
    let past = (u64::from(azos_ota::OTA_BOOT_GOOD_DELAY_S) + 5) * TIMER_FREQ;
    while now() < past {
        azos_sched::task_block(azos_sched::WaitReason::Timer(past));
    }
    let mut t = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut t, b"/fat/DURSMOKE.TXT", azos_fs::O_WRONLY | azos_fs::O_CREAT | azos_fs::O_TRUNC);
    let wrote = fd >= 0 && azos_fs::vfs_write(&mut t, fd, BODY.as_ptr(), BODY.len()) == BODY.len() as i32;
    let closed = fd >= 0 && azos_fs::vfs_close(&mut t, fd) == 0;
    if !(wrote && closed) {
        kprintln!("[ORDERLY] FAIL smoke: /fat/DURSMOKE.TXT not written (fd {})", fd);
        return;
    }
    let (dirty, _) = azos_fs::fat32_writeback_dirty();
    kprintln!("[ORDERLY] smoke: /fat/DURSMOKE.TXT written ({} dirty cache lines), power-off now", dirty);
    azos_syscall::handlers::power_off_orderly();
}

/// Gate row `power-off: a queued record is drained`. Past the boot-good mark,
/// queues a latching e-stop record the way a caller in a SpinLock section does
/// (on the ring, no wake), holds the flusher so its periodic pass cannot write
/// it, and powers off. Only the orderly path's drain can put it on the medium;
/// the next boot of the volume comes up latched, and then this does nothing.
#[cfg(feature = "orderly-drain-smoke")]
pub(crate) fn orderly_drain_smoke_task(_: usize) {
    use azos_actuation::logger;
    use azos_drv_sys::timebase::{now, TIMER_FREQ};
    let past = (u64::from(azos_ota::OTA_BOOT_GOOD_DELAY_S) + 5) * TIMER_FREQ;
    while now() < past {
        azos_sched::task_block(azos_sched::WaitReason::Timer(past));
    }
    if azos_actuation::estop::estop_is_active() {
        return;
    }
    logger::logger_hold_flusher();
    let queued = {
        let _section = azos_sync::critical_section();
        logger::log_safety_violation_durable(logger::SAFETY_ESTOP, 2, 0)
    };
    if queued != Err(logger::LogStorageError::Deferred) || !logger::durable_record_pending() {
        kprintln!("[ORDERLY] FAIL drain smoke: the record was not left queued");
        return;
    }
    kprintln!("[ORDERLY] drain smoke: record queued, power-off now");
    azos_syscall::handlers::power_off_orderly();
}

/// Gate row `safe mode: attempts exhausted`, on the boot that entered safe
/// mode (every other boot of `safe-mode-smoke` crashed on purpose in
/// `boot_count_loaded`). Asks the actuators to move and checks they did not,
/// then waits past sys-wdt's boot-good mark and reads BOOTMETA back: the boot
/// must still be unconfirmed. The row then installs an image over OTA.
#[cfg(feature = "safe-mode-smoke")]
pub(crate) fn safe_mode_probe_task(_: usize) {
    use azos_behavior::brain_protocol::{PayloadCmd, PAYLOAD_ON, PAYLOAD_TYPE_SPRAY};
    use azos_drv_sys::timebase::{now, TIMER_FREQ};
    use azos_robot::motor::{motor_set_reporting, motor_state, MotorDir, MOTOR_REFUSED_HALTED};
    fn sleep_ms(ms: u64) {
        azos_sched::task_block(azos_sched::WaitReason::Timer(now() + ms * (TIMER_FREQ / 1000).max(1)));
    }
    if !azos_actuation::estop::safe_mode_active() {
        kprintln!("[SAFE-MODE] FAIL probe: this boot is not in safe mode");
        return;
    }
    let recorded = azos_ota::ota_read_boot_meta().boot_count;
    let t0 = now();
    while motor_state(0).is_none() {
        if now() - t0 > 20 * TIMER_FREQ {
            kprintln!("[SAFE-MODE] FAIL probe: motor 0 never initialised");
            return;
        }
        sleep_ms(50);
    }
    let (rc, applied) = motor_set_reporting(0, MotorDir::Forward, 60);
    let speed = motor_state(0).map(|(_, s)| s);
    if rc != MOTOR_REFUSED_HALTED || applied.unwrap_or(0) != 0 || speed != Some(0) {
        kprintln!("[SAFE-MODE] FAIL probe: motor 0 forward 60% answered rc={} applied={:?} speed={:?}",
                  rc, applied, speed);
        return;
    }
    let spray = azos_behavior::payload::payload_exec(PayloadCmd {
        payload_type: PAYLOAD_TYPE_SPRAY, channel: 0, value: PAYLOAD_ON, duration_ms: 0,
    });
    if spray {
        kprintln!("[SAFE-MODE] FAIL probe: the spray pump was switched on");
        return;
    }
    kprintln!("[SAFE-MODE] probe: motor 0 forward 60% refused (rc={}, applied 0%), spray refused",
              rc);
    let past = (u64::from(azos_ota::OTA_BOOT_GOOD_DELAY_S) + 5) * TIMER_FREQ;
    while now() < past {
        sleep_ms(500);
    }
    let later = azos_ota::ota_read_boot_meta();
    if later.boot_count != recorded || later.boot_count == 0 {
        kprintln!("[SAFE-MODE] FAIL probe: BOOTMETA boot_count {} -> {} after {} s: the boot was \
                   confirmed", recorded, later.boot_count, azos_ota::OTA_BOOT_GOOD_DELAY_S + 5);
        return;
    }
    kprintln!("[SAFE-MODE] PASS probe: actuators held; {} s up and BOOTMETA boot_count still {} \
               (not confirmed); waiting for an OTA image",
              azos_ota::OTA_BOOT_GOOD_DELAY_S + 5, later.boot_count);
}
