// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! sensor-ts-smoke (wave 11, SENSORTS): the IMU's acquisition stamp, from the
//! driver to the staleness check the safety layer reads.
//!
//! Two facts, printed once on the console:
//!
//!   1. **The driver stamps at the read.** Twenty `imu_read_scaled_stamped`
//!      calls, 10 ms apart: each stamp lies between the timebase readings
//!      taken just before and just after its call, and none goes backwards.
//!   2. **The bus ages the sample from that stamp.** `SENSOR_BUS`, fed by the
//!      kernel's `imu` task through `update_imu_at`, is snapshotted and its
//!      IMU sample's age compared with `SensorBus::IMU_MAX_AGE_TICKS` — the
//!      check `SensorState::imu_valid` carries into L0 (`safety::check_common`).
//!
//! `[SENSORTS] PASS: ...` when both hold. `[SENSORTS] STALE: ...` is printed
//! ONLY when IMU readings keep arriving and the bus still judges the newest
//! one too old — the staleness check firing on a sample that was delivered
//! but not acquired recently. That is what `sensor-ts-freeze` (every reading
//! carries the first reading's stamp) must produce, and what a bus stamped at
//! delivery could never produce while the IMU task runs: the canary row's
//! marker. `[SENSORTS] FAILED: ...` for anything else. L0's verdict on the
//! same snapshot is printed for information only: once the behaviour loop has
//! latched an e-stop, `safety_check` answers `RemoteEstop` first, so the
//! verdict is not what the rows judge.

use crate::*;

/// IMU readings the smoke takes itself.
const READS: u32 = 20;

fn sleep_ms(ms: u64) {
    let dl = azos_drv_sys::timebase::now() + azos_drv_sys::timebase::TIMER_FREQ * ms / 1000;
    azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
}

fn ticks_to_us(t: u64) -> u64 {
    t.saturating_mul(1_000_000) / azos_drv_sys::timebase::TIMER_FREQ
}

pub(crate) fn sensor_ts_smoke_task(_: usize) {
    use azos_behavior::sensor_bus::{SensorBus, SENSOR_BUS};
    use azos_behavior::types::SensorState;
    use core::sync::atomic::Ordering as O;

    // The `imu` task's first publication, waited for on the clock (10 s).
    let give_up = azos_drv_sys::timebase::now() + azos_drv_sys::timebase::TIMER_FREQ * 10;
    while SENSOR_BUS.imu_updated_at.load(O::Relaxed) == 0 {
        if azos_drv_sys::timebase::now() >= give_up {
            kprintln!("[SENSORTS] FAILED: no IMU sample reached the sensor bus in 10 s");
            return;
        }
        sleep_ms(10);
    }
    // Two seconds of normal running: longer than the bus bound (200 ms) and
    // than L0's grace on an invalid IMU (1 s), so a frozen stamp is old by
    // now and L0 has had time to act on it.
    sleep_ms(2000);

    // 1. The driver's stamps.
    let (mut answered, mut inside, mut monotonic) = (0u32, true, true);
    let mut last = 0u64;
    for _ in 0..READS {
        let before = azos_drv_sys::timebase::now();
        let got = azos_imu::imu_read_scaled_stamped();
        let after = azos_drv_sys::timebase::now();
        if let Some((_, acq)) = got {
            answered += 1;
            inside &= acq >= before && acq <= after;
            monotonic &= acq >= last;
            last = acq;
        }
        sleep_ms(10);
    }

    // 2. The bus, as the behaviour loop snapshots it.
    let now = azos_drv_sys::timebase::now();
    let mut s = SensorState::new();
    SENSOR_BUS.snapshot_at(&mut s, now);
    let age = now.saturating_sub(SENSOR_BUS.imu_updated_at.load(O::Relaxed));
    let bound = SensorBus::IMU_MAX_AGE_TICKS;
    let mut verdict = azos_behavior::safety::safety_check(&s);
    // A stale bus sample: give L0 its grace (1 s) and up to half a second
    // more to act on it, judging fresh snapshots, as the behaviour loop does.
    if !s.imu_valid {
        let until = now + azos_drv_sys::timebase::TIMER_FREQ * 3 / 2;
        while verdict.violation == azos_behavior::safety::SafetyViolation::None
            && azos_drv_sys::timebase::now() < until
        {
            sleep_ms(100);
            let mut s2 = SensorState::new();
            SENSOR_BUS.snapshot_at(&mut s2, azos_drv_sys::timebase::now());
            verdict = azos_behavior::safety::safety_check(&s2);
        }
    }

    if answered != READS {
        kprintln!("[SENSORTS] FAILED: the IMU answered {}/{} reads", answered, READS);
        return;
    }
    if !s.imu_valid {
        kprintln!("[SENSORTS] STALE: IMU readings still arriving ({}/{} answered) but the bus sample was acquired {} us ago >= {} us: imu_valid=false; L0 verdict {:?}",
                  answered, READS, ticks_to_us(age), ticks_to_us(bound), verdict.violation);
    }
    if !(inside && monotonic) {
        // After STALE, a line the canary row does not read as a failure: the
        // frozen stamp is outside every later read by construction.
        if !s.imu_valid {
            kprintln!("[SENSORTS] reads: IMU stamps inside their read={} monotonic={} (last stamp {} ticks)",
                      inside, monotonic, last);
        } else {
            kprintln!("[SENSORTS] FAILED: IMU stamps inside their read={} monotonic={} (last stamp {} ticks)",
                      inside, monotonic, last);
        }
        return;
    }
    if s.imu_valid {
        kprintln!("[SENSORTS] PASS: {} IMU reads stamped inside their read, monotonic; bus IMU sample acquired {} us ago < {} us: fresh (L0 verdict {:?})",
                  READS, ticks_to_us(age), ticks_to_us(bound), verdict.violation);
    }
}
