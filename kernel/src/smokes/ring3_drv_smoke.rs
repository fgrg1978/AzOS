// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DRV1 (wave 9): the functional test of the buzzer and the INA219.
//!
//! Wave 9: both drivers run in ring 3 (`userspace/drivers/buzz_drv`,
//! `userspace/drivers/ina_drv`), started from their `start = true` rows; the kernel API
//! below is their proxy client. The assertions are the ones the in-kernel
//! drivers passed before the move.
//!
//! Driven through the kernel API the syscall handlers call
//! (`azos_drv_actuator::buzzer::*` behind `SYS_BUZZER_*`,
//! `azos_drv_sensor::ina219::ina219_read_power` behind
//! `SYS_SENSOR_READ(SENSOR_TYPE_POWER)`), and checked against what the
//! hardware underneath shows: the simulated PWM channel's state, and the
//! fixed readings of the simulated INA219 (`i2c::ina219_sim`).
//!
//! One verdict line per driver: `[DRV1] <driver> PASS` or
//! `[DRV1] <driver> FAIL: <what>`. `FAIL:`, not `FAILED:`: the gate's shared
//! failure pattern matches `FAILED:` in every row, and each driver's row must
//! go red on its own driver only (each row adds its own `FAIL` pattern).

use crate::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};

/// The buzzer's PWM channel.
pub const BUZZER_CH: u32 = 5;
const MS: u64 = TIMER_FREQ / 1000;

/// Until `ms` have passed: a block can return early on a stamp left by a
/// late proxy reply (seen in the DRV2 canary: a 3 s sleep ended at
/// 194 ms), so it is repeated to the deadline.
fn sleep_ms(ms: u64) {
    let end = now() + ms * MS;
    while now() < end {
        azos_sched::task_block(azos_sched::WaitReason::Timer(end));
    }
}

/// How long a ring-3 driver may take to register: the launcher reads its
/// ELF off FAT32 after the volume is mounted.
const REGISTER_WAIT_MS: u64 = 60_000;

/// The TID of the ring-3 driver `tid_of` reports, once it has registered.
/// `None` after `REGISTER_WAIT_MS`: the driver was never started, or
/// exited before registering.
fn wait_for_driver(tid_of: fn() -> Option<u32>) -> Option<u32> {
    let deadline = now() + REGISTER_WAIT_MS * MS;
    loop {
        if let Some(t) = tid_of() { return Some(t); }
        if now() >= deadline { return None; }
        sleep_ms(50);
    }
}

/// Timebase ticks to microseconds.
fn us(ticks: u64) -> u64 {
    ticks * 1_000_000 / TIMER_FREQ
}

/// Calls a proxied op may take to be answered. Generous on purpose: a
/// driver that never answers fails at any bound, so a wider one costs
/// only time on failure and keeps host load out of the verdict.
const CALL_ATTEMPTS: u32 = 30;

/// Repeat `op` until the driver answers it. A call can end at the proxy's
/// 100 ms reply timeout while the driver (best_effort, woken from its park
/// by the submit) waits for a hart; that is counted in `PROXY_TIMEOUTS`
/// and reported, and the test is about what the driver does once it
/// answers. The assertions below read the state the ANSWERED call left
/// (requests are served in order).
fn answered(op: impl Fn() -> bool) -> Result<(), &'static str> {
    for _ in 0..CALL_ATTEMPTS {
        if op() { return Ok(()); }
        sleep_ms(50);
    }
    Err("none of 30 calls was answered with its PWM writes accepted")
}

/// Longest a 50 ms tone may take to be switched off. Generous, as
/// `CALL_ATTEMPTS`: one aarch64 boot at best_effort measured 1578 ms.
const TONE_END_LIMIT_MS: u64 = 5_000;
/// Reads of the power record before giving up: each ends at the proxy's
/// 100 ms reply timeout at most.
const POWER_READ_ATTEMPTS: u32 = 30;

/// `Ok((us, ms))`: how long the `buzzer_on` call took, request to reply,
/// and after how long the 50 ms tone was seen switched off (wall clock
/// under TCG: informational; only the 5 s bound is asserted).
fn buzzer() -> Result<(u64, u64), &'static str> {
    use azos_drv_actuator::buzzer as bz;
    use azos_drv_actuator::pwm::pwm_get;
    // A4: 1e9 / 440 = 2272727 ns.
    let t0 = now();
    answered(|| bz::buzzer_on(440))?;
    let call_us = us(now() - t0);
    let c = pwm_get(BUZZER_CH).ok_or("no such PWM channel")?;
    if !c.enabled { return Err("buzzer_on left the channel disabled"); }
    if c.period_ns != 2_272_727 { return Err("buzzer_on(440) did not set a 2272727 ns period"); }
    // 50% of the period, as `pwm_set_duty_pct` computes it. Not
    // `duty_pct() == 50`: that divides back and truncates to 49 here.
    if c.duty_ns != (c.period_ns as u64 * 50 / 100) as u32 { return Err("buzzer_on did not set 50% duty"); }
    answered(bz::buzzer_off)?;
    if pwm_get(BUZZER_CH).ok_or("no such PWM channel")?.enabled {
        return Err("buzzer_off left the channel enabled");
    }
    // The tone must end on its own. The ring-3 driver ends it against
    // its own clock, at best_effort priority, so WHEN depends on what
    // else the harts run: polled, bounded, and the time reported.
    let t0 = now();
    answered(|| bz::buzzer_tone(1000, 50))?;
    let c = pwm_get(BUZZER_CH).ok_or("no such PWM channel")?;
    if c.period_ns != 1_000_000 { return Err("buzzer_tone(1000) did not set a 1000000 ns period"); }
    while pwm_get(BUZZER_CH).is_some_and(|c| c.enabled) {
        if now() - t0 > TONE_END_LIMIT_MS * MS {
            return Err("a 50 ms tone was still sounding 5 s later");
        }
        sleep_ms(5);
    }
    Ok((call_us, us(now() - t0) / 1000))
}

/// Most empty fetches per second the INA219 driver may show while no
/// client calls it: it wakes to sample its chip at 10 Hz
/// (`INA219_POLL_HZ`, userspace), plus [`super::DRIVER_IDLE_MAX_PER_S`].
const INA_IDLE_MAX_PER_S: u64 = 10 + super::DRIVER_IDLE_MAX_PER_S;

/// Window the integrated charge is compared with the clock over.
const CHARGE_WINDOW_MS: u64 = 3_000;

/// `Ok((mV, mA, %, us, reads, charge %, window ms))`: `us` as for
/// [`buzzer`], of the read that answered, and how many reads that took;
/// then the charge the driver integrated over a [`CHARGE_WINDOW_MS`]
/// window, as a percentage of the simulated current times this task's
/// measured window, and the samples the driver published in it.
fn ina219() -> Result<(u16, u16, u8, u64, u32, u64, u64, u32), &'static str> {
    use azos_drv_bus::i2c::ina219_sim;
    use azos_drv_sensor::ina219::{ina219_read_power, POWER_DATA_SIZE};
    let mut b = [0u8; POWER_DATA_SIZE];
    let mut attempts = 0;
    let call_us = loop {
        attempts += 1;
        let t0 = now();
        let n = ina219_read_power(&mut b);
        let call_us = us(now() - t0);
        if n == POWER_DATA_SIZE { break call_us; }
        if attempts >= POWER_READ_ATTEMPTS {
            return Err("SENSOR_TYPE_POWER record was not 12 bytes in 30 reads");
        }
        sleep_ms(100);
    };
    let mv = u16::from_le_bytes([b[0], b[1]]);
    let ma = u16::from_le_bytes([b[2], b[3]]);
    let (pct, sag, failsafe) = (b[8], b[9], b[10]);
    if mv as u32 != (ina219_sim::BUS_VOLTAGE_RAW as u32 >> 3) * 4 {
        return Err("bus voltage is not the simulated 7400 mV");
    }
    if ma as u32 != ina219_sim::CURRENT_RAW as u32 / 10 {
        return Err("current is not the simulated 1500 mA (calibration not written?)");
    }
    if !(90..=100).contains(&pct) { return Err("capacity outside 90..=100% after seconds of 1.5 A"); }
    if sag != 0 { return Err("sag reported on a constant voltage"); }
    if failsafe != 0 { return Err("failsafe level raised on a full battery"); }
    // Wave 11 (SENSORTS): the record through `power_op::READ_TS` carries
    // when the driver's register reads behind it completed, on the vDSO
    // clock (the driver reads it in ring 3; the kernel converts its own
    // counter the same way). The driver samples at 10 Hz, so a stamp is
    // never ahead of this read and never a second old.
    {
        use azos_drv_sensor::ina219::ina219_read_power_stamped;
        let ns = |t: u64| azos_abi::time::ticks_to_ns(t, azos_drv_sys::timebase::TIMER_FREQ);
        let mut b2 = [0u8; POWER_DATA_SIZE];
        let (n, acq) = ina219_read_power_stamped(&mut b2);
        let after = ns(now());
        if n != POWER_DATA_SIZE { return Err("the stamped power record (READ_TS) was not 12 bytes"); }
        if acq == 0 || acq > after || after - acq >= 1_000_000_000 {
            kprintln!("[DRV1] ina219 stamp: acq_ns={} read at {} ns", acq, after);
            return Err("the power sample's acquisition stamp is 0, ahead of the read, or a second old");
        }
        kprintln!("[DRV1] ina219 sample acquired {} us before the read (driver's vDSO clock)",
                  (after - acq) / 1000);
    }
    // Wave 10 (DRV2): the charge is integrated over the time the driver
    // measured, so over a window it is the current times the window, give
    // or take one sample period at each end (the driver samples at
    // 10 Hz; a late sample moves charge between windows, never loses it).
    // The +-50% bound is for those ends and host load, not for the rate.
    use azos_drv_sensor::ina219::ina219_charge_ma_us;
    use azos_drv_sensor::ina219::ina219_stats;
    let s0 = ina219_stats().map_or(0, |s| s.0);
    let q0 = ina219_charge_ma_us().ok_or("no STATS reply with the integrated charge")?;
    let t0 = now();
    sleep_ms(CHARGE_WINDOW_MS);
    let q1 = ina219_charge_ma_us().ok_or("no STATS reply with the integrated charge")?;
    let samples = ina219_stats().map_or(0, |s| s.0).wrapping_sub(s0);
    let window_us = us(now() - t0);
    let expect = ma as u64 * window_us;
    let charge_pct = q1.saturating_sub(q0).saturating_mul(100) / expect.max(1);
    if !(50..=150).contains(&charge_pct) {
        return Err("charge over the window is not the current times the measured time (outside 50..=150%)");
    }
    Ok((mv, ma, pct, call_us, attempts, charge_pct, window_us / 1000, samples))
}

/// Calls [`latency`] times.
const LATENCY_CALLS: usize = 16;

/// Time [`LATENCY_CALLS`] calls of `op` (wall clock under TCG,
/// informational) and print `<who> proxy round trip over N calls: min=
/// p50= p90= max= us failed=`. More than half unanswered is a verdict,
/// `<who> FAIL:`: the driver is parked between calls, so a call is
/// answered in time only if its submit wakes it.
fn latency(who: &str, op: impl Fn() -> bool) {
    let mut t = [0u64; LATENCY_CALLS];
    let (mut n, mut failed) = (0usize, 0u32);
    for _ in 0..LATENCY_CALLS {
        let t0 = now();
        let ok = op();
        let dt = us(now() - t0);
        if ok { t[n] = dt; n += 1; } else { failed += 1; }
    }
    if failed as usize > LATENCY_CALLS / 2 {
        kprintln!("{} FAIL: {}/{} calls unanswered within the proxy timeout", who, failed, LATENCY_CALLS);
    }
    if n == 0 {
        kprintln!("{} proxy round trip: 0/{} calls answered", who, LATENCY_CALLS);
        return;
    }
    let s = &mut t[..n];
    s.sort_unstable();
    // A kernel-placed driver is a direct call, not a proxied one.
    let what = if (who.ends_with("ina219") && azos_drv_sensor::ina219::IN_KERNEL)
        || (who.ends_with("buzzer") && azos_drv_actuator::buzzer::IN_KERNEL)
    {
        "direct call"
    } else {
        "proxy round trip"
    };
    kprintln!("{} {} over {} calls: min={}us p50={}us p90={}us max={}us failed={}",
        who, what, n, s[0], s[n / 2], s[(n * 9) / 10], s[n - 1], failed);
}

/// Wave 11 (DRVPLACE): what the placement itself promises.
///
/// Kernel placement: the topology declares no ring-3 host (`INADRV.ELF`,
/// whose row grants `Cap<I2c>` on the chip) and no ring-3 task owns
/// `DRV_KIND_POWER_MON`. Ring-3 placement: no kernel host task answers
/// (`IN_KERNEL` is false, so the API is the proxy) and the row is declared.
/// The kernel build refuses the first mismatch at link time
/// (`tasks/ina219_host.rs`); this is the boot-time check of the same thing,
/// which `ina219-placement-canary` reaches by skipping the link-time one.
fn placement_check() -> Result<(), &'static str> {
    use azos_drv_sensor::ina219::IN_KERNEL;
    let declared = azos_topology::get().is_some_and(|t| t.tasks().iter()
        .any(|r| r.name.as_bytes() == azos_topology::builder::TASK_INADRV_IMAGE));
    if IN_KERNEL && declared {
        return Err("placement is kernel but the topology declares the ring-3 host INADRV.ELF");
    }
    if !IN_KERNEL && !declared {
        return Err("placement is ring-3 but the topology declares no INADRV.ELF row");
    }
    if IN_KERNEL {
        if let Some(t) = azos_driver_server::driver_owner_tid(azos_abi::drv_kind::DRV_KIND_POWER_MON) {
            kprintln!("[DRV1] ina219 ring-3 owner tid={} under the kernel placement", t);
            return Err("placement is kernel but a ring-3 task owns DRV_KIND_POWER_MON");
        }
    }
    Ok(())
}

/// Wave 12 (DRVPLACE): [`placement_check`] for the buzzer. Kernel
/// placement: no `BUZZDRV.ELF` row, no ring-3 owner of `DRV_KIND_BUZZER`.
/// Ring-3 placement: the row is declared. The link-time half is in
/// `tasks/buzzer_host.rs`.
fn buzzer_placement_check() -> Result<(), &'static str> {
    use azos_drv_actuator::buzzer::IN_KERNEL;
    let declared = azos_topology::get().is_some_and(|t| t.tasks().iter()
        .any(|r| r.name.as_bytes() == azos_topology::builder::TASK_BUZZDRV_IMAGE));
    if IN_KERNEL && declared {
        return Err("placement is kernel but the topology declares the ring-3 host BUZZDRV.ELF");
    }
    if !IN_KERNEL && !declared {
        return Err("placement is ring-3 but the topology declares no BUZZDRV.ELF row");
    }
    if IN_KERNEL {
        if let Some(t) = azos_driver_server::driver_owner_tid(azos_abi::drv_kind::DRV_KIND_BUZZER) {
            kprintln!("[DRV1] buzzer ring-3 owner tid={} under the kernel placement", t);
            return Err("placement is kernel but a ring-3 task owns DRV_KIND_BUZZER");
        }
    }
    Ok(())
}

/// Reads timed by [`read_path_cost`].
const READ_PATH_CALLS: u64 = 256;

/// The cost of one `ina219_read_power` (the call `SYS_SENSOR_READ(POWER)`
/// makes), in clock ns per read over [`READ_PATH_CALLS`] back-to-back
/// reads. Under `-icount shift=0` one ns is one guest instruction, so the
/// line is the read path's instruction count in this placement: a direct
/// copy of the published state (kernel) against a proxy round trip to the
/// parked driver (ring 3). Informational; the gate's placement-parity row
/// compares the two boots.
fn read_path_cost() {
    use azos_drv_sensor::ina219::{ina219_read_power, POWER_DATA_SIZE};
    let ns = |t: u64| azos_abi::time::ticks_to_ns(t, azos_drv_sys::timebase::TIMER_FREQ);
    let mut b = [0u8; POWER_DATA_SIZE];
    let mut ok = 0u64;
    let t0 = now();
    for _ in 0..READ_PATH_CALLS {
        if ina219_read_power(&mut b) == POWER_DATA_SIZE { ok += 1; }
    }
    let total = ns(now() - t0);
    kprintln!("[DRV1] ina219 read path ({}): {} reads ({} answered) in {} ns, {} ns/read",
        azos_drv_sensor::ina219::PLACEMENT, READ_PATH_CALLS, ok, total, total / READ_PATH_CALLS);
}

/// Each driver is waited for, then tested, independently: a missing
/// buzzer driver does not stop the INA219 verdict.
pub fn task(_: usize) {
    // Wave 10 (DRV2): both drivers' idle serve-loop passes, measured
    // before either is called (the INA219 still samples its chip).
    let buzz = wait_for_driver(azos_drv_actuator::buzzer::buzzer_driver_tid);
    let ina = wait_for_driver(azos_drv_sensor::ina219::ina219_driver_tid);
    // Ring-3 placement only, as for the INA219: the kernel host has no
    // serve loop a caller wakes.
    let buzz_idle = buzz.filter(|_| !azos_drv_actuator::buzzer::IN_KERNEL).and_then(|_|
        super::driver_idle_report("[DRV1] buzzer", azos_abi::drv_kind::DRV_KIND_BUZZER));
    // Ring-3 placement only: the kernel host has no serve loop to idle in
    // (it samples on its own clock and is never woken by a caller).
    let ina_idle = ina.filter(|_| !azos_drv_sensor::ina219::IN_KERNEL).and_then(|_|
        super::driver_idle_report("[DRV1] ina219", azos_abi::drv_kind::DRV_KIND_POWER_MON));
    // The proxied call's spread, request to copied-out reply, for each
    // driver: the wait a client pays for the driver to notice a request.
    if buzz.is_some() {
        latency("[DRV1] buzzer", || azos_drv_actuator::buzzer::buzzer_off());
    }
    if ina.is_some() {
        latency("[DRV1] ina219", || azos_drv_sensor::ina219::ina219_stats().is_some());
    }
    // Wave 12 (DRVPLACE): the buzzer's placement conditions first, as the
    // INA219's below.
    if let Err(e) = buzzer_placement_check() {
        kprintln!("[DRV1] buzzer FAIL: {}", e);
    } else { match buzz {
        None if azos_drv_actuator::buzzer::IN_KERNEL =>
            kprintln!("[DRV1] buzzer FAIL: no kernel host of DRV_KIND_BUZZER in {} ms", REGISTER_WAIT_MS),
        None => kprintln!("[DRV1] buzzer FAIL: no ring-3 driver registered DRV_KIND_BUZZER in {} ms",
            REGISTER_WAIT_MS),
        Some(_) if buzz_idle.is_some_and(|r| r > super::DRIVER_IDLE_MAX_PER_S) =>
            kprintln!("[DRV1] buzzer FAIL: idle and silent, {}/s empty fetches (above {}/s)",
                buzz_idle.unwrap_or(0), super::DRIVER_IDLE_MAX_PER_S),
        Some(tid) => match buzzer() {
            Ok((call_us, end_ms)) => kprintln!("[DRV1] buzzer PASS ch={} 440 Hz on/off, 1000 Hz 50 ms tone ended after {} ms ({} tid={} prio={} call={} us proxy-timeouts={})",
                BUZZER_CH, end_ms, azos_drv_actuator::buzzer::PLACEMENT, tid,
                azos_sched::task_priority(tid).unwrap_or(u32::MAX), call_us,
                azos_drv_sys::user_driver_proxy::PROXY_TIMEOUTS.load(core::sync::atomic::Ordering::Relaxed)),
            Err(e) => kprintln!("[DRV1] buzzer FAIL: {}", e),
        },
    } }
    // Wave 11 (DRVPLACE): the same verdict in either placement, plus the
    // placement's own conditions and the read path's cost.
    let placement = azos_drv_sensor::ina219::PLACEMENT;
    if let Err(e) = placement_check() {
        kprintln!("[DRV1] ina219 FAIL: {}", e);
        return;
    }
    if ina.is_some() {
        read_path_cost();
    }
    match ina {
        None => kprintln!("[DRV1] ina219 FAIL: no {} host of DRV_KIND_POWER_MON in {} ms",
            placement, REGISTER_WAIT_MS),
        Some(_) if ina_idle.is_some_and(|r| r > INA_IDLE_MAX_PER_S) =>
            kprintln!("[DRV1] ina219 FAIL: idle, {}/s empty fetches (above {}/s)",
                ina_idle.unwrap_or(0), INA_IDLE_MAX_PER_S),
        Some(tid) => match ina219() {
            Ok((mv, ma, pct, call_us, reads, charge_pct, window_ms, window_samples)) => {
                let (samples, failures, _) = azos_drv_sensor::ina219::ina219_stats().unwrap_or((0, 0, false));
                kprintln!("[DRV1] ina219 PASS {} mV {} mA {}% ({} tid={} prio={} samples={} failures={} call={} us reads={} proxy-timeouts={} charge={}% of {} mA x {} ms over {} samples)",
                    mv, ma, pct, placement, tid, azos_sched::task_priority(tid).unwrap_or(u32::MAX), samples, failures, call_us,
                    reads, azos_drv_sys::user_driver_proxy::PROXY_TIMEOUTS.load(core::sync::atomic::Ordering::Relaxed),
                    charge_pct, ma, window_ms, window_samples)
            }
            Err(e) => kprintln!("[DRV1] ina219 FAIL: {}", e),
        },
    }
}
