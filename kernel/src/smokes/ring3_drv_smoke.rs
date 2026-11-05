// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DRV1 (wave 9): the functional test of the buzzer and the INA219.
//!
//! Wave 9: both drivers run in ring 3 (`userspace/drivers/buzz_drv`,
//! `userspace/drivers/ina_drv`), started from their `start = true` rows; the
//! kernel API of each is its interface on an endpoint (`crate::buzzer`,
//! `azos_drv_sensor::ina219`), which calls whichever host the driver is in.
//! The assertions are the ones the in-kernel drivers passed before the move.
//!
//! Driven through the kernel API its callers use (`crate::buzzer::*`,
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
    use crate::buzzer as bz;
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
    use azos_drv_sensor::ina219::ina219_stats;
    const NO_STATS: &str = "no stats reply with the integrated charge";
    let p0 = ina219_stats().ok_or(NO_STATS)?;
    let (s0, q0) = (p0.samples, p0.charge_ma_us);
    let t0 = now();
    sleep_ms(CHARGE_WINDOW_MS);
    let p1 = ina219_stats().ok_or(NO_STATS)?;
    let q1 = p1.charge_ma_us;
    let samples = p1.samples.wrapping_sub(s0);
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
    // A kernel-placed driver is a direct call, not a proxied one; the buzzer
    // in ring 3 is an endpoint call.
    let buzzer_in_kernel = crate::buzzer::host() == Some(azos_topology::placement::Host::Kernel);
    let ina_in_kernel = azos_drv_sensor::ina219::placement() == Some(azos_drv_sensor::ina219::Placement::Kernel);
    let what = if (who.ends_with("ina219") && ina_in_kernel) || (who.ends_with("buzzer") && buzzer_in_kernel) {
        "direct call"
    } else {
        "endpoint round trip"
    };
    kprintln!("{} {} over {} calls: min={}us p50={}us p90={}us max={}us failed={}",
        who, what, n, s[0], s[n / 2], s[(n * 9) / 10], s[n - 1], failed);
}

/// What the placement itself promises. The INA219 is where its row says
/// (`kernel/src/powermon.rs` reads it and tells the drivers crate): placed in
/// the kernel, the kernel host task answers and no ring-3 task owns
/// `endpoint.powermon`; placed in ring 3, a task owns it.
fn placement_check() -> Result<(), &'static str> {
    use azos_drv_sensor::ina219::{placement, Placement};
    let row = azos_topology::get().and_then(|t| t.row_place(azos_topology::builder::TASK_INADRV_IMAGE));
    match (placement(), row.map(|r| r.host)) {
        (None, _) => Err("the INA219 is in no host"),
        (Some(Placement::Kernel), Some(azos_topology::placement::Host::Ring3)) =>
            Err("the row places the INA219 in ring 3 and it runs in the kernel"),
        (Some(Placement::Ring3), Some(azos_topology::placement::Host::Kernel)) =>
            Err("the row places the INA219 in the kernel and it runs in ring 3"),
        (Some(Placement::Ring3), None) => Err("placement is ring-3 but the topology declares no INADRV.ELF row"),
        (Some(Placement::Kernel), _) => match crate::powermon::ring3_host_tid() {
            Some(t) => {
                kprintln!("[DRV1] ina219 ring-3 owner tid={} under the kernel placement", t);
                Err("placement is kernel but a ring-3 task owns endpoint.powermon")
            }
            None => Ok(()),
        },
        _ => Ok(()),
    }
}

/// [`placement_check`] for the buzzer. Its row is declared in every build,
/// says the driver is `stateless`, and the driver is in the host the row
/// says (the smoke runs before anything can have moved it).
fn buzzer_placement_check() -> Result<(), &'static str> {
    use azos_topology::placement::Host;
    let row = azos_topology::get()
        .and_then(|t| t.row_place(azos_topology::builder::TASK_BUZZDRV_IMAGE))
        .ok_or("the topology declares no BUZZDRV.ELF row")?;
    if !row.stateless {
        return Err("the BUZZDRV.ELF row is not stateless: the driver cannot move");
    }
    match (row.host, crate::buzzer::host()) {
        (_, None) => Err("the driver is in no host"),
        (Host::Kernel, Some(Host::Ring3)) => Err("the row places the driver in the kernel and it runs in ring 3"),
        (Host::Ring3, Some(Host::Kernel)) => Err("the row places the driver in ring 3 and it runs in the kernel"),
        _ => Ok(()),
    }
}

/// Where the INA219 runs, for the log.
fn placement_str() -> &'static str {
    azos_drv_sensor::ina219::placement().map_or("none", |p| p.as_str())
}

/// Most wakes a second the ring-3 INA219 host may show while nobody calls
/// it: its main thread's sampling (`INA219_POLL_HZ`, 10), plus the bound of a
/// parked ring-3 driver with nothing timed (`DRIVER_IDLE_MAX_PER_S`, 5: one
/// per one-second park, with headroom for stamped wakes). The accept thread
/// waits in `SYS_IPC_ACCEPT` for a call and adds nothing.
const INA_IDLE_MAX_PER_S: u64 = azos_drv_sensor::ina219::INA219_POLL_HZ as u64 + 5;
/// Most kernel entries a second the idle host may make: a sample is two
/// register reads (one I2C call each) and one park, so 8 a sample leaves
/// room for a contended lock's yield and a reconfiguration, plus 20 for the
/// power service's period (a few `DevicePower` calls, each an accept and a
/// reply) and the like. A loop that turns without blocking makes a syscall a
/// turn: thousands a second.
const INA_IDLE_ENTRIES_MAX_PER_S: u64 = azos_drv_sensor::ina219::INA219_POLL_HZ as u64 * 8 + 20;
/// The quiet window [`ring3_idle`] measures over.
const IDLE_WINDOW_MS: u64 = 3_000;

/// What the ring-3 INA219 host did over [`IDLE_WINDOW_MS`] in which this task
/// calls nothing, a second: `wakes` of its threads (a blocked thread made
/// ready: a sampling loop that parks too often) and kernel `entries` (every
/// syscall of every thread: a loop that turns without blocking, which is
/// never woken, shows only here). Both are counted per Domain, and both
/// threads of the driver are in its Domain. `None` when the host is not in
/// ring 3; a count the build does not keep (Kconfig `WAKE_RING_ENTRIES` 0,
/// `DOMAIN_ENTRY_COUNTERS` off) is `None` on its own.
struct Idle {
    wakes: Option<u64>,
    entries: Option<u64>,
}

/// Measure [`Idle`].
///
/// Canaries: runtime `ina219-idle-busy`, the window is not quiet (the smoke
/// calls the host back to back), so the wake bound must fail; ina_drv's
/// cargo feature `accept-spin-canary` (built with `INA_DRV_FEATURES`, by
/// hand), its accept thread turns without blocking, so the entry bound must
/// fail while the wake count stays at the sampling rate.
fn ring3_idle() -> Option<Idle> {
    let tid = crate::powermon::ring3_host_tid()?;
    let key = azos_sched::task_domain(azos_sched::idx_for_tid(tid)?);
    let entries = || azos_sched::domain::entries(key).iter().sum::<u64>();
    let (w0, e0) = (azos_sched::domain::wakes(key)?, entries());
    let t0 = now();
    if canary!("ina219-idle-busy") {
        while now() < t0 + IDLE_WINDOW_MS * MS {
            let _ = azos_drv_sensor::ina219::ina219_stats();
        }
    } else {
        sleep_ms(IDLE_WINDOW_MS);
    }
    let (w1, e1) = (azos_sched::domain::wakes(key)?, entries());
    let ms = ((now() - t0) / MS).max(1);
    let rate = |d: u64| d * 1000 / ms;
    let idle = Idle {
        wakes: (azos_limits::WAKE_RING_ENTRIES != 0).then(|| rate(w1.wrapping_sub(w0))),
        entries: azos_limits::DOMAIN_ENTRY_COUNTERS.then(|| rate(e1.wrapping_sub(e0))),
    };
    kprintln!("[DRV1] ina219 idle over {} ms: {:?} wakes/s (bound {}), {:?} kernel entries/s (bound {})",
        ms, idle.wakes, INA_IDLE_MAX_PER_S, idle.entries, INA_IDLE_ENTRIES_MAX_PER_S);
    Some(idle)
}

/// The idle verdict: `Err` names the bound the host broke.
fn idle_check() -> Result<(), &'static str> {
    let Some(i) = ring3_idle() else { return Ok(()) };
    if i.wakes.is_some_and(|r| r > INA_IDLE_MAX_PER_S) {
        return Err("idle, the ring-3 host woke more than its bound with no call");
    }
    if i.entries.is_some_and(|r| r > INA_IDLE_ENTRIES_MAX_PER_S) {
        return Err("idle, the ring-3 host entered the kernel more than its bound with no call");
    }
    Ok(())
}

/// Reads timed by [`read_path_cost`].
const READ_PATH_CALLS: u64 = 256;

/// The cost of one `ina219_read_power` (the call `SYS_SENSOR_READ(POWER)`
/// makes), in clock ns per read over [`READ_PATH_CALLS`] back-to-back
/// reads. Under `-icount shift=0` one ns is one guest instruction, so the
/// line is the read path's instruction count in this placement: a direct
/// copy of the published state (kernel) against an endpoint round trip to the
/// ring-3 driver. Informational; the gate's placement-parity row
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
        placement_str(), READ_PATH_CALLS, ok, total, total / READ_PATH_CALLS);
}

/// Each driver is waited for, then tested, independently: a missing
/// buzzer driver does not stop the INA219 verdict.
pub fn task(_: usize) {
    let buzz = wait_for_driver(crate::buzzer::driver_tid);
    let ina = wait_for_driver(crate::powermon::driver_tid);
    // The call's spread, request to copied-out reply, for each driver: the
    // wait a client pays for the driver to notice a request.
    if buzz.is_some() {
        latency("[DRV1] buzzer", crate::buzzer::buzzer_off);
    }
    if ina.is_some() {
        latency("[DRV1] ina219", || azos_drv_sensor::ina219::ina219_stats().is_some());
    }
    // The buzzer's placement conditions first, as the INA219's below.
    if let Err(e) = buzzer_placement_check() {
        kprintln!("[DRV1] buzzer FAIL: {}", e);
    } else { match buzz {
        None => kprintln!("[DRV1] buzzer FAIL: no host of the Buzzer interface within {} ms",
            REGISTER_WAIT_MS),
        Some(tid) => match buzzer() {
            Ok((call_us, end_ms)) => kprintln!("[DRV1] buzzer PASS ch={} 440 Hz on/off, 1000 Hz 50 ms tone ended after {} ms ({} tid={} prio={} call={} us)",
                BUZZER_CH, end_ms,
                crate::buzzer::host().map_or("moving", |h| h.as_str()), tid,
                azos_sched::task_priority(tid).unwrap_or(u32::MAX), call_us),
            Err(e) => kprintln!("[DRV1] buzzer FAIL: {}", e),
        },
    } }
    // Wave 11 (DRVPLACE): the same verdict in either placement, plus the
    // placement's own conditions and the read path's cost.
    let placement = placement_str();
    if let Err(e) = placement_check() {
        kprintln!("[DRV1] ina219 FAIL: {}", e);
        return;
    }
    if ina.is_some() {
        read_path_cost();
    }
    match ina {
        None => kprintln!("[DRV1] ina219 FAIL: no {} host of the PowerMon interface in {} ms",
            placement, REGISTER_WAIT_MS),
        Some(tid) => match ina219().and_then(|v| idle_check().map(|()| v)) {
            Ok((mv, ma, pct, call_us, reads, charge_pct, window_ms, window_samples)) => {
                let st = azos_drv_sensor::ina219::ina219_stats().unwrap_or_default();
                kprintln!("[DRV1] ina219 PASS {} mV {} mA {}% ({} tid={} prio={} samples={} failures={} call={} us reads={} charge={}% of {} mA x {} ms over {} samples)",
                    mv, ma, pct, placement, tid, azos_sched::task_priority(tid).unwrap_or(u32::MAX), st.samples, st.failures, call_us,
                    reads, charge_pct, ma, window_ms, window_samples)
            }
            Err(e) => kprintln!("[DRV1] ina219 FAIL: {}", e),
        },
    }
}
