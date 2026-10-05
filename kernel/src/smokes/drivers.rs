// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Driver smokes: the ring-3 GPIO driver smoke, proxy round-trip and idle
//! reports, and the e-stop GPIO smoke.

use crate::*;

/// Set when `gpio_user_driver_smoke_task` has finished, whatever its verdict:
/// the M4 supervisor smoke kills the driver only after this, so it cannot turn
/// the AQ3 smoke's own lines into failures.
#[cfg(feature = "qemu")]
pub(crate) static GPIO_SMOKE_DONE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "qemu")]
pub(crate) fn gpio_user_driver_smoke_task(arg: usize) {
    gpio_user_driver_smoke(arg);
    GPIO_SMOKE_DONE.store(true, core::sync::atomic::Ordering::Release);
}

/// E11.AQ3 validation smoke: exercise the ring-3 GPIO driver round-trip.
///
/// Constructs a `UserDriverProxy` for `DRV_KIND_GPIO` and issues a
/// `GPIO_OP_PING` through it. The proxy enqueues the request on the
/// driver-server queue; the userspace `gpio_drv` process (autorun'd) fetches,
/// handles, and replies; the proxy returns the reply. A successful round-trip
/// proves a driver running in a *user process* serves kernel-side callers.
///
/// Retries until `gpio_drv` has registered (it may still be starting), then
/// prints the result once. QEMU-only (validation aid).
///
/// ISA-neutral: `UserDriverProxy`/`azos_driver_server`'s queue and
/// `azos_sched::task_yield` carry no `target_arch` branch, so this was
/// never riscv64-specific — the gate `#[cfg]` above it just meant nothing
/// on aarch64 called it (see `install_ring3_seams`'s doc for the shape of
/// that same mistake elsewhere in the boot code).
#[cfg(feature = "qemu")]
fn gpio_user_driver_smoke(_: usize) {
    use azos_drv_api::{Driver, DriverIsolation, DriverManifest};
    use azos_drv_sys::user_driver_proxy::UserDriverProxy;
    use azos_abi::cap::CapPerms;

    // From the driver server, not restated: the capability seeding grants
    // `DriverRegistry(DRV_KIND_GPIO)` and the two must be the same value.
    use azos_driver_server::DRV_KIND_GPIO;
    const GPIO_OP_PING: u32 = 0;
    const PING_REPLY_TAG: u8 = 0xA5;
    const PING_INPUT: u8 = 0x42;
    /// Outer retry budget while gpio_drv comes up, in ms of counter time.
    /// autorun loads the ELF from FAT32 and exec's it only after boot is well
    /// underway, so the smoke must out-wait that startup. Each failed attempt
    /// is either: (a) submit-fail fast (kind not yet registered) → a 1 ms
    /// sleep; or (b) submit OK + the proxy's blocked 100 ms reply timeout
    /// (gpio_drv didn't reply in this window). It was 20,000 attempts 100
    /// yields apart: a count, whose duration followed host load.
    const SMOKE_WAIT_MS: u64 = 120_000;

    // tid is informational here — request routing is by driver kind.
    let manifest = DriverManifest::new(
        DRV_KIND_GPIO,
        "gpio-user",
        DriverIsolation::UserProcess { tid: 0 },
        CapPerms::RW,
    );
    let proxy = UserDriverProxy::new(manifest);

    let input = [PING_INPUT];
    let mut output = [0u8; 8];
    let give_up = azos_drv_sys::timebase::now()
        .saturating_add(azos_syscall::sleep::ms_to_ticks(SMOKE_WAIT_MS));
    loop {
        match proxy.handle_request(GPIO_OP_PING, &input, &mut output) {
            Ok(n) if n >= 2 && output[0] == PING_REPLY_TAG => {
                kprintln!(
                    "[AQ3] GPIO ring-3 round-trip OK — reply tag={:#04x} echo={:#04x} ({} bytes from user process)",
                    output[0], output[1], n
                );
                // The proxy round trip, timed on this same path so the
                // number before and after a change to the wait is read by the
                // same instrument: `PROXY_TIMING_PINGS` more pings, each timed
                // with the timebase from submit to copied-out reply. Wall
                // clock under TCG — a spread, not an instruction count.
                proxy_round_trip_report(&proxy);
                // Wave 10 (DRV2): how often the driver ran its serve loop for
                // nothing while no client called it. Before
                // `proxy_pi_smoke::start`, whose calls would be counted.
                //
                // Asserted: parked in `SYS_DRIVER_REPLY_WAIT`, an idle driver
                // wakes once per kernel park bound (1 s), not per poll (the
                // 581 loop it replaced measured ~155 000/s). The bound leaves
                // room for a stamped wake or two; a driver back on a poll
                // exceeds it by orders of magnitude.
                if let Some(r) = driver_idle_report("[AQ3] gpio_drv", DRV_KIND_GPIO) {
                    if r > DRIVER_IDLE_MAX_PER_S {
                        kprintln!("[AQ3] gpio_drv idle FAIL: {}/s empty fetches with no client, above {}/s",
                                  r, DRIVER_IDLE_MAX_PER_S);
                    }
                }
                // Wave 7: the scheduling state of the driver that ANSWERED,
                // read live from the scheduler by the registered TID — not the
                // loader's log line. The gate row asserts `priority=24
                // class=best_effort`, what the `GPIODRV.ELF` topology row
                // declares; before wave 7 this read 16/best_effort (the
                // default class raw is best_effort; the priority is what moved).
                // Read after 33 round trips in which this task (16) donated
                // to the driver (24): 24 here is also the proof that every
                // donation was returned.
                match azos_driver_server::driver_owner_tid(DRV_KIND_GPIO) {
                    Some(tid) => {
                        kprintln!(
                            "[AQ3] gpio_drv tid={} runs at priority={} class={}",
                            tid,
                            azos_sched::task_priority(tid).unwrap_or(u32::MAX),
                            azos_syscall::topo_sched::class_name_of(
                                azos_sched::task_class_raw(tid).unwrap_or(u8::MAX)),
                        );
                        #[cfg(feature = "proxy-pi-smoke")]
                        proxy_pi_smoke::start(tid);
                    }
                    None => kprintln!("[AQ3] gpio_drv has no registered owner after a reply FAILED:"),
                }
                return;
            }
            Ok(n) => {
                kprintln!("[AQ3] GPIO ring-3 unexpected reply (len={}, out0={:#04x})", n, output[0]);
                return;
            }
            Err(_) => {
                if azos_drv_sys::timebase::now() >= give_up {
                    kprintln!("[AQ3] GPIO ring-3 round-trip FAILED — no reply from gpio_drv");
                    return;
                }
                azos_syscall::sleep::sleep_ms(1);
            }
        }
    }
}

/// Time `PROXY_TIMING_PINGS` proxy round trips to the ring-3 GPIO driver and
/// print min / median / max in microseconds, plus how many failed.
///
/// Called by `gpio_user_driver_smoke_task` after its first successful round
/// trip, so the driver is known to be up. Informational: no gate row asserts
/// the numbers (they are wall clock under TCG and follow host load); the line
/// exists so the proxy's wait can be compared before and after a change on
/// the same path with the same instrument.
#[cfg(feature = "qemu")]
fn proxy_round_trip_report(proxy: &azos_drv_sys::user_driver_proxy::UserDriverProxy) {
    use azos_drv_api::Driver;
    use azos_drv_sys::timebase::{now, TIMER_FREQ};
    const PROXY_TIMING_PINGS: usize = 32;
    const GPIO_OP_PING: u32 = 0;
    let mut us = [0u64; PROXY_TIMING_PINGS];
    let mut n = 0usize;
    let mut failed = 0u32;
    let spin_before = azos_drv_sys::user_driver_proxy::PROXY_SPIN_REPLIES
        .load(core::sync::atomic::Ordering::Relaxed);
    for _ in 0..PROXY_TIMING_PINGS {
        let mut out = [0u8; 8];
        let t0 = now();
        let r = proxy.handle_request(GPIO_OP_PING, &[0x42], &mut out);
        let dt = now().wrapping_sub(t0);
        match r {
            Ok(_) => {
                us[n] = dt.saturating_mul(1_000_000) / TIMER_FREQ;
                n += 1;
            }
            Err(_) => failed += 1,
        }
    }
    // Wave 10 (DRV2): more than half the pings unanswered within the proxy's
    // 100 ms is a verdict. The driver is parked between pings, so each one
    // is answered only if its submit wakes the driver; without that wake a
    // ping waits for the driver's 1 s park bound and times out (the canary
    // measured N/32 failed; every normal boot measured 0).
    if failed as usize > PROXY_TIMING_PINGS / 2 {
        kprintln!("[AQ3] proxy round trip FAIL: {}/{} pings unanswered within the proxy timeout",
                  failed, PROXY_TIMING_PINGS);
    }
    if n == 0 {
        kprintln!("[AQ3] proxy round trip: 0/{} pings answered", PROXY_TIMING_PINGS);
        return;
    }
    let s = &mut us[..n];
    s.sort_unstable();
    // `spin=` counts the replies the bounded spin found before any block
    // (wave 9): the mechanism, next to the wall-clock spread it is meant to move.
    let spun = azos_drv_sys::user_driver_proxy::PROXY_SPIN_REPLIES
        .load(core::sync::atomic::Ordering::Relaxed)
        .wrapping_sub(spin_before);
    kprintln!("[AQ3] proxy round trip over {} pings: min={}us median={}us max={}us failed={} spin={}",
              n, s[0], s[n / 2], s[n - 1], failed, spun);
}
/// Quiet window [`driver_idle_fetches`] measures over.
#[cfg(feature = "qemu")]
const DRIVER_IDLE_WINDOW_MS: u64 = 3_000;

/// Most empty fetches per second a parked ring-3 driver with nothing timed
/// may show: one per kernel park bound (`DRIVER_PARK_DEFAULT_MS`, 1 s), plus
/// headroom for stamped wakes.
#[cfg(feature = "qemu")]
pub(crate) const DRIVER_IDLE_MAX_PER_S: u64 = 5;

/// Empty-queue fetches (`azos_driver_server::driver_empty_fetches`) of
/// `kind`'s ring-3 driver over [`DRIVER_IDLE_WINDOW_MS`] of this task's sleep,
/// in which the caller sends the driver nothing: `(count, window ms)`. Each is
/// one pass of the driver's serve loop that found no request — its poll, or
/// its park ending with nothing queued. `None` without a registered driver.
#[cfg(feature = "qemu")]
fn driver_idle_fetches(kind: u32) -> Option<(u32, u64)> {
    use azos_drv_sys::timebase::{now, TIMER_FREQ};
    let a = azos_driver_server::driver_empty_fetches(kind)?;
    let t0 = now();
    let end = t0 + DRIVER_IDLE_WINDOW_MS * (TIMER_FREQ / 1000);
    while now() < end {
        azos_sched::task_block(azos_sched::WaitReason::Timer(end));
    }
    let b = azos_driver_server::driver_empty_fetches(kind)?;
    Some((b.wrapping_sub(a), ((now() - t0) * 1000 / TIMER_FREQ).max(1)))
}

/// Print [`driver_idle_fetches`] for `kind` as `<who> idle: N empty fetches
/// in T ms (R/s)`. Informational.
#[cfg(feature = "qemu")]
pub(crate) fn driver_idle_report(who: &str, kind: u32) -> Option<u64> {
    match driver_idle_fetches(kind) {
        Some((n, ms)) => {
            let tenths = n as u64 * 10_000 / ms;
            kprintln!("{} idle: {} empty fetches in {} ms ({}.{}/s)", who, n, ms, tenths / 10, tenths % 10);
            Some(tenths / 10)
        }
        None => {
            kprintln!("{} idle: no registered driver to measure", who);
            None
        }
    }
}

/// reflex-smoke: prove the ring-3 reflex daemon actually reacts to sensors.
///
/// Sequence, all observed through reflex's own stdout:
///   1. wait for the daemon to be up (it prints a banner on entry)
///   2. put an obstacle at 100 mm — below OBSTACLE_CRITICAL_MM (150) — and
///      expect `[reflex] CRITICAL OBSTACLE`
///   3. clear the road to 1500 mm — above OBSTACLE_CLEAR_MM (600) — and
///      expect `[reflex] Clear`
///
/// Step 3 matters as much as step 2. Asserting only the trigger would pass on
/// a daemon wedged permanently in override, which on a robot means motors
/// held in reverse forever.
///
/// QEMU-only: `us_set_distance` writes the simulated distance array that
/// `us_read_mm` serves. On real hardware the value comes from the sensor.
/// estop-gpio-smoke: the PHYSICAL kill switch, the third of the four e-stop
/// sources, and the only one QEMU cannot present on its own.
///
/// **Why a task and not a line in CONFIG.INI.** The poll in `rt_motor_task` is
/// active-low — `gpio_read(pin) == 0` means the switch is pressed — and every
/// simulated GPIO pin powers up reading 0 (`GpioState::new`). On a board the
/// pin sits high through a pull-up and the switch pulls it down; QEMU models
/// the pin and not the circuit. So an image that merely set
/// `estop_gpio_pin=30` would latch the e-stop on the first poll, before
/// anything could move, and the scenario would prove nothing. That is also why
/// no image in this tree has ever configured it, and why this source had no
/// coverage at all.
///
/// **Order matters and closes the window by construction.** The pin is driven
/// HIGH first — the released switch — and only then is the pin number stored
/// into `CFG_ESTOP_GPIO_PIN`, so there is no interval in which the watchdog
/// can see an armed switch reading a floating 0. Configuring through the file
/// could not give that guarantee: the config is applied long before this runs.
///
/// Pin 30 belongs to nothing else here: 0-3 are the two H-bridges, 13-15 carry
/// the sensor-bus flags, and 20 and 0 are the two GPIO capabilities the
/// topology grants to ring 3.
#[cfg(feature = "estop-gpio-smoke")]
pub(crate) fn estop_gpio_smoke_task(_arg: usize) {
    use azos_drv_gpio::gpio::{gpio_set_direction, gpio_write, GpioDir};
    const PIN: u32 = 30;

    gpio_set_direction(PIN, GpioDir::Output);
    gpio_write(PIN, 1);
    azos_config::CFG_ESTOP_GPIO_PIN.store(PIN, Ordering::Relaxed);
    kprintln!("[ESTOPGPIO] kill switch armed on pin {} (released)", PIN);

    // Press once the wheels have been commanded to turn for 2 s of REAL
    // time, or at a 40 s ceiling (the peer drives for 50 s). This used to be
    // a count of 6 M yields: under host load (gate 187, three cargo builds
    // beside it) the count outlasted the peer's whole script, the row saw no
    // press at all, and the two latch rows that reuse this disk fell with it.
    // QEMU's clock follows the host's, as the peer's does; a yield count
    // follows how much CPU the host happened to give this guest. If the
    // wheels never turned, the press still happens at the ceiling and the
    // row's "were the wheels turning" check fails loudly.
    use azos_drv_sys::timebase::{now, TIMER_FREQ};
    let ceiling = now() + 40 * TIMER_FREQ;
    let mut driving_since: Option<u64> = None;
    loop {
        azos_sched::task_yield();
        let t = now();
        let cmd = azos_robot::motor_cmd_read();
        let fresh = azos_robot::motor_cmd_age_ticks() < TIMER_FREQ / 2;
        if fresh && (cmd.speed_l != 0 || cmd.speed_r != 0) {
            let since = *driving_since.get_or_insert(t);
            if t.saturating_sub(since) >= 2 * TIMER_FREQ { break; }
        } else {
            driving_since = None;
        }
        if t >= ceiling { break; }
    }

    kprintln!("[ESTOPGPIO] pressing the kill switch");
    gpio_write(PIN, 0);

    // Stay alive 8 s for the watchdog to poll and for the scenario to see
    // whether anything drives afterwards.
    let end = now() + 8 * TIMER_FREQ;
    while now() < end { azos_sched::task_yield(); }
    kprintln!("[ESTOPGPIO] DONE");
}
