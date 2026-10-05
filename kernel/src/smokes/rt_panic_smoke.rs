// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RT7 rows (`rt-panic-canary`, RFC-0052 §5.5 row R6): a deliberate panic in
//! a non-safety kernel task, on hart 0 — the hart rt-motor and flight-ctrl
//! run on.
//!
//! An observer task on hart 1 arms the flight controller, measures the
//! control loops over [`WINDOW_MS`] (rt-motor's `CONTROL_HEARTBEAT` and
//! flight-ctrl's `FLIGHT_TICKS`), creates the culprit and then:
//!
//! * under `PANIC_POLICY_CONTAIN`, the panic is contained: the observer sees
//!   one isolation, the culprit's slot gone, the global panic flag clear, and
//!   measures both loops again over the same window, sampling the heartbeat
//!   every millisecond for the longest stretch it stood still; then it waits
//!   for flight-ctrl's own Land and Disarm. One verdict line,
//!   `[RT7-SMOKE] PASS` or `[RT7-SMOKE] FAIL <why>`.
//! * otherwise (reset policy, or a context that fails the predicate) the
//!   panic takes the reset path and every hart halts: the observer prints
//!   nothing more. The rows read the panic handler's own verdict line.
//!
//! `rt-panic-canary-safety` (wave 13): no culprit task — rt-motor itself, a
//! registered safety task, panics on its next tick, holding no lock. The
//! policy never contains it: the reset path runs and sets the global panic
//! latch. The observer masks its own interrupts first (so its tick cannot
//! park it), waits for the latch, gives the handler [`LATCH_SETTLE_MS`] to
//! finish on the wire, then commands motor 0 and reads the ESC: one line,
//! `[RT7-SMOKE] latch: panicked=<b> motor_set rc=<n> applied=<duty> esc_armed=<b>`.
//! With the latch kept the motor write is refused (`rc=-1 applied=none`) and
//! the ESC stays disarmed. Then it parks as the timer handler would.
//!
//! `rt-panic-canary-spin`: the culprit panics holding a `SpinLock` taken with
//! `lock()` — NOT `lock_irqsave()`, which would also fail the interrupts-on
//! check, so removing the depth check would not change the outcome and the
//! row would stop being that check's canary.

use core::sync::atomic::{AtomicU32, Ordering};

use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};

/// The control hart: rt-motor and flight-ctrl are pinned here.
const CULPRIT_HART: i8 = 0;
/// The observer's hart.
const OBSERVER_HART: i8 = 1;
/// Settling time after boot before the first window.
const SETTLE_MS: u64 = 2000;
/// Measurement window, before and after the panic.
const WINDOW_MS: u64 = 500;
/// How long the observer waits for the isolation to be recorded.
const CONTAIN_WAIT_MS: u64 = 2000;
/// PASS bound: the heartbeat never stood still longer than this across the
/// panic (rt-motor's period is 1 ms; the bound leaves room for TCG jitter,
/// and a halted hart 0 stands still for the whole window).
const HB_STILL_MAX_US: u64 = 50_000;

/// `rt-panic-canary-safety`: how long the observer waits for the latch.
#[cfg(feature = "rt-panic-canary-safety")]
const LATCH_WAIT_MS: u64 = 2000;
/// `rt-panic-canary-safety`: time left to the panic handler to print its
/// banner and trace dump before the observer's own line.
#[cfg(feature = "rt-panic-canary-safety")]
const LATCH_SETTLE_MS: u64 = 1000;

/// TID of the culprit, for the observer.
static CULPRIT_TID: AtomicU32 = AtomicU32::new(0);

static SPIN: azos_sync::SpinLock<u32> = azos_sync::SpinLock::new(0);

fn ms(n: u64) -> u64 {
    n * (TIMER_FREQ / 1000)
}

fn sleep_until(deadline: u64) {
    while now() < deadline {
        azos_sched::task_block(azos_sched::WaitReason::Timer(deadline));
    }
}

/// Create the observer. Called from `kernel_main` with the other smokes.
pub fn spawn() {
    azos_sched::task_create_affinity("rt7-observer", observer_task, 0,
        azos_sched::DEFAULT_PRIORITY, OBSERVER_HART);
    kprintln!("[RT7-SMOKE] observer created on hart {}; policy={}", OBSERVER_HART,
        if azos_limits::PANIC_POLICY_CONTAIN { "contain" } else { "reset" });
}

fn culprit_task(_: usize) {
    CULPRIT_TID.store(azos_sched::current_task_tid(), Ordering::Release);
    #[cfg(feature = "rt-panic-canary-spin")]
    {
        let g = SPIN.lock();
        kprintln!("[RT7-SMOKE] culprit tid={} panicking with a SpinLock held",
            azos_sched::current_task_tid());
        if *g == 0 {
            panic!("rt-panic-canary: deliberate panic with a SpinLock held");
        }
    }
    #[cfg(not(feature = "rt-panic-canary-spin"))]
    {
        let _ = &SPIN;
        kprintln!("[RT7-SMOKE] culprit tid={} panicking (no lock held)",
            azos_sched::current_task_tid());
        panic!("rt-panic-canary: deliberate panic in a non-safety kernel task");
    }
}

/// `(heartbeat, flight ticks, elapsed ms)` over one window of at least
/// [`WINDOW_MS`] from `start`. The elapsed time is measured, not assumed:
/// the observer's own wake can be late (a host-descheduled vCPU — wave 13
/// saw "+767" and "+953" against ~320 for a nominal 500 ms), and judging
/// counts against the nominal window read a late observer as a control loop
/// that ran 2-3 times too fast, then "lost its period" after the panic.
fn window(start: u64) -> (u32, u32, u64) {
    let hb0 = azos_actuation::watchdog::control_heartbeat();
    let ft0 = azos_safety_core::flight_ctrl::flight_ticks();
    let t0 = now();
    sleep_until(start + ms(WINDOW_MS));
    let hb = azos_actuation::watchdog::control_heartbeat().wrapping_sub(hb0);
    let ft = azos_safety_core::flight_ctrl::flight_ticks().wrapping_sub(ft0);
    (hb, ft, ((now() - t0) / ms(1)).max(1))
}

fn observer_task(_: usize) {
    sleep_until(now() + ms(SETTLE_MS));
    let armed = azos_flight::flight_arm();
    kprintln!("[RT7-SMOKE] flight controller armed: {}", armed);

    let (hb_before, ft_before, el_before) = window(now());
    kprintln!("[RT7-SMOKE] before: heartbeat +{} flight ticks +{} in {} ms",
        hb_before, ft_before, el_before);

    #[cfg(feature = "rt-panic-canary-safety")]
    latch_check();

    let contained0 = azos_common::panic_policy::contained_count();
    azos_sched::task_create_affinity("rt7-culprit", culprit_task, 0,
        azos_sched::DEFAULT_PRIORITY, CULPRIT_HART);

    // Watch the heartbeat every millisecond until the isolation shows up.
    let t_spawn = now();
    let mut last_hb = azos_actuation::watchdog::control_heartbeat();
    let mut last_adv = t_spawn;
    let mut still_max = 0u64;
    let end = t_spawn + ms(CONTAIN_WAIT_MS);
    let mut seen = false;
    while now() < end {
        sleep_until(now() + ms(1));
        let t = now();
        let hb = azos_actuation::watchdog::control_heartbeat();
        if hb != last_hb {
            last_hb = hb;
            last_adv = t;
        }
        still_max = still_max.max(t - last_adv);
        if !seen && azos_common::panic_policy::contained_count() != contained0 {
            seen = true;
        }
        // Keep sampling for one window after the isolation, so the still
        // time covers the panic and its aftermath.
        if seen && t.wrapping_sub(t_spawn) >= ms(WINDOW_MS) {
            break;
        }
    }
    let still_us = still_max * 1_000_000 / TIMER_FREQ;
    let isolations = azos_common::panic_policy::contained_count().wrapping_sub(contained0);
    let tid = CULPRIT_TID.load(Ordering::Acquire);
    // The culprit leaves only after its CRASH.LOG append, which shares the
    // UART and its hart with whatever else prints then (gate 203/204: the
    // behavior task's one-shot `[BENCH-RES]` sweep landed inside the window
    // and the slot was freed just after a fixed 500 ms check). Wait for the
    // exit itself, bounded by CONTAIN_WAIT_MS: a culprit that is never
    // released still fails the row.
    let gone_by = t_spawn + ms(CONTAIN_WAIT_MS);
    while tid != 0 && azos_sched::idx_for_tid(tid).is_some() && now() < gone_by {
        sleep_until(now() + ms(1));
    }
    let culprit_gone = tid != 0 && azos_sched::idx_for_tid(tid).is_none();
    let panicked = azos_common::is_panicked();
    kprintln!("[RT7-SMOKE] isolations={} culprit tid={} gone={} global_panic={} \
               heartbeat still max {} us", isolations, tid, culprit_gone, panicked, still_us);

    let (hb_after, ft_after, el_after) = window(now());
    kprintln!("[RT7-SMOKE] after: heartbeat +{} flight ticks +{} in {} ms",
        hb_after, ft_after, el_after);

    // flight-ctrl's own Land, then Disarm after PANIC_CONTAIN_LAND_MS.
    let land_end = now() + ms(azos_limits::PANIC_CONTAIN_LAND_MS as u64 + 2000);
    let mut landing_seen = false;
    while now() < land_end && azos_flight::is_armed() {
        if azos_flight::flight_mode() == azos_flight::FlightMode::Land {
            landing_seen = true;
        }
        sleep_until(now() + ms(10));
    }
    let disarmed = !azos_flight::is_armed();
    kprintln!("[RT7-SMOKE] flight: Land seen={} disarmed={}", landing_seen, disarmed);

    // Half the pre-panic RATE is the bound (counts over measured elapsed
    // times): the loops keep their period, not merely "advance at all".
    let slower = |a: u32, ea: u64, b: u32, eb: u64| (a as u64) * eb * 2 < (b as u64) * ea;
    let why = if isolations != 1 {
        "isolations != 1"
    } else if !culprit_gone {
        "culprit still has a slot"
    } else if panicked {
        "global panic flag set"
    } else if still_us > HB_STILL_MAX_US {
        "heartbeat stood still too long"
    } else if slower(hb_after, el_after, hb_before, el_before) || hb_after == 0 {
        "rt-motor lost its period"
    } else if slower(ft_after, el_after, ft_before, el_before) || ft_after == 0 {
        "flight-ctrl lost its period"
    } else if !armed || !landing_seen || !disarmed {
        "no Land then Disarm"
    } else {
        ""
    };
    if why.is_empty() {
        kprintln!("[RT7-SMOKE] PASS");
    } else {
        kprintln!("[RT7-SMOKE] FAIL {}", why);
    }
}

/// `rt-panic-canary-safety`: rt-motor panics; the observer reads the latch the
/// reset path leaves behind (see the module doc). Never returns (the last
/// loop); typed `()` so the contain path after its call stays reachable code
/// in this build rather than a warning.
#[cfg(feature = "rt-panic-canary-safety")]
fn latch_check() {
    use azos_arch::Interrupts;
    kprintln!("[RT7-SMOKE] culprit rt-motor panicking (a safety task)");
    // Masked from before the request: this hart's next tick would otherwise
    // park it (`halt_if_panicked`) before it reads anything.
    let irqs = azos_arch::ARCH.disable_all();
    azos_safety_core::rt_motor::request_canary_panic();
    let t0 = now();
    while !azos_common::is_panicked() && now().wrapping_sub(t0) < ms(LATCH_WAIT_MS) {
        core::hint::spin_loop();
    }
    let t1 = now();
    while now().wrapping_sub(t1) < ms(LATCH_SETTLE_MS) {
        core::hint::spin_loop();
    }
    let panicked = azos_common::is_panicked();
    let (rc, applied) = azos_robot::motor_set_reporting(0, azos_robot::MotorDir::Forward, 50);
    let esc_armed = azos_robot_drivers::esc::esc_is_armed();
    match applied {
        Some(d) => kprintln!("[RT7-SMOKE] latch: panicked={} motor_set rc={} applied={} esc_armed={}",
            panicked, rc, d, esc_armed),
        None => kprintln!("[RT7-SMOKE] latch: panicked={} motor_set rc={} applied=none esc_armed={}",
            panicked, rc, esc_armed),
    }
    // Park as the timer handler would; without a latch, say so and go on.
    azos_actuation::watchdog::halt_if_panicked();
    kprintln!("[RT7-SMOKE] FAIL no panic latch {} ms after the request", LATCH_WAIT_MS);
    azos_arch::ARCH.restore(irqs);
    loop {
        sleep_until(now() + ms(1000));
    }
}
