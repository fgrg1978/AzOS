// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The e-stop GPIO smoke.

use crate::*;

/// estop-gpio-smoke: the PHYSICAL kill switch, the third of the four e-stop
/// sources, and the only one QEMU cannot present on its own.
///
/// **Why a task and not a line in CONFIG.INI.** The kill switch is active-low
/// (no `gpio-keys` node describes it on QEMU, so the task takes the wiring
/// default) and every simulated GPIO pin powers up reading 0. On a board the
/// pin sits high through a pull-up and the switch pulls it down; QEMU models
/// the pin and not the circuit. So an image that merely set
/// `estop_gpio_pin=30` would latch the e-stop at the arm, before anything
/// could move, and the scenario would prove nothing. That is also why no
/// image in this tree has ever configured it.
///
/// **The circuit is `gpio_inject`.** The pin is the kill switch's input; this
/// task plays the switch and its pull-up from outside, and the simulation
/// takes the edge as the boards' interrupt handler does (acknowledge, mask,
/// stamp, wake the `kill-switch` task). So the press below goes through the
/// edge path the boards take, and the task's `edge to latch` line is the
/// measurement the row reads.
///
/// **Order matters and closes the window by construction.** The pin is driven
/// HIGH first — the released switch — and only then is the pin number stored
/// into `CFG_ESTOP_GPIO_PIN`, so there is no interval in which the task can
/// arm a switch reading a floating 0. Configuring through the file could not
/// give that guarantee: the config is applied long before this runs.
///
/// Pin 30 belongs to nothing else here: 0-3 are the two H-bridges, 13-15 carry
/// the sensor-bus flags, and 20 and 0 are the two GPIO capabilities the
/// topology grants to ring 3.
#[cfg(feature = "estop-gpio-smoke")]
pub(crate) fn estop_gpio_smoke_task(_arg: usize) {
    use azos_drv_gpio::gpio::{gpio_inject, gpio_set_direction, GpioDir};
    const PIN: u32 = 30;

    gpio_set_direction(PIN, GpioDir::Input);
    gpio_inject(PIN, true);
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
    gpio_inject(PIN, false);

    // Stay alive 8 s for the record to reach the disk and for the scenario to
    // see whether anything drives afterwards.
    let end = now() + 8 * TIMER_FREQ;
    while now() < end { azos_sched::task_yield(); }
    // What the recorder did with the press, for a red latch row to read.
    let (durable, lost, pending) = azos_actuation::logger::logger_latch_stats();
    let a = azos_actuation::logger::logger_analytics();
    kprintln!("[ESTOPGPIO] recorder: latch durable={} lost={} pending={} flusher passes={} dropped={} flush_errors={}",
        durable, lost, pending, azos_actuation::logger::logger_flusher_passes(),
        a.events_dropped, a.flush_errors);
    kprintln!("[ESTOPGPIO] DONE");
}
