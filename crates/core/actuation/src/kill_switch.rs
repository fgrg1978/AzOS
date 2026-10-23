// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The physical kill switch: its boot-time report, and the task that takes
//! its edges and latches the e-stop.
//!
//! **Edge to stop.** The switch's GPIO raises the controller's interrupt on
//! both edges (`azos_drv_gpio::gpio::gpio_edge_arm`). The handler acknowledges
//! and masks the pin, stamps the edge and wakes [`kill_switch_task`]
//! ([`edge_wake`]); the task samples the level and, on a new press
//! (`azos_drv_gpio::debounce`: the first active sample, no wait), latches and
//! stops (`gate::latch_and_stop`) and then records, exactly as the 500 ms
//! poll in `sys-wdt` it replaces did. The latch is not taken in the handler:
//! `estop_activate` runs the domain's on-latch hooks and the stop hooks drive
//! the motors, which take locks an interrupt must not wait on. So the stop's
//! latency is the handler, one wake of this task and one sample; it pays no
//! debounce window (the window only keeps a bouncing release from being a
//! second press and a second durable record).
//!
//! **Which pin, which polarity, which window.** The pin is CONFIG.INI's
//! `estop_gpio_pin` (signed, fail-closed: `azos_config::signed`), read on
//! every pass, so a pin armed after boot is taken up within a re-check
//! period. Its polarity and debounce window are the device tree's: a
//! `gpio-keys` child that names this pin of the controller
//! (`azos_drv_gpio::gpio::gpio_key`, recorded at the bind). A tree that does
//! not describe the pin gets the wiring this switch has always had, active
//! low with a pull-up, and the binding's default window (5 ms), and the arm
//! line says it is a default.
//!
//! **Why a slow re-check stays** (Kconfig `KILL_SWITCH_RECHECK_MS`). Three
//! things reach no edge to the handler: a switch already pressed when the
//! line is armed (the arm samples it), a controller whose line the kernel
//! could not route (then the re-check is the only reader, and the arm line
//! says "polled"), and the config arming a pin after boot. The re-check is
//! the same sample through the same debounce, so a press the edge already
//! took is not taken twice.

use core::sync::atomic::{AtomicU32, Ordering};
use azos_drv_gpio::debounce::{Step, Switch};
use azos_drv_gpio::gpio::{self, EdgeMode};
use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};

/// Called by the kernel right after CONFIG.INI is loaded.
pub fn report_config() {
    // **Say out loud whether the physical kill switch is armed.**
    //
    // The task arms only `estop_gpio_pin < 64`, so an `estop_gpio_pin` that
    // is malformed or out of range is skipped in exactly the same silence as
    // one that was never configured. The operator who typed
    // `estop_gpio_pin=GPIO5` gets a robot with no kill switch and no
    // indication of it.
    //
    // 255 is the deliberate "no switch" sentinel and stays quiet-ish;
    // anything else out of range is a configuration the operator meant
    // to work, and is recorded as a safety event rather than only
    // printed, because a boot log scrolls past and the recorder does
    // not.
    let p = azos_config::CFG_ESTOP_GPIO_PIN.load(Ordering::Relaxed);
    if p < 64 {
        kprintln!("[SAFETY] kill switch armed on GPIO {}", p);
    } else if p == 255 {
        azos_drv_sys::kwarn!("[SAFETY] kill switch NOT armed — no estop_gpio_pin configured");
    } else {
        azos_drv_sys::kwarn!("[SAFETY] kill switch NOT armed — estop_gpio_pin={} is out of range (0-63)", p);
        crate::logger::log_safety_violation(
            crate::logger::SAFETY_ESTOP_PIN_INVALID,
            0, p);
    }
}

/// The task's id, for [`edge_wake`]; 0 until it runs.
static TID: AtomicU32 = AtomicU32::new(0);

/// The edge's wake (interrupt context; `gpio::set_edge_waker`): a TID wake of
/// the task's timer sleep, stamped when it has not blocked yet, so an edge
/// between its sample and its sleep is not lost.
pub fn edge_wake() -> bool {
    match TID.load(Ordering::Acquire) {
        0 => false,
        tid => azos_sched::scheduler::wake_task_by_tid(tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_))),
    }
}

/// The line the task reads.
struct Armed {
    pin: u32,
    mode: EdgeMode,
    switch: Switch,
}

/// Arm `pin` (`estop_gpio_pin`), or nothing for the "no switch" values.
fn arm(pin: u32) -> Option<Armed> {
    if pin as usize >= gpio::GPIO_MAX_PINS {
        return None;
    }
    let key = gpio::gpio_key(pin);
    let (active_low, debounce_ms) = match key {
        Some(k) => (k.active_low, k.debounce_ms),
        None => (true, gpio::GPIO_KEYS_DEBOUNCE_MS_DEFAULT),
    };
    let Some(mode) = gpio::gpio_edge_arm(pin) else {
        azos_drv_sys::kerr!("[KILLSW] GPIO {} cannot be armed (no controller, or not an input): the kill switch is NOT read", pin);
        return None;
    };
    kprintln!("[KILLSW] armed on GPIO {}: active-{}, debounce {} ms ({}), edges {}",
        pin, if active_low { "low" } else { "high" }, debounce_ms,
        if key.is_some() { "device tree" } else { "no tree description: defaults" },
        match mode {
            EdgeMode::Interrupt => "by interrupt",
            EdgeMode::Polled => "NOT by interrupt (the controller's line is not routed): polled",
        });
    Some(Armed {
        pin,
        mode,
        switch: Switch::new(active_low, debounce_ms as u64 * (TIMER_FREQ / 1000)),
    })
}

/// The kill-switch task (Kconfig `KILL_SWITCH_PRIORITY`, in the real-time
/// band). Sleeps until an edge, the end of a release window, or the re-check
/// period; then samples the armed line, and on a new press latches, stops
/// and records.
pub fn kill_switch_task(_: usize) {
    TID.store(azos_sync::waitqueue::caller_tid(), Ordering::Release);
    let recheck = TIMER_FREQ * azos_limits::KILL_SWITCH_RECHECK_MS as u64 / 1000;
    let mut armed: Option<Armed> = None;
    let mut edges_seen = gpio::gpio_edge_stamp().1;
    loop {
        let pin = azos_config::CFG_ESTOP_GPIO_PIN.load(Ordering::Relaxed);
        if armed.as_ref().map(|a| a.pin) != Some(pin) {
            if let Some(old) = armed.take() {
                gpio::gpio_edge_disarm(old.pin);
            }
            armed = arm(pin);
        }
        let mut deadline = now().saturating_add(recheck);
        if let Some(a) = armed.as_mut() {
            let level = gpio::gpio_read(a.pin);
            let t = now();
            if a.switch.sample(t, level) == Step::Press {
                // Latch and stop, in the one place that sequence lives — see
                // `gate::latch_and_stop` for why the latch precedes the
                // wheels. This switch is the reason that function exists: a
                // copy of the sequence here once missed `estop_activate()`,
                // so the switch stopped the wheels and let the next command
                // move them again. Not cleared when the pin is released: an
                // operator decides when it is safe to resume.
                crate::gate::latch_and_stop();
                let latched = now();
                azos_drv_sys::kwarn!("[KILLSW] GPIO ESTOP (pin {}) — motors stopped, envelope latched", a.pin);
                // The edge that woke this pass, if one did: the stop's latency
                // from the controller's interrupt (the evidence the board run
                // reads against the 1 ms target).
                let (stamp, n) = gpio::gpio_edge_stamp();
                if n != edges_seen && stamp <= t {
                    kprintln!("[KILLSW] edge to latch {} us (pin {})",
                        latched.saturating_sub(stamp) * 1_000_000 / TIMER_FREQ, a.pin);
                }
                // Source 2 = the physical switch: which of the sources fired is
                // the first question after an incident. Durable, after the
                // stop, as every e-stop source writes it.
                let _ = crate::logger::log_safety_violation_durable(
                    crate::logger::SAFETY_ESTOP, 2, a.pin);
            }
            edges_seen = gpio::gpio_edge_stamp().1;
            if let Some(d) = a.switch.deadline() {
                deadline = deadline.min(d);
            }
            // Sampled: the next edge may come. One taken edge per pass, so a
            // chattering line cannot storm the handler.
            if a.mode == EdgeMode::Interrupt {
                gpio::gpio_edge_rearm(a.pin);
            }
        }
        azos_sched::task_block(azos_sched::WaitReason::Timer(deadline));
    }
}
