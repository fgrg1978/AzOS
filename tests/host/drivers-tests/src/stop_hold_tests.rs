// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's stop holds what it stopped: the lock-free GPIO and PWM writers
//! (`gpio_write_panic`, `pwm_set_duty_pct_panic`: the panic handler and the
//! motor layer's safe-state drive) against the ordinary writers, on the
//! simulated backends QEMU runs (`gpio.rs`, `pwm.rs`, the real files) and on
//! the shared bookkeeping (`hold.rs`, `pwm_hold.rs`).
//!
//! Finding N345: a command that was past its checks when the kernel drove a
//! wheel to its safe state wrote its pins after the drive and re-drove the
//! actuator. The stop now holds the pin or the channel until its release, and
//! a writer that raced it writes the held value back.
//!
//! Every test uses its own pins and channels: the backends are process-wide
//! statics and the tests run on parallel threads.

use super::gpio::{self, GpioDir};
use super::hold::PinHold;
use super::pwm;
use super::pwm_hold::ChanHold;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::SeqCst};
use std::sync::Arc;

/// **The stop wins until it is released (GPIO).** After the stop, a write at
/// the other level, a toggle and a switch to input are refused and the pin
/// keeps the stop's level; a write of the stop's level passes; the release
/// lets commands through again.
///
/// **Canary.** Make `gpio_write` skip `HOLD.refuses` and `after_write` (the
/// old "a newer command supersedes the stop"): the second assertion fails.
#[test]
fn a_gpio_command_after_the_kernels_stop_is_refused_until_the_release() {
    const P: u32 = 40;
    assert_eq!(gpio::gpio_set_direction(P, GpioDir::Output), 0);
    assert_eq!(gpio::gpio_write(P, 1), 0);
    assert_eq!(gpio::gpio_write_panic(P, 0), 0);
    assert_eq!(gpio::gpio_write(P, 1), -1, "a command changed a held pin");
    assert_eq!(gpio::gpio_read(P), 0);
    assert_eq!(gpio::gpio_toggle(P), -1, "a toggle changed a held pin");
    assert_eq!(gpio::gpio_set_direction(P, GpioDir::Input), -1, "a held pin was floated");
    assert_eq!(gpio::gpio_read(P), 0);
    assert_eq!(gpio::gpio_held(P), Some(0));
    assert_eq!(gpio::gpio_write(P, 0), 0, "a stop was refused");
    assert_eq!(gpio::gpio_set_direction(P, GpioDir::Output), 0);

    assert_eq!(gpio::gpio_release(P), 0);
    assert_eq!(gpio::gpio_held(P), None);
    assert_eq!(gpio::gpio_write(P, 1), 0);
    assert_eq!(gpio::gpio_read(P), 1);
    assert_eq!(gpio::gpio_toggle(P), 0);
    assert_eq!(gpio::gpio_read(P), 0);
}

/// **The stop wins until it is released (PWM).** After the stop to 0 %, a
/// duty command that would change it is refused (the reporting variant says
/// the channel holds 0), the nanosecond write too, a period change keeps the
/// held percentage, a 0 % command passes, and the release lets commands
/// through again.
///
/// **Canary.** Make `write_pct` skip `HOLD.refuses` and `held_after`: the
/// first refusal assertion fails.
#[test]
fn a_pwm_command_after_the_kernels_stop_is_refused_until_the_release() {
    const C: u32 = 6;
    assert_eq!(pwm::pwm_set_period(C, 1_000_000), 0);
    assert_eq!(pwm::pwm_set_duty_pct(C, 60), 0);
    assert_eq!(pwm::pwm_set_duty_pct_panic(C, 0), 0);
    assert_eq!(pwm::pwm_set_duty_pct_reporting(C, 80), Some(0), "a command changed a held channel");
    assert_eq!(pwm::pwm_set_duty_pct(C, 80), -1);
    assert_eq!(pwm::pwm_set_duty(C, 500_000), -1);
    assert_eq!(pwm::pwm_set_period(C, 2_000_000), 0);
    assert_eq!(pwm::pwm_get(C).map(|c| c.duty_ns), Some(0), "the held duty moved");
    assert_eq!(pwm::pwm_held(C), Some(0));
    assert_eq!(pwm::pwm_set_duty_pct(C, 0), 0, "a stop was refused");

    assert_eq!(pwm::pwm_release(C), 0);
    assert_eq!(pwm::pwm_held(C), None);
    assert_eq!(pwm::pwm_set_duty_pct_reporting(C, 80), Some(80));
}

/// **The window, step by step.** The writer checks (no hold), the stop holds
/// and writes, then the writer's store lands: the writer's second check sees
/// the hold, writes the held level back and reports the command as not
/// standing. The same for a channel.
///
/// **Canary.** Make `PinHold::after_write` return `true` without calling
/// `put` (no second check): the pin ends at the writer's level.
#[test]
fn a_writer_that_checked_before_the_stop_and_wrote_after_it_writes_the_stop_back() {
    let h = PinHold::new();
    let pin = std::cell::Cell::new(1u32);
    assert!(!h.refuses(3, 1), "writer: no hold yet");
    h.hold(3, 0);
    pin.set(0); // the stop's write
    pin.set(1); // the writer's store, late
    let stands = h.after_write(3, 1, |_, v| pin.set(v));
    assert!(!stands, "the overtaken command reported success");
    assert_eq!(pin.get(), 0, "the stop was lost to a late writer");

    let c = ChanHold::new();
    assert!(!c.refuses(2, 70));
    c.hold(2, 0);
    assert_eq!(c.held_after(2), Some(0), "the late writer did not see the hold");
}

/// Writers hammer one pin at level 1 while the stop lands at a varying point;
/// after the stop every write is refused and the pin must end at the stop's
/// level, whichever writer was mid-write. `ROUNDS` rounds with `WRITERS`
/// threads each.
///
/// **Canary.** As above (drop the second check in `gpio_write`): some round
/// ends with the pin high.
#[test]
fn concurrent_gpio_writers_never_outlast_the_kernels_stop() {
    const P: u32 = 41;
    const ROUNDS: u32 = 400;
    const WRITERS: usize = 4;
    assert_eq!(gpio::gpio_set_direction(P, GpioDir::Output), 0);
    for round in 0..ROUNDS {
        assert_eq!(gpio::gpio_release(P), 0);
        assert_eq!(gpio::gpio_write(P, 1), 0);
        let go = Arc::new(AtomicBool::new(true));
        let after = Arc::new(AtomicU32::new(0));
        let ws: Vec<_> = (0..WRITERS)
            .map(|_| {
                let (go, after) = (go.clone(), after.clone());
                std::thread::spawn(move || {
                    while go.load(SeqCst) {
                        let held_before = gpio::gpio_held(P).is_some();
                        let rc = gpio::gpio_write(P, 1);
                        if held_before {
                            assert_eq!(rc, -1, "a write issued after the stop was taken");
                            after.fetch_add(1, SeqCst);
                        }
                    }
                })
            })
            .collect();
        for _ in 0..(round % 64) * 50 {
            std::hint::spin_loop();
        }
        assert_eq!(gpio::gpio_write_panic(P, 0), 0);
        // A writer that failed its assertion has stopped counting.
        while after.load(SeqCst) < 4 * WRITERS as u32 && !ws.iter().all(|w| w.is_finished()) {
            std::hint::spin_loop();
        }
        go.store(false, SeqCst);
        for w in ws {
            w.join().unwrap();
        }
        assert_eq!(gpio::gpio_read(P), 0, "round {round}: a writer outlasted the stop");
    }
    assert_eq!(gpio::gpio_release(P), 0);
}

/// The same for a PWM channel: duty writers at 90 % against the stop to 0 %.
///
/// **Canary.** Drop the `held_after` write-back in `pwm.rs`'s `write_pct`:
/// some round ends with the channel at 90 %.
#[test]
fn concurrent_pwm_writers_never_outlast_the_kernels_stop() {
    const C: u32 = 7;
    const ROUNDS: u32 = 400;
    const WRITERS: usize = 4;
    assert_eq!(pwm::pwm_set_period(C, 1_000_000), 0);
    for round in 0..ROUNDS {
        assert_eq!(pwm::pwm_release(C), 0);
        assert_eq!(pwm::pwm_set_duty_pct(C, 90), 0);
        let go = Arc::new(AtomicBool::new(true));
        let after = Arc::new(AtomicU32::new(0));
        let ws: Vec<_> = (0..WRITERS)
            .map(|_| {
                let (go, after) = (go.clone(), after.clone());
                std::thread::spawn(move || {
                    while go.load(SeqCst) {
                        let held_before = pwm::pwm_held(C).is_some();
                        let applied = pwm::pwm_set_duty_pct_reporting(C, 90);
                        if held_before {
                            assert_eq!(applied, Some(0), "a duty issued after the stop was taken");
                            after.fetch_add(1, SeqCst);
                        }
                    }
                })
            })
            .collect();
        for _ in 0..(round % 64) * 50 {
            std::hint::spin_loop();
        }
        assert_eq!(pwm::pwm_set_duty_pct_panic(C, 0), 0);
        // A writer that failed its assertion has stopped counting.
        while after.load(SeqCst) < 4 * WRITERS as u32 && !ws.iter().all(|w| w.is_finished()) {
            std::hint::spin_loop();
        }
        go.store(false, SeqCst);
        for w in ws {
            w.join().unwrap();
        }
        assert_eq!(pwm::pwm_get(C).map(|c| c.duty_ns), Some(0), "round {round}: a writer outlasted the stop");
    }
    assert_eq!(pwm::pwm_release(C), 0);
}
