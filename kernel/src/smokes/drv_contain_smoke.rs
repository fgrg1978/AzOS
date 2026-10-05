// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 13 (RT7): a driver placed in the kernel survives a panic in its host.
//! Feature `drv-contain-smoke` (implies `buzzer-kernel`); the gate row builds
//! it with Kconfig `PANIC_POLICY_CONTAIN`.
//!
//! An observer task:
//!
//! 1. waits for the buzzer's kernel host, and checks the host does its job:
//!    a 50 ms tone, then no call for [`ENDED_WAIT_MS`] — the tone has ended
//!    only if the host task advanced it (a call would also advance it, so
//!    none is made), so the buzzer's PWM channel is off;
//! 2. asks the host to panic (it does so on its next step, holding no lock)
//!    and wakes it with a beep;
//! 3. waits for the isolation (`panic_policy::contained_count`) and for a new
//!    host TID — the supervisor's successor (`SupOrigin::KernelHost`);
//! 4. checks the successor does the same job as in step 1.
//!
//! One verdict line: `[DRVCONTAIN] PASS host tid=<a> -> tid=<b> ...` or
//! `[DRVCONTAIN] FAIL <why>`. With the supervisor off (`sup-canary`) step 3
//! never sees a new TID; with the panic not contained, the machine resets
//! and prints no verdict.

use core::sync::atomic::{AtomicBool, Ordering};

use azos_drv_actuator::buzzer::{buzzer_beep, buzzer_driver_tid, buzzer_tone, BUZZER_PWM_CHANNEL};
use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};

/// How long the observer waits for the host (first start, and successor).
const HOST_WAIT_MS: u64 = 5_000;
/// How long a 50 ms tone gets to end with no call made.
const ENDED_WAIT_MS: u64 = 1_500;
/// Tone length.
const TONE_MS: u32 = 50;

static PANIC_REQUEST: AtomicBool = AtomicBool::new(false);

/// The host's step asks: panic now? True once per request.
pub(crate) fn take_panic_request() -> bool {
    PANIC_REQUEST.swap(false, Ordering::AcqRel)
}

fn ms(n: u64) -> u64 {
    n * (TIMER_FREQ / 1000)
}

fn sleep_until(deadline: u64) {
    while now() < deadline {
        azos_sched::task_block(azos_sched::WaitReason::Timer(deadline));
    }
}

/// Wait until the host TID is `Some` and not `not`.
fn host_other_than(not: u32) -> Option<u32> {
    let end = now() + ms(HOST_WAIT_MS);
    while now() < end {
        match buzzer_driver_tid() {
            Some(t) if t != not => return Some(t),
            _ => sleep_until(now() + ms(10)),
        }
    }
    None
}

fn pwm_on() -> bool {
    azos_drv_actuator::pwm::pwm_get(BUZZER_PWM_CHANNEL).is_some_and(|c| c.enabled)
}

/// A tone that only the host task can end: `(started, on while playing,
/// off after ENDED_WAIT_MS)`.
fn tone_ends() -> (bool, bool, bool) {
    let started = buzzer_tone(440, TONE_MS);
    let on = pwm_on();
    sleep_until(now() + ms(ENDED_WAIT_MS));
    (started, on, !pwm_on())
}

/// Create the observer. Called from `kernel_main` with the other smokes.
pub(crate) fn spawn() {
    azos_sched::task_create("drvcontain-obs", observer_task, 0,
        azos_sched::DEFAULT_PRIORITY);
    kprintln!("[DRVCONTAIN] observer created; policy={}",
        if azos_limits::PANIC_POLICY_CONTAIN { "contain" } else { "reset" });
}

fn observer_task(_: usize) {
    let Some(first) = host_other_than(0) else {
        kprintln!("[DRVCONTAIN] FAIL the buzzer's kernel host never started");
        return;
    };
    let before = tone_ends();
    kprintln!("[DRVCONTAIN] host tid={} before: started={} on={} ended={}",
        first, before.0, before.1, before.2);

    let contained0 = azos_common::panic_policy::contained_count();
    PANIC_REQUEST.store(true, Ordering::Release);
    // The call wakes the host, whose next step panics.
    let _ = buzzer_beep();
    let heir = host_other_than(first);
    let isolations = azos_common::panic_policy::contained_count().wrapping_sub(contained0);
    let after = if heir.is_some() { tone_ends() } else { (false, false, false) };
    kprintln!("[DRVCONTAIN] isolations={} successor={:?} after: started={} on={} ended={}",
        isolations, heir, after.0, after.1, after.2);

    let why = if before != (true, true, true) {
        "the host did not end a tone before the panic"
    } else if isolations != 1 {
        "isolations != 1"
    } else if heir.is_none() {
        "the host was not restarted"
    } else if after != (true, true, true) {
        "the successor did not end a tone"
    } else {
        ""
    };
    if why.is_empty() {
        kprintln!("[DRVCONTAIN] PASS host tid={} -> tid={}", first, heir.unwrap_or(0));
    } else {
        kprintln!("[DRVCONTAIN] FAIL {}", why);
    }
}
