// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Buzzer, kernel placement: the in-kernel host of `crates/drivers/buzzer`
//! (Kconfig `DRV_BUZZER_PLACEMENT = kernel`, cargo feature `buzzer-kernel`).
//!
//! The ring-3 host's loop, split in two. A call runs `azos_buzzer::serve`
//! in the caller's context, against [`crate::pwm`] (the controller the
//! ring-3 host reaches through `Cap<Pwm>`), and returns once the first step
//! has started — as the ring-3 driver answers — then wakes the host task.
//! The host task (`kernel/src/tasks/buzzer_host.rs`) advances the timed
//! steps against the clock, parked until the current one is due.
//!
//! One lock, [`HOST`], serialises the two: it is held across a handful of
//! PWM register writes (no I2C transfer, no wait), never across a block.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use azos_abi::drv_kind::buzzer_op;
use azos_buzzer::{serve, Player, Pwm, BUZZER_PWM_CHANNEL};
use azos_sync::SpinLock;

use azos_drv_sys::timebase::{now, TIMER_FREQ};

/// The buzzer's channel through the kernel's PWM driver.
struct KernelPwm;

impl Pwm for KernelPwm {
    fn set_period_ns(&mut self, period_ns: u32) -> bool {
        crate::pwm::pwm_set_period(BUZZER_PWM_CHANNEL, period_ns) >= 0
    }
    fn set_duty_pct(&mut self, pct: u32) -> bool {
        crate::pwm::pwm_set_duty_pct(BUZZER_PWM_CHANNEL, pct) >= 0
    }
    fn enable(&mut self) -> bool {
        crate::pwm::pwm_enable(BUZZER_PWM_CHANNEL) >= 0
    }
    fn disable(&mut self) -> bool {
        crate::pwm::pwm_disable(BUZZER_PWM_CHANNEL) >= 0
    }
}

/// What is playing, and the clock (ms) it was last advanced to.
struct Host {
    player: Player,
    last_ms: u64,
}

static HOST: SpinLock<Host> = SpinLock::new(Host { player: Player::new(), last_ms: 0 });

/// The host task's TID, 0 until it has started.
static HOST_TID: AtomicU32 = AtomicU32::new(0);

/// How a call wakes the host task (`fn(tid)`), registered by the task: this
/// crate sits below the scheduler and cannot name its wake.
static WAKE: AtomicUsize = AtomicUsize::new(0);

fn clock_ms() -> u64 {
    azos_abi::time::ticks_to_ns(now(), TIMER_FREQ) / 1_000_000
}

/// Advance `h` to now: the time since its last advance is played first, so a
/// request that does not replace the sound does not stretch the step.
fn catch_up(h: &mut Host) {
    let t = clock_ms();
    let e = t.saturating_sub(h.last_ms).min(u32::MAX as u64) as u32;
    h.last_ms = t;
    h.player.elapse(&mut KernelPwm, e);
}

/// The host task's step: register it (first call; `wake` is how a call
/// wakes it), advance the sound, and say how long it may park — until the
/// current step is due, or 0 (until woken) when nothing is timed.
pub fn host_step(tid: u32, wake: fn(u32)) -> u32 {
    WAKE.store(wake as usize, Ordering::Release);
    let park = {
        let mut h = HOST.lock();
        if HOST_TID.load(Ordering::Relaxed) == 0 {
            h.last_ms = clock_ms();
            // Silent before serving, as the ring-3 host starts.
            h.player.stop(&mut KernelPwm);
        }
        catch_up(&mut h);
        h.player.park_ms()
    };
    HOST_TID.store(tid, Ordering::Release);
    park
}

/// One request; `true` when the PWM writes of its first step were accepted
/// (the ring-3 reply's byte 0). `false` before the host task started: no
/// host is "no driver", as an unregistered ring-3 kind.
fn call(op: u32, input: &[u8]) -> bool {
    let host = HOST_TID.load(Ordering::Acquire);
    if host == 0 {
        return false;
    }
    let ok = {
        let mut h = HOST.lock();
        catch_up(&mut h);
        serve(&mut h.player, &mut KernelPwm, op, input) == Some(true)
    };
    // The host task re-reads the park: a new sound may be due sooner.
    let w = WAKE.load(Ordering::Acquire);
    if w != 0 {
        // SAFETY: only ever stored from a `fn(u32)` in `host_step`.
        let f: fn(u32) = unsafe { core::mem::transmute(w) };
        f(host);
    }
    ok
}

/// The host task, once started: the counterpart of a registered ring-3
/// driver's TID.
pub fn buzzer_driver_tid() -> Option<u32> {
    match HOST_TID.load(Ordering::Acquire) {
        0 => None,
        t => Some(t),
    }
}

/// Play `freq_hz` for `duration_ms`. Returns once the tone has STARTED.
pub fn buzzer_tone(freq_hz: u16, duration_ms: u32) -> bool {
    let f = freq_hz.to_le_bytes();
    let d = duration_ms.to_le_bytes();
    call(buzzer_op::TONE, &[f[0], f[1], d[0], d[1], d[2], d[3]])
}

/// Start a continuous tone; `0` stops.
pub fn buzzer_on(freq_hz: u16) -> bool {
    call(buzzer_op::ON, &freq_hz.to_le_bytes())
}

/// Stop whatever is playing.
pub fn buzzer_off() -> bool {
    call(buzzer_op::OFF, &[])
}

/// A 100 ms beep at `TONE_OK`.
pub fn buzzer_beep() -> bool {
    call(buzzer_op::BEEP, &[])
}

/// Three 80 ms beeps at `TONE_ALERT`, 60 ms apart.
pub fn buzzer_alert() -> bool {
    call(buzzer_op::ALERT, &[])
}

/// C4 - E4 - G4 - C5.
pub fn buzzer_startup() -> bool {
    call(buzzer_op::STARTUP, &[])
}

/// The chip-logic source this host runs (`tools/chip_source_check.py`).
pub const SOURCE_MARKER: &[u8] = &azos_buzzer::SOURCE_MARKER;
