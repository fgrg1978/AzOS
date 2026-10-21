// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Piezo buzzer, the kernel host (wave 12 DRVPLACE).
//!
//! One chip-logic source, `crates/drivers/buzzer`, and two hosts: this one,
//! in the kernel, and `userspace/drivers/buzz_drv`, in ring 3, serving the
//! same `Buzzer` interface on `endpoint.buzzer`. Which one runs is the
//! topology row's placement (`azos_topology::placement`) and it can change
//! while the system runs (a `stateless` row), so both are always built.
//!
//! [`KernelBuzzer`] is the kernel host as an implementation of the interface:
//! a call runs the chip logic in the caller's context against
//! [`crate::pwm`] (the controller the ring-3 host reaches through the `pwm`
//! endpoint) and returns once the first step has started, as the ring-3 host
//! answers, then wakes the host task. The host task
//! (`kernel/src/tasks/buzzer_host.rs`) advances the timed steps against the
//! clock, parked until the current one is due. A direct-call stub over it
//! (`BuzzerDirect<KernelBuzzer>`) is what a kernel caller holds while the
//! driver is placed here; `kernel/src/buzzer.rs` is the caller.
//!
//! One lock, [`HOST`], serialises the two: it is held across a handful of
//! PWM register writes (no I2C transfer, no wait), never across a block.
//!
//! Not read by any safety decision, which is what allows the ring-3 placement.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use azos_buzzer::{Driver, Pwm, BUZZER_PWM_CHANNEL};
use azos_devif::{outcome, Buzzer, Out};
use azos_sync::SpinLock;

use azos_drv_sys::timebase::{now, TIMER_FREQ};

/// C4 (middle C), Hz.
pub const TONE_C4: u16 = azos_buzzer::TONE_C4;
/// A4 (concert pitch), Hz.
pub const TONE_A4: u16 = 440;
/// Acknowledgment tone, Hz.
pub const TONE_OK: u16 = azos_buzzer::TONE_OK;
/// Alert tone, Hz.
pub const TONE_ALERT: u16 = azos_buzzer::TONE_ALERT;
/// The PWM channel both hosts drive.
pub use azos_buzzer::BUZZER_PWM_CHANNEL as PWM_CHANNEL;

/// The buzzer's channel through the kernel's PWM driver.
pub struct KernelPwm;

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
    drv: Driver<KernelPwm>,
    last_ms: u64,
}

static HOST: SpinLock<Host> =
    SpinLock::new(Host { drv: Driver { player: azos_buzzer::Player::new(), pwm: KernelPwm }, last_ms: 0 });

/// The host task's TID, 0 while no host is serving.
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
    h.drv.elapse(e);
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
            h.drv.off();
        }
        catch_up(&mut h);
        h.drv.player.park_ms()
    };
    HOST_TID.store(tid, Ordering::Release);
    park
}

/// The host is gone (its task ended, or the driver moved to ring 3): no call
/// is served here until a new host task registers, and nothing it was playing
/// is remembered. The channel is left as it is; the next host, wherever it
/// runs, silences it before it serves.
pub fn host_gone() {
    let mut h = HOST.lock();
    HOST_TID.store(0, Ordering::Release);
    h.drv.player = azos_buzzer::Player::new();
}

/// The worst time, in nanoseconds, of `rounds` rounds of the register writes a
/// sound starts with (period, duty, enable's twin: disable) on the real
/// controller, with the duty at 0 and the channel off, so nothing sounds. What
/// a call to this host costs, measured on the hardware it will run on; 0 when
/// the controller refuses the writes (no PWM: nothing is measured). The
/// kernel measures it at boot, before any host runs, and a move into the
/// kernel is admitted against it.
pub fn calibrate(rounds: u32) -> u64 {
    let mut pwm = KernelPwm;
    let mut worst = 0;
    for _ in 0..rounds {
        let t0 = now();
        let ok = pwm.set_period_ns(1_000_000) && pwm.set_duty_pct(0) && pwm.disable();
        let dt = now().saturating_sub(t0);
        if !ok {
            return 0;
        }
        worst = worst.max(azos_abi::time::ticks_to_ns(dt, TIMER_FREQ));
    }
    worst
}

/// The host task, once started.
pub fn host_tid() -> Option<u32> {
    match HOST_TID.load(Ordering::Acquire) {
        0 => None,
        t => Some(t),
    }
}

/// The kernel host as the `Buzzer` interface: each call runs the chip logic in
/// the caller's context. `NOT_READY` before the host task started or after it
/// is gone: no host is "no driver".
#[derive(Clone, Copy, Default)]
pub struct KernelBuzzer;

fn call(f: impl FnOnce(&mut Driver<KernelPwm>) -> Out<()>) -> Out<()> {
    let host = HOST_TID.load(Ordering::Acquire);
    if host == 0 {
        return Out::err(outcome::NOT_READY);
    }
    let out = {
        let mut h = HOST.lock();
        catch_up(&mut h);
        f(&mut h.drv)
    };
    // The host task re-reads the park: a new sound may be due sooner.
    let w = WAKE.load(Ordering::Acquire);
    if w != 0 {
        // SAFETY: only ever stored from a `fn(u32)` in `host_step`.
        let f: fn(u32) = unsafe { core::mem::transmute(w) };
        f(host);
    }
    out
}

impl Buzzer for KernelBuzzer {
    fn tone(&mut self, freq_hz: u32, ms: u32) -> Out<()> { call(|d| d.tone(freq_hz, ms)) }
    fn on(&mut self, freq_hz: u32) -> Out<()> { call(|d| d.on(freq_hz)) }
    fn off(&mut self) -> Out<()> { call(|d| d.off()) }
    fn beep(&mut self) -> Out<()> { call(|d| d.beep()) }
    fn alert(&mut self) -> Out<()> { call(|d| d.alert()) }
    fn startup(&mut self) -> Out<()> { call(|d| d.startup()) }
}

/// The chip-logic source this host runs (`tools/chip_source_check.py`).
pub const SOURCE_MARKER: &[u8] = &azos_buzzer::SOURCE_MARKER;
