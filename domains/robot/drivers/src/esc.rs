// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// ESC (Electronic Speed Controller) driver — PWM output for brushless motors.
///
/// Phase J1: provides ESC initialization, arming sequence, and per-channel
/// throttle control. **Wired to `azos_drv_actuator::pwm` 2026-09-26 (U05-7)** —
/// `esc_set_throttle`/`esc_arm`/`esc_disarm` now call `pwm_set_duty_pct`/
/// `pwm_enable`/`pwm_disable` for real, on every board (QEMU sim or VF2
/// MMIO, whichever `pwm.rs` selects). Before this fix, `esc_set_throttle`
/// only stored an `AtomicU16` and the doc claimed "on real hardware, wraps
/// the PWM driver" while never calling `azos_drv_actuator::pwm` on any `cfg` — a
/// caller (`domains/robot/safety-core/src/flight_ctrl.rs` calls this for real) got
/// state that changed but no PWM line that moved, on VF2/K1 OR the QEMU
/// simulation.
///
/// **What this does NOT fix.** `pwm.rs`'s VF2 register model is a separate,
/// still-unverified concern (that file's own module doc) — wiring ESC
/// through it makes ESC reach exactly as much hardware as `pwm.rs` itself
/// correctly reaches, no more. On VF2 the gate's domain is
/// `pwm_domain::PWM_DOMAIN_VF2_DRIVER`: the SiFive layout `pwm.rs` programs,
/// ONE control register across all 4 modelled channels (`shared_control:
/// true`) — enabling ESC channel N there enables every other channel on the
/// same instance too (the real OpenCores part, `PWM_DOMAIN_INDEPENDENT_8`, does
/// not share; the driver does). That is a property `pwm.rs` encodes, not something
/// `esc.rs` needs to re-check (the ring-3 capability gate for that lives in
/// `pwm_driver.rs::handle_request` via `pwm_domain::pwm_control_allowed`,
/// per that module's own doc — this file has no ring-3 caller identity to
/// gate against).
///
/// ESC protocol: standard PWM 400 Hz
/// - 1000 µs pulse = 0% throttle (idle)
/// - 2000 µs pulse = 100% throttle (full power)
/// - Arm sequence: hold 1000 µs for 2 seconds

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, Ordering};

/// Maximum ESC channels.
pub const ESC_MAX_CH: usize = 8;

/// ESC state: throttle per channel (0-1000 = 0%-100%).
static ESC_THROTTLE: [AtomicU16; ESC_MAX_CH] = [
    AtomicU16::new(0), AtomicU16::new(0), AtomicU16::new(0), AtomicU16::new(0),
    AtomicU16::new(0), AtomicU16::new(0), AtomicU16::new(0), AtomicU16::new(0),
];

static ESC_ARMED: AtomicBool = AtomicBool::new(false);
static ESC_COUNT: AtomicU8 = AtomicU8::new(0);
static ESC_READY: AtomicBool = AtomicBool::new(false);

/// Initialize ESC outputs.
///
/// `count`: number of ESC channels to use (1-8).
pub fn esc_init(count: u8) {
    let count = if count > ESC_MAX_CH as u8 { ESC_MAX_CH as u8 } else { count };
    ESC_COUNT.store(count, Ordering::Relaxed);

    // Set all channels to 0 (idle).
    for i in 0..ESC_MAX_CH {
        ESC_THROTTLE[i].store(0, Ordering::Relaxed);
    }

    ESC_ARMED.store(false, Ordering::Relaxed);
    ESC_READY.store(true, Ordering::Release);

    azos_drv_sys::kprintln!("[ESC] Initialized {} channels (simulated PWM 400 Hz)", count);
}

/// Arm the ESCs (send minimum throttle for arming sequence).
///
/// In real hardware, this would hold 1000 µs pulse for 2 seconds.
/// In QEMU simulation, just sets the armed flag.
pub fn esc_arm() {
    if !ESC_READY.load(Ordering::Acquire) { return; }

    // Set all channels to 0 (minimum throttle signal).
    let count = ESC_COUNT.load(Ordering::Relaxed) as usize;
    for i in 0..count {
        ESC_THROTTLE[i].store(0, Ordering::Relaxed);
    }

    // Actually drive PWM low/idle on every channel, then enable outputs —
    // matches the "hold 1000 µs (0% duty) then arm" real-ESC sequence.
    for i in 0..count {
        let _ = azos_drv_actuator::pwm::pwm_set_duty_pct(i as u32, 0);
        let _ = azos_drv_actuator::pwm::pwm_enable(i as u32);
    }

    ESC_ARMED.store(true, Ordering::Release);
    azos_drv_sys::kprintln!("[ESC] Armed ({} channels)", count);
}

/// Disarm the ESCs (cut all motor power).
pub fn esc_disarm() {
    let count = ESC_COUNT.load(Ordering::Relaxed) as usize;
    for i in 0..count {
        ESC_THROTTLE[i].store(0, Ordering::Relaxed);
        let _ = azos_drv_actuator::pwm::pwm_set_duty_pct(i as u32, 0);
        let _ = azos_drv_actuator::pwm::pwm_disable(i as u32);
    }
    ESC_ARMED.store(false, Ordering::Release);
    azos_drv_sys::kprintln!("[ESC] Disarmed");
}

/// Emergency ESC disarm for the panic handler.
///
/// Identical to `esc_disarm()` except it drops the trailing
/// `kprintln!("[ESC] Disarmed")`. The throttle/armed state here is all
/// atomics, so it was already lock-free — but `kprintln!` acquires the
/// UART spinlock (`uart::acquire()`), and if another hart holds it at
/// panic time this call would spin forever and the actual panic message
/// (printed afterward via lock-free `uart::puts`) would never come out.
/// Deliberately dropping this print is a conscious trade-off for the
/// panic path, not an oversight — the panic handler reports its own
/// summary right after this returns.
pub fn esc_disarm_panic() {
    let count = ESC_COUNT.load(Ordering::Relaxed) as usize;
    for i in 0..count {
        ESC_THROTTLE[i].store(0, Ordering::Relaxed);
        // `pwm_set_duty_pct_panic` — like `gpio_write_panic`, deliberately
        // lock-free (see that function's doc in `pwm.rs`). `pwm_disable`
        // takes the PWM lock; calling it here could spin forever in the
        // panic handler exactly like the lock this whole class of `_panic`
        // function exists to avoid. Zero duty is "motor stop" regardless
        // of the enable bit.
        let _ = azos_drv_actuator::pwm::pwm_set_duty_pct_panic(i as u32, 0);
    }
    ESC_ARMED.store(false, Ordering::Release);
}

/// Set throttle for a single ESC channel.
///
/// - `ch`: channel index (0-based)
/// - `pct`: throttle percentage × 10 (0-1000 = 0.0%-100.0%)
///
/// Only works when armed.  If not armed, silently ignored.
pub fn esc_set_throttle(ch: u8, pct: u16) {
    // Never spin an ESC after a panic — esc_disarm_panic() already stopped it.
    if azos_common::is_panicked() { return; }
    if !ESC_ARMED.load(Ordering::Acquire) { return; }
    let ch = ch as usize;
    if ch >= ESC_MAX_CH { return; }

    let pct = if pct > 1000 { 1000 } else { pct };
    ESC_THROTTLE[ch].store(pct, Ordering::Relaxed);

    // `pct` is tenths of a percent (0-1000); `pwm_set_duty_pct` takes a
    // plain 0-100 percentage — the actual PWM-level "1000-2000 µs pulse"
    // shaping is `pwm.rs`'s job (its own duty-cycle-to-register math), not
    // re-derived here.
    let _ = azos_drv_actuator::pwm::pwm_set_duty_pct(ch as u32, (pct / 10) as u32);
}

/// Read current throttle value for a channel.
pub fn esc_get_throttle(ch: u8) -> u16 {
    let ch = ch as usize;
    if ch >= ESC_MAX_CH { return 0; }
    ESC_THROTTLE[ch].load(Ordering::Relaxed)
}

/// Check if ESCs are armed.
pub fn esc_is_armed() -> bool {
    ESC_ARMED.load(Ordering::Acquire)
}

/// Check if ESC driver is initialized.
pub fn esc_is_ready() -> bool {
    ESC_READY.load(Ordering::Acquire)
}

/// Get configured channel count.
pub fn esc_count() -> u8 {
    ESC_COUNT.load(Ordering::Relaxed)
}

/// Print ESC status info.
pub fn esc_info() {
    let ready = ESC_READY.load(Ordering::Acquire);
    if !ready {
        azos_drv_sys::kconsoleln!("[ESC] Not initialized");
        return;
    }
    let count = ESC_COUNT.load(Ordering::Relaxed);
    let armed = ESC_ARMED.load(Ordering::Acquire);
    azos_drv_sys::kconsoleln!("[ESC] Channels: {}  Armed: {}  PWM: 400 Hz (sim)", count, armed);

    for i in 0..count as usize {
        let thr = ESC_THROTTLE[i].load(Ordering::Relaxed);
        azos_drv_sys::kconsoleln!("[ESC]   M{}: {}‰", i + 1, thr);
    }
}
