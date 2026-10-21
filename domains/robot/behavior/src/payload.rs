// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! E04: Payload Abstraction — spray pump, gripper servo, camera trigger.
//!
//! The Brain Server sends `PKT_PAYLOAD` commands that route here.
//! All hardware assignments are named constants — no magic numbers.
//!
//! Hardware assignments (VF2 GPIO / PWM):
//!   SPRAY        → GPIO pin 20   (MOSFET drives 12 V pump)
//!   CAM_TRIGGER  → GPIO pin 21   (3.3 V pulse → external camera shutter)
//!   GRIPPER      → PWM channel 4 (hobby servo, 50 Hz)
//!
//! On QEMU the GPIO/PWM drivers use an in-memory simulation, so the same
//! code path runs in simulation and on real hardware — true for the spray
//! pump and the camera trigger (plain GPIO). **Not true for the gripper**:
//! `pwm_set_duty` is unimplemented on real hardware
//! (`azos_drv_actuator::pwm::pwm_set_duty`) and `PAYLOAD_PWM_GRIPPER` (4) is
//! out of range on the real 4-channel JH7110 PWM8 instance (valid 0-3) even
//! if it were — see that const's own doc. `payload_gripper` therefore only
//! moves anything in the QEMU simulation.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use azos_drv_sys::timebase::now;
use azos_drv_gpio::gpio::{GpioDir, gpio_set_direction, gpio_write};
use azos_drv_actuator::pwm::{pwm_enable, pwm_set_period, pwm_set_duty};

use crate::brain_protocol::{
    PayloadCmd,
    PAYLOAD_TYPE_SPRAY, PAYLOAD_TYPE_GRIPPER, PAYLOAD_TYPE_CAM_TRIGGER,
    PAYLOAD_OFF,
};

// ── Hardware pin / channel assignments ───────────────────────────────────────

/// GPIO pin driving the spray pump MOSFET gate.
pub const PAYLOAD_GPIO_SPRAY: u32 = 20;
/// GPIO pin driving the external camera shutter trigger input.
pub const PAYLOAD_GPIO_CAM_TRIGGER: u32 = 21;
/// PWM channel connected to the gripper servo signal wire.
///
/// Currently non-functional on real hardware: `pwm_set_duty` is
/// unimplemented (see `drivers::pwm::pwm_set_duty`) and this channel index
/// (4) is out of range on the real 4-channel JH7110 PWM8 instance (valid:
/// 0-3) even if it were implemented. A working gripper needs its own
/// high-resolution timer to generate the ~50 Hz / 1-2 ms RC-servo signal —
/// the kernel's existing scheduler tick (10 ms) is far too coarse to
/// represent that pulse width at all. Deliberately deferred to hardware
/// bring-up (decided 2026-08): not attempted in this pass.
///
/// **And moving it to channel 2 or 3 is NOT the fix** (owner decision
/// 2026-09-13). The JH7110 instance has one `PWMCFG` for all four channels, and
/// `pwm_set_period` programs its shared scale field — so a 50 Hz servo period
/// set here at `payload_init` would reprogram the drivetrain's PWM frequency
/// at boot, before anything moves. The gripper gets its own PWM instance or a
/// dedicated timer, chosen at bring-up. Until then every call on `vf2` fails
/// the channel bound and says so, which is the safe way for it to be broken.
pub const PAYLOAD_PWM_GRIPPER: u32 = 4;

// ── Servo PWM constants (standard 50 Hz hobby servo) ─────────────────────────

/// Servo frame period: 20 ms = 50 Hz.
pub const GRIPPER_PWM_PERIOD_NS: u32 = 20_000_000;
/// Pulse width for fully open position (~180°): 2 ms.
pub const GRIPPER_PWM_OPEN_NS: u32 = 2_000_000;
/// Pulse width for fully closed position (~0°): 1 ms.
pub const GRIPPER_PWM_CLOSED_NS: u32 = 1_000_000;
/// Pulse width range used for proportional position mapping.
pub const GRIPPER_PWM_RANGE_NS: u32 = GRIPPER_PWM_OPEN_NS - GRIPPER_PWM_CLOSED_NS;

// ── Camera trigger constants ──────────────────────────────────────────────────

/// Camera shutter trigger pulse width — 50 ms, long enough for any DSLR /
/// mirrorless shutter to register. Owner fix, 2026-09-26 (U08-8, M48): was a
/// raw `500_000` (10 MHz QEMU literal) — 125 ms on VF2 (4 MHz), 20.8 ms on
/// K1 (24 MHz). Reachable: `payload_exec`'s shutter path is the one caller
/// (`:169` in this file at the time of the audit), dispatched from both
/// brain paths in `kernel/src/tasks/behavior.rs`.
pub const CAM_TRIGGER_PULSE_TICKS: u64 = azos_drv_sys::timebase::TIMER_FREQ / 20;

// ── Runtime state (lock-free atomics) ────────────────────────────────────────

/// True while the spray pump GPIO is driven high.
static SPRAY_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Current gripper position: 0 = fully closed, 100 = fully open.
static GRIPPER_POS: AtomicU8 = AtomicU8::new(0);

/// True while the shutter line is held high and its pulse has not run out.
static CAM_TRIGGER_ACTIVE: AtomicBool = AtomicBool::new(false);
/// `now()` at the instant the in-flight pulse was raised.
static CAM_TRIGGER_SINCE: AtomicU64 = AtomicU64::new(0);

// ── Initialisation ────────────────────────────────────────────────────────────

/// Initialise payload GPIO outputs and PWM channels.
///
/// Must be called once after `gpio_init()` and `pwm_init()` during boot.
pub fn payload_init() {
    // Spray pump: GPIO output, default off.
    gpio_set_direction(PAYLOAD_GPIO_SPRAY, GpioDir::Output);
    gpio_write(PAYLOAD_GPIO_SPRAY, 0);

    // Camera trigger: GPIO output, default low.
    gpio_set_direction(PAYLOAD_GPIO_CAM_TRIGGER, GpioDir::Output);
    gpio_write(PAYLOAD_GPIO_CAM_TRIGGER, 0);

    // Gripper servo: PWM at 50 Hz, parked at closed position.
    // Every step's return code is checked and logged — silently discarding
    // these previously meant the gripper could fail to move on real
    // hardware with no diagnostic trail (see `drivers::pwm::pwm_set_duty`
    // doc comment: unimplemented on vf2/k1 pending JH7110 TRM duty
    // comparator info, so this WILL fail there today).
    if pwm_set_period(PAYLOAD_PWM_GRIPPER, GRIPPER_PWM_PERIOD_NS) != 0 {
        azos_drv_sys::kerr!(
            "[PAYLOAD] gripper: pwm_set_period(ch={}) failed", PAYLOAD_PWM_GRIPPER
        );
    }
    if pwm_set_duty(PAYLOAD_PWM_GRIPPER, GRIPPER_PWM_CLOSED_NS) != 0 {
        azos_drv_sys::kerr!(
            "[PAYLOAD] gripper: pwm_set_duty(ch={}) failed — gripper will not move \
             to the closed position on this platform", PAYLOAD_PWM_GRIPPER
        );
    }
    if pwm_enable(PAYLOAD_PWM_GRIPPER) != 0 {
        azos_drv_sys::kerr!(
            "[PAYLOAD] gripper: pwm_enable(ch={}) failed", PAYLOAD_PWM_GRIPPER
        );
    }
}

// ── Command dispatch ──────────────────────────────────────────────────────────

/// `actuator_type` byte base for a `log_actuator_cmd` record of a PAYLOAD
/// command, distinct from a motor id (`domains/robot/robot::motor::MAX_MOTORS` is
/// 4, so ids 0-3 are taken) — a reader tells the two domains apart by this
/// offset rather than by which file wrote the record.
pub const PAYLOAD_ACTUATOR_TYPE_BASE: u8 = 0x10;

/// Execute a decoded `PayloadCmd` received from the Brain Server.
///
/// Returns `true` if the command type was recognised, handled, and NOT
/// refused.
///
/// **H22 (coordinator audit, 2026-09-26).** Before this decision this
/// function had no e-stop check at all, no capability, and wrote no record
/// on success — a 12 V spray pump kept running through a latched e-stop,
/// same class of gap `motor.rs`'s chokepoint closed for the wheels. Checked
/// HERE, the single chokepoint both brain paths dispatch through
/// (`kernel/src/tasks/behavior.rs`), the same way `motor_set_reporting` is the wheels'. Capability
/// is not added here — there is no `Cap<Payload>` kind yet, and a ring-3
/// caller cannot reach this function today (no syscall names it) — so this
/// closes the e-stop and record halves of the finding, not the third.
pub fn payload_exec(cmd: PayloadCmd) -> bool {
    if crate::safety::estop_is_active() {
        crate::logger::log_safety_violation(
            crate::logger::SAFETY_PAYLOAD_REFUSED, cmd.payload_type, 0);
        return false;
    }
    let ok = match cmd.payload_type {
        PAYLOAD_TYPE_SPRAY       => payload_spray(cmd.value != PAYLOAD_OFF),
        PAYLOAD_TYPE_GRIPPER     => payload_gripper(cmd.value),
        PAYLOAD_TYPE_CAM_TRIGGER => payload_cam_trigger(),
        _                        => false,
    };
    if ok {
        crate::logger::log_actuator_cmd(
            PAYLOAD_ACTUATOR_TYPE_BASE + cmd.payload_type, cmd.value as i16, 0, 0, 0);
    }
    ok
}

/// Stop every payload actuator that can move — called from `crate::safety::
/// estop_activate()`'s callers via `domains/robot/safety-core::actuation::
/// latch_and_stop`, the one place that sequence lives, so a command already
/// in flight when the latch engages does not keep running until the next
/// `payload_exec` call refuses the NEXT one.
///
/// Writes the hardware line directly rather than calling [`payload_spray`]:
/// that would be circular (this IS the stop the latch check above exists to
/// enforce). The gripper and shutter are left where they are — neither is
/// "irreversible while running" the way a 12 V pump is; only the pump needs
/// an ACTIVE stop, not just a refusal of the next command.
pub fn payload_emergency_stop() {
    gpio_write(PAYLOAD_GPIO_SPRAY, 0);
    SPRAY_ACTIVE.store(false, Ordering::Relaxed);
}

// ── Individual payload actions ────────────────────────────────────────────────

/// Activate or deactivate the spray pump.
///
/// `on = true` → GPIO high (MOSFET on → pump runs).
/// `on = false` → GPIO low (pump off).
pub fn payload_spray(on: bool) -> bool {
    gpio_write(PAYLOAD_GPIO_SPRAY, if on { 1 } else { 0 });
    SPRAY_ACTIVE.store(on, Ordering::Relaxed);
    true
}

/// Set the gripper servo position.
///
/// `pos` is clamped to `0..=100` where 0 = fully closed, 100 = fully open.
/// Maps linearly to the PWM pulse width range 1 ms … 2 ms.
pub fn payload_gripper(pos: u8) -> bool {
    let clamped = pos.min(100) as u32;
    // Linear map: pos=0 → CLOSED_NS, pos=100 → OPEN_NS
    let duty_ns = GRIPPER_PWM_CLOSED_NS + clamped * GRIPPER_PWM_RANGE_NS / 100;
    if pwm_set_duty(PAYLOAD_PWM_GRIPPER, duty_ns) != 0 {
        azos_drv_sys::kerr!(
            "[PAYLOAD] gripper: pwm_set_duty(ch={}, pos={}) failed — gripper did not move",
            PAYLOAD_PWM_GRIPPER, clamped
        );
        return false;
    }
    GRIPPER_POS.store(clamped as u8, Ordering::Relaxed);
    true
}

/// Has an in-flight shutter pulse run its full width? Pure.
#[inline]
pub const fn cam_pulse_is_done(since: u64, now: u64) -> bool {
    now.wrapping_sub(since) >= CAM_TRIGGER_PULSE_TICKS
}

/// Raise the external camera shutter trigger. Returns `false` if a pulse is
/// already in flight.
///
/// **This used to busy-wait for the whole 50 ms pulse, and the caller is a
/// packet handler.** `payload_exec` runs inside `behavior_task`'s dispatch
/// loop, driven by `PKT_PAYLOAD` frames a peer sends — 11 bytes each, and the
/// loop consumes every frame coalesced into one read. Twenty-three of them in
/// a 256-byte recv bought 1.15 s of stall on hart 2: L0's reactive checks did
/// not run, and a `PKT_ESTOP` sitting behind the pulses in the same segment
/// was not read until they had all finished. A remote peer must not be able to
/// buy kernel time by the frame.
///
/// The pulse is a DEADLINE now, lowered by [`payload_tick`] on a later pass of
/// the same loop. Two things come with that, both improvements rather than
/// costs: the line is guaranteed to stay high for at least the full width
/// (the tick granularity can only make it longer, never shorter), and a
/// re-trigger while the pulse is in flight is refused instead of restarting
/// it — which is also what the hardware means. A shutter cannot fire twice
/// inside one of its own pulses.
pub fn payload_cam_trigger() -> bool {
    // `compare_exchange`, not load-then-store: two harts can be inside this
    // function at once and exactly one may raise the line.
    if CAM_TRIGGER_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    CAM_TRIGGER_SINCE.store(now(), Ordering::Relaxed);
    gpio_write(PAYLOAD_GPIO_CAM_TRIGGER, 1);
    true
}

/// Drop the shutter line once its pulse has run its width.
///
/// Called once per pass of `behavior_task`'s loop. Cheap and branch-free when
/// no pulse is in flight, which is almost always.
pub fn payload_tick() {
    if !CAM_TRIGGER_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let since = CAM_TRIGGER_SINCE.load(Ordering::Relaxed);
    if cam_pulse_is_done(since, now()) {
        gpio_write(PAYLOAD_GPIO_CAM_TRIGGER, 0);
        CAM_TRIGGER_ACTIVE.store(false, Ordering::Release);
    }
}

/// Is a shutter pulse currently in flight?
pub fn payload_cam_trigger_active() -> bool {
    CAM_TRIGGER_ACTIVE.load(Ordering::Acquire)
}

// ── State accessors ───────────────────────────────────────────────────────────

/// Returns `true` if the spray pump is currently active.
pub fn payload_spray_active() -> bool {
    SPRAY_ACTIVE.load(Ordering::Relaxed)
}

/// Returns the current gripper position (0 = closed, 100 = open).
pub fn payload_gripper_pos() -> u8 {
    GRIPPER_POS.load(Ordering::Relaxed)
}
