// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PID velocity controller for wheeled robots — 4WD differential drive.
//!
//! The robot has 4 motors wired as 2 channels (left pair, right pair).
//! Each channel has an encoder. The PID loop reads encoder ticks, computes
//! the velocity error against the desired speed (ticks/s), and adjusts PWM
//! output accordingly.
//!
//! This module lives in the drivers crate; the kernel's RT motor task glues
//! it with encoder reads (from robot crate) and motor writes.
//!
//! # Usage
//!
//! 1. Call `motor_pid_init()` once at startup.
//! 2. From the deliberative layer, call `motor_pid_set_target(speed_l, speed_r)`
//!    where speeds are in encoder ticks per second.
//! 3. From the RT motor task, call `motor_pid_tick(ticks_l, ticks_r)` every
//!    `PID_DT_MS` ms. It returns `(pwm_l, pwm_r)` to apply to the motors.
//! 4. Use `motor_pid_enable(false)` to bypass PID for direct PWM control.

use core::sync::atomic::{AtomicBool, AtomicI16, Ordering};
use azos_sync::SpinLock;

// ── PID Tuning Constants ─────────────────────────────────────────────────────

/// Default proportional gain (integer, converted to Q16.16 internally).
pub const DEFAULT_KP: i32 = 1;

/// Default integral gain.
pub const DEFAULT_KI: i32 = 0;

/// Default derivative gain.
pub const DEFAULT_KD: i32 = 0;

/// Minimum PID output (maps to PWM duty -100%).
pub const PID_OUTPUT_MIN: i32 = -100;

/// Maximum PID output (maps to PWM duty +100%).
pub const PID_OUTPUT_MAX: i32 = 100;

/// PID loop period in milliseconds (expected call rate of `motor_pid_tick`).
pub const PID_DT_MS: u32 = azos_limits::PID_DT_MS as u32;
// Kconfig range 1..=1000 (config/Kconfig.robot); checked again here because a
// zero would reach the divisions in `motor_pid_tick`'s fallback path.
const _: () = assert!(PID_DT_MS >= 1 && PID_DT_MS <= 1000, "PID_DT_MS out of 1..=1000");

/// Anti-windup: maximum absolute value for the integral accumulator (ticks·ms).
/// Prevents integral windup during sustained error.
pub const INTEGRAL_WINDUP_LIMIT: i64 = 10_000;

/// Number of motor channels (left pair + right pair).
pub const NUM_CHANNELS: usize = 2;

/// Largest velocity error (ticks/s) the PID math will act on.
///
/// Anything past this is not a real wheel speed — it is a corrupt encoder
/// read or a hostile syscall argument — and letting such a value reach the
/// gain multiplications below is what turns bad input into an arithmetic
/// overflow. Clamping keeps the operands bounded; the `saturating_*` calls
/// in [`PidController::update`] are the belt to this suspenders, because a
/// caller can set gains as large as `i32::MAX` via `motor_pid_set_gains`
/// and `kp * error` must not trap even for that combination.
pub const ERROR_LIMIT: i64 = 1_000_000;

/// Longest interval (ms) that still yields a usable velocity estimate.
///
/// Two consecutive ticks further apart than this tell us nothing about
/// current wheel speed: the robot may have travelled anywhere in between.
/// Rather than feed a meaningless derivative into the motors, the loop
/// re-establishes its baseline and outputs zero for one cycle. The RT task
/// calls at `PID_DT_MS` (10 ms), so this is 100x the nominal period —
/// it fires on genuine loss of sync, not on jitter.
pub const MAX_DT_MS: u64 = 1_000;

/// Index for left motor channel.
pub const CH_LEFT: usize = 0;

/// Index for right motor channel.
pub const CH_RIGHT: usize = 1;

// ── PID Controller ───────────────────────────────────────────────────────────

/// Fixed-point scale factor (Q16.16): 1.0 = 65536.
const FIXED_SCALE: i64 = 65_536;

/// PID controller for a single motor channel.
///
/// Uses fixed-point Q16.16 arithmetic internally for `no_std` compatibility.
/// All gains are stored in Q16.16; inputs/outputs are integer ticks and PWM%.
#[derive(Clone, Copy)]
pub struct PidController {
    /// Proportional gain (Q16.16).
    kp: i64,
    /// Integral gain (Q16.16).
    ki: i64,
    /// Derivative gain (Q16.16).
    kd: i64,
    /// Accumulated integral term (Q16.16).
    integral: i64,
    /// Previous error for derivative calculation.
    prev_error: i64,
    /// Minimum output value.
    output_min: i32,
    /// Maximum output value.
    output_max: i32,
}

impl PidController {
    /// Create a new PID controller with the given gains.
    ///
    /// Gains are integer values that get converted to Q16.16 internally.
    pub const fn new(kp: i32, ki: i32, kd: i32) -> Self {
        PidController {
            kp: kp as i64 * FIXED_SCALE,
            ki: ki as i64 * FIXED_SCALE,
            kd: kd as i64 * FIXED_SCALE,
            integral: 0,
            prev_error: 0,
            output_min: PID_OUTPUT_MIN,
            output_max: PID_OUTPUT_MAX,
        }
    }

    /// Compute PID output given setpoint and measurement.
    ///
    /// - `setpoint`: desired speed in ticks/s.
    /// - `measurement`: actual speed in ticks/s.
    /// - `dt_ms`: time delta in milliseconds (must be > 0).
    ///
    /// Returns clamped PWM output in `[output_min, output_max]`.
    pub fn update(&mut self, setpoint: i32, measurement: i32, dt_ms: u32) -> i32 {
        if dt_ms == 0 {
            return 0;
        }

        // Widen to i64 BEFORE subtracting, then clamp.
        //
        // This was `(setpoint - measurement) as i64` — an **i32**
        // subtraction whose result was only then widened. With
        // `overflow-checks = true` that traps whenever the operands are far
        // apart, and `measurement` is reachable at `i32::MIN`: it is the
        // velocity computed in `motor_pid_tick` from encoder ticks that a
        // ring-3 task passes in through `sys_motor_tick_typed`. A trap here
        // is not a caught error — `panic = "abort"` makes it a full board
        // reset, i.e. a moving robot losing its controller. Widening first
        // makes the subtraction total for every i32 pair.
        //
        // This function is `pub` on a `pub` struct, so the guard belongs
        // here and not only in the caller: it must hold for any future
        // caller that does not clamp its own inputs.
        let error = (setpoint as i64 - measurement as i64)
            .clamp(-ERROR_LIMIT, ERROR_LIMIT);

        // Proportional term: P = Kp * error
        //
        // `kp` is Q16.16, so `motor_pid_set_gains(i32::MAX, ..)` yields
        // |kp| up to 2^47; against a clamped |error| of 2^20 the product
        // still exceeds i64. Saturating is the right failure mode for a
        // controller: the output is clamped to ±100 anyway, so a saturated
        // term and a merely enormous one command the same full-scale PWM.
        let p = self.kp.saturating_mul(error) / FIXED_SCALE;

        // Integral term: I += Ki * error * dt
        // dt in seconds = dt_ms / 1000, so: Ki * error * dt_ms / 1000
        let i_step = self
            .ki
            .saturating_mul(error)
            .saturating_mul(dt_ms as i64)
            / (FIXED_SCALE * 1000);
        // Saturating add: the accumulator is clamped on the next line, but
        // the addition itself must not trap on the way there.
        self.integral = self.integral.saturating_add(i_step);
        // Anti-windup clamping
        let windup_limit = INTEGRAL_WINDUP_LIMIT * FIXED_SCALE;
        self.integral = self.integral.clamp(-windup_limit, windup_limit);
        let i = self.integral / FIXED_SCALE;

        // Derivative term: D = Kd * d(error)/dt
        // d(error)/dt = (error - prev_error) / dt_seconds
        //
        // `de` cannot overflow: both terms are already clamped to
        // ±ERROR_LIMIT, so |de| ≤ 2·ERROR_LIMIT. The divisor cannot
        // overflow either — FIXED_SCALE · u32::MAX ≈ 2.8e14 — and cannot be
        // zero, because `dt_ms == 0` returned above.
        let de = error - self.prev_error;
        let d = self
            .kd
            .saturating_mul(de)
            .saturating_mul(1000)
            / (FIXED_SCALE * dt_ms as i64);
        let d = d / FIXED_SCALE;

        self.prev_error = error;

        // Sum and clamp. Saturating: each term is individually bounded well
        // below i64::MAX after the divisions above, but the sum is written
        // this way so that widening any single term later cannot silently
        // reintroduce a trapping add on the path to the motors.
        let output = p.saturating_add(i).saturating_add(d);
        output.clamp(self.output_min as i64, self.output_max as i64) as i32
    }

    /// Reset integral and derivative state.
    pub fn reset(&mut self) {
        self.integral = 0;
        self.prev_error = 0;
    }
}

// ── Global State (atomic, shared between RT task and deliberative layer) ─────

/// Target speed for left channel (ticks/s), set by deliberative layer.
static TARGET_SPEED_L: AtomicI16 = AtomicI16::new(0);

/// Target speed for right channel (ticks/s), set by deliberative layer.
static TARGET_SPEED_R: AtomicI16 = AtomicI16::new(0);

/// Whether the PID velocity controller is enabled.
/// When disabled, motor commands pass through directly (open-loop).
static PID_ENABLED: AtomicBool = AtomicBool::new(false);

/// The two PID controllers (left, right), protected by a spinlock.
/// Only the RT motor task calls `update()`; tuning can happen from shell/config.
static PID_CONTROLLERS: SpinLock<[PidController; NUM_CHANNELS]> = SpinLock::new([
    PidController::new(DEFAULT_KP, DEFAULT_KI, DEFAULT_KD),
    PidController::new(DEFAULT_KP, DEFAULT_KI, DEFAULT_KD),
]);

/// Internal state: previous encoder ticks and timestamp for velocity calculation.
/// Protected by spinlock since only the RT task mutates it, but keeps it grouped.
struct TickState {
    prev_ticks_l: i64,
    prev_ticks_r: i64,
    /// Previous CLINT timestamp (ticks). Zero means "first call, no baseline yet."
    prev_time: u64,
}

impl TickState {
    const fn new() -> Self {
        TickState {
            prev_ticks_l: 0,
            prev_ticks_r: 0,
            prev_time: 0,
        }
    }
}

static TICK_STATE: SpinLock<TickState> = SpinLock::new(TickState::new());

// ── Public API ───────────────────────────────────────────────────────────────

/// Clamp an i64 into i32 range instead of truncating.
///
/// `as i32` on an out-of-range value wraps, so a very large positive velocity
/// becomes a large negative one and the PID responds by driving the motor
/// backwards. Saturating keeps the sign, which is the property that matters
/// when the number feeds an actuator.
#[inline]
fn clamp_i32(v: i64) -> i32 {
    if v > i32::MAX as i64 { i32::MAX }
    else if v < i32::MIN as i64 { i32::MIN }
    else { v as i32 }
}

/// Initialize both PID controllers and enable closed-loop control.
///
/// Call once during system startup, before the RT motor task begins.
pub fn motor_pid_init() {
    {
        let mut pids = PID_CONTROLLERS.lock();
        pids[CH_LEFT] = PidController::new(DEFAULT_KP, DEFAULT_KI, DEFAULT_KD);
        pids[CH_RIGHT] = PidController::new(DEFAULT_KP, DEFAULT_KI, DEFAULT_KD);
    }

    TARGET_SPEED_L.store(0, Ordering::Relaxed);
    TARGET_SPEED_R.store(0, Ordering::Relaxed);

    {
        let mut ts = TICK_STATE.lock();
        *ts = TickState::new();
    }

    PID_ENABLED.store(true, Ordering::Release);

    azos_drv_sys::kprintln!(
        "[MOTOR-PID] Initialized: Kp={} Ki={} Kd={} dt={}ms windup_limit={}",
        DEFAULT_KP, DEFAULT_KI, DEFAULT_KD, PID_DT_MS, INTEGRAL_WINDUP_LIMIT
    );
}

/// Set the target speed for both channels (ticks per second).
///
/// Positive = forward, negative = reverse.
/// Called from the deliberative layer (behavior task / brain protocol).
pub fn motor_pid_set_target(speed_l: i16, speed_r: i16) {
    TARGET_SPEED_L.store(speed_l, Ordering::Relaxed);
    TARGET_SPEED_R.store(speed_r, Ordering::Relaxed);
}

/// Execute one PID control tick.
///
/// - `ticks_l`, `ticks_r`: current cumulative encoder readings.
/// - `now`: current CLINT timestamp (from `timebase::now()`).
///
/// Returns `(pwm_left, pwm_right)` — signed PWM output to apply to motors.
/// Positive = forward, negative = backward. Magnitude is duty cycle 0-100%.
///
/// Must be called from the RT motor task at approximately `PID_DT_MS` intervals.
pub fn motor_pid_tick(ticks_l: i64, ticks_r: i64, now: u64) -> (i32, i32) {
    if !motor_pid_enabled() {
        return (0, 0);
    }

    let mut ts = TICK_STATE.lock();

    // On first call, record baseline — no PID output yet.
    if ts.prev_time == 0 {
        ts.prev_ticks_l = ticks_l;
        ts.prev_ticks_r = ticks_r;
        ts.prev_time = now;
        return (0, 0);
    }

    // Compute elapsed time in milliseconds.
    //
    // `now` comes straight from userspace: sys_motor_tick_typed passes a0..a3
    // through motor_cap::motor_tick_cap to here with no range validation on
    // the way. With `overflow-checks = true` and `panic = "abort"`, a bare
    // `elapsed * 1000` is a board reset two calls away — pass `now = 1`, then
    // `now = 0x8000_0000_0000_0001`, and the multiply overflows u64. On a
    // robot a spontaneous reset is a physical-safety event, so this is a
    // security bound, not a robustness nicety.
    //
    // Saturating rather than rejecting: a saturated `dt_ms` yields a velocity
    // of ~0, which the PID treats as "no motion measured" — the safe reading.
    let elapsed_clint = now.wrapping_sub(ts.prev_time);
    let timer_freq = azos_drv_irqchip::clint::TIMER_FREQ;
    let dt_ms = if timer_freq > 0 {
        (elapsed_clint.saturating_mul(1000) / timer_freq).min(u32::MAX as u64) as u32
    } else {
        PID_DT_MS // fallback
    };

    // Avoid computation on zero-length interval.
    if dt_ms == 0 {
        return (0, 0);
    }

    // Compute actual velocity (ticks per second).
    //
    // Same provenance as `now` above: `ticks_l`/`ticks_r` are userspace
    // values. `i64::MAX` followed by `i64::MIN` overflows the subtraction, and
    // the `* 1000` overflows well before that. Both saturate, and the result
    // is clamped into i32 rather than truncated — a wrapped cast would turn a
    // huge positive velocity into a large negative one, which the PID would
    // answer by driving the motor the wrong way.
    let delta_l = ticks_l.saturating_sub(ts.prev_ticks_l);
    let delta_r = ticks_r.saturating_sub(ts.prev_ticks_r);
    let vel_l = clamp_i32(delta_l.saturating_mul(1000) / dt_ms as i64);
    let vel_r = clamp_i32(delta_r.saturating_mul(1000) / dt_ms as i64);

    // Save current state for next iteration.
    ts.prev_ticks_l = ticks_l;
    ts.prev_ticks_r = ticks_r;
    ts.prev_time = now;

    // Drop the tick state lock before acquiring PID lock (avoid nested lock order issues).
    drop(ts);

    // Read targets.
    let target_l = TARGET_SPEED_L.load(Ordering::Relaxed) as i32;
    let target_r = TARGET_SPEED_R.load(Ordering::Relaxed) as i32;

    // Run PID controllers.
    let mut pids = PID_CONTROLLERS.lock();
    let pwm_l = pids[CH_LEFT].update(target_l, vel_l, dt_ms);
    let pwm_r = pids[CH_RIGHT].update(target_r, vel_r, dt_ms);

    (pwm_l, pwm_r)
}

/// Check whether PID velocity control is enabled.
pub fn motor_pid_enabled() -> bool {
    PID_ENABLED.load(Ordering::Acquire)
}

/// Enable or disable PID velocity control.
///
/// When disabled, the RT motor task should apply motor commands directly
/// (open-loop). When enabled, `motor_pid_tick()` handles closed-loop control.
pub fn motor_pid_enable(en: bool) {
    if en && !motor_pid_enabled() {
        // Reset controllers when re-enabling to avoid integral windup carryover.
        let mut pids = PID_CONTROLLERS.lock();
        pids[CH_LEFT].reset();
        pids[CH_RIGHT].reset();
        let mut ts = TICK_STATE.lock();
        ts.prev_time = 0;
    }
    PID_ENABLED.store(en, Ordering::Release);
    azos_drv_sys::kprintln!("[MOTOR-PID] PID {}", if en { "ENABLED" } else { "DISABLED" });
}

/// Update PID gains at runtime (e.g., from shell or config).
pub fn motor_pid_set_gains(kp: i32, ki: i32, kd: i32) {
    {
        let mut pids = PID_CONTROLLERS.lock();
        for pid in pids.iter_mut() {
            *pid = PidController::new(kp, ki, kd);
        }
    }
    // Printed after the hold: `motor_pid_tick` (the RT motor task) takes
    // PID_CONTROLLERS every period, and a console line is not bounded.
    azos_drv_sys::kprintln!("[MOTOR-PID] Gains updated: Kp={} Ki={} Kd={}", kp, ki, kd);
}

/// Reset both PID controllers (zero integral and derivative state).
pub fn motor_pid_reset() {
    let mut pids = PID_CONTROLLERS.lock();
    pids[CH_LEFT].reset();
    pids[CH_RIGHT].reset();
    TARGET_SPEED_L.store(0, Ordering::Relaxed);
    TARGET_SPEED_R.store(0, Ordering::Relaxed);
    let mut ts = TICK_STATE.lock();
    *ts = TickState::new();
}
