// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! On-board safety profiles — kernel-level safety checks per robot type.
//!
//! These run ON the robot, independent of the brain server. Even if TCP
//! is down, WiFi is dead, and the brain is off, these checks ALWAYS run.
//!
//! Architecture:
//!   Brain safety (policy/safety.py) — high-level, VLM-informed decisions
//!   Kernel safety (this module) — hard limits, cannot be overridden
//!
//! The kernel safety layer runs as part of L0 (emergency stop) in the
//! subsumption arbiter. For the always-runs / always-applied /
//! cannot-be-disabled invariant and its evidence, see the comment on the
//! `layer_emergency_stop` call inside `arbitrate()` in
//! `domains/robot/behavior/src/arbiter.rs` (canonical statement) — this module only
//! computes the `SafetyAction` that L0 consumes.
//!
//! Robot types:
//!   WHEELED  — tilt, battery, obstacle, speed limit
//!   DRONE    — tilt, battery (2-tier), GPS lock, altitude ceiling, comms timeout
//!   HUMANOID — tilt, battery, fall detection (accel magnitude)
//!   ACKERMANN — same as wheeled + steering limit

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use crate::types::*;

// ---------------------------------------------------------------------------
// Robot type constants (must match brain_protocol.rs)
// ---------------------------------------------------------------------------
pub const ROBOT_TYPE_WHEELED: u8 = 0;
pub const ROBOT_TYPE_DRONE: u8 = 1;
pub const ROBOT_TYPE_HUMANOID: u8 = 2;
pub const ROBOT_TYPE_ACKERMANN: u8 = 3;

// ---------------------------------------------------------------------------
// Safety thresholds — named constants, NO magic numbers
// ---------------------------------------------------------------------------

// ── Common (all types) ──────────────────────────────────────────────────────
/// Minimum accel_z (mg) — below this, robot is falling/tipped.
pub const SAFETY_FALL_ACCEL_Z_MG: i32 = 500;
/// Maximum gyro rate (mdps) — above this, robot is spinning out of control.
pub const SAFETY_MAX_GYRO_MDPS: u32 = 90_000;
/// Comms timeout — 5 seconds. Owner fix, 2026-09-26 (U12-9 class, U08-8):
/// was a raw `50_000_000` (10 MHz QEMU literal) — 7.5 s on VF2 (4 MHz), 1.25 s
/// on K1 (24 MHz) — the same per-board tick-unit class `layers.rs:62-67`
/// fixed for `REMOTE_ACTION_MAX_AGE_S` on 2026-09-18. Currently unused (no
/// caller checks it for the wheeled profile — see U08-4/M32: the wheeled
/// robot has NO comms-loss e-stop of its own today, only `sys_wdt`'s timer
/// liveness and `rt_motor.rs`'s own comms-loss stop, which is unlatched and
/// unrecorded — reported, not fixed here, since wiring a NEW caller for this
/// constant is a behavior change beyond a tick-unit fix).
///
/// Wave 11: the seconds come from Kconfig `SAFETY_COMMS_TIMEOUT_S` (Robot
/// menu, default 5); the tick count is still derived here from the board's
/// `TIMER_FREQ`, so it is the same time on every board.
pub const SAFETY_COMMS_TIMEOUT_TICKS: u64 =
    azos_drv_sys::timebase::TIMER_FREQ * azos_limits::SAFETY_COMMS_TIMEOUT_S as u64;

// ── Wheeled ─────────────────────────────────────────────────────────────────
/// Battery cutoff for wheeled robots (mV).
pub const SAFETY_WHEELED_MIN_BATTERY_MV: u16 = 6500;
/// Maximum tilt for wheeled (centidegrees) — ~45°.
pub const SAFETY_WHEELED_MAX_TILT_CDEG: u16 = 4500;
/// Obstacle emergency stop distance (mm).
pub const SAFETY_WHEELED_OBSTACLE_MM: u16 = 150;
/// Maximum motor speed (% of max).
pub const SAFETY_WHEELED_MAX_SPEED_PCT: u8 = 80;

// ── Drone (stricter) ────────────────────────────────────────────────────────
/// Battery: trigger RTL (mV).
pub const SAFETY_DRONE_LOW_BATTERY_MV: u16 = 7000;
/// Battery: trigger immediate LAND (mV).
pub const SAFETY_DRONE_CRITICAL_BATTERY_MV: u16 = 6500;
/// Maximum tilt for drone (centidegrees) — ~35°.
pub const SAFETY_DRONE_MAX_TILT_CDEG: u16 = 3500;
/// Drone comms timeout — 3 seconds (shorter than wheeled). Owner fix,
/// 2026-09-26 (U08-8): was a raw `30_000_000`, the same per-board tick-unit
/// defect class as [`SAFETY_COMMS_TIMEOUT_TICKS`] above — 4.5 s on VF2,
/// 0.75 s on K1, both silently different from the 3 s the doc comment and
/// `check_drone`'s caller assume. This one DOES have a caller
/// (`check_drone`), so the wrong unit was live, not latent.
///
/// Wave 11: the seconds come from Kconfig `SAFETY_DRONE_COMMS_TIMEOUT_S`
/// (Robot menu, default 3), scaled by the board's `TIMER_FREQ` here.
pub const SAFETY_DRONE_COMMS_TIMEOUT_TICKS: u64 =
    azos_drv_sys::timebase::TIMER_FREQ * azos_limits::SAFETY_DRONE_COMMS_TIMEOUT_S as u64;
/// Maximum altitude (mm) — geofence ceiling.
pub const SAFETY_DRONE_MAX_ALTITUDE_MM: i32 = 50_000;
/// Minimum GPS satellites for safe flight.
pub const SAFETY_DRONE_MIN_SATELLITES: u8 = 6;

// ── Humanoid ────────────────────────────────────────────────────────────────
/// Battery cutoff for humanoid (mV).
pub const SAFETY_HUMANOID_MIN_BATTERY_MV: u16 = 6500;
/// Fall detection: accel magnitude threshold (mg).
pub const SAFETY_HUMANOID_FALL_ACCEL_MG: u32 = 4000;

// ---------------------------------------------------------------------------
// Safety action results
// ---------------------------------------------------------------------------

/// Action the safety system demands.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SafetyAction {
    /// No safety violation — continue normal operation.
    None,
    /// Stop all motors immediately.
    EmergencyStop,
    /// Drone: return to launch point.
    ReturnToLaunch,
    /// Drone: land immediately (critical battery).
    LandNow,
    /// Reduce speed to safe limit.
    SpeedLimit(i32),
}

/// Result of a safety check — what happened and what to do.
#[derive(Clone, Copy)]
pub struct SafetyResult {
    pub action: SafetyAction,
    pub violation: SafetyViolation,
}

/// What triggered the safety action.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SafetyViolation {
    None,
    Falling,
    Spinning,
    LowBattery,
    CriticalBattery,
    ObstacleTooClose,
    ExcessiveTilt,
    NoGpsFix,
    AltitudeCeiling,
    CommsTimeout,
    FallDetected,
    Overheated,
    RemoteEstop,
    /// Robot has crossed the circular geofence boundary (E03).
    GeofenceViolation,
    /// The IMU has been invalid/stale for longer than
    /// [`IMU_INCOHERENT_AFTER_TICKS`] (owner decision 2026-09-26, V1.6).
    SensorIncoherent,
}

impl SafetyResult {
    pub const fn safe() -> Self {
        Self { action: SafetyAction::None, violation: SafetyViolation::None }
    }

    pub fn is_violation(&self) -> bool {
        self.violation != SafetyViolation::None
    }
}

// ── Thermal thresholds ──────────────────────────────────────────────────────
/// Maximum operating temperature (centidegrees Celsius) — MPU-6050 limit.
pub const SAFETY_MAX_TEMP_CDEG: i32 = 8500;
/// Warning temperature threshold (centidegrees Celsius).
pub const SAFETY_WARN_TEMP_CDEG: i32 = 7000;

// ---------------------------------------------------------------------------
// The e-stop latch, release authority and safe mode
// ---------------------------------------------------------------------------
// Moved to `azos_actuation::estop` (wave 11): the latch is cross-cutting,
// not robot-specific. Re-exported here so every robot caller keeps its path.
// `crate::estop` is that module (`lib.rs`), so this also resolves when a host
// suite pulls this file in with `#[path]` beside its own copy of the module.
pub use crate::estop::*;

/// Work the latch must do for the robot domain whenever it arms: the cached
/// remote action becomes the stop. `estop_activate` used to do this inline;
/// the latch now lives in `azos_actuation`, which cannot name
/// `crate::remote`, so it runs this through `register_on_latch_hook`.
/// Registered once at boot by `azos_safety_core::actuation::install`,
/// before anything can latch on a running system.
pub fn on_estop_latched() {
    crate::remote::set_last_action(
        crate::remote::stop_action(azos_drv_sys::timebase::now()),
    );
}

// ---------------------------------------------------------------------------
// Current robot type
// ---------------------------------------------------------------------------
// Starts at the type `make config` chose (Kconfig ROBOT_TYPE_ID, Robot menu;
// 0 = wheeled in every other domain and for robot type "None", the value
// every image had before the option existed). Nothing in production calls
// `safety_set_robot_type` today: only host tests change it.
const BUILD_ROBOT_TYPE: u8 = azos_limits::ROBOT_TYPE_ID as u8;
const _: () = assert!(
    BUILD_ROBOT_TYPE <= ROBOT_TYPE_ACKERMANN,
    "ROBOT_TYPE_ID must name a robot type safety.rs knows (0..=3)",
);
static ROBOT_TYPE: AtomicU8 = AtomicU8::new(BUILD_ROBOT_TYPE);

/// Set the robot type for safety checks.
pub fn safety_set_robot_type(robot_type: u8) {
    ROBOT_TYPE.store(robot_type, Ordering::Release);
}

/// Get current robot type.
pub fn safety_robot_type() -> u8 {
    ROBOT_TYPE.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Bounded runtime safety monitor — output envelope (RFC-0033, RFC-0035)
// ---------------------------------------------------------------------------

/// Reduced speed cap (% of max) applied to LOW-CONFIDENCE commands (RFC-0035).
/// When the brain marks a command low-confidence (e.g. a reactive-LLM action vs
/// a deterministic plan/scripted step), the robot self-limits: act, but cautiously.
pub const SAFETY_LOW_CONFIDENCE_CAP_PCT: u8 = 40;

// ── RFC-0037: Graded degrade-level speed caps ────────────────────────────────
//
// Applied in `motor_envelope` AFTER the low-confidence cap. The level→pct
// mapping is `azos_degrade_policy::level_cap_pct()`, a pure function in
// the dep-free leaf crate. This keeps motor-actuation policy out of the TCB
// (`crates/core/ipc`) while remaining independently host-tested in the leaf.
//
// `DEGRADE_LEVEL_CONTAINED` (stop + cap-denial) is also handled in `CapTable::get`
// for user-task actuation; the 0 % cap here ensures the in-kernel motor loop
// (which does NOT go through `get()`) also stops. Both layers are required.
//
// The re-exports below keep the safety-module naming convention for callers
// inside behavior that need these values without importing from the leaf directly.

/// Speed ceiling at `DEGRADE_LEVEL_FULL` (RFC-0037): no extra restriction.
/// Re-exported from `azos_degrade_policy::DEGRADE_SPEED_CAP_FULL_PCT`.
pub const SAFETY_DEGRADE_FULL_CAP_PCT: i32 = azos_degrade_policy::DEGRADE_SPEED_CAP_FULL_PCT;

// The level numbers are declared twice since wave 11: by `azos_ipc::cap`
// (core: it holds the level and enforces containment) and by
// `azos_degrade_policy` (robot: the level -> speed mapping). This crate
// sees both, so the two copies are checked against each other here; a drift
// is a compile error, not a mis-mapped speed cap.
const _: () = {
    use azos_degrade_policy as p;
    use azos_ipc::cap as c;
    assert!(p::DEGRADE_LEVEL_FULL == c::DEGRADE_LEVEL_FULL);
    assert!(p::DEGRADE_LEVEL_CAUTIOUS == c::DEGRADE_LEVEL_CAUTIOUS);
    assert!(p::DEGRADE_LEVEL_SLOW == c::DEGRADE_LEVEL_SLOW);
    assert!(p::DEGRADE_LEVEL_CONTAINED == c::DEGRADE_LEVEL_CONTAINED);
    assert!(p::DEGRADE_LEVEL_MAX == c::DEGRADE_LEVEL_MAX);
};

/// Speed ceiling at `DEGRADE_LEVEL_CAUTIOUS` (RFC-0037): 70 % of per-type max.
/// Re-exported from `azos_degrade_policy::DEGRADE_SPEED_CAP_CAUTIOUS_PCT`.
pub const SAFETY_DEGRADE_CAUTIOUS_CAP_PCT: i32 = azos_degrade_policy::DEGRADE_SPEED_CAP_CAUTIOUS_PCT;

/// Speed ceiling at `DEGRADE_LEVEL_SLOW` (RFC-0037): 30 % of per-type max.
/// Re-exported from `azos_degrade_policy::DEGRADE_SPEED_CAP_SLOW_PCT`.
pub const SAFETY_DEGRADE_SLOW_CAP_PCT: i32 = azos_degrade_policy::DEGRADE_SPEED_CAP_SLOW_PCT;

/// Speed ceiling at `DEGRADE_LEVEL_CONTAINED` (RFC-0037): 0 % — full stop.
/// Re-exported from `azos_degrade_policy::DEGRADE_SPEED_CAP_CONTAINED_PCT`.
pub const SAFETY_DEGRADE_CONTAINED_CAP_PCT: i32 = azos_degrade_policy::DEGRADE_SPEED_CAP_CONTAINED_PCT;

/// Whether the most recent brain command was flagged low-confidence (RFC-0035).
/// Set at command ingest from `FLAG_LOW_CONFIDENCE`; read by `motor_envelope` at
/// the chokepoint. Conservative on staleness: stays low until a high-confidence
/// command clears it (and the watchdog safe-stops on comms loss regardless).
static CMD_LOW_CONF: AtomicBool = AtomicBool::new(false);

/// Record the confidence of the most recent brain command (RFC-0035).
pub fn cmd_set_low_confidence(low: bool) {
    CMD_LOW_CONF.store(low, Ordering::Release);
}

/// Whether the current command context is low-confidence.
pub fn cmd_low_confidence() -> bool {
    CMD_LOW_CONF.load(Ordering::Acquire)
}

/// Bounded runtime safety monitor: the LAST line of defence between any motor
/// command and PWM, applied at the single `rt_motor_task` MotorCmd→PID→PWM
/// chokepoint. **It is NOT structurally unbypassable, and the comment that said
/// so was false.** This function is applied by `rt_motor_task`, one caller of
/// `motor_set` among several: `sys_motor_speed` and `sys_motor_enable` reach
/// the motors without passing through here. What makes the envelope
/// unavoidable is the actuation gate inside `motor_set`
/// (`domains/robot/robot/src/motor.rs`), which calls this. Every command source funnels
/// through it).
///
/// This complements, and does not replace, the sensor-reactive L0 `safety_check`
/// upstream: L0 reacts to the world (obstacle, tilt, battery); this validates the
/// command's own MAGNITUDE — a hard ESTOP override, the per-robot-type speed cap
/// (`SAFETY_*_MAX_SPEED_PCT`), and (RFC-0035) a tighter cap when the brain marked
/// the command low-confidence. `(speed_l, speed_r)` are percent (±100); returns
/// the clamped pair.
///
/// O(1), no allocation, no I/O — its cost is bounded by construction (a couple of
/// branches plus two clamps), not by measurement. This is a runtime-assurance
/// gate, NOT a formally verified component (see RFC-0033; "verified" is reserved
/// for the Phase-5 horizon).
pub fn motor_envelope(speed_l: i32, speed_r: i32) -> (i32, i32) {
    // Hard stop overrides everything — unconditional, highest priority.
    if estop_is_active() {
        return (0, 0);
    }
    // Per-type magnitude cap. Wheeled/Ackermann share the wheeled cap; drone and
    // humanoid actuation has its own envelope on its own path, so pass through
    // here (still clamped to the protocol's ±100 upstream).
    let mut cap: i32 = match safety_robot_type() {
        ROBOT_TYPE_WHEELED | ROBOT_TYPE_ACKERMANN => SAFETY_WHEELED_MAX_SPEED_PCT as i32,
        _ => 100,
    };
    // RFC-0035: confidence-aware real-time — act cautiously on uncertain commands.
    if cmd_low_confidence() {
        cap = cap.min(SAFETY_LOW_CONFIDENCE_CAP_PCT as i32);
    }
    // RFC-0037: graded degrade-level speed ceiling. Applied AFTER the low-confidence
    // cap so both constraints compose (the tighter one wins). The mapping lives in
    // the dep-free leaf crate `azos_degrade_policy` (level_cap_pct); the
    // runtime level state stays in `azos_ipc::cap::degrade_level()`. Unknown
    // levels clamp to 0 (fail-closed) inside level_cap_pct.
    let level_cap: i32 = azos_degrade_policy::level_cap_pct(
        azos_ipc::cap::degrade_level(),
    );
    cap = cap.min(level_cap);
    (speed_l.clamp(-cap, cap), speed_r.clamp(-cap, cap))
}

// ---------------------------------------------------------------------------
// Main safety check — dispatches by robot type
// ---------------------------------------------------------------------------

/// Run all safety checks for the current robot type.
/// This is called from L0 (emergency stop layer) every tick.
///
/// Returns the highest-priority safety action needed.
pub fn safety_check(state: &SensorState) -> SafetyResult {
    // Remote ESTOP — highest priority, unconditional
    if estop_is_active() {
        return SafetyResult {
            action: SafetyAction::EmergencyStop,
            violation: SafetyViolation::RemoteEstop,
        };
    }

    // Common checks first (all robot types)
    let common = check_common(state);
    if common.is_violation() {
        return common;
    }

    // Type-specific checks
    match ROBOT_TYPE.load(Ordering::Relaxed) {
        ROBOT_TYPE_DRONE => check_drone(state),
        ROBOT_TYPE_HUMANOID => check_humanoid(state),
        _ => check_wheeled(state), // wheeled + ackermann
    }
}

// ---------------------------------------------------------------------------
// Common checks (all robot types)
// ---------------------------------------------------------------------------

/// Second, longer bound on top of `SensorBus::IMU_MAX_AGE_TICKS` (200 ms,
/// which is already what `SensorState.imu_valid` means: "a sample arrived
/// AND it is fresh"). Owner decision, 2026-09-26 (V1.6): fail-operational on
/// a dead IMU forever — the behaviour before this decision — reads a robot
/// lying on its side, or one whose sensor died outright, as "nothing to
/// check," exactly the case `sensor_bus.rs`'s own staleness handling was
/// written against. But treating the FIRST invalid tick as a fault would
/// stop the robot on a normal scheduling hiccup, or on the handful of ticks
/// between boot and the first sample — so this is a grace period, not a
/// threshold of one: `check_common` keeps today's "no reading yet, skip the
/// checks that need one" behaviour for up to this long, and only escalates
/// to [`SafetyViolation::SensorIncoherent`] beyond it.
pub const IMU_INCOHERENT_AFTER_TICKS: u64 = azos_drv_sys::timebase::TIMER_FREQ; // ~1 s, per-board

/// CLINT tick the CURRENT stretch of `!imu_valid` started, or 0 while the
/// IMU is valid (or has never been invalid this boot). An edge, not a level:
/// [`check_common`] resets this to 0 the instant a valid sample is seen
/// again, so recovering for even one tick ends the grace period rather than
/// resuming a count from before.
static IMU_INVALID_SINCE: AtomicU64 = AtomicU64::new(0);

/// Whether the durable `SensorIncoherent` record has already been written
/// for the CURRENT stretch of invalidity — "recorded ONCE" (owner decision),
/// matching every other latch-shaped event in this file, not once per tick
/// the condition continues to hold.
static IMU_INCOHERENT_RECORDED: AtomicBool = AtomicBool::new(false);

/// Test-only: put the IMU-staleness tracking back to "valid, never seen
/// invalid" between tests. `cfg(test)` for the same reason as
/// [`test_reset_operator_authority`]'s doc — present only where this file
/// compiles under `cargo test` (this crate's own suite, or
/// `tests/host/behavior-tests`' `#[path]` pull), absent from the kernel binary.
#[cfg(test)]
pub fn test_reset_imu_incoherence() {
    IMU_INVALID_SINCE.store(0, Ordering::Relaxed);
    IMU_INCOHERENT_RECORDED.store(false, Ordering::Relaxed);
}

fn check_common(state: &SensorState) -> SafetyResult {
    // Thermal check — works even without valid IMU flag (temp reads separately)
    if state.temp_cdeg > SAFETY_MAX_TEMP_CDEG {
        return SafetyResult {
            action: SafetyAction::EmergencyStop,
            violation: SafetyViolation::Overheated,
        };
    }

    if !state.imu_valid {
        let now = azos_drv_sys::timebase::now();
        let since = IMU_INVALID_SINCE.load(Ordering::Relaxed);
        let since = if since == 0 {
            // The edge: this is the first invalid tick of a new stretch.
            IMU_INVALID_SINCE.store(now.max(1), Ordering::Relaxed);
            now.max(1)
        } else {
            since
        };
        let elapsed = now.saturating_sub(since);
        if elapsed < IMU_INCOHERENT_AFTER_TICKS {
            // Within the grace period: today's behaviour — no reading yet,
            // skip the checks below that need one, but do not (yet) stop.
            return SafetyResult::safe();
        }
        if !IMU_INCOHERENT_RECORDED.swap(true, Ordering::Relaxed) {
            let _ = crate::logger::log_safety_violation_durable(
                crate::logger::SAFETY_SENSOR_INCOHERENT, 0, elapsed as u32);
        }
        return SafetyResult {
            action: SafetyAction::EmergencyStop,
            violation: SafetyViolation::SensorIncoherent,
        };
    }
    // A valid sample: end whatever stretch of invalidity was being tracked.
    IMU_INVALID_SINCE.store(0, Ordering::Relaxed);
    IMU_INCOHERENT_RECORDED.store(false, Ordering::Relaxed);

    // Falling: accel_z too low
    if state.accel_mg[2] < SAFETY_FALL_ACCEL_Z_MG {
        return SafetyResult {
            action: SafetyAction::EmergencyStop,
            violation: SafetyViolation::Falling,
        };
    }

    // Spinning: any gyro axis too fast
    if state.gyro_mdps[0].unsigned_abs() > SAFETY_MAX_GYRO_MDPS
        || state.gyro_mdps[1].unsigned_abs() > SAFETY_MAX_GYRO_MDPS
        || state.gyro_mdps[2].unsigned_abs() > SAFETY_MAX_GYRO_MDPS
    {
        return SafetyResult {
            action: SafetyAction::EmergencyStop,
            violation: SafetyViolation::Spinning,
        };
    }

    SafetyResult::safe()
}

// ---------------------------------------------------------------------------
// Wheeled safety
// ---------------------------------------------------------------------------

fn check_wheeled(state: &SensorState) -> SafetyResult {
    // Battery cutoff
    if state.battery_mv > 0 && state.battery_mv < SAFETY_WHEELED_MIN_BATTERY_MV {
        return SafetyResult {
            action: SafetyAction::EmergencyStop,
            violation: SafetyViolation::LowBattery,
        };
    }

    // Obstacle too close (front rangefinder)
    if state.cam_dist_front > 0 && state.cam_dist_front < SAFETY_WHEELED_OBSTACLE_MM {
        return SafetyResult {
            action: SafetyAction::EmergencyStop,
            violation: SafetyViolation::ObstacleTooClose,
        };
    }

    // Tilt check
    if state.imu_valid {
        let tilt = tilt_from_accel(state.accel_mg);
        if tilt > SAFETY_WHEELED_MAX_TILT_CDEG as u32 {
            return SafetyResult {
                action: SafetyAction::EmergencyStop,
                violation: SafetyViolation::ExcessiveTilt,
            };
        }
    }

    // E03: Geofence check (EmergencyStop for wheeled — can't RTL). `Inside`,
    // `Disabled` and `Unknown` are named explicitly here rather than folded
    // into a catch-all, so a reader (or a future diff) cannot mistake "no
    // position to check" for "checked, and inside."
    match geofence_status(state) {
        GeofenceStatus::Outside => {
            return SafetyResult {
                action: SafetyAction::EmergencyStop, // wheeled can't fly back
                violation: SafetyViolation::GeofenceViolation,
            };
        }
        GeofenceStatus::Inside | GeofenceStatus::Disabled | GeofenceStatus::Unknown => {}
    }

    SafetyResult::safe()
}

// ---------------------------------------------------------------------------
// Drone safety (stricter)
// ---------------------------------------------------------------------------

fn check_drone(state: &SensorState) -> SafetyResult {
    // Critical battery → immediate land (highest priority after common)
    if state.battery_mv > 0 && state.battery_mv < SAFETY_DRONE_CRITICAL_BATTERY_MV {
        return SafetyResult {
            action: SafetyAction::LandNow,
            violation: SafetyViolation::CriticalBattery,
        };
    }

    // Low battery → RTL
    if state.battery_mv > 0 && state.battery_mv < SAFETY_DRONE_LOW_BATTERY_MV {
        return SafetyResult {
            action: SafetyAction::ReturnToLaunch,
            violation: SafetyViolation::LowBattery,
        };
    }

    // Tilt check (stricter for drone)
    if state.imu_valid {
        let tilt = tilt_from_accel(state.accel_mg);
        if tilt > SAFETY_DRONE_MAX_TILT_CDEG as u32 {
            return SafetyResult {
                action: SafetyAction::EmergencyStop,
                violation: SafetyViolation::ExcessiveTilt,
            };
        }
    }

    // Comms timeout — if no brain command in N seconds, hover/RTL
    if state.remote_action.valid {
        let age = state.timestamp.saturating_sub(state.remote_action.received_at);
        if age > SAFETY_DRONE_COMMS_TIMEOUT_TICKS {
            return SafetyResult {
                action: SafetyAction::ReturnToLaunch,
                violation: SafetyViolation::CommsTimeout,
            };
        }
    }

    // E03: Geofence check. `Inside`, `Disabled` and `Unknown` are named
    // explicitly rather than folded into a catch-all, so "no position to
    // check" cannot be mistaken for "checked, and inside."
    match geofence_status(state) {
        GeofenceStatus::Outside => {
            return SafetyResult {
                action: SafetyAction::ReturnToLaunch,
                violation: SafetyViolation::GeofenceViolation,
            };
        }
        GeofenceStatus::Inside | GeofenceStatus::Disabled | GeofenceStatus::Unknown => {}
    }

    SafetyResult::safe()
}

// ---------------------------------------------------------------------------
// Humanoid safety
// ---------------------------------------------------------------------------

fn check_humanoid(state: &SensorState) -> SafetyResult {
    // Battery cutoff
    if state.battery_mv > 0 && state.battery_mv < SAFETY_HUMANOID_MIN_BATTERY_MV {
        return SafetyResult {
            action: SafetyAction::EmergencyStop,
            violation: SafetyViolation::LowBattery,
        };
    }

    // Fall detection via acceleration magnitude
    if state.imu_valid {
        let mag = accel_magnitude(state.accel_mg);
        if mag > SAFETY_HUMANOID_FALL_ACCEL_MG {
            return SafetyResult {
                action: SafetyAction::EmergencyStop,
                violation: SafetyViolation::FallDetected,
            };
        }
    }

    SafetyResult::safe()
}

// ---------------------------------------------------------------------------
// Math helpers (no libm, integer only)
// ---------------------------------------------------------------------------

/// Compute tilt angle from accelerometer in centidegrees (integer approx).
/// Uses the ratio of horizontal to vertical acceleration.
fn tilt_from_accel(accel_mg: [i32; 3]) -> u32 {
    let ax = accel_mg[0].unsigned_abs();
    let ay = accel_mg[1].unsigned_abs();
    let az = accel_mg[2].unsigned_abs();

    let horiz_sq = (ax as u64) * (ax as u64) + (ay as u64) * (ay as u64);
    let vert_sq = (az as u64) * (az as u64);

    if vert_sq == 0 {
        return 9000; // 90 degrees — completely horizontal
    }

    // atan(sqrt(horiz_sq) / sqrt(vert_sq)) in centidegrees
    // Approximation: atan(x) ≈ 57.3° * x for small x, clamped
    // ratio = sqrt(horiz_sq / vert_sq) * 100 (in percent)
    let ratio_pct = isqrt(horiz_sq * 10000 / vert_sq);
    // Convert: ratio_pct * 57.3 = centidegrees (approx for small angles)
    // For larger angles this overestimates, which is safer (more conservative)
    let cdeg = (ratio_pct * 573 / 100) as u32;
    cdeg.min(9000) // cap at 90°
}

/// Compute acceleration magnitude (mg) from [ax, ay, az].
fn accel_magnitude(accel_mg: [i32; 3]) -> u32 {
    let ax = accel_mg[0] as i64;
    let ay = accel_mg[1] as i64;
    let az = accel_mg[2] as i64;
    isqrt((ax * ax + ay * ay + az * az) as u64) as u32
}

/// Integer square root (Newton's method).
fn isqrt(n: u64) -> u64 {
    if n <= 1 { return n; }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

// ── E03: Circular Geofence (GPS boundary) ────────────────────────────────────
//
// A single circular geofence centered on a GPS coordinate.  The robot must
// stay within `radius_m` metres of the centre.  If it exits the fence, the
// safety system triggers `ReturnToLaunch` (drone) or `EmergencyStop` (wheeled).
//
// The fence is disabled when `radius_m == 0`.
//
// Distance is approximated using the equirectangular projection:
//
//   Δlat_m  = (lat - center_lat) * LAT_DEG_TO_M
//   Δlon_m  = (lon - center_lon) * LON_DEG_TO_M * cos(center_lat)
//   dist_m  = sqrt(Δlat_m² + Δlon_m²)
//
// The trig-free version replaces cos(lat) with a precomputed integer factor.
// Valid for fences ≤ 50 km from equator; sufficient for robotics use.
//
// **Current wiring.** The position comes from `SensorBus::update_gps`
// (`sensor_bus.rs`), fed by the kernel's `sensor-ahrs` task on every `CH_GPS`
// publish. `SensorBus::snapshot` fills `SensorState.gps_*` in micro-degrees
// and zeroes the quality and satellite count of a fix older than
// `SensorBus::GPS_MAX_AGE_TICKS`, so a receiver that goes silent reads
// `Unknown` rather than its last `Inside`.
//
// `geofence_set` has no production caller (the `geofence-smoke` QEMU probe in
// `kernel/src/smokes/safety.rs` is the only one), so on a normal boot `GEOFENCE` stays
// disabled and geofence enforcement lives in the brain (`server.py`'s polygon
// `Geofence` + an `EStopCmd` carrying `ESTOP_REASON_GEOFENCE`, landing on
// `estop_activate()`).
//
// A breach detected here does less than the brain's: L0 turns
// `EmergencyStop` into `MotorOutput::some(0, 0)` (`layers.rs`), which zeroes
// the command on every tick the robot reads `Outside` — but it does not latch
// the e-stop, disarm the ESC or write a record, and once the reading stops
// being `Outside` (including a fix going stale, which reads `Unknown`) L1-L3
// drive again.

use azos_sync::SpinLock;

/// Geofence configuration stored in a SpinLock for atomic updates from brain.
struct GeofenceConfig {
    /// Centre latitude (micro-degrees × 10⁶, i.e. degrees * 1_000_000).
    center_lat_udeg: i32,
    /// Centre longitude (micro-degrees).
    center_lon_udeg: i32,
    /// Radius in metres (0 = disabled).
    radius_m: u32,
}

impl GeofenceConfig {
    const fn disabled() -> Self {
        GeofenceConfig { center_lat_udeg: 0, center_lon_udeg: 0, radius_m: 0 }
    }
}

static GEOFENCE: SpinLock<GeofenceConfig> = SpinLock::new(GeofenceConfig::disabled());

/// Configure the circular geofence.
///
/// `center_lat_udeg` — latitude in micro-degrees (degrees × 1_000_000).
/// `center_lon_udeg` — longitude in micro-degrees.
/// `radius_m`        — radius in metres (0 = disable fence).
pub fn geofence_set(center_lat_udeg: i32, center_lon_udeg: i32, radius_m: u32) {
    let mut g = GEOFENCE.lock();
    g.center_lat_udeg = center_lat_udeg;
    g.center_lon_udeg = center_lon_udeg;
    g.radius_m        = radius_m;
}

/// Disable the geofence.
pub fn geofence_disable() {
    GEOFENCE.lock().radius_m = 0;
}

/// What a geofence evaluation established.
///
/// `Inside` and `Outside` are the only variants meaning "a real position was
/// checked against a real fence." An unconfigured fence and a fence with no
/// trustworthy position are named separately (`Disabled`, `Unknown`) so
/// neither can be mistaken for "checked, and compliant" — the failure mode
/// a plain `bool` return hides, because `false` means both "outside" is
/// false because you're inside, and "outside" is false because nobody knows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GeofenceStatus {
    /// No fence configured (`radius_m == 0`).
    Disabled,
    /// A fence is configured, but there is no position to check it against
    /// (no GPS fix, or too few satellites to trust the fix).
    Unknown,
    /// Position known and within `radius_m` of the centre.
    Inside,
    /// Position known and beyond `radius_m` of the centre.
    Outside,
}

/// Evaluate the configured geofence against a GPS position.
///
/// Returns `Disabled` without evaluating distance if the fence is off
/// (`radius_m == 0`); otherwise `Inside` or `Outside`.
///
/// `lat_udeg`, `lon_udeg` — current position in micro-degrees. The caller is
/// responsible for only passing a position it trusts: this function has no
/// way to distinguish a real fix from an all-zero default.
fn geofence_eval(lat_udeg: i32, lon_udeg: i32) -> GeofenceStatus {
    match geofence_offsets(lat_udeg, lon_udeg) {
        None => GeofenceStatus::Disabled,
        Some((dist_sq_m2, radius_m2)) if dist_sq_m2 > radius_m2 => GeofenceStatus::Outside,
        Some(_) => GeofenceStatus::Inside,
    }
}

/// How far the position is from the fence centre and how far the fence
/// reaches, both squared, in m²; `None` when no fence is configured.
///
/// The distance arithmetic lives here alone so that a verdict and the record
/// of the breach that produced it cannot be computed two different ways.
fn geofence_offsets(lat_udeg: i32, lon_udeg: i32) -> Option<(i64, i64)> {
    /// Metres per degree of latitude (constant, ~111 km/deg).
    const LAT_M_PER_DEG_UDEG: i64 = 111_000; // metres per 1_000_000 µdeg

    let g = GEOFENCE.lock();
    if g.radius_m == 0 { return None; }

    // Δlat and Δlon in micro-degrees
    let dlat_udeg = (lat_udeg - g.center_lat_udeg) as i64;
    let dlon_udeg = (lon_udeg - g.center_lon_udeg) as i64;

    // Convert to metres (integer, scaled by 1000 for precision)
    // Δlat_m * 1000 = dlat_udeg * LAT_M_PER_DEG_UDEG / 1_000_000 * 1000
    //               = dlat_udeg * LAT_M_PER_DEG_UDEG / 1_000
    let dlat_mm = dlat_udeg * LAT_M_PER_DEG_UDEG / 1_000_000;

    // Longitude scale: cos(lat) approximation using centre latitude.
    // cos(lat) ≈ 1 - (lat_deg² / 2) for |lat| < 45°; we use integer 1000ths.
    // More accurately: we precompute cos_factor = cos(center_lat) * 1000
    // Using the identity: cos(x) ≈ (1 - 2sin²(x/2)), small-angle: ≈ 1 - x²/2
    // For a simpler bound, use cos(45°) ≈ 707/1000 as minimum (worst case).
    let lat_deg_abs = (g.center_lat_udeg.unsigned_abs() / 1_000_000) as i64;
    // cos_factor/1000 = (1 - lat_deg² / 20000) clamped to [500, 1000]
    let cos_factor: i64 = (1000 - (lat_deg_abs * lat_deg_abs / 20000)).clamp(500, 1000);

    let dlon_mm = dlon_udeg * LAT_M_PER_DEG_UDEG * cos_factor / (1_000_000 * 1000);

    // Squared distance in m² (no sqrt needed — compare to radius²)
    let dist_sq_m2 = dlat_mm * dlat_mm + dlon_mm * dlon_mm;
    let radius_m2  = (g.radius_m as i64) * (g.radius_m as i64);

    Some((dist_sq_m2, radius_m2))
}

/// Metres the position lies beyond the fence, 0 when inside it, `None` with no
/// fence. One integer square root over [`geofence_offsets`]; saturates at
/// `u32::MAX` so a nonsense position still records a number.
///
/// Public because the smoke probe has to report the same distance the latch
/// recorded in a case where [`geofence_breach_latch`] returns `None` — the
/// behaviour loop having already latched this very breach.
pub fn geofence_overshoot_m(lat_udeg: i32, lon_udeg: i32) -> Option<u32> {
    let (dist_sq_m2, radius_m2) = geofence_offsets(lat_udeg, lon_udeg)?;
    let dist = isqrt_u64(dist_sq_m2.max(0) as u64);
    let radius = isqrt_u64(radius_m2.max(0) as u64);
    Some(dist.saturating_sub(radius).min(u32::MAX as u64) as u32)
}

/// Integer square root, rounded down. Bit-by-bit, no floating point: this
/// crate runs in the kernel, where the FPU is not ours to use.
const fn isqrt_u64(n: u64) -> u64 {
    let (mut rem, mut root, mut bit) = (n, 0u64, 1u64 << 62);
    while bit > n { bit >>= 2; }
    while bit != 0 {
        if rem >= root + bit {
            rem -= root + bit;
            root = (root >> 1) + bit;
        } else {
            root >>= 1;
        }
        bit >>= 2;
    }
    root
}

/// GGA fix qualities the geofence acts on: 1 GPS, 2 DGPS, 3 PPS, 4 RTK fixed,
/// 5 RTK float — every mode in which the receiver MEASURES the position.
///
/// The rule was `>= 1`, which is this list plus 6 (dead reckoning), 7 (manual
/// input) and 8 (simulator): three qualities carrying a position the receiver
/// did not measure. A fence acting on a manual or simulated position stops the
/// machine on a number somebody typed, and — worse in this direction — reads a
/// drifting dead-reckoned position as being inside the fence. Owner decision,
/// 2026-09-16.
pub const GEOFENCE_FIX_QUALITIES: [u8; 5] = [1, 2, 3, 4, 5];

/// Whether a GGA fix quality is one the geofence acts on.
pub const fn geofence_fix_trusted(quality: u8) -> bool {
    matches!(quality, 1..=5)
}
/// Minimum satellites in use the geofence acts on: 4, the fewest that fix a
/// position in three dimensions plus the receiver clock.
pub const GEOFENCE_MIN_SATELLITES: u8 = 4;

/// Evaluate the configured geofence against the GPS data in a sensor snapshot.
///
/// `Unknown` whenever the fix is not trustworthy: a quality outside
/// [`GEOFENCE_FIX_QUALITIES`], fewer than [`GEOFENCE_MIN_SATELLITES`]
/// satellites, or — through `SensorBus::snapshot`, which zeroes both — a
/// stale fix.
pub fn geofence_status(state: &SensorState) -> GeofenceStatus {
    let valid = geofence_fix_trusted(state.gps_fix)
        && state.gps_satellites >= GEOFENCE_MIN_SATELLITES;

    if !valid { return GeofenceStatus::Unknown; } // No trustworthy GPS fix.

    geofence_eval(state.gps_lat_udeg, state.gps_lon_udeg)
}

/// Latch the emergency stop on a fence breach, once per breach.
///
/// Owner decision, 2026-09-16. Until then a breach only made L0 command
/// (0, 0): the moment the reading stopped saying `Outside` — a fix going
/// stale is enough, and reads as `Unknown` — L1-L3 drove again, with nothing
/// recorded and nobody asked. A fence that releases itself is not a fence.
/// Now the machine holds until an operator clears the latch, like every other
/// stop source.
///
/// `Some(overshoot_m)` the first time, for the caller to write as the
/// `SAFETY_ESTOP` detail; `None` when the position is not outside the fence,
/// or the latch already holds — so a breach lasting a thousand ticks writes
/// one record rather than a thousand.
///
/// The latch is taken BEFORE the distance is measured: the stop is the
/// urgent half, and the record is written from what the caller gets back.
pub fn geofence_breach_latch(state: &SensorState) -> Option<u32> {
    if geofence_status(state) != GeofenceStatus::Outside { return None; }
    if estop_is_active() { return None; }
    estop_activate();
    Some(geofence_overshoot_m(state.gps_lat_udeg, state.gps_lon_udeg).unwrap_or(0))
}
