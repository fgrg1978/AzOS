// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Reflex Daemon -local obstacle avoidance without brain connection.
//!
//! Runs as a user-mode process alongside brain_client. Continuously reads
//! the rangefinder and IMU, and overrides motor commands when danger is
//! detected. This is a safety layer that works even if the brain server
//! is unreachable or the TCP link is down.
//!
//! Priority: reflex overrides brain commands when triggered.
//! Implementation: reads sensors at high rate, publishes motor commands
//! only when an override is needed (obstacle or tilt detected).
//!
//! Behaviors (Brooks subsumption style, highest priority first):
//!   1. E-STOP:  extreme tilt (fall) → motors off
//!   2. BACKUP:  obstacle < CRITICAL_MM → reverse briefly
//!   3. TURN:    obstacle < WARNING_MM → turn away
//!   4. PASS:    no danger → do nothing (brain_client controls)

#![no_std]
#![no_main]

use azos_libsys as sys;

// ── Constants ────────────────────────────────────────────────────────────────

// Obstacle thresholds (mm)
const OBSTACLE_CRITICAL_MM: u16 = 150;   // immediate reverse
const OBSTACLE_WARNING_MM: u16 = 400;    // turn away
const OBSTACLE_CLEAR_MM: u16 = 600;      // resume normal

// Tilt threshold (milli-g, ~45 degrees)
const TILT_ESTOP_MG: i32 = 700;

// Motor speeds
//
// This file used to carry `BACKUP_SPEED = 30` / `TURN_SPEED = 40` and
// reverse by passing their negation to the speed call, on the strength of a
// libsys doc that read "signed: positive = forward, negative = reverse".
//
// That doc was wrong. `sys::motor_speed_typed` (560) takes an UNSIGNED
// percentage and always drives `MotorDir::Forward`
// (`sys_motor_speed_typed`, crates/core/syscall/src/handlers.rs), and `motor_set`
// (domains/robot/robot/src/motor.rs) clamps it with `speed_pct.min(100)`. A
// sign-extended -30 arrives as 0xFFFF...E2 and clamps to 100 — so "reverse
// away from the obstacle" drove BOTH MOTORS FULL SPEED FORWARD INTO IT. On
// QEMU that was a log line; on the robot it is a collision, and it is the
// reason this daemon is here at all.
//
// Until `SYS_MOTOR_MOVE_TYPED` (584, U11-12) existed, the motor ABI could
// not express a (direction, speed) pair in one call — `motor_speed_typed`
// (560) drives forward only, `motor_direction_typed` (576) drives at a
// kernel-fixed 50% only — so this daemon ran every reflex at 50% rather
// than the 30/40 it was designed to ask for. 584 carries both, so the
// intended speeds are restored below.
const BACKUP_SPEED_PCT: u32 = 30;
const TURN_SPEED_PCT: u32 = 40;

// Timing
const REFLEX_PERIOD_MS: u64 = 25;       // 40 Hz -faster than brain's 20 Hz
const BACKUP_DURATION_MS: u64 = 500;     // reverse for 500ms
const TURN_DURATION_MS: u64 = 400;       // turn for 400ms
const ESTOP_HOLD_MS: u64 = 2000;         // hold e-stop for 2s before re-checking

// Sensor types — re-exported from libsys
use sys::{SENSOR_TYPE_IMU, SENSOR_TYPE_RANGE};

// Motor IDs
const MOTOR_LEFT: u64 = 0;
const MOTOR_RIGHT: u64 = 1;

// ── Sensor reading ──────────────────────────────────────────────────────────

struct ReflexSensors {
    range_front: u16,
    range_right: u16,
    accel_x_mg: i32,
    accel_y_mg: i32,
    accel_z_mg: i32,
}

impl ReflexSensors {
    fn new() -> Self {
        Self {
            range_front: u16::MAX,  // assume clear until first read
            range_right: u16::MAX,
            accel_x_mg: 0,
            accel_y_mg: 0,
            accel_z_mg: 1000,       // assume upright (1g on Z)
        }
    }

    fn read(&mut self) {
        // Rangefinder: 4 bytes
        let mut range_buf = [0u8; 4];
        // SAFETY: written once by `motor_caps_init` before this loop runs.
        if sys::sensor_read_typed(unsafe { CAP_RANGE }, &mut range_buf) >= 4 {
            self.range_front = u16::from_le_bytes([range_buf[0], range_buf[1]]);
            self.range_right = u16::from_le_bytes([range_buf[2], range_buf[3]]);
        }

        // IMU: 24 bytes (only need accel for tilt detection)
        let mut imu_buf = [0u8; 24];
        if sys::sensor_read_typed(unsafe { CAP_IMU }, &mut imu_buf) >= 12 {
            self.accel_x_mg = i32::from_le_bytes([
                imu_buf[0], imu_buf[1], imu_buf[2], imu_buf[3],
            ]);
            self.accel_y_mg = i32::from_le_bytes([
                imu_buf[4], imu_buf[5], imu_buf[6], imu_buf[7],
            ]);
            self.accel_z_mg = i32::from_le_bytes([
                imu_buf[8], imu_buf[9], imu_buf[10], imu_buf[11],
            ]);
        }
    }

    fn is_tilted(&self) -> bool {
        // Tilt detected when lateral acceleration exceeds threshold
        // (robot is falling or tipped)
        abs_i32(self.accel_x_mg) > TILT_ESTOP_MG
            || abs_i32(self.accel_y_mg) > TILT_ESTOP_MG
    }

    fn obstacle_front(&self) -> bool {
        self.range_front > 0 && self.range_front < OBSTACLE_WARNING_MM
    }

    fn obstacle_critical(&self) -> bool {
        self.range_front > 0 && self.range_front < OBSTACLE_CRITICAL_MM
    }

    fn front_clear(&self) -> bool {
        self.range_front == 0 || self.range_front >= OBSTACLE_CLEAR_MM
    }
}

fn abs_i32(v: i32) -> i32 {
    if v < 0 { -v } else { v }
}

// ── Reflex behaviors ────────────────────────────────────────────────────────

/// The two `Cap<Motor>` handles, looked up once at startup.
///
/// Looked up once rather than per stop: `cap_lookup` is a syscall, and
/// `motor_stop` is on the path this daemon exists to make fast. A handle does
/// not go stale while its holder lives — the generation field exists so that a
/// handle to a REVOKED slot is detected, and nothing revokes these.
///
/// `0` is a valid handle only in the sense that `Cap::NULL` is zero and would
/// be refused as stale, which is why the sentinel below is checked before use
/// rather than trusted.
static mut CAP_LEFT: u32 = 0;
static mut CAP_RIGHT: u32 = 0;

/// The two `Cap<Sensor>` handles this daemon reads, looked up with the motors.
static mut CAP_RANGE: u32 = 0;
static mut CAP_IMU: u32 = 0;

/// Look up the motor capabilities. Returns false if either is missing.
///
/// **No fallback.** A silent fallback would make the typed path untestable —
/// the scenario would pass whether or not 560 works — and would hide the one
/// condition that must never be silent: a safety reflex that cannot stop the
/// motors.
fn motor_caps_init() -> bool {
    let l = sys::cap_lookup(sys::CapKind::Motor as u8, MOTOR_LEFT as u32);
    let r = sys::cap_lookup(sys::CapKind::Motor as u8, MOTOR_RIGHT as u32);
    // The sensors this daemon reads. Looked up here rather than at first use
    // so that a missing grant is a startup failure with a message, not a read
    // that silently returns an error in the middle of the avoidance loop.
    let rng = sys::cap_lookup(sys::CapKind::Sensor as u8, SENSOR_TYPE_RANGE as u32);
    let imu = sys::cap_lookup(sys::CapKind::Sensor as u8, SENSOR_TYPE_IMU as u32);
    if l < 0 || r < 0 || rng < 0 || imu < 0 {
        return false;
    }
    // SAFETY: single-threaded ring-3 program, written once before `run()`
    // reads them and never again.
    unsafe {
        CAP_LEFT = l as u32;
        CAP_RIGHT = r as u32;
        CAP_RANGE = rng as u32;
        CAP_IMU = imu as u32;
    }
    true
}

/// Stop both motors immediately.
///
/// Through `SYS_MOTOR_SPEED_TYPED` (560): the wheel comes from the
/// capability, so this cannot command a motor the topology did not grant.
///
/// **Not `SYS_MOTOR_SET_TARGET_TYPED` (550), and the difference is this
/// daemon's whole purpose.** 550 writes a PID target — it asks the control
/// loop to aim for zero, which arrives when the loop converges. 560 actuates
/// now. For a reflex that exists to stop before hitting something,
/// "eventually" is a different behaviour, not a slower one.
fn motor_stop() {
    // SAFETY: written once by `motor_caps_init` before `run()` starts.
    let (l, r) = unsafe { (CAP_LEFT, CAP_RIGHT) };
    sys::motor_speed_typed(l, 0);
    sys::motor_speed_typed(r, 0);
}

/// Reverse both motors briefly, at the daemon's own chosen speed.
///
/// Through `SYS_MOTOR_MOVE_TYPED` (584, U11-12): direction AND speed in one
/// call, on the wheels the capabilities name. See the note on the motor
/// speed constants above for why this used to run at a kernel-fixed 50%.
fn motor_backup() {
    // SAFETY: written once by `motor_caps_init` before `run()` starts.
    let (l, r) = unsafe { (CAP_LEFT, CAP_RIGHT) };
    sys::motor_move_typed(l, sys::MOTOR_DIR_BACKWARD, BACKUP_SPEED_PCT);
    sys::motor_move_typed(r, sys::MOTOR_DIR_BACKWARD, BACKUP_SPEED_PCT);
    sys::sleep(BACKUP_DURATION_MS);
    motor_stop();
}

/// Turn away from obstacle (spin in place: left reverses, right drives).
fn motor_turn_away() {
    // SAFETY: written once by `motor_caps_init` before `run()` starts.
    let (l, r) = unsafe { (CAP_LEFT, CAP_RIGHT) };
    sys::motor_move_typed(l, sys::MOTOR_DIR_BACKWARD, TURN_SPEED_PCT);
    sys::motor_move_typed(r, sys::MOTOR_DIR_FORWARD, TURN_SPEED_PCT);
    sys::sleep(TURN_DURATION_MS);
    motor_stop();
}

// ── Main loop ───────────────────────────────────────────────────────────────

fn run() {
    sys::println(b"[reflex] Starting reflex daemon (obstacle avoidance)");

    // Before anything else: without the motor capabilities this daemon cannot
    // stop the machine, which is the only thing it is for. Refusing to run is
    // the correct outcome — a reflex that starts and cannot act is worse than
    // one that never started, because the log says it is watching.
    if !motor_caps_init() {
        sys::println(b"[reflex] FATAL missing motor or sensor capabilities - refusing to run");
        sys::exit(1);
    }

    let mut sensors = ReflexSensors::new();
    let mut overriding = false;

    loop {
        sensors.read();

        // Priority 1: E-STOP on tilt (fall detection)
        if sensors.is_tilted() {
            if !overriding {
                sys::print(b"[reflex] TILT DETECTED -E-STOP\n");
            }
            motor_stop();
            overriding = true;
            sys::sleep(ESTOP_HOLD_MS);
            continue;
        }

        // Priority 2: Critical obstacle -reverse
        if sensors.obstacle_critical() {
            if !overriding {
                sys::print(b"[reflex] CRITICAL OBSTACLE -BACKUP\n");
            }
            overriding = true;
            motor_backup();
            continue;
        }

        // Priority 3: Warning obstacle -turn away
        if sensors.obstacle_front() {
            if !overriding {
                sys::print(b"[reflex] OBSTACLE WARNING -TURNING\n");
            }
            overriding = true;
            motor_turn_away();
            continue;
        }

        // Priority 4: All clear -release control
        if overriding && sensors.front_clear() {
            sys::print(b"[reflex] Clear -releasing control\n");
            overriding = false;
            // Don't set motor speed -let brain_client resume control
        }

        sys::sleep(REFLEX_PERIOD_MS);
    }
}

// ── Entry point ─────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn _start() -> ! {
    run();
    sys::exit(0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[reflex] PANIC -stopping motors\n");
    motor_stop();
    sys::exit(1);
}
