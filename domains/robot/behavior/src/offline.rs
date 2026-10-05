// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Offline autonomy — fallback behavior when brain server is unreachable.
//!
//! When the robot loses connection to the brain (WiFi down, brain crashed),
//! this module provides deterministic local behavior:
//!   1. Patrol last known waypoints by odometry
//!   2. Sensor triggers → buzzer directly (no VLM needed)
//!   3. Battery low → stop and wait (or dock if waypoint known)
//!   4. Obstacle avoidance via reflex ELF (already running)
//!   5. LED status: blue blink = offline mode
//!
//! The brain can upload waypoints before disconnecting. The kernel stores
//! up to OFFLINE_MAX_WAYPOINTS in a static buffer. On disconnect, the
//! offline patrol layer activates and follows these waypoints in a loop.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use crate::types::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of offline patrol waypoints.
pub const OFFLINE_MAX_WAYPOINTS: usize = 32;

/// Speed for offline patrol (% of max, conservative).
pub const OFFLINE_PATROL_SPEED: i32 = 25;

/// Speed for turning toward next waypoint.
pub const OFFLINE_TURN_SPEED: i32 = 20;

/// Distance threshold to consider waypoint reached (mm).
pub const OFFLINE_WAYPOINT_REACH_MM: i64 = 500;

/// Heading tolerance before driving forward (centidegrees).
pub const OFFLINE_HEADING_TOLERANCE_CDEG: i64 = 2000;

/// Battery threshold to stop all movement (mV).
pub const OFFLINE_BATTERY_STOP_MV: u16 = 6400;

/// Seconds between reconnection attempts — 5 seconds. Owner fix, 2026-09-26
/// (U08-8): was a raw `50_000_000` (10 MHz QEMU literal) — 12.5 s on VF2,
/// 2.08 s on K1. `offline_should_reconnect` (the one caller) has no
/// production caller either (audit note), so this was latent, not live.
pub const OFFLINE_RECONNECT_INTERVAL_TICKS: u64 = azos_drv_sys::timebase::TIMER_FREQ * 5;

/// Sensor flag: PIR triggered.
const SENSOR_FLAG_PIR: u16 = 0x0001;
/// Sensor flag: sound triggered.
const SENSOR_FLAG_SOUND: u16 = 0x0002;

/// Buzzer beep duration for sensor trigger (ms).
pub const OFFLINE_BUZZER_BEEP_MS: u32 = 500;

// ---------------------------------------------------------------------------
// Waypoint storage (static, lock-free)
// ---------------------------------------------------------------------------

/// A simple 2D waypoint (x_mm, y_mm) for offline patrol.
#[derive(Clone, Copy)]
pub struct OfflineWaypoint {
    pub x_mm: i32,
    pub y_mm: i32,
}

impl OfflineWaypoint {
    pub const fn zero() -> Self {
        Self { x_mm: 0, y_mm: 0 }
    }
}

/// Static waypoint buffer — written by brain protocol, read by offline layer.
static mut WAYPOINTS: [OfflineWaypoint; OFFLINE_MAX_WAYPOINTS] =
    [OfflineWaypoint { x_mm: 0, y_mm: 0 }; OFFLINE_MAX_WAYPOINTS];

/// Number of valid waypoints stored.
static WAYPOINT_COUNT: AtomicU8 = AtomicU8::new(0);

/// Current waypoint index during offline patrol.
static CURRENT_WP_IDX: AtomicU8 = AtomicU8::new(0);

/// Whether offline mode is active.
static OFFLINE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Patrol lap counter.
static OFFLINE_LAPS: AtomicU32 = AtomicU32::new(0);

/// Last time we attempted reconnection.
static LAST_RECONNECT_TICK: AtomicU64 = AtomicU64::new(0);

// AtomicU64 is not available on all targets, use two AtomicU32s
struct AtomicU64 {
    lo: AtomicU32,
    hi: AtomicU32,
}

impl AtomicU64 {
    const fn new(v: u64) -> Self {
        Self {
            lo: AtomicU32::new(v as u32),
            hi: AtomicU32::new((v >> 32) as u32),
        }
    }

    fn load(&self, order: Ordering) -> u64 {
        let hi = self.hi.load(order) as u64;
        let lo = self.lo.load(order) as u64;
        (hi << 32) | lo
    }

    fn store(&self, v: u64, order: Ordering) {
        self.hi.store((v >> 32) as u32, order);
        self.lo.store(v as u32, order);
    }
}

// ---------------------------------------------------------------------------
// Public API — called from brain protocol / behavior task
// ---------------------------------------------------------------------------

/// Upload a waypoint from the brain server (called before or during connection).
/// Returns true if stored, false if buffer full.
pub fn offline_add_waypoint(x_mm: i32, y_mm: i32) -> bool {
    let count = WAYPOINT_COUNT.load(Ordering::Relaxed) as usize;
    if count >= OFFLINE_MAX_WAYPOINTS {
        return false;
    }
    unsafe {
        WAYPOINTS[count] = OfflineWaypoint { x_mm, y_mm };
    }
    WAYPOINT_COUNT.store((count + 1) as u8, Ordering::Release);
    true
}

/// Clear all stored waypoints.
pub fn offline_clear_waypoints() {
    WAYPOINT_COUNT.store(0, Ordering::Release);
    CURRENT_WP_IDX.store(0, Ordering::Relaxed);
}

/// Get number of stored waypoints.
pub fn offline_waypoint_count() -> usize {
    WAYPOINT_COUNT.load(Ordering::Relaxed) as usize
}

/// Activate offline mode (called when brain connection lost).
pub fn offline_activate() {
    if !OFFLINE_ACTIVE.load(Ordering::Relaxed) {
        OFFLINE_ACTIVE.store(true, Ordering::Release);
        CURRENT_WP_IDX.store(0, Ordering::Relaxed);
        OFFLINE_LAPS.store(0, Ordering::Relaxed);
    }
}

/// Deactivate offline mode (called when brain reconnects).
pub fn offline_deactivate() {
    OFFLINE_ACTIVE.store(false, Ordering::Release);
}

/// Check if offline mode is active.
pub fn offline_is_active() -> bool {
    OFFLINE_ACTIVE.load(Ordering::Acquire)
}

/// Get offline patrol stats.
pub fn offline_laps() -> u32 {
    OFFLINE_LAPS.load(Ordering::Relaxed)
}

/// Check if it's time to attempt reconnection.
pub fn offline_should_reconnect(now_ticks: u64) -> bool {
    let last = LAST_RECONNECT_TICK.load(Ordering::Relaxed);
    if now_ticks.saturating_sub(last) >= OFFLINE_RECONNECT_INTERVAL_TICKS {
        LAST_RECONNECT_TICK.store(now_ticks, Ordering::Relaxed);
        true
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Behavior layer — offline patrol
// ---------------------------------------------------------------------------

/// Offline patrol behavior layer.
///
/// Navigates to stored waypoints using odometry. No VLM, no LLM —
/// pure deterministic waypoint following with obstacle avoidance
/// handled by reflex ELF / L1 layer.
///
/// Returns valid MotorOutput when offline and waypoints available.
/// Returns MotorOutput::none() when brain is connected or no waypoints.
pub fn layer_offline_patrol(state: &SensorState) -> BehaviorOutput {
    if !OFFLINE_ACTIVE.load(Ordering::Acquire) {
        return BehaviorOutput { cmd: MotorOutput::none(), layer: 3 };
    }

    let count = WAYPOINT_COUNT.load(Ordering::Relaxed) as usize;
    if count == 0 {
        // No waypoints — stop safely
        return BehaviorOutput { cmd: MotorOutput::some(0, 0), layer: 3 };
    }

    // Battery check — stop if critically low
    if state.battery_mv > 0 && state.battery_mv < OFFLINE_BATTERY_STOP_MV {
        return BehaviorOutput { cmd: MotorOutput::some(0, 0), layer: 3 };
    }

    // Sensor trigger → buzzer (handled externally by behavior_task)
    // Here we just continue patrol — the buzzer is triggered in the main loop.

    let idx = CURRENT_WP_IDX.load(Ordering::Relaxed) as usize;
    let wp = unsafe { WAYPOINTS[idx % count] };

    // Compute distance and heading to waypoint
    let dx = wp.x_mm as i64 - odom_x_from_state(state);
    let dy = wp.y_mm as i64 - odom_y_from_state(state);
    let dist_sq = dx * dx + dy * dy;

    // Check if waypoint reached
    let reach_sq = OFFLINE_WAYPOINT_REACH_MM * OFFLINE_WAYPOINT_REACH_MM;
    if dist_sq < reach_sq {
        // Advance to next waypoint
        let next = ((idx + 1) % count) as u8;
        CURRENT_WP_IDX.store(next, Ordering::Relaxed);
        if next == 0 {
            OFFLINE_LAPS.fetch_add(1, Ordering::Relaxed);
        }
        return BehaviorOutput { cmd: MotorOutput::some(0, 0), layer: 3 };
    }

    // Compute desired heading (centidegrees)
    let desired_cdeg = atan2_cdeg(dy, dx);
    let heading_err = wrap_cdeg(desired_cdeg - state.odom_heading_cdeg);

    // Turn toward waypoint if heading error too large
    if heading_err.unsigned_abs() > OFFLINE_HEADING_TOLERANCE_CDEG as u64 {
        if heading_err > 0 {
            BehaviorOutput {
                cmd: MotorOutput::some(-OFFLINE_TURN_SPEED, OFFLINE_TURN_SPEED),
                layer: 3,
            }
        } else {
            BehaviorOutput {
                cmd: MotorOutput::some(OFFLINE_TURN_SPEED, -OFFLINE_TURN_SPEED),
                layer: 3,
            }
        }
    } else {
        // Drive forward
        BehaviorOutput {
            cmd: MotorOutput::some(OFFLINE_PATROL_SPEED, OFFLINE_PATROL_SPEED),
            layer: 3,
        }
    }
}

/// Check sensor flags and trigger buzzer directly (no brain needed).
/// Returns true if any sensor triggered.
pub fn offline_check_sensors(state: &SensorState) -> bool {
    if state.sensor_flags == 0 {
        return false;
    }
    // PIR or sound → trigger buzzer
    (state.sensor_flags & (SENSOR_FLAG_PIR | SENSOR_FLAG_SOUND)) != 0
}

// ---------------------------------------------------------------------------
// Math helpers (no_std, no libm)
// ---------------------------------------------------------------------------

/// Convert odometry distance + heading to approximate X position (mm).
fn odom_x_from_state(state: &SensorState) -> i64 {
    // Approximate: x = dist * cos(heading)
    // Using fixed-point: cos(cdeg) from lookup
    let heading_deg = (state.odom_heading_cdeg / 100) as i32;
    let cos_val = cos_deg_fixed(heading_deg);
    (state.odom_dist_mm * cos_val as i64) / 1000
}

/// Convert odometry distance + heading to approximate Y position (mm).
fn odom_y_from_state(state: &SensorState) -> i64 {
    let heading_deg = (state.odom_heading_cdeg / 100) as i32;
    let sin_val = sin_deg_fixed(heading_deg);
    (state.odom_dist_mm * sin_val as i64) / 1000
}

/// atan2 returning centidegrees (integer approximation).
fn atan2_cdeg(y: i64, x: i64) -> i64 {
    if x == 0 && y == 0 { return 0; }

    // Rough atan2 using octant decomposition
    let ax = if x < 0 { -x } else { x };
    let ay = if y < 0 { -y } else { y };

    // atan(y/x) ≈ 45 * y / (x + 0.28*y) for small ratios (in degrees)
    let angle_deg = if ax >= ay {
        if ax == 0 { 0 } else { (45 * ay / (ax + ay / 4)).min(45) }
    } else {
        90 - if ay == 0 { 0 } else { (45 * ax / (ay + ax / 4)).min(45) }
    };

    let angle_cdeg = angle_deg * 100;

    // Map to correct quadrant
    if x >= 0 && y >= 0 { angle_cdeg }
    else if x < 0 && y >= 0 { 18000 - angle_cdeg }
    else if x < 0 && y < 0 { -(18000 - angle_cdeg) }
    else { -angle_cdeg }
}

/// Wrap angle to [-18000, 18000) centidegrees.
fn wrap_cdeg(mut angle: i64) -> i64 {
    while angle > 18000 { angle -= 36000; }
    while angle <= -18000 { angle += 36000; }
    angle
}

/// Fixed-point cosine (input: degrees, output: ×1000).
fn cos_deg_fixed(deg: i32) -> i32 {
    sin_deg_fixed(90 - deg)
}

/// Fixed-point sine (input: degrees, output: ×1000).
/// Simple lookup for 0-90°, mirrored for other quadrants.
fn sin_deg_fixed(mut deg: i32) -> i32 {
    // Normalize to 0-359
    deg = ((deg % 360) + 360) % 360;

    let (quadrant, idx) = if deg <= 90 {
        (0, deg)
    } else if deg <= 180 {
        (1, 180 - deg)
    } else if deg <= 270 {
        (2, deg - 180)
    } else {
        (3, 360 - deg)
    };

    // Sine values ×1000 for 0° to 90° in 15° steps, linearly interpolated
    const SIN_TABLE: [i32; 7] = [0, 259, 500, 707, 866, 966, 1000];
    const STEP: i32 = 15;

    let table_idx = (idx / STEP) as usize;
    let frac = idx % STEP;

    let val = if table_idx >= 6 {
        SIN_TABLE[6]
    } else {
        let a = SIN_TABLE[table_idx];
        let b = SIN_TABLE[table_idx + 1];
        a + (b - a) * frac / STEP
    };

    match quadrant {
        0 | 1 => val,
        _ => -val,
    }
}
