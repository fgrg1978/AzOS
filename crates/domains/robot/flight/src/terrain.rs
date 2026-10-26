// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Terrain Following Controller (D05).
//!
//! Maintains a constant altitude above the terrain surface using a downward-
//! facing rangefinder.  Intended for low-altitude fixed-wing or multi-rotor
//! flight in undulating terrain.
//!
//! ## Algorithm
//! A P-PD (proportional + derivative) controller on the height error:
//! ```text
//! error_mm = target_agl_mm − range_mm
//! throttle_trim += Kp × error + Kd × (error − prev_error) / dt
//! ```
//!
//! The computed throttle trim is added to the base throttle from the pilot
//! or autopilot.  Clamped to ±`TERRAIN_MAX_TRIM` throttle units.
//!
//! ## Coordinate convention
//! AGL = Above Ground Level (range reading from downward-facing rangefinder).

use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default target AGL in mm (3 m default hover height).
pub const TERRAIN_DEFAULT_AGL_MM: i32 = 3_000;
/// Proportional gain (throttle units per metre error × 1000).
/// 1 m error → 100 throttle units with Kp=100.
pub const TERRAIN_KP: i32 = 100;
/// Derivative gain (throttle units per metre/s × 1000).
pub const TERRAIN_KD: i32 = 50;
/// Maximum throttle trim authority (prevents runaway).
pub const TERRAIN_MAX_TRIM: i32 = 200;
/// Minimum valid rangefinder reading (mm).
/// Readings below this are considered invalid (too close / no surface).
pub const TERRAIN_RANGE_MIN_MM: i32 = 100;
/// Maximum valid rangefinder reading (mm).
/// Above this the terrain controller disengages (too high / sensor range limit).
pub const TERRAIN_RANGE_MAX_MM: i32 = 10_000; // 10 m

// ── State ─────────────────────────────────────────────────────────────────────

static TERRAIN_ENABLED:    AtomicBool = AtomicBool::new(false);
static TERRAIN_TARGET_AGL: AtomicI32  = AtomicI32::new(TERRAIN_DEFAULT_AGL_MM);
static TERRAIN_PREV_ERROR: AtomicI32  = AtomicI32::new(0);
static TERRAIN_TRIM:       AtomicI32  = AtomicI32::new(0);

// ── API ───────────────────────────────────────────────────────────────────────

/// Enable or disable terrain following.
pub fn terrain_set_enabled(en: bool) {
    TERRAIN_ENABLED.store(en, Ordering::Relaxed);
    if !en {
        TERRAIN_TRIM.store(0, Ordering::Relaxed);
        TERRAIN_PREV_ERROR.store(0, Ordering::Relaxed);
    }
}

/// Check if terrain following is active.
pub fn terrain_is_enabled() -> bool { TERRAIN_ENABLED.load(Ordering::Relaxed) }

/// Set the desired height above ground (mm).
pub fn terrain_set_target_agl(agl_mm: i32) {
    TERRAIN_TARGET_AGL.store(agl_mm.max(TERRAIN_RANGE_MIN_MM), Ordering::Relaxed);
}

/// Get the current target AGL (mm).
pub fn terrain_target_agl() -> i32 { TERRAIN_TARGET_AGL.load(Ordering::Relaxed) }

/// Update the terrain controller.
///
/// - `range_mm`: current downward rangefinder reading in mm.
/// - `dt_ms`: time since last update (milliseconds).
///
/// Returns the throttle trim to add to the base throttle (can be negative).
/// Returns 0 if terrain following is disabled or the range is invalid.
pub fn terrain_update(range_mm: i32, dt_ms: u32) -> i32 {
    if !TERRAIN_ENABLED.load(Ordering::Relaxed) { return 0; }
    if range_mm < TERRAIN_RANGE_MIN_MM || range_mm > TERRAIN_RANGE_MAX_MM {
        // Invalid range — hold current trim, don't update.
        return TERRAIN_TRIM.load(Ordering::Relaxed);
    }

    let target   = TERRAIN_TARGET_AGL.load(Ordering::Relaxed);
    let error    = target - range_mm;
    let prev_err = TERRAIN_PREV_ERROR.load(Ordering::Relaxed);
    let dt       = dt_ms as i32;

    // P term.
    let p_term = TERRAIN_KP * error / 1_000;
    // D term: derivative of error over time.
    let d_term = if dt > 0 {
        TERRAIN_KD * (error - prev_err) * 1_000 / dt / 1_000
    } else {
        0
    };

    let trim = (p_term + d_term).clamp(-TERRAIN_MAX_TRIM, TERRAIN_MAX_TRIM);

    TERRAIN_PREV_ERROR.store(error, Ordering::Relaxed);
    TERRAIN_TRIM.store(trim, Ordering::Relaxed);
    trim
}

/// Get the last computed throttle trim.
pub fn terrain_trim() -> i32 { TERRAIN_TRIM.load(Ordering::Relaxed) }

/// Get (target_agl_mm, current_trim, enabled) status tuple.
pub fn terrain_status() -> (i32, i32, bool) {
    (
        TERRAIN_TARGET_AGL.load(Ordering::Relaxed),
        TERRAIN_TRIM.load(Ordering::Relaxed),
        TERRAIN_ENABLED.load(Ordering::Relaxed),
    )
}
