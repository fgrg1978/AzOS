// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_limits`.
//!
//! `safety.rs` (pulled by `#[path]`) reads one generated constant,
//! `ROBOT_TYPE_ID`: the robot type the safety envelope starts with. The real
//! crate generates it from `.config` with a build script that needs registry
//! crates; this suite has a path-only `Cargo.lock`. The value is the one every
//! non-robot domain and the robot type "None" build with (0, wheeled), which
//! is the starting type the tests here assume before they set their own.

pub const ROBOT_TYPE_ID: usize = 0;

/// Kconfig `SAFETY_COMMS_TIMEOUT_S` / `SAFETY_DRONE_COMMS_TIMEOUT_S` (wave 11),
/// at their defaults: the safety layer scales them by `TIMER_FREQ`.
pub const SAFETY_COMMS_TIMEOUT_S: usize = 5;
pub const SAFETY_DRONE_COMMS_TIMEOUT_S: usize = 3;

/// Wave 15 (config/Kconfig.robot, "RC input and geofence"), at their defaults.
pub const RC_INPUT: bool = true;
pub const RC_FAILSAFE_ESTOP: bool = true;
pub const RC_LINK_TIMEOUT_MS: u64 = 500;
pub const RC_MODE_CHANNEL: usize = 5;
pub const RC_KILL_CHANNEL: usize = 6;
pub const RC_SWITCH_HIGH_US: u64 = 1700;
pub const RC_DRIVE_CHANNEL: usize = 2;
pub const RC_STEER_CHANNEL: usize = 1;
pub const RC_STICK_DEADBAND_US: u64 = 20;
pub const RC_STICK_FULL_SCALE_PCT: usize = 100;
pub const GEOFENCE: bool = true;
pub const GEOFENCE_RADIUS_M: usize = 100;
pub const GEOFENCE_MIN_SATELLITES: usize = 4;
pub const LOG_RING_ENTRIES: usize = 128;
pub const LOG_FLUSHER_JOBS: usize = 4;
