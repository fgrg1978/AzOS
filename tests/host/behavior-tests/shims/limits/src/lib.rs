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
