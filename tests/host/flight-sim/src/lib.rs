// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side simulation and unit-test harness for drone flight algorithms (D07).
//!
//! This crate is a **pure-std Rust** mirror of the `azos_flight` crate's
//! pure mathematical core.  It exists so that algorithm unit tests can run on
//! the development machine with a plain `cargo test -p azos_flight_sim`
//! without the RISC-V toolchain or any arch-specific dependencies.
//!
//! ## Modules
//! - [`trig`]    — integer sin/cos table (SLAM D06)
//! - [`mixer`]   — motor mixer for all frame types (D04)
//! - [`path3d`]  — 3-D geometry primitives (RRT* D03)
//! - [`terrain`] — terrain-following PD controller (D05)
//! - [`sitl`]    — quadrotor SITL physics (D02)
//! - [`ekf`]     — scalar Kalman update (D01)

pub mod trig;
pub mod mixer;
pub mod path3d;
pub mod terrain;
pub mod sitl;
pub mod ekf;

// ── Re-exports for convenience ────────────────────────────────────────────────
pub use trig::{sin1000, cos1000};
pub use mixer::{FrameType, MixerOutput, mixer_compute};
pub use path3d::Point3D;
