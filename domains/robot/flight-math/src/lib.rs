// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pure no_std drone math, shared by the kernel `flight` crate and host tests.
//!
//! This crate has **zero kernel dependencies** so it builds both for the
//! workspace's `riscv64imac-unknown-none-elf` target (as part of the kernel)
//! and for the developer host (where `flight-math-tests` runs its `cargo test`
//! suite). Keeping the math here — rather than inside `domains/robot/flight`, which
//! pulls in `azos_drv_*` and is therefore not host-buildable — is what
//! makes it unit-testable.
//!
//! Modules:
//! - [`trig`]: integer sine/cosine lookup tables (centi-degrees, ×1000 scale).
//! - [`wind`]: acceleration-residual wind/disturbance estimator (D04).
//! - [`scan`]: beam-count cap shared with `flight`'s SLAM update (D06).

#![no_std]

pub mod position;
pub mod scan;
pub mod trig;
pub mod wind;
