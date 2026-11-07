// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
#![forbid(unsafe_code)]

//! The sensors the robot extension produces, at the instance numbers the
//! topology's `sensor.<n>` endpoints name (`azos_abi::sensor_sample::instance`).
//!
//! An image without the extension still has those numbers, reserved and empty:
//! a read answers `NOT_READY`, which is what a capability on one was granted
//! for. The power monitor (instance 9) is the board's I/O.

mod set;
pub use set::*;
