// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! The safety path of the actuation authority (RFC-0040 gap 0): the code that
//! moves or stops a motor and used to live in `kernel/src/main.rs`.
//!
//! The kernel stays the composition root. It creates every task (name,
//! priority, hart), calls the ISR-side functions from its trap handler, calls
//! `txn::txn_try_rollback` from `handle_exception`, and installs the hook for
//! the one scaffolding call this path makes (the OTA boot-good mark).

pub mod actuation;
pub mod flight_ctrl;
pub mod rt_motor;
pub mod txn;

// Moved to `azos_actuation` (wave 11, DOMAIN): the boot latch replay, the
// kill switch, the system watchdog task and the tick/heartbeat/WDT feed are
// not robot-specific. Re-exported so `azos_safety_core::<module>` paths
// keep resolving for robot code.
pub use azos_actuation::{boot_latch, kill_switch, sys_wdt, watchdog};
