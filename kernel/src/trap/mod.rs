// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64 trap handling the crate root used to carry (declared under that
//! gate in `main.rs`): interrupt and exception dispatch, entered from
//! `entry::riscv64::riscv64_trap_handler` and `trap_entry.S`. aarch64's own
//! dispatch lives in `entry::aarch64`. Re-exported so callers keep the names.

mod interrupt;
pub(crate) use interrupt::*;
mod exception;
pub(crate) use exception::*;
