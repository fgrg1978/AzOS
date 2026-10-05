// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Driver base: the board description (`platform::hw`), the in-kernel driver
//! registry (`runtime`) and resource decoding (`drv_resource`).
//!
//! No MMIO access of its own. Every driver class crate builds on it; it
//! depends on no driver crate.

#![no_std]

pub mod runtime;

pub mod platform;

/// Which resource a driver call reaches — pure, host-testable.
pub mod drv_resource;
