// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Driver base: the board description (`platform::hw`), the in-kernel driver
//! registry (`runtime`).
//!
//! No MMIO access of its own ([`window`] only keeps the base a bound driver was
//! handed). Every driver class crate builds on it; it
//! depends on no driver crate.

#![no_std]
#![forbid(unsafe_code)]

pub mod runtime;

pub mod platform;

pub mod window;

