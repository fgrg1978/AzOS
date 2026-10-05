// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! GPIO: the pin controller and its `Driver` registration.

#![no_std]

// Second Driver trait migration (A3a.2). Validates the trait shape
// against a pin-oriented hardware family — sim on QEMU, real MMIO
// on VF2/K1.
pub mod gpio_driver;

pub mod gpio;
