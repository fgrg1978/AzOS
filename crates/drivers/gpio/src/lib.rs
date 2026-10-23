// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! GPIO: the pin controller and its `Driver` registration.

#![no_std]

// Second Driver trait migration (A3a.2). Validates the trait shape
// against a pin-oriented hardware family — sim on QEMU, real MMIO
// on VF2/K1.
pub mod gpio_driver;

pub mod gpio;

/// The kill switch's debounce: which samples of an input line are a new
/// press. Pure; the host suite pulls the file in with `#[path]`.
pub mod debounce;

/// The JH7110 sys pin controller's GPIO interrupt registers over a trait
/// (`gpio.rs`'s `mmio` module is the kernel half). Compiled for the VF2 only;
/// the host suite pulls the file in with `#[path]`.
#[cfg(feature = "vf2")]
pub mod gpio_jh7110_irq;

/// The SpacemiT K1 controller's registers over a trait (`gpio.rs`'s `k1`
/// module is the kernel half). Compiled for the K1 only; the host suite pulls
/// the file in with `#[path]`.
#[cfg(feature = "k1")]
pub mod gpio_k1;
