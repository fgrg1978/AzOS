// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! GPIO: the pin controller and its `Driver` registration.

#![no_std]

pub mod gpio;

/// The controllers the `Gpio` interface serves, by controller number.
pub mod chips;

pub(crate) use azos_drv_base::instances;

/// A soft second controller for development kernels (Kconfig
/// `GPIO_SOFT_EXPANDER`).
#[cfg(feature = "soft-expander")]
pub mod expander;

/// The kill switch's debounce: which samples of an input line are a new
/// press. Pure; the host suite pulls the file in with `#[path]`.
pub mod debounce;

/// The JH7110 sys pin controller's GPIO interrupt registers over a trait
/// (`gpio.rs`'s `mmio` module is the kernel half). Compiled for the VF2 only;
/// the host suite pulls the file in with `#[path]`.
#[cfg(feature = "vf2")]
pub mod gpio_jh7110_irq;

/// The pins the kernel's stop holds, shared by every `gpio` backend.
pub mod hold;

/// The SpacemiT K1 controller's registers over a trait (`gpio.rs`'s `k1`
/// module is the kernel half). Compiled for the K1 only; the host suite pulls
/// the file in with `#[path]`.
#[cfg(feature = "k1")]
pub mod gpio_k1;
