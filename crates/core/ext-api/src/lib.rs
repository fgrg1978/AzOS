// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
#![forbid(unsafe_code)]

//! The contract between the base kernel and an extension (robot, industrial,
//! IoT...), as `arch/api` is the contract between the kernel and an ISA.
//!
//! An extension adds to the base and never changes it. It is named by a
//! [`Manifest`], built against one [`API_LEVEL`], and installed once at boot
//! (`azos_actuation::providers::install`); a manifest built against another
//! level is refused there. What it provides today is its effect
//! [`Provider`]s: the stop work for the physical effects it owns, run by the
//! actuation core whenever the e-stop latches, so the core never names an
//! extension's devices.

/// The contract's level. A change to [`Provider`] or [`Manifest`] that an
/// extension built against the old shape could not meet raises it.
pub const API_LEVEL: u16 = 1;

/// What an extension owns of the machine's effects, as the actuation core
/// drives it.
pub struct Provider {
    /// Named in the boot banner and in a refused install.
    pub name: &'static str,
    /// Stop the provider's devices. Run after the latch is set, so every
    /// write from every path is already clamped; may take locks.
    pub stop: fn(),
    /// The same stop, lock-free: the panic handler and the timer interrupt of
    /// a hart that saw another one panic run it.
    pub panic_stop: fn(),
    /// Work that must happen whenever the latch arms (after the latch store,
    /// before the stop), such as making a cached command the stop.
    pub on_latch: Option<fn()>,
    /// Is the provider's own gate in place? Ring-3 images start only once
    /// every provider says so (fail closed).
    pub ready: Option<fn() -> bool>,
}

/// An extension, as the base sees it.
pub struct Manifest {
    pub name: &'static str,
    /// The [`API_LEVEL`] it was built against.
    pub api_level: u16,
    /// Run in this order by every stop.
    pub providers: &'static [Provider],
}
