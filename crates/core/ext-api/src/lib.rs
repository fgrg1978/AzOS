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
//! level is refused there. What it provides is its effect [`Provider`]s (the
//! stop work for the physical effects it owns, run by the actuation core
//! whenever the e-stop latches, and the effect kinds they serve) and its
//! [`BootHook`]s, run at declared boot phases, so the base never names an
//! extension's devices or tasks. Its hard-deadline loops over an effect are
//! [`EffectLoop`]s: the base creates them, as safety tasks, from the
//! descriptor the extension's driver registers.

/// The contract's level. A change to [`Provider`] or [`Manifest`] that an
/// extension built against the old shape could not meet raises it.
pub const API_LEVEL: u16 = 4;

/// What an extension owns of the machine's effects, as the actuation core
/// drives it.
pub struct Provider {
    /// Named in the boot banner and in a refused install.
    pub name: &'static str,
    /// The effect kinds (`azos_actuation::kind`) whose devices it owns. An
    /// effect of a kind no installed provider owns is refused, with a
    /// receipt: the image has no such device.
    pub kinds: &'static [u8],
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

/// The kernel's enable of an interrupt line on the calling CPU; `true` when
/// the line is routed there.
pub type EnableLine = fn(line: u32) -> bool;

/// A loop with a hard deadline over an irreversible effect (a drivetrain's
/// command-to-PWM loop, a flight controller's mixer), whose body the effect's
/// driver provides. The base creates it at the task phase on the CPU class of
/// the effect loops (Kconfig `TASK_CONTROL_PLACE`), outside the real-time
/// band's budget, and registers it as a safety task: a fault in it is never
/// contained. It is the only kind of task an extension keeps in the kernel;
/// what chooses rather than enforces runs in ring 3.
pub struct EffectLoop {
    /// The task's name.
    pub name: &'static str,
    /// The loop; it never returns.
    pub body: fn(usize),
    /// Its scheduler priority, inside the real-time band.
    pub priority: u32,
}

/// The kernel's creation of one [`EffectLoop`].
pub type SpawnLoop = fn(&'static EffectLoop);

/// Work an extension does at one declared boot phase, run once per phase in
/// install order.
#[derive(Clone, Copy)]
pub enum BootHook {
    /// After CONFIG.INI is loaded under its signed authority and applied.
    ConfigLoaded(fn()),
    /// Inside the actuation core's install, after its own seams and before
    /// the gate reads as installed: wire the provider's effect kinds into the
    /// effect interface (the write-ahead gate, the safe-state drivers).
    Effects(fn()),
    /// At the start of the board's bring-up: the hardware bus, entropy, PCI,
    /// the block device and mounts and the signed configuration are done, the
    /// scheduler is not up, and the I2C, PWM and temperature controllers are
    /// not bound yet. Attach static descriptors to the instance numbers the
    /// base reserves for them (the sensor class's) and probe nothing, so the
    /// base names none of them.
    Devices(fn()),
    /// With the system watchdog, before the scheduler starts: create the
    /// extension's kernel tasks.
    Tasks(fn(EnableLine)),
    /// At the same phase, in the same order: an effect loop the base creates.
    EffectLoop(&'static EffectLoop),
}

/// An extension, as the base sees it.
pub struct Manifest {
    pub name: &'static str,
    /// The [`API_LEVEL`] it was built against.
    pub api_level: u16,
    /// Run in this order by every stop.
    pub providers: &'static [Provider],
    pub hooks: &'static [BootHook],
}
