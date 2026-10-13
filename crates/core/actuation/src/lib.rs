// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! The authority over irreversible effects that every domain with an
//! actuator shares (owner decision, wave 11: safety is cross-cutting).
//!
//! - [`estop`]: the emergency-stop latch, its signed release authority, safe
//!   mode.
//! - [`gate`]: the one latch-and-stop sequence, the stop work a domain
//!   registers into it, the ring-3 e-stop and the capability-denial / audit
//!   recorders the kernel installs at boot.
//! - [`logger`]: the flight recorder (ring + durable FAT32 log) every safety
//!   record goes to, and the boot replay of the latch.
//! - [`boot_latch`], [`kill_switch`], [`sys_wdt`], [`watchdog`]: the boot
//!   latch replay, the GPIO kill-switch check, the system watchdog task and
//!   the timer-ISR tick / heartbeat / hardware-watchdog feed.
//!
//! Robot-specific parts stay in `domains/robot`: the motor gate and its
//! per-robot-type envelope (`azos_safety_core::actuation`,
//! `azos_behavior::safety::motor_envelope`), the control loop, flight.
//! They plug in through [`hooks`] tables registered at boot, so this crate
//! depends on no domain crate.

pub mod boot_latch;
pub mod estop;
pub mod gate;
pub mod hooks;
pub mod kill_switch;
pub mod logger;
pub mod sys_wdt;
pub mod watchdog;
