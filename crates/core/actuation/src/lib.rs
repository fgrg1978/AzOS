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
//! - `effect_gate` (feature `effect-gate`, Kconfig `EFFECT_WRITE_AHEAD`):
//!   write-ahead receipts, the device op is issued only after its record is
//!   committed to the flight recorder's ring (innovation B1); a ring at its
//!   limit refuses the effect with a receipt.
//! - `safe_state` (same feature; innovation B2): the other half of the gate.
//!   An effect with a declared deadline is admitted against the device's
//!   placement latency plus its row's `commit_ns` and watched; the system
//!   watchdog's pass drives a device that missed its deadline to its declared
//!   safe state, and an effect that failed is compensated. One decision
//!   record each (`Rule::EffectDeadline`, `SafeState`, `Compensation`). The
//!   device then stays held (a stop does not lift it) for at least
//!   `B2_HOLD_MIN_MS`, and only `safe_state::release`, with the operator's
//!   signed warrant of the e-stop release, lifts it.
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
#[cfg(feature = "effect-gate")]
pub mod effect_gate;
#[cfg(feature = "effect-gate")]
mod envelope;
pub mod estop;
pub mod gate;
pub mod hooks;
pub mod kill_switch;
pub mod logger;
#[cfg(feature = "effect-gate")]
pub mod safe_state;
pub mod sys_wdt;
pub mod watchdog;
