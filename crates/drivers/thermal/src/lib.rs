// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The thermal framework's runtime: the part that touches hardware.
//!
//! The policy (zones, trips, step-wise cooling, the floors, degrade and the
//! record ring) is `azos_energy::thermal`; the way an OPP reaches a clock is
//! `azos_energy::opp`. This crate joins them to a board:
//!
//! * [`dt`] — builds the zones from the device tree's `thermal-zones`
//!   (`azos_dtb::dtb_thermal`), resolving the sensor and the cooled CPUs.
//! * [`sensor`] — the [`sensor::SensorBank`] seam and its errors.
//! * [`jh7110`] — the StarFive JH7110 `sfctemp` sensor, and the board object
//!   that pairs it with the clock framework through [`jh7110::CpuClock`].
//! * [`soc`] — the CPU clock over the SoC clock framework (`azos_soc`),
//!   capped at the rate the unmoved supply is known to carry; it implements
//!   [`jh7110::CpuClock`].
//! * [`rpi`] — the Raspberry Pi board object: temperature and ARM clock both
//!   through the firmware mailbox (`azos_firmware`).
//! * [`k1`] — the SpacemiT K1: the `TSEN` sensor (five channels, started at
//!   probe with a check that the window holds what is written to it) and the
//!   DVFS actuator (the OPP table with its voltages from the device tree, the
//!   order in which a cluster's rail and clock move, a rail two clusters
//!   share). [`k1_soc`] is its hardware over the SoC frameworks (the K1
//!   clock provider and the P1 PMIC bucks over I2C) and reads the clusters
//!   from the device tree.
//! * [`x86_sensor`] — the x86_64 package temperature (Intel `coretemp` MSRs,
//!   AMD Zen over SMN), probed from CPUID before any register is read, and
//!   [`x86_sensor::X86Board`], the sensor paired with the actuator the board
//!   has. [`x86`] is that actuator (Intel HWP or AMD CPPC level requests per
//!   logical CPU, refusing every request on a CPU with neither) and the RAPL
//!   package energy meter.
//! * [`runtime`] — [`runtime::Runtime::from_dt`] builds the board's runtime
//!   from the device tree; [`runtime::Runtime::tick`] reads the zones that
//!   are due, decides, sets the clocks and settles the degrade level. The
//!   kernel's thermal task (`kernel/src/boot/thermal.rs`) owns the runtime,
//!   wakes at [`runtime::Runtime::poll_interval_ms`] and is the one caller.
//! * `fake` (Cargo feature of the QEMU gate row) — a board with a scripted
//!   temperature and a clock that only remembers.
//!
//! A board plugs in as a `SensorBank` + `OppActuator` pair; nothing here is
//! board-specific outside [`jh7110`], [`rpi`], [`k1`], [`x86_sensor`] and [`x86`].
//! A machine whose x86_64 probe finds no sensor (QEMU, a hypervisor) has no
//! thermal zone to read and the framework stays idle (invariant I4).

#![cfg_attr(target_os = "none", no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod dt;
#[cfg(feature = "fake")]
pub mod fake;
pub mod jh7110;
pub mod k1;
pub mod k1_soc;
pub mod rpi;
pub mod runtime;
pub mod sensor;
pub mod soc;
pub mod x86;
pub mod x86_sensor;
