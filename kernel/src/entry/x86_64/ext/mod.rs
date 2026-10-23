// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64-only boot extras with no counterpart on the other ISAs.

pub(crate) mod cpu_init;
/// The core types the CPUs report, for the energy model (Kconfig ENERGY).
#[cfg(feature = "energy")]
pub(crate) mod hybrid_energy;
/// The hardware-virtualization probe and record (Kconfig X86_SVM, X86_VMX).
pub(crate) mod hv;
/// The x86 thermal board object's CPUID, MSR and config-space access (Kconfig THERMAL).
#[cfg(all(feature = "thermal", not(feature = "thermal-smoke")))]
pub(crate) mod thermal_hw;
/// The Limine boot entry's requests and Rust half (Kconfig X86_BOOT_LIMINE).
#[cfg(feature = "x86-limine")]
pub(crate) mod limine;
/// The clocksource's boot record and the TSC watchdog task (Kconfig
/// X86_TSC_CLOCK, X86_TSC_WATCHDOG).
pub(crate) mod tsc_watchdog;
