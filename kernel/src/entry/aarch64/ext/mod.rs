// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64-only boot extras with no counterpart on the other ISAs.

pub(crate) mod hv_vectors;
#[cfg(feature = "pci")]
pub(crate) mod its_route;
pub(crate) mod pan_patch;
#[cfg(any(feature = "rpi-firmware", feature = "energy"))]
pub(crate) mod rpi_mbox;
#[cfg(feature = "wdt-bcm2835-pm")]
pub(crate) mod rpi_pm;
pub(crate) mod selftests;
// I-13's rollback of an EL1 Alignment fault (ktest).
#[cfg(all(feature = "ktest", feature = "use-robot"))]
mod txn_align;
