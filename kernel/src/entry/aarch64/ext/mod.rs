// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64-only boot extras with no counterpart on the other ISAs.

pub(crate) mod hv_vectors;
#[cfg(feature = "pci")]
pub(crate) mod its_route;
pub(crate) mod pan_patch;
#[cfg(feature = "thermal")]
pub(crate) mod rpi_mbox;
pub(crate) mod selftests;
