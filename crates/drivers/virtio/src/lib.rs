// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! VirtIO transport (MMIO and PCI) and its devices: block, network, entropy.
//!
//! The block and network classes (`azos_drv_block`, `azos_drv_net`) select a
//! VirtIO backend from here; this crate sees them only through the class
//! traits in `azos_drv_api`.

#![no_std]

pub mod virtio;
