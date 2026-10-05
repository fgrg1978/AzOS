// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Network devices: the NIC backend selection (`net_device`), the Ethernet MAC
//! driver, and the WiFi API surface.

#![no_std]

/// `NetDevice` trait + the NIC-backend selection point. See the module doc
/// for why `crates/net/net`'s three hand-written `if eth_is_ready() {...} else
/// {...}` dispatch sites collapse into this.
pub mod net_device;

// Real Ethernet MAC driver (Cadence MACB/GEM on VF2; stub on QEMU).
#[allow(dead_code)]
pub mod eth;

// WiFi driver — API surface only; no-op stubs (no WiFi hardware).
pub mod wifi;
