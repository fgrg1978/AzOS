// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Network devices: the NIC backend selection (`net_device`), the Ethernet MAC
//! drivers (`eth`: Cadence MACB/GEM; `dwmac`: Synopsys DesignWare QoS).

#![no_std]

/// `NetDevice` trait + the NIC-backend selection point. See the module doc
/// for why `crates/net/stack`'s three hand-written `if eth_is_ready() {...} else
/// {...}` dispatch sites collapse into this.
pub mod net_device;

// Kconfig DRV_E1000E: the Intel e1000e NIC over PCI. Its wire half (descriptor
// cursors, MAC and link decoding) is also igc.rs's, so Kconfig DRV_IGC compiles
// the module too; the device half stays behind `e1000e`.
#[cfg(any(feature = "e1000e", feature = "igc"))]
pub mod e1000e;

// The device half e1000e.rs and igc.rs share: rings, buffers, the receive and
// transmit paths, the interrupt hook and the PCI bring-up order.
#[cfg(any(feature = "e1000e", feature = "igc"))]
pub mod pci_nic;

// Kconfig DRV_IGC: the Intel I225/I226 2.5 GbE NIC over PCI.
#[cfg(feature = "igc")]
pub mod igc;
// Kconfig USB_CDC / USB_SMSC95XX: a USB network function (CDC-ECM/NCM, SMSC
// LAN95xx) as a NIC.
#[cfg(feature = "usb-net")]
pub mod usb_net;

// Real Ethernet MAC driver (Cadence MACB/GEM on VF2; stub on QEMU).
#[allow(dead_code)]
pub mod eth;

// Synopsys DesignWare Ethernet QoS MAC + MDIO/PHY (the VisionFive 2's gmac0).
// The driver proper is generic over the register window and the DMA domain
// and builds everywhere; its statics and `NetDevice` face (`dwmac::board`) are
// the board feature's.
pub mod dwmac;
