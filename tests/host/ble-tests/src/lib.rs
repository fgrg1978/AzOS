// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of the BLE host stack (userspace/lib/ble). The harness is `rig`: a scripted
//! controller per host and a radio between two of them. The in-tree user of the library
//! until `ble-gatt` lands.
#![cfg(test)]

mod att_t;
mod crypto_t;
mod h4_t;
mod hci_t;
mod host_t;
mod l2cap_t;
mod rig;
mod smp_t;
