// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Buses: I2C, SPI, CAN, USB host and device controllers, the UART bridge to
//! the companion radio, and the DTB-instantiated device bus (`hwbus`).

#![no_std]

// Third Driver trait migration (A3a.3). Bus-oriented hardware
// (DesignWare I2C). Proves the uniform `(op, input, output)` API
// scales to multi-axis (bus + slave addr + register) addressing.
pub mod i2c_driver;

pub mod i2c;

// SPI master driver (sim on QEMU; Cadence SPI on VF2).
#[allow(dead_code)]
pub mod spi;

// CAN bus driver (simulation only — no CAN hardware on supported platforms).
#[allow(dead_code)]
pub mod can;

// USB host controller (skeleton; xHCI on VF2).
#[allow(dead_code)]
pub mod usb;

// USB device-mode controller (DEV02 DFU recovery — DWC2 on VF2/K1).
// Trait + scaffold; DWC2 register programming is post-hardware work.
#[allow(dead_code)]
pub mod usb_device;

// UART bridge driver for ESP32-C3 WiFi relay (VF2 UART1; stub on others).
pub mod uart_bridge;

/// DTB-instantiated (or platform-table-instantiated) device bus (U05 §5
/// Q3, Linux-driver-model shape) — `kernel/src/entry/*/boot_hooks.rs` (not
/// this crate) holds the parsed DTB and is the intended caller for the
/// live DTB bases; see this module's doc.
pub mod hwbus;
