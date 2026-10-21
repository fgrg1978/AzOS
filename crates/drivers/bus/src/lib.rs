// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Buses: I2C, SPI, CAN, USB host and device controllers, the UART bridge to
//! the companion radio, and the kernel's hardware bus (`hwbus`: the runtime
//! device table every enumerator fills and every driver binds through).

#![no_std]

// Third Driver trait migration (A3a.3). Bus-oriented hardware
// (DesignWare I2C). Proves the uniform `(op, input, output)` API
// scales to multi-axis (bus + slave addr + register) addressing.
pub mod i2c_driver;

pub mod i2c;
pub mod i2c_txn;

// SpacemiT K1 I2C master: the byte-at-a-time state machine `i2c.rs` drives
// on the K1 board.
#[cfg(feature = "k1")]
pub mod i2c_k1;

// SPI master driver (sim on QEMU; Cadence SPI on VF2).
#[allow(dead_code)]
pub mod spi;

// CAN bus driver (simulation only — no CAN hardware on supported platforms).
#[allow(dead_code)]
pub mod can;

// UART bridge driver for ESP32-C3 WiFi relay (VF2 UART1; stub on others).
pub mod uart_bridge;

/// The kernel's hardware bus instance (`azos_hwbus`) and the lookups the
/// capability layer uses.
pub mod hwbus;
