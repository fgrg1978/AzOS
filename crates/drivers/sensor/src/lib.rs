// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Sensors: INA219 power monitor, ADS1115 ADC, LD19 LiDAR, rangefinders
//! (ultrasonic and time-of-flight) and the MIPI CSI-2 camera interface.

#![no_std]

// Rangefinder sensors — ultrasonic (HC-SR04) + Time-of-Flight (VL53L0X).
pub mod rangefinder;

// MIPI CSI-2 camera driver (simulated on QEMU; JH7110 ISP on VF2; SpacemiT ISP on K1).
pub mod csi;

// ADS1115 16-bit 4-channel I2C ADC (battery voltage, analog sensors).
pub mod ads1115;

// LD19 (LD-06) 2D LiDAR UART driver — 360° scan, 12m range.
pub mod lidar;

// INA219 power monitor: the kernel API over either host of
// `crates/drivers/ina219` (Kconfig DRV_INA219_PLACEMENT: the ring-3 driver
// `userspace/drivers/ina_drv` through the proxy, or the in-kernel host).
pub mod ina219;

// Optical flow sensor driver (F26): PMW3901 / PAA5100JE via SPI — DELETED
// 2026-09-26 (U05-7). Zero callers anywhere in kernel/crates/tests for any
// of its public functions (`optical_flow_init`, `optical_flow_poll`,
// `flow_delta_x/y`, `flow_squal`, `flow_to_velocity_nm_s`, …) or its
// `OpticalFlowSensor` type — confirmed by grep before deletion, unlike
// `lidar`/`ina219`/`ads1115`/`buzzer`/`dma`, which all have at least one
// real external caller (a `SYS_SENSOR_READ` arm, a shell command, or a
// `main.rs` init call) and stay. `flow_to_velocity_nm_s` also traps in i32
// for |counts| > 2191 (multiplies by 980_000) — one more reason not to
// leave it reachable un-exercised. If drone/slip-detection velocity
// estimation is wanted again, re-add from git history with a real caller
// this time, not a parallel API surface with none.
