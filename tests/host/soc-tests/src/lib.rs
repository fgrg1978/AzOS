// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `azos_soc`: the device-tree reader and consumer lookup,
//! the five frameworks over mock providers, and the JH7110 register models
//! against hand-written traces.

// The DesignWare I2C bring-up (crates/drivers/bus), pulled in by path as
// drivers-tests does: the VisionFive 2 rows feed it the rate the clock tree
// resolves (`vf2_clock_tests`).
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../../crates/drivers/bus/src/i2c_txn.rs"]
mod i2c_txn;
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../../crates/drivers/bus/src/i2c_dw.rs"]
mod i2c_dw;

#[cfg(test)]
mod support;

#[cfg(test)]
mod bind_tests;
#[cfg(test)]
mod board_drivers_tests;
#[cfg(test)]
mod clk_tests;
#[cfg(test)]
mod consumer_tests;
#[cfg(test)]
mod fdt_tests;
#[cfg(test)]
mod jh7110_iomux_tests;
#[cfg(test)]
mod jh7110_tests;
#[cfg(test)]
mod k1_tests;
#[cfg(test)]
mod reset_tests;
#[cfg(test)]
mod pd_tests;
#[cfg(test)]
mod pinctrl_tests;
#[cfg(test)]
mod regulator_tests;
#[cfg(test)]
mod hwbus_tests;
#[cfg(test)]
mod vf2_clock_tests;
#[cfg(test)]
mod wire;
