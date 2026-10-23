// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Power management: system suspend, and the Raspberry Pi's PM block (its
//! watchdog, reboot and power-off).

#![no_std]
#![forbid(unsafe_code)]

pub mod bcm2835_pm;
pub mod pm;
