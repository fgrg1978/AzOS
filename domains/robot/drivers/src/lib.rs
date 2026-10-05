// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Drivers only the robot domain uses: the ESC outputs for brushless motors and
//! the RC receiver (SBUS / PPM).

#![no_std]

// ESC (Electronic Speed Controller) PWM output for brushless motors.
pub mod esc;

// RC (Remote Control) receiver — SBUS / PPM input.
pub mod rc;
