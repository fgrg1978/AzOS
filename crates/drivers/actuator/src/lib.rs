// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Actuators: PWM (and which channels a write reaches, `pwm_domain`), the motor
//! PID loop, and the piezo buzzer, each with its `Driver` registration where
//! one exists.

#![no_std]

// Fourth Driver trait migration (A3a.4). Multi-parameter actuator
// (PWM channel + nanosecond period/duty).
pub mod pwm_driver;

// Fifth Driver trait migration (A3a.5). Closed-loop controller
// (motor PID) — pure software, no MMIO of its own.
pub mod motor_driver;

pub mod pwm;

/// Which channels one PWM control-register write actually reaches. Kept out
/// of `pwm.rs` so `tests/host/drivers-tests` can pull it with `#[path]` — see the
/// module docs.
pub mod pwm_domain;

// PID velocity controller for wheeled robots (4WD differential drive).
pub mod motor_pid;

// Piezo buzzer: the kernel's client of the ring-3 driver (`userspace/drivers/buzz_drv`).
pub mod buzzer;
