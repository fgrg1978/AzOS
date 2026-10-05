// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

pub mod error;
pub mod panic_policy;
pub mod wcet;

use core::sync::atomic::{AtomicBool, Ordering};

/// Global "the kernel has panicked" flag.
///
/// Set by the panic handler before it brings actuators to a safe state.
/// Consulted by the actuator drivers (`motor_set`/`esc_set_throttle`) and the
/// timer ISR so that a hart which has NOT panicked halts on its next tick
/// instead of kicking the watchdog or re-commanding the motors.
static PANICKED: AtomicBool = AtomicBool::new(false);

/// Mark the system as panicked. Idempotent; never cleared.
#[inline]
pub fn set_panicked() {
    PANICKED.store(true, Ordering::SeqCst);
}

/// True once any hart has entered the panic handler.
#[inline]
pub fn is_panicked() -> bool {
    PANICKED.load(Ordering::Relaxed)
}
