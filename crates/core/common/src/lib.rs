// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

pub mod error;
pub mod panic_policy;
pub mod wcet;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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

/// CPUs parked because the kernel panicked, one bit per CPU id (the
/// `Cpu::hart_id` index; ids from 64 up are not tracked). Set by the CPU
/// itself right before it halts (`azos_actuation::watchdog::halt_if_panicked`,
/// from its timer tick or from the panic handler's stop IPI) and read by the
/// panicking CPU, which waits for every other online CPU to show up here
/// before it prints its report (Kconfig `PANIC_QUIESCE`). A bit, not a
/// count: a CPU that parks twice (its tick, then the IPI it already had
/// pending) is counted once.
static PARKED: AtomicU64 = AtomicU64::new(0);

/// This CPU is about to halt for good because the kernel panicked.
#[inline]
pub fn note_parked(cpu: usize) {
    if cpu < 64 {
        PARKED.fetch_or(1 << cpu, Ordering::AcqRel);
    }
}

/// The CPUs parked so far ([`note_parked`]), one bit per CPU id.
#[inline]
pub fn parked_mask() -> u64 {
    PARKED.load(Ordering::Acquire)
}
