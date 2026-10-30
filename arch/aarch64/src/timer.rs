// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The clock and the per-CPU timer.
//!
//! **The clock** ([`now_ticks`]) counts at Kconfig `TIMER_FREQ`, the rate every
//! `N * TIMER_FREQ` timeout in the tree is written in, so it is `CNTVCT_EL0`
//! scaled from the `CNTFRQ_EL0` the firmware or hypervisor set: 1 GHz under
//! QEMU's TCG, the host's fixed rate under HVF, 19.2 or 54 MHz on a Pi.
//! `ticks = CNTVCT_EL0 * mult >> 32`, no division, and with no base: the counter
//! is readable at reset, so the scale is known before anything reads the clock.
//!
//! The product is 128 bits and cannot overflow. The result leaves 64 bits when
//! the counter has run `2^64 / TIMER_FREQ` seconds, 584 years at 1 GHz, whatever
//! `CNTFRQ_EL0` is, and saturates. Truncating `mult` loses at most `counter /
//! 2^32` ticks: under 18 ms in a century at 24 MHz.
//!
//! **The timer** fires at a deadline in clock ticks: the distance to it in
//! counter units on top of the counter now ([`ticks_to_counter`]), since scaling
//! the absolute deadline back would carry `mult`'s rounding into every arm.
//!
//! A reader of the raw counter that pairs it with [`counter_hz`] (the tracer's
//! stamps, a guest's virtual time) stays on the raw counter.

#[cfg(target_arch = "aarch64")]
use crate::sysregs;
#[cfg(target_arch = "aarch64")]
use azos_arch_api::clock_scale::Scale;
#[cfg(target_arch = "aarch64")]
use core::sync::atomic::{AtomicU64, Ordering};

const NS_PER_S: u64 = 1_000_000_000;

/// The clock's rate (Kconfig `TIMER_FREQ`).
pub const TICK_HZ: u64 = azos_limits::TIMER_FREQ as u64;

#[cfg(target_arch = "aarch64")]
static TO_TICKS: AtomicU64 = AtomicU64::new(Scale::IDENTITY.mult);
#[cfg(target_arch = "aarch64")]
static TO_COUNTER: AtomicU64 = AtomicU64::new(Scale::IDENTITY.mult);

/// Take the clock's scale from `CNTFRQ_EL0`. Once, on the boot CPU, before the
/// clock is read: the register is system-wide, so the secondaries share it.
/// A rate that cannot be scaled (a firmware that left it 0) stays 1:1.
#[cfg(target_arch = "aarch64")]
pub fn clock_init() {
    let hz = sysregs::read_cntfrq_el0();
    if let (Some(to_ticks), Some(to_counter)) = (Scale::new(hz, TICK_HZ), Scale::new_up(TICK_HZ, hz)) {
        TO_TICKS.store(to_ticks.mult, Ordering::Relaxed);
        TO_COUNTER.store(to_counter.mult, Ordering::Relaxed);
    }
}

/// Runtime canary `clock-scale-skip`: the counter is taken for the clock, as if
/// `CNTFRQ_EL0` were `TIMER_FREQ`.
#[cfg(target_arch = "aarch64")]
pub fn clock_unscaled() {
    TO_TICKS.store(Scale::IDENTITY.mult, Ordering::Relaxed);
    TO_COUNTER.store(Scale::IDENTITY.mult, Ordering::Relaxed);
}

/// The 32.32 multiplier from the counter to the clock, as ring 3 applies it.
#[cfg(target_arch = "aarch64")]
pub fn counter_to_ticks_mult() -> u64 {
    TO_TICKS.load(Ordering::Relaxed)
}

/// The clock's rate: what a [`now_ticks`] difference is divided by.
#[cfg(target_arch = "aarch64")]
pub fn freq_hz() -> u64 {
    TICK_HZ
}

/// The rate of the raw counter, `CNTFRQ_EL0`.
#[cfg(target_arch = "aarch64")]
pub fn counter_hz() -> u64 {
    sysregs::read_cntfrq_el0()
}

/// The clock, in `TIMER_FREQ` ticks. Monotonic, as `CNTVCT_EL0` is.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn now_ticks() -> u64 {
    Scale { mult: TO_TICKS.load(Ordering::Relaxed) }.apply(sysregs::read_cntvct_el0())
}

/// The raw counter value at which the clock reaches `deadline`, never earlier;
/// the counter now for a deadline already past, `u64::MAX` for one past the
/// counter's range.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn ticks_to_counter(deadline: u64) -> u64 {
    let mult = TO_COUNTER.load(Ordering::Relaxed);
    if mult == Scale::IDENTITY.mult {
        return deadline;
    }
    let counter = sysregs::read_cntvct_el0();
    let now = Scale { mult: TO_TICKS.load(Ordering::Relaxed) }.apply(counter);
    counter.saturating_add(Scale { mult }.apply_ceil(deadline.saturating_sub(now)))
}

/// Wall-clock-style nanosecond reading. Convenience wrapper
/// around `now_ticks` + the calibrated frequency.
#[cfg(target_arch = "aarch64")]
pub fn now_ns() -> u64 {
    let hz = freq_hz();
    if hz == 0 {
        return 0;
    }
    // Avoid 64-bit overflow on the multiply: split into seconds
    // and remainder, mix back. Cheap at the cost of an extra div.
    let t = now_ticks();
    let secs = t / hz;
    let rem  = t % hz;
    secs * NS_PER_S + (rem * NS_PER_S) / hz
}

/// Disarm the virtual timer — clears CNTV_CTL_EL0.ENABLE so
/// no IRQ fires regardless of CVAL. CVAL is preserved.
#[cfg(target_arch = "aarch64")]
pub fn disarm() {
    unsafe {
        // CNTV_CTL_EL0: bit 0 = ENABLE, bit 1 = IMASK, bit 2 = ISTATUS (RO).
        // Write 0 → disable + unmask (the unmask is irrelevant when disabled).
        core::arch::asm!(
            "msr CNTV_CTL_EL0, xzr",
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Per-core generic-timer bring-up: puts THIS PE's virtual timer into a
/// known (disarmed) state. `CNTV_*` sysregs are banked per-PE by the
/// architecture — nothing here is shared across cores, or needs to be —
/// this exists so SMP bring-up has one canonical "make this core's timer
/// sane" call, alongside `gic::init_redistributor_at`/`init_cpu_interface`,
/// instead of relying on reset state QEMU and real silicon aren't
/// guaranteed to agree on (a secondary PE woken via PSCI CPU_ON has no
/// architectural guarantee CNTV_CTL_EL0 starts at 0).
#[cfg(target_arch = "aarch64")]
pub fn init_percpu() {
    disarm();
}
#[cfg(not(target_arch = "aarch64"))]
pub fn init_percpu() {}

// ── Host-build stubs ────────────────────────────────────────

#[cfg(not(target_arch = "aarch64"))]
pub fn freq_hz() -> u64 { 0 }
#[cfg(not(target_arch = "aarch64"))]
pub fn counter_hz() -> u64 { 0 }
#[cfg(not(target_arch = "aarch64"))]
pub fn now_ticks() -> u64 { 0 }
#[cfg(not(target_arch = "aarch64"))]
pub fn now_ns() -> u64 { 0 }
#[cfg(not(target_arch = "aarch64"))]
pub fn disarm() {}
