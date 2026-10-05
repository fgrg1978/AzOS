// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Generic timer convenience API.
//!
//! Wraps the CNTV_* / CNTFRQ_EL0 / CNTVCT_EL0 sysregs that
//! the existing `sysregs.rs` helpers expose into a friendlier
//! ns / µs / Hz API so callers don't have to keep multiplying
//! by `read_cntfrq_el0()`.
//!
//! Used today by `aarch64-hello`'s B1.gic.timer demo (inline), and by
//! `entry::aarch64::boot_hooks` for `freq_hz()` (period
//! computation for the periodic tick). The kernel's own scheduler-tick
//! deadline (`ARCH.set_timer_deadline`, `arm_periodic_timer`) goes through
//! `azos_arch_api::Cpu`/`Interrupts` (`api_impl::Aarch64`), which calls
//! `sysregs::write_cntv_cval_el0` directly rather than through this
//! module's own `ns`/`us` wrappers — this module is a convenience API used
//! by some callers, not the kernel's only path to the timer.

#![allow(dead_code)]

#[cfg(target_arch = "aarch64")]
use crate::sysregs;

const NS_PER_S: u64 = 1_000_000_000;
const NS_PER_US: u64 = 1_000;

/// Read the generic-timer counter frequency. Architecturally
/// fixed for the platform — typically 50 MHz on QEMU virt,
/// 19.2 MHz on most ARM SoCs. The value comes from CNTFRQ_EL0
/// (set by EL3 firmware at boot; kernel just reads).
#[cfg(target_arch = "aarch64")]
pub fn freq_hz() -> u64 {
    sysregs::read_cntfrq_el0()
}

/// Read the current count (CNTVCT_EL0, the virtual count — see
/// [`sysregs::read_cntvct_el0`] for why the kernel is virtual-only). Monotonic, wraps in
/// `2^64 / freq_hz` seconds (centuries at MHz frequencies).
#[cfg(target_arch = "aarch64")]
pub fn now_ticks() -> u64 {
    sysregs::read_cntvct_el0()
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

/// Arm the virtual timer to fire `ns_from_now` nanoseconds in
/// the future. Programs CNTV_CVAL_EL0 with `now_ticks + Δticks`
/// and ENs the timer via CNTV_CTL_EL0.
///
/// Fires on PPI 27 ([`crate::gic::PPI_VIRT_TIMER`]); the kernel's GIC handler dispatches it.
/// Re-arming overwrites the previous deadline.
#[cfg(target_arch = "aarch64")]
pub fn arm_deadline_ns(ns_from_now: u64) {
    let hz = freq_hz();
    let ticks = if hz == 0 {
        ns_from_now
    } else {
        // ns * hz / 1_000_000_000 — same split trick as now_ns.
        let secs = ns_from_now / NS_PER_S;
        let rem  = ns_from_now % NS_PER_S;
        secs * hz + (rem * hz) / NS_PER_S
    };
    let deadline = now_ticks().wrapping_add(ticks);
    sysregs::write_cntv_cval_el0(deadline);
    sysregs::enable_virt_timer();
}

/// Same as [`arm_deadline_ns`] but takes microseconds — saves
/// the caller a `* 1000` for the common scheduler-tick case.
#[cfg(target_arch = "aarch64")]
pub fn arm_deadline_us(us_from_now: u64) {
    arm_deadline_ns(us_from_now.saturating_mul(NS_PER_US))
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
pub fn now_ticks() -> u64 { 0 }
#[cfg(not(target_arch = "aarch64"))]
pub fn now_ns() -> u64 { 0 }
#[cfg(not(target_arch = "aarch64"))]
pub fn arm_deadline_ns(_ns: u64) {}
#[cfg(not(target_arch = "aarch64"))]
pub fn arm_deadline_us(_us: u64) {}
#[cfg(not(target_arch = "aarch64"))]
pub fn disarm() {}
