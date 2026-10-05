// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Simulated wheel encoders — Phase 17 + G2.
//!
//! Accumulates signed ticks proportional to motor speed × call count.
//! Called once per `rt_motor_task` scheduler iteration.
//!
//! Physical constants (simulated QEMU robot):
//! - `TICKS_PER_M`  = 1 000  — encoder pulses per simulated metre.
//! - `WHEEL_BASE_MM`= 200 mm — distance between the two wheels.
//!
//! Phase G2: ticks_per_m / wheel_base_mm are now configurable at runtime
//! via `set_ticks_per_m()` / `set_wheel_base_mm()`.  The `const` values
//! remain for backward compatibility.
//!
//! Gated on `target_pointer_width = "64"` because `AtomicI64` is not
//! lock-free on RV32.

use core::sync::atomic::{AtomicU32, Ordering};

/// Encoder ticks per simulated metre of travel (compile-time default).
pub const TICKS_PER_M: i64 = 1_000;

/// Distance between wheels in millimetres (compile-time default).
pub const WHEEL_BASE_MM: i64 = 200;

// Phase G2: runtime-configurable values (initialised from config atomics).
static RT_TICKS_PER_M:  AtomicU32 = AtomicU32::new(1000);
static RT_WHEEL_BASE_MM: AtomicU32 = AtomicU32::new(200);

/// Get runtime ticks-per-metre value.
pub fn ticks_per_m() -> i64 {
    RT_TICKS_PER_M.load(Ordering::Relaxed) as i64
}

/// Set runtime ticks-per-metre value.
pub fn set_ticks_per_m(v: u32) {
    if v > 0 { RT_TICKS_PER_M.store(v, Ordering::Relaxed); }
}

/// Get runtime wheel-base in millimetres.
pub fn wheel_base_mm() -> i64 {
    RT_WHEEL_BASE_MM.load(Ordering::Relaxed) as i64
}

/// Set runtime wheel-base in millimetres.
pub fn set_wheel_base_mm(v: u32) {
    if v > 0 { RT_WHEEL_BASE_MM.store(v, Ordering::Relaxed); }
}

#[cfg(target_pointer_width = "64")]
mod inner {
    use core::sync::atomic::{AtomicI64, Ordering};

    static TICKS_L: AtomicI64 = AtomicI64::new(0);
    static TICKS_R: AtomicI64 = AtomicI64::new(0);

    pub fn encoder_tick(speed_l: i32, speed_r: i32) {
        TICKS_L.fetch_add(speed_l as i64, Ordering::Relaxed);
        TICKS_R.fetch_add(speed_r as i64, Ordering::Relaxed);
    }

    pub fn encoder_read() -> (i64, i64) {
        (TICKS_L.load(Ordering::Relaxed), TICKS_R.load(Ordering::Relaxed))
    }

    /// [`encoder_read`] and its acquisition time: reading the counters IS the
    /// measurement (a quadrature counter is read, not polled for news), so
    /// the stamp is the timebase counter right after the two loads.
    pub fn encoder_read_stamped() -> ((i64, i64), u64) {
        let v = encoder_read();
        (v, azos_drv_sys::timebase::now())
    }

    pub fn encoder_reset() {
        TICKS_L.store(0, Ordering::Relaxed);
        TICKS_R.store(0, Ordering::Relaxed);
    }
}

#[cfg(target_pointer_width = "64")]
pub use inner::{encoder_tick, encoder_read, encoder_read_stamped, encoder_reset};

// RV32 stubs — encoder not available (AtomicI64 not lock-free).
#[cfg(target_pointer_width = "32")]
pub fn encoder_tick(_speed_l: i32, _speed_r: i32) {}
#[cfg(target_pointer_width = "32")]
pub fn encoder_read() -> (i64, i64) { (0, 0) }
#[cfg(target_pointer_width = "32")]
pub fn encoder_read_stamped() -> ((i64, i64), u64) { ((0, 0), 0) }
#[cfg(target_pointer_width = "32")]
pub fn encoder_reset() {}
