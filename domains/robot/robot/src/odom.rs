// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Dead-reckoning odometry — Phase 17 + G2.
//!
//! Phase G2: uses `encoder::ticks_per_m()` / `encoder::wheel_base_mm()`
//! runtime getters instead of compile-time constants.
//!
//! Gated on `target_pointer_width = "64"` because `AtomicI64` is not
//! lock-free on RV32.

#[cfg(target_pointer_width = "64")]
mod inner {
    use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};
    use crate::encoder;

    static DIST_MM:      AtomicI64 = AtomicI64::new(0);
    static HEADING_CDEG: AtomicI64 = AtomicI64::new(0);
    static PREV_L:       AtomicI64 = AtomicI64::new(0);
    static PREV_R:       AtomicI64 = AtomicI64::new(0);
    /// Timebase ticks when the encoder counts behind the current estimate
    /// were read (`odom_update_at`'s `acq`); 0 = never updated with one.
    static ACQ:          AtomicU64 = AtomicU64::new(0);

    /// [`odom_update`] from encoder counts read at timebase tick `acq`. The
    /// estimate's acquisition time is then the counts' — stored after the
    /// estimate, so a reader that loads it first never sees it younger than
    /// the distance and heading it reads.
    pub fn odom_update_at(ticks_l: i64, ticks_r: i64, acq: u64) {
        odom_update(ticks_l, ticks_r);
        ACQ.store(acq, Ordering::Release);
    }

    /// [`odom_get`] and the acquisition time of the counts it integrates
    /// (0 = never stamped).
    pub fn odom_get_stamped() -> ((i64, i64), u64) {
        let acq = ACQ.load(Ordering::Acquire);
        (odom_get(), acq)
    }

    pub fn odom_update(ticks_l: i64, ticks_r: i64) {
        let prev_l = PREV_L.load(Ordering::Relaxed);
        let prev_r = PREV_R.load(Ordering::Relaxed);
        let dl = ticks_l - prev_l;
        let dr = ticks_r - prev_r;
        PREV_L.store(ticks_l, Ordering::Relaxed);
        PREV_R.store(ticks_r, Ordering::Relaxed);

        let tpm = encoder::ticks_per_m();
        let wb  = encoder::wheel_base_mm();

        let dist_delta = (dl + dr) * 1_000 / (2 * tpm);
        let head_delta = ((dr - dl) as i128 * 36_000_000
            / (tpm as i128 * wb as i128)) as i64;

        DIST_MM.fetch_add(dist_delta, Ordering::Relaxed);
        HEADING_CDEG.fetch_add(head_delta, Ordering::Relaxed);
    }

    pub fn odom_get() -> (i64, i64) {
        (DIST_MM.load(Ordering::Relaxed), HEADING_CDEG.load(Ordering::Relaxed))
    }

    pub fn odom_reset() {
        DIST_MM.store(0, Ordering::Relaxed);
        HEADING_CDEG.store(0, Ordering::Relaxed);
        PREV_L.store(0, Ordering::Relaxed);
        PREV_R.store(0, Ordering::Relaxed);
        ACQ.store(0, Ordering::Relaxed);
    }
}

#[cfg(target_pointer_width = "64")]
pub use inner::{odom_update, odom_update_at, odom_get, odom_get_stamped, odom_reset};

// RV32 stubs
#[cfg(target_pointer_width = "32")]
pub fn odom_update(_ticks_l: i64, _ticks_r: i64) {}
#[cfg(target_pointer_width = "32")]
pub fn odom_get() -> (i64, i64) { (0, 0) }
#[cfg(target_pointer_width = "32")]
pub fn odom_update_at(_ticks_l: i64, _ticks_r: i64, _acq: u64) {}
#[cfg(target_pointer_width = "32")]
pub fn odom_get_stamped() -> ((i64, i64), u64) { ((0, 0), 0) }
#[cfg(target_pointer_width = "32")]
pub fn odom_reset() {}
