// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Dead-reckoning odometry — Phase 17 + G2.
//!
//! Phase G2: uses `encoder::ticks_per_m()` / `encoder::wheel_base_mm()`
//! runtime getters instead of compile-time constants.
//!
//! Gated on `target_pointer_width = "64"`: the RV32 build carries stubs.

#[cfg(target_pointer_width = "64")]
mod inner {
    use azos_rings::{Log, Writer};
    use azos_sync::SpinLock;
    use crate::encoder;

    /// The whole estimate, published as one item: a reader never pairs a
    /// distance with another update's heading or time.
    #[derive(Clone, Copy)]
    struct Odom {
        dist_mm: i64,
        heading_cdeg: i64,
        prev_l: i64,
        prev_r: i64,
        /// Timebase ticks when the encoder counts behind the current estimate
        /// were read (`odom_update_at`'s `acq`); 0 = never updated with one.
        acq: u64,
    }

    const ZERO: Odom = Odom { dist_mm: 0, heading_cdeg: 0, prev_l: 0, prev_r: 0, acq: 0 };

    static STATE: Log<Odom, 1> = Log::new(ZERO);

    /// `STATE`'s one writer, taken on the first update. The lock also makes
    /// each update's read-modify-publish whole; it masks preemption for it.
    static TX: SpinLock<Option<Writer<'static, Odom, 1>>> = SpinLock::new(None);

    fn update(f: impl FnOnce(Odom) -> Odom) {
        let mut tx = TX.lock();
        let w = tx.get_or_insert_with(|| STATE.writer().expect("odom: second writer"));
        w.publish(f(STATE.latest().1));
    }

    /// [`odom_update`] from encoder counts read at timebase tick `acq`. The
    /// estimate's acquisition time is then the counts', published with the
    /// distance and heading it stamps.
    pub fn odom_update_at(ticks_l: i64, ticks_r: i64, acq: u64) {
        update(|o| Odom { acq, ..step(o, ticks_l, ticks_r) });
    }

    /// [`odom_get`] and the acquisition time of the counts it integrates
    /// (0 = never stamped).
    pub fn odom_get_stamped() -> ((i64, i64), u64) {
        let o = STATE.latest().1;
        ((o.dist_mm, o.heading_cdeg), o.acq)
    }

    pub fn odom_update(ticks_l: i64, ticks_r: i64) {
        update(|o| step(o, ticks_l, ticks_r));
    }

    fn step(o: Odom, ticks_l: i64, ticks_r: i64) -> Odom {
        let dl = ticks_l - o.prev_l;
        let dr = ticks_r - o.prev_r;

        let tpm = encoder::ticks_per_m();
        let wb  = encoder::wheel_base_mm();

        let dist_delta = (dl + dr) * 1_000 / (2 * tpm);
        let head_delta = ((dr - dl) as i128 * 36_000_000
            / (tpm as i128 * wb as i128)) as i64;

        Odom {
            dist_mm: o.dist_mm + dist_delta,
            heading_cdeg: o.heading_cdeg + head_delta,
            prev_l: ticks_l,
            prev_r: ticks_r,
            acq: o.acq,
        }
    }

    pub fn odom_get() -> (i64, i64) {
        odom_get_stamped().0
    }

    pub fn odom_reset() {
        update(|_| ZERO);
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
