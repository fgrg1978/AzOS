// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Trajectory ring buffer — Phase 17.
//!
//! Records up to `TRAJ_CAP` trajectory points.  When the buffer is full,
//! the oldest entry is silently overwritten.
//!
//! Thread-safe via `azos_sync::SpinLock`.
//!
//! # API
//!
//! - [`traj_record`]   — append one point.
//! - [`traj_len`]      — current number of points.
//! - [`traj_get`]      — retrieve by position (0 = oldest).
//! - [`traj_reset`]    — clear the ring.

use azos_sync::SpinLock;

/// Maximum number of trajectory points stored in the ring buffer.
pub const TRAJ_CAP: usize = 256;

/// One trajectory sample.
#[derive(Copy, Clone)]
pub struct TrajPoint {
    /// CLINT time in milliseconds at the moment of recording.
    pub timestamp_ms: u64,
    /// Left  motor speed at this step (−100 .. 100).
    pub speed_l:      i32,
    /// Right motor speed at this step (−100 .. 100).
    pub speed_r:      i32,
    /// ML class chosen at this step (0 = forward, 1 = right, 2 = stop).
    pub ml_class:     u8,
    /// Odometry: total path length in mm at this step.
    pub dist_mm:      i64,
    /// Odometry: cumulative heading change in centidegrees at this step.
    pub heading_cdeg: i64,
}

const ZERO_POINT: TrajPoint = TrajPoint {
    timestamp_ms: 0, speed_l: 0, speed_r: 0,
    ml_class: 0, dist_mm: 0, heading_cdeg: 0,
};

struct TrajBuf {
    buf:   [TrajPoint; TRAJ_CAP],
    head:  usize,
    count: usize,
}

impl TrajBuf {
    const fn new() -> Self {
        Self { buf: [ZERO_POINT; TRAJ_CAP], head: 0, count: 0 }
    }
}

static TRAJ: SpinLock<TrajBuf> = SpinLock::new(TrajBuf::new());

/// Append one trajectory point to the ring buffer.
///
/// If the buffer is full, the oldest entry is overwritten.
pub fn traj_record(ts_ms: u64, speed_l: i32, speed_r: i32,
                   ml_class: u8, dist_mm: i64, heading_cdeg: i64) {
    let mut g = TRAJ.lock();
    let idx = (g.head + g.count) % TRAJ_CAP;
    g.buf[idx] = TrajPoint { timestamp_ms: ts_ms, speed_l, speed_r,
                              ml_class, dist_mm, heading_cdeg };
    if g.count < TRAJ_CAP {
        g.count += 1;
    } else {
        g.head = (g.head + 1) % TRAJ_CAP; // overwrite oldest
    }
}

/// Returns the current number of recorded points.
pub fn traj_len() -> usize {
    TRAJ.lock().count
}

/// Retrieve the point at position `pos` (0 = oldest).
///
/// Returns `None` if `pos >= traj_len()`.
pub fn traj_get(pos: usize) -> Option<TrajPoint> {
    let g = TRAJ.lock();
    if pos >= g.count { return None; }
    Some(g.buf[(g.head + pos) % TRAJ_CAP])
}

/// Clear the ring buffer.
pub fn traj_reset() {
    let mut g = TRAJ.lock();
    g.head  = 0;
    g.count = 0;
}
