// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Beam-count bound shared between the kernel `flight` crate's SLAM update
//! and its host tests.
//!
//! `slam_update_scan` (`domains/robot/flight/src/slam.rs`) takes caller-supplied
//! `ranges`/`angles_cdeg` slices with no static bound on their length —
//! unlike the sibling `nav` crate's 2D scan matcher, whose `Scan2D` caps
//! beam count at the *type* level (`SCAN_MAX_POINTS: usize = 360`, baked
//! into a fixed-size array field). A caller passing an oversized scan (a
//! buggy driver, or one LiDAR firmware's "high density" mode) would make
//! `slam_update_scan`'s per-beam Bresenham ray-cast loop run unbounded
//! while it holds `SLAM`'s lock — a bound that lives only in the caller is
//! not a bound.
//!
//! This lives in `flight-math` rather than directly in `domains/robot/flight`
//! because `domains/robot/flight` pulls in `azos_drv_*` and is not
//! host-buildable (see the crate-level doc comment), so a cap enforced
//! only there could never be exercised by a host test — mutating it would
//! be invisible to `cargo test`. `flight-math` has zero kernel
//! dependencies and is already the shared home for exactly this class of
//! logic (D04 trig/wind), so `slam_update_scan` calls [`cap_scan`]
//! directly: the function under test in `flight-math-tests` is the same
//! code that runs in the kernel, not a mirror of it.

/// Maximum LiDAR/rangefinder beams processed per `slam_update_scan` call.
///
/// Matches `azos_nav::SCAN_MAX_POINTS` (360): a full-rotation 2D LiDAR
/// at 1° angular resolution, the same resolution nav's own scan matcher
/// already assumes. There is no in-tree LiDAR driver yet — `slam_update_scan`
/// has no caller in the tree today, same as `path3d_plan` — so this is the
/// same design point as the sibling subsystem rather than a measured
/// worst case.
///
/// It bounds the total ray-casting work `slam_update_scan` can do per call:
/// 360 beams, each ray-cast across at most `SLAM_MAX_RANGE_MM / SLAM_CELL_MM`
/// = 8000 / 100 = 80 grid cells (the Bresenham step count for a
/// maximum-range beam) — at most 28,800 cell visits while `SLAM`'s lock is
/// held, regardless of what a caller passes in.
pub const SLAM_MAX_BEAMS: usize = 360;

/// Cap a caller-supplied scan to at most [`SLAM_MAX_BEAMS`] beams.
///
/// Returns `(ranges, angles_cdeg)` slices of equal length: the shorter of
/// the two inputs, further capped to `SLAM_MAX_BEAMS`. Returning the
/// trimmed slices themselves (rather than just a length for the caller to
/// re-derive) means the caller's per-beam loop can only ever see a
/// beam count that has already gone through this cap — there is no
/// call-site length expression left to accidentally revert to the
/// uncapped `ranges.len().min(angles_cdeg.len())`.
pub fn cap_scan<'a>(ranges: &'a [u16], angles_cdeg: &'a [i32]) -> (&'a [u16], &'a [i32]) {
    let n = ranges.len().min(angles_cdeg.len()).min(SLAM_MAX_BEAMS);
    (&ranges[..n], &angles_cdeg[..n])
}
