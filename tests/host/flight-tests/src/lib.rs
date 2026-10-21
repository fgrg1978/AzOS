// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the 3D RRT* path planner.
//!
//! `domains/robot/flight` as a whole does not build on the host — it pulls in AHRS,
//! GPS and the driver layer — so the module under test is pulled in with
//! `#[path]` and compiled unmodified against a shim for its single external
//! dependency. The code exercised here is the code that ships.
//!
//! ## Why the tests live in one function
//!
//! The planner keeps its tree and its occupancy grid in a `static`, and the
//! RNG seed in that same static is *not* cleared by `path3d_reset`. Two
//! `#[test]` functions would run on separate threads against one shared tree
//! and one shared RNG, so each would see a starting state that depends on how
//! far the other had got — the same shared-table pollution that has broken
//! tests in this tree before. A single sequential test is deterministic.

#[path = "../../../../domains/robot/flight/src/path3d.rs"]
pub mod path3d;

/// The failsafe chain, compiled unmodified — it names no external crate.
///
/// It had no test at all until 2026-09-06: `check_failsafe` and
/// `FailsafeAction` appear nowhere in the tree except `domains/robot/flight/src` and
/// one kernel call site, so nothing exercised the failsafe logic of a flying
/// machine on the host or in QEMU.
#[path = "../../../../domains/robot/flight/src/failsafe.rs"]
pub mod failsafe;

/// The PID controller, compiled unmodified — it names no external crate,
/// which is what makes it the ONE piece of `domains/robot/flight/src/lib.rs` this
/// crate can pull in directly (see that file's own doc for why the whole
/// module cannot be).
#[path = "../../../../domains/robot/flight/src/pid.rs"]
pub mod pid;

#[cfg(test)]
mod failsafe_tests {
    use super::failsafe::*;

    const MS: u64 = 1_000;

    #[test]
    fn every_arm_of_the_priority_chain_is_reachable() {
        // Without this, a chain whose later arms are shadowed by an earlier
        // one reads as correct: each individual assertion below would still
        // pass if written alone against a function that always returned it.
        assert!(check_failsafe(0, 0, 0) == FailsafeAction::None);
        assert!(check_failsafe(0, 2_000 * MS, 0) == FailsafeAction::RTL);
        assert!(check_failsafe(0, 0, 4_000 * MS) == FailsafeAction::PosHold);
        assert!(check_failsafe(100 * MS, 0, 0) == FailsafeAction::Land);
    }

    #[test]
    fn attitude_loss_outranks_rc_loss_and_server_loss() {
        // Priority, not just detection: all three conditions true at once must
        // give the most severe answer, because acting on the mildest while the
        // attitude estimate is gone is how a drone flies a level-hold with no
        // idea which way is up.
        assert!(check_failsafe(100 * MS, 2_000 * MS, 4_000 * MS) == FailsafeAction::Land);
        assert!(check_failsafe(0, 2_000 * MS, 4_000 * MS) == FailsafeAction::RTL);
    }

    #[test]
    fn the_thresholds_are_exclusive_at_the_boundary() {
        // 50 ms / 1 s / 3 s, and `>` not `>=`. Pinned because an off-by-one
        // here is the difference between a failsafe that fires on a single
        // late sample and one that never fires at all.
        assert!(check_failsafe(50_000, 0, 0) == FailsafeAction::None);
        assert!(check_failsafe(50_001, 0, 0) == FailsafeAction::Land);
        assert!(check_failsafe(0, 1_000_000, 0) == FailsafeAction::None);
        assert!(check_failsafe(0, 1_000_001, 0) == FailsafeAction::RTL);
        assert!(check_failsafe(0, 0, 3_000_000) == FailsafeAction::None);
        assert!(check_failsafe(0, 0, 3_000_001) == FailsafeAction::PosHold);
    }

    #[test]
    fn a_failsafe_frame_is_not_fresh_rc_input() {
        // The decision that makes the RTL arm above reachable at all. The
        // flight task published EVERY frame the receiver returned, including
        // ones flagged as failsafe — which refreshed the channel, so the age
        // never grew and RTL could not fire, while those same sticks were what
        // Stabilize flew on.
        assert!(!rc_frame_is_fresh_input(true), "a failsafe frame must not refresh the channel");
    }

    #[test]
    fn a_good_frame_still_is_fresh_rc_input() {
        // The negative half. Without it, `rc_frame_is_fresh_input` could
        // return false unconditionally — the RC link would age out one second
        // after arming and the aircraft would RTL on a perfectly good link.
        assert!(rc_frame_is_fresh_input(false));
    }
}

#[cfg(test)]
mod tests {
    use super::path3d::*;
    use core::sync::atomic::Ordering;

    fn samples() -> u64 { IS_FREE_SAMPLES.load(Ordering::Relaxed) }

    const START: Point3D = Point3D { x: -30_000, y: 0, z: 0 };
    const GOAL:  Point3D = Point3D { x:  30_000, y: 0, z: 0 };

    /// A wall in the x=0 plane, optionally with a square hole centred on
    /// `(gap_y, gap_z)` mm and `HALF` mm to each side.
    fn build_wall(gap: Option<(i32, i32)>) {
        const HALF: i32 = 20000;
        for y in -48..=48 {
            for z in -48..=48 {
                let (wy, wz) = (y * 1_000, z * 1_000);
                if let Some((gy, gz)) = gap {
                    if (wy - gy).abs() <= HALF && (wz - gz).abs() <= HALF { continue; }
                }
                path3d_mark_obstacle(0, wy, wz);
            }
        }
    }

    #[test]
    fn the_planner_holds_its_invariants() {
        let mut path = [Point3D::default(); PATH3D_MAX_PATH];

        // ── Phase 1: cost ──────────────────────────────────────────────────
        //
        // `path3d_plan` runs with `PATH3D` held, so its cost is a blocking
        // time for every other task that wants the planner. The budget is
        // asserted rather than merely recorded because this cost is invisible
        // in the result: dropping the rewire loop's near-radius filter raises
        // it 2.6x here and returns *the same path*, so no assertion on
        // `path_out` would notice.
        //
        // `is_free` samples the line it is given at `PATH3D_VOXEL_MM / 2`
        // intervals, so its cost is proportional to that line's LENGTH, not to
        // the number of nodes. Bounding rewiring to `PATH3D_NEAR_MM` (8 m)
        // bounds one call to 6 samples; unbounded, the same call can span the
        // volume diagonal (173 m) and take 111.
        //
        // Measured 2026-09-05: 7,070 with the filter, 18,532 without. The
        // budget sits between them with headroom, and the run is fully
        // deterministic — one thread, one fixed seed — so the headroom is for
        // deliberate change, not for noise.
        path3d_reset();
        let n = path3d_plan(&START, &GOAL, &mut path);
        let open_cost = samples();
        assert!(n >= 2, "planner found no path in empty space (n={n})");

        const OPEN_SPACE_SAMPLE_BUDGET: u64 = 10_000;
        assert!(
            open_cost <= OPEN_SPACE_SAMPLE_BUDGET,
            "planning in open space took {open_cost} voxel samples, budget is \
             {OPEN_SPACE_SAMPLE_BUDGET}. `is_free` cost is proportional to the \
             length of the line it is asked about, so this grows when a loop \
             stops bounding those lines — check the rewire loop's near-radius \
             filter."
        );

        // ── Phase 2: the grid is actually consulted ────────────────────────
        //
        // A sealed wall between start and goal must make the planner fail.
        // Without this the two phases below prove nothing: a planner that
        // ignored the occupancy grid entirely would satisfy them both.
        path3d_reset();
        build_wall(None);
        let n = path3d_plan(&START, &GOAL, &mut path);
        assert!(
            n == 0,
            "a sealed wall stands between start and goal, yet the planner \
             returned a {n}-waypoint path through it"
        );

        // ── Phase 3: it routes, rather than flying straight ────────────────
        //
        // Same wall with one hole, deliberately off the start–goal axis: a
        // straight line from start to goal hits the wall, so a returned path
        // is evidence of routing and not of the obstacle being missed.
        //
        // The hole is 40 m across, which is far larger than it ought to need
        // to be, and that is a finding rather than a tuning choice. Holes of
        // 10, 16, 20, 24 and 30 m were all tried at several offsets and the
        // planner failed to find any path through them. With 512 nodes spread
        // over a 100 m cube and no bias towards the aperture, it does not
        // sample the gap often enough to grow a branch through it. Nothing
        // here is wrong — RRT* is probabilistically complete, not complete —
        // but a planner that needs a 40 m doorway is not one to hand a real
        // vehicle, and the number is written down so the next person does not
        // have to rediscover it. Raising `PATH3D_MAX_NODES` or biasing the
        // sampler towards frontier voxels is the fix; neither is in scope
        // here, and either would move this constant.
        path3d_reset();
        build_wall(Some((20000, 0)));
        let n = path3d_plan(&START, &GOAL, &mut path);

        assert!(n >= 2, "planner found no path through the off-axis gap (n={n})");
        assert!(path[0] == START, "path does not start at the start point");
        assert!(
            path[n - 1].dist(&GOAL) <= PATH3D_GOAL_TOL,
            "path ends {} mm from the goal, tolerance is {}",
            path[n - 1].dist(&GOAL), PATH3D_GOAL_TOL,
        );

        // Consecutive waypoints are a child and its parent — the extractor
        // walks the parent chain — so the returned path exposes the tree's
        // edges without a test-only accessor into the planner's state. A
        // zero-length edge is the degenerate case in which "cost strictly
        // decreases towards the root" stops being strict, and that property is
        // what keeps the parent chain from closing on itself.
        for i in 1..n {
            assert!(
                path[i - 1] != path[i],
                "waypoints {} and {} are the same point", i - 1, i
            );
        }
    }
}

#[cfg(test)]
mod pid_tests {
    use super::pid::Pid;

    /// **RED before the fix** (reproduced by putting `Pid::update`'s D-term
    /// line back to `((error - self.prev_error) as i64 * ...)`, subtracting
    /// in `i32` before widening): `pid.update(i32::MAX, 1000)` right after
    /// `pid.update(i32::MIN, 1000)` panicked — `attempt to subtract with
    /// overflow` — under this crate's default (debug) profile, which is the
    /// same `overflow_checks` setting the kernel's own release profile turns
    /// on deliberately. See the agent report for the exact captured output.
    ///
    /// Unreachable from the MPU-6050 driver (i16-derived accel/gyro can
    /// never produce an `error` anywhere near `i32::{MIN,MAX}`), reachable
    /// from SITL, which is exactly why this needed a host test rather than
    /// a QEMU one: nothing on a real board can drive this input.
    #[test]
    fn a_toxic_gyro_sample_does_not_overflow_the_d_term() {
        let mut pid = Pid::new(1000, 0, 1000, i32::MIN, i32::MAX);
        // First call establishes `prev_error = i32::MIN`.
        let _ = pid.update(i32::MIN, 1000);
        // Second call: `error - prev_error` = `i32::MAX - i32::MIN`, which
        // overflows `i32` by a factor of ~2 — the exact class this fix
        // closes. Must not panic, and the clamp must still hold.
        let out = pid.update(i32::MAX, 1000);
        assert!(out >= i32::MIN && out <= i32::MAX);
    }

    /// The ordinary case still behaves like a PID: a fixed positive error
    /// produces a fixed positive output (D term settles to 0 once `error`
    /// stops changing between calls).
    #[test]
    fn a_steady_error_produces_a_steady_positive_output() {
        let mut pid = Pid::new(1000, 0, 0, -1000, 1000);
        let out = pid.update(500, 1000);
        assert!(out > 0, "a positive error must produce a positive output, got {out}");
    }
}
