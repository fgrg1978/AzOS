// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! 3D Path Planning — RRT* algorithm (D03).
//!
//! Rapidly-exploring Random Tree with rewiring (RRT*) for UAV 3D path planning.
//! Finds collision-free paths in a 3D voxel grid from start to goal.
//!
//! ## Coordinate frame
//! All coordinates are in mm (NED: X=North, Y=East, Z=-Altitude).
//!
//! ## Limitations (embedded constraints)
//! - Max nodes: `PATH3D_MAX_NODES` (static allocation, no heap).
//! - Voxel grid: `PATH3D_GRID_SIZE`³ occupancy grid.
//! - Path output: up to `PATH3D_MAX_PATH` waypoints.
//!
//! ## Usage
//! Sketch, not a doctest — the names below are unbound, and the crate
//! does not build on the host. `tests/host/flight-tests` is the runnable form.
//! ```text
//! path3d_reset();
//! // Mark obstacles in the occupancy grid:
//! path3d_mark_obstacle(x_mm, y_mm, z_mm);
//! // Find a path:
//! let n = path3d_plan(&start, &goal, &mut path_out);
//! ```

use azos_sync::pi_mutex::PiMutex;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum RRT* tree nodes.
pub const PATH3D_MAX_NODES: usize = 512;
/// Maximum output path waypoints.
pub const PATH3D_MAX_PATH:  usize = 64;
/// Voxel grid resolution per axis.
pub const PATH3D_GRID_SIZE: usize = 32;
/// Physical size of the planning volume per axis (mm).
pub const PATH3D_VOLUME_MM: i32 = 100_000; // 100 m
/// Size of one voxel (mm).
pub const PATH3D_VOXEL_MM:  i32 = PATH3D_VOLUME_MM / PATH3D_GRID_SIZE as i32;
/// RRT* step length (mm) — maximum distance to extend tree per iteration.
pub const PATH3D_STEP_MM:   i32 = 3_000; // 3 m
/// RRT* near-radius for rewiring (mm).
pub const PATH3D_NEAR_MM:   i32 = 8_000; // 8 m
/// RRT* maximum planning iterations.
pub const PATH3D_MAX_ITERS: u32 = 2_000;
/// Goal tolerance (mm) — declare success when within this distance of goal.
pub const PATH3D_GOAL_TOL:  i32 = 2_000; // 2 m

// ── Types ─────────────────────────────────────────────────────────────────────

/// A 3D point in mm (NED).
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Point3D {
    pub x: i32,
    pub y: i32,
    pub z: i32,
}

impl Point3D {
    /// Squared Euclidean distance (mm²).  May overflow for very large distances;
    /// safe for distances < ~46 km.
    pub fn dist_sq(&self, other: &Point3D) -> i64 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        let dz = self.z - other.z;
        dx as i64 * dx as i64 + dy as i64 * dy as i64 + dz as i64 * dz as i64
    }

    /// Approximate Euclidean distance (mm) using integer sqrt.
    pub fn dist(&self, other: &Point3D) -> i32 {
        isqrt64(self.dist_sq(other)) as i32
    }
}

/// One RRT* tree node.
#[derive(Clone, Copy)]
struct RrtNode {
    pos:    Point3D,
    parent: u16,         // index of parent node; u16::MAX = root
    cost:   i32,         // cost from root (mm)
}

const RRTNODE_EMPTY: RrtNode = RrtNode {
    pos: Point3D { x: 0, y: 0, z: 0 },
    parent: u16::MAX,
    cost: 0,
};

// ── Occupancy grid ────────────────────────────────────────────────────────────

/// 3D occupancy grid: 1 bit per voxel, packed into u32 words.
/// Total: 32³ = 32768 voxels = 1024 u32 words = 4 KiB.
const GRID_WORDS: usize = PATH3D_GRID_SIZE * PATH3D_GRID_SIZE * PATH3D_GRID_SIZE / 32;

struct Path3dState {
    grid:      [u32; GRID_WORDS],
    nodes:     [RrtNode; PATH3D_MAX_NODES],
    node_count: u16,
    /// Pseudo-random seed for tree sampling.
    rng:       u32,
}

impl Path3dState {
    const fn new() -> Self {
        Path3dState {
            grid: [0; GRID_WORDS],
            nodes: [RRTNODE_EMPTY; PATH3D_MAX_NODES],
            node_count: 0,
            rng: 0xDEAD_BEEF,
        }
    }
}

/// `PiMutex`, not `SpinLock` — deliberately, after measuring what `path3d_plan`
/// actually costs while the lock is held.
///
/// ## Measured
/// Disassembly of the release RV64 object (`llvm-objdump -dl` on
/// `libazos_flight.rlib`, cgu containing `path3d`) gives real static
/// sizes: `path3d_plan` is 935 instructions / 2940 B; `is_free` (its own
/// non-inlined function, called via `jalr`, NOT inlined) is 213 / 726 B;
/// `Point3D::dist_sq` (also non-inlined) is 47 / 164 B. Per-line source
/// mapping (via embedded debug info) attributes each measured block to a
/// source line, giving real per-call costs: one `is_free` call ≈
/// `138 + 122×(steps+1)` instructions, where `steps` is the Bresenham
/// step count for the segment it checks.
///
/// ## Reasoned from there
/// `path3d_plan`'s outer loop runs until `PATH3D_MAX_NODES` (512) nodes
/// exist — the `if node_count >= PATH3D_MAX_NODES { break; }` guard fires
/// before `PATH3D_MAX_ITERS` (2000) is generally reached, so 512, not 2000,
/// is the binding constant. The dominant cost is the resulting
/// Θ(MAX_NODES²) shape: up to 512 successful iterations, each scanning up
/// to 511 existing nodes twice (best-parent selection, then rewiring) —
/// roughly 262,000 `is_free`-gated loop-body traversals total, not
/// counting the O(N) nearest-neighbour scan repeated for every iteration
/// (including ones that get rejected and never add a node).
///
/// Combining the measured per-call costs with these compile-time bounds
/// gives a worst-case range, not a point estimate, because two things are
/// data-dependent:
///   * **Floor ≈ 85M instructions** (≈ 55–170 ms at 1.5–0.5 GHz, 1 IPC):
///     the best-parent near-radius check (`PATH3D_NEAR_MM` = 8000 mm)
///     usually fails, so its `is_free` call is rarely reached, and the
///     rewire condition (`c < cost`) is rarely true. This does not depend
///     on any adversarial geometry assumption — it is the cost of the
///     O(N) scans alone.
///   * **Ceiling ≈ 2.0 BILLION instructions** (≈ 1.3–4 s at 1.5–0.5 GHz):
///     reached if the tree stays spatially dense enough that the
///     best-parent near-check keeps passing for most existing nodes —
///     plausible for a short local replan boxed in by obstacles, not
///     contrived.
///
/// The analysis above originally carried a second, dominant term: the
/// rewire loop had no near-radius filter, so its `is_free` calls were
/// bounded only by the 100 m volume's diagonal (~173 m, ~110 samples,
/// ≈ 13,700 instructions per call against ≈ 870 for a bounded one) and
/// the ceiling stood at ~24x the floor rather than a small multiple.
/// That was a real bug and it is fixed — the loop now applies the same
/// `PATH3D_NEAR_MM` filter best-parent does. The effect was measured
/// end-to-end rather than estimated: one full plan in open space takes
/// 7,070 voxel samples with the filter and 18,532 without. It is held
/// there by `tests/host/flight-tests`, which counts samples through
/// `IS_FREE_SAMPLES` because the defect is invisible in the returned
/// path — the same 17 waypoints come back either way.
///
/// Either end of that range is minutes, not microseconds, on top of what
/// commit `eeda7c4` made `SpinLock` cost: the *entire* range would run
/// with preemption disabled on the holder's hart. `path3d_plan` has no
/// in-tree caller yet (`kernel/src/main.rs`'s `task_create_affinity`
/// calls never reference it — same as `slam`), so nothing is starved
/// today, but wiring up a planner task on a shared hart with this as a
/// plain `SpinLock` would be a landmine even under the *floor* estimate.
///
/// ## Why `PiMutex` and not the other two options
///   * **Shrinking the locked section** (plan into a local, publish
///     under a short lock) doesn't fit: `Path3dState` is
///     `grid: [u32; 1024]` (4096 B) + `nodes: [RrtNode; 512]` (≈20 B each
///     once padded ≈ 10,240 B) + change ≈ 14.3 KB total, against a kernel
///     stack budget of roughly 12 KiB usable. It doesn't fit as a local;
///     making it fit would mean a second **static** scratch buffer with
///     its own swap protocol — a materially bigger redesign than this
///     finding calls for.
///   * **Planning incrementally, dropping the lock between RRT*
///     iterations,** is the only option that also bounds the *worst
///     case* rather than just making it preemptible — but it requires
///     the shared state to survive being observed mid-plan across a
///     release, and it does not: `path3d_reset()` is a separate public
///     entry point that zeroes `nodes`/`node_count` unconditionally. A
///     concurrent reset between two of `path3d_plan`'s iterations leaves
///     the in-progress `nearest_idx`/`best_parent` (stack-local `u16`
///     indices computed before the reset) pointing at nodes that have
///     since been reinitialized, with no generation counter or version
///     check anywhere to detect it — the algorithm would silently
///     continue building a path off of nodes that no longer mean what it
///     thinks they mean. Not memory-unsafe (the array is fixed-size, so
///     every index stays in bounds), but logically corrupt, and nothing
///     here catches it. Implementing this safely needs that
///     reset-vs-plan invariant added first; that's more than a locking
///     change.
///
/// `PiMutex` sidesteps both: the guard carries no preempt count, so
/// `path3d_plan` keeps running exactly as long as it always did (this
/// commit doesn't make it faster — the floor/ceiling above are unchanged)
/// but a higher-priority task on the same hart is no longer forced to
/// wait for the whole thing. It's also the pattern already applied to
/// `BLK_LOCK`, `KERNEL_FD_TABLE`, `LOG_FILE`, `JPEG_RAW`, and
/// `EXEC_BOUNCE` for the same reason.
///
/// Two `PiMutex` caveats from `pi_mutex.rs` that apply here:
///   * **Never take this from an interrupt handler.** The obvious future
///     caller of `path3d_mark_obstacle` is a LiDAR/depth-sensor ISR;
///     `PiMutex::lock` from IRQ context is unsound (the owner check can
///     see `owner == my_tid` for the interrupted task and decline to
///     donate, and yielding from IRQ context isn't valid either).
///   * **Not recursive.** Nothing here currently re-enters `PATH3D` while
///     holding it — `is_free`/`is_occupied` take an already-borrowed
///     `&Path3dState` rather than re-locking — so this is a constraint to
///     preserve, not a bug to fix.
///
/// ## Untested
/// No test here distinguishes `PiMutex` from `SpinLock`: both give the
/// same `Deref`/`DerefMut` access to `Path3dState` from a single-threaded
/// host test, and the only behavioral difference — whether the holder's
/// hart is preemptible — has no host-observable effect (there is no
/// scheduler on the host, and even in `flight-sim`/`flight-math-tests`
/// there is exactly one thread of execution). Recorded here rather than
/// backed by a test that would pass against either lock type, same as the
/// untested-guard note on `user_leaf_is_task_owned` in
/// `crates/core/mm/src/vmm.rs`.
static PATH3D: PiMutex<Path3dState> = PiMutex::new(Path3dState::new());

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Integer square root (Newton's method, no float).
fn isqrt64(n: i64) -> i64 {
    if n <= 0 { return 0; }
    let mut x = n;
    let mut x1 = (x + 1) / 2;
    while x1 < x {
        x = x1;
        x1 = (x + n / x) / 2;
    }
    x
}

/// Xorshift32 pseudo-random number generator.
fn rng_next(seed: &mut u32) -> u32 {
    let mut x = *seed;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *seed = x;
    x
}

/// Map a world coordinate to a voxel index (clamp to grid bounds).
fn world_to_voxel(v: i32) -> usize {
    let idx = (v + PATH3D_VOLUME_MM / 2) / PATH3D_VOXEL_MM;
    idx.clamp(0, PATH3D_GRID_SIZE as i32 - 1) as usize
}

fn voxel_index(x: usize, y: usize, z: usize) -> (usize, u32) {
    let flat = x * PATH3D_GRID_SIZE * PATH3D_GRID_SIZE + y * PATH3D_GRID_SIZE + z;
    (flat / 32, 1u32 << (flat % 32))
}

fn is_occupied(state: &Path3dState, pt: &Point3D) -> bool {
    let xi = world_to_voxel(pt.x);
    let yi = world_to_voxel(pt.y);
    let zi = world_to_voxel(pt.z);
    let (word, bit) = voxel_index(xi, yi, zi);
    state.grid[word] & bit != 0
}

/// Steer from `a` toward `b` by at most `step_mm`.
fn steer(a: &Point3D, b: &Point3D, step_mm: i32) -> Point3D {
    let d = a.dist(b);
    if d == 0 || d <= step_mm { return *b; }
    Point3D {
        x: a.x + (b.x - a.x) * step_mm / d,
        y: a.y + (b.y - a.y) * step_mm / d,
        z: a.z + (b.z - a.z) * step_mm / d,
    }
}

/// Voxel samples taken by `is_free`, cumulative. Host builds only — under
/// `target_os = "none"` this static and its increment do not exist, so the
/// kernel pays nothing for it.
///
/// This is the planner's real cost. `is_free` samples the line it is given at
/// a fixed spatial interval, so its cost is proportional to the LENGTH of that
/// line, not to the number of nodes: one call over a near-radius edge is 6
/// samples, one over the volume diagonal is 111. A change that leaves the
/// number of `is_free` calls alone can still multiply the work by twenty, and
/// no assertion on the returned path can see it — the returned path is usually
/// identical. Counting samples is the only way to hold that cost to a budget.
#[cfg(not(target_os = "none"))]
pub static IS_FREE_SAMPLES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Check if the straight line from `a` to `b` is collision-free.
/// Samples the line at voxel-resolution intervals.
fn is_free(state: &Path3dState, a: &Point3D, b: &Point3D) -> bool {
    let d = a.dist(b);
    if d == 0 { return true; }
    let steps = (d / (PATH3D_VOXEL_MM / 2)).max(1);
    #[cfg(not(target_os = "none"))]
    IS_FREE_SAMPLES.fetch_add(steps as u64 + 1, core::sync::atomic::Ordering::Relaxed);
    for i in 0..=steps {
        let pt = Point3D {
            x: a.x + (b.x - a.x) * i / steps,
            y: a.y + (b.y - a.y) * i / steps,
            z: a.z + (b.z - a.z) * i / steps,
        };
        if is_occupied(state, &pt) { return false; }
    }
    true
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Clear the occupancy grid and RRT tree.
pub fn path3d_reset() {
    #[cfg(not(target_os = "none"))]
    IS_FREE_SAMPLES.store(0, core::sync::atomic::Ordering::Relaxed);
    let mut s = PATH3D.lock();
    s.grid = [0; GRID_WORDS];
    s.nodes = [RRTNODE_EMPTY; PATH3D_MAX_NODES];
    s.node_count = 0;
}

/// Mark a voxel at world position `(x, y, z)` mm as occupied (obstacle).
pub fn path3d_mark_obstacle(x: i32, y: i32, z: i32) {
    let mut s = PATH3D.lock();
    let xi = world_to_voxel(x);
    let yi = world_to_voxel(y);
    let zi = world_to_voxel(z);
    let (word, bit) = voxel_index(xi, yi, zi);
    s.grid[word] |= bit;
}

/// Plan a path from `start` to `goal` using RRT*.
///
/// Returns the number of waypoints written to `path_out`.
/// Returns 0 if no path was found within `PATH3D_MAX_ITERS`.
pub fn path3d_plan(start: &Point3D, goal: &Point3D, path_out: &mut [Point3D]) -> usize {
    let mut s = PATH3D.lock();
    s.nodes[0] = RrtNode { pos: *start, parent: u16::MAX, cost: 0 };
    s.node_count = 1;

    let mut goal_node: Option<u16> = None;

    for _ in 0..PATH3D_MAX_ITERS {
        if s.node_count as usize >= PATH3D_MAX_NODES { break; }

        // Sample random point (bias toward goal 10% of the time).
        let rand = rng_next(&mut s.rng);
        let q_rand = if rand % 10 == 0 {
            *goal
        } else {
            Point3D {
                x: (rand as i32 % PATH3D_VOLUME_MM) - PATH3D_VOLUME_MM / 2,
                y: ((rng_next(&mut s.rng) as i32) % PATH3D_VOLUME_MM) - PATH3D_VOLUME_MM / 2,
                z: ((rng_next(&mut s.rng) as i32) % PATH3D_VOLUME_MM) - PATH3D_VOLUME_MM / 2,
            }
        };

        // Find nearest node.
        let mut nearest_idx = 0u16;
        let mut nearest_dist = i64::MAX;
        for i in 0..s.node_count as usize {
            let d = s.nodes[i].pos.dist_sq(&q_rand);
            if d < nearest_dist { nearest_dist = d; nearest_idx = i as u16; }
        }

        // Steer toward q_rand.
        let q_new = steer(&s.nodes[nearest_idx as usize].pos, &q_rand, PATH3D_STEP_MM);

        if !is_free(&s, &s.nodes[nearest_idx as usize].pos, &q_new) { continue; }

        // Find near nodes within PATH3D_NEAR_MM.
        let new_cost_base = s.nodes[nearest_idx as usize].cost
            + s.nodes[nearest_idx as usize].pos.dist(&q_new);

        // Choose best parent (minimize cost).
        let mut best_parent = nearest_idx;
        let mut best_cost   = new_cost_base;
        for i in 0..s.node_count as usize {
            if s.nodes[i].pos.dist(&q_new) > PATH3D_NEAR_MM { continue; }
            if !is_free(&s, &s.nodes[i].pos, &q_new) { continue; }
            let c = s.nodes[i].cost + s.nodes[i].pos.dist(&q_new);
            if c < best_cost { best_cost = c; best_parent = i as u16; }
        }

        // Add new node.
        let new_idx = s.node_count;
        s.nodes[new_idx as usize] = RrtNode { pos: q_new, parent: best_parent, cost: best_cost };
        s.node_count += 1;

        // Rewire near nodes through q_new if cheaper.
        //
        // The near-radius filter is the same one best-parent applies above, and
        // it is what makes this loop "rewire *near* nodes". Without it the loop
        // considers every node in the tree, so `is_free` traces lines up to the
        // volume diagonal (173 m) instead of `PATH3D_NEAR_MM` (8 m) — 111 voxel
        // samples per call instead of 6, on a path that runs under a lock.
        // Rewiring a node 100 m away also produces a tree edge 100 m long,
        // which is then emitted as a pair of consecutive waypoints: a segment
        // 33x the step length the planner is supposed to be bounded by.
        for i in 0..new_idx as usize {
            let d = s.nodes[i].pos.dist(&q_new);
            if d > PATH3D_NEAR_MM { continue; }
            let c = best_cost + d;
            if c < s.nodes[i].cost && is_free(&s, &q_new, &s.nodes[i].pos) {
                s.nodes[i].parent = new_idx;
                s.nodes[i].cost   = c;
            }
        }

        // Check if we reached the goal.
        if q_new.dist(goal) <= PATH3D_GOAL_TOL {
            match goal_node {
                None    => goal_node = Some(new_idx),
                Some(g) => {
                    if best_cost < s.nodes[g as usize].cost {
                        goal_node = Some(new_idx);
                    }
                }
            }
        }
    }

    // Extract path by tracing back from goal node.
    let goal_idx = match goal_node { Some(g) => g, None => return 0 };

    let mut path_rev = [Point3D::default(); PATH3D_MAX_PATH];
    let mut path_len = 0usize;
    let mut idx = goal_idx;
    loop {
        if path_len >= PATH3D_MAX_PATH { break; }
        path_rev[path_len] = s.nodes[idx as usize].pos;
        path_len += 1;
        let parent = s.nodes[idx as usize].parent;
        if parent == u16::MAX { break; }
        idx = parent;
    }

    // Reverse into output buffer.
    let out_len = path_len.min(path_out.len());
    for i in 0..out_len {
        path_out[i] = path_rev[path_len - 1 - i];
    }
    out_len
}
