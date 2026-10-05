// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! 2D SLAM — Occupancy Grid with Rangefinder Ray Casting (D06).
//!
//! Implements a grid-based SLAM (Simultaneous Localization and Mapping)
//! suitable for indoor robots using a 2D LiDAR or multi-rangefinder array.
//!
//! ## Algorithm
//! - **Map**: 2D occupancy grid stored as log-odds probabilities (i8, scaled).
//! - **Update**: inverse sensor model — ray casting from robot pose to each
//!   rangefinder reading.  Free cells along the ray are decremented; the
//!   hit cell is incremented.
//! - **Pose tracking**: dead-reckoning from odometry; no loop closure in this
//!   phase (future: ICP or particle filter).
//!
//! ## Map resolution
//! Each cell = `SLAM_CELL_MM` mm².  Map covers `SLAM_GRID × SLAM_GRID` cells
//! centred at the initial robot position.
//!
//! ## Log-odds encoding
//! Values stored as i8 log-odds × 10 (range −128 to +127):
//! - `0`   = unknown.
//! - `> 0` = occupied (higher = more certain).
//! - `< 0` = free (more negative = more certain).

use core::sync::atomic::{AtomicI32, AtomicI64, Ordering};
use azos_sync::SpinLock;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Grid side length (cells per axis).
pub const SLAM_GRID:      usize = 256;
/// Cell size (mm).
pub const SLAM_CELL_MM:   i32   = 100; // 10 cm per cell
/// Total map extent (mm per axis).
pub const SLAM_EXTENT_MM: i32   = SLAM_GRID as i32 * SLAM_CELL_MM;
/// Log-odds increment for a hit measurement (× 10, i.e. 0.5 nats scaled).
const SLAM_L_HIT:   i8 = 20;
/// Log-odds decrement for a free measurement along the ray.
const SLAM_L_FREE:  i8 = -5;
/// Log-odds clamp (prevents saturation from too many observations).
const SLAM_L_MAX:   i8 = 100;
const SLAM_L_MIN:   i8 = -100;
/// Minimum range reading to include in the map update (mm).
const SLAM_MIN_RANGE_MM: i32 = 50;
/// Maximum range reading (beyond this is treated as "no obstacle").
const SLAM_MAX_RANGE_MM: i32 = 8_000;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Robot 2D pose.
#[derive(Clone, Copy, Default)]
pub struct Pose2D {
    /// X position in mm (East).
    pub x_mm: i32,
    /// Y position in mm (North).
    pub y_mm: i32,
    /// Heading in centi-degrees (0 = North, 9000 = East).
    pub heading_cdeg: i32,
}

// ── State ─────────────────────────────────────────────────────────────────────

struct SlamState {
    /// Log-odds grid: positive = occupied, negative = free.
    grid: [[i8; SLAM_GRID]; SLAM_GRID],
    /// Current robot pose.
    pose: Pose2D,
}

impl SlamState {
    const fn new() -> Self {
        SlamState {
            grid: [[0i8; SLAM_GRID]; SLAM_GRID],
            pose: Pose2D { x_mm: 0, y_mm: 0, heading_cdeg: 0 },
        }
    }
}

static SLAM: SpinLock<SlamState> = SpinLock::new(SlamState::new());

/// Odometry: accumulated distance (mm × 1000 for sub-mm precision).
static SLAM_ODO_X: AtomicI64 = AtomicI64::new(0);
static SLAM_ODO_Y: AtomicI64 = AtomicI64::new(0);
/// Update counter (number of map updates performed).
static SLAM_UPDATES: AtomicI32 = AtomicI32::new(0);

// ── Integer trig (shared lookup table) ────────────────────────────────────────
// sin1000 / cos1000 live in `crate::trig` so slam and wind share one table.
use crate::trig::{cos1000, sin1000};

// ── Map utilities ──────────────────────────────────────────────────────────────

/// Convert world mm position to grid cell index.  Returns `None` if out of bounds.
fn world_to_cell(x_mm: i32, y_mm: i32) -> Option<(usize, usize)> {
    let half = SLAM_EXTENT_MM / 2;
    let xi = (x_mm + half) / SLAM_CELL_MM;
    let yi = (y_mm + half) / SLAM_CELL_MM;
    if xi < 0 || yi < 0 || xi >= SLAM_GRID as i32 || yi >= SLAM_GRID as i32 {
        return None;
    }
    Some((xi as usize, yi as usize))
}

/// Update a cell with a log-odds delta, clamped.
fn update_cell(grid: &mut [[i8; SLAM_GRID]; SLAM_GRID], xi: usize, yi: usize, delta: i8) {
    let v = grid[xi][yi].saturating_add(delta);
    grid[xi][yi] = v.clamp(SLAM_L_MIN, SLAM_L_MAX);
}

/// Bresenham's line algorithm: iterate cells from (x0, y0) to (x1, y1).
fn bresenham(x0: i32, y0: i32, x1: i32, y1: i32, mut visit: impl FnMut(i32, i32)) {
    let dx = (x1 - x0).abs();
    let dy = -(y1 - y0).abs();
    let sx = if x0 < x1 { 1i32 } else { -1 };
    let sy = if y0 < y1 { 1i32 } else { -1 };
    let mut err = dx + dy;
    let mut x = x0;
    let mut y = y0;
    loop {
        visit(x, y);
        if x == x1 && y == y1 { break; }
        let e2 = 2 * err;
        if e2 >= dy { err += dy; x += sx; }
        if e2 <= dx { err += dx; y += sy; }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Reset the SLAM map and pose to the initial state.
pub fn slam_reset() {
    let mut s = SLAM.lock();
    s.grid = [[0i8; SLAM_GRID]; SLAM_GRID];
    s.pose = Pose2D::default();
    SLAM_ODO_X.store(0, Ordering::Relaxed);
    SLAM_ODO_Y.store(0, Ordering::Relaxed);
    SLAM_UPDATES.store(0, Ordering::Relaxed);
}

/// Update robot pose from odometry.
///
/// - `dist_mm`: distance travelled since last call (can be negative for reverse).
/// - `heading_cdeg`: current heading (centi-degrees, 0=North, 9000=East).
pub fn slam_update_odometry(dist_mm: i32, heading_cdeg: i32) {
    // Dead-reckoning: integrate position.
    let dx = dist_mm * cos1000(heading_cdeg) / 1_000;
    let dy = dist_mm * sin1000(heading_cdeg) / 1_000;
    SLAM_ODO_X.fetch_add(dx as i64, Ordering::Relaxed);
    SLAM_ODO_Y.fetch_add(dy as i64, Ordering::Relaxed);
    let mut s = SLAM.lock();
    s.pose.x_mm = SLAM_ODO_X.load(Ordering::Relaxed) as i32;
    s.pose.y_mm = SLAM_ODO_Y.load(Ordering::Relaxed) as i32;
    s.pose.heading_cdeg = heading_cdeg;
}

/// Process a rangefinder scan and update the occupancy grid.
///
/// `ranges[n]`: array of range measurements.
/// `angles_cdeg[n]`: absolute heading of each beam (centi-degrees).
///
/// The beam count is capped internally at
/// `azos_flight_math::scan::SLAM_MAX_BEAMS` — unlike `nav`'s `Scan2D`,
/// nothing about this function's signature bounds how many beams a caller
/// can pass, so the cap has to be enforced here rather than relied on from
/// the call site. See `azos_flight_math::scan` for why the cap lives
/// in that crate instead of this one.
pub fn slam_update_scan(ranges: &[u16], angles_cdeg: &[i32]) {
    let (ranges, angles_cdeg) = azos_flight_math::scan::cap_scan(ranges, angles_cdeg);
    let n = ranges.len();
    let mut s = SLAM.lock();
    let rx = s.pose.x_mm;
    let ry = s.pose.y_mm;

    for i in 0..n {
        let r = ranges[i] as i32;
        if r < SLAM_MIN_RANGE_MM { continue; }

        let angle = angles_cdeg[i];
        let (hit_valid, hit_x, hit_y) = if r < SLAM_MAX_RANGE_MM {
            let hx = rx + r * cos1000(angle) / 1_000;
            let hy = ry + r * sin1000(angle) / 1_000;
            (true, hx, hy)
        } else {
            (false, 0, 0)
        };

        // Ray cast: mark free cells along the ray.
        let end_x = if hit_valid { hit_x } else {
            rx + SLAM_MAX_RANGE_MM * cos1000(angle) / 1_000
        };
        let end_y = if hit_valid { hit_y } else {
            ry + SLAM_MAX_RANGE_MM * sin1000(angle) / 1_000
        };

        // Convert to cell coordinates for Bresenham.
        let half = SLAM_EXTENT_MM / 2;
        let cx0 = (rx + half) / SLAM_CELL_MM;
        let cy0 = (ry + half) / SLAM_CELL_MM;
        let cx1 = (end_x + half) / SLAM_CELL_MM;
        let cy1 = (end_y + half) / SLAM_CELL_MM;

        // Free cells along the ray (don't update the last cell if it's a hit).
        let hit_cx = if hit_valid { (hit_x + half) / SLAM_CELL_MM } else { cx1 };
        let hit_cy = if hit_valid { (hit_y + half) / SLAM_CELL_MM } else { cy1 };

        let grid_ptr: *mut [[i8; SLAM_GRID]; SLAM_GRID] = &mut s.grid;
        bresenham(cx0, cy0, cx1, cy1, |cx, cy| {
            if cx == hit_cx && cy == hit_cy { return; } // skip hit cell
            if cx < 0 || cy < 0 || cx >= SLAM_GRID as i32 || cy >= SLAM_GRID as i32 { return; }
            unsafe { update_cell(&mut *grid_ptr, cx as usize, cy as usize, SLAM_L_FREE); }
        });

        // Mark hit cell as occupied.
        if hit_valid {
            if let Some((hxi, hyi)) = world_to_cell(hit_x, hit_y) {
                update_cell(&mut s.grid, hxi, hyi, SLAM_L_HIT);
            }
        }
    }

    SLAM_UPDATES.fetch_add(1, Ordering::Relaxed);
}

/// Read the occupancy probability of a cell at world position `(x_mm, y_mm)`.
///
/// Returns the log-odds value (positive = occupied, negative = free, 0 = unknown).
pub fn slam_cell_logodds(x_mm: i32, y_mm: i32) -> i8 {
    match world_to_cell(x_mm, y_mm) {
        Some((xi, yi)) => SLAM.lock().grid[xi][yi],
        None           => 0,
    }
}

/// Returns `true` if the cell at `(x_mm, y_mm)` is considered occupied
/// (log-odds > 0).
pub fn slam_is_occupied(x_mm: i32, y_mm: i32) -> bool {
    slam_cell_logodds(x_mm, y_mm) > 0
}

/// Get the current robot pose estimate.
pub fn slam_pose() -> Pose2D { SLAM.lock().pose }

/// Return `(total_cells, occupied_cells, free_cells)` for map statistics.
pub fn slam_stats() -> (u32, u32, u32) {
    let s = SLAM.lock();
    let mut occ = 0u32;
    let mut free = 0u32;
    for row in &s.grid {
        for &v in row.iter() {
            if v > 0 { occ += 1; }
            else if v < 0 { free += 1; }
        }
    }
    ((SLAM_GRID * SLAM_GRID) as u32, occ, free)
}

/// Number of map updates performed since init.
pub fn slam_update_count() -> i32 { SLAM_UPDATES.load(Ordering::Relaxed) }
