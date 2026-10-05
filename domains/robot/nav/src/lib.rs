// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! Navigation — waypoints, mission, occupancy grid, obstacle avoidance (Phases M+N).
//!
//! Provides the navigation stack for autonomous flight:
//! - **Waypoint**: target position + action
//! - **Mission**: ring buffer of up to 32 waypoints
//! - **nav_update()**: pure-pursuit guidance (current GPS → target → FlightTarget)
//! - **OccupancyGrid**: 2D grid map (100×100 cells, 10 cm/cell = 10m × 10m)
//! - **Obstacle**: detected obstacle from server perception or local sensors
//!
//! All arithmetic is integer (no `f32`).
//!
//! # Channels
//!
//! - `CH_OBSTACLES`  — detected obstacles (from server or local sensors)
//! - `CH_PROXIMITY`  — proximity sensor readings (ultrasonic + ToF)

use core::sync::atomic::{AtomicU8, Ordering};
use azos_channel::Channel;

// ── Channels ────────────────────────────────────────────────────────────────

/// Channel for obstacle detections (from server or local perception).
pub static CH_OBSTACLES: Channel<ObstacleSet> = Channel::new(ObstacleSet::new());

/// Channel for proximity sensor readings.
pub static CH_PROXIMITY: Channel<ProximityData> = Channel::new(ProximityData::new());

// ── Proximity data ──────────────────────────────────────────────────────────

/// Proximity sensor readings (from rangefinders).
#[derive(Clone, Copy)]
pub struct ProximityData {
    /// Distance per direction in mm (0 = no sensor).
    /// [front, right, rear, left, down, up]
    pub distances_mm: [u16; 6],
    /// Number of valid readings.
    pub count: u8,
}

impl ProximityData {
    pub const fn new() -> Self {
        ProximityData { distances_mm: [0; 6], count: 0 }
    }

    /// Returns true if any sensor detects an obstacle within `threshold_mm`.
    pub fn obstacle_within(&self, threshold_mm: u16) -> bool {
        for i in 0..self.count as usize {
            if i >= 6 { break; }
            if self.distances_mm[i] > 0 && self.distances_mm[i] < threshold_mm {
                return true;
            }
        }
        false
    }
}

// ── Obstacle type ───────────────────────────────────────────────────────────

/// Maximum obstacles tracked simultaneously.
pub const MAX_OBSTACLES: usize = 8;

/// Detected obstacle (from server perception or local sensors).
#[derive(Clone, Copy)]
pub struct Obstacle {
    /// Relative X position in mm (positive = right).
    pub x_mm: i32,
    /// Relative Y position in mm (positive = forward).
    pub y_mm: i32,
    /// Estimated size (radius) in mm.
    pub radius_mm: u16,
    /// Confidence (0-100).
    pub confidence: u8,
    /// Source: 0=local sensor, 1=server perception.
    pub source: u8,
}

impl Obstacle {
    pub const fn new() -> Self {
        Obstacle { x_mm: 0, y_mm: 0, radius_mm: 0, confidence: 0, source: 0 }
    }
}

/// Set of detected obstacles.
#[derive(Clone, Copy)]
pub struct ObstacleSet {
    pub obstacles: [Obstacle; MAX_OBSTACLES],
    pub count: u8,
}

impl ObstacleSet {
    pub const fn new() -> Self {
        ObstacleSet {
            obstacles: [Obstacle::new(); MAX_OBSTACLES],
            count: 0,
        }
    }
}

// ── Waypoint ────────────────────────────────────────────────────────────────

/// Action to perform at waypoint.
#[derive(Clone, Copy, PartialEq)]
pub enum WaypointAction {
    /// Continue to next waypoint (no pause).
    None,
    /// Hover for N seconds (×10, so 30 = 3.0s).
    Hover(u16),
    /// Land at this waypoint.
    Land,
    /// Return to launch after this waypoint.
    RTL,
}

/// Navigation waypoint.
#[derive(Clone, Copy)]
pub struct Waypoint {
    /// Target latitude in degrees × 10^7.
    pub lat_deg7: i32,
    /// Target longitude in degrees × 10^7.
    pub lon_deg7: i32,
    /// Target altitude above MSL in millimetres.
    pub alt_mm: i32,
    /// Target speed in cm/s.
    pub speed_cms: u16,
    /// Action to perform on arrival.
    pub action: WaypointAction,
}

impl Waypoint {
    pub const fn new() -> Self {
        Waypoint {
            lat_deg7: 0,
            lon_deg7: 0,
            alt_mm: 0,
            speed_cms: 100,
            action: WaypointAction::None,
        }
    }
}

// ── Mission ─────────────────────────────────────────────────────────────────

/// Maximum waypoints in a mission.
pub const MISSION_MAX: usize = 32;

/// Mission: ordered sequence of waypoints.
pub struct Mission {
    waypoints: [Waypoint; MISSION_MAX],
    count: u8,
    current: u8,
}

static MISSION_CURRENT: AtomicU8 = AtomicU8::new(0);

impl Mission {
    pub const fn new() -> Self {
        Mission {
            waypoints: [Waypoint::new(); MISSION_MAX],
            count: 0,
            current: 0,
        }
    }

    /// Clear mission.
    pub fn clear(&mut self) {
        self.count = 0;
        self.current = 0;
        MISSION_CURRENT.store(0, Ordering::Relaxed);
    }

    /// Add a waypoint to the mission.  Returns false if mission is full.
    pub fn add_waypoint(&mut self, wp: Waypoint) -> bool {
        if self.count as usize >= MISSION_MAX { return false; }
        self.waypoints[self.count as usize] = wp;
        self.count += 1;
        true
    }

    /// Get current waypoint.
    pub fn current_waypoint(&self) -> Option<&Waypoint> {
        if self.current < self.count {
            Some(&self.waypoints[self.current as usize])
        } else {
            None
        }
    }

    /// Advance to next waypoint.  Returns false if mission complete.
    pub fn advance(&mut self) -> bool {
        if self.current + 1 < self.count {
            self.current += 1;
            MISSION_CURRENT.store(self.current, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Get waypoint count.
    pub fn len(&self) -> u8 { self.count }

    /// Get current waypoint index.
    pub fn current_index(&self) -> u8 { self.current }

    /// Get waypoint at index, or None if out of range.
    pub fn get_waypoint(&self, idx: usize) -> Option<Waypoint> {
        if idx < self.count as usize { Some(self.waypoints[idx]) } else { None }
    }
}

// ── Navigation controller ───────────────────────────────────────────────────

/// Arrival threshold in mm (within this distance, we consider WP reached).
const ARRIVAL_THRESHOLD_MM: i32 = 2000; // 2 meters

/// Compute navigation update: given current GPS position and target waypoint,
/// produce a FlightTarget for the flight controller.
///
/// Uses simplified pure-pursuit guidance:
/// 1. Compute bearing to target
/// 2. Compute distance to target
/// 3. Map bearing error to roll command
/// 4. Set pitch for forward flight at target speed
/// 5. Set altitude target
///
/// Returns (FlightTarget, arrived: bool).
pub fn nav_update(
    current: &azos_gps::GpsPosition,
    target: &Waypoint,
) -> (azos_flight::FlightTarget, bool) {
    // Compute delta position in mm.
    // At the equator, 1 deg7 ≈ 0.0111 mm (1 deg ≈ 111,111 m).
    // Simplified: dx_mm = dlon_deg7 * 11111 / 1_000_000
    //             dy_mm = dlat_deg7 * 11111 / 1_000_000
    // (This ignores latitude correction for longitude — acceptable for local nav.)
    let dlat = target.lat_deg7 - current.lat_deg7;
    let dlon = target.lon_deg7 - current.lon_deg7;

    // Convert deg7 deltas to mm.
    // 1 deg7 = 1e-7 deg. 1 deg lat ≈ 111,111 m = 111,111,000 mm.
    // So 1 deg7 = 111,111,000 / 10,000,000 = 11.1111 mm ≈ 11 mm.
    let dy_mm = (dlat as i64 * 11) as i32;
    let dx_mm = (dlon as i64 * 11) as i32;

    // Distance to target (simplified Manhattan for speed, or Euclidean via isqrt).
    let dist_sq = dx_mm as i64 * dx_mm as i64 + dy_mm as i64 * dy_mm as i64;
    let dist_mm = isqrt(dist_sq as u64) as i32;

    // Check arrival.
    if dist_mm < ARRIVAL_THRESHOLD_MM {
        return (azos_flight::FlightTarget {
            roll_cdeg: 0,
            pitch_cdeg: 0,
            yaw_rate_mdps: 0,
            throttle: 400, // hover throttle
            alt_mm: target.alt_mm,
        }, true);
    }

    // Compute bearing to target in centi-degrees (0 = north, 9000 = east).
    // bearing = atan2(dx, dy) in cdeg.
    let bearing_cdeg = atan2_cdeg(dx_mm, dy_mm);

    // Heading error: desired bearing - current course.
    let current_hdg = current.course_cdeg as i32;
    let mut hdg_error = bearing_cdeg - current_hdg;
    // Normalize to -18000..+18000.
    if hdg_error > 18000 { hdg_error -= 36000; }
    if hdg_error < -18000 { hdg_error += 36000; }

    // Map heading error to roll command.
    // Clamp to ±3000 cdeg (±30° bank angle).
    let roll_cdeg = if hdg_error > 3000 { 3000 }
                    else if hdg_error < -3000 { -3000 }
                    else { hdg_error };

    // Pitch: tilt forward proportional to distance (more tilt = faster).
    // Max forward pitch: -1500 cdeg (-15°).
    let pitch_cdeg = if dist_mm > 10000 { -1500 }
                     else { -(dist_mm * 1500 / 10000) };

    // Throttle: maintain current altitude or climb to target.
    let alt_error = target.alt_mm - current.alt_mm;
    let throttle_adj = if alt_error > 1000 { 100 }       // climb
                       else if alt_error < -1000 { -100 } // descend
                       else { 0 };
    let throttle = (400 + throttle_adj) as u16; // hover ≈ 400

    (azos_flight::FlightTarget {
        roll_cdeg,
        pitch_cdeg,
        yaw_rate_mdps: 0,
        throttle,
        alt_mm: target.alt_mm,
    }, false)
}

// ── Occupancy grid ──────────────────────────────────────────────────────────

/// Grid dimensions.
pub const GRID_SIZE: usize = 100;
/// Cell size in mm (100 mm = 10 cm).
pub const CELL_SIZE_MM: u32 = 100;

/// 2D occupancy grid (100×100 cells, 10 cm/cell = 10m × 10m).
///
/// Each cell is a u8: 0 = free, 255 = occupied, 1-254 = probability.
/// Center of grid is the robot's position.
pub struct OccupancyGrid {
    cells: [u8; GRID_SIZE * GRID_SIZE],
}

impl OccupancyGrid {
    pub const fn new() -> Self {
        OccupancyGrid {
            cells: [0u8; GRID_SIZE * GRID_SIZE],
        }
    }

    /// Clear the grid (all cells free).
    pub fn clear(&mut self) {
        for c in self.cells.iter_mut() { *c = 0; }
    }

    /// Get cell value at (x, y) grid coordinates.
    pub fn get(&self, x: usize, y: usize) -> u8 {
        if x >= GRID_SIZE || y >= GRID_SIZE { return 255; }
        self.cells[y * GRID_SIZE + x]
    }

    /// Set cell value at (x, y) grid coordinates.
    pub fn set(&mut self, x: usize, y: usize, val: u8) {
        if x >= GRID_SIZE || y >= GRID_SIZE { return; }
        self.cells[y * GRID_SIZE + x] = val;
    }

    /// Mark an obstacle at relative position (dx_mm, dy_mm) from grid center.
    pub fn mark_obstacle(&mut self, dx_mm: i32, dy_mm: i32, radius_mm: u16) {
        let cx = (GRID_SIZE / 2) as i32 + dx_mm / CELL_SIZE_MM as i32;
        let cy = (GRID_SIZE / 2) as i32 + dy_mm / CELL_SIZE_MM as i32;
        let r = (radius_mm as i32 / CELL_SIZE_MM as i32).max(1);

        // Fill circular area.
        for dy in -r..=r {
            for dx in -r..=r {
                if dx * dx + dy * dy <= r * r {
                    let gx = (cx + dx) as usize;
                    let gy = (cy + dy) as usize;
                    self.set(gx, gy, 255);
                }
            }
        }
    }

    /// Count occupied cells.
    pub fn occupied_count(&self) -> u32 {
        let mut count = 0u32;
        for &c in self.cells.iter() {
            if c > 127 { count += 1; }
        }
        count
    }

    /// Check if a path from center to (dx_mm, dy_mm) is clear.
    /// Returns true if no occupied cells along the path.
    pub fn path_clear(&self, dx_mm: i32, dy_mm: i32) -> bool {
        let cx = (GRID_SIZE / 2) as i32;
        let cy = (GRID_SIZE / 2) as i32;
        let tx = cx + dx_mm / CELL_SIZE_MM as i32;
        let ty = cy + dy_mm / CELL_SIZE_MM as i32;

        // Bresenham line from (cx,cy) to (tx,ty).
        let mut x = cx;
        let mut y = cy;
        let adx = (tx - cx).unsigned_abs() as i32;
        let ady = (ty - cy).unsigned_abs() as i32;
        let sx: i32 = if cx < tx { 1 } else { -1 };
        let sy: i32 = if cy < ty { 1 } else { -1 };
        let mut err = adx - ady;

        loop {
            if self.get(x as usize, y as usize) > 127 {
                return false;
            }
            if x == tx && y == ty { break; }
            let e2 = 2 * err;
            if e2 > -ady { err -= ady; x += sx; }
            if e2 < adx  { err += adx; y += sy; }
        }
        true
    }
}

// ── Integer math helpers ────────────────────────────────────────────────────

/// Integer square root (Babylonian method).
fn isqrt(n: u64) -> u64 {
    if n == 0 { return 0; }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Integer atan2 returning centi-degrees (0..36000, 0=north/+Y, 9000=east/+X).
///
/// This is a navigation-style atan2 (bearing from north, clockwise positive).
fn atan2_cdeg(x: i32, y: i32) -> i32 {
    if x == 0 && y == 0 { return 0; }

    // Use math atan2 (returns -18000..+18000, 0=east) then convert to bearing.
    let math_angle = math_atan2_cdeg(y, x); // note: (y,x) for math convention
    // Math: 0=east, 90=north. Bearing: 0=north, 90=east.
    // bearing = 90 - math_angle = 9000 - math_angle (in cdeg).
    let mut bearing = 9000 - math_angle;
    if bearing < 0 { bearing += 36000; }
    if bearing >= 36000 { bearing -= 36000; }
    bearing
}

/// Standard math atan2 in centi-degrees (-18000..+18000).
fn math_atan2_cdeg(y: i32, x: i32) -> i32 {
    if x == 0 && y == 0 { return 0; }

    let abs_y = (y as i64).unsigned_abs().max(1) as i64;
    let abs_x = (x as i64).unsigned_abs() as i64;

    let (ratio_num, ratio_den) = if abs_x >= abs_y {
        (abs_y, abs_x)
    } else {
        (abs_x, abs_y)
    };

    let r_1000 = (ratio_num * 1000 / ratio_den) as i32;
    let r2 = r_1000 as i64 * r_1000 as i64 / 1000;
    let numer = r_1000 as i64 * 4500;
    let denom = 1000 + 280 * r2 / 1000;
    let atan_cdeg = if denom == 0 { 4500 } else { (numer / denom) as i32 };

    let angle = if abs_x >= abs_y { atan_cdeg } else { 9000 - atan_cdeg };

    if x >= 0 && y >= 0 { angle }
    else if x < 0 && y >= 0 { 18000 - angle }
    else if x < 0 && y < 0 { -(18000 - angle) }
    else { -angle }
}

// ── Scan Matching / SLAM (F12) ──────────────────────────────────────────────

/// Maximum number of points in a 2D LiDAR scan.
pub const SCAN_MAX_POINTS: usize = 360;

/// Maximum ICP iterations.
const ICP_MAX_ITER: usize = 20;

/// ICP convergence threshold in mm² (stop when mean error below this).
const ICP_CONVERGENCE_MM2: i64 = 25; // 5mm

/// A 2D point in millimeters (relative to robot).
#[derive(Clone, Copy, Default)]
pub struct Point2D {
    pub x: i32,
    pub y: i32,
}

/// A 2D LiDAR scan (set of points).
pub struct Scan2D {
    pub points: [Point2D; SCAN_MAX_POINTS],
    pub count: u16,
}

impl Scan2D {
    pub const fn new() -> Self {
        Self {
            points: [Point2D { x: 0, y: 0 }; SCAN_MAX_POINTS],
            count: 0,
        }
    }
}

/// Result of scan matching: estimated translation (dx, dy) in mm and rotation in centi-degrees.
#[derive(Clone, Copy, Default)]
pub struct ScanMatchResult {
    pub dx_mm: i32,
    pub dy_mm: i32,
    pub dtheta_cdeg: i32,
    pub converged: bool,
    pub mean_error_mm2: i64,
}

/// Simple ICP (Iterative Closest Point) scan matching.
///
/// Finds the rigid transform (translation only, no rotation for simplicity)
/// that best aligns `current` scan to `reference` scan.
/// Returns the estimated displacement.
pub fn scan_match_icp(reference: &Scan2D, current: &Scan2D) -> ScanMatchResult {
    let ref_count = reference.count as usize;
    let cur_count = current.count as usize;
    if ref_count < 2 || cur_count < 2 {
        return ScanMatchResult::default();
    }

    let mut tx: i32 = 0;
    let mut ty: i32 = 0;
    let mut mean_err: i64 = i64::MAX;

    for _iter in 0..ICP_MAX_ITER {
        // For each current point (shifted by tx,ty), find closest reference point
        let mut sum_dx: i64 = 0;
        let mut sum_dy: i64 = 0;
        let mut sum_err: i64 = 0;
        let mut matches: u32 = 0;

        for i in 0..cur_count.min(SCAN_MAX_POINTS) {
            let cx = current.points[i].x + tx;
            let cy = current.points[i].y + ty;

            // Find nearest reference point (brute force, bounded by scan size)
            let mut best_dist = i64::MAX;
            let mut best_rx: i32 = 0;
            let mut best_ry: i32 = 0;

            for j in 0..ref_count.min(SCAN_MAX_POINTS) {
                let dx = (reference.points[j].x - cx) as i64;
                let dy = (reference.points[j].y - cy) as i64;
                let dist = dx * dx + dy * dy;
                if dist < best_dist {
                    best_dist = dist;
                    best_rx = reference.points[j].x;
                    best_ry = reference.points[j].y;
                }
            }

            sum_dx += (best_rx - cx) as i64;
            sum_dy += (best_ry - cy) as i64;
            sum_err += best_dist;
            matches += 1;
        }

        if matches == 0 { break; }

        // Update transform
        tx += (sum_dx / matches as i64) as i32;
        ty += (sum_dy / matches as i64) as i32;
        mean_err = sum_err / matches as i64;

        if mean_err < ICP_CONVERGENCE_MM2 {
            return ScanMatchResult {
                dx_mm: tx, dy_mm: ty,
                dtheta_cdeg: 0, // rotation not estimated in this simplified version
                converged: true,
                mean_error_mm2: mean_err,
            };
        }
    }

    ScanMatchResult {
        dx_mm: tx, dy_mm: ty,
        dtheta_cdeg: 0,
        converged: mean_err < ICP_CONVERGENCE_MM2 * 4, // relaxed threshold
        mean_error_mm2: mean_err,
    }
}

/// Update occupancy grid from a LiDAR scan (probabilistic, log-odds).
///
/// `robot_x`, `robot_y`: robot position in grid coordinates.
/// `scan`: current LiDAR scan (points relative to robot, in mm).
pub fn grid_update_from_scan(
    grid: &mut OccupancyGrid,
    robot_x: usize, robot_y: usize,
    scan: &Scan2D,
) {
    /// Log-odds increment for occupied cells.
    const LOG_ODDS_OCC: i16 = 20;
    /// Log-odds decrement for free cells (ray trace).
    const LOG_ODDS_FREE: i16 = -5;

    for i in 0..(scan.count as usize).min(SCAN_MAX_POINTS) {
        let p = &scan.points[i];
        let gx = robot_x as i32 + p.x / CELL_SIZE_MM as i32;
        let gy = robot_y as i32 + p.y / CELL_SIZE_MM as i32;

        // Mark endpoint as occupied
        if gx >= 0 && (gx as usize) < GRID_SIZE && gy >= 0 && (gy as usize) < GRID_SIZE {
            let cell = grid.get(gx as usize, gy as usize);
            let new_val = (cell as i16 + LOG_ODDS_OCC).clamp(0, 255) as u8;
            grid.set(gx as usize, gy as usize, new_val);
        }

        // Ray trace: mark free cells along the ray from robot to endpoint
        // (simplified: step along the ray in CELL_SIZE increments)
        let dist_cells = isqrt(((p.x / CELL_SIZE_MM as i32).pow(2)
            + (p.y / CELL_SIZE_MM as i32).pow(2)) as u64) as i32;
        if dist_cells > 1 {
            for step in 1..dist_cells {
                let fx = robot_x as i32 + (p.x * step) / (dist_cells * CELL_SIZE_MM as i32);
                let fy = robot_y as i32 + (p.y * step) / (dist_cells * CELL_SIZE_MM as i32);
                if fx >= 0 && (fx as usize) < GRID_SIZE && fy >= 0 && (fy as usize) < GRID_SIZE {
                    let cell = grid.get(fx as usize, fy as usize);
                    let new_val = (cell as i16 + LOG_ODDS_FREE).clamp(0, 255) as u8;
                    grid.set(fx as usize, fy as usize, new_val);
                }
            }
        }
    }
}

// ── Info ─────────────────────────────────────────────────────────────────────

/// Print navigation status.
pub fn nav_info() {
    let obs = CH_OBSTACLES.read();
    let prox = CH_PROXIMITY.read();

    azos_drv_sys::kconsoleln!("[NAV] Obstacles: {} detected (ch seq={})",
        obs.val.count, obs.seq);
    azos_drv_sys::kconsoleln!("[NAV] Proximity: {} sensors (ch seq={})",
        prox.val.count, prox.seq);

    if prox.val.count > 0 {
        let d = &prox.val.distances_mm;
        let labels = ["front", "right", "rear", "left", "down", "up"];
        for i in 0..prox.val.count as usize {
            if i >= 6 { break; }
            if d[i] > 0 {
                azos_drv_sys::kconsoleln!("[NAV]   {}: {} mm", labels[i], d[i]);
            }
        }
    }

    let wp_idx = MISSION_CURRENT.load(Ordering::Relaxed);
    azos_drv_sys::kconsoleln!("[NAV] Mission: waypoint {}", wp_idx);
}

// ── A* Path Planning (F13) ──────────────────────────────────────────────────

/// Maximum path length (waypoints in the found path).
pub const ASTAR_MAX_PATH: usize = 128;

/// Maximum nodes A* will explore before giving up.
const ASTAR_MAX_OPEN: usize = 512;

/// Cost multiplier for heuristic (×10 for integer math).
const COST_STRAIGHT: u16 = 10;
const COST_DIAGONAL: u16 = 14; // ~sqrt(2) × 10

/// Occupancy threshold: cells above this value are considered obstacles.
const OBSTACLE_THRESHOLD: u8 = 127;

/// A* node in the open/closed set.
#[derive(Clone, Copy)]
struct AstarNode {
    x: u8,
    y: u8,
    g: u16,     // cost from start
    f: u16,     // g + heuristic
    parent: u16, // index in nodes array (u16::MAX = no parent)
    open: bool,
    closed: bool,
}

impl AstarNode {
    const fn empty() -> Self {
        Self { x: 0, y: 0, g: u16::MAX, f: u16::MAX, parent: u16::MAX, open: false, closed: false }
    }
}

/// Result of A* path search.
pub struct AstarPath {
    /// Grid coordinates of the path (start to goal).
    pub points: [(u8, u8); ASTAR_MAX_PATH],
    /// Number of valid points in the path.
    pub len: usize,
}

impl AstarPath {
    const fn empty() -> Self {
        Self { points: [(0, 0); ASTAR_MAX_PATH], len: 0 }
    }
}

/// Find a path from (sx, sy) to (gx, gy) on the occupancy grid using A*.
///
/// Returns a path (list of grid coordinates) or None if no path exists.
/// All coordinates are grid cells (0..GRID_SIZE).
pub fn astar_plan(grid: &OccupancyGrid, sx: usize, sy: usize, gx: usize, gy: usize) -> Option<AstarPath> {
    if sx >= GRID_SIZE || sy >= GRID_SIZE || gx >= GRID_SIZE || gy >= GRID_SIZE {
        return None;
    }
    if grid.get(gx, gy) > OBSTACLE_THRESHOLD {
        return None; // goal is inside obstacle
    }

    // Node storage: flat array indexed by (y * GRID_SIZE + x), but we only
    // track nodes that have been visited. Use a compact open list.
    let mut nodes = [AstarNode::empty(); ASTAR_MAX_OPEN];

    // Grid-indexed lookup: which node index corresponds to each cell.
    // Using u16::MAX = unvisited. This uses 20KB for 100×100 grid.
    let mut cell_node: [u16; GRID_SIZE * GRID_SIZE] = [u16::MAX; GRID_SIZE * GRID_SIZE];

    // Start node
    let start_h = heuristic(sx, sy, gx, gy);
    nodes[0] = AstarNode { x: sx as u8, y: sy as u8, g: 0, f: start_h, parent: u16::MAX, open: true, closed: false };
    cell_node[sy * GRID_SIZE + sx] = 0;
    let mut node_count: usize = 1;

    // 8-directional neighbors
    const DIRS: [(i8, i8); 8] = [
        (0, -1), (1, 0), (0, 1), (-1, 0),    // cardinal
        (1, -1), (1, 1), (-1, 1), (-1, -1),   // diagonal
    ];

    loop {
        // Find open node with lowest f
        let mut best_idx: usize = usize::MAX;
        let mut best_f: u16 = u16::MAX;
        for i in 0..node_count {
            if nodes[i].open && nodes[i].f < best_f {
                best_f = nodes[i].f;
                best_idx = i;
            }
        }
        if best_idx == usize::MAX {
            return None; // no path found
        }

        let current = nodes[best_idx];
        nodes[best_idx].open = false;
        nodes[best_idx].closed = true;

        // Goal reached?
        if current.x as usize == gx && current.y as usize == gy {
            return Some(reconstruct_path(&nodes, best_idx));
        }

        // Expand neighbors
        for (di, &(dx, dy)) in DIRS.iter().enumerate() {
            let nx = current.x as i16 + dx as i16;
            let ny = current.y as i16 + dy as i16;
            if nx < 0 || ny < 0 || nx >= GRID_SIZE as i16 || ny >= GRID_SIZE as i16 {
                continue;
            }
            let nx = nx as usize;
            let ny = ny as usize;

            if grid.get(nx, ny) > OBSTACLE_THRESHOLD {
                continue; // obstacle
            }

            let move_cost = if di < 4 { COST_STRAIGHT } else { COST_DIAGONAL };
            let new_g = current.g.saturating_add(move_cost);

            let cell_idx = ny * GRID_SIZE + nx;
            let existing = cell_node[cell_idx];

            if existing != u16::MAX {
                let node = &mut nodes[existing as usize];
                if node.closed { continue; }
                if new_g < node.g {
                    node.g = new_g;
                    node.f = new_g + heuristic(nx, ny, gx, gy);
                    node.parent = best_idx as u16;
                    node.open = true;
                }
            } else {
                // New node
                if node_count >= ASTAR_MAX_OPEN {
                    return None; // search space exhausted
                }
                let h = heuristic(nx, ny, gx, gy);
                nodes[node_count] = AstarNode {
                    x: nx as u8, y: ny as u8,
                    g: new_g, f: new_g + h,
                    parent: best_idx as u16,
                    open: true, closed: false,
                };
                cell_node[cell_idx] = node_count as u16;
                node_count += 1;
            }
        }
    }
}

/// Manhattan distance heuristic (×COST_STRAIGHT for integer consistency).
fn heuristic(x1: usize, y1: usize, x2: usize, y2: usize) -> u16 {
    let dx = if x1 > x2 { x1 - x2 } else { x2 - x1 };
    let dy = if y1 > y2 { y1 - y2 } else { y2 - y1 };
    ((dx + dy) as u16) * COST_STRAIGHT
}

/// Reconstruct path from goal node back to start.
fn reconstruct_path(nodes: &[AstarNode; ASTAR_MAX_OPEN], goal_idx: usize) -> AstarPath {
    let mut path = AstarPath::empty();

    // Trace back from goal to start
    let mut stack = [(0u8, 0u8); ASTAR_MAX_PATH];
    let mut stack_len = 0;
    let mut idx = goal_idx;

    while idx != usize::MAX && stack_len < ASTAR_MAX_PATH {
        let node = &nodes[idx];
        stack[stack_len] = (node.x, node.y);
        stack_len += 1;
        idx = if node.parent == u16::MAX { usize::MAX } else { node.parent as usize };
    }

    // Reverse into path
    for i in 0..stack_len {
        path.points[i] = stack[stack_len - 1 - i];
    }
    path.len = stack_len;
    path
}

// ===========================================================================
// R02: Speculative Waypoint Cache (SPO-inspired)
// ===========================================================================
//
// The brain sends waypoints one at a time over the network.  Transmission
// latency (10-50 ms) means the robot can stand still waiting for the next
// command even when the next destination is predictable.
//
// The speculative cache pre-computes the `N` most likely next waypoints from
// the current mission plan.  When the robot completes a waypoint, it
// immediately starts executing the top speculative candidate instead of
// waiting for brain confirmation.
//
// If the brain then sends a different waypoint (speculation miss), the robot
// corrects course.  The cost of a miss is one heading change; the benefit of
// a hit is eliminating the full round-trip latency.
//
// Inspired by: SPO (Speculative Pre-Optimization) from the Reality-Native OS
// design and the classic out-of-order execution idea from processor design.

use azos_sync::SpinLock;

/// Maximum number of speculative candidates in the cache.
pub const SPEC_WP_CACHE_SIZE: usize = 4;

/// Confidence in a speculative waypoint (0-255; 255 = certain).
pub const SPEC_CONFIDENCE_HIGH:   u8 = 200;
pub const SPEC_CONFIDENCE_MEDIUM: u8 = 128;
pub const SPEC_CONFIDENCE_LOW:    u8 = 64;

/// One speculative waypoint candidate.
#[derive(Clone, Copy)]
pub struct SpecWaypoint {
    /// The predicted next waypoint.
    pub wp: Waypoint,
    /// Confidence score (higher = more likely to be correct).
    pub confidence: u8,
    /// Whether this slot is occupied.
    pub valid: bool,
}

impl SpecWaypoint {
    pub const fn empty() -> Self {
        SpecWaypoint {
            wp: Waypoint::new(),
            confidence: 0,
            valid: false,
        }
    }
}

struct SpecCache {
    candidates: [SpecWaypoint; SPEC_WP_CACHE_SIZE],
    /// How many valid candidates are stored.
    count: usize,
    /// Speculation hit counter (for telemetry).
    hits: u32,
    /// Speculation miss counter.
    misses: u32,
}

impl SpecCache {
    const fn new() -> Self {
        SpecCache {
            candidates: [SpecWaypoint::empty(); SPEC_WP_CACHE_SIZE],
            count: 0,
            hits: 0,
            misses: 0,
        }
    }
}

static SPEC_CACHE: SpinLock<SpecCache> = SpinLock::new(SpecCache::new());

/// Fill the speculative cache from the next `n` waypoints in the current mission.
///
/// Called after the robot confirms arrival at a waypoint, so the cache is
/// ready before the brain's reply arrives.
pub fn spec_wp_prefill(mission: &Mission) {
    let mut cache = SPEC_CACHE.lock();
    cache.count = 0;

    let current = mission.current_index() as usize;
    let total   = mission.len() as usize;

    let fill = (SPEC_WP_CACHE_SIZE).min(total.saturating_sub(current + 1));
    for i in 0..fill {
        let wp_idx = current + 1 + i;
        if wp_idx >= total { break; }
        let confidence = if i == 0 {
            SPEC_CONFIDENCE_HIGH
        } else if i == 1 {
            SPEC_CONFIDENCE_MEDIUM
        } else {
            SPEC_CONFIDENCE_LOW
        };
        if let Some(wp) = mission.get_waypoint(wp_idx) {
            cache.candidates[i] = SpecWaypoint {
                wp,
                confidence,
                valid: true,
            };
        }
        cache.count += 1;
    }
}

/// Return the best speculative candidate (highest confidence), or None.
pub fn spec_wp_top() -> Option<Waypoint> {
    let cache = SPEC_CACHE.lock();
    if cache.count == 0 { return None; }
    let mut best_idx = 0;
    let mut best_conf = 0u8;
    for i in 0..cache.count {
        if cache.candidates[i].valid && cache.candidates[i].confidence > best_conf {
            best_conf = cache.candidates[i].confidence;
            best_idx = i;
        }
    }
    if cache.candidates[best_idx].valid {
        Some(cache.candidates[best_idx].wp)
    } else {
        None
    }
}

/// Confirm that the speculative waypoint matched (brain sent the same one).
pub fn spec_wp_hit() {
    SPEC_CACHE.lock().hits += 1;
}

/// Report a speculation miss (brain sent a different waypoint).
/// Clears the cache so stale predictions are not re-used.
pub fn spec_wp_miss() {
    let mut cache = SPEC_CACHE.lock();
    cache.misses += 1;
    for c in cache.candidates.iter_mut() { *c = SpecWaypoint::empty(); }
    cache.count = 0;
}

/// Inject a custom speculative waypoint (e.g., from a local planner).
pub fn spec_wp_push(wp: Waypoint, confidence: u8) -> bool {
    let mut cache = SPEC_CACHE.lock();
    if cache.count >= SPEC_WP_CACHE_SIZE { return false; }
    let idx = cache.count;
    cache.candidates[idx] = SpecWaypoint { wp, confidence, valid: true };
    cache.count += 1;
    true
}

/// Return speculation hit/miss counts for telemetry.
pub fn spec_wp_stats() -> (u32, u32) {
    let cache = SPEC_CACHE.lock();
    (cache.hits, cache.misses)
}
