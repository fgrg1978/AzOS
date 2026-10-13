// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! 3-D geometry primitives — mirror of flight/src/path3d.rs (D03).
//!
//! Tests the pure mathematical functions used by the RRT* planner:
//! integer square root, point distance, and steering.

// ── Constants (match path3d.rs) ───────────────────────────────────────────────

/// Step size for RRT* extension (mm).
pub const PATH3D_STEP_MM: i32 = 3_000;
/// Planning volume half-extent (mm).
pub const PATH3D_VOLUME_MM: i32 = 100_000;
/// Voxel grid dimension.
pub const PATH3D_GRID_SIZE: usize = 32;
/// Voxel size (mm).
pub const PATH3D_VOXEL_MM: i32 = PATH3D_VOLUME_MM / PATH3D_GRID_SIZE as i32;

// ── Types ─────────────────────────────────────────────────────────────────────

/// 3-D point in mm (NED frame).
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Point3D { pub x: i32, pub y: i32, pub z: i32 }

impl Point3D {
    /// Squared Euclidean distance (mm²).
    pub fn dist_sq(&self, other: &Point3D) -> i64 {
        let dx = (self.x - other.x) as i64;
        let dy = (self.y - other.y) as i64;
        let dz = (self.z - other.z) as i64;
        dx * dx + dy * dy + dz * dz
    }

    /// Euclidean distance (mm) using integer Newton sqrt.
    pub fn dist(&self, other: &Point3D) -> i32 {
        isqrt64(self.dist_sq(other)) as i32
    }
}

/// Integer square root (Newton's method, no float).
pub fn isqrt64(n: i64) -> i64 {
    if n <= 0 { return 0; }
    let mut x = n;
    let mut x1 = (x + 1) / 2;
    while x1 < x { x = x1; x1 = (x + n / x) / 2; }
    x
}

/// Map world coordinate to voxel index (clamped).
pub fn world_to_voxel(v: i32) -> usize {
    let idx = (v + PATH3D_VOLUME_MM / 2) / PATH3D_VOXEL_MM;
    idx.clamp(0, PATH3D_GRID_SIZE as i32 - 1) as usize
}

/// Steer from `a` toward `b` by at most `step_mm`.
pub fn steer(a: &Point3D, b: &Point3D, step_mm: i32) -> Point3D {
    let d = a.dist(b);
    if d == 0 || d <= step_mm { return *b; }
    Point3D {
        x: a.x + (b.x - a.x) * step_mm / d,
        y: a.y + (b.y - a.y) * step_mm / d,
        z: a.z + (b.z - a.z) * step_mm / d,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isqrt_exact_squares() {
        assert_eq!(isqrt64(0),   0);
        assert_eq!(isqrt64(1),   1);
        assert_eq!(isqrt64(4),   2);
        assert_eq!(isqrt64(9),   3);
        assert_eq!(isqrt64(100), 10);
        assert_eq!(isqrt64(1_000_000), 1_000);
    }

    #[test]
    fn isqrt_non_perfect_square() {
        // isqrt(2) = 1, isqrt(3) = 1, isqrt(8) = 2
        assert_eq!(isqrt64(2), 1);
        assert_eq!(isqrt64(3), 1);
        assert_eq!(isqrt64(8), 2);
    }

    #[test]
    fn isqrt_negative_returns_zero() {
        assert_eq!(isqrt64(-1), 0);
        assert_eq!(isqrt64(-1_000_000), 0);
    }

    #[test]
    fn point3d_dist_sq_axis_aligned() {
        let a = Point3D { x: 0, y: 0, z: 0 };
        let b = Point3D { x: 3, y: 0, z: 0 };
        assert_eq!(a.dist_sq(&b), 9);
    }

    #[test]
    fn point3d_dist_3_4_5() {
        let a = Point3D { x: 0, y: 0, z: 0 };
        let b = Point3D { x: 3_000, y: 4_000, z: 0 };
        assert_eq!(a.dist(&b), 5_000);
    }

    #[test]
    fn point3d_dist_symmetric() {
        let a = Point3D { x: 1_000, y: 2_000, z: 3_000 };
        let b = Point3D { x: 4_000, y: 6_000, z: 3_000 };
        assert_eq!(a.dist(&b), b.dist(&a));
    }

    #[test]
    fn point3d_dist_to_self_is_zero() {
        let p = Point3D { x: 5_000, y: -3_000, z: 1_000 };
        assert_eq!(p.dist(&p), 0);
    }

    #[test]
    fn steer_close_returns_target() {
        let a = Point3D { x: 0, y: 0, z: 0 };
        let b = Point3D { x: 1_000, y: 0, z: 0 }; // 1 m, less than step 3 m
        let s = steer(&a, &b, PATH3D_STEP_MM);
        assert_eq!(s, b);
    }

    #[test]
    fn steer_far_limits_step() {
        let a = Point3D { x: 0, y: 0, z: 0 };
        let b = Point3D { x: 30_000, y: 0, z: 0 }; // 30 m
        let s = steer(&a, &b, PATH3D_STEP_MM);
        // Should be exactly 3000 mm along X
        assert_eq!(s.x, PATH3D_STEP_MM);
        assert_eq!(s.y, 0);
        assert_eq!(s.z, 0);
    }

    #[test]
    fn steer_diagonal() {
        let a = Point3D { x: 0, y: 0, z: 0 };
        let b = Point3D { x: 6_000, y: 8_000, z: 0 }; // dist = 10 000 mm
        let s = steer(&a, &b, PATH3D_STEP_MM);
        // Step fraction = 3000/10000; x = 6000*0.3 = 1800, y = 8000*0.3 = 2400
        assert_eq!(s.x, 1_800);
        assert_eq!(s.y, 2_400);
        assert_eq!(s.z, 0);
    }

    #[test]
    fn steer_to_same_point_returns_same() {
        let a = Point3D { x: 1_000, y: 2_000, z: 3_000 };
        let s = steer(&a, &a, PATH3D_STEP_MM);
        assert_eq!(s, a);
    }

    #[test]
    fn world_to_voxel_center_is_mid() {
        // Centre of volume (0) should map to grid mid-point (16)
        assert_eq!(world_to_voxel(0), 16);
    }

    #[test]
    fn world_to_voxel_clamp_negative() {
        assert_eq!(world_to_voxel(-1_000_000), 0);
    }

    #[test]
    fn world_to_voxel_clamp_positive() {
        assert_eq!(world_to_voxel(1_000_000), PATH3D_GRID_SIZE - 1);
    }
}
