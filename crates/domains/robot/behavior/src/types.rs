// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sensor snapshot the robot's safety layer judges.
//!
//! All types are `Copy` and use no heap allocation.

/// Behaviour layers: L0 (the safety layer, the kernel's) and the three the
/// ring-3 engine chooses among.
pub const NUM_LAYERS: usize = 4;

/// A snapshot of the sensor bus.
#[derive(Clone, Copy)]
pub struct SensorState {
    pub cam_dist_front: u16,    // milli-units (0..1000)
    pub cam_dist_right: u16,    // milli-units (0..1000)

    // IMU
    pub accel_mg:   [i32; 3],
    pub gyro_mdps:  [i32; 3],
    pub imu_valid:  bool,

    // Odometry
    pub odom_dist_mm:       i64,
    pub odom_heading_cdeg:  i64,

    // Encoders
    pub enc_left:  i64,
    pub enc_right: i64,

    // Misc
    pub battery_mv:     u16,
    pub velocity_mm_s:  i32,
    pub temp_cdeg:      i32,

    // Digital sensor flags (PIR/sound/IR triggers)
    pub sensor_flags:   u16,

    // GPS (E03 geofence — micro-degrees × 10⁶)
    pub gps_lat_udeg:   i32,
    pub gps_lon_udeg:   i32,
    pub gps_fix:        u8,
    pub gps_satellites: u8,

    // Timestamp (CLINT ticks)
    pub timestamp: u64,
}

impl SensorState {
    pub const fn new() -> Self {
        SensorState {
            cam_dist_front: 0,
            cam_dist_right: 0,
            accel_mg:       [0; 3],
            gyro_mdps:      [0; 3],
            imu_valid:      false,
            odom_dist_mm:       0,
            odom_heading_cdeg:  0,
            enc_left:  0,
            enc_right: 0,
            battery_mv:    0,
            velocity_mm_s: 0,
            temp_cdeg:     0,
            sensor_flags:  0,
            gps_lat_udeg:   0,
            gps_lon_udeg:   0,
            gps_fix:        0,
            gps_satellites: 0,
            timestamp: 0,
        }
    }
}
