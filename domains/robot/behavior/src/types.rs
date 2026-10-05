// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Core types for the subsumption behavior engine — Phase G1.
//!
//! All types are `Copy` and use no heap allocation.

/// CMD constants for VlaAction.
pub const CMD_NONE:      u8 = 0;
pub const CMD_MOTOR:     u8 = 1;
pub const CMD_STOP:      u8 = 2;
pub const CMD_POSE:      u8 = 3;
pub const CMD_HEARTBEAT: u8 = 255;

/// Number of behavior layers in the subsumption arbiter.
pub const NUM_LAYERS: usize = 4;

/// Unified sensor snapshot — passed into every behavior layer.
#[derive(Clone, Copy)]
pub struct SensorState {
    // Camera
    pub cam_pixels:     [u8; 32],
    pub cam_w:          u8,
    pub cam_h:          u8,
    pub cam_valid:      bool,
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

    // Remote VLA action (last received)
    pub remote_action: VlaAction,

    // Timestamp (CLINT ticks)
    pub timestamp: u64,
}

impl SensorState {
    pub const fn new() -> Self {
        SensorState {
            cam_pixels:     [0; 32],
            cam_w:          8,
            cam_h:          4,
            cam_valid:      false,
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
            remote_action: VlaAction::new(),
            timestamp: 0,
        }
    }
}

/// Action received from the VLA server.
#[derive(Clone, Copy)]
pub struct VlaAction {
    pub cmd:         u8,
    pub actions:     [i16; 6],
    pub received_at: u64,
    pub valid:       bool,
}

impl VlaAction {
    pub const fn new() -> Self {
        VlaAction {
            cmd:         CMD_NONE,
            actions:     [0; 6],
            received_at: 0,
            valid:       false,
        }
    }
}

/// Goal from the VLA server in natural language.
#[derive(Clone, Copy)]
pub struct VlaGoal {
    pub goal_id:  u32,
    pub text:     [u8; 56],
    pub text_len: u8,
    pub valid:    bool,
}

impl VlaGoal {
    pub const fn new() -> Self {
        VlaGoal {
            goal_id:  0,
            text:     [0; 56],
            text_len: 0,
            valid:    false,
        }
    }
}

/// Motor output from a behavior layer.
#[derive(Clone, Copy)]
pub struct MotorOutput {
    pub speed_l: i32,
    pub speed_r: i32,
    pub valid:   bool,
}

impl MotorOutput {
    pub const fn none() -> Self {
        MotorOutput { speed_l: 0, speed_r: 0, valid: false }
    }

    pub const fn some(speed_l: i32, speed_r: i32) -> Self {
        MotorOutput { speed_l, speed_r, valid: true }
    }
}

/// Output of the behavior arbiter — winning motor command + which layer.
#[derive(Clone, Copy)]
pub struct BehaviorOutput {
    pub cmd:   MotorOutput,
    pub layer: u8,
}

/// MLP inference result passed into the arbiter.
#[derive(Clone, Copy)]
pub struct MlpResult {
    pub class: u8,
    pub valid: bool,
}

impl MlpResult {
    pub const fn none() -> Self {
        MlpResult { class: 0, valid: false }
    }
}

/// Status of a single behavior layer.
#[derive(Clone, Copy)]
pub struct LayerStatus {
    pub layer:   u8,
    pub name:    &'static str,
    pub enabled: bool,
    pub winning: bool,
}
