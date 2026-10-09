// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! Subsumption Behavior Engine — Phase G1.
//!
//! Brooks-style layered behavior architecture with 4 priority levels:
//! - L0: emergency-stop  (IMU fall/spin detection, always active)
//! - L1: avoid-obstacle  (local MLP inference, gated by no-ml)
//! - L2: remote-vla      (TCP ↔ external VLA server)
//! - L3: explore          (default wander forward)
//!
//! The arbiter iterates L0→L3; the first layer that returns a valid
//! `MotorOutput` wins and is published to the RT motor task.

pub mod types;
pub mod layers;
pub mod arbiter;
pub mod remote;
pub mod brain_protocol;
pub mod auth_envelope;
pub mod auth_envelope_core;
pub mod encrypt_link;
// Pure policy `encrypt_link` depends on (U09-8/V1.2). Its own module doc
// explains why it is a separate, dependency-free sibling file rather than
// inline in `encrypt_link.rs`: `tests/host/behavior-tests/` needs to
// `#[path]`-include it alone, the same pattern `crates/core/ota/src/pure.rs`
// uses for `tests/host/ota-tests/`.
pub mod encrypt_link_policy;
pub mod brain_tx;
pub mod camera_tx;
pub mod offline;
pub mod safety;
// Wave 15: the RC receiver's safety policy (Kconfig `RC_INPUT`).
#[cfg(feature = "rc-input")]
pub mod rc_link;
pub mod balance;
pub mod sensor_bus;
pub mod skill_profile;
pub mod world_state;
pub mod habit;
pub mod payload;
// The flight recorder and the e-stop latch moved to `azos_actuation`
// (wave 11): they are cross-cutting. Re-exported at their old paths, so
// `crate::logger` / `azos_behavior::logger` keep resolving.
pub use azos_actuation::{estop, logger};
pub mod ml_link;

// Re-export public API
pub use types::*;
pub use skill_profile::{
    SkillId, SkillProfile, SKILL_PROFILES, MAX_SKILLS,
    CPU_BUDGET_TOTAL, SKILL_MAX_CPU_UNITS,
    skill_admit, skill_start, skill_end, skill_profile,
    skill_set_battery_pct, skill_battery_pct, skill_budget_info,
};

pub use world_state::{
    WorldState, WorldSnapshot, WORLD_STATE,
    world_state_read, world_state_write_begin, WorldStateWriteGuard,
};

pub use habit::{
    Habit, HabitTrigger, HABIT_PROMOTE_THRESHOLD, MAX_HABITS, HABIT_MAX_SEQ,
    habit_record, habit_match, habit_prune, habit_stats,
};
pub use arbiter::{
    arbitrate, layer_set_enabled, layer_is_enabled, last_winner,
    layer_statuses, LAYER_NAMES,
};
pub use remote::{
    encode_observation, decode_action_packet, decode_goal_packet,
    remote_configure, remote_set_enabled, remote_is_enabled,
    remote_server_ip, remote_server_port, remote_info, RemoteInfo,
    current_goal, set_current_goal, last_action, set_last_action,
    remote_set_connected, remote_set_socket, remote_socket,
    remote_inc_sent, remote_inc_recv,
    remote_actuation_from, RemoteActuation, REMOTE_PCT_TO_MILLI,
    OBS_TOTAL, ACTION_PACKET_SIZE, GOAL_PACKET_SIZE,
    OBS_MAGIC, ACT_MAGIC, GOAL_MAGIC,
};
pub use brain_protocol::{
    build_packet, parse_packet, crc8,
    encode_sensor_packet, encode_status_packet, decode_actuator_cmd,
    decode_predict_cmd, PredictCmd,
    encode_camera_header,
    decode_mode_cmd, decode_waypoint_cmd, decode_config_cmd,
    ActuatorCmd as BrainActuatorCmd,
    ModeCmd, WaypointCmd, ConfigCmd,
    PKT_SENSOR, PKT_CAMERA, PKT_STATUS, PKT_OTA_ACK,
    PKT_ACTUATOR, PKT_MODE, PKT_WAYPOINT, PKT_CONFIG, PKT_PAYLOAD,
    PKT_OTA_BEGIN, PKT_OTA_CHUNK, PKT_OTA_END, PKT_ESTOP, PKT_PREDICT, PKT_DEGRADE,
    PKT_SEMANTIC_LEVEL,
    ESTOP_REASON_OPERATOR, ESTOP_REASON_SAFETY, ESTOP_REASON_GEOFENCE,
    DEGRADE_CLEAR, DEGRADE_REASON_MALFORMED, DEGRADE_REASON_PERCEPTION_BLIND,
    DEGRADE_REASON_SENSOR_INCOHERENT, DEGRADE_REASON_UNMODELLED_HAZARD,
    OTA_ACK_OK, OTA_ACK_ERROR,
    ROBOT_WHEELED, ROBOT_DRONE, ROBOT_HUMANOID, ROBOT_ACKERMANN,
    FLAG_EMERGENCY, FLAG_ALERT, ACT_DIFF_DRIVE,
    CAMERA_HDR_SIZE, CAMERA_FMT_GRAY8, CAMERA_FMT_JPEG,
    SENSOR_PAYLOAD_SIZE, STATUS_PAYLOAD_SIZE,
    MODE_PAYLOAD_SIZE, WAYPOINT_PAYLOAD_SIZE, CONFIG_PAYLOAD_SIZE,
    PAYLOAD_PAYLOAD_SIZE, PayloadCmd,
    decode_payload_cmd,
    PAYLOAD_TYPE_SPRAY, PAYLOAD_TYPE_GRIPPER, PAYLOAD_TYPE_CAM_TRIGGER,
    PAYLOAD_OFF, PAYLOAD_ON, GRIPPER_OPEN, GRIPPER_CLOSED,
    SENSOR_FRAME_SIZE, STATUS_FRAME_SIZE, FRAME_OVERHEAD,
    // Config keys + values
    CFG_KEY_LED, CFG_KEY_POWER, CFG_KEY_CAMERA, CFG_KEY_WIFI,
    CFG_KEY_LIDAR_HZ, CFG_KEY_BUZZER, CFG_KEY_SIREN,
    CFG_KEY_SPOTLIGHT, CFG_KEY_LASER,
    CFG_KEY_SERVO_PAN, CFG_KEY_SERVO_TILT, CFG_KEY_SPEAKER,
    BUZZER_OFF, BUZZER_BEEP, BUZZER_SIREN,
    CAMERA_PWR_OFF, CAMERA_PWR_ON,
};
