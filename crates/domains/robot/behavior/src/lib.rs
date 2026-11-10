// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! The robot's behaviour stack as the kernel keeps it: the safety layer's
//! checks and envelope (run by the robot enforcer), the brain protocol's
//! framing and the frames that ask for authority, the payload drivers, the RC
//! receiver's policy, the sensor bus and the layer switches the ring-3
//! behaviour engine (`userspace/services/brain_client`) reads. Choosing a
//! motion is the engine's.

pub mod types;
pub mod switches;
pub mod brain_protocol;
pub mod safety;
// The RC receiver's safety policy (Kconfig `RC_INPUT`).
#[cfg(feature = "rc-input")]
pub mod rc_link;
pub mod sensor_bus;
pub mod payload;
// The flight recorder and the e-stop latch moved to `azos_actuation`
//: they are cross-cutting. Re-exported at their old paths, so
// `crate::logger` / `azos_behavior::logger` keep resolving.
pub use azos_actuation::{estop, logger};

// Re-export public API
pub use types::*;

pub use switches::{layer_mask, layer_set_enabled};
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
