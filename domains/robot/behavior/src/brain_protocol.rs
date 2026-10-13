// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Brain Protocol — binary wire format for Robot ↔ Brain Server communication.
//!
//! Packet frame:
//!   MAGIC[2] | TYPE[1] | LEN[2 LE] | PAYLOAD[0..65535] | CRC8[1]
//!
//! `PAYLOAD` was documented as `[0..1400]` until 2026-09-26: `parse_packet`
//! bounds nothing below the full range of its 2-byte LE length field, and
//! CAMERA_FRAME payloads (a JPEG) routinely exceed 1400 bytes — so 1400 was
//! never the wire limit, only a rough MTU-sized figure for the SENSOR/STATUS
//! packets below. The receive buffer the caller reads into is the real
//! bound; `parse_packet` itself refuses anything `buf` does not actually hold
//! (`buf.len() < total`).
//!
//! Robot → Server (0x01-0x7F):
//!   0x01  SENSOR_PACKET   64 bytes (wheeled: 34B header + 28B payload + 2B flags)
//!   0x02  CAMERA_FRAME    5B header + JPEG
//!   0x03  STATUS          8 bytes
//!
//! Server → Robot (0x80-0xFF):
//!   0x80  ACTUATOR_CMD    3 + 2*N bytes
//!   0x81  MODE_CMD        1 byte
//!   0x82  WAYPOINT_CMD    14 bytes
//!   0x83  CONFIG_CMD      4 bytes (key + value + reserved)
//!
//! SensorPacket common header (34 bytes, little-endian):
//!   timestamp_ms: u64   (8B)
//!   accel_mg[3]:  i32×3 (12B)
//!   gyro_mdps[3]: i32×3 (12B)
//!   battery_mv:   u16   (2B)
//!
//! SensorPacket wheeled extra (30 bytes):
//!   odom_dist_mm:  i32  (4B)
//!   odom_hdg_cdeg: i32  (4B)
//!   encoder_l:     i64  (8B)
//!   encoder_r:     i64  (8B)
//!   range_front:   u16  (2B)
//!   range_right:   u16  (2B)
//!   sensor_flags:  u16  (2B)  — PIR/sound/IR digital trigger flags
//!
//! StatusPacket (8 bytes):
//!   mode:       u8
//!   tasks_ok:   u8
//!   canary_ok:  u8
//!   uptime_s:   u32 LE
//!   robot_type: u8
//!
//! ActuatorCmd payload (3 + 2*N bytes):
//!   actuator_type: u8  (0=diff_drive, 1=quad_rotor, 2=humanoid)
//!   n_channels:    u8
//!   flags:         u8  (bit0=emergency, bit1=alert)
//!   channels:      [i16; N] LE
//!
//! ConfigCmd payload (4 bytes):
//!   config_key: u8   — subsystem selector (LED, buzzer, power, etc.)
//!   value:      u8   — command value
//!   reserved:   u16  — reserved for future use

// RFC-0027 — `#[wcet(...)]` instrumentation.  The macro emits calls gated
// `cfg(target_os = "none")`; under host-test builds (regression-tests pulls
// this file via `#[path]`) those calls disappear, so the macro is safe to
// apply here.
use wcet_macro::wcet;


pub const MAGIC: [u8; 2]       = *b"BR";

// Packet types — Robot → Server
pub const PKT_SENSOR:  u8 = 0x01;
pub const PKT_CAMERA:  u8 = 0x02;
pub const PKT_STATUS:  u8 = 0x03;

// Packet types — Robot → Server (OTA)
pub const PKT_OTA_ACK:  u8 = 0x04;

/// Compact 20-byte sensor frame for E02 LoRa / low-bandwidth links.
/// Must stay in lockstep with `protocol.SensorCompact` in AzOSRobotBrain.
/// Wire layout (`<iiHHBBHH>` = 20 bytes, little-endian):
///   - `lat_deg7`:     i32  — latitude × 1e7
///   - `lon_deg7`:     i32  — longitude × 1e7
///   - `alt_cm`:       u16  — altitude in cm
///   - `battery_mv`:   u16  — battery voltage in mV
///   - `mode`:         u8   — robot mode byte
///   - `gps_fix`:      u8   — GPS fix quality
///   - `speed_cms`:    u16  — ground speed in cm/s
///   - `heading_cdeg`: u16  — heading in centi-degrees
/// (A previous comment here mis-documented the layout as
/// pos_x_mm/pos_y_mm/dist_front/batt_pct/flags/ts_ms — that was wrong and
/// would mislead any future LoRa encoder; this is the authoritative layout
/// matching `AzOSRobotBrain/protocol.py:361`.)
pub const PKT_SENSOR_COMPACT: u8 = 0x05;

/// RFC-0039: capability declaration, both directions. **Reserved, not yet
/// sent or handled** — the number is claimed so a future implementation and a
/// current build cannot disagree about what 0x06 means.
///
/// Payload will be `epoch u8 | n u8 | types [u8; n]`: the packet types this
/// side both parses and ACTS ON. That distinction is the point — this tree
/// decodes `PKT_WAYPOINT` and the three OTA types and dispatches none of them,
/// so from a sender's side they are as ineffective as a type that does not
/// exist, and must not be declared.
///
/// Until it is implemented, an arriving 0x06 is recorded by the same
/// `SAFETY_UNKNOWN_PKT` path as any other type this build does not act on,
/// which is exactly the visibility this RFC exists to add.
pub const PKT_CAPS: u8 = 0x06;

// Packet types — Server → Robot
pub const PKT_ACTUATOR:  u8 = 0x80;
pub const PKT_MODE:      u8 = 0x81;
pub const PKT_WAYPOINT:  u8 = 0x82;
pub const PKT_CONFIG:    u8 = 0x83;
pub const PKT_OTA_BEGIN: u8 = 0x84;
pub const PKT_OTA_CHUNK: u8 = 0x85;
pub const PKT_OTA_END:   u8 = 0x86;
/// E04: Brain → Robot: control an attached payload (spray, gripper, cam trigger).
pub const PKT_PAYLOAD:   u8 = 0x87;
pub const PKT_ESTOP:     u8 = 0x88;
/// RFC-0034: Brain → Robot speculative-actuation prediction. Carries the brain's
/// predicted NEXT actuator command + a confidence byte, so the kernel can act on
/// it ahead of the confirmed command (gated by the Fase-1 safety envelope and the
/// `SPECULATIVE_ACTUATION` config, default off). Payload = ActuatorCmd bytes
/// followed by one confidence byte (0..=255; 255 = certain).
pub const PKT_PREDICT:   u8 = 0x89;
/// RFC-0036: Brain → Robot degraded-mode trigger. The brain arms degraded mode
/// when it detects a situational hazard only it can perceive (most concretely:
/// perception has failed for several cycles — it has gone blind). In degraded
/// mode the kernel contains the userspace blast radius (every write/actuation
/// through a user-task capability is denied at the `CapTable::get` chokepoint),
/// while the in-kernel control loop keeps running and safe-stops as normal.
/// Payload = 1 reason byte (`DEGRADE_*`); reason 0 = clear.
pub const PKT_DEGRADE:         u8 = 0x8A;
/// RFC-0037: Brain → Robot graded semantic-level command. Selects an ordered
/// restriction level (0 = FULL / normal … 3 = CONTAINED / stop + cap-denial).
/// Payload = 1 byte: the level index. Out-of-range index → kernel clamps to
/// CONTAINED (fail-closed). The level is sticky until changed; comms-loss
/// safe-stop is provided by the existing motor watchdog (500 ms).
pub const PKT_SEMANTIC_LEVEL: u8 = 0x8B;

// Robot types
pub const ROBOT_WHEELED:   u8 = 0;
pub const ROBOT_DRONE:     u8 = 1;
pub const ROBOT_HUMANOID:  u8 = 2;
pub const ROBOT_ACKERMANN: u8 = 3;

// ActuatorCmd flags
pub const FLAG_EMERGENCY: u8 = 0x01;
pub const FLAG_ALERT:     u8 = 0x02;
/// RFC-0035: the brain marks a command as low-confidence (e.g. a reactive-LLM
/// action vs a deterministic scripted/plan step). The kernel tightens the motor
/// envelope for low-confidence commands (confidence-aware real-time).
pub const FLAG_LOW_CONFIDENCE: u8 = 0x04;

// ESTOP reason codes (PKT_ESTOP payload byte 0)
pub const ESTOP_REASON_OPERATOR:  u8 = 0;
pub const ESTOP_REASON_SAFETY:    u8 = 1;
pub const ESTOP_REASON_GEOFENCE:  u8 = 2;

// DEGRADE reason codes (PKT_DEGRADE payload byte 0). Reason 0 clears degraded
// mode (brain recovered); any non-zero reason arms it. RFC-0036.
pub const DEGRADE_CLEAR:                  u8 = 0;
pub const DEGRADE_REASON_PERCEPTION_BLIND: u8 = 1;
pub const DEGRADE_REASON_SENSOR_INCOHERENT: u8 = 2;
pub const DEGRADE_REASON_UNMODELLED_HAZARD: u8 = 3;
/// A `PKT_DEGRADE` arrived with no reason byte at all (RFC-0039 fail-closed).
///
/// The handler used to read `unwrap_or(DEGRADE_CLEAR)`, so a truncated frame
/// DISARMED containment — and because `degraded_set` writes the same atomic as
/// the graded degrade level, it also reset a `CONTAINED` level to `FULL`. The
/// sibling `PKT_SEMANTIC_LEVEL`, given the same malformed input on the same
/// atomic, fails closed. Two handlers, one piece of state, opposite answers.
///
/// A distinct value rather than reusing an existing reason, so the flight
/// recorder can tell "the brain said the sensors are incoherent" from "we
/// could not read what the brain said".
pub const DEGRADE_REASON_MALFORMED: u8 = 0xFF;

// OTA ACK status codes (PKT_OTA_ACK payload byte 0)
pub const OTA_ACK_OK:    u8 = 0;
pub const OTA_ACK_ERROR: u8 = 1;

// Actuator types
pub const ACT_DIFF_DRIVE: u8 = 0;

// Camera header: width(u16 LE) + height(u16 LE) + format(u8) = 5 bytes
pub const CAMERA_HDR_SIZE: usize = 5;
pub const CAMERA_FMT_GRAY8: u8 = 0;
pub const CAMERA_FMT_JPEG:  u8 = 1;

// ── Config keys (CONFIG_CMD config_key field) ───────────────────────────────

/// LED state control.
pub const CFG_KEY_LED:       u8 = 0x10;
/// Power mode (ECO / ALERT).
pub const CFG_KEY_POWER:     u8 = 0x11;
/// Camera power GPIO (on / off).
pub const CFG_KEY_CAMERA:    u8 = 0x12;
/// ESP32 WiFi sleep mode (batch / continuous).
pub const CFG_KEY_WIFI:      u8 = 0x13;
/// LiDAR scan rate in Hz.
pub const CFG_KEY_LIDAR_HZ:  u8 = 0x14;
/// Buzzer pattern.
pub const CFG_KEY_BUZZER:    u8 = 0x15;
/// Siren module (12V MOSFET).
pub const CFG_KEY_SIREN:     u8 = 0x16;
/// LED 10W COB spotlight (MOSFET).
pub const CFG_KEY_SPOTLIGHT: u8 = 0x17;
/// Green laser 532nm (MOSFET).
pub const CFG_KEY_LASER:     u8 = 0x18;
/// Pan servo angle (0-180 degrees).
pub const CFG_KEY_SERVO_PAN: u8 = 0x19;
/// Tilt servo angle (0-180 degrees).
pub const CFG_KEY_SERVO_TILT: u8 = 0x1A;
/// Speaker / amplifier audio file ID.
pub const CFG_KEY_SPEAKER:   u8 = 0x1B;

// ── LED state codes ─────────────────────────────────────────────────────────

#[allow(dead_code)] pub const LED_OFF:          u8 = 0x00;
#[allow(dead_code)] pub const LED_GREEN:        u8 = 0x01;
#[allow(dead_code)] pub const LED_GREEN_BLINK:  u8 = 0x02;
#[allow(dead_code)] pub const LED_YELLOW:       u8 = 0x03;
#[allow(dead_code)] pub const LED_YELLOW_BLINK: u8 = 0x04;
#[allow(dead_code)] pub const LED_RED:          u8 = 0x05;
#[allow(dead_code)] pub const LED_RED_BLINK:    u8 = 0x06;
#[allow(dead_code)] pub const LED_RED_STROBE:   u8 = 0x07;
#[allow(dead_code)] pub const LED_BLUE:         u8 = 0x08;
#[allow(dead_code)] pub const LED_BLUE_BLINK:   u8 = 0x09;
#[allow(dead_code)] pub const LED_WHITE_FLASH:  u8 = 0x0A;

// ── Buzzer patterns ─────────────────────────────────────────────────────────

pub const BUZZER_OFF:   u8 = 0x00;
pub const BUZZER_BEEP:  u8 = 0x01;
pub const BUZZER_SIREN: u8 = 0x02;
#[allow(dead_code)] pub const BUZZER_CHIRP: u8 = 0x03;

// ── Power modes ─────────────────────────────────────────────────────────────

#[allow(dead_code)] pub const POWER_ECO:   u8 = 0x00;
#[allow(dead_code)] pub const POWER_ALERT: u8 = 0x01;

// ── Camera power ────────────────────────────────────────────────────────────

pub const CAMERA_PWR_OFF: u8 = 0x00;
pub const CAMERA_PWR_ON:  u8 = 0x01;

// ── WiFi modes ──────────────────────────────────────────────────────────────

#[allow(dead_code)] pub const WIFI_BATCH:      u8 = 0x00;
#[allow(dead_code)] pub const WIFI_CONTINUOUS: u8 = 0x01;

// ── Device on/off (siren, spotlight, laser) ─────────────────────────────────

#[allow(dead_code)] pub const DEVICE_OFF:       u8 = 0x00;
#[allow(dead_code)] pub const DEVICE_ON:        u8 = 0x01;
#[allow(dead_code)] pub const SPOTLIGHT_STROBE: u8 = 0x02;

// ── Speaker audio IDs ───────────────────────────────────────────────────────

#[allow(dead_code)] pub const SPEAKER_STOP:     u8 = 0x00;
#[allow(dead_code)] pub const SPEAKER_WARNING:  u8 = 0x01;
#[allow(dead_code)] pub const SPEAKER_DOG_BARK: u8 = 0x02;
#[allow(dead_code)] pub const SPEAKER_SIREN_FX: u8 = 0x03;

// ── Digital sensor flags (u16 bit flags in sensor_flags field) ──────────────

#[allow(dead_code)] pub const SENSOR_FLAG_PIR:   u16 = 0x0001;
#[allow(dead_code)] pub const SENSOR_FLAG_SOUND: u16 = 0x0002;
#[allow(dead_code)] pub const SENSOR_FLAG_IR:    u16 = 0x0004;

// Payload sizes
pub const SENSOR_PAYLOAD_SIZE: usize = 64;   // 34 header + 28 wheeled + 2 flags
pub const STATUS_PAYLOAD_SIZE: usize = 8;
// Frame overhead: MAGIC(2) + TYPE(1) + LEN(2) + CRC(1) = 6
pub const FRAME_OVERHEAD: usize = 6;

pub const SENSOR_FRAME_SIZE: usize = SENSOR_PAYLOAD_SIZE + FRAME_OVERHEAD;  // 70
pub const STATUS_FRAME_SIZE: usize = STATUS_PAYLOAD_SIZE + FRAME_OVERHEAD;  // 14

/// Maximum channels in an ActuatorCmd.
pub const MAX_CHANNELS: usize = 8;

// ── ActuatorCmd ───────────────────────────────────────────────────────────────

/// Decoded actuator command from the Brain Server.
#[derive(Clone, Copy)]
pub struct ActuatorCmd {
    pub actuator_type: u8,
    pub n_channels:    u8,
    pub flags:         u8,
    pub channels:      [i16; MAX_CHANNELS],
}

impl ActuatorCmd {
    pub const fn zeroed() -> Self {
        ActuatorCmd {
            actuator_type: ACT_DIFF_DRIVE,
            n_channels:    0,
            flags:         0,
            channels:      [0i16; MAX_CHANNELS],
        }
    }

    pub fn is_emergency(&self) -> bool {
        self.flags & FLAG_EMERGENCY != 0
    }

    /// RFC-0035: whether the brain marked this command low-confidence (the kernel
    /// tightens the motor envelope when set).
    pub fn is_low_confidence(&self) -> bool {
        self.flags & FLAG_LOW_CONFIDENCE != 0
    }

    /// For differential drive: (speed_l, speed_r) as i32, clamped -100..100.
    pub fn diff_drive(&self) -> (i32, i32) {
        if self.n_channels >= 2 {
            let l = (self.channels[0] as i32).clamp(-100, 100);
            let r = (self.channels[1] as i32).clamp(-100, 100);
            (l, r)
        } else {
            (0, 0)
        }
    }
}

// ── CRC-8/MAXIM (polynomial 0x31) ────────────────────────────────────────────

pub fn crc8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0x00;
    for &b in data {
        crc ^= b;
        for _ in 0..8 {
            if crc & 0x80 != 0 {
                crc = crc.wrapping_shl(1) ^ 0x31;
            } else {
                crc = crc.wrapping_shl(1);
            }
        }
    }
    crc
}

// ── Frame builder ─────────────────────────────────────────────────────────────

/// Build a framed packet into `out`.
///
/// `out` must be at least `payload.len() + 6` bytes.
/// Returns the total bytes written.
pub fn build_packet(pkt_type: u8, payload: &[u8], out: &mut [u8]) -> usize {
    let len = payload.len();
    // Header: MAGIC + TYPE + LEN(LE)
    out[0] = MAGIC[0];
    out[1] = MAGIC[1];
    out[2] = pkt_type;
    out[3] = (len & 0xFF) as u8;
    out[4] = (len >> 8) as u8;
    // Payload
    out[5..5 + len].copy_from_slice(payload);
    // CRC over header + payload
    let crc = crc8(&out[..5 + len]);
    out[5 + len] = crc;
    6 + len
}

// ── Frame parser ──────────────────────────────────────────────────────────────

/// Parse one packet from `buf`.
///
/// Returns `Some((pkt_type, payload_start, payload_len, total_consumed))`
/// or `None` if the buffer is incomplete or corrupt.
#[wcet(50_us)]
pub fn parse_packet(buf: &[u8]) -> Option<(u8, usize, usize, usize)> {
    if buf.len() < 6 { return None; }
    if buf[0] != MAGIC[0] || buf[1] != MAGIC[1] { return None; }
    let pkt_type = buf[2];
    let length   = (buf[3] as usize) | ((buf[4] as usize) << 8);
    let total    = 5 + length + 1;
    if buf.len() < total { return None; }
    // CRC check: header (5B) + payload (lengthB)
    let expected = crc8(&buf[..5 + length]);
    if buf[5 + length] != expected { return None; }
    // Payload starts at offset 5
    Some((pkt_type, 5, length, total))
}

// ── SensorPacket encoder ──────────────────────────────────────────────────────

/// Encode a wheeled SensorPacket payload (64 bytes) into `buf`.
#[allow(clippy::too_many_arguments)]
pub fn encode_sensor_packet(
    buf:            &mut [u8; SENSOR_PAYLOAD_SIZE],
    timestamp_ms:   u64,
    accel_mg:       [i32; 3],
    gyro_mdps:      [i32; 3],
    battery_mv:     u16,
    odom_dist_mm:   i32,
    odom_hdg_cdeg:  i32,
    encoder_l:      i64,
    encoder_r:      i64,
    range_front_mm: u16,
    range_right_mm: u16,
    sensor_flags:   u16,
) {
    // ── Common header (34 bytes) ──────────────────────────────────────────────
    put_u64(buf, 0,  timestamp_ms);
    put_i32(buf, 8,  accel_mg[0]);
    put_i32(buf, 12, accel_mg[1]);
    put_i32(buf, 16, accel_mg[2]);
    put_i32(buf, 20, gyro_mdps[0]);
    put_i32(buf, 24, gyro_mdps[1]);
    put_i32(buf, 28, gyro_mdps[2]);
    put_u16(buf, 32, battery_mv);
    // ── Wheeled payload (28 bytes at offset 34) ───────────────────────────────
    put_i32(buf, 34, odom_dist_mm);
    put_i32(buf, 38, odom_hdg_cdeg);
    put_i64(buf, 42, encoder_l);
    put_i64(buf, 50, encoder_r);
    put_u16(buf, 58, range_front_mm);
    put_u16(buf, 60, range_right_mm);
    // ── Digital sensor flags (2 bytes at offset 62) ───────────────────────────
    put_u16(buf, 62, sensor_flags);
}

// ── StatusPacket encoder ──────────────────────────────────────────────────────

/// Encode a StatusPacket payload (8 bytes) into `buf`.
pub fn encode_status_packet(
    buf:        &mut [u8; STATUS_PAYLOAD_SIZE],
    mode:       u8,
    tasks_ok:   u8,
    canary_ok:  u8,
    uptime_s:   u32,
    robot_type: u8,
) {
    buf[0] = mode;
    buf[1] = tasks_ok;
    buf[2] = canary_ok;
    put_u32(buf, 3, uptime_s);
    buf[7] = robot_type;
}

// ── ActuatorCmd decoder ───────────────────────────────────────────────────────

/// Decode an ActuatorCmd from the payload bytes of a `PKT_ACTUATOR` packet.
///
/// Returns `None` if payload is too short.
pub fn decode_actuator_cmd(payload: &[u8]) -> Option<ActuatorCmd> {
    if payload.len() < 3 { return None; }
    let actuator_type = payload[0];
    let n             = payload[1] as usize;
    let flags         = payload[2];
    if payload.len() < 3 + n * 2 { return None; }

    let mut channels = [0i16; MAX_CHANNELS];
    let n_clamped    = n.min(MAX_CHANNELS);
    for i in 0..n_clamped {
        channels[i] = i16::from_le_bytes([payload[3 + i * 2], payload[3 + i * 2 + 1]]);
    }

    Some(ActuatorCmd {
        actuator_type,
        n_channels: n_clamped as u8,
        flags,
        channels,
    })
}

// ── PredictCmd decoder (RFC-0034 speculative actuation) ───────────────────────

/// A predicted next actuator command plus the brain's confidence in it.
#[derive(Clone, Copy)]
pub struct PredictCmd {
    /// The predicted next command.
    pub cmd: ActuatorCmd,
    /// Confidence 0..=255 (255 = certain; e.g. a deterministic scripted step).
    pub confidence: u8,
}

/// Decode a `PKT_PREDICT` payload = `ActuatorCmd` bytes followed by one
/// confidence byte. Returns `None` if malformed. The kernel uses this only as a
/// hint, gated by the safety envelope and `SPECULATIVE_ACTUATION` (default off);
/// a malformed or absent prediction simply means no speculation.
pub fn decode_predict_cmd(payload: &[u8]) -> Option<PredictCmd> {
    if payload.is_empty() { return None; }
    // The confidence byte is the last byte; the rest is the ActuatorCmd.
    let (cmd_bytes, conf) = payload.split_at(payload.len() - 1);
    let cmd = decode_actuator_cmd(cmd_bytes)?;
    Some(PredictCmd { cmd, confidence: conf[0] })
}

// ── Camera frame encoder ─────────────────────────────────────────────────

/// Encode the 5-byte camera header into `hdr_buf`.
///
/// Format: width(u16 LE) + height(u16 LE) + pixel_format(u8)
pub fn encode_camera_header(hdr_buf: &mut [u8; CAMERA_HDR_SIZE], width: u16, height: u16, fmt: u8) {
    put_u16(hdr_buf, 0, width);
    put_u16(hdr_buf, 2, height);
    hdr_buf[4] = fmt;
}

// ── ModeCmd ─────────────────────────────────────────────────────────────────

/// Payload size for MODE_CMD: 1 byte (mode_id).
pub const MODE_PAYLOAD_SIZE: usize = 1;

/// Reserved `mode_id`: the ONLY value that may clear an armed e-stop, or exit
/// degraded mode, via `PKT_MODE` (owner decision, 2026-09-06). Every other
/// mode id changes mode and must leave both containment states exactly as
/// they were.
///
/// `PKT_ESTOP` only ever ARMS — grep its handlers — so `PKT_MODE` is the only
/// rearm path in this tree. Before this constant existed, `decode_mode_cmd`
/// handed back an unchecked byte and the two `kernel/src/tasks/behavior.rs` dispatch
/// sites cleared on ANY value, with no `mode_id` defined anywhere to check
/// against.
///
/// Not `0`: a truncated payload, or a buffer that was zeroed and never
/// actually filled in, reads as `0` by default — `0` would let the single
/// most common malformed-frame case rearm the robot. Not a small value like
/// `1` or `2` either: those are the values most likely to be the first "real"
/// mode ids a brain implementation assigns, so claiming one as the reset
/// sentinel would collide with an actual operating mode the moment one is
/// defined. `0xFF` sits at the far end of the byte range, away from where
/// sequential mode ids will be allocated, cannot arise from a zeroed or
/// short/truncated payload, and matches the convention this protocol already
/// uses for a reserved/sentinel byte (see `DEGRADE_REASON_MALFORMED`, also
/// `0xFF`, above).
///
/// Must stay in lockstep with `MODE_ID_ESTOP_RESET` in
/// `AzOSRobotBrain/protocol.py`.
pub const MODE_ID_ESTOP_RESET: u8 = 0xFF;

/// Decoded mode command from the Brain Server.
#[derive(Clone, Copy, Debug)]
pub struct ModeCmd {
    pub mode_id: u8,
}

/// Decode a ModeCmd from the payload bytes of a `PKT_MODE` packet.
///
/// Returns `None` if payload is too short.
pub fn decode_mode_cmd(payload: &[u8]) -> Option<ModeCmd> {
    if payload.len() < MODE_PAYLOAD_SIZE { return None; }
    Some(ModeCmd { mode_id: payload[0] })
}

/// Whether a `PKT_MODE` mode id is the reserved one that is allowed to clear
/// e-stop / degraded-mode containment.
///
/// A pure predicate so the two `kernel/src/tasks/behavior.rs` dispatch sites — the TCP
/// brain link and the `feature = "vf2"` UART bridge, which is compiled out of
/// every QEMU build — and the host tests all share one answer, instead of two
/// (or three) copies of the same comparison that can silently drift apart.
pub fn mode_clears_containment(mode_id: u8) -> bool {
    mode_id == MODE_ID_ESTOP_RESET
}

/// Decide what a `PKT_MODE` arrival should do to an armed e-stop, and what to
/// tell the flight recorder.
///
/// Returns `None` when the e-stop is not currently armed — there is nothing
/// to clear and nothing to refuse, so nothing is recorded either. Returns
/// `Some((should_clear, action_code))` when it is: the caller MUST call
/// `estop_deactivate()` iff `should_clear` is true, and MUST pass
/// `action_code` to [`crate::logger::log_safety_violation_durable`] with
/// `SAFETY_ESTOP` either way.
///
/// This exists, and is not left as an inline `if` at each call site, for the
/// same reason [`crate::logger::semantic_level_record`] exists: the kernel
/// takes `PKT_MODE` on two dispatch sites that both need the identical
/// answer, and neither call site is itself reachable from a host test — both
/// live inside `kernel`'s `no_std` binary. A test that calls this function is
/// pinning the actual decision the dispatch sites make; a test that
/// re-derives the same `if` locally would still pass if a future edit
/// deleted the gate from `kernel/src/tasks/behavior.rs` and left `mode_clears_containment`
/// untouched.
///
/// `action_code` 3 = cleared, 4 = refused (distinct from the 0/1/2 that the
/// three activation sources — TCP, UART, GPIO — already pass for this event
/// code; see the doc comment on `SAFETY_ESTOP` in `logger.rs`).
pub fn mode_estop_record(mode_id: u8, estop_armed: bool) -> Option<(bool, u8)> {
    if !estop_armed {
        return None;
    }
    if mode_clears_containment(mode_id) {
        Some((true, 3))
    } else {
        Some((false, 4))
    }
}

// `refusal_is_worth_recording` and `relatched_within_window` moved with the
// latch to `azos_actuation::estop` (wave 11), their only caller.

/// Decide what a `PKT_MODE` arrival should do to degraded mode (RFC-0036),
/// and what to tell the flight recorder.
///
/// Same shape and same reasoning as [`mode_estop_record`], for the sibling
/// piece of state this same handler touches — see the gate's doc comment in
/// `kernel/src/tasks/behavior.rs` for why degraded-mode clearing is gated on the SAME reserved id.
/// Returns `None` when degraded mode is not currently active. Returns
/// `Some((should_clear, action_code, detail))` when it is: the caller MUST
/// call `degraded_set(false)` iff `should_clear` is true, and MUST pass
/// `action_code`/`detail` to [`crate::logger::log_safety_violation`] with
/// `SAFETY_DEGRADE` either way.
///
/// `action_code` 0 = now full authority (matches the `PKT_DEGRADE` clear
/// path, `detail` 1 marks the source as MODE rather than DEGRADE); 2 =
/// refused, `detail` carries the mode id that was rejected.
pub fn mode_degrade_record(mode_id: u8, degraded_active: bool) -> Option<(bool, u8, u32)> {
    if !degraded_active {
        return None;
    }
    if mode_clears_containment(mode_id) {
        Some((true, 0, 1))
    } else {
        Some((false, 2, mode_id as u32))
    }
}

// ── WaypointCmd ─────────────────────────────────────────────────────────────

/// Payload size for WAYPOINT_CMD: 14 bytes.
///   lat_deg7(i32) + lon_deg7(i32) + alt_cm(u16) + speed_cms(u16) + action(u8) + flags(u8)
pub const WAYPOINT_PAYLOAD_SIZE: usize = 14;

// Field offsets within WaypointCmd payload
const WP_OFF_LAT:       usize = 0;
const WP_OFF_LON:       usize = 4;
const WP_OFF_ALT:       usize = 8;
const WP_OFF_SPEED:     usize = 10;
const WP_OFF_ACTION:    usize = 12;
const WP_OFF_FLAGS:     usize = 13;

/// Decoded waypoint command from the Brain Server.
#[derive(Clone, Copy, Debug)]
pub struct WaypointCmd {
    pub lat_deg7:  i32,   // latitude × 1e7
    pub lon_deg7:  i32,   // longitude × 1e7
    pub alt_cm:    u16,   // altitude in cm
    pub speed_cms: u16,   // speed in cm/s
    pub action:    u8,    // action at waypoint
    pub flags:     u8,    // waypoint flags
}

/// Decode a WaypointCmd from the payload bytes of a `PKT_WAYPOINT` packet.
///
/// Returns `None` if payload is too short.
pub fn decode_waypoint_cmd(payload: &[u8]) -> Option<WaypointCmd> {
    if payload.len() < WAYPOINT_PAYLOAD_SIZE { return None; }
    Some(WaypointCmd {
        lat_deg7:  get_i32(payload, WP_OFF_LAT),
        lon_deg7:  get_i32(payload, WP_OFF_LON),
        alt_cm:    get_u16(payload, WP_OFF_ALT),
        speed_cms: get_u16(payload, WP_OFF_SPEED),
        action:    payload[WP_OFF_ACTION],
        flags:     payload[WP_OFF_FLAGS],
    })
}

// ── ConfigCmd ───────────────────────────────────────────────────────────────

/// Total payload size for CONFIG_CMD: key(1) + value(1) + reserved(2) = 4 bytes.
pub const CONFIG_PAYLOAD_SIZE: usize = 4;

// Field offsets within ConfigCmd payload
const CFG_OFF_KEY:      usize = 0;
const CFG_OFF_VALUE:    usize = 1;
const CFG_OFF_RESERVED: usize = 2;

/// Decoded config command from the Brain Server.
///
/// 4-byte format: config_key(u8) + value(u8) + reserved(u16 LE).
#[derive(Clone, Copy, Debug)]
pub struct ConfigCmd {
    pub config_key: u8,
    pub value:      u8,
    pub reserved:   u16,
}

/// Decode a ConfigCmd from the payload bytes of a `PKT_CONFIG` packet.
///
/// Returns `None` if payload is too short.
pub fn decode_config_cmd(payload: &[u8]) -> Option<ConfigCmd> {
    if payload.len() < CONFIG_PAYLOAD_SIZE { return None; }
    Some(ConfigCmd {
        config_key: payload[CFG_OFF_KEY],
        value:      payload[CFG_OFF_VALUE],
        reserved:   get_u16(payload, CFG_OFF_RESERVED),
    })
}

// ── PayloadCmd (E04) ────────────────────────────────────────────────────────

/// Payload type: spray pump (GPIO on/off).
pub const PAYLOAD_TYPE_SPRAY:       u8 = 0;
/// Payload type: gripper servo (0=closed … 100=open).
pub const PAYLOAD_TYPE_GRIPPER:     u8 = 1;
/// Payload type: external camera shutter trigger (GPIO pulse).
pub const PAYLOAD_TYPE_CAM_TRIGGER: u8 = 2;

/// Generic off state for spray / digital payloads.
pub const PAYLOAD_OFF: u8 = 0;
/// Generic on state for spray / digital payloads.
pub const PAYLOAD_ON:  u8 = 1;

/// Gripper: fully open (value=100).
pub const GRIPPER_OPEN:   u8 = 100;
/// Gripper: fully closed (value=0).
pub const GRIPPER_CLOSED: u8 = 0;

/// Total payload size for PKT_PAYLOAD:
/// payload_type(1) + channel(1) + value(1) + duration_ms(2 LE) = 5 bytes.
pub const PAYLOAD_PAYLOAD_SIZE: usize = 5;

const PL_OFF_TYPE:     usize = 0;
const PL_OFF_CHANNEL:  usize = 1;
const PL_OFF_VALUE:    usize = 2;
const PL_OFF_DURATION: usize = 3;

/// Decoded payload command from the Brain Server.
#[derive(Clone, Copy, Debug)]
pub struct PayloadCmd {
    /// Which payload type (PAYLOAD_TYPE_*).
    pub payload_type: u8,
    /// Which device index (0 = first of that type).
    pub channel:      u8,
    /// Command value: 0/1 for on/off; 0-100 for gripper position.
    pub value:        u8,
    /// Optional duration (ms); 0 = indefinite / one-shot.
    pub duration_ms:  u16,
}

/// Decode a PayloadCmd from the payload bytes of a `PKT_PAYLOAD` packet.
///
/// Returns `None` if the payload is too short.
pub fn decode_payload_cmd(payload: &[u8]) -> Option<PayloadCmd> {
    if payload.len() < PAYLOAD_PAYLOAD_SIZE { return None; }
    Some(PayloadCmd {
        payload_type: payload[PL_OFF_TYPE],
        channel:      payload[PL_OFF_CHANNEL],
        value:        payload[PL_OFF_VALUE],
        duration_ms:  get_u16(payload, PL_OFF_DURATION),
    })
}

// ── Little-endian helpers ─────────────────────────────────────────────────────

// All these emit a single store on RV64 once the optimiser sees the
// slice operation. The hand-rolled byte-by-byte version had to retain
// per-byte bounds checks in some build configurations.

#[inline]
fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

#[inline]
fn put_i32(buf: &mut [u8], off: usize, v: i32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[inline]
fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[inline]
fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    let b = v.to_le_bytes();
    for i in 0..8 { buf[off + i] = b[i]; }
}

#[inline]
fn put_i64(buf: &mut [u8], off: usize, v: i64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

// ── Little-endian reader helpers ─────────────────────────────────────────────

#[inline]
fn get_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn get_i32(buf: &[u8], off: usize) -> i32 {
    i32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}
