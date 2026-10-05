// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! Telemetry protocol — binary robot↔server communication (Phase L).
//!
//! Defines packet types for bidirectional communication between the
//! robot (RISC-V) and the ground station server.
//!
//! # Protocol
//!
//! All packets have an 8-byte header:
//! ```text
//! [magic:4][length:2][type:1][seq:1]
//! ```
//! Followed by payload, then a 1-byte CRC-8.
//!
//! Robot → Server: magic = "TLMR"
//! Server → Robot: magic = "CMDS"
//!
//! # Packet Types (Robot → Server)
//!
//! - `TELEM_ATTITUDE` (0x01): attitude + GPS + mode, 10 Hz
//! - `TELEM_SENSORS`  (0x02): raw IMU + baro + distances, 5 Hz
//! - `TELEM_STATUS`   (0x03): task health + config summary, 1 Hz
//!
//! # Packet Types (Server → Robot)
//!
//! - `CMD_ARM`        (0x10): arm/disarm motors
//! - `CMD_MODE`       (0x11): set flight mode
//! - `CMD_TARGET`     (0x12): attitude/throttle target
//! - `CMD_WAYPOINT`   (0x13): mission waypoint upload
//! - `CMD_CONFIG`     (0x14): update config key remotely

// ── Magic bytes ─────────────────────────────────────────────────────────────

/// Robot → Server packet magic.
pub const TELEM_MAGIC: [u8; 4] = *b"TLMR";
/// Server → Robot packet magic.
pub const CMD_MAGIC: [u8; 4] = *b"CMDS";

// ── Packet types ────────────────────────────────────────────────────────────

pub const TELEM_ATTITUDE: u8 = 0x01;
pub const TELEM_SENSORS:  u8 = 0x02;
pub const TELEM_STATUS:   u8 = 0x03;

pub const CMD_ARM:      u8 = 0x10;
pub const CMD_MODE:     u8 = 0x11;
pub const CMD_TARGET:   u8 = 0x12;
pub const CMD_WAYPOINT: u8 = 0x13;
pub const CMD_CONFIG:   u8 = 0x14;

// ── Header ──────────────────────────────────────────────────────────────────

/// Packet header size.
pub const HEADER_SIZE: usize = 8;
/// CRC size.
pub const CRC_SIZE: usize = 1;

/// Packet header.
#[derive(Clone, Copy)]
pub struct Header {
    pub magic: [u8; 4],
    pub length: u16,
    pub pkt_type: u8,
    pub seq: u8,
}

impl Header {
    /// Serialize header to buffer.  Returns 8.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        if buf.len() < HEADER_SIZE { return 0; }
        buf[0..4].copy_from_slice(&self.magic);
        buf[4] = (self.length & 0xFF) as u8;
        buf[5] = (self.length >> 8) as u8;
        buf[6] = self.pkt_type;
        buf[7] = self.seq;
        HEADER_SIZE
    }

    /// Parse header from buffer.
    pub fn parse(buf: &[u8]) -> Option<Header> {
        if buf.len() < HEADER_SIZE { return None; }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buf[0..4]);
        Some(Header {
            magic,
            length: buf[4] as u16 | ((buf[5] as u16) << 8),
            pkt_type: buf[6],
            seq: buf[7],
        })
    }
}

// ── CRC-8 ───────────────────────────────────────────────────────────────────

/// CRC-8/MAXIM (polynomial 0x31, init 0x00).
pub fn crc8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            if crc & 0x80 != 0 {
                crc = (crc << 1) ^ 0x31;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ── Telemetry serialization (Robot → Server) ────────────────────────────────

/// Sequence counter for outgoing telemetry.
static mut TELEM_SEQ: u8 = 0;

fn next_seq() -> u8 {
    unsafe {
        let s = TELEM_SEQ;
        TELEM_SEQ = s.wrapping_add(1);
        s
    }
}

/// Write a little-endian i32 to buffer.
fn put_i32(buf: &mut [u8], offset: usize, val: i32) {
    let bytes = val.to_le_bytes();
    buf[offset..offset + 4].copy_from_slice(&bytes);
}

/// Write a little-endian u16 to buffer.
#[allow(dead_code)]
fn put_u16(buf: &mut [u8], offset: usize, val: u16) {
    let bytes = val.to_le_bytes();
    buf[offset..offset + 2].copy_from_slice(&bytes);
}

/// Read a little-endian i32 from buffer.
fn get_i32(buf: &[u8], offset: usize) -> i32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[offset..offset + 4]);
    i32::from_le_bytes(bytes)
}

/// Read a little-endian u16 from buffer.
fn get_u16(buf: &[u8], offset: usize) -> u16 {
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&buf[offset..offset + 2]);
    u16::from_le_bytes(bytes)
}

/// Serialize TELEM_ATTITUDE packet.
///
/// Payload (28 bytes):
/// - roll_cdeg: i32
/// - pitch_cdeg: i32
/// - yaw_cdeg: i32
/// - alt_cm: i32
/// - lat_deg7: i32
/// - lon_deg7: i32
/// - flight_mode: u8
/// - armed: u8
/// - sats: u8
/// - fix: u8
///
/// Total: header(8) + payload(28) + crc(1) = 37 bytes.
pub fn serialize_attitude(
    buf: &mut [u8],
    att: &azos_ahrs::Attitude,
    gps: &azos_gps::GpsPosition,
    mode: u8,
    armed: bool,
) -> usize {
    const PAYLOAD_LEN: usize = 28;
    let total = HEADER_SIZE + PAYLOAD_LEN + CRC_SIZE;
    if buf.len() < total { return 0; }

    let hdr = Header {
        magic: TELEM_MAGIC,
        length: PAYLOAD_LEN as u16,
        pkt_type: TELEM_ATTITUDE,
        seq: next_seq(),
    };
    hdr.serialize(buf);

    let p = HEADER_SIZE;
    put_i32(buf, p,      att.roll_cdeg);
    put_i32(buf, p + 4,  att.pitch_cdeg);
    put_i32(buf, p + 8,  att.yaw_cdeg);
    put_i32(buf, p + 12, att.alt_cm);
    put_i32(buf, p + 16, gps.lat_deg7);
    put_i32(buf, p + 20, gps.lon_deg7);
    buf[p + 24] = mode;
    buf[p + 25] = armed as u8;
    buf[p + 26] = gps.sats;
    buf[p + 27] = gps.fix;

    // CRC over header + payload.
    buf[HEADER_SIZE + PAYLOAD_LEN] = crc8(&buf[..HEADER_SIZE + PAYLOAD_LEN]);

    total
}

/// Serialize TELEM_SENSORS packet.
///
/// Payload (28 bytes):
/// - accel_mg: [i32; 3] = 12 bytes
/// - gyro_mdps: [i32; 3] = 12 bytes
/// - pressure_pa: u32 = 4 bytes (stored as i32 for uniformity)
///
/// Total: 8 + 28 + 1 = 37 bytes.
pub fn serialize_sensors(
    buf: &mut [u8],
    imu: &azos_imu::ImuData,
    pressure_pa: u32,
) -> usize {
    const PAYLOAD_LEN: usize = 28;
    let total = HEADER_SIZE + PAYLOAD_LEN + CRC_SIZE;
    if buf.len() < total { return 0; }

    let hdr = Header {
        magic: TELEM_MAGIC,
        length: PAYLOAD_LEN as u16,
        pkt_type: TELEM_SENSORS,
        seq: next_seq(),
    };
    hdr.serialize(buf);

    let p = HEADER_SIZE;
    put_i32(buf, p,      imu.accel_mg[0]);
    put_i32(buf, p + 4,  imu.accel_mg[1]);
    put_i32(buf, p + 8,  imu.accel_mg[2]);
    put_i32(buf, p + 12, imu.gyro_mdps[0]);
    put_i32(buf, p + 16, imu.gyro_mdps[1]);
    put_i32(buf, p + 20, imu.gyro_mdps[2]);
    put_i32(buf, p + 24, pressure_pa as i32);

    buf[HEADER_SIZE + PAYLOAD_LEN] = crc8(&buf[..HEADER_SIZE + PAYLOAD_LEN]);

    total
}

// ── Command parsing (Server → Robot) ────────────────────────────────────────

/// Parsed command from server.
#[derive(Clone, Copy)]
pub enum ServerCmd {
    /// Arm (true) or disarm (false) motors.
    Arm(bool),
    /// Set flight mode (mode byte).
    Mode(u8),
    /// Set attitude/throttle target.
    Target {
        roll_cdeg: i32,
        pitch_cdeg: i32,
        yaw_rate_mdps: i32,
        throttle: u16,
    },
    /// Waypoint upload.
    Waypoint {
        lat_deg7: i32,
        lon_deg7: i32,
        alt_mm: i32,
        speed_cms: u16,
    },
}

/// Parse a command packet from the server.
///
/// Returns `None` if packet is malformed or CRC fails.
pub fn parse_command(buf: &[u8]) -> Option<ServerCmd> {
    let hdr = Header::parse(buf)?;

    // Verify magic.
    if hdr.magic != CMD_MAGIC { return None; }

    let payload_start = HEADER_SIZE;
    let payload_end = HEADER_SIZE + hdr.length as usize;
    let total = payload_end + CRC_SIZE;
    if buf.len() < total { return None; }

    // Verify CRC.
    let expected_crc = crc8(&buf[..payload_end]);
    if buf[payload_end] != expected_crc { return None; }

    let payload = &buf[payload_start..payload_end];

    match hdr.pkt_type {
        CMD_ARM => {
            if payload.is_empty() { return None; }
            Some(ServerCmd::Arm(payload[0] != 0))
        }
        CMD_MODE => {
            if payload.is_empty() { return None; }
            Some(ServerCmd::Mode(payload[0]))
        }
        CMD_TARGET => {
            if payload.len() < 14 { return None; }
            Some(ServerCmd::Target {
                roll_cdeg: get_i32(payload, 0),
                pitch_cdeg: get_i32(payload, 4),
                yaw_rate_mdps: get_i32(payload, 8),
                throttle: get_u16(payload, 12),
            })
        }
        CMD_WAYPOINT => {
            if payload.len() < 14 { return None; }
            Some(ServerCmd::Waypoint {
                lat_deg7: get_i32(payload, 0),
                lon_deg7: get_i32(payload, 4),
                alt_mm: get_i32(payload, 8),
                speed_cms: get_u16(payload, 12),
            })
        }
        _ => None,
    }
}

// ── Telemetry state ─────────────────────────────────────────────────────────

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static TELEM_ACTIVE: AtomicBool = AtomicBool::new(false);
static TELEM_PORT: AtomicU32 = AtomicU32::new(5000);
static TELEM_PACKETS_SENT: AtomicU32 = AtomicU32::new(0);

/// Start telemetry transmission.
pub fn telem_start(port: u16) {
    TELEM_PORT.store(port as u32, Ordering::Relaxed);
    TELEM_ACTIVE.store(true, Ordering::Release);
    azos_drv_sys::kprintln!("[TELEM] Started on UDP port {}", port);
}

/// Stop telemetry transmission.
pub fn telem_stop() {
    TELEM_ACTIVE.store(false, Ordering::Release);
    azos_drv_sys::kprintln!("[TELEM] Stopped");
}

/// Check if telemetry is active.
pub fn telem_is_active() -> bool {
    TELEM_ACTIVE.load(Ordering::Acquire)
}

/// Get configured telemetry port.
pub fn telem_port() -> u16 {
    TELEM_PORT.load(Ordering::Relaxed) as u16
}

/// Increment and return packets sent counter.
pub fn telem_inc_sent() -> u32 {
    TELEM_PACKETS_SENT.fetch_add(1, Ordering::Relaxed)
}

/// Get total packets sent.
pub fn telem_packets_sent() -> u32 {
    TELEM_PACKETS_SENT.load(Ordering::Relaxed)
}

/// Print telemetry status.
pub fn telem_info() {
    let active = TELEM_ACTIVE.load(Ordering::Acquire);
    let port = TELEM_PORT.load(Ordering::Relaxed);
    let sent = TELEM_PACKETS_SENT.load(Ordering::Relaxed);
    azos_drv_sys::kconsoleln!("[TELEM] Active: {}  Port: {}  Packets sent: {}",
        active, port, sent);
}
