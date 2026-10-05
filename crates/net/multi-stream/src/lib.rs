// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Stream-ID-prefixed multiplexed wire format for the brain↔kernel link.
//!
//! # Wire format (RFC-0021)
//!
//! Each multiplexed frame on the TCP byte stream is laid out as:
//!
//! ```text
//! +─────────────+──────────────────+──────────────────────────────────────+
//! │ STREAM_ID   │ LEN              │ PAYLOAD                               │
//! │  1 byte     │  2 bytes LE      │  LEN bytes                           │
//! +─────────────+──────────────────+──────────────────────────────────────+
//! ```
//!
//! - `STREAM_ID`: logical stream selector (see [`StreamId`] constants).
//! - `LEN`: payload length in bytes, little-endian `u16`.  Maximum payload
//!   is [`MAX_PAYLOAD_LEN`] bytes (65535 — the `u16` range).
//! - `PAYLOAD`: raw bytes for the inner protocol on this stream.
//!
//! ## Stream IDs
//!
//! | Range          | Use                                              |
//! |----------------|--------------------------------------------------|
//! | `0x00`         | Control — sensors, status, actuator cmds         |
//! | `0x10..=0x1F`  | Camera streams (up to 16 independent cameras)   |
//! | `0x20`         | LIDAR point-cloud stream (future)                |
//! | `0x21`         | Audio stream (future)                            |
//! | `0x22..=0xFF`  | Reserved                                         |
//!
//! ## Back-pressure semantics
//!
//! Each stream ID has its own logical send queue on the brain side.  If a
//! camera ring fills (camera frame queue is full), control-plane traffic
//! on `STREAM_CONTROL` still flows.  The multiplexer simply wraps whatever
//! bytes are ready; it does not enforce per-stream ordering across streams.

#![no_std]

// ── Frame header layout ───────────────────────────────────────────────────────

/// Size of the stream-ID byte in the frame header.
pub const STREAM_ID_BYTES: usize = 1;
/// Size of the length field in the frame header (u16 little-endian).
pub const LEN_FIELD_BYTES: usize = 2;
/// Total overhead per multi-stream frame (stream-id + len).
pub const HEADER_LEN: usize = STREAM_ID_BYTES + LEN_FIELD_BYTES;
/// Maximum payload bytes per frame (u16::MAX).
pub const MAX_PAYLOAD_LEN: usize = 65535;
/// Minimum frame length on the wire (header only, zero-payload is valid).
pub const MIN_FRAME_LEN: usize = HEADER_LEN;

// ── Stream ID allocations ─────────────────────────────────────────────────────

/// Control stream — carries the existing `brain_protocol` packets
/// (SENSOR, CAMERA, STATUS, ACTUATOR, MODE, WAYPOINT, CONFIG).
pub const STREAM_CONTROL: u8 = 0x00;

/// First camera stream.  Camera stream IDs range from
/// `STREAM_CAMERA_BASE` through `STREAM_CAMERA_LAST`.
pub const STREAM_CAMERA_BASE: u8 = 0x10;
/// Last (inclusive) camera stream ID.
pub const STREAM_CAMERA_LAST: u8 = 0x1F;
/// Number of concurrent camera streams supported.
pub const STREAM_CAMERA_COUNT: u8 = STREAM_CAMERA_LAST - STREAM_CAMERA_BASE + 1;

/// LIDAR point-cloud stream (future use).
pub const STREAM_LIDAR: u8 = 0x20;
/// Audio capture/playback stream (future use).
pub const STREAM_AUDIO: u8 = 0x21;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors returned by [`wrap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapError {
    /// `inner_bytes.len()` exceeds [`MAX_PAYLOAD_LEN`].
    PayloadTooLarge,
    /// Output buffer is too small to hold the header + payload.
    OutputTooSmall,
}

// ── wrap() ────────────────────────────────────────────────────────────────────

/// Encode a payload as a multiplexed frame into `out`.
///
/// Writes `[stream_id][len_lo][len_hi][payload...]` to `out[..3+len]`.
///
/// # Returns
/// The total number of bytes written to `out` (= [`HEADER_LEN`] + payload
/// length) on success, or a [`WrapError`] if the payload is too large or `out`
/// is too small.
///
/// # Errors
/// - [`WrapError::PayloadTooLarge`] — `inner_bytes.len() > MAX_PAYLOAD_LEN`.
/// - [`WrapError::OutputTooSmall`] — `out.len() < HEADER_LEN + inner_bytes.len()`.
pub fn wrap(stream_id: u8, inner_bytes: &[u8], out: &mut [u8]) -> Result<usize, WrapError> {
    let payload_len = inner_bytes.len();
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(WrapError::PayloadTooLarge);
    }
    let total = HEADER_LEN + payload_len;
    if out.len() < total {
        return Err(WrapError::OutputTooSmall);
    }
    out[0] = stream_id;
    // LEN is little-endian u16.
    let len_le = (payload_len as u16).to_le_bytes();
    out[1] = len_le[0];
    out[2] = len_le[1];
    out[HEADER_LEN..total].copy_from_slice(inner_bytes);
    Ok(total)
}

// ── unwrap() ─────────────────────────────────────────────────────────────────

/// Parse a multiplexed frame from `frame`.
///
/// # Returns
/// `Some((stream_id, payload_len, payload_slice))` on success, or `None` if
/// the frame is malformed:
/// - `frame.len() < HEADER_LEN` — not even a complete header.
/// - `LEN` field claims more bytes than `frame[HEADER_LEN..]` contains
///   (length-extension attack / truncated read).
///
/// On success, `payload_slice` has exactly `payload_len` bytes starting at
/// `frame[HEADER_LEN]`.
pub fn unwrap(frame: &[u8]) -> Option<(u8, usize, &[u8])> {
    if frame.len() < HEADER_LEN {
        return None;
    }
    let stream_id = frame[0];
    let payload_len = u16::from_le_bytes([frame[1], frame[2]]) as usize;
    let available = frame.len().saturating_sub(HEADER_LEN);
    if payload_len > available {
        return None; // length-extension or truncated frame
    }
    let payload = &frame[HEADER_LEN..HEADER_LEN + payload_len];
    Some((stream_id, payload_len, payload))
}

// ── Helper: camera stream ID ──────────────────────────────────────────────────

/// Return the stream ID for camera index `n` (0-based).
///
/// Returns `None` if `n >= STREAM_CAMERA_COUNT`.
pub fn camera_stream_id(n: u8) -> Option<u8> {
    if n >= STREAM_CAMERA_COUNT {
        return None;
    }
    Some(STREAM_CAMERA_BASE + n)
}

/// Return `true` if `stream_id` is a camera stream.
pub fn is_camera_stream(stream_id: u8) -> bool {
    stream_id >= STREAM_CAMERA_BASE && stream_id <= STREAM_CAMERA_LAST
}
