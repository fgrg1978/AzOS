// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Stream-ID-prefixed multiplexed wire format for the brain↔kernel link.
//!
//! # Wire format
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
#![forbid(unsafe_code)]

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

// ── StreamDemux: the receive side over a byte stream ─────────────────────────

/// Splits a TCP byte stream back into its streams, across reads.
///
/// TCP keeps no `send()` boundary: one `recv()` can hold several frames, or
/// end inside a header or a payload. [`unwrap`] parses one whole frame from
/// one buffer; applied to each read it dropped every frame after the first and
/// every frame torn across two reads. This walks the stream instead and hands
/// each payload on in the pieces the reads cut it into, tagged with its
/// stream: a consumer that reassembles its own records (the brain link's
/// record layer does) needs no frame-sized buffer here, and a frame of a
/// stream the consumer ignores costs no copy. State is a header in progress
/// and the bytes left of the current payload, so a frame of any length, up to
/// [`MAX_PAYLOAD_LEN`], passes.
#[derive(Clone, Copy, Debug)]
pub struct StreamDemux {
    head: [u8; HEADER_LEN],
    /// Header bytes collected so far (`HEADER_LEN`: the header is whole and
    /// `left` counts down the payload).
    head_len: usize,
    /// Payload bytes of the current frame not yet handed on.
    left: usize,
}

impl StreamDemux {
    pub const fn new() -> Self {
        StreamDemux { head: [0; HEADER_LEN], head_len: 0, left: 0 }
    }

    /// Forget a frame in progress (a new connection starts at a header).
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Walk `input`, calling `f(stream_id, piece)` for every payload piece it
    /// holds, in stream order. A payload torn across reads comes as two or
    /// more pieces; an empty payload calls nothing. Stops at the first `Err`
    /// of `f` and returns it (the caller ends the connection: the walk's
    /// position is then meaningless).
    pub fn feed<E>(
        &mut self,
        mut input: &[u8],
        mut f: impl FnMut(u8, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        while !input.is_empty() {
            if self.head_len < HEADER_LEN {
                let take = (HEADER_LEN - self.head_len).min(input.len());
                self.head[self.head_len..self.head_len + take].copy_from_slice(&input[..take]);
                self.head_len += take;
                input = &input[take..];
                if self.head_len < HEADER_LEN {
                    break;
                }
                self.left = u16::from_le_bytes([self.head[1], self.head[2]]) as usize;
            }
            let take = self.left.min(input.len());
            if take != 0 {
                f(self.head[0], &input[..take])?;
                input = &input[take..];
                self.left -= take;
            }
            if self.left == 0 {
                self.head_len = 0;
            }
        }
        Ok(())
    }
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
