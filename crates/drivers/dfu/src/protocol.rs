// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DFU 1.1 control-pipe request decoding (§3.2 Table 3.2).
//!
//! USB setup packets targeting the DFU class are 8 bytes with
//! `bmRequestType = 0b0010_0001` for OUT (host→device) and
//! `0b1010_0001` for IN. The interface field is the DFU interface
//! number (always 0 in our builds).

/// bRequest codes (§3.2 Table 3.2).
pub const DFU_REQ_DETACH:    u8 = 0;
pub const DFU_REQ_DNLOAD:    u8 = 1;
pub const DFU_REQ_UPLOAD:    u8 = 2;
pub const DFU_REQ_GETSTATUS: u8 = 3;
pub const DFU_REQ_CLRSTATUS: u8 = 4;
pub const DFU_REQ_GETSTATE:  u8 = 5;
pub const DFU_REQ_ABORT:     u8 = 6;

/// bmRequestType bits we care about.
const REQ_TYPE_CLASS_INTERFACE_OUT: u8 = 0b0010_0001;
const REQ_TYPE_CLASS_INTERFACE_IN:  u8 = 0b1010_0001;

/// Raw 8-byte USB setup packet — direction (bit 7 of
/// bmRequestType) included so the decoder can validate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupPacket {
    pub bm_request_type: u8,
    pub b_request:       u8,
    pub w_value:         u16,
    pub w_index:         u16,
    pub w_length:        u16,
}

impl SetupPacket {
    /// Parse from 8 raw bytes (little-endian). Returns `None` if
    /// the buffer is short.
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }
        Some(Self {
            bm_request_type: buf[0],
            b_request:       buf[1],
            w_value:         u16::from_le_bytes([buf[2], buf[3]]),
            w_index:         u16::from_le_bytes([buf[4], buf[5]]),
            w_length:        u16::from_le_bytes([buf[6], buf[7]]),
        })
    }
}

/// Whether the request is host→device (OUT) or device→host (IN).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DfuRequestType {
    Out, // host writes data
    In,  // device reports data
}

/// Decoded DFU request — semantically meaningful so the state
/// machine handler can match on it directly without re-parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DfuRequest {
    /// `DFU_DETACH` (§5.1) — host asks the runtime to drop into
    /// DFU mode. `w_value` is the detach timeout the host accepts.
    Detach { detach_timeout_ms: u16 },
    /// `DFU_DNLOAD` (§5.1.4) — host pushes a chunk. `w_value` is
    /// the block number (informational); `w_length` is the number
    /// of bytes that follow in the data stage.
    Dnload { block_num: u16, len: u16 },
    /// `DFU_UPLOAD` (§5.1.3) — host requests a chunk. We currently
    /// reject UPLOAD (no `DFU_ATTR_CAN_UPLOAD`), but parse for
    /// completeness.
    Upload { block_num: u16, len: u16 },
    /// `DFU_GETSTATUS` (§5.1.6) — host polls device status. Reply
    /// is 6 bytes; see [`DfuStatus::encode`].
    GetStatus,
    /// `DFU_CLRSTATUS` (§5.1.7) — host clears `Error` state.
    ClrStatus,
    /// `DFU_GETSTATE` (§5.1.8) — host queries `bState`. Reply is
    /// 1 byte.
    GetState,
    /// `DFU_ABORT` (§5.1.9) — host abandons in-progress download.
    Abort,
}

/// Parse a Setup packet into a [`DfuRequest`] if it targets the
/// DFU class interface. Returns `None` for non-DFU traffic so the
/// caller can pass it on to the standard USB request handler.
pub fn parse_setup_packet(pkt: SetupPacket) -> Option<(DfuRequestType, DfuRequest)> {
    let dir = match pkt.bm_request_type {
        REQ_TYPE_CLASS_INTERFACE_OUT => DfuRequestType::Out,
        REQ_TYPE_CLASS_INTERFACE_IN  => DfuRequestType::In,
        _ => return None,
    };
    let req = match pkt.b_request {
        DFU_REQ_DETACH    => DfuRequest::Detach    { detach_timeout_ms: pkt.w_value },
        DFU_REQ_DNLOAD    => DfuRequest::Dnload    { block_num: pkt.w_value, len: pkt.w_length },
        DFU_REQ_UPLOAD    => DfuRequest::Upload    { block_num: pkt.w_value, len: pkt.w_length },
        DFU_REQ_GETSTATUS => DfuRequest::GetStatus,
        DFU_REQ_CLRSTATUS => DfuRequest::ClrStatus,
        DFU_REQ_GETSTATE  => DfuRequest::GetState,
        DFU_REQ_ABORT     => DfuRequest::Abort,
        _ => return None,
    };
    Some((dir, req))
}
