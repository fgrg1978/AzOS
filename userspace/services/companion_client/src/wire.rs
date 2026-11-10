// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The companion protocol's frame around a payload: MAGIC(2) + TYPE(1) + LEN(2 LE)
//! + PAYLOAD + CRC8(1). Pure, so the host suite includes it by path.

pub const MAGIC: [u8; 2] = *b"CL";
/// MAGIC(2) + TYPE(1) + LEN(2) + CRC(1).
pub const FRAME_OVERHEAD: usize = 6;
/// Where a payload starts in a frame.
pub const PAYLOAD_AT: usize = 5;

/// CRC-8/MAXIM polynomial.
const CRC8_POLY: u8 = 0x31;

pub fn crc8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            if crc & 0x80 != 0 {
                crc = (crc << 1) ^ CRC8_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

pub fn put_u16_le(buf: &mut [u8], off: usize, v: u16) {
    let b = v.to_le_bytes();
    buf[off] = b[0];
    buf[off + 1] = b[1];
}

/// Frame a payload.
pub fn build_frame(frame: &mut [u8], pkt_type: u8, payload: &[u8]) -> usize {
    frame[PAYLOAD_AT..PAYLOAD_AT + payload.len()].copy_from_slice(payload);
    seal_in_place(frame, pkt_type, payload.len())
}

/// Frame the `payload_len` bytes already at `frame[PAYLOAD_AT..]`: the header
/// and the CRC around them. The length of the frame.
pub fn seal_in_place(frame: &mut [u8], pkt_type: u8, payload_len: usize) -> usize {
    frame[0] = MAGIC[0];
    frame[1] = MAGIC[1];
    frame[2] = pkt_type;
    put_u16_le(frame, 3, payload_len as u16);
    let crc = crc8(&frame[..PAYLOAD_AT + payload_len]);
    frame[PAYLOAD_AT + payload_len] = crc;
    FRAME_OVERHEAD + payload_len
}
