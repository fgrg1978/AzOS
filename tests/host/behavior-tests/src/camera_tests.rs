// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The camera on the engine's brain link (`userspace/services/brain_client/src/camera.rs`
//! and `wire.rs`, the real files): when a frame is due and the message a frame
//! becomes, checked against the brain protocol's own encoder
//! (`brain_protocol::build_packet`, `encode_camera_header`).

use crate::brain_protocol::{build_packet, encode_camera_header, CAMERA_FMT_JPEG, CAMERA_HDR_SIZE, PKT_CAMERA};
use crate::camera::*;
use crate::wire;

/// A JPEG-shaped byte string: SOI, an APP0 segment, a SOF0 stating `w` x `h`,
/// filler, EOI.
fn jpeg(w: u16, h: u16, len: usize) -> Vec<u8> {
    let mut j = vec![0xFF, 0xD8, 0xFF, 0xE0, 0, 4, 0xAA, 0xBB, 0xFF, 0xC0, 0, 11, 8];
    j.extend_from_slice(&h.to_be_bytes());
    j.extend_from_slice(&w.to_be_bytes());
    j.extend_from_slice(&[1, 1, 0x11, 0]);
    j.resize(len - 2, 0x5A);
    j.extend_from_slice(&[0xFF, 0xD9]);
    j
}

/// **A frame goes out once per period**: due at the start of a session, again
/// exactly a period after the last one sent, and a cycle that found no frame
/// does not move the pace.
///
/// **Canary.** Count the period from `due`'s first call instead of from `sent`
/// (set `next_ms` in `due`): the second case goes red.
#[test]
fn a_frame_is_due_once_per_period() {
    let mut p = Pacer::new(250);
    assert!(p.due(0), "a session starts with a frame due");
    assert!(p.due(1_000), "a cycle that took no frame leaves it due");
    p.sent(1_000);
    assert!(!p.due(1_000) && !p.due(1_249), "not before the period is out");
    assert!(p.due(1_250), "due the cycle the period ends");
    p.sent(1_250);
    assert!(!p.due(1_499));
    p.reset();
    assert!(p.due(1_251), "a new session starts with a frame due");
    let mut late = Pacer::new(250);
    late.sent(u64::MAX - 10);
    assert!(!late.due(0), "a clock near the end of its range does not wrap into a due frame");
}

/// **A frame is one camera message**: the brain protocol's frame around the
/// 5-byte header (the JPEG's own size, the JPEG format) and the JPEG, with the
/// length and the CRC the protocol's own encoder gives, and the JPEG bytes
/// exact.
///
/// **Canary.** Swap the width and the height in `frame_message`: the header
/// comparison goes red.
#[test]
fn a_frame_becomes_one_camera_message() {
    let j = jpeg(160, 120, 3_000);
    assert_eq!(jpeg_size(&j), Some((160, 120)));
    let mut out = vec![0u8; MSG_MAX];
    let n = frame_message(&mut out, &j).expect("fits");

    let mut hdr = [0u8; CAMERA_HDR_SIZE];
    encode_camera_header(&mut hdr, 160, 120, CAMERA_FMT_JPEG);
    let mut payload = hdr.to_vec();
    payload.extend_from_slice(&j);
    let mut want = vec![0u8; payload.len() + wire::FRAME_OVERHEAD];
    let wn = build_packet(PKT_CAMERA, &payload, &mut want);
    assert_eq!(&out[..n], &want[..wn], "the bytes the protocol's own encoder gives");
    assert_eq!(n, wire::FRAME_OVERHEAD + CAMERA_HDR_SIZE + j.len());
    assert_eq!(out[2], PKT_CAMERA);
    assert_eq!(&out[wire::PAYLOAD_AT + CAMERA_HDR_SIZE..n - 1], &j[..]);
    assert_eq!(out[n - 1], wire::crc8(&out[..n - 1]), "the CRC covers header and payload");
}

/// The largest JPEG fills the link's largest message exactly; one byte more,
/// nothing, or bytes that are no JPEG are not framed (and nothing is written
/// past the buffer).
#[test]
fn a_frame_that_does_not_fit_or_is_not_a_jpeg_is_not_framed() {
    let mut out = vec![0u8; MSG_MAX];
    let n = frame_message(&mut out, &jpeg(640, 480, JPEG_MAX)).expect("the largest fits");
    assert_eq!(n, MSG_MAX);
    assert_eq!(frame_message(&mut out, &jpeg(640, 480, JPEG_MAX + 1)), None);
    assert_eq!(frame_message(&mut out, &[]), None);
    assert_eq!(frame_message(&mut out, &[0x12; 100]), None, "no SOI");
    assert_eq!(frame_message(&mut out, &[0xFF, 0xD8, 0xFF, 0xD9]), None, "no frame header in it");
    let j = jpeg(160, 120, 500);
    assert_eq!(frame_message(&mut vec![0u8; 100], &j), None, "a buffer too small for it");
}

/// A send that makes no progress is a stall once the limit is reached, not
/// before.
#[test]
fn a_send_that_makes_no_progress_stalls() {
    assert!(!stalled(10_000, 10_000 + STALL_MS - 1));
    assert!(stalled(10_000, 10_000 + STALL_MS));
    assert!(!stalled(10_000, 5_000), "a clock that moved back is not a stall");
}

/// The JPEG's size comes from its first frame header, past other segments.
#[test]
fn the_size_is_read_from_the_frame_header() {
    assert_eq!(jpeg_size(&jpeg(1, 65_535, 200)), Some((1, 65_535)));
    assert_eq!(jpeg_size(&[0xFF, 0xD8]), None);
    let truncated = &jpeg(160, 120, 200)[..14];
    assert_eq!(jpeg_size(truncated), None);
}
