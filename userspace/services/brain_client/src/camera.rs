// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The camera on the brain link: when a frame is due and how it is framed.
//! Pure, so the host suite includes it by path.
//!
//! The engine reads the camera's newest frame through the `Frame` interface
//! and sends it as a `PKT_CAMERA` message on the control session, at most once
//! per `BRAIN_CAMERA_PERIOD_MS`, which is also the period the kernel captures
//! at while this reader is attached. A frame that does not fit one message is
//! skipped, never split.
//!
//! A frame is kilobytes among 70-byte sensor frames: on one TCP connection a
//! stalled window holds every sensor frame behind it. So the sealed frame is
//! sent a piece per cycle without waiting (`link::pump`), sensor frames wait
//! until it is out, and a session whose window stays shut for [`STALL_MS`] is
//! ended instead of holding the engine.

use crate::wire::{self, FRAME_OVERHEAD, PAYLOAD_AT};

pub const PKT_CAMERA: u8 = 0x02;
/// width(u16 LE) + height(u16 LE) + pixel format(u8).
pub const CAMERA_HDR_SIZE: usize = 5;
pub const CAMERA_FMT_JPEG: u8 = 1;

/// The largest message the link seals (`azos_crypto::secure_channel`).
pub const MSG_MAX: usize = azos_crypto::secure_channel::MAX_MESSAGE_BYTES;
/// The largest JPEG one camera message carries.
pub const JPEG_MAX: usize = MSG_MAX - FRAME_OVERHEAD - CAMERA_HDR_SIZE;

/// A send that has made no progress for this long ends the session (ms).
pub const STALL_MS: u64 = 2_000;

/// Paces the frames: one per `period_ms`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pacer {
    period_ms: u64,
    next_ms: u64,
}

impl Pacer {
    pub const fn new(period_ms: u64) -> Pacer {
        Pacer { period_ms, next_ms: 0 }
    }

    /// Is a frame due at `now_ms`?
    pub fn due(&self, now_ms: u64) -> bool {
        now_ms >= self.next_ms
    }

    /// A frame went out at `now_ms`: the next is due a period later. A cycle
    /// that found no frame ready does not call this, and asks again at the
    /// next one.
    pub fn sent(&mut self, now_ms: u64) {
        self.next_ms = now_ms.saturating_add(self.period_ms);
    }

    /// The session ended: the next one starts with a frame due.
    pub fn reset(&mut self) {
        self.next_ms = 0;
    }
}

/// Has a send that began making no progress at `since_ms` stalled by `now_ms`?
pub fn stalled(since_ms: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(since_ms) >= STALL_MS
}

/// The pixel size a baseline or progressive JPEG states (its first SOF
/// marker): `(width, height)`; `None` for bytes that are no JPEG.
pub fn jpeg_size(jpeg: &[u8]) -> Option<(u16, u16)> {
    if jpeg.get(..2)? != [0xFF, 0xD8] {
        return None;
    }
    let mut at = 2;
    while at + 4 <= jpeg.len() {
        if jpeg[at] != 0xFF {
            return None;
        }
        let marker = jpeg[at + 1];
        if marker == 0xFF {
            at += 1;
            continue;
        }
        let len = u16::from_be_bytes([jpeg[at + 2], jpeg[at + 3]]) as usize;
        if matches!(marker, 0xC0..=0xC2) {
            let sof = jpeg.get(at + 5..at + 9)?;
            return Some((u16::from_be_bytes([sof[2], sof[3]]), u16::from_be_bytes([sof[0], sof[1]])));
        }
        at += 2 + len;
    }
    None
}

/// The camera message for `jpeg` in `out`: the frame (`wire`) around the
/// header and the JPEG, which is copied once, to where it goes. Its length;
/// `None` when `jpeg` is no JPEG, is empty or does not fit [`JPEG_MAX`].
pub fn frame_message(out: &mut [u8], jpeg: &[u8]) -> Option<usize> {
    if jpeg.is_empty() || jpeg.len() > JPEG_MAX {
        return None;
    }
    let (w, h) = jpeg_size(jpeg)?;
    let body = PAYLOAD_AT + CAMERA_HDR_SIZE;
    out.get_mut(..body + jpeg.len() + 1)?;
    wire::put_u16_le(out, PAYLOAD_AT, w);
    wire::put_u16_le(out, PAYLOAD_AT + 2, h);
    out[PAYLOAD_AT + 4] = CAMERA_FMT_JPEG;
    out[body..body + jpeg.len()].copy_from_slice(jpeg);
    Some(wire::seal_in_place(out, PKT_CAMERA, CAMERA_HDR_SIZE + jpeg.len()))
}
