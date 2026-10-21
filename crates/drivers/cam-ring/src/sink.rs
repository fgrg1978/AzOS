// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The producer's side of a frame ring as a trait: what a camera driver that
//! is not the CSI capture task (a USB video class driver, in
//! `azos_usb::class::uvc`) needs from the ring, and what it tells it about
//! the frame it wrote.
//!
//! The driver claims a slot when a frame starts, appends the payloads of the
//! frame to it as they arrive, and commits or aborts it; it never sees the
//! ring's consumers, slot count or policy. [`FrameSink::wanted`] is how the
//! driver learns whether anyone reads the frames at all, so it does not hold
//! the camera streaming (and the bus bandwidth with it) for nobody.

/// What the bytes of a frame are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameFormat {
    /// A baseline JPEG (Motion-JPEG frames of a camera, or the CSI path's
    /// own encoder). The default of [`FanoutRing::commit`](crate::FanoutRing::commit).
    Jpeg,
    /// Packed YUV 4:2:2, `Y0 U Y1 V` per two pixels (YUY2): `2 * width *
    /// height` bytes.
    Yuyv,
}

/// What a committed frame is: its format and, for raw pixels, its size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameInfo {
    pub format: FrameFormat,
    /// Pixels per row; 0 when unknown (a JPEG carries its own size).
    pub width: u16,
    /// Rows; 0 when unknown.
    pub height: u16,
}

impl FrameInfo {
    /// A JPEG whose size is in its header.
    pub const JPEG: FrameInfo = FrameInfo { format: FrameFormat::Jpeg, width: 0, height: 0 };

    pub const fn yuyv(width: u16, height: u16) -> FrameInfo {
        FrameInfo { format: FrameFormat::Yuyv, width, height }
    }

    /// One word, for a slot's atomic. All zero is [`FrameInfo::JPEG`].
    pub(crate) const fn pack(self) -> u64 {
        let f = match self.format {
            FrameFormat::Jpeg => 0u64,
            FrameFormat::Yuyv => 1,
        };
        f | (self.width as u64) << 8 | (self.height as u64) << 24
    }

    pub(crate) const fn unpack(v: u64) -> FrameInfo {
        FrameInfo {
            format: if v & 0xff == 1 { FrameFormat::Yuyv } else { FrameFormat::Jpeg },
            width: (v >> 8) as u16,
            height: (v >> 24) as u16,
        }
    }
}

/// A ring a camera driver writes frames into.
pub trait FrameSink {
    /// Does anyone read the frames? A driver streams only while this is true.
    fn wanted(&self) -> bool;
    /// A buffer for the next frame, which is the caller's until
    /// [`commit`](Self::commit) or [`abort`](Self::abort). `None`: the ring
    /// refuses a frame now (its policy, or another producer is writing one);
    /// the driver drops the frame it was about to write.
    #[allow(clippy::mut_from_ref)]
    fn claim(&self) -> Option<&mut [u8]>;
    /// Publish the claimed buffer: its first `len` bytes are a frame of kind
    /// `info`, acquired at `stamp` (the producer's clock).
    fn commit(&self, len: usize, stamp: u64, info: FrameInfo);
    /// Give the claimed buffer back; nothing is published.
    fn abort(&self);
}
