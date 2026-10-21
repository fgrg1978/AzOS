// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Raw pixels of a camera frame, for the consumer that wants something else
//! than what the camera sent.

/// The luma plane of a YUY2 frame (`w` x `h`, `Y0 U Y1 V` per two pixels,
/// `2 * w * h` bytes), taking every `step`-th pixel of every `step`-th row,
/// with the smallest `step` that fits the result in `max_w` x `max_h`, into
/// `dst`. Returns the size of the result, or `None` for a frame that is not
/// `w * h` pixels or a `dst` too small for the result.
///
/// The perception path is grayscale, and a grayscale JPEG of the luma is what
/// the link carries; chroma is dropped, not converted.
pub fn yuyv_luma(yuyv: &[u8], w: usize, h: usize, dst: &mut [u8], max_w: usize, max_h: usize) -> Option<(usize, usize)> {
    if w == 0 || h == 0 || max_w == 0 || max_h == 0 || yuyv.len() < 2 * w * h {
        return None;
    }
    let step = w.div_ceil(max_w).max(h.div_ceil(max_h));
    let (cw, ch) = (w / step, h / step);
    if cw == 0 || ch == 0 || dst.len() < cw * ch {
        return None;
    }
    for y in 0..ch {
        let row = &yuyv[2 * y * step * w..];
        for x in 0..cw {
            dst[y * cw + x] = row[2 * x * step];
        }
    }
    Some((cw, ch))
}

/// The size (width, height) a JPEG's start-of-frame segment declares, or
/// `None` if the bytes do not start a JPEG or end before a SOF is seen.
///
/// A Motion-JPEG frame of a camera carries its own size ([`FrameInfo::JPEG`]
/// has none), and the link's camera header has to say it.
///
/// [`FrameInfo::JPEG`]: crate::FrameInfo::JPEG
pub fn jpeg_size(jpeg: &[u8]) -> Option<(u16, u16)> {
    if jpeg.len() < 4 || jpeg[..2] != [0xff, 0xd8] {
        return None;
    }
    let mut at = 2;
    while at + 4 <= jpeg.len() {
        if jpeg[at] != 0xff {
            return None;
        }
        let marker = jpeg[at + 1];
        match marker {
            // Fill byte before the marker.
            0xff => at += 1,
            // Standalone markers (TEM, RSTn, SOI): no length.
            0x01 | 0xd0..=0xd8 => at += 2,
            // Start of scan or end of image: no SOF came before.
            0xd9 | 0xda => return None,
            // SOFn, except DHT (c4), JPG (c8) and DAC (cc).
            0xc0..=0xcf if !matches!(marker, 0xc4 | 0xc8 | 0xcc) => {
                // Length, precision, height, width.
                if at + 9 > jpeg.len() {
                    return None;
                }
                let h = u16::from_be_bytes([jpeg[at + 5], jpeg[at + 6]]);
                let w = u16::from_be_bytes([jpeg[at + 7], jpeg[at + 8]]);
                return (w != 0 && h != 0).then_some((w, h));
            }
            _ => {
                let len = u16::from_be_bytes([jpeg[at + 2], jpeg[at + 3]]) as usize;
                if len < 2 {
                    return None;
                }
                at += 2 + len;
            }
        }
    }
    None
}
