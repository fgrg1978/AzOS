// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Copying a rectangle of a client's image onto the scanout: the one pixel
//! move of the `Display` interface's `present`.
//!
//! The image is a byte slice laid out like the scanout (same pixel format,
//! the image's own stride), so a rectangle sits at the same coordinates in
//! both. The slice may hold only a band of the screen's rows, starting at row
//! `src_top`: a display server's image is many memory objects, each a band
//! (`azos_devif::display`, "Surfaces"). Rows are copied whole (`memcpy`); the
//! scanout is write-combining and is never read back.

use crate::pixel::Surface;
use crate::Rect;

/// Copy `r` from `src` (an image in the scanout's pixel format whose rows are
/// `src_stride` bytes apart and whose first row is screen row `src_top`) onto
/// `dst`. The rectangle is cut to the screen first.
///
/// Returns the rectangle that was copied, `None` when nothing was: it lies
/// outside the screen, is empty, starts above `src_top`, `src` is too short to
/// hold its last row, or the stride is shorter than a screen row; nothing is
/// touched then.
pub fn copy_rect(dst: &Surface, src: &[u8], src_stride: usize, src_top: usize, r: Rect) -> Option<Rect> {
    // SAFETY: `src` is a live slice of `src.len()` readable bytes.
    unsafe { copy_rect_raw(dst, src.as_ptr(), src.len(), src_stride, src_top, r) }
}

/// [`copy_rect`] for an image another party writes while it is read (a display
/// server's surface): no slice is formed over memory that changes under it.
///
/// # Safety
///
/// `src` must be readable for `src_len` bytes for the whole call. The bytes
/// may change meanwhile (the copy then shows a mix of two frames, which is
/// what damage is for); the memory must not be freed or unmapped.
pub unsafe fn copy_rect_raw(
    dst: &Surface,
    src: *const u8,
    src_len: usize,
    src_stride: usize,
    src_top: usize,
    r: Rect,
) -> Option<Rect> {
    let r = r.clip(dst.width as u32, dst.height as u32)?;
    let bpp = dst.fmt.bytes();
    let (x, y, w, h) = (r.x as usize, r.y as usize, r.w as usize, r.h as usize);
    if bpp == 0 || src_stride < dst.width * bpp || y < src_top {
        return None;
    }
    // The last byte read: the end of the rectangle's last row, counted from
    // the image's first row.
    let need = (y - src_top + h - 1).checked_mul(src_stride)?.checked_add((x + w) * bpp)?;
    if src_len < need {
        return None;
    }
    for row in y..y + h {
        let from = (row - src_top) * src_stride + x * bpp;
        // SAFETY: the rectangle is inside the screen, so the destination row
        // segment lies within `dst.len()` bytes of `dst.base`, which the
        // creator of the `Surface` promised is writable; the source segment
        // lies within `src_len` bytes of `src` by the length check above and
        // the caller's promise; the scanout is a device or its own RAM and
        // the image a client's pages, so they do not overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(src.add(from), dst.base.add(row * dst.stride + x * bpp), w * bpp);
        }
    }
    Some(r)
}
