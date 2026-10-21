// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Rectangle arithmetic on the Display interface's [`Rect`] (16 bits a field),
//! and the signed, wider [`Span`] a layer occupies before it is cut to the
//! screen.

use azos_devif::display::Rect;

/// The part of `a` that is also in `b`.
pub fn intersect(a: Rect, b: Rect) -> Option<Rect> {
    let x0 = a.x.max(b.x) as u32;
    let y0 = a.y.max(b.y) as u32;
    let x1 = (a.x as u32 + a.w as u32).min(b.x as u32 + b.w as u32);
    let y1 = (a.y as u32 + a.h as u32).min(b.y as u32 + b.h as u32);
    if x1 <= x0 || y1 <= y0 {
        return None;
    }
    Some(Rect::new(x0 as u16, y0 as u16, (x1 - x0) as u16, (y1 - y0) as u16))
}

/// The smallest rectangle that holds both (an empty one counts as nothing).
/// Both lie inside the 65535 x 65535 plane a [`Rect`] addresses; a side that
/// would pass it is cut there.
pub fn bounds(a: Rect, b: Rect) -> Rect {
    if a.is_empty() {
        return b;
    }
    if b.is_empty() {
        return a;
    }
    let x0 = a.x.min(b.x) as u32;
    let y0 = a.y.min(b.y) as u32;
    let x1 = (a.x as u32 + a.w as u32).max(b.x as u32 + b.w as u32);
    let y1 = (a.y as u32 + a.h as u32).max(b.y as u32 + b.h as u32);
    let side = |lo: u32, hi: u32| (hi - lo).min(u16::MAX as u32) as u16;
    Rect::new(x0 as u16, y0 as u16, side(x0, x1), side(y0, y1))
}

/// Is every pixel of `inner` in `outer`? An empty `inner` is in anything.
pub fn contains(outer: Rect, inner: Rect) -> bool {
    inner.is_empty()
        || (!outer.is_empty()
            && inner.x >= outer.x
            && inner.y >= outer.y
            && inner.x as u32 + inner.w as u32 <= outer.x as u32 + outer.w as u32
            && inner.y as u32 + inner.h as u32 <= outer.y as u32 + outer.h as u32)
}

/// Pixels in `r`.
pub fn area(r: Rect) -> u64 {
    r.w as u64 * r.h as u64
}

/// A half-open box `x0..x1`, `y0..y1` on the (signed, unbounded) plane of
/// device pixels: where a layer lands, partly or wholly off the screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Span {
    pub x0: i64,
    pub y0: i64,
    pub x1: i64,
    pub y1: i64,
}

impl Span {
    /// The part inside a `width` x `height` screen.
    pub fn clip(&self, width: u32, height: u32) -> Option<Rect> {
        let x0 = self.x0.max(0);
        let y0 = self.y0.max(0);
        let x1 = self.x1.min(width as i64);
        let y1 = self.y1.min(height as i64);
        if x1 <= x0 || y1 <= y0 {
            return None;
        }
        Some(Rect::new(x0 as u16, y0 as u16, (x1 - x0) as u16, (y1 - y0) as u16))
    }

    /// Does it hold every pixel of `r`?
    pub fn covers(&self, r: Rect) -> bool {
        self.x0 <= r.x as i64
            && self.y0 <= r.y as i64
            && self.x1 >= r.x as i64 + r.w as i64
            && self.y1 >= r.y as i64 + r.h as i64
    }
}
