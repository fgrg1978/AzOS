// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The union of what changed, as at most [`DAMAGE_MAX`] rectangles: the most
//! one `Display::present` carries.
//!
//! Adding a rectangle drops it when a held one already covers it, drops the
//! held ones it covers, and when the list is full merges the pair whose
//! bounding box wastes the fewest pixels: either the new rectangle into a
//! held one, or two held ones to make room. So the list always covers every
//! pixel ever added, and what it adds beyond them is the cheapest the greedy
//! choice finds. The rectangles may overlap; each is copied by the display, so
//! a pixel in two is copied twice, which is correct and costs little at six.

use crate::geom::{area, bounds, contains};
use azos_devif::display::{Rect, DAMAGE_MAX};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Damage {
    rects: [Rect; DAMAGE_MAX],
    len: usize,
}

impl Damage {
    pub const fn new() -> Damage {
        Damage { rects: [Rect::new(0, 0, 0, 0); DAMAGE_MAX], len: 0 }
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The rectangles, to give to `Present::new`.
    pub fn rects(&self) -> &[Rect] {
        &self.rects[..self.len]
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    fn remove(&mut self, i: usize) {
        self.rects.copy_within(i + 1..self.len, i);
        self.len -= 1;
    }

    /// Add `r` (inside the 65535 x 65535 plane; an empty one adds nothing).
    pub fn add(&mut self, r: Rect) {
        if r.is_empty() || self.rects().iter().any(|&h| contains(h, r)) {
            return;
        }
        let mut i = 0;
        while i < self.len {
            if contains(r, self.rects[i]) {
                self.remove(i);
            } else {
                i += 1;
            }
        }
        if self.len < DAMAGE_MAX {
            self.rects[self.len] = r;
            self.len += 1;
            return;
        }
        if cfg!(feature = "canary-damage-drop") {
            return;
        }
        // Full. The cheapest way to make room, in pixels the merge adds.
        let waste = |a: Rect, b: Rect| area(bounds(a, b)) as i64 - area(a) as i64 - area(b) as i64;
        let mut best = (waste(self.rects[0], r), 0usize, None::<usize>);
        for i in 0..self.len {
            let w = waste(self.rects[i], r);
            if w < best.0 {
                best = (w, i, None);
            }
            for j in i + 1..self.len {
                let w = waste(self.rects[i], self.rects[j]);
                if w < best.0 {
                    best = (w, i, Some(j));
                }
            }
        }
        let at = best.1;
        match best {
            (_, i, None) => self.rects[i] = bounds(self.rects[i], r),
            (_, i, Some(j)) => {
                self.rects[i] = bounds(self.rects[i], self.rects[j]);
                self.rects[j] = r;
            }
        }
        // The grown rectangle may now hold others.
        let grown = self.rects[at];
        let mut kept = 0;
        for k in 0..self.len {
            if k == at || !contains(grown, self.rects[k]) {
                self.rects[kept] = self.rects[k];
                kept += 1;
            }
        }
        self.len = kept;
    }
}
