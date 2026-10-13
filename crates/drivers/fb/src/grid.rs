// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The text grid behind the framebuffer console: a ring of rows, a cursor,
//! scrolling and the dirty rectangle a flush has to redraw. No hardware here;
//! the host tests run the scroll and dirty-rect math directly.

use crate::font::{CELL_H, CELL_W};
use crate::pixel::Surface;

/// How many text cells fit a pixel size.
pub const fn cells(pixels: usize, cell: usize) -> usize {
    pixels / cell
}

/// The rectangle of cells changed since the last flush; `all` after a scroll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dirty {
    pub all: bool,
    pub empty: bool,
    pub c0: usize,
    pub c1: usize,
    pub r0: usize,
    pub r1: usize,
}

impl Dirty {
    pub const CLEAN: Self = Self { all: false, empty: true, c0: 0, c1: 0, r0: 0, r1: 0 };

    pub fn mark(&mut self, col: usize, row: usize) {
        if self.empty {
            *self = Self { all: self.all, empty: false, c0: col, c1: col, r0: row, r1: row };
        } else {
            self.c0 = self.c0.min(col);
            self.c1 = self.c1.max(col);
            self.r0 = self.r0.min(row);
            self.r1 = self.r1.max(row);
        }
    }
}

/// Escape-sequence skipping state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Esc {
    None,
    Got,
    Csi,
}

/// A `COLS` x `ROWS` capacity text grid, of which the first `cols` x `rows`
/// are in use (the framebuffer decides at `init`).
pub struct Grid<const COLS: usize, const ROWS: usize> {
    cells: [[u8; COLS]; ROWS],
    pub cols: usize,
    pub rows: usize,
    /// Storage row shown as screen row 0.
    pub top: usize,
    pub cx: usize,
    pub cy: usize,
    pub dirty: Dirty,
    /// Screens scrolled by one line so far.
    pub scrolls: u64,
    esc: Esc,
}

impl<const COLS: usize, const ROWS: usize> Grid<COLS, ROWS> {
    pub const fn new() -> Self {
        Self {
            cells: [[b' '; COLS]; ROWS],
            cols: 0,
            rows: 0,
            top: 0,
            cx: 0,
            cy: 0,
            dirty: Dirty::CLEAN,
            scrolls: 0,
            esc: Esc::None,
        }
    }

    /// Size the grid for a surface in pixels (clamped to the capacity) and
    /// clear it. Returns `false` when not even one cell fits.
    pub fn resize(&mut self, width: usize, height: usize) -> bool {
        self.cols = cells(width, CELL_W).min(COLS);
        self.rows = cells(height, CELL_H).min(ROWS);
        self.top = 0;
        self.cx = 0;
        self.cy = 0;
        self.esc = Esc::None;
        for r in self.cells.iter_mut() {
            r.fill(b' ');
        }
        self.dirty = Dirty { all: true, ..Dirty::CLEAN };
        self.cols > 0 && self.rows > 0
    }

    #[inline]
    fn slot(&self, row: usize) -> usize {
        (self.top + row) % self.rows
    }

    /// The character at screen cell (`col`, `row`).
    pub fn at(&self, col: usize, row: usize) -> u8 {
        self.cells[self.slot(row)][col]
    }

    fn newline(&mut self) {
        self.cx = 0;
        if self.cy + 1 < self.rows {
            self.cy += 1;
        } else {
            // Scroll: the oldest row becomes the new, blank bottom row.
            let old = self.slot(0);
            self.cells[old][..self.cols].fill(b' ');
            self.top = (self.top + 1) % self.rows;
            self.scrolls += 1;
            self.dirty.all = true;
        }
    }

    /// Consume console bytes: printable ASCII is stored, `\n` `\r` `\t`
    /// and backspace move the cursor, ANSI CSI sequences are skipped.
    pub fn put_bytes(&mut self, bytes: &[u8]) {
        if self.cols == 0 || self.rows == 0 {
            return;
        }
        for &b in bytes {
            match self.esc {
                Esc::Got => {
                    self.esc = if b == b'[' { Esc::Csi } else { Esc::None };
                    continue;
                }
                Esc::Csi => {
                    if (0x40..=0x7E).contains(&b) {
                        self.esc = Esc::None;
                    }
                    continue;
                }
                Esc::None => {}
            }
            match b {
                0x1B => self.esc = Esc::Got,
                b'\n' => self.newline(),
                b'\r' => self.cx = 0,
                b'\t' => {
                    let next = (self.cx / 8 + 1) * 8;
                    while self.cx < next.min(self.cols) {
                        self.put_char(b' ');
                    }
                }
                0x08 => self.cx = self.cx.saturating_sub(1),
                0x20..=0x7E => self.put_char(b),
                _ => self.put_char(b'?'),
            }
        }
    }

    fn put_char(&mut self, b: u8) {
        if self.cx >= self.cols {
            self.newline();
        }
        let s = self.slot(self.cy);
        self.cells[s][self.cx] = b;
        self.dirty.mark(self.cx, self.cy);
        self.cx += 1;
    }

    /// Draw what changed onto `surf`, then mark the grid clean. Returns the
    /// number of cells drawn.
    pub fn flush(&mut self, surf: &Surface, fg: u32, bg: u32) -> usize {
        let (c0, c1, r0, r1) = if self.dirty.all {
            (0, self.cols - 1, 0, self.rows - 1)
        } else if self.dirty.empty {
            return 0;
        } else {
            (self.dirty.c0, self.dirty.c1.min(self.cols - 1), self.dirty.r0, self.dirty.r1.min(self.rows - 1))
        };
        let mut n = 0;
        for r in r0..=r1 {
            for c in c0..=c1 {
                surf.draw_glyph(c * CELL_W, r * CELL_H, self.at(c, r), fg, bg);
                n += 1;
            }
        }
        self.dirty = Dirty::CLEAN;
        n
    }
}
