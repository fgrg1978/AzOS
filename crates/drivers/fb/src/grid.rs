// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The text grid behind the framebuffer console: a ring of rows, a cursor,
//! scrolling and the dirty rectangle a flush has to redraw. No hardware here;
//! the host tests run the scroll and dirty-rect math directly.
//!
//! **The terminal server's window onto it.** With a screen region attached
//! ([`Grid::attach_screen`], `azos_input_wire::screen`) the grid also
//! publishes what is on the screen (the rows, and whether each wrapped), keeps
//! the lines that scrolled off in a bounded scrollback, and notes the mouse
//! reporting modes programs ask for (`ESC [ ? 1000/1002/1003/1006 h|l`). In
//! return a flush draws the overlay the server asked for: a pointer cell and a
//! selection in inverse video, and the view scrolled back into the scrollback.
//! The overlay is drawn over the text and never written into it.

use crate::font::{CELL_H, CELL_W};
use crate::pixel::Surface;
use azos_input_wire::screen::{
    Overlay, Publisher, MOUSE_DRAG, MOUSE_MOTION, MOUSE_PRESS, MOUSE_SGR,
};

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

/// Escape-sequence state.
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
    /// Per storage row: it ended by auto-wrap, the text goes on in the next.
    wrapped: [bool; ROWS],
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
    /// The CSI being read: `?` seen, the finished parameters, the one being read.
    csi_private: bool,
    csi_params: [u32; 4],
    csi_n: usize,
    csi_cur: u32,
    /// The terminal server's window, once attached.
    screen: Option<Publisher>,
    /// Mouse reporting modes set on the console (`MOUSE_*`).
    mouse: u32,
    /// The server's last mode-clear count the grid acted on.
    clear_seen: u32,
    /// `prepare` ran since the last `flush` finished.
    prepared: bool,
    /// The overlay drawn on the screen now, and the one asked for.
    shown: Overlay,
    want: Overlay,
}

impl<const COLS: usize, const ROWS: usize> Grid<COLS, ROWS> {
    pub const fn new() -> Self {
        Self {
            cells: [[b' '; COLS]; ROWS],
            wrapped: [false; ROWS],
            cols: 0,
            rows: 0,
            top: 0,
            cx: 0,
            cy: 0,
            dirty: Dirty::CLEAN,
            scrolls: 0,
            esc: Esc::None,
            csi_private: false,
            csi_params: [0; 4],
            csi_n: 0,
            csi_cur: 0,
            screen: None,
            mouse: 0,
            clear_seen: 0,
            prepared: false,
            shown: Overlay { ptr: None, sel: None, view_off: 0 },
            want: Overlay { ptr: None, sel: None, view_off: 0 },
        }
    }

    /// Publish the screen into `p` from now on: its dimensions, what is on
    /// the screen now, and the lines that scroll off from here. Replaces a
    /// screen already attached.
    pub fn attach_screen(&mut self, mut p: Publisher) {
        p.set_dims(self.cols as u32, self.rows as u32);
        self.mouse = 0;
        p.set_mouse_mode(0);
        self.clear_seen = p.mode_clear_seq();
        self.screen = Some(p);
        self.shown = Overlay::default();
        self.want = Overlay::default();
        self.dirty.all = true;
    }

    /// The mouse modes programs have set on the console.
    pub fn mouse_mode(&self) -> u32 {
        self.mouse
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
        self.wrapped.fill(false);
        if let Some(p) = &mut self.screen {
            p.set_dims(self.cols as u32, self.rows as u32);
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

    /// Move to the start of the next row. `wrap`: the row is left because the
    /// text ran past the last column, not because the writer ended the line.
    fn newline(&mut self, wrap: bool) {
        let leaving = self.slot(self.cy);
        self.wrapped[leaving] = wrap;
        self.cx = 0;
        if self.cy + 1 < self.rows {
            self.cy += 1;
        } else {
            // Scroll: the oldest row becomes the new, blank bottom row.
            let old = self.slot(0);
            if let Some(p) = &mut self.screen {
                p.push_scrollback(&self.cells[old][..self.cols], self.wrapped[old]);
            }
            self.cells[old][..self.cols].fill(b' ');
            self.wrapped[old] = false;
            self.top = (self.top + 1) % self.rows;
            self.scrolls += 1;
            self.dirty.all = true;
        }
    }

    /// A finished CSI sequence: the mouse modes are the only thing kept.
    fn csi_done(&mut self, fin: u8) {
        if self.csi_n < self.csi_params.len() {
            self.csi_params[self.csi_n] = self.csi_cur;
            self.csi_n += 1;
        }
        if self.csi_private && (fin == b'h' || fin == b'l') {
            let before = self.mouse;
            for &p in &self.csi_params[..self.csi_n] {
                let bit = match p {
                    1000 => MOUSE_PRESS,
                    1002 => MOUSE_DRAG,
                    1003 => MOUSE_MOTION,
                    1006 => MOUSE_SGR,
                    _ => continue,
                };
                if fin == b'h' {
                    self.mouse |= bit;
                } else {
                    self.mouse &= !bit;
                }
            }
            if self.mouse != before {
                if let Some(s) = &self.screen {
                    s.set_mouse_mode(self.mouse);
                }
            }
        }
    }

    /// Consume console bytes: printable ASCII is stored, `\n` `\r` `\t`
    /// and backspace move the cursor, ANSI CSI sequences are skipped (the
    /// mouse reporting modes are noted on the way), and NUL is ignored: it is
    /// the byte the terminal server writes to have the overlay redrawn.
    pub fn put_bytes(&mut self, bytes: &[u8]) {
        if self.cols == 0 || self.rows == 0 {
            return;
        }
        for &b in bytes {
            match self.esc {
                Esc::Got => {
                    self.esc = if b == b'[' { Esc::Csi } else { Esc::None };
                    self.csi_private = false;
                    self.csi_n = 0;
                    self.csi_cur = 0;
                    continue;
                }
                Esc::Csi => {
                    match b {
                        b'?' => self.csi_private = true,
                        b'0'..=b'9' => self.csi_cur = (self.csi_cur * 10 + (b - b'0') as u32).min(99_999),
                        b';' => {
                            if self.csi_n < self.csi_params.len() {
                                self.csi_params[self.csi_n] = self.csi_cur;
                                self.csi_n += 1;
                            }
                            self.csi_cur = 0;
                        }
                        0x40..=0x7E => {
                            self.esc = Esc::None;
                            self.csi_done(b);
                        }
                        _ => {}
                    }
                    continue;
                }
                Esc::None => {}
            }
            match b {
                0x1B => self.esc = Esc::Got,
                b'\n' => self.newline(false),
                0x00 => {}
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
            self.newline(true);
        }
        let s = self.slot(self.cy);
        self.cells[s][self.cx] = b;
        self.dirty.mark(self.cx, self.cy);
        self.cx += 1;
    }

    /// Rows `r0..=r1` of the view need drawing.
    fn mark_rows(&mut self, r0: usize, r1: usize) {
        self.dirty.mark(0, r0.min(self.rows - 1));
        self.dirty.mark(self.cols - 1, r1.min(self.rows - 1));
    }

    /// The overlay changed from `shown` to `want`: mark what must be redrawn.
    fn mark_overlay(&mut self) {
        let (a, b) = (self.shown, self.want);
        if a.view_off != b.view_off {
            self.dirty.all = true;
            return;
        }
        for (_, r) in [a.ptr, b.ptr].into_iter().flatten() {
            self.mark_rows(r as usize, r as usize);
        }
        let cols = self.cols as u32;
        // Cells whose highlight changed lie between the two starts and between
        // the two ends; with only one selection, all of it.
        let span = |lo: u32, hi: u32, me: &mut Self| me.mark_rows((lo / cols) as usize, (hi / cols) as usize);
        match (a.sel, b.sel) {
            (Some((l1, h1)), Some((l2, h2))) => {
                if l1 != l2 {
                    span(l1.min(l2), l1.max(l2), self);
                }
                if h1 != h2 {
                    span(h1.min(h2), h1.max(h2), self);
                }
            }
            (Some((l, h)), None) | (None, Some((l, h))) => span(l, h, self),
            (None, None) => {}
        }
    }

    /// What a draw starts with, once per flush: take the screen region's mode
    /// clear and overlay, publish the rows that changed, mark what the overlay
    /// changed. `dirty_pixels` runs it first so that its rectangle is the
    /// one `flush` draws; `flush` then finds it done.
    fn prepare(&mut self) {
        if self.prepared {
            return;
        }
        self.prepared = true;
        if let Some(s) = &self.screen {
            if s.mode_clear_seq() != self.clear_seen {
                self.clear_seen = s.mode_clear_seq();
                self.mouse = 0;
                s.set_mouse_mode(0);
            }
            if let Some(o) = s.overlay() {
                self.want = o;
            }
        }
        if !self.dirty.empty || self.dirty.all {
            self.publish();
        }
        if self.want != self.shown {
            self.mark_overlay();
        }
    }

    /// Publish the rows that changed to the screen region.
    fn publish(&mut self) {
        let Some(p) = &mut self.screen else { return };
        let (r0, r1) = if self.dirty.all { (0, self.rows - 1) } else { (self.dirty.r0, self.dirty.r1.min(self.rows - 1)) };
        for r in r0..=r1 {
            let s = (self.top + r) % self.rows;
            p.put_row(r as u32, &self.cells[s][..self.cols], self.wrapped[s]);
        }
        p.bump_seq();
    }

    /// The pixel rectangle `flush` would redraw now, `None` when it would draw
    /// nothing: the console reports it to the display before the flush marks
    /// the grid clean. It first settles what `flush` settles (the screen
    /// region, the overlay's changes), so a pointer or a selection that moved
    /// is in the rectangle; the `flush` that follows does not do it again.
    pub fn dirty_pixels(&mut self) -> Option<crate::Rect> {
        if self.cols == 0 || self.rows == 0 {
            return None;
        }
        self.prepare();
        let (c0, c1, r0, r1) = if self.dirty.all {
            (0, self.cols - 1, 0, self.rows - 1)
        } else if self.dirty.empty {
            return None;
        } else {
            (self.dirty.c0, self.dirty.c1.min(self.cols - 1), self.dirty.r0, self.dirty.r1.min(self.rows - 1))
        };
        Some(crate::Rect {
            x: (c0 * CELL_W) as u32,
            y: (r0 * CELL_H) as u32,
            w: ((c1 - c0 + 1) * CELL_W) as u32,
            h: ((r1 - r0 + 1) * CELL_H) as u32,
        })
    }

    /// Draw what changed onto `surf`, then mark the grid clean. Returns the
    /// number of cells drawn. Publishes the changed rows to the screen region
    /// and draws the overlay the terminal server asked for.
    pub fn flush(&mut self, surf: &Surface, fg: u32, bg: u32) -> usize {
        if self.cols == 0 || self.rows == 0 {
            return 0;
        }
        self.prepare();
        let (c0, c1, r0, r1) = if self.dirty.all {
            (0, self.cols - 1, 0, self.rows - 1)
        } else if self.dirty.empty {
            self.prepared = false;
            return 0;
        } else {
            (self.dirty.c0, self.dirty.c1.min(self.cols - 1), self.dirty.r0, self.dirty.r1.min(self.rows - 1))
        };
        let want = self.want;
        let off = want.view_off as usize;
        let cols = self.cols as u32;
        let mut n = 0;
        for r in r0..=r1 {
            let mut text = [b' '; COLS];
            if r >= off {
                text[..self.cols].copy_from_slice(&self.cells[(self.top + r - off) % self.rows][..self.cols]);
            } else if let Some(p) = &self.screen {
                let _ = p.sb_row((off - r - 1) as u32, &mut text[..self.cols]);
            }
            for c in c0..=c1 {
                let at = r as u32 * cols + c as u32;
                let inverse = (want.ptr == Some((c as u32, r as u32))) ^ matches!(want.sel, Some((lo, hi)) if (lo..=hi).contains(&at));
                let (f, b) = if inverse { (bg, fg) } else { (fg, bg) };
                surf.draw_glyph(c * CELL_W, r * CELL_H, text[c], f, b);
                n += 1;
            }
        }
        self.shown = want;
        self.dirty = Dirty::CLEAN;
        self.prepared = false;
        n
    }
}
