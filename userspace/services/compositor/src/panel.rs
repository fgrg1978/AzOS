// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The two trusted panels the compositor alone draws: the trusted-path banner
//! and the "why was this refused" panel.
//!
//! Both are XRGB8888 images the scene shows as overlays above every window
//! (`windows.rs`). A client has no way to draw over them and no way to learn
//! what they look like beyond what any screen shows, which is the point of the
//! banner: it is what the system says when it saw the Secure Attention Key.
//!
//! The panel's rows come from the decision server: the newest refusals, each as
//! a header (id, rule, verdict, subject) and the alternative the rule rejected
//! (`azos_decision::RULES`). Text is the console font (8x16, the framebuffer
//! console's), included from `crates/drivers/fb/src/font.rs` as a module of the
//! image (`crate::font`).

use azos_decisions::{ProvenanceRecord, RULES, VERDICTS};
use core::fmt::Write;

use crate::font::{self, CELL_H, CELL_W};

/// Text columns of the refusal panel.
pub const WHY_COLS: usize = 56;
/// Text rows of the refusal panel (the title and three decisions of two rows).
pub const WHY_ROWS: usize = 7;
/// Decisions the panel shows.
pub const WHY_DECISIONS: usize = (WHY_ROWS - 1) / 2;
/// Padding around the text, pixels.
const PAD: usize = 8;

/// Width of both panels, pixels.
pub const PANEL_W: usize = WHY_COLS * CELL_W + 2 * PAD;
/// Height of the banner: two text rows.
pub const BANNER_H: usize = 2 * CELL_H + 2 * PAD;
/// Height of the refusal panel.
pub const WHY_H: usize = WHY_ROWS * CELL_H + 2 * PAD;
/// Bytes of the banner's pixels.
pub const BANNER_BYTES: usize = PANEL_W * BANNER_H * 4;
/// Bytes of the refusal panel's pixels.
pub const WHY_BYTES: usize = PANEL_W * WHY_H * 4;

const BANNER_BG: u32 = 0x0010_2C5C;
const BANNER_EDGE: u32 = 0x00FF_C83C;
const WHY_BG: u32 = 0x0018_1818;
const TEXT: u32 = 0x00F0_F0F0;
const TITLE: u32 = 0x00FF_C83C;
const DIM: u32 = 0x00A0_A0A0;

/// An XRGB8888 image being drawn.
struct Canvas<'a> {
    px: &'a mut [u8],
    w: usize,
    h: usize,
}

impl Canvas<'_> {
    fn put(&mut self, x: usize, y: usize, rgb: u32) {
        if x >= self.w || y >= self.h {
            return;
        }
        let at = (y * self.w + x) * 4;
        if let Some(p) = self.px.get_mut(at..at + 4) {
            p.copy_from_slice(&[rgb as u8, (rgb >> 8) as u8, (rgb >> 16) as u8, 0]);
        }
    }

    fn fill(&mut self, rgb: u32) {
        for y in 0..self.h {
            for x in 0..self.w {
                self.put(x, y, rgb);
            }
        }
    }

    /// A `t`-pixel frame round the image.
    fn frame(&mut self, t: usize, rgb: u32) {
        for y in 0..self.h {
            for x in 0..self.w {
                if x < t || y < t || x + t >= self.w || y + t >= self.h {
                    self.put(x, y, rgb);
                }
            }
        }
    }

    /// `s` at text cell (`col`, `row`) inside the padding; characters past the
    /// image are cut.
    fn text(&mut self, col: usize, row: usize, s: &[u8], rgb: u32) {
        for (i, &c) in s.iter().enumerate() {
            let g = font::glyph(c);
            let (x0, y0) = (PAD + (col + i) * CELL_W, PAD + row * CELL_H);
            for (gy, bits) in g.iter().enumerate() {
                for gx in 0..CELL_W {
                    if bits & (0x80 >> gx) != 0 {
                        self.put(x0 + gx, y0 + gy, rgb);
                    }
                }
            }
        }
    }
}

/// A fixed-width text row that cuts what does not fit.
pub struct Row {
    b: [u8; WHY_COLS],
    n: usize,
}

impl Row {
    pub const fn new() -> Row {
        Row { b: [b' '; WHY_COLS], n: 0 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.b[..self.n]
    }
}

impl Default for Row {
    fn default() -> Self {
        Row::new()
    }
}

impl Write for Row {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &c in s.as_bytes() {
            if self.n >= WHY_COLS {
                break;
            }
            // Printable ASCII only; the font shows anything else as `?`.
            self.b[self.n] = if (0x20..0x7F).contains(&c) { c } else { b'?' };
            self.n += 1;
        }
        Ok(())
    }
}

/// The rows of the refusal panel under its title.
pub struct Why {
    rows: [Row; WHY_ROWS - 1],
    n: usize,
}

impl Why {
    pub const fn new() -> Why {
        const EMPTY: Row = Row::new();
        Why { rows: [EMPTY; WHY_ROWS - 1], n: 0 }
    }

    /// The rows used.
    pub fn rows(&self) -> &[Row] {
        &self.rows[..self.n]
    }

    fn next(&mut self) -> Option<&mut Row> {
        let r = self.rows.get_mut(self.n)?;
        self.n += 1;
        Some(r)
    }

    /// A plain line (no decision to show).
    pub fn note(&mut self, s: &str) {
        if let Some(r) = self.next() {
            let _ = r.write_str(s);
        }
    }

    /// One decision as two rows: who decided what about whom, and the
    /// alternative the rule rejected. `false` when the panel is full.
    pub fn decision(&mut self, rec: &ProvenanceRecord) -> bool {
        if self.n + 2 > self.rows.len() {
            return false;
        }
        let info = RULES.get(rec.rule as usize);
        let verdict = VERDICTS.get(rec.verdict as usize).copied().unwrap_or("?");
        if let Some(r) = self.next() {
            let (name, subject) = match info {
                Some(i) => (i.name, i.subject.split('|').next().unwrap_or("")),
                None => ("unknown-rule", "subject"),
            };
            let _ = write!(r, "#{} {} {} {}={}", rec.seq, name, verdict, subject, rec.subject);
        }
        if let Some(r) = self.next() {
            let _ = match info {
                Some(i) => write!(r, "  not: {}", i.rejected_if_no),
                None => write!(r, "  (no such rule)"),
            };
        }
        true
    }
}

impl Default for Why {
    fn default() -> Self {
        Why::new()
    }
}

/// Draw the trusted-path banner into `px` (`PANEL_W` x `BANNER_H`, XRGB8888):
/// `chords` is the count of Secure Attention Key chords, `ms` how long the focus
/// is held back.
pub fn render_banner(px: &mut [u8], chords: u32, ms: u32) {
    let mut c = Canvas { px, w: PANEL_W, h: BANNER_H };
    c.fill(BANNER_BG);
    c.frame(2, BANNER_EDGE);
    let mut r = Row::new();
    let _ = write!(r, "TRUSTED PATH: the system saw Ctrl+Alt+Delete (#{chords})");
    c.text(0, 0, r.as_bytes(), TITLE);
    let mut r = Row::new();
    let _ = write!(r, "No application draws this. Keyboard held back {ms} ms.");
    c.text(0, 1, r.as_bytes(), TEXT);
}

/// Draw the refusal panel into `px` (`PANEL_W` x `WHY_H`, XRGB8888).
pub fn render_why(px: &mut [u8], why: &Why) {
    let mut c = Canvas { px, w: PANEL_W, h: WHY_H };
    c.fill(WHY_BG);
    c.frame(1, DIM);
    c.text(0, 0, b"Why was this refused? (newest refusals, decisd)", TITLE);
    for (i, r) in why.rows().iter().enumerate() {
        // The second row of a decision is the dimmer one.
        let dim = r.as_bytes().starts_with(b"  ");
        c.text(0, 1 + i, r.as_bytes(), if dim { DIM } else { TEXT });
    }
}
