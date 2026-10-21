// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The console mouse, in the manner of gpm: a pointer cell, text selection,
//! paste, and scrollback by the wheel; or, when a program asked the terminal
//! to report the mouse, the xterm mouse reports instead.
//!
//! The pointer is a cell of the screen. Relative devices move it by
//! [`MICKEYS_X`] x [`MICKEYS_Y`] counts per cell, a tablet places it by
//! proportion. What the screen holds is read from the shared screen region
//! ([`Viewer::row`], one row at a time: the live screen and the scrollback
//! behind it); what the server wants drawn (pointer cell, selection,
//! scrollback offset) is written back as an [`Overlay`] for the renderer.
//!
//! * **Left drag** selects, cell by cell; a selection runs across the line
//!   breaks of the text it covers and joins the rows the terminal wrapped
//!   itself (the row's wrap flag), so a long command line copies as one line.
//!   **Double click** selects a word, **triple click** the row; dragging
//!   after either extends by words or rows. **Right button** extends the
//!   selection to the pointer. A finished selection is copied to the paste
//!   buffer ([`CLIP_MAX`] bytes).
//! * **Middle button** pastes the buffer into the terminal input.
//! * **The wheel** scrolls the scrollback, [`WHEEL_LINES`] rows a notch.
//!   Output, or a key, brings the view back to the live screen.
//! * **Reporting** (the program set `ESC [ ? 1000 h`, `1002 h` or `1003 h`
//!   on the console, which the renderer saw): buttons, motion and the wheel
//!   go to the program as X10 or, with `1006`, SGR reports on the terminal
//!   input, and nothing is selected. Shift held gives the selection back,
//!   as in xterm.
//!
//! Pure given a [`Viewer`] and a [`Sink`]: `tests/host/term-tests` pulls this
//! file in with `#[path]`.

use crate::keys::Mods;
use azos_input_wire::event::*;
use azos_input_wire::screen::{Overlay, Viewer, MOUSE_ANY, MOUSE_DRAG, MOUSE_MOTION, MOUSE_SGR};

/// Relative counts per cell column.
pub const MICKEYS_X: i32 = 8;
/// Relative counts per cell row.
pub const MICKEYS_Y: i32 = 16;
/// Two presses on one cell within this are a double click.
pub const DOUBLE_CLICK_NS: u64 = 400_000_000;
/// Rows a wheel notch scrolls.
pub const WHEEL_LINES: u32 = 3;
/// Bytes of the paste buffer.
pub const CLIP_MAX: usize = 1024;
/// Most columns a row can have (`FB_CONSOLE_COLS_MAX`'s range ends here).
pub const ROW_MAX: usize = 512;

/// Where the terminal input bytes go.
pub trait Sink {
    /// Bytes typed (a paste).
    fn push(&mut self, bytes: &[u8]);
    /// A mouse report for the program that asked for them.
    fn report(&mut self, bytes: &[u8]) {
        self.push(bytes);
    }
    /// The secure-attention chord (Ctrl+Alt+Del) was pressed. The chord makes
    /// no bytes: no program ever reads it.
    fn attention(&mut self) {}
}

/// How far a drag extends the selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gran {
    Cell,
    Word,
    Line,
}

/// The cell class a double click groups by.
fn class(c: u8) -> u8 {
    match c {
        b' ' | 0 => 0,
        c if c.is_ascii_alphanumeric() => 1,
        b'_' | b'-' | b'.' | b'/' | b'~' | b':' | b'@' | b'%' | b'+' | b'=' | b',' | b'#' | b'?' | b'&' => 1,
        _ => 2,
    }
}

#[derive(Clone, Copy, Debug)]
struct Selection {
    /// The selection, view cell indices, `lo <= hi`, inclusive.
    lo: u32,
    hi: u32,
}

/// The mouse.
pub struct Mouse {
    x: i32,
    y: i32,
    visible: bool,
    buttons: u8,
    sel: Option<Selection>,
    /// A press is down and may become a selection.
    drag: Option<(Gran, (u32, u32))>,
    view_off: u32,
    seq: u32,
    cols: u32,
    rows: u32,
    last_click: Option<(u64, u32)>,
    clicks: u8,
    /// The cell of the last motion report.
    reported: Option<(u32, u32)>,
    clip: [u8; CLIP_MAX],
    clip_len: usize,
    dirty: bool,
}

impl Mouse {
    pub const fn new() -> Self {
        Mouse {
            x: 0,
            y: 0,
            visible: false,
            buttons: 0,
            sel: None,
            drag: None,
            view_off: 0,
            seq: 0,
            cols: 0,
            rows: 0,
            last_click: None,
            clicks: 0,
            reported: None,
            clip: [0; CLIP_MAX],
            clip_len: 0,
            dirty: false,
        }
    }

    fn cell(&self) -> (u32, u32) {
        let col = (self.x / MICKEYS_X) as u32;
        let row = (self.y / MICKEYS_Y) as u32;
        (col.min(self.cols.saturating_sub(1)), row.min(self.rows.saturating_sub(1)))
    }

    fn index(&self, col: u32, row: u32) -> u32 {
        row * self.cols + col
    }

    /// What to draw.
    pub fn overlay(&self) -> Overlay {
        Overlay {
            ptr: self.visible.then(|| self.cell()),
            sel: self.sel.map(|s| (s.lo, s.hi)),
            view_off: self.view_off,
        }
    }

    /// Did the overlay change since the last call? (Clears the flag.)
    pub fn take_dirty(&mut self) -> bool {
        core::mem::take(&mut self.dirty)
    }

    /// The paste buffer.
    #[cfg(test)]
    pub fn clip(&self) -> &[u8] {
        &self.clip[..self.clip_len]
    }

    #[cfg(test)]
    pub fn has_selection(&self) -> bool {
        self.sel.is_some()
    }

    /// Follow the screen: its size, and its content. A new content sequence
    /// means the cells moved under a selection, and output brings a scrolled
    /// view back to the live screen.
    pub fn sync(&mut self, scr: &Viewer) {
        let (cols, rows) = scr.dims();
        if (cols, rows) != (self.cols, self.rows) {
            self.cols = cols;
            self.rows = rows;
            self.x = self.x.clamp(0, (cols as i32 * MICKEYS_X - 1).max(0));
            self.y = self.y.clamp(0, (rows as i32 * MICKEYS_Y - 1).max(0));
            self.drop_selection();
            self.dirty = true;
        }
        let seq = scr.seq();
        if seq != self.seq {
            self.seq = seq;
            if self.sel.is_some() || self.drag.is_some() || self.view_off != 0 {
                self.drop_selection();
                self.view_off = 0;
                self.dirty = true;
            }
        }
    }

    fn drop_selection(&mut self) {
        if self.sel.take().is_some() {
            self.dirty = true;
        }
        self.drag = None;
    }

    /// A key was pressed: hide the pointer and return to the live screen.
    pub fn key_pressed(&mut self) {
        if self.visible || self.view_off != 0 {
            self.visible = false;
            if self.view_off != 0 {
                self.view_off = 0;
                self.drop_selection();
            }
            self.dirty = true;
        }
    }

    // ── motion ──────────────────────────────────────────────────────────────

    /// Relative motion in device counts.
    pub fn rel(&mut self, axis: u16, delta: i32, scr: &Viewer, mods: &Mods, sink: &mut impl Sink) {
        if self.cols == 0 {
            return;
        }
        match axis {
            // `delta` is device data, any i32: saturate, then clamp.
            REL_X => self.x = self.x.saturating_add(delta).clamp(0, self.cols as i32 * MICKEYS_X - 1),
            REL_Y => self.y = self.y.saturating_add(delta).clamp(0, self.rows as i32 * MICKEYS_Y - 1),
            _ => return,
        }
        self.moved(scr, mods, sink);
    }

    /// Absolute position (a tablet), `0..=ABS_MAX`.
    pub fn abs(&mut self, axis: u16, value: u32, scr: &Viewer, mods: &Mods, sink: &mut impl Sink) {
        if self.cols == 0 {
            return;
        }
        let v = value.min(ABS_MAX) as u64;
        match axis {
            ABS_X => self.x = (v * (self.cols as u64 * MICKEYS_X as u64) / (ABS_MAX as u64 + 1)) as i32,
            ABS_Y => self.y = (v * (self.rows as u64 * MICKEYS_Y as u64) / (ABS_MAX as u64 + 1)) as i32,
            _ => return,
        }
        self.moved(scr, mods, sink);
    }

    fn moved(&mut self, scr: &Viewer, mods: &Mods, sink: &mut impl Sink) {
        if !self.visible {
            self.visible = true;
            self.dirty = true;
        }
        let (col, row) = self.cell();
        if self.reported == Some((col, row)) && !self.dirty {
            return;
        }
        let mode = scr.mouse_mode();
        if mode & MOUSE_ANY != 0 && !mods.shift() {
            if self.reported != Some((col, row)) {
                let held = self.buttons;
                if mode & MOUSE_MOTION != 0 || (mode & MOUSE_DRAG != 0 && held != 0) {
                    let b = if held == 0 { 3 } else { held.trailing_zeros() as u8 };
                    report(sink, mode, 32 + b, col, row, true, mods);
                }
            }
            self.reported = Some((col, row));
            self.dirty = true;
            return;
        }
        self.reported = Some((col, row));
        self.dirty = true;
        if let Some((gran, anchor)) = self.drag {
            self.extend(scr, gran, anchor, col, row);
        }
    }

    // ── buttons ─────────────────────────────────────────────────────────────

    /// A button went down or up.
    pub fn button(&mut self, code: u16, down: bool, now_ns: u64, scr: &Viewer, mods: &Mods, sink: &mut impl Sink) {
        let bit = match code {
            BTN_LEFT => 1u8,
            BTN_MIDDLE => 2,
            BTN_RIGHT => 4,
            _ => return,
        };
        if self.cols == 0 {
            return;
        }
        if down {
            self.buttons |= bit;
        } else {
            self.buttons &= !bit;
        }
        if !self.visible {
            self.visible = true;
            self.dirty = true;
        }
        let (col, row) = self.cell();
        let mode = scr.mouse_mode();
        if mode & MOUSE_ANY != 0 && !mods.shift() {
            let b = bit.trailing_zeros() as u8;
            report(sink, mode, if down || mode & MOUSE_SGR != 0 { b } else { 3 }, col, row, down, mods);
            return;
        }
        match (code, down) {
            (BTN_LEFT, true) => self.press(now_ns, scr, col, row),
            (BTN_LEFT, false) => self.release(scr),
            (BTN_MIDDLE, true) => {
                if self.clip_len > 0 {
                    sink.push(&self.clip[..self.clip_len]);
                }
            }
            (BTN_RIGHT, true) => {
                if let Some(s) = self.sel {
                    let at = self.index(col, row);
                    let (anchor, gran) = if at < s.lo { ((s.hi, s.hi), Gran::Cell) } else { ((s.lo, s.lo), Gran::Cell) };
                    self.extend(scr, gran, anchor, col, row);
                    self.copy(scr);
                }
            }
            _ => {}
        }
    }

    /// Events may have been lost (a full ring): let go of every button held,
    /// as if it were released now. The selection a held left button was
    /// dragging is finished and copied; a program that was told a button went
    /// down is told it went up.
    pub fn release_all(&mut self, now_ns: u64, scr: &Viewer, mods: &Mods, sink: &mut impl Sink) {
        for (code, bit) in [(BTN_LEFT, 1u8), (BTN_MIDDLE, 2), (BTN_RIGHT, 4)] {
            if self.buttons & bit != 0 {
                self.button(code, false, now_ns, scr, mods, sink);
            }
        }
        self.buttons = 0;
        self.release(scr);
    }

    fn press(&mut self, now_ns: u64, scr: &Viewer, col: u32, row: u32) {
        let at = self.index(col, row);
        let again = matches!(self.last_click, Some((t, c)) if c == at && now_ns.saturating_sub(t) <= DOUBLE_CLICK_NS);
        self.clicks = if again { (self.clicks + 1).min(3) } else { 1 };
        self.last_click = Some((now_ns, at));
        let had = self.sel.take().is_some();
        let (gran, anchor) = match self.clicks {
            1 => (Gran::Cell, (at, at)),
            2 => (Gran::Word, self.word_bounds(scr, col, row)),
            _ => (Gran::Line, (self.index(0, row), self.index(self.cols - 1, row))),
        };
        self.drag = Some((gran, anchor));
        if self.clicks > 1 {
            self.sel = Some(Selection { lo: anchor.0, hi: anchor.1 });
        }
        if had || self.sel.is_some() {
            self.dirty = true;
        }
    }

    fn release(&mut self, scr: &Viewer) {
        if self.drag.take().is_some() && self.sel.is_some() {
            self.copy(scr);
        }
    }

    /// Move the selection's free end to the pointer, by the press's unit.
    fn extend(&mut self, scr: &Viewer, gran: Gran, anchor: (u32, u32), col: u32, row: u32) {
        let at = self.index(col, row);
        let (plo, phi) = match gran {
            Gran::Cell => (at, at),
            Gran::Word => self.word_bounds(scr, col, row),
            Gran::Line => (self.index(0, row), self.index(self.cols - 1, row)),
        };
        let (lo, hi) = (anchor.0.min(plo), anchor.1.max(phi));
        // A click that has not left its cell selects nothing.
        let sel = if gran == Gran::Cell && lo == hi { None } else { Some(Selection { lo, hi }) };
        if sel.map(|s| (s.lo, s.hi)) != self.sel.map(|s| (s.lo, s.hi)) {
            self.sel = sel;
            self.dirty = true;
        }
    }

    /// The cells of the word at (`col`, `row`), as view cell indices.
    fn word_bounds(&self, scr: &Viewer, col: u32, row: u32) -> (u32, u32) {
        let mut buf = [0u8; ROW_MAX];
        let Some((n, _)) = self.view_row(scr, row, &mut buf) else {
            let at = self.index(col, row);
            return (at, at);
        };
        let c = (col as usize).min(n.saturating_sub(1));
        let k = class(buf[c]);
        let (mut a, mut b) = (c, c);
        while a > 0 && class(buf[a - 1]) == k {
            a -= 1;
        }
        while b + 1 < n && class(buf[b + 1]) == k {
            b += 1;
        }
        (self.index(a as u32, row), self.index(b as u32, row))
    }

    fn view_row(&self, scr: &Viewer, row: u32, out: &mut [u8; ROW_MAX]) -> Option<(usize, bool)> {
        scr.row(row as i32 - self.view_off as i32, out)
    }

    // ── wheel ───────────────────────────────────────────────────────────────

    /// The wheel turned: positive scrolls up (back into the scrollback).
    pub fn wheel(&mut self, v: i32, scr: &Viewer, mods: &Mods, sink: &mut impl Sink) {
        if v == 0 || self.cols == 0 {
            return;
        }
        let mode = scr.mouse_mode();
        if mode & MOUSE_ANY != 0 && !mods.shift() {
            let (col, row) = self.cell();
            for _ in 0..v.unsigned_abs().min(4) {
                report(sink, mode, if v > 0 { 64 } else { 65 }, col, row, true, mods);
            }
            return;
        }
        let max = scr.sb_count();
        // `v` is device data, any i32 (`unsigned_abs` of `i32::MIN` is 2^31).
        let step = WHEEL_LINES.saturating_mul(v.unsigned_abs());
        let off = if v > 0 { self.view_off.saturating_add(step).min(max) } else { self.view_off.saturating_sub(step) };
        if off != self.view_off {
            self.view_off = off;
            self.drop_selection();
            self.dirty = true;
        }
    }

    // ── copy ────────────────────────────────────────────────────────────────

    /// Copy the selection's text into the paste buffer.
    fn copy(&mut self, scr: &Viewer) {
        let Some(s) = self.sel else { return };
        let mut n = 0;
        let (c0, r0) = (s.lo % self.cols, s.lo / self.cols);
        let (c1, r1) = (s.hi % self.cols, s.hi / self.cols);
        for r in r0..=r1 {
            let mut buf = [0u8; ROW_MAX];
            let Some((len, wrapped)) = self.view_row(scr, r, &mut buf) else { break };
            let from = if r == r0 { c0 as usize } else { 0 };
            let mut to = if r == r1 { (c1 as usize + 1).min(len) } else { len };
            // A row that ends here for good loses its trailing blanks when
            // the selection reaches its end; a wrapped row's blanks are text.
            if !wrapped && (r != r1 || c1 as usize + 1 >= len) {
                while to > from && buf[to - 1] == b' ' {
                    to -= 1;
                }
            }
            let part = &buf[from.min(to)..to];
            let room = CLIP_MAX - n;
            let take = part.len().min(room);
            self.clip[n..n + take].copy_from_slice(&part[..take]);
            n += take;
            if r != r1 && !wrapped && n < CLIP_MAX {
                self.clip[n] = b'\n';
                n += 1;
            }
        }
        self.clip_len = n;
    }
}

impl Default for Mouse {
    fn default() -> Self {
        Self::new()
    }
}

/// One xterm mouse report: `b` the button code (0 left, 1 middle, 2 right,
/// 3 none/release, 32+ motion, 64/65 wheel), modifiers added from `mods`.
fn report(sink: &mut impl Sink, mode: u32, b: u8, col: u32, row: u32, press: bool, mods: &Mods) {
    let b = b + 4 * mods.shift() as u8 + 8 * mods.alt() as u8 + 16 * mods.ctrl() as u8;
    let mut out = [0u8; 24];
    let mut n = 0;
    let mut put = |bytes: &[u8]| {
        out[n..n + bytes.len()].copy_from_slice(bytes);
        n += bytes.len();
    };
    if mode & MOUSE_SGR != 0 {
        put(b"\x1b[<");
        put_num(&mut put, b as u32);
        put(b";");
        put_num(&mut put, col + 1);
        put(b";");
        put_num(&mut put, row + 1);
        put(if press { b"M" } else { b"m" });
    } else {
        // The X10 form carries each value as one byte past 32: it ends at 223.
        if col + 1 > 222 || row + 1 > 222 {
            return;
        }
        put(&[0x1b, b'[', b'M', 32 + b, 32 + col as u8 + 1, 32 + row as u8 + 1]);
    }
    sink.report(&out[..n]);
}

fn put_num(put: &mut impl FnMut(&[u8]), mut v: u32) {
    let mut d = [0u8; 10];
    let mut i = d.len();
    loop {
        i -= 1;
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    put(&d[i..]);
}
