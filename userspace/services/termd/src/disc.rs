// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The terminal's line discipline: modes, focus, type-ahead, and the typed
//! events the Terminal interface delivers.
//!
//! Pure: no syscalls. The server feeds it the bytes the console produced
//! ([`Discipline::push`]), asks for the next event ([`Discipline::step`]) and
//! writes what it wants shown ([`Discipline::take_output`]).
//! `tests/host/term-tests` pulls this file in with `#[path]`.
//!
//! * **Cooked** (the default): bytes go through the line editor
//!   (`edit.rs`); the event is [`Event::Line`] when Enter completes a line.
//! * **Raw**: no editing; the event is [`Event::Bytes`] with what was typed.
//! * **Echo**: what the editor (or, in raw mode, the byte) would show is
//!   dropped when off. The prompt of [`Discipline::begin_line`] is shown
//!   either way; it is the client's text, not an echo.
//! * **The interrupt key (0x03)** is an event in both modes: [`Event::Interrupt`]
//!   carrying the foreground job. The line being edited is cleared and `^C`
//!   shown (if echo is on). Nothing is signalled.
//! * **Focus** ([`Discipline::set_foreground`]): job 0 is the client. While a
//!   job has the focus the discipline delivers only interrupts; every other
//!   byte is held (type-ahead, [`HELD_MAX`] bytes) and replayed through the
//!   mode in force when the focus comes back.
//! * **End of input** (0x04 on an empty line) is [`Event::Eof`], in cooked
//!   mode only; raw mode passes the byte.

use crate::edit::{Editor, Event as EdEvent, History, LINE_MAX, OUT_MAX};

/// Type-ahead kept, in bytes. A byte that does not fit is dropped.
pub const HELD_MAX: usize = 256;
/// Most bytes one [`Event::Bytes`] carries.
pub const RAW_MAX: usize = 48;
/// Output the discipline can hold between two [`Discipline::take_output`].
pub const OUTBUF_MAX: usize = OUT_MAX + 16;

/// What [`Discipline::step`] produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// A line is complete: [`Discipline::line`].
    Line,
    /// Raw bytes: [`Discipline::raw`], this many of them.
    Bytes(usize),
    /// The interrupt key, addressed to this foreground job (0 = the client).
    Interrupt(u32),
    /// End of input.
    Eof,
}

/// The discipline.
pub struct Discipline {
    ed: Editor,
    hist: History,
    raw_mode: bool,
    echo: bool,
    cols: u16,
    rows: u16,
    fg: u32,
    held: [u8; HELD_MAX],
    head: usize,
    held_n: usize,
    /// Interrupt keys seen while a job had the focus, not yet delivered.
    intr: u16,
    line: [u8; LINE_MAX],
    line_len: usize,
    raw: [u8; RAW_MAX],
    out: [u8; OUTBUF_MAX],
    out_len: usize,
}

impl Discipline {
    /// A cooked terminal with echo on, 80x24, the client in focus.
    pub const fn new() -> Self {
        Self {
            ed: Editor::new(),
            hist: History::new(),
            raw_mode: false,
            echo: true,
            cols: 80,
            rows: 24,
            fg: 0,
            held: [0; HELD_MAX],
            head: 0,
            held_n: 0,
            intr: 0,
            line: [0; LINE_MAX],
            line_len: 0,
            raw: [0; RAW_MAX],
            out: [0; OUTBUF_MAX],
            out_len: 0,
        }
    }

    /// Back to what [`Discipline::new`] makes, in place: the next user gets
    /// none of the last one's history, size or mode (`Service::submit`).
    /// Assigning `Discipline::new()` built the whole value (about 10 KiB, the
    /// history) on the caller's stack first, which took the login path past
    /// termd's 16 KiB stack. Every field is named, so a new one cannot be
    /// left out.
    pub fn reset(&mut self) {
        let Self { ed, hist, raw_mode, echo, cols, rows, fg, held, head, held_n, intr, line, line_len, raw, out, out_len } =
            self;
        *ed = Editor::new();
        hist.clear();
        (*raw_mode, *echo, *cols, *rows, *fg) = (false, true, 80, 24, 0);
        held.fill(0);
        (*head, *held_n, *intr) = (0, 0, 0);
        line.fill(0);
        *line_len = 0;
        raw.fill(0);
        out.fill(0);
        *out_len = 0;
    }

    // ── state ───────────────────────────────────────────────────────────────

    pub fn size(&self) -> (u16, u16) {
        (self.cols, self.rows)
    }

    pub fn set_size(&mut self, cols: u16, rows: u16) {
        self.cols = cols;
        self.rows = rows;
    }

    #[cfg(test)]
    pub fn is_raw(&self) -> bool {
        self.raw_mode
    }

    pub fn set_raw(&mut self, raw: bool) {
        self.raw_mode = raw;
    }

    #[cfg(test)]
    pub fn echo(&self) -> bool {
        self.echo
    }

    pub fn set_echo(&mut self, on: bool) {
        self.echo = on;
    }

    pub fn foreground(&self) -> u32 {
        self.fg
    }

    /// Move the focus. Leaving the client for a job: the interrupt keys
    /// already typed (they are in the type-ahead) were typed for that job, so
    /// they become its interrupts. Returning to the client drops interrupts
    /// not yet delivered: the job they were for is gone.
    pub fn set_foreground(&mut self, job: u32) {
        if job != 0 && self.fg == 0 {
            let mut keep = [0u8; HELD_MAX];
            let mut n = 0;
            while let Some(b) = self.pop() {
                if b == 0x03 {
                    self.intr = self.intr.saturating_add(1);
                } else {
                    keep[n] = b;
                    n += 1;
                }
            }
            self.push(&keep[..n]);
        }
        if job == 0 {
            self.intr = 0;
        }
        self.fg = job;
    }

    pub fn set_prompt(&mut self, p: &[u8]) {
        self.ed.set_prompt(p);
    }

    /// Print the prompt and clear the line being edited.
    pub fn begin_line(&mut self) {
        self.ed.start();
        let mut tmp = [0u8; OUT_MAX];
        let o = self.ed.take_output();
        let n = o.len();
        tmp[..n].copy_from_slice(o);
        self.show(&tmp[..n]);
    }

    /// Redraw the line being edited: prompt, text, cursor. For a client that
    /// wrote over it (a finished background job). With echo off the typed
    /// text must not reappear, so nothing is drawn.
    pub fn redraw(&mut self) {
        if !self.echo {
            return;
        }
        self.ed.redraw();
        let mut tmp = [0u8; OUT_MAX];
        let o = self.ed.take_output();
        let n = o.len();
        tmp[..n].copy_from_slice(o);
        self.show(&tmp[..n]);
    }

    // ── bytes in, events out ────────────────────────────────────────────────

    /// Take typed bytes. While a job has the focus the interrupt key is
    /// counted (it is delivered first) and the rest held; otherwise all of it
    /// is held for [`Discipline::step`].
    pub fn push(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if b == 0x03 && self.fg != 0 {
                self.intr = self.intr.saturating_add(1);
            } else if self.held_n < HELD_MAX {
                self.held[(self.head + self.held_n) % HELD_MAX] = b;
                self.held_n += 1;
            }
        }
    }

    /// Bytes held (type-ahead).
    #[cfg(test)]
    pub fn held(&self) -> usize {
        self.held_n
    }

    fn pop(&mut self) -> Option<u8> {
        if self.held_n == 0 {
            return None;
        }
        let b = self.held[self.head];
        self.head = (self.head + 1) % HELD_MAX;
        self.held_n -= 1;
        Some(b)
    }

    fn peek(&self) -> Option<u8> {
        (self.held_n > 0).then(|| self.held[self.head])
    }

    /// The next event the held bytes make, or `None` when they make none.
    pub fn step(&mut self) -> Option<Event> {
        if self.intr > 0 {
            self.intr -= 1;
            self.show_interrupt();
            return Some(Event::Interrupt(self.fg));
        }
        if self.fg != 0 {
            return None;
        }
        if self.raw_mode {
            return self.step_raw();
        }
        while let Some(b) = self.pop() {
            let ev = self.ed.feed(b, &self.hist);
            let mut tmp = [0u8; OUT_MAX];
            let o = self.ed.take_output();
            let n = o.len();
            tmp[..n].copy_from_slice(o);
            self.echo_out(&tmp[..n]);
            match ev {
                EdEvent::None => {}
                EdEvent::Line => {
                    let l = self.ed.line();
                    self.line_len = l.len();
                    self.line[..l.len()].copy_from_slice(l);
                    let (copy, n) = (self.line, self.line_len);
                    self.hist.push(&copy[..n]);
                    // The editor is ready for the next line, which may
                    // already be held.
                    self.clear_line();
                    return Some(Event::Line);
                }
                EdEvent::Interrupt => {
                    self.clear_line();
                    self.show_interrupt();
                    return Some(Event::Interrupt(0));
                }
                EdEvent::Eof => return Some(Event::Eof),
            }
        }
        None
    }

    fn step_raw(&mut self) -> Option<Event> {
        if self.peek() == Some(0x03) {
            self.pop();
            self.show_interrupt();
            return Some(Event::Interrupt(0));
        }
        let mut n = 0;
        while n < RAW_MAX {
            match self.peek() {
                Some(0x03) | None => break,
                Some(b) => {
                    self.pop();
                    self.raw[n] = b;
                    n += 1;
                }
            }
        }
        if n == 0 {
            return None;
        }
        let (copy, n2) = (self.raw, n);
        self.echo_out(&copy[..n2]);
        Some(Event::Bytes(n))
    }

    /// Drop the line being edited and its prompt output.
    fn clear_line(&mut self) {
        self.ed.start();
        let _ = self.ed.take_output();
    }

    fn show_interrupt(&mut self) {
        self.echo_out(b"^C\n");
    }

    // ── what the last event holds ───────────────────────────────────────────

    /// The line of the last [`Event::Line`].
    pub fn line(&self) -> &[u8] {
        &self.line[..self.line_len]
    }

    /// The bytes of the last [`Event::Bytes`] (valid up to its count).
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// History line `back` (0 = newest).
    pub fn history(&self, back: usize) -> Option<&[u8]> {
        self.hist.get(back)
    }

    // ── output ──────────────────────────────────────────────────────────────

    fn show(&mut self, b: &[u8]) {
        let n = b.len().min(OUTBUF_MAX - self.out_len);
        self.out[self.out_len..self.out_len + n].copy_from_slice(&b[..n]);
        self.out_len += n;
    }

    fn echo_out(&mut self, b: &[u8]) {
        if self.echo {
            self.show(b);
        }
    }

    /// What to write to the console, and forget it.
    pub fn take_output(&mut self) -> &[u8] {
        let n = self.out_len;
        self.out_len = 0;
        &self.out[..n]
    }
}

impl Default for Discipline {
    fn default() -> Self {
        Self::new()
    }
}
