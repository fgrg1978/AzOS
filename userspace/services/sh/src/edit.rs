// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The shell's line discipline (RFC-0055 §5.4): echo, editing and history,
//! in ring 3. The kernel hands the shell raw bytes (`SYS_CONSOLE_WAIT`) and
//! never echoes; this module turns them into a line and into the bytes to
//! write back.
//!
//! Pure: no syscalls. [`Editor::feed`] takes one byte and appends what the
//! terminal must show to an output buffer the caller writes in one `write`.
//! `tests/host/sh-tests` pulls this file in with `#[path]`.
//!
//! Keys: printable ASCII inserts at the cursor; BS/DEL deletes before it;
//! `^A`/`^E` or Home/End move to the ends; Left/Right move; `^U` kills the
//! line, `^W` the word before the cursor; Up/Down walk the history; `^L`
//! redraws; `^C` and `^D` are reported to the caller, which decides.

/// Longest line, in bytes. A byte that would go past it is dropped.
pub const LINE_MAX: usize = 255;
/// Lines the history keeps.
pub const HIST_N: usize = 32;
/// Output a single [`Editor::feed`] can produce, at most: a full redraw.
pub const OUT_MAX: usize = 2 * LINE_MAX + 64;
/// Longest prompt.
pub const PROMPT_MAX: usize = 32;

/// What a byte did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Nothing for the caller beyond the output.
    None,
    /// Enter: [`Editor::line`] is complete. The newline was echoed.
    Line,
    /// `^C`. The line is kept; the caller decides (clear it, or stop a job).
    Interrupt,
    /// `^D` on an empty line.
    Eof,
}

/// The history ring: the last [`HIST_N`] distinct non-empty lines.
pub struct History {
    lines: [[u8; LINE_MAX]; HIST_N],
    lens: [u8; HIST_N],
    /// Lines stored, at most `HIST_N`.
    n: usize,
    /// Slot the next line goes into.
    next: usize,
}

impl History {
    /// An empty history.
    pub const fn new() -> Self {
        Self { lines: [[0; LINE_MAX]; HIST_N], lens: [0; HIST_N], n: 0, next: 0 }
    }

    /// Lines stored.
    pub fn len(&self) -> usize {
        self.n
    }

    /// Is it empty?
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// The `back`-th line before the newest (0 = newest).
    pub fn get(&self, back: usize) -> Option<&[u8]> {
        if back >= self.n {
            return None;
        }
        let i = (self.next + HIST_N - 1 - back) % HIST_N;
        Some(&self.lines[i][..self.lens[i] as usize])
    }

    /// Remember `line`, unless it is empty, all blanks, or repeats the newest.
    pub fn push(&mut self, line: &[u8]) {
        if line.iter().all(|&b| b == b' ' || b == b'\t') || line.len() > LINE_MAX {
            return;
        }
        if self.get(0) == Some(line) {
            return;
        }
        let i = self.next;
        self.lines[i][..line.len()].copy_from_slice(line);
        self.lens[i] = line.len() as u8;
        self.next = (self.next + 1) % HIST_N;
        if self.n < HIST_N {
            self.n += 1;
        }
    }
}

impl Default for History {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape-sequence state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Esc {
    None,
    /// Saw ESC.
    Esc,
    /// Saw ESC `[` (or ESC `O`), collecting a parameter digit.
    Csi(u8),
}

/// The line being edited, its cursor, and the output to send.
pub struct Editor {
    line: [u8; LINE_MAX],
    len: usize,
    cur: usize,
    esc: Esc,
    /// How far back in the history Up has walked: 0 = editing a new line.
    hist_pos: usize,
    /// The new line, saved while the history is walked.
    saved: [u8; LINE_MAX],
    saved_len: usize,
    prompt: [u8; PROMPT_MAX],
    prompt_len: usize,
    out: [u8; OUT_MAX],
    out_len: usize,
}

impl Editor {
    /// A fresh editor with prompt `prompt` (cut to [`PROMPT_MAX`]).
    pub const fn new() -> Self {
        Self {
            line: [0; LINE_MAX],
            len: 0,
            cur: 0,
            esc: Esc::None,
            hist_pos: 0,
            saved: [0; LINE_MAX],
            saved_len: 0,
            prompt: [0; PROMPT_MAX],
            prompt_len: 0,
            out: [0; OUT_MAX],
            out_len: 0,
        }
    }

    /// Set the prompt [`Editor::start`] and redraws print.
    pub fn set_prompt(&mut self, p: &[u8]) {
        let n = p.len().min(PROMPT_MAX);
        self.prompt[..n].copy_from_slice(&p[..n]);
        self.prompt_len = n;
    }

    /// Begin a new line: clear it and queue the prompt.
    pub fn start(&mut self) {
        self.len = 0;
        self.cur = 0;
        self.esc = Esc::None;
        self.hist_pos = 0;
        let (p, n) = (self.prompt, self.prompt_len);
        self.emit(&p[..n]);
    }

    /// The line typed so far (complete after [`Event::Line`]).
    pub fn line(&self) -> &[u8] {
        &self.line[..self.len]
    }

    /// Cursor position within the line.
    pub fn cursor(&self) -> usize {
        self.cur
    }

    /// The bytes to write, and forget them.
    pub fn take_output(&mut self) -> &[u8] {
        let n = self.out_len;
        self.out_len = 0;
        &self.out[..n]
    }

    fn emit(&mut self, b: &[u8]) {
        let room = OUT_MAX - self.out_len;
        let n = b.len().min(room);
        self.out[self.out_len..self.out_len + n].copy_from_slice(&b[..n]);
        self.out_len += n;
    }

    fn emit_num(&mut self, mut v: usize) {
        let mut d = [0u8; 20];
        let mut i = d.len();
        loop {
            i -= 1;
            d[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.emit(&d[i..]);
    }

    /// Move the terminal cursor left by `n` columns.
    fn left(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        if n <= 4 {
            for _ in 0..n {
                self.emit(b"\x08");
            }
        } else {
            self.emit(b"\x1b[");
            self.emit_num(n);
            self.emit(b"D");
        }
    }

    /// The line changed from position `from` on (`erased` columns were
    /// removed): rewrite the tail, blank what was removed, put the cursor
    /// back.
    fn redraw_tail(&mut self, from: usize, erased: usize) {
        let tail = self.line;
        self.emit(&tail[from..self.len]);
        for _ in 0..erased {
            self.emit(b" ");
        }
        self.left(self.len - self.cur + erased);
    }

    /// Redraw the whole line: carriage return, prompt, text, clear to the end
    /// of the line, cursor.
    pub fn redraw(&mut self) {
        let (p, n) = (self.prompt, self.prompt_len);
        let line = self.line;
        self.emit(b"\r");
        self.emit(&p[..n]);
        self.emit(&line[..self.len]);
        self.emit(b"\x1b[K");
        self.left(self.len - self.cur);
    }

    fn insert(&mut self, b: u8) {
        if self.len >= LINE_MAX {
            return;
        }
        self.line.copy_within(self.cur..self.len, self.cur + 1);
        self.line[self.cur] = b;
        self.len += 1;
        self.cur += 1;
        if self.cur == self.len {
            self.emit(&[b]);
        } else {
            let from = self.cur - 1;
            self.redraw_tail(from, 0);
        }
    }

    /// Delete `n` bytes before the cursor.
    fn delete_back(&mut self, n: usize) {
        let n = n.min(self.cur);
        if n == 0 {
            return;
        }
        self.line.copy_within(self.cur..self.len, self.cur - n);
        self.len -= n;
        self.cur -= n;
        self.left(n);
        let from = self.cur;
        self.redraw_tail(from, n);
    }

    /// Delete the byte at the cursor.
    fn delete_at(&mut self) {
        if self.cur >= self.len {
            return;
        }
        self.line.copy_within(self.cur + 1..self.len, self.cur);
        self.len -= 1;
        let from = self.cur;
        self.redraw_tail(from, 1);
    }

    fn set_line(&mut self, src: &[u8]) {
        let n = src.len().min(LINE_MAX);
        self.line[..n].copy_from_slice(&src[..n]);
        self.len = n;
        self.cur = n;
        self.redraw();
    }

    fn history_up(&mut self, hist: &History) {
        let Some(l) = hist.get(self.hist_pos) else { return };
        if self.hist_pos == 0 {
            self.saved[..self.len].copy_from_slice(&self.line[..self.len]);
            self.saved_len = self.len;
        }
        let mut copy = [0u8; LINE_MAX];
        copy[..l.len()].copy_from_slice(l);
        let n = l.len();
        self.hist_pos += 1;
        self.set_line(&copy[..n]);
    }

    fn history_down(&mut self, hist: &History) {
        if self.hist_pos == 0 {
            return;
        }
        self.hist_pos -= 1;
        let mut copy = [0u8; LINE_MAX];
        let n;
        if self.hist_pos == 0 {
            n = self.saved_len;
            copy[..n].copy_from_slice(&self.saved[..n]);
        } else {
            let l = hist.get(self.hist_pos - 1).unwrap_or(b"");
            n = l.len();
            copy[..n].copy_from_slice(l);
        }
        self.set_line(&copy[..n]);
    }

    /// Feed one byte from the console.
    pub fn feed(&mut self, b: u8, hist: &History) -> Event {
        match self.esc {
            Esc::Esc => {
                self.esc = if b == b'[' || b == b'O' { Esc::Csi(0) } else { Esc::None };
                return Event::None;
            }
            Esc::Csi(p) => {
                if b.is_ascii_digit() {
                    self.esc = Esc::Csi(p.saturating_mul(10).saturating_add(b - b'0'));
                    return Event::None;
                }
                // Other parameter bytes (`;`, `?`, ...): the sequence goes on,
                // and only the last number is kept. A final byte is 0x40..=0x7e.
                if (0x20..0x40).contains(&b) {
                    self.esc = Esc::Csi(0);
                    return Event::None;
                }
                self.esc = Esc::None;
                match (b, p) {
                    (b'A', _) => self.history_up(hist),
                    (b'B', _) => self.history_down(hist),
                    (b'C', _) => {
                        if self.cur < self.len {
                            let c = self.line[self.cur];
                            self.emit(&[c]);
                            self.cur += 1;
                        }
                    }
                    (b'D', _) => {
                        if self.cur > 0 {
                            self.cur -= 1;
                            self.left(1);
                        }
                    }
                    (b'H', _) | (b'~', 1) | (b'~', 7) => self.home(),
                    (b'F', _) | (b'~', 4) | (b'~', 8) => self.end(),
                    (b'~', 3) => self.delete_at(),
                    // A cursor-position report (`ESC [ r ; c R`) and anything
                    // else: ignored. `;` ends the first number, which is fine:
                    // the next digits restart it and `R` is dropped.
                    _ => {}
                }
                return Event::None;
            }
            Esc::None => {}
        }
        match b {
            b'\r' | b'\n' => {
                self.emit(b"\n");
                return Event::Line;
            }
            0x1b => self.esc = Esc::Esc,
            0x08 | 0x7f => self.delete_back(1),
            0x01 => self.home(),
            0x05 => self.end(),
            0x02 => {
                if self.cur > 0 {
                    self.cur -= 1;
                    self.left(1);
                }
            }
            0x06 => {
                if self.cur < self.len {
                    let c = self.line[self.cur];
                    self.emit(&[c]);
                    self.cur += 1;
                }
            }
            0x03 => return Event::Interrupt,
            0x04 => {
                if self.len == 0 {
                    return Event::Eof;
                }
                self.delete_at();
            }
            0x0b => {
                // ^K: kill to the end of the line.
                let erased = self.len - self.cur;
                self.len = self.cur;
                self.redraw_tail(self.cur, erased);
            }
            0x0c => {
                self.emit(b"\x1b[H\x1b[2J");
                self.redraw();
            }
            0x10 => self.history_up(hist),
            0x0e => self.history_down(hist),
            0x15 => {
                let n = self.cur;
                self.delete_back(n);
            }
            0x17 => {
                let mut i = self.cur;
                while i > 0 && self.line[i - 1] == b' ' {
                    i -= 1;
                }
                while i > 0 && self.line[i - 1] != b' ' {
                    i -= 1;
                }
                let n = self.cur - i;
                self.delete_back(n);
            }
            0x20..=0x7e => self.insert(b),
            _ => {}
        }
        Event::None
    }

    fn home(&mut self) {
        let n = self.cur;
        self.left(n);
        self.cur = 0;
    }

    fn end(&mut self) {
        let line = self.line;
        self.emit(&line[self.cur..self.len]);
        self.cur = self.len;
    }
}

impl Default for Editor {
    fn default() -> Self {
        Self::new()
    }
}
