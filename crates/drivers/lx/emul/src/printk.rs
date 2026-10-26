// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! `printk`: level parsing, console filtering and a record ring.
//!
//! In L0 the text arrives already formatted (Linux's `vsnprintf` comes with
//! the L1 C side); this module handles what happens after formatting:
//!
//! * the level prefix: `KERN_SOH` (0x01) followed by `'0'..='7'`, `'c'` for
//!   `KERN_CONT` or `'d'` for the default level; a message without one gets
//!   the default message level 4;
//! * a fixed ring of records that drops the oldest when full and counts
//!   what it dropped, so a log flood is visible after the fact;
//! * the console: lines with level below the console loglevel (default 7)
//!   go to a pluggable sink, tagged `"[LX] "` so the AzOS console shows
//!   which output came from the Linux layer.
//!
//! `KERN_CONT` appends to the previous record while that record has not yet
//! ended with a newline, as on Linux; on the console the fragment is written
//! untagged so the line reads as one.

/// Start-of-header byte of a level prefix.
pub const KERN_SOH: u8 = 0x01;
/// `KERN_EMERG`.
pub const KERN_EMERG: &[u8] = b"\x010";
/// `KERN_ALERT`.
pub const KERN_ALERT: &[u8] = b"\x011";
/// `KERN_CRIT`.
pub const KERN_CRIT: &[u8] = b"\x012";
/// `KERN_ERR`.
pub const KERN_ERR: &[u8] = b"\x013";
/// `KERN_WARNING`.
pub const KERN_WARNING: &[u8] = b"\x014";
/// `KERN_NOTICE`.
pub const KERN_NOTICE: &[u8] = b"\x015";
/// `KERN_INFO`.
pub const KERN_INFO: &[u8] = b"\x016";
/// `KERN_DEBUG`.
pub const KERN_DEBUG: &[u8] = b"\x017";
/// `KERN_CONT`.
pub const KERN_CONT: &[u8] = b"\x01c";

/// Level of a message that carries no prefix (`MESSAGE_LOGLEVEL_DEFAULT`).
pub const MESSAGE_LOGLEVEL_DEFAULT: u8 = 4;
/// Console threshold: levels strictly below it are printed.
pub const CONSOLE_LOGLEVEL_DEFAULT: u8 = 7;
/// Bytes kept per record; longer text is truncated and counted.
pub const LINE_MAX: usize = 256;
/// Tag written before every console line.
pub const TAG: &[u8] = b"[LX] ";

/// Console sink: receives the level and one chunk of console bytes.
pub type Sink = fn(level: u8, bytes: &[u8]);

/// Parsed prefix of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    /// Explicit level, if one was given.
    pub level: Option<u8>,
    /// `KERN_CONT` was present.
    pub cont: bool,
    /// Bytes consumed by the prefix.
    pub len: usize,
}

/// Parse the run of `KERN_SOH` headers at the start of `msg`. The first
/// level wins; an unknown header byte ends the prefix and stays in the text.
pub fn parse_prefix(msg: &[u8]) -> Prefix {
    let mut p = Prefix { level: None, cont: false, len: 0 };
    while msg.len() >= p.len + 2 && msg[p.len] == KERN_SOH {
        match msg[p.len + 1] {
            c @ b'0'..=b'7' => {
                if p.level.is_none() {
                    p.level = Some(c - b'0');
                }
            }
            b'c' => p.cont = true,
            b'd' => {}
            _ => break,
        }
        p.len += 2;
    }
    p
}

/// One log record.
#[derive(Clone, Copy, Debug)]
pub struct Record {
    level: u8,
    seq: u64,
    len: u16,
    open: bool,
    truncated: bool,
    text: [u8; LINE_MAX],
}

impl Record {
    const EMPTY: Record =
        Record { level: 0, seq: 0, len: 0, open: false, truncated: false, text: [0; LINE_MAX] };

    /// Log level 0..=7.
    pub fn level(&self) -> u8 {
        self.level
    }

    /// Sequence number (gap-free across drops, so a reader can see how many
    /// it missed).
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Stored text, without the level prefix, including any newline.
    pub fn text(&self) -> &[u8] {
        &self.text[..self.len as usize]
    }

    /// True if the text was cut at [`LINE_MAX`].
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    fn append(&mut self, body: &[u8]) -> usize {
        let room = LINE_MAX - self.len as usize;
        let n = body.len().min(room);
        let at = self.len as usize;
        self.text[at..at + n].copy_from_slice(&body[..n]);
        self.len += n as u16;
        if n < body.len() {
            self.truncated = true;
        }
        if body.last() == Some(&b'\n') {
            self.open = false;
        }
        n
    }
}

/// Counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrintkStats {
    /// Records overwritten because the ring was full.
    pub dropped: u64,
    /// Messages cut at [`LINE_MAX`].
    pub truncated: u64,
    /// Messages suppressed from the console by the loglevel.
    pub filtered: u64,
}

/// The log: a ring of `R` records plus console state.
#[derive(Debug)]
pub struct Printk<const R: usize> {
    ring: [Record; R],
    head: usize,
    len: usize,
    next_seq: u64,
    console_loglevel: u8,
    sink: Option<Sink>,
    console_open: bool,
    stats: PrintkStats,
}

impl<const R: usize> Default for Printk<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const R: usize> Printk<R> {
    /// Empty log, no sink, console loglevel 7.
    pub const fn new() -> Self {
        Printk {
            ring: [Record::EMPTY; R],
            head: 0,
            len: 0,
            next_seq: 0,
            console_loglevel: CONSOLE_LOGLEVEL_DEFAULT,
            sink: None,
            console_open: false,
            stats: PrintkStats { dropped: 0, truncated: 0, filtered: 0 },
        }
    }

    /// Install the console writer (lxsrv passes its AzOS console write).
    pub fn set_sink(&mut self, sink: Option<Sink>) {
        self.sink = sink;
    }

    /// Set the console threshold (levels below it are printed).
    pub fn set_console_loglevel(&mut self, level: u8) {
        self.console_loglevel = level;
    }

    /// Current console threshold.
    pub fn console_loglevel(&self) -> u8 {
        self.console_loglevel
    }

    /// Counters.
    pub fn stats(&self) -> PrintkStats {
        self.stats
    }

    /// Records held (at most `R`).
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if no record is held.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Records from oldest to newest.
    pub fn records(&self) -> impl Iterator<Item = &Record> + '_ {
        (0..self.len).map(move |i| &self.ring[(self.head + i) % R])
    }

    /// Newest record.
    pub fn last(&self) -> Option<&Record> {
        if self.len == 0 {
            None
        } else {
            Some(&self.ring[(self.head + self.len - 1) % R])
        }
    }

    fn last_mut(&mut self) -> Option<&mut Record> {
        if self.len == 0 {
            None
        } else {
            Some(&mut self.ring[(self.head + self.len - 1) % R])
        }
    }

    /// `printk` of an already-formatted message. Returns the number of text
    /// bytes stored (prefix excluded).
    pub fn printk(&mut self, msg: &[u8]) -> usize {
        let p = parse_prefix(msg);
        let body = &msg[p.len..];
        if p.cont {
            if let Some(last) = self.last_mut().filter(|r| r.open) {
                let level = last.level;
                let was_trunc = last.truncated;
                let n = last.append(body);
                if !was_trunc && n < body.len() {
                    self.stats.truncated += 1;
                }
                self.console(level, &body[..n], false);
                return n;
            }
        }
        self.emit(p.level.unwrap_or(MESSAGE_LOGLEVEL_DEFAULT), body)
    }

    fn emit(&mut self, level: u8, body: &[u8]) -> usize {
        if R == 0 {
            self.stats.dropped += 1;
            return 0;
        }
        if self.len == R {
            self.head = (self.head + 1) % R;
            self.len -= 1;
            self.stats.dropped += 1;
        }
        let idx = (self.head + self.len) % R;
        self.len += 1;
        let mut rec = Record::EMPTY;
        rec.level = level;
        rec.seq = self.next_seq;
        rec.open = true;
        self.next_seq += 1;
        let n = rec.append(body);
        if rec.truncated {
            self.stats.truncated += 1;
        }
        self.ring[idx] = rec;
        self.console(level, &body[..n], true);
        n
    }

    fn console(&mut self, level: u8, text: &[u8], new_line: bool) {
        if level >= self.console_loglevel {
            self.stats.filtered += 1;
            return;
        }
        let Some(sink) = self.sink else { return };
        if !new_line {
            sink(level, text);
        } else {
            // One sink call per line, so a console that writes atomically
            // never interleaves the tag and the text.
            let mut buf = [0u8; 1 + TAG.len() + LINE_MAX];
            let mut n = 0;
            if self.console_open {
                buf[0] = b'\n';
                n = 1;
            }
            buf[n..n + TAG.len()].copy_from_slice(TAG);
            n += TAG.len();
            buf[n..n + text.len()].copy_from_slice(text);
            n += text.len();
            sink(level, &buf[..n]);
        }
        if !text.is_empty() {
            self.console_open = text.last() != Some(&b'\n');
        }
    }

    /// `pr_emerg`.
    pub fn pr_emerg(&mut self, text: &[u8]) -> usize {
        self.emit(0, text)
    }
    /// `pr_alert`.
    pub fn pr_alert(&mut self, text: &[u8]) -> usize {
        self.emit(1, text)
    }
    /// `pr_crit`.
    pub fn pr_crit(&mut self, text: &[u8]) -> usize {
        self.emit(2, text)
    }
    /// `pr_err`.
    pub fn pr_err(&mut self, text: &[u8]) -> usize {
        self.emit(3, text)
    }
    /// `pr_warn`.
    pub fn pr_warn(&mut self, text: &[u8]) -> usize {
        self.emit(4, text)
    }
    /// `pr_notice`.
    pub fn pr_notice(&mut self, text: &[u8]) -> usize {
        self.emit(5, text)
    }
    /// `pr_info`.
    pub fn pr_info(&mut self, text: &[u8]) -> usize {
        self.emit(6, text)
    }
    /// `pr_debug`: recorded, filtered from the console at the default
    /// loglevel (Linux compiles it out unless `DEBUG`; keeping the record
    /// costs nothing and helps post-mortems).
    pub fn pr_debug(&mut self, text: &[u8]) -> usize {
        self.emit(7, text)
    }
    /// `pr_cont`.
    pub fn pr_cont(&mut self, text: &[u8]) -> usize {
        let mut buf = [0u8; 2 + LINE_MAX];
        buf[..2].copy_from_slice(KERN_CONT);
        let n = text.len().min(LINE_MAX);
        buf[2..2 + n].copy_from_slice(&text[..n]);
        self.printk(&buf[..2 + n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        static OUT: RefCell<Vec<(u8, Vec<u8>)>> = const { RefCell::new(Vec::new()) };
    }

    fn sink(level: u8, bytes: &[u8]) {
        OUT.with(|o| o.borrow_mut().push((level, bytes.to_vec())));
    }

    fn take() -> Vec<(u8, Vec<u8>)> {
        OUT.with(|o| core::mem::take(&mut *o.borrow_mut()))
    }

    fn console_text() -> Vec<u8> {
        take().into_iter().flat_map(|(_, b)| b).collect()
    }

    fn log() -> Printk<4> {
        let mut p = Printk::new();
        p.set_sink(Some(sink));
        take();
        p
    }

    #[test]
    fn prefix_parsing() {
        assert_eq!(parse_prefix(b"\x013hi"), Prefix { level: Some(3), cont: false, len: 2 });
        assert_eq!(parse_prefix(b"hi"), Prefix { level: None, cont: false, len: 0 });
        assert_eq!(parse_prefix(b"\x01chi"), Prefix { level: None, cont: true, len: 2 });
        assert_eq!(parse_prefix(b"\x01c\x016x"), Prefix { level: Some(6), cont: true, len: 4 });
        assert_eq!(parse_prefix(b"\x016\x012x").level, Some(6), "first level wins");
        assert_eq!(parse_prefix(b"\x019x").len, 0, "unknown header is text");
        assert_eq!(parse_prefix(b"\x01").len, 0, "a lone SOH is text");
        assert_eq!(parse_prefix(b"\x01dx"), Prefix { level: None, cont: false, len: 2 });
    }

    #[test]
    fn default_level_and_tagging() {
        let mut p = log();
        p.printk(b"plain\n");
        assert_eq!(p.last().unwrap().level(), MESSAGE_LOGLEVEL_DEFAULT);
        assert_eq!(p.last().unwrap().text(), b"plain\n");
        assert_eq!(take(), vec![(4, b"[LX] plain\n".to_vec())]);
    }

    #[test]
    fn console_filter_prints_levels_below_the_threshold() {
        let mut p = log();
        p.printk(b"\x016info\n");
        p.printk(b"\x017debug\n");
        assert_eq!(console_text(), b"[LX] info\n");
        assert_eq!(p.len(), 2, "filtered messages are still recorded");
        assert_eq!(p.stats().filtered, 1);
        p.set_console_loglevel(4);
        p.pr_warn(b"w\n");
        p.pr_err(b"e\n");
        assert_eq!(console_text(), b"[LX] e\n");
        p.set_console_loglevel(8);
        p.pr_debug(b"d\n");
        assert_eq!(console_text(), b"[LX] d\n");
    }

    #[test]
    fn kern_cont_appends_to_the_open_record() {
        let mut p = log();
        p.pr_info(b"probing");
        p.pr_cont(b" ok");
        p.printk(b"\x01c done\n");
        assert_eq!(p.len(), 1);
        let r = p.last().unwrap();
        assert_eq!(r.text(), b"probing ok done\n");
        assert_eq!(r.level(), 6, "a continuation keeps the level of its record");
        assert_eq!(console_text(), b"[LX] probing ok done\n");
        // The record is closed now: a continuation starts a new one.
        p.pr_cont(b"orphan\n");
        assert_eq!(p.len(), 2);
        assert_eq!(p.last().unwrap().level(), MESSAGE_LOGLEVEL_DEFAULT);
    }

    #[test]
    fn a_new_record_after_an_open_line_starts_on_a_new_console_line() {
        let mut p = log();
        p.pr_info(b"half");
        p.pr_info(b"next\n");
        assert_eq!(console_text(), b"[LX] half\n[LX] next\n");
    }

    #[test]
    fn continuation_of_a_filtered_record_is_filtered() {
        let mut p = log();
        p.pr_debug(b"dbg");
        p.pr_cont(b" more\n");
        assert!(take().is_empty());
        assert_eq!(p.last().unwrap().text(), b"dbg more\n");
    }

    #[test]
    fn ring_overflow_drops_oldest_and_counts() {
        let mut p = log();
        for i in 0..10u8 {
            p.pr_info(&[b'a' + i, b'\n']);
        }
        assert_eq!(p.len(), 4);
        assert_eq!(p.stats().dropped, 6);
        let seqs: Vec<u64> = p.records().map(|r| r.seq()).collect();
        assert_eq!(seqs, vec![6, 7, 8, 9]);
        let texts: Vec<u8> = p.records().map(|r| r.text()[0]).collect();
        assert_eq!(texts, b"ghij".to_vec());
    }

    #[test]
    fn long_lines_are_truncated_and_counted() {
        let mut p = log();
        let long = [b'x'; LINE_MAX + 10];
        assert_eq!(p.pr_info(&long), LINE_MAX);
        assert!(p.last().unwrap().truncated());
        assert_eq!(p.pr_cont(b"more"), 0);
        assert_eq!(p.stats().truncated, 1, "one message, one count");
        let out = take();
        assert_eq!(out[0].1.len(), TAG.len() + LINE_MAX);
    }

    #[test]
    fn no_sink_still_records() {
        let mut p: Printk<2> = Printk::new();
        p.pr_err(b"x\n");
        assert_eq!(p.len(), 1);
        assert!(take().is_empty());
    }
}
