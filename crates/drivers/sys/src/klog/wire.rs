// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The structured kernel log's wire: a record's payload in its ring, the
//! record as a reader copies it out, and the text line `logd` writes.
//!
//! **Why this file names nothing but `core`.** The kernel pushes with it
//! (`super`), `userspace/services/logd` and the toolbox's `log` tool read
//! with it (`#[path]`, the same source, so a reader cannot drift from the
//! writer; the same arrangement as `crates/core/recovery/src/crashdump.rs`),
//! and the host tests run it unchanged (`tests/host/drivers-tests`).
//!
//! The ring is the record substrate's (`azos_rings::region::record`, its
//! kernel-log ring): the envelope carries the sequence, the time, the CPU,
//! the level (its `kind`) and the [`FLAG_*`](FLAG_PARTIAL) bits (its
//! `flags`); the payload is
//!
//! ```text
//! payload [0]         module length (u8)
//!         [1..25)     module path (the Rust module the line was printed from)
//!         [32..288)   message (no trailing newline); the envelope's `len` is 32 + its length
//! ```

/// Bytes of the module field.
pub const MODULE_BYTES: usize = 24;
/// Bytes of the message field: the console's pre-format buffer.
pub const MSG_BYTES: usize = 256;
/// Payload offset of the module length.
pub const P_MODULE_LEN: usize = 0;
/// Payload offset of the module path.
pub const P_MODULE: usize = 1;
/// Payload offset of the message.
pub const P_MSG: usize = 32;
/// Payload bytes of a record.
pub const PAYLOAD_BYTES: usize = P_MSG + MSG_BYTES;

const _: () = assert!(P_MODULE + MODULE_BYTES <= P_MSG);

/// The line had no newline (a `kprint!` fragment): the next record continues it.
pub const FLAG_PARTIAL: u8 = 1;
/// The line was longer than [`MSG_BYTES`]: the message is its beginning.
pub const FLAG_TRUNC: u8 = 2;

/// Linux numbering, as `uart::level`.
pub const LEVEL_ERR: u8 = 3;
/// See [`LEVEL_ERR`].
pub const LEVEL_WARN: u8 = 4;
/// See [`LEVEL_ERR`].
pub const LEVEL_INFO: u8 = 6;
/// See [`LEVEL_ERR`].
pub const LEVEL_DEBUG: u8 = 7;

/// The module path as stored: without the `azos_` every crate name starts
/// with, cut at [`MODULE_BYTES`].
pub fn trim_module(path: &str) -> &[u8] {
    let b = path.as_bytes();
    let b = b.strip_prefix(b"azos_").unwrap_or(b);
    &b[..b.len().min(MODULE_BYTES)]
}

/// A line's payload, as the producer stores it: `put(offset, bytes)` for
/// each field (the ring's store). Returns the envelope's `len` and its
/// flags: `flags` plus [`FLAG_TRUNC`] when the message is cut at
/// [`MSG_BYTES`].
pub fn encode(module: &str, msg: &[u8], flags: u8, mut put: impl FnMut(usize, &[u8])) -> (u16, u8) {
    let m = trim_module(module);
    let n = msg.len().min(MSG_BYTES);
    put(P_MODULE_LEN, &[m.len() as u8]);
    put(P_MODULE, m);
    put(P_MSG, &msg[..n]);
    ((P_MSG + n) as u16, if msg.len() > MSG_BYTES { flags | FLAG_TRUNC } else { flags })
}

/// The envelope's `len` and flags [`encode`] gives, without storing.
pub fn encoded(msg: &[u8], flags: u8) -> (u16, u8) {
    encode("", msg, flags, |_, _| {})
}

/// One record, copied out of its slot.
#[derive(Clone, Copy)]
pub struct Record {
    pub seq: u64,
    pub ts: u64,
    pub level: u8,
    pub flags: u8,
    pub cpu: u8,
    module_len: u8,
    msg_len: u16,
    module: [u8; MODULE_BYTES],
    msg: [u8; MSG_BYTES],
}

impl Record {
    /// A record built by a reader that has one of its own to write (`logd`'s
    /// notices); module and message are cut to their fields.
    pub fn make(seq: u64, ts: u64, level: u8, flags: u8, cpu: u8, module: &str, msg: &[u8]) -> Record {
        let mut r = Record::empty();
        r.seq = seq;
        r.ts = ts;
        r.level = level;
        r.flags = flags;
        r.cpu = cpu;
        let m = trim_module(module);
        r.module[..m.len()].copy_from_slice(m);
        r.module_len = m.len() as u8;
        let n = msg.len().min(MSG_BYTES);
        r.msg[..n].copy_from_slice(&msg[..n]);
        r.msg_len = n as u16;
        r
    }
    /// The record a ring slot held: its envelope's fields and its payload
    /// (`len` is the envelope's). Fields are cut to their sizes, so a payload
    /// a reader did not write itself cannot make it read past one.
    pub fn decode(seq: u64, ts: u64, level: u8, flags: u8, cpu: u8, len: u16, payload: &[u8]) -> Record {
        let mut r = Record::empty();
        r.seq = seq;
        r.ts = ts;
        r.level = level;
        r.flags = flags;
        r.cpu = cpu;
        let ml = (payload.get(P_MODULE_LEN).copied().unwrap_or(0) as usize).min(MODULE_BYTES);
        if let Some(m) = payload.get(P_MODULE..P_MODULE + ml) {
            r.module[..ml].copy_from_slice(m);
            r.module_len = ml as u8;
        }
        let n = (len as usize).saturating_sub(P_MSG).min(MSG_BYTES).min(payload.len().saturating_sub(P_MSG));
        r.msg[..n].copy_from_slice(&payload[P_MSG..P_MSG + n]);
        r.msg_len = n as u16;
        r
    }
    pub const fn empty() -> Record {
        Record { seq: 0, ts: 0, level: 0, flags: 0, cpu: 0, module_len: 0, msg_len: 0, module: [0; MODULE_BYTES], msg: [0; MSG_BYTES] }
    }
    /// The module field.
    pub fn module(&self) -> &[u8] {
        &self.module[..(self.module_len as usize).min(MODULE_BYTES)]
    }
    /// The message.
    pub fn msg(&self) -> &[u8] {
        &self.msg[..(self.msg_len as usize).min(MSG_BYTES)]
    }
}

// ---- The text line --------------------------------------------------------

/// Bytes a [`line`] can take at most: the fields, and a message of
/// [`MSG_BYTES`] bytes each escaped to four.
pub const LINE_MAX: usize = 20 + 1 + 20 + 1 + 3 + 1 + 2 + 1 + MODULE_BYTES + 1 + MSG_BYTES * 4 + 1;

/// The letter of a level: `E`, `W`, `I`, `D`, or `?`.
pub const fn level_letter(level: u8) -> u8 {
    match level {
        LEVEL_ERR => b'E',
        LEVEL_WARN => b'W',
        LEVEL_INFO => b'I',
        LEVEL_DEBUG => b'D',
        _ => b'?',
    }
}

/// The level a letter names (the inverse of [`level_letter`]).
pub const fn letter_level(letter: u8) -> Option<u8> {
    match letter {
        b'E' => Some(LEVEL_ERR),
        b'W' => Some(LEVEL_WARN),
        b'I' => Some(LEVEL_INFO),
        b'D' => Some(LEVEL_DEBUG),
        _ => None,
    }
}

struct Put<'a> {
    out: &'a mut [u8],
    n: usize,
}

impl Put<'_> {
    fn byte(&mut self, b: u8) {
        if self.n < self.out.len() {
            self.out[self.n] = b;
            self.n += 1;
        }
    }
    fn bytes(&mut self, b: &[u8]) {
        for &x in b {
            self.byte(x);
        }
    }
    fn dec(&mut self, mut v: u64) {
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
        self.bytes(&d[i..]);
    }
}

/// Write one record as a text line into `out` (at least [`LINE_MAX`] bytes;
/// a shorter buffer cuts the line), newline included; returns its length.
///
/// ```text
/// <seq> <ts_us> <cpu> <L>[+] <module> <message>\n
/// ```
///
/// `ts_us` is microseconds since the timebase's zero (the boot); `L` is the
/// level letter, followed by `+` when the record is a fragment the next one
/// continues; an empty module is `-`. The message is escaped so a record is
/// always one line: `\\`, `\n`, `\r`, `\t` and `\xNN` for any other control
/// byte; every other byte is as stored.
pub fn line(r: &Record, ts_hz: u64, out: &mut [u8]) -> usize {
    line_of(r.seq, r.ts, ts_hz, r.cpu, r.level, r.flags & FLAG_PARTIAL != 0, r.module(), r.msg(), out)
}

/// [`line`] from its parts, with a message of any length (`out` holds it):
/// a security record's line, whose message is longer than a kernel log
/// record's.
#[allow(clippy::too_many_arguments)]
pub fn line_of(seq: u64, ts: u64, ts_hz: u64, cpu: u8, level: u8, partial: bool, module: &[u8], msg: &[u8], out: &mut [u8]) -> usize {
    let ts_us = if ts_hz == 0 { ts } else { (ts as u128 * 1_000_000 / ts_hz as u128) as u64 };
    let mut p = Put { out, n: 0 };
    p.dec(seq);
    p.byte(b' ');
    p.dec(ts_us);
    p.byte(b' ');
    p.dec(cpu as u64);
    p.byte(b' ');
    p.byte(level_letter(level));
    if partial {
        p.byte(b'+');
    }
    p.byte(b' ');
    if module.is_empty() {
        p.byte(b'-');
    } else {
        p.bytes(module);
    }
    p.byte(b' ');
    for &b in msg {
        match b {
            b'\\' => p.bytes(b"\\\\"),
            b'\n' => p.bytes(b"\\n"),
            b'\r' => p.bytes(b"\\r"),
            b'\t' => p.bytes(b"\\t"),
            0..=0x1f | 0x7f => {
                p.bytes(b"\\x");
                p.byte(b"0123456789abcdef"[(b >> 4) as usize]);
                p.byte(b"0123456789abcdef"[(b & 15) as usize]);
            }
            _ => p.byte(b),
        }
    }
    p.byte(b'\n');
    p.n
}

/// One text line, parsed (the message still escaped).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Line<'a> {
    pub seq: u64,
    pub ts_us: u64,
    pub cpu: u8,
    pub level: u8,
    pub partial: bool,
    /// `-` when the record had no module.
    pub module: &'a [u8],
    pub msg: &'a [u8],
}

fn dec(b: &[u8]) -> Option<u64> {
    if b.is_empty() || b.len() > 20 {
        return None;
    }
    let mut v = 0u64;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(v)
}

/// Parse a line [`line`] wrote (without or with its newline); `None` for
/// anything else, which a reader skips.
pub fn parse(text: &[u8]) -> Option<Line<'_>> {
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    let mut f = text.splitn(6, |&b| b == b' ');
    let seq = dec(f.next()?)?;
    let ts_us = dec(f.next()?)?;
    let cpu = u8::try_from(dec(f.next()?)?).ok()?;
    let lv = f.next()?;
    let (letter, partial) = match lv {
        [l] => (*l, false),
        [l, b'+'] => (*l, true),
        _ => return None,
    };
    let level = letter_level(letter).unwrap_or(0);
    if level == 0 && letter != b'?' {
        return None;
    }
    let module = f.next()?;
    let msg = f.next().unwrap_or(&[]);
    Some(Line { seq, ts_us, cpu, level, partial, module, msg })
}

/// Undo the escaping of a line's message into `out`; returns its length (cut
/// at `out.len()`).
pub fn unescape(msg: &[u8], out: &mut [u8]) -> usize {
    let mut n = 0;
    let mut i = 0;
    let mut put = |b: u8, n: &mut usize| {
        if *n < out.len() {
            out[*n] = b;
            *n += 1;
        }
    };
    while i < msg.len() {
        let b = msg[i];
        i += 1;
        if b != b'\\' {
            put(b, &mut n);
            continue;
        }
        match msg.get(i) {
            Some(b'\\') => put(b'\\', &mut n),
            Some(b'n') => put(b'\n', &mut n),
            Some(b'r') => put(b'\r', &mut n),
            Some(b't') => put(b'\t', &mut n),
            Some(b'x') => {
                let hex = |c: &u8| (*c as char).to_digit(16);
                match (msg.get(i + 1).and_then(hex), msg.get(i + 2).and_then(hex)) {
                    (Some(h), Some(l)) => {
                        put((h * 16 + l) as u8, &mut n);
                        i += 2;
                    }
                    _ => {
                        put(b'\\', &mut n);
                        continue;
                    }
                }
            }
            _ => {
                put(b'\\', &mut n);
                continue;
            }
        }
        i += 1;
    }
    n
}

// ---- The file ring ----------------------------------------------------------

/// Files a ring of log files can hold (a hex digit names the slot).
pub const FILE_SLOTS_MAX: usize = 16;
/// Bytes of a file name, NUL included: `KLOGx.TXT`.
pub const FILE_NAME_BYTES: usize = 10;
/// The module `logd`'s own lines are written under.
pub const LOGD_MODULE: &[u8] = b"logd";
/// The module of a line `logd` wrote for a decision record (`@`: no Rust
/// module path starts with it, so no kernel line can claim it).
pub const DECISION_MODULE: &[u8] = b"@decision";
/// The module of a line `logd` wrote for a telemetry event.
pub const TELEMETRY_MODULE: &[u8] = b"@telemetry";
/// The module of a security record's line (`azos_seclog::text`).
pub const SECURITY_MODULE: &[u8] = b"@security";

/// The name of file `slot` (a FAT 8.3 name, root of the tree `logd` is
/// granted), NUL-terminated.
pub fn file_name(slot: u8) -> [u8; FILE_NAME_BYTES] {
    let mut n = *b"KLOG0.TXT\0";
    n[4] = b"0123456789ABCDEF"[(slot & 15) as usize];
    n
}

/// The text of the line that opens every file: `file <serial>`. The serial
/// grows by one at each rotation, which is how a reader orders the files (the
/// kernel's sequence numbers start again at every boot).
pub fn file_head(serial: u64, out: &mut [u8; 24]) -> usize {
    out[..5].copy_from_slice(b"file ");
    let mut d = [0u8; 20];
    let mut i = d.len();
    let mut v = serial;
    loop {
        i -= 1;
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out[5..5 + d.len() - i].copy_from_slice(&d[i..]);
    5 + d.len() - i
}

/// The serial a file's opening line carries, if `l` is one.
pub fn head_serial(l: &Line<'_>) -> Option<u64> {
    if l.module != LOGD_MODULE {
        return None;
    }
    dec(l.msg.strip_prefix(b"file ")?)
}

/// Splits a stream of bytes into lines, whatever the chunks: a line longer
/// than [`LINE_MAX`] (which [`line`] never writes) is dropped whole.
pub struct Lines {
    buf: [u8; LINE_MAX],
    n: usize,
    over: bool,
}

impl Lines {
    pub const fn new() -> Lines {
        Lines { buf: [0; LINE_MAX], n: 0, over: false }
    }
    /// Feed `chunk`; `f` gets each complete line, without its newline.
    pub fn feed(&mut self, chunk: &[u8], f: &mut dyn FnMut(&[u8])) {
        for &b in chunk {
            if b == b'\n' {
                if !self.over {
                    f(&self.buf[..self.n]);
                }
                self.n = 0;
                self.over = false;
            } else if self.n < LINE_MAX {
                self.buf[self.n] = b;
                self.n += 1;
            } else {
                self.over = true;
            }
        }
    }
}
