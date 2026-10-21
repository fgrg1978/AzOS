// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The structured kernel log's wire: the ring's layout, the producer's push,
//! the reader's cursor and the text line `logd` writes.
//!
//! **Why this file names nothing but `core`.** The kernel pushes with it
//! (`super`), `userspace/services/logd` and the toolbox's `log` tool read
//! with it (`#[path]`, the same source, so a reader cannot drift from the
//! writer; the same arrangement as `crates/core/recovery/src/crashdump.rs`),
//! and the host tests run it unchanged (`tests/host/drivers-tests`).
//!
//! # Layout (little endian)
//!
//! ```text
//! region  [0..128)    header
//!         [128..)     entries x SLOT_BYTES slots
//! header  [0..4)      magic "KLG1"       [4..8)    version
//!         [8..12)     slot bytes         [12..16)  entries (a power of two)
//!         [16..24)    ts_hz: ticks per second of the records' `ts`
//!         [64..72)    head (u64, producers): records claimed so far, on its own line
//! slot    [0..8)      stamp  (u64)  2i+1 while record i is being stored, 2i+2 once whole
//!         [8..16)     ts     (u64)  the timebase tick the line was printed at
//!         [16..24)    seq    (u64)  i, the record's index since boot
//!         [24]        level  (u8)   Linux numbering: 3 err, 4 warn, 6 info, 7 debug
//!         [25]        flags  (u8)   FLAG_*
//!         [26]        cpu    (u8)
//!         [27]        module length (u8)
//!         [28..30)    message length (u16)
//!         [32..56)    module path (the Rust module the line was printed from)
//!         [64..320)   message (no trailing newline)
//! ```
//!
//! # Protocol
//!
//! One ring for the whole kernel, many producers, any number of readers. A
//! producer claims record `i` with a `fetch_add` on `head` (so a producer an
//! interrupt handler interrupts mid-store gets a different slot from the
//! handler's, and nothing is masked or locked), stores the record in slot
//! `i & (entries - 1)` between the two stamps, and never waits: a full ring
//! overwrites its oldest record. A reader keeps its own cursor `c`, the
//! index of the next record it wants (a reader writes nothing to the region,
//! so the grant is `READ|MAP` and a hostile reader cannot touch the kernel's
//! words), and takes slot `c` when its stamp is `2c+2`, re-reading the stamp
//! after its copy: a stamp that moved means the producer lapped the reader,
//! and the reader jumps to the oldest record still there and counts what it
//! lost. A stamp below `2c+2` with `head` past `c` is a producer that
//! claimed the slot and has not finished: [`Next::Pending`], to be retried.
//! The producer reads nothing the readers can write.

use core::sync::atomic::{fence, AtomicU64, Ordering};

/// `"KLG1"`.
pub const MAGIC: u32 = u32::from_le_bytes(*b"KLG1");
/// Layout version.
pub const VERSION: u32 = 1;
/// Bytes of the region header.
pub const HDR_BYTES: usize = 128;
/// Bytes of one slot.
pub const SLOT_BYTES: usize = 320;
/// Bytes of the module field.
pub const MODULE_BYTES: usize = 24;
/// Bytes of the message field: the console's pre-format buffer.
pub const MSG_BYTES: usize = 256;

const OFF_VERSION: usize = 4;
const OFF_SLOT_BYTES: usize = 8;
const OFF_ENTRIES: usize = 12;
const OFF_TS_HZ: usize = 16;
const OFF_HEAD: usize = 64;

const S_STAMP: usize = 0;
const S_TS: usize = 8;
const S_SEQ: usize = 16;
const S_LEVEL: usize = 24;
const S_FLAGS: usize = 25;
const S_CPU: usize = 26;
const S_MODULE_LEN: usize = 27;
const S_MSG_LEN: usize = 28;
const S_MODULE: usize = 32;
const S_MSG: usize = 64;

const _: () = assert!(S_MODULE + MODULE_BYTES <= S_MSG);
const _: () = assert!(S_MSG + MSG_BYTES == SLOT_BYTES);
const _: () = assert!(SLOT_BYTES % 8 == 0 && HDR_BYTES % 8 == 0);

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

/// Bytes of a region of `entries` slots.
pub const fn region_bytes(entries: u32) -> usize {
    HDR_BYTES + entries as usize * SLOT_BYTES
}

/// A record to push.
pub struct New<'a> {
    pub ts: u64,
    pub level: u8,
    pub flags: u8,
    pub cpu: u8,
    /// The module path as `module_path!()` gives it; stored trimmed
    /// ([`trim_module`]).
    pub module: &'a str,
    /// The message, without its newline; cut at [`MSG_BYTES`].
    pub msg: &'a [u8],
}

/// The module path as stored: without the `azos_` every crate name starts
/// with, cut at [`MODULE_BYTES`].
pub fn trim_module(path: &str) -> &[u8] {
    let b = path.as_bytes();
    let b = b.strip_prefix(b"azos_").unwrap_or(b);
    &b[..b.len().min(MODULE_BYTES)]
}

/// One record, copied out of a slot.
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

#[inline]
unsafe fn word(base: *const u8, off: usize) -> &'static AtomicU64 {
    // SAFETY: the caller keeps `base + off` inside a live, 8-aligned region.
    unsafe { AtomicU64::from_ptr(base.add(off) as *mut u64) }
}

#[inline]
unsafe fn read_u32(base: *const u8, off: usize) -> u32 {
    // SAFETY: as `word`.
    unsafe { core::ptr::read_volatile(base.add(off) as *const u32) }
}

/// The header of a region of `entries` slots, as bytes: the const form the
/// kernel's pre-region ring is built from.
pub const fn header(entries: u32, ts_hz: u64) -> [u8; HDR_BYTES] {
    let mut h = [0u8; HDR_BYTES];
    let m = MAGIC.to_le_bytes();
    let v = VERSION.to_le_bytes();
    let s = (SLOT_BYTES as u32).to_le_bytes();
    let e = entries.to_le_bytes();
    let t = ts_hz.to_le_bytes();
    let mut i = 0;
    while i < 4 {
        h[i] = m[i];
        h[OFF_VERSION + i] = v[i];
        h[OFF_SLOT_BYTES + i] = s[i];
        h[OFF_ENTRIES + i] = e[i];
        i += 1;
    }
    i = 0;
    while i < 8 {
        h[OFF_TS_HZ + i] = t[i];
        i += 1;
    }
    h
}

/// Format `base` as an empty ring of `entries` slots.
///
/// # Safety
/// `base` is 8-aligned, writable, zeroed, [`region_bytes`]`(entries)` long,
/// and no producer or reader uses it yet.
pub unsafe fn format(base: *mut u8, entries: u32, ts_hz: u64) {
    let h = header(entries, ts_hz);
    // SAFETY: the caller owns the region.
    unsafe {
        core::ptr::copy_nonoverlapping(h.as_ptr(), base, HDR_BYTES);
    }
    fence(Ordering::Release);
}

/// Push `r` into the ring at `base`; returns the index it was stored at.
///
/// # Safety
/// `base` is a ring [`format`]ted (or built from [`header`]) and live for the
/// life of the program; it is 8-aligned. Any number of callers at once.
pub unsafe fn push(base: *mut u8, r: &New<'_>) -> u64 {
    // SAFETY: the producer's own header, which no reader can write.
    let entries = unsafe { read_u32(base, OFF_ENTRIES) } as u64;
    let head = unsafe { word(base, OFF_HEAD) };
    let i = head.fetch_add(1, Ordering::Relaxed);
    let slot = unsafe { base.add(HDR_BYTES + (i & (entries - 1)) as usize * SLOT_BYTES) };
    let stamp = unsafe { word(slot, S_STAMP) };
    stamp.store(2 * i + 1, Ordering::Relaxed);
    fence(Ordering::Release);
    let module = trim_module(r.module);
    let n = r.msg.len().min(MSG_BYTES);
    let mut flags = r.flags;
    if r.msg.len() > MSG_BYTES {
        flags |= FLAG_TRUNC;
    }
    // SAFETY: every store is inside the claimed slot.
    unsafe {
        word(slot, S_TS).store(r.ts, Ordering::Relaxed);
        word(slot, S_SEQ).store(i, Ordering::Relaxed);
        core::ptr::write_volatile(slot.add(S_LEVEL), r.level);
        core::ptr::write_volatile(slot.add(S_FLAGS), flags);
        core::ptr::write_volatile(slot.add(S_CPU), r.cpu);
        core::ptr::write_volatile(slot.add(S_MODULE_LEN), module.len() as u8);
        core::ptr::write_volatile(slot.add(S_MSG_LEN) as *mut u16, n as u16);
        core::ptr::copy_nonoverlapping(module.as_ptr(), slot.add(S_MODULE), module.len());
        core::ptr::copy_nonoverlapping(r.msg.as_ptr(), slot.add(S_MSG), n);
    }
    stamp.store(2 * i + 2, Ordering::Release);
    i
}

/// What one [`Reader::next`] found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Next {
    /// The record at the cursor, copied out; the cursor moved past it.
    Record,
    /// Nothing newer than the cursor.
    Empty,
    /// A producer has claimed the record at the cursor and not finished
    /// storing it. Retry; a reader that sees it for good may [`Reader::skip`].
    Pending,
    /// The producer lapped the reader: this many records are gone, and the
    /// cursor now stands at the oldest one left.
    Lost(u64),
}

/// A reader of a ring: its geometry, validated once.
#[derive(Clone, Copy)]
pub struct Reader {
    base: *const u8,
    entries: u64,
    ts_hz: u64,
}

impl Reader {
    /// Open the region at `base`, `len` bytes: `None` unless it is a ring of
    /// this layout version that fits.
    ///
    /// # Safety
    /// `base` is 8-aligned and readable for `len` bytes for as long as the
    /// reader is used.
    pub unsafe fn open(base: *const u8, len: usize) -> Option<Reader> {
        if len < HDR_BYTES {
            return None;
        }
        // SAFETY: inside the header, within `len`.
        let (magic, version, slot, entries) = unsafe {
            (read_u32(base, 0), read_u32(base, OFF_VERSION), read_u32(base, OFF_SLOT_BYTES), read_u32(base, OFF_ENTRIES))
        };
        if magic != MAGIC || version != VERSION || slot as usize != SLOT_BYTES {
            return None;
        }
        if entries == 0 || !entries.is_power_of_two() || region_bytes(entries) > len {
            return None;
        }
        // SAFETY: inside the header.
        let ts_hz = unsafe { word(base, OFF_TS_HZ).load(Ordering::Relaxed) };
        Some(Reader { base, entries: entries as u64, ts_hz })
    }

    /// Ticks per second of the records' `ts`.
    pub fn ts_hz(&self) -> u64 {
        self.ts_hz
    }
    /// Slots in the ring.
    pub fn entries(&self) -> u64 {
        self.entries
    }
    /// Records claimed so far.
    pub fn head(&self) -> u64 {
        // SAFETY: inside the header.
        unsafe { word(self.base, OFF_HEAD).load(Ordering::Acquire) }
    }
    /// The oldest record still in the ring.
    pub fn oldest(&self) -> u64 {
        self.head().saturating_sub(self.entries)
    }

    /// The record at `*cursor`, if there is one.
    pub fn next(&self, cursor: &mut u64, out: &mut Record) -> Next {
        let head = self.head();
        let c = *cursor;
        let oldest = head.saturating_sub(self.entries);
        if c < oldest {
            *cursor = oldest;
            return Next::Lost(oldest - c);
        }
        if c >= head {
            return Next::Empty;
        }
        // SAFETY: the slot is inside the region `open` validated.
        let slot = unsafe { self.base.add(HDR_BYTES + (c & (self.entries - 1)) as usize * SLOT_BYTES) };
        let stamp = unsafe { word(slot, S_STAMP) };
        let want = 2 * c + 2;
        let s = stamp.load(Ordering::Acquire);
        if s < want {
            return Next::Pending;
        }
        if s > want {
            return self.lapped(cursor);
        }
        // SAFETY: loads inside the slot; a torn copy is caught by the stamp.
        unsafe {
            out.ts = word(slot, S_TS).load(Ordering::Relaxed);
            out.seq = word(slot, S_SEQ).load(Ordering::Relaxed);
            out.level = core::ptr::read_volatile(slot.add(S_LEVEL));
            out.flags = core::ptr::read_volatile(slot.add(S_FLAGS));
            out.cpu = core::ptr::read_volatile(slot.add(S_CPU));
            out.module_len = core::ptr::read_volatile(slot.add(S_MODULE_LEN));
            out.msg_len = core::ptr::read_volatile(slot.add(S_MSG_LEN) as *const u16);
            core::ptr::copy_nonoverlapping(slot.add(S_MODULE), out.module.as_mut_ptr(), MODULE_BYTES);
            core::ptr::copy_nonoverlapping(slot.add(S_MSG), out.msg.as_mut_ptr(), MSG_BYTES);
        }
        fence(Ordering::Acquire);
        if stamp.load(Ordering::Relaxed) != want || out.seq != c {
            return self.lapped(cursor);
        }
        *cursor = c + 1;
        Next::Record
    }

    fn lapped(&self, cursor: &mut u64) -> Next {
        let oldest = self.oldest().max(*cursor + 1);
        let lost = oldest - *cursor;
        *cursor = oldest;
        Next::Lost(lost)
    }

    /// Give up on the record at `*cursor` (a producer that never finished it).
    pub fn skip(&self, cursor: &mut u64) {
        *cursor += 1;
    }
}

/// Copy every record `from` still holds into the ring at `to`, in order and
/// with its own timestamp, level, flags and CPU (their indices are the new
/// ring's).
///
/// # Safety
/// As [`push`] for `to`; `from` is a ring nobody pushes into meanwhile.
pub unsafe fn replay(from: &Reader, to: *mut u8) {
    let mut cursor = from.oldest();
    let mut rec = Record::empty();
    while from.next(&mut cursor, &mut rec) == Next::Record {
        let r = New {
            ts: rec.ts,
            level: rec.level,
            flags: rec.flags,
            cpu: rec.cpu,
            // The stored field is already trimmed, and trimming is idempotent
            // (a module path is ASCII).
            module: core::str::from_utf8(rec.module()).unwrap_or(""),
            msg: rec.msg(),
        };
        // SAFETY: the caller's contract.
        unsafe { push(to, &r) };
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
    let ts_us = if ts_hz == 0 { r.ts } else { (r.ts as u128 * 1_000_000 / ts_hz as u128) as u64 };
    let mut p = Put { out, n: 0 };
    p.dec(r.seq);
    p.byte(b' ');
    p.dec(ts_us);
    p.byte(b' ');
    p.dec(r.cpu as u64);
    p.byte(b' ');
    p.byte(level_letter(r.level));
    if r.flags & FLAG_PARTIAL != 0 {
        p.byte(b'+');
    }
    p.byte(b' ');
    if r.module().is_empty() {
        p.byte(b'-');
    } else {
        p.bytes(r.module());
    }
    p.byte(b' ');
    for &b in r.msg() {
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
