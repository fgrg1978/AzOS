// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Terminal` object: AzOS's answer to a pty.
//!
//! A terminal is not a file with an `ioctl` table and a signal side channel.
//! It is a typed interface (`#[azos_interface]`, the L13 IDL) served by a
//! ring-3 terminal server (`userspace/services/termd`) that owns the console,
//! runs the line discipline, and serves ONE client (the shell). The client
//! reaches it through a `Cap<Endpoint>` the name server lends for the name
//! `term` (the shell's signed row imports it; `userspace/lib/names`), not
//! through a descriptor number and not by a grant of its own.
//!
//! * **State** is set by typed ops: [`Terminal::set_size`], [`Terminal::set_mode`]
//!   (raw or cooked), [`Terminal::set_echo`], [`Terminal::set_prompt`],
//!   [`Terminal::set_foreground`].
//! * **Input** is a stream of typed events ([`Event`]) pulled with
//!   [`Terminal::read_event`]: a completed line, raw bytes, end of input, a
//!   timeout, and the **interrupt key (Ctrl-C) as an [`Kind::Interrupt`]
//!   event** that names the foreground job it was addressed to. There is no
//!   signal: the client decides what an interrupt means (the shell stops the
//!   job; an editor could ignore it).
//! * **Focus** is [`Terminal::set_foreground`]: `0` is the client itself (line
//!   editing, echo); a non-zero job id means a job runs. While one does the
//!   terminal delivers no line and no bytes, only interrupts tagged with that
//!   id, and holds what is typed (type-ahead) for the next line.
//!
//! # The two byte streams
//!
//! Both are **inline, chunked**, not shared-memory queues, and that is a
//! stated shortcut, not a design:
//!
//! * **Input** (terminal to client): an event carries up to [`CHUNK_BYTES`]
//!   (48) bytes in the reply's six data words; the rest of a longer line (a
//!   line is at most 255 bytes) is fetched with [`Terminal::line_chunk`].
//!   `IDL` packs an array one word per element, so a byte array would not fit
//!   the eight inline words; bytes are packed eight to a `u64` by
//!   [`pack_bytes`] on both sides.
//! * **Output** (client to terminal) does not pass through the terminal
//!   server: the client writes the console's TX stream directly
//!   (the console's `WRITE` op). TX has no single owner (the kernel, the tools the client
//!   starts and the client all write it), so a second path through the server
//!   would add a call per write and order nothing. The server writes only
//!   what the discipline produces: the prompt, the echo and the `^C` echo.
//!
//! A `rings::Queue` in shared memory would need `Cap<Shm>` transferred and
//! mapped on both sides, and today's two-sided shm path goes through leases
//! (grant, wait, accept-map). That is its own front; when it lands, the
//! input stream moves there and [`Terminal::read_event`] stays as the control
//! channel.
//!
//! # Not here: the Linux runtime mapping
//!
//! `/dev/ptmx` and termios are not mapped onto this object. A foreground
//! Linux job reads the console through the kernel's own discipline while the
//! console's owner lends it input (`SPAWN_F_CONSOLE_IN`,
//! `CONSOLE_RX.lend`). The owner is the terminal server, so the kernel lets
//! a CLIENT of the owner (a task holding a call capability on an endpoint
//! the owner serves, here the shell on `endpoint.term`) start the job that
//! input is lent to; the lend is still the owner's, single, and ends with
//! the job. While it lasts `^C` is `SIGINT` to the job (the kernel's own
//! rule), not an [`Kind::Interrupt`] event, and the server reads nothing. A
//! termios view would be a Linux-side translation of
//! `set_mode`/`set_echo`/`set_size`.
#![no_std]

pub use azos_idl::{Cap, IdlError, MsgDesc, Transport};
use azos_idl::azos_interface;

/// The interface id (ASCII "TERM").
pub const TERMINAL_ID: u32 = 0x5445_524D;
/// `timeout_ms` meaning "wait for an event".
pub const WAIT_FOREVER: u32 = u32::MAX;
/// Payload bytes of one chunk.
pub const CHUNK_BYTES: usize = 48;
/// Data words of one chunk.
pub const CHUNK_WORDS: usize = CHUNK_BYTES / 8;
/// Longest line a terminal delivers, in bytes.
pub const LINE_MAX: usize = 255;
/// Longest prompt, in bytes.
pub const PROMPT_MAX: usize = 32;
/// Words of a prompt.
pub const PROMPT_WORDS: usize = PROMPT_MAX / 8;
/// Window size a fresh terminal reports.
pub const DEFAULT_COLS: u16 = 80;
/// Window size a fresh terminal reports.
pub const DEFAULT_ROWS: u16 = 24;

/// The Terminal interface. One client, one server; see the module doc.
#[azos_interface(id = 0x5445_524D, level = 1, words = 8)]
pub trait Terminal {
    /// The window size, columns in the high half: `cols << 16 | rows`.
    #[idempotent]
    fn size(&self) -> u32;
    /// Set the window size (a display that resized, or the client's own
    /// configuration).
    fn set_size(&mut self, cols: u16, rows: u16);
    /// Raw (`true`): no line editing, bytes come back as [`Kind::Bytes`].
    /// Cooked (`false`, the default): the server edits and delivers lines.
    /// The interrupt key is an event in both.
    fn set_mode(&mut self, raw: bool);
    /// Echo typed input (default on). The prompt and the interrupt echo
    /// (`^C`) follow it; the prompt does not (see [`Terminal::begin_line`]).
    fn set_echo(&mut self, on: bool);
    /// Focus: `0` is the client (it reads); any other value is the id of the
    /// job that has the terminal. Interrupts are tagged with it.
    fn set_foreground(&mut self, job: u32);
    /// The prompt of the next [`Terminal::begin_line`]: `len` bytes (at most
    /// [`PROMPT_MAX`]) packed by [`pack_bytes`].
    fn set_prompt(&mut self, len: u32, text: [u64; PROMPT_WORDS]);
    /// Start a line: print the prompt and clear the line being edited. What
    /// was typed while a job had the focus is replayed into it by the next
    /// [`Terminal::read_event`].
    fn begin_line(&mut self);
    /// Redraw the line being edited (prompt, text, cursor), for a client that
    /// wrote over it. Draws nothing with echo off.
    fn redraw(&mut self);
    /// The next event, waiting at most `timeout_ms` (0 polls, [`WAIT_FOREVER`]
    /// waits). The server's own wait: a blocked call does not wake on the
    /// caller's other events (a child's exit), so a client that has some polls.
    fn read_event(&mut self, timeout_ms: u32) -> [u64; 1 + CHUNK_WORDS];
    /// The bytes of the last [`Kind::Line`] from `off` on.
    #[idempotent]
    fn line_chunk(&self, off: u32) -> [u64; 1 + CHUNK_WORDS];
    /// History line `back` (0 = newest) from `off` on; word 0 has no
    /// [`Event::len`] when there is no such line.
    #[idempotent]
    fn history(&self, back: u32, off: u32) -> [u64; 1 + CHUNK_WORDS];
    /// End the session with `status`: the server exits with it, which
    /// releases console input. Status 0 gives the console back to the kernel's
    /// recovery shell; a non-zero one is a failed session, which the
    /// supervisor answers by restarting the server (and the shell).
    fn hangup(&mut self, status: i32);
}

/// What an event is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Nothing arrived within the timeout.
    Timeout = 0,
    /// A line is complete; [`Event::len`] bytes, first chunk inline.
    Line = 1,
    /// Raw bytes ([`Event::len`] of them, at most [`CHUNK_BYTES`]).
    Bytes = 2,
    /// The interrupt key; [`Event::job`] is the foreground job.
    Interrupt = 3,
    /// End of input (`^D` on an empty line).
    Eof = 4,
}

impl Kind {
    pub const fn from_u8(v: u8) -> Option<Kind> {
        Some(match v {
            0 => Kind::Timeout,
            1 => Kind::Line,
            2 => Kind::Bytes,
            3 => Kind::Interrupt,
            4 => Kind::Eof,
            _ => return None,
        })
    }
}

/// One decoded event (or chunk).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub kind: Kind,
    /// Total length of the line, or bytes of this [`Kind::Bytes`] event.
    pub len: u16,
    /// The foreground job an [`Kind::Interrupt`] was addressed to.
    pub job: u32,
    /// The first (up to) [`CHUNK_BYTES`] bytes.
    pub data: [u8; CHUNK_BYTES],
}

impl Event {
    pub const fn new(kind: Kind) -> Event {
        Event { kind, len: 0, job: 0, data: [0; CHUNK_BYTES] }
    }

    /// The inline bytes: `min(len, CHUNK_BYTES)` of them.
    pub fn inline(&self) -> &[u8] {
        &self.data[..(self.len as usize).min(CHUNK_BYTES)]
    }
}

/// Reply words of an event or chunk.
pub type EventWords = [u64; 1 + CHUNK_WORDS];

/// Pack an event: word 0 is `kind | len << 8 | job << 32`, then the bytes.
pub fn pack_event(e: &Event) -> EventWords {
    let mut w = [0u64; 1 + CHUNK_WORDS];
    w[0] = e.kind as u64 | (e.len as u64) << 8 | (e.job as u64) << 32;
    let mut d = [0u64; CHUNK_WORDS];
    pack_bytes(&e.data, &mut d);
    w[1..].copy_from_slice(&d);
    w
}

/// Decode an event. `None` for a kind this level does not know.
pub fn unpack_event(w: &EventWords) -> Option<Event> {
    let kind = Kind::from_u8(w[0] as u8)?;
    let mut e = Event::new(kind);
    e.len = (w[0] >> 8) as u16;
    e.job = (w[0] >> 32) as u32;
    unpack_bytes(&w[1..], &mut e.data);
    Some(e)
}

/// Bit 16 of a chunk's word 0: the line exists.
const CHUNK_VALID: u64 = 1 << 16;

/// Pack a chunk of `src` (the whole line or history entry) from `off`: word
/// 0 is `total_len | valid << 16`; the data words hold up to [`CHUNK_BYTES`]
/// bytes from `off`. `src == None`: no such line (valid clear, length 0).
pub fn pack_chunk(src: Option<&[u8]>, off: usize) -> EventWords {
    let mut w = [0u64; 1 + CHUNK_WORDS];
    let Some(s) = src else { return w };
    w[0] = s.len() as u64 | CHUNK_VALID;
    let mut b = [0u8; CHUNK_BYTES];
    if off < s.len() {
        let n = (s.len() - off).min(CHUNK_BYTES);
        b[..n].copy_from_slice(&s[off..off + n]);
    }
    let mut d = [0u64; CHUNK_WORDS];
    pack_bytes(&b, &mut d);
    w[1..].copy_from_slice(&d);
    w
}

/// A decoded chunk: the source's total length, and `Some` bytes only if it
/// exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub valid: bool,
    pub total: u16,
    pub data: [u8; CHUNK_BYTES],
}

/// Decode a [`pack_chunk`] reply.
pub fn unpack_chunk(w: &EventWords) -> Chunk {
    let mut c = Chunk { valid: w[0] & CHUNK_VALID != 0, total: w[0] as u16, data: [0; CHUNK_BYTES] };
    unpack_bytes(&w[1..], &mut c.data);
    c
}

/// Pack bytes eight to a word, little endian; words past the bytes are 0.
/// Bytes past `8 * out.len()` are dropped.
pub fn pack_bytes(src: &[u8], out: &mut [u64]) {
    for (i, o) in out.iter_mut().enumerate() {
        let mut v = 0u64;
        for k in 0..8 {
            if let Some(&b) = src.get(i * 8 + k) {
                v |= (b as u64) << (8 * k);
            }
        }
        *o = v;
    }
}

/// The inverse of [`pack_bytes`]: fill `out` from the words.
pub fn unpack_bytes(words: &[u64], out: &mut [u8]) {
    for (i, o) in out.iter_mut().enumerate() {
        *o = words.get(i / 8).map_or(0, |w| (w >> (8 * (i % 8))) as u8);
    }
}

/// `cols << 16 | rows`, the form [`Terminal::size`] returns.
pub const fn pack_size(cols: u16, rows: u16) -> u32 {
    (cols as u32) << 16 | rows as u32
}

/// The inverse of [`pack_size`]: `(cols, rows)`.
pub const fn unpack_size(v: u32) -> (u16, u16) {
    ((v >> 16) as u16, v as u16)
}
