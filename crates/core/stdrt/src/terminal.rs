// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A job's own terminal: the `Terminal` interface (`userspace/lib/term`)
//! through the call capability the shell handed the program as fd 0
//! (`SYS_SPAWN_EX`, `MOVE_KIND_ENDPOINT`), written out by hand for the reason
//! [`crate::entropy`] is: the generated client needs the IDL proc-macro, which
//! cannot be part of the std build graph. `tests/host/stdrt-tests` runs these
//! functions against the generated dispatcher, which pins the ids and the
//! wire form to the interface's.
//!
//! The server answers the capability only while the program's job has the
//! focus, and only the five ops here (size, mode, echo, the next event, the
//! rest of a line). Input is typed events: a line (cooked mode, the default),
//! bytes (raw mode), the end of input; [`Reader`] turns them into the byte
//! stream `std::io::stdin` reads.

use azos_abi::ipc_msg::{MsgDesc, MSG_VERSION};

/// The interface id (ASCII "TERM"), `azos_term::TERMINAL_ID`.
pub const TERMINAL_ID: u32 = 0x5445_524D;
/// The interface level this client speaks.
pub const LEVEL: u64 = 2;
/// Op numbers, `azos_term::TerminalIdl::OP_*`.
pub const OP_SIZE: u64 = 1;
pub const OP_SET_MODE: u64 = 3;
pub const OP_SET_ECHO: u64 = 4;
pub const OP_READ_EVENT: u64 = 9;
pub const OP_LINE_CHUNK: u64 = 10;
/// Event kinds, `azos_term::Kind`.
pub const KIND_LINE: u8 = 1;
pub const KIND_BYTES: u8 = 2;
pub const KIND_EOF: u8 = 4;
/// Payload bytes of one event or chunk, `azos_term::CHUNK_BYTES`.
pub const CHUNK_BYTES: usize = 48;
/// The longest the server waits in one job's `read_event`,
/// `azos_term::JOB_WAIT_MAX_MS`: what a read asks for, and loops on.
pub const JOB_WAIT_MS: u32 = 50;
/// The longest line, `azos_term::LINE_MAX`.
pub const LINE_MAX: usize = 255;
/// Bit 16 of a chunk's word 0: the line exists (`azos_term::pack_chunk`).
const CHUNK_VALID: u64 = 1 << 16;

/// The endpoint call: request in `*msg`, reply written over it, 0 when
/// answered.
pub type Call<'a> = &'a mut dyn FnMut(&mut MsgDesc) -> isize;

/// One call: header `op`, then `args`; the reply's words after the status, or
/// `None` when the call failed or the server refused it (a job without the
/// focus, a revoked badge).
fn call(c: Call<'_>, op: u64, args: &[u64]) -> Option<MsgDesc> {
    let mut m = MsgDesc { version: MSG_VERSION, n_words: 1 + args.len() as u8, ..MsgDesc::default() };
    m.words[0] = (TERMINAL_ID as u64) << 32 | LEVEL << 16 | op;
    m.words[1..1 + args.len()].copy_from_slice(args);
    (c(&mut m) == 0 && m.words[0] == 0).then_some(m)
}

/// The window size, `(columns, rows)`.
pub fn size(c: Call<'_>) -> Option<(u16, u16)> {
    let m = call(c, OP_SIZE, &[])?;
    let v = m.words[1] as u32;
    Some(((v >> 16) as u16, v as u16))
}

/// Raw (`true`) or cooked input. `false`: refused.
pub fn set_mode(c: Call<'_>, raw: bool) -> bool {
    call(c, OP_SET_MODE, &[raw as u64]).is_some()
}

/// Echo on or off. `false`: refused.
pub fn set_echo(c: Call<'_>, on: bool) -> bool {
    call(c, OP_SET_ECHO, &[on as u64]).is_some()
}

/// What one [`Reader::read`] came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read {
    /// This many bytes were written to the buffer.
    Bytes(usize),
    /// The end of input (`^D` on an empty line).
    End,
    /// Nothing within the wait (or an interrupt key, which is the shell's).
    Again,
    /// The terminal refused or the call failed: it is not this program's.
    Gone,
}

/// The stream of a job's terminal: what the last event left unread.
pub struct Reader {
    buf: [u8; LINE_MAX + 1],
    len: usize,
    off: usize,
}

impl Reader {
    pub const fn new() -> Self {
        Self { buf: [0; LINE_MAX + 1], len: 0, off: 0 }
    }

    fn take(&mut self, out: &mut [u8]) -> usize {
        let n = (self.len - self.off).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.off..self.off + n]);
        self.off += n;
        n
    }

    /// Fill `out` with what is typed: bytes left from the last event first,
    /// else the next event within `wait_ms`. A line comes whole (its chunks
    /// fetched), with the newline the terminal took; raw bytes as typed.
    pub fn read(&mut self, c: Call<'_>, out: &mut [u8], wait_ms: u32) -> Read {
        if out.is_empty() {
            return Read::Bytes(0);
        }
        if self.off < self.len {
            return Read::Bytes(self.take(out));
        }
        let Some(m) = call(c, OP_READ_EVENT, &[wait_ms as u64]) else { return Read::Gone };
        let w0 = m.words[1];
        let (kind, len) = (w0 as u8, ((w0 >> 8) as u16 as usize).min(LINE_MAX));
        let inline = |i: usize| m.words[2 + i / 8].to_le_bytes()[i % 8];
        match kind {
            KIND_BYTES => {
                let n = len.min(CHUNK_BYTES);
                for i in 0..n {
                    self.buf[i] = inline(i);
                }
                (self.len, self.off) = (n, 0);
            }
            KIND_LINE => {
                let first = len.min(CHUNK_BYTES);
                for i in 0..first {
                    self.buf[i] = inline(i);
                }
                let mut got = first;
                while got < len {
                    let Some(ch) = call(c, OP_LINE_CHUNK, &[got as u64]) else { return Read::Gone };
                    if ch.words[1] & CHUNK_VALID == 0 {
                        break;
                    }
                    let n = (len - got).min(CHUNK_BYTES);
                    for i in 0..n {
                        self.buf[got + i] = ch.words[2 + i / 8].to_le_bytes()[i % 8];
                    }
                    got += n;
                }
                self.buf[got] = b'\n';
                (self.len, self.off) = (got + 1, 0);
            }
            KIND_EOF => return Read::End,
            _ => return Read::Again,
        }
        Read::Bytes(self.take(out))
    }
}

impl Default for Reader {
    fn default() -> Self {
        Self::new()
    }
}
