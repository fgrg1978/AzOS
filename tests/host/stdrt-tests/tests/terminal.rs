// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_stdrt::terminal` is the hand-written client of the `Terminal`
//! interface a job reads its lent terminal through. It is run here against the
//! generated dispatcher (`azos_term::TerminalIdl`), so a change of the
//! interface's id, level, op numbers or wire form fails this file; and its
//! `Reader` is checked for what `std::io::stdin` reads: a line whole with its
//! newline (however many chunks it takes), raw bytes as typed, a short buffer
//! across calls, the end of input, and a refusal.

use azos_idl::MsgDesc;
use azos_stdrt::terminal::{self, Read, Reader};
use azos_term::{
    pack_chunk, pack_event, Event, EventWords, JobTerminal, Kind, Lent, Terminal, TerminalIdl, CHUNK_BYTES,
    PROMPT_WORDS,
};
use std::collections::VecDeque;

/// A terminal that answers from a script of events, holds the last line for
/// `line_chunk`, and records the mode and echo it was set to and the waits.
#[derive(Default)]
struct Term {
    events: VecDeque<Event>,
    line: Vec<u8>,
    raw: Option<bool>,
    echo: Option<bool>,
    waits: Vec<u32>,
}

impl Term {
    fn line(&mut self, l: &[u8]) {
        let mut e = Event::new(Kind::Line);
        e.len = l.len() as u16;
        let n = l.len().min(CHUNK_BYTES);
        e.data[..n].copy_from_slice(&l[..n]);
        self.events.push_back(e);
        self.line = l.to_vec();
    }
    fn bytes(&mut self, b: &[u8]) {
        let mut e = Event::new(Kind::Bytes);
        e.len = b.len() as u16;
        e.data[..b.len()].copy_from_slice(b);
        self.events.push_back(e);
    }
}

impl Terminal for Term {
    fn size(&self) -> u32 {
        azos_term::pack_size(132, 43)
    }
    fn set_size(&mut self, _: u16, _: u16) {}
    fn set_mode(&mut self, raw: bool) {
        self.raw = Some(raw);
    }
    fn set_echo(&mut self, on: bool) {
        self.echo = Some(on);
    }
    fn set_foreground(&mut self, _: u32) {}
    fn set_prompt(&mut self, _: u32, _: [u64; PROMPT_WORDS]) {}
    fn begin_line(&mut self) {}
    fn redraw(&mut self) {}
    fn read_event(&mut self, timeout_ms: u32) -> EventWords {
        self.waits.push(timeout_ms);
        pack_event(&self.events.pop_front().unwrap_or(Event::new(Kind::Timeout)))
    }
    fn line_chunk(&self, off: u32) -> EventWords {
        pack_chunk(Some(&self.line), off as usize)
    }
    fn history(&self, _: u32, _: u32) -> EventWords {
        pack_chunk(None, 0)
    }
    fn hangup(&mut self, _: i32) {}
    fn lend_job(&mut self, _: u32) -> Lent<JobTerminal> {
        Lent::none()
    }
}

fn through(t: &mut Term) -> impl FnMut(&mut MsgDesc) -> isize + '_ {
    move |m: &mut MsgDesc| {
        let req = *m;
        let mut reply = MsgDesc::default();
        let _ = TerminalIdl::dispatch(t, &req, &mut reply);
        *m = reply;
        0
    }
}

/// **The ids are the generated ones.**
///
/// **Canary.** Change `terminal::OP_READ_EVENT` to 8: this goes red, and so
/// does every read below (the dispatcher answers another op).
#[test]
fn ids_are_the_generated_ones() {
    assert_eq!(terminal::TERMINAL_ID, azos_term::TERMINAL_ID);
    assert_eq!(terminal::LEVEL, u64::from(TerminalIdl::LEVEL));
    assert_eq!(terminal::OP_SIZE, u64::from(TerminalIdl::OP_SIZE));
    assert_eq!(terminal::OP_SET_MODE, u64::from(TerminalIdl::OP_SET_MODE));
    assert_eq!(terminal::OP_SET_ECHO, u64::from(TerminalIdl::OP_SET_ECHO));
    assert_eq!(terminal::OP_READ_EVENT, u64::from(TerminalIdl::OP_READ_EVENT));
    assert_eq!(terminal::OP_LINE_CHUNK, u64::from(TerminalIdl::OP_LINE_CHUNK));
    assert_eq!((terminal::KIND_LINE, terminal::KIND_BYTES, terminal::KIND_EOF), (Kind::Line as u8, Kind::Bytes as u8, Kind::Eof as u8));
    assert_eq!((terminal::CHUNK_BYTES, terminal::LINE_MAX), (CHUNK_BYTES, azos_term::LINE_MAX));
}

/// **Mode, echo and size cross the wire** as the generated client sends them.
#[test]
fn mode_echo_and_size_reach_the_server() {
    let mut t = Term::default();
    assert!(terminal::set_mode(&mut through(&mut t), true));
    assert!(terminal::set_echo(&mut through(&mut t), false));
    assert_eq!(terminal::size(&mut through(&mut t)), Some((132, 43)));
    assert_eq!((t.raw, t.echo), (Some(true), Some(false)));
    assert!(terminal::set_mode(&mut through(&mut t), false));
    assert_eq!(t.raw, Some(false));
}

/// **A line comes whole, with its newline**: a 200-byte line is the inline
/// chunk and three more, and a buffer shorter than the line takes it across
/// reads without asking the terminal again.
///
/// **Canary.** Stop fetching after the inline chunk (`while got < len` →
/// `while false`): the line is cut at 48 bytes and this goes red.
#[test]
fn a_line_comes_whole_with_its_newline_across_short_reads() {
    let long: Vec<u8> = (0..200u32).map(|i| b'a' + (i % 26) as u8).collect();
    let mut t = Term::default();
    t.line(&long);
    let mut r = Reader::new();
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    while got.last() != Some(&b'\n') {
        match r.read(&mut through(&mut t), &mut buf, 50) {
            Read::Bytes(n) => got.extend_from_slice(&buf[..n]),
            other => panic!("{other:?}"),
        }
    }
    let mut want = long.clone();
    want.push(b'\n');
    assert_eq!(got, want);
    assert_eq!(t.waits, [50], "one event read for the line");
}

/// **Raw bytes as typed; a timeout is "again", the end of input is the end;
/// a refusal is "gone".**
#[test]
fn raw_bytes_timeouts_the_end_and_a_refusal() {
    let mut t = Term::default();
    t.bytes(b"\x1b[A");
    t.events.push_back(Event::new(Kind::Eof));
    let mut r = Reader::new();
    let mut buf = [0u8; 2];
    assert_eq!(r.read(&mut through(&mut t), &mut buf, 50), Read::Bytes(2));
    assert_eq!(&buf, b"\x1b[");
    assert_eq!(r.read(&mut through(&mut t), &mut buf, 50), Read::Bytes(1), "the rest, without a call");
    assert_eq!(buf[0], b'A');
    assert_eq!(r.read(&mut through(&mut t), &mut buf, 50), Read::End);
    assert_eq!(r.read(&mut through(&mut t), &mut buf, 50), Read::Again, "a timeout");
    // A refused call (the job lost the focus): the status word is not 0.
    let mut refused = |m: &mut MsgDesc| {
        azos_idl::refuse(m);
        0
    };
    assert_eq!(r.read(&mut refused, &mut buf, 50), Read::Gone);
    assert!(!terminal::set_mode(&mut refused, true));
    assert_eq!(terminal::size(&mut |_m: &mut MsgDesc| -1), None, "a failed call");
}
