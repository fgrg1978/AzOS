// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Terminal object's server side: the interface's implementation over a
//! [`Discipline`] and a [`Console`].
//!
//! Request-driven, because the ABI's accept blocks and a single task cannot
//! wait on an endpoint and on the UART at once: `main.rs` sits in accept, and
//! every op is either immediate or, for [`Terminal::read_event`], runs the
//! console wait itself inside the call. Bytes typed between two calls wait in
//! the kernel's RX ring; the one client calls again at once, and while a job
//! runs it calls [`Terminal::read_event`] with a short timeout, so the
//! interrupt key is read within that timeout. That is coherent for ONE client,
//! which is all this serves.
//!
//! Pure given a [`Console`]: `tests/host/term-tests` pulls this file in with
//! `#[path]` and drives it through the generated client stub over a loopback.

use crate::disc::{Discipline, Event as DEvent};
use azos_term::{
    pack_chunk, pack_event, pack_size, unpack_bytes, Event, EventWords, Kind, Terminal, CHUNK_BYTES, PROMPT_MAX,
    PROMPT_WORDS, WAIT_FOREVER,
};

/// The console as the server sees it: the kernel's RX owner side.
pub trait Console {
    /// Read at most `buf.len()` typed bytes, waiting up to `timeout_ns`
    /// (`None`: until some arrive). The count read, 0 on timeout, negative if
    /// the console cannot be read.
    fn read(&mut self, buf: &mut [u8], timeout_ns: Option<u64>) -> isize;
    /// Write to the console.
    fn write(&mut self, b: &[u8]);
}

/// The Terminal served over a console.
pub struct Service<C: Console> {
    pub d: Discipline,
    pub con: C,
    /// The client hung up with this status: the server ends after answering.
    pub hung_up: Option<i32>,
}

impl<C: Console> Service<C> {
    pub const fn new(con: C) -> Self {
        Self { d: Discipline::new(), con, hung_up: None }
    }

    fn flush(&mut self) {
        let o = self.d.take_output();
        if !o.is_empty() {
            self.con.write(o);
        }
    }

    fn event_of(&self, ev: DEvent) -> Event {
        let mut e;
        match ev {
            DEvent::Line => {
                e = Event::new(Kind::Line);
                let l = self.d.line();
                e.len = l.len() as u16;
                let n = l.len().min(CHUNK_BYTES);
                e.data[..n].copy_from_slice(&l[..n]);
            }
            DEvent::Bytes(n) => {
                e = Event::new(Kind::Bytes);
                e.len = n as u16;
                e.data[..n].copy_from_slice(&self.d.raw()[..n]);
            }
            DEvent::Interrupt(job) => {
                e = Event::new(Kind::Interrupt);
                e.job = job;
            }
            DEvent::Eof => e = Event::new(Kind::Eof),
        }
        e
    }
}

impl<C: Console> Terminal for Service<C> {
    fn size(&self) -> u32 {
        let (c, r) = self.d.size();
        pack_size(c, r)
    }

    fn set_size(&mut self, cols: u16, rows: u16) {
        self.d.set_size(cols, rows);
    }

    fn set_mode(&mut self, raw: bool) {
        self.d.set_raw(raw);
    }

    fn set_echo(&mut self, on: bool) {
        self.d.set_echo(on);
    }

    fn set_foreground(&mut self, job: u32) {
        self.d.set_foreground(job);
    }

    fn set_prompt(&mut self, len: u32, text: [u64; PROMPT_WORDS]) {
        let mut b = [0u8; PROMPT_MAX];
        unpack_bytes(&text, &mut b);
        self.d.set_prompt(&b[..(len as usize).min(PROMPT_MAX)]);
    }

    fn begin_line(&mut self) {
        self.d.begin_line();
        self.flush();
    }

    fn redraw(&mut self) {
        self.d.redraw();
        self.flush();
    }

    fn read_event(&mut self, timeout_ms: u32) -> EventWords {
        let timeout = (timeout_ms != WAIT_FOREVER).then(|| timeout_ms as u64 * 1_000_000);
        loop {
            let ev = self.d.step();
            self.flush();
            if let Some(ev) = ev {
                return pack_event(&self.event_of(ev));
            }
            let mut buf = [0u8; 64];
            let n = self.con.read(&mut buf, timeout);
            if n > 0 {
                self.d.push(&buf[..n as usize]);
                continue;
            }
            return pack_event(&Event::new(Kind::Timeout));
        }
    }

    fn line_chunk(&self, off: u32) -> EventWords {
        pack_chunk(Some(self.d.line()), off as usize)
    }

    fn history(&self, back: u32, off: u32) -> EventWords {
        pack_chunk(self.d.history(back as usize), off as usize)
    }

    fn hangup(&mut self, status: i32) {
        self.hung_up = Some(status);
    }
}
