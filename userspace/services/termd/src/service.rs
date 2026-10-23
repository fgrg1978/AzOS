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
//! The input event ring (keys with no byte, the mouse; `input.rs`) is drained
//! inside the same call. The console wait is also the wait for the ring: the
//! server announces on the ring's consumer flag before it sleeps in the
//! console wait, the input drivers nudge that wait when they publish into a
//! ring whose consumer announced (`LOG_CONSOLE_WAIT` then returns 0 bytes
//! early), and the ring is looked at again. No timer: an idle prompt sleeps
//! until a byte, an event or the caller's deadline. (While the console's
//! input is lent to a Linux job the wait is a timer-only one, so events are
//! acted on at the caller's next call.)
//!
//! # The login gate
//!
//! With users enrolled ([`Gate::state`] is not `OPEN`) the server also owns the
//! way in. Without a session it serves nobody and waits for the
//! secure-attention key ([`Service::locked_loop`]); with one, the key is looked
//! for in everything it reads (the keyboard chord in the input ring, the serial
//! byte in the console bytes) and, when it comes, the session is ended and the
//! secure prompt takes the input ([`Service::secure_prompt`]): the shell
//! reads none of it, whatever it was in the middle of. The prompt asks for the
//! user name and the passphrase, makes the credential and calls the login
//! service ([`Gate::login`]); the kernel verifies it and the service starts the
//! user's shell. Nothing typed at the prompt reaches the line discipline, and
//! the passphrase is wiped when the credential is made. Without a gate every
//! path below is skipped and the server is what it was.
//!
//! Pure given a [`Console`] and a [`Gate`]: `tests/host/term-tests` pulls this
//! file in with `#[path]` and drives it through the generated client stub over
//! a loopback.

use crate::disc::{Discipline, Event as DEvent};
use crate::input::Input;
use crate::mouse::Sink;
use crate::secure::{wipe, wipe_words, Echo, Prompt, Step};
use azos_login::{pack_credential, pack_name, state, status, CREDENTIAL_WORDS, NAME_WORDS};
use azos_rings::region::SpscRing;
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
    /// Monotonic time, nanoseconds (the double-click clock and the wait
    /// deadlines). No system call: the vDSO page.
    fn now_ns(&self) -> u64;
    /// Ask the renderer to draw the overlay the screen region now holds (a
    /// byte the console draws nothing for).
    fn refresh(&mut self);
}

/// What the terminal server asks of the login service.
pub trait Gate {
    /// [`state::OPEN`] (nobody is enrolled: no gate), [`state::LOCKED`] or
    /// [`state::SESSION`]. A service that cannot be reached is `LOCKED`; it is
    /// asked only on a gated console (the call right on it is minted for none
    /// other: `azos_topology::builder::login_call_withheld`).
    fn state(&mut self) -> u32;
    /// Log `user` in with `credential`: a [`status`].
    fn login(&mut self, user: [u64; NAME_WORDS], credential: [u64; CREDENTIAL_WORDS]) -> u32;
    /// End the session: the shell and everything beneath it stop. `true` only
    /// when the service says none is left (`ended::OK`); a shell that
    /// survived, or a service that cannot be asked, is `false`: the prompt is
    /// not drawn while something of the last user's may still run.
    fn end(&mut self) -> bool;
}

/// No login service: nobody is enrolled, the console is the system's.
pub struct NoGate;

impl Gate for NoGate {
    fn state(&mut self) -> u32 {
        state::OPEN
    }
    fn login(&mut self, _: [u64; NAME_WORDS], _: [u64; CREDENTIAL_WORDS]) -> u32 {
        status::NOT_NOW
    }
    fn end(&mut self) -> bool {
        true
    }
}

/// Where the server is in the login gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// No gate: the shell is served as it always was.
    Open,
    /// Gated and nobody is logged in: nothing is served.
    Locked,
    /// Gated and a user's shell is the client.
    Session,
}

/// The terminal input as the input consumer's sink: the line discipline.
struct Typed<'a> {
    d: &'a mut Discipline,
    attention: &'a mut bool,
}

impl Sink for Typed<'_> {
    fn push(&mut self, bytes: &[u8]) {
        self.d.push(bytes);
    }

    /// A mouse report is for the client's own input. While a job has the
    /// focus nothing reads it, and held it would be replayed into the line
    /// editor when the job ends.
    fn report(&mut self, bytes: &[u8]) {
        if self.d.foreground() == 0 {
            self.d.push(bytes);
        }
    }

    fn attention(&mut self) {
        *self.attention = true;
    }
}

/// The input consumer's sink while the secure prompt or the locked wait owns
/// the input: the keys with no byte and the mouse are nothing to it, the chord
/// restarts it.
struct Quiet<'a>(&'a mut bool);

impl Sink for Quiet<'_> {
    fn push(&mut self, _: &[u8]) {}

    fn report(&mut self, _: &[u8]) {}

    fn attention(&mut self) {
        *self.0 = true;
    }
}

/// Bytes typed after the serial secure-attention key in the same read, kept
/// for the prompt.
const CARRY_MAX: usize = 64;

/// The canary's sink: bytes go nowhere.
#[cfg(feature = "canary-drop-input")]
struct Nothing;

#[cfg(feature = "canary-drop-input")]
impl Sink for Nothing {
    fn push(&mut self, _: &[u8]) {}
}

/// The Terminal served over a console.
pub struct Service<C: Console, G: Gate = NoGate> {
    pub d: Discipline,
    pub con: C,
    /// The client hung up with this status: the server ends after answering.
    pub hung_up: Option<i32>,
    /// The input event ring and the mouse, once attached.
    pub inp: Option<Input<SpscRing>>,
    /// The login service.
    pub gate: G,
    /// Where the server is in the gate ([`Service::gate_up`]).
    pub mode: Mode,
    /// The control byte that is the secure-attention key on a serial line; 0:
    /// none (a keyboard chord only).
    pub sak_serial: u8,
    prompt: Prompt,
    /// The chord was pressed (set by the input sink).
    attention: bool,
    carry: [u8; CARRY_MAX],
    carry_len: usize,
}

#[cfg(test)]
impl<C: Console> Service<C, NoGate> {
    /// A server with no gate, for the host tests of the terminal itself.
    pub const fn new(con: C) -> Self {
        Self::with_gate(con, NoGate)
    }
}

impl<C: Console, G: Gate> Service<C, G> {
    pub const fn with_gate(con: C, gate: G) -> Self {
        Self {
            d: Discipline::new(),
            con,
            hung_up: None,
            inp: None,
            gate,
            mode: Mode::Open,
            sak_serial: 0,
            prompt: Prompt::new(),
            attention: false,
            carry: [0; CARRY_MAX],
            carry_len: 0,
        }
    }

    /// Drain the input ring into the terminal input and hand the renderer the
    /// overlay that changed.
    fn pump_input(&mut self) {
        let Some(inp) = self.inp.as_mut() else { return };
        // The canary takes the events and hands the terminal input nothing
        // (not leaving them: the server would not be able to sleep).
        let now = self.con.now_ns();
        #[cfg(feature = "canary-drop-input")]
        inp.pump(now, &mut Nothing);
        #[cfg(not(feature = "canary-drop-input"))]
        inp.pump(now, &mut Typed { d: &mut self.d, attention: &mut self.attention });
        if inp.flush_overlay() {
            self.con.refresh();
        }
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

// ── The login gate ──────────────────────────────────────────────────────────

impl<C: Console, G: Gate> Service<C, G> {
    /// Ask the login service where the gate is. Call once, before serving.
    pub fn gate_up(&mut self) {
        self.mode = match self.gate.state() {
            state::OPEN => Mode::Open,
            state::SESSION => Mode::Session,
            _ => Mode::Locked,
        };
    }

    /// Is the console behind a login?
    pub fn guarded(&self) -> bool {
        self.mode != Mode::Open
    }

    /// Nobody is logged in and the gate is up.
    pub fn locked(&self) -> bool {
        self.mode == Mode::Locked
    }

    /// End the session and say so; `false` leaves it (and `mode`) as it was,
    /// with the person told.
    fn end_session(&mut self) -> bool {
        if self.gate.end() {
            self.mode = Mode::Locked;
            return true;
        }
        self.say(b"\n[AzOS] the session's shell did not stop: no login is taken until it does\n");
        false
    }

    /// The session's client hung up (it exited): end the session and lock.
    /// While the shell survives the forced stop the console stays unserved and
    /// the secure-attention key asks again; `false`: the console cannot be read
    /// (the caller ends, with the session still recorded).
    pub fn session_ended(&mut self) -> bool {
        self.hung_up = None;
        while !self.end_session() {
            if !self.await_attention() {
                return false;
            }
        }
        true
    }

    fn say(&mut self, text: &[u8]) {
        self.con.write(text);
    }

    /// The look of the secure-attention key on a serial line, for the banner.
    fn banner(&mut self) {
        self.say(b"\n[AzOS] press Ctrl+Alt+Del");
        if self.sak_serial != 0 {
            let key = [self.sak_serial.wrapping_add(0x40)];
            self.say(b" (or ^");
            self.con.write(&key);
            self.say(b" on a serial line)");
        }
        self.say(b" to log in\n");
    }

    /// The input ring looked at while the prompt or the locked wait owns the
    /// input.
    fn pump_quiet(&mut self) {
        let Some(inp) = self.inp.as_mut() else { return };
        let now = self.con.now_ns();
        inp.pump(now, &mut Quiet(&mut self.attention));
        if inp.flush_overlay() {
            self.con.refresh();
        }
    }

    /// The next typed bytes for the prompt or the locked wait: bytes kept from
    /// after the serial key first, else a wait on the console and the ring. The
    /// ring's events are looked at as they come (the chord sets `attention`);
    /// `Ok(0)` is such an event, to be looked at by the caller. `Err`: the
    /// console cannot be read.
    fn secure_read(&mut self, buf: &mut [u8; 64]) -> Result<usize, ()> {
        loop {
            if self.carry_len > 0 {
                let n = self.carry_len;
                buf[..n].copy_from_slice(&self.carry[..n]);
                wipe(&mut self.carry);
                self.carry_len = 0;
                return Ok(n);
            }
            self.pump_quiet();
            if self.attention {
                return Ok(0);
            }
            if self.inp.as_mut().is_some_and(|i| !i.announce()) {
                continue;
            }
            let n = self.con.read(buf, None);
            if let Some(inp) = self.inp.as_mut() {
                inp.woke();
                if n > 0 {
                    inp.console_key();
                }
            }
            if n < 0 {
                return Err(());
            }
            if n > 0 {
                return Ok(n as usize);
            }
            // A wait nudged for the ring: look at it.
        }
    }

    /// Keep what was typed after the serial key at `at` in `bytes`, for the prompt.
    fn keep_after(&mut self, bytes: &[u8], at: usize) {
        let rest = &bytes[at + 1..];
        let n = rest.len().min(CARRY_MAX);
        self.carry[..n].copy_from_slice(&rest[..n]);
        self.carry_len = n;
    }

    /// Where the serial secure-attention key is in `bytes`, if it is.
    fn sak_in(&self, bytes: &[u8]) -> Option<usize> {
        (self.sak_serial != 0).then(|| bytes.iter().position(|&b| b == self.sak_serial)).flatten()
    }

    /// Locked: serve nobody, show how to log in, and let nothing through but
    /// the secure-attention key; then the secure prompt. Returns with the
    /// server logged in (`Session`), or `Locked` after the person gave up, or
    /// with the console unreadable (the caller ends).
    pub fn locked_loop(&mut self) {
        while self.mode == Mode::Locked {
            self.banner();
            if !self.await_attention() {
                return;
            }
            self.secure_prompt();
        }
    }

    /// Wait for the secure-attention key, dropping everything else typed.
    /// `false`: the console cannot be read.
    fn await_attention(&mut self) -> bool {
        self.attention = false;
        loop {
            let mut buf = [0u8; 64];
            let r = self.secure_read(&mut buf);
            let n = match r {
                Ok(n) => n,
                Err(()) => return false,
            };
            if core::mem::take(&mut self.attention) {
                wipe(&mut buf);
                return true;
            }
            let at = self.sak_in(&buf[..n]);
            if let Some(at) = at {
                let typed = buf;
                self.keep_after(&typed[..n], at);
                wipe(&mut buf);
                return true;
            }
            wipe(&mut buf);
        }
    }

    /// The key came while a session ran: the session ends (the shell is gone
    /// before the prompt is drawn, so no program of the user's is left to
    /// draw over it or to read), then the prompt. A shell that does not stop
    /// keeps the session: no prompt, the same user's shell is served, and the
    /// next key asks again.
    fn take_over(&mut self) {
        if self.end_session() {
            self.secure_prompt();
        } else {
            // What came after the key was for a prompt that is not drawn: it
            // is not kept for the next one.
            wipe(&mut self.carry);
            self.carry_len = 0;
        }
    }

    /// The secure prompt: user name, passphrase, credential, the login
    /// service. Returns when a login succeeded (`mode` is `Session` and the
    /// discipline is a fresh one: a user's history is not the next one's) or
    /// when the person gave up (`mode` stays `Locked`).
    pub fn secure_prompt(&mut self) {
        let mut echo = Echo::new();
        'prompt: loop {
            self.prompt.reset();
            self.attention = false;
            self.say(b"\nAzOS login\nlogin: ");
            loop {
                let mut buf = [0u8; 64];
                let n = match self.secure_read(&mut buf) {
                    Ok(n) => n,
                    Err(()) => {
                        self.prompt.reset();
                        return;
                    }
                };
                if core::mem::take(&mut self.attention) {
                    wipe(&mut buf);
                    continue 'prompt;
                }
                for i in 0..n {
                    let b = buf[i];
                    if self.sak_serial != 0 && b == self.sak_serial {
                        wipe(&mut buf);
                        continue 'prompt;
                    }
                    let step = self.prompt.feed(b, &mut echo);
                    let shown = echo.take();
                    if !shown.is_empty() {
                        self.con.write(shown);
                    }
                    match step {
                        Step::More => {}
                        Step::Passphrase => self.say(b"passphrase: "),
                        Step::Cancel => {
                            wipe(&mut buf);
                            self.prompt.reset();
                            self.say(b"\n");
                            return;
                        }
                        Step::Submit => {
                            wipe(&mut buf);
                            if self.submit() {
                                return;
                            }
                            continue 'prompt;
                        }
                    }
                }
                wipe(&mut buf);
            }
        }
    }

    /// Make the credential of what was typed, wipe the passphrase, and ask the
    /// login service. `true`: the user's shell started.
    fn submit(&mut self) -> bool {
        let Some(name) = pack_name(self.prompt.user()) else {
            self.prompt.reset();
            return false;
        };
        let mut cred = azos_login::credential(self.prompt.user(), self.prompt.passphrase());
        self.prompt.reset();
        let mut words = pack_credential(&cred);
        wipe(&mut cred);
        let rc = self.gate.login(name, words);
        wipe_words(&mut words);
        match rc {
            status::STARTED => {
                // A new user, a new terminal: not the last one's history, size or mode.
                self.d.reset();
                self.mode = Mode::Session;
                self.say(b"\n");
                true
            }
            status::NOT_NOW => {
                self.say(b"\nlogin: not available now\n");
                false
            }
            status::NOT_READY => {
                self.say(b"\nlogin: this board cannot verify a login\n");
                false
            }
            status::NO_SESSION => {
                self.say(b"\nlogin: the shell did not start\n");
                false
            }
            _ => {
                self.say(b"\nLogin incorrect\n");
                false
            }
        }
    }
}

impl<C: Console, G: Gate> Terminal for Service<C, G> {
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
        if job == 0 {
            if let Some(inp) = self.inp.as_mut() {
                inp.job_ended();
            }
        }
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
        let deadline = (timeout_ms != WAIT_FOREVER).then(|| self.con.now_ns().saturating_add(timeout_ms as u64 * 1_000_000));
        loop {
            self.pump_input();
            if core::mem::take(&mut self.attention) && self.mode == Mode::Session {
                // The chord: the session ends and the prompt takes the input.
                // The client that was reading is gone (its reply goes nowhere).
                self.take_over();
                return pack_event(&Event::new(Kind::Timeout));
            }
            let ev = self.d.step();
            self.flush();
            if let Some(ev) = ev {
                return pack_event(&self.event_of(ev));
            }
            // About to sleep: tell the ring. An event that came meanwhile is
            // taken first.
            if self.inp.as_mut().is_some_and(|i| !i.announce()) {
                continue;
            }
            let wait = deadline.map(|d| d.saturating_sub(self.con.now_ns()));
            let mut buf = [0u8; 64];
            let n = self.con.read(&mut buf, wait);
            if let Some(inp) = self.inp.as_mut() {
                inp.woke();
            }
            if n > 0 {
                let got = n as usize;
                if self.mode == Mode::Session {
                    if let Some(at) = self.sak_in(&buf[..got]) {
                        // The serial key: what was typed before it is dropped,
                        // what came after it is for the prompt.
                        self.keep_after(&buf[..got], at);
                        wipe(&mut buf);
                        self.take_over();
                        return pack_event(&Event::new(Kind::Timeout));
                    }
                }
                self.d.push(&buf[..got]);
                if let Some(inp) = self.inp.as_mut() {
                    inp.console_key();
                }
                continue;
            }
            // A wait that ended before the caller's deadline was nudged for the
            // ring: go round and look at it.
            if n == 0 && deadline.map_or(true, |d| self.con.now_ns() < d) && self.inp.is_some() {
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
