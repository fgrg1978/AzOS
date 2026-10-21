// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What runs behind the session channel: a command, or a prompt that runs
//! one command per line.
//!
//! Pure: the process side is a [`Runner`] (`main.rs` implements it over
//! `SYS_SPAWN_EX` and two pipes; `tests/host/sshd-tests` over a script).
//! The line editing, echo, history, `^C` and `^D` are the terminal server's
//! line discipline (`userspace/services/termd/src/disc.rs`), the same code
//! that serves the console, fed with the bytes of the channel.
//!
//! A command is one image of the volume (an applet of `TOOLBOX.ELF`, or
//! `/fat/NAME.ELF` if the server's row may start it) started with the channel as its stdio: its stdout and
//! stderr are one pipe read here and sent on the channel, its stdin a pipe
//! fed from the bytes the client sends. What `SH.ELF` adds (pipelines,
//! redirections, variables, builtins, jobs) is not here: the shell is a client
//! of the Terminal object served on the console, and a session does not own
//! the console. A line that asks for any of it is refused with a message that
//! says so, not run as something else.
//!
//! With a pty (`pty-req`) the channel is a terminal: typed bytes are echoed
//! and line-edited, `^C` stops the command, `^D` on an empty line ends its
//! input, and `\n` in the output is sent as `\r\n`. Without one the bytes
//! pass through as they are.

use crate::disc::{Discipline, Event as DEvent};
use alloc::boxed::Box;
use alloc::vec::Vec;

/// The prompt of an interactive session.
pub const PROMPT: &[u8] = b"azos-ssh$ ";
/// Output held for the channel before the command is made to wait.
pub const OUT_HIGH: usize = 32 * 1024;
/// How long a stop request has before `^C` forces the command, in ms.
pub const GRACE_MS: u64 = 300;
/// The most arguments of a command.
pub const MAX_ARGS: usize = 15;

/// What reading the command's output came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read {
    /// This many bytes were read.
    Data(usize),
    /// Nothing yet.
    Empty,
    /// The command closed its output.
    Eof,
}

/// The process side of a session.
pub trait Runner {
    /// Start the command `argv` with stdin and stdout/stderr pipes. `Err` is
    /// the message for the client (not found, not permitted, no pipe).
    fn spawn(&mut self, argv: &[Vec<u8>]) -> Result<(), &'static str>;
    /// Write to the command's stdin without blocking; the bytes taken.
    fn write_stdin(&mut self, data: &[u8]) -> usize;
    /// The client's input is over: the command reads end of file.
    fn close_stdin(&mut self);
    /// Read the command's output without blocking.
    fn read_output(&mut self, buf: &mut [u8]) -> Read;
    /// The command's exit status, once it has exited.
    fn exit_status(&mut self) -> Option<i32>;
    /// Ask the command to stop; `force` kills it.
    fn stop(&mut self, force: bool);
}

enum State {
    /// Nothing started: waiting for `shell` or `exec`.
    Idle,
    /// At the prompt (interactive).
    Prompt,
    /// A command runs. `interactive` returns to the prompt after it.
    Running { interactive: bool, stdin_open: bool, stop_at: Option<u64>, forced: bool, status: Option<i32> },
    /// Over: the status the client is told.
    Done(u32),
}

/// One session.
pub struct Session<R: Runner> {
    runner: R,
    /// On the heap: the discipline holds the history and the type-ahead (about
    /// 10 KiB), and a ring-3 stack is 16 KiB.
    disc: Box<Discipline>,
    state: State,
    pty: bool,
    /// Bytes for the channel, newline translation done.
    out: Vec<u8>,
    /// Bytes for the command's stdin not taken yet.
    stdin: Vec<u8>,
    /// The client sent EOF on the channel: no more input will come.
    client_eof: bool,
    /// End of input for the running command (`^D` on a terminal).
    cmd_eof: bool,
}

/// Why a command line cannot run.
fn parse(line: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut args: Vec<Vec<u8>> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut have = false;
    let mut i = 0;
    while i < line.len() {
        let c = line[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => {
                if have {
                    args.push(core::mem::take(&mut cur));
                    have = false;
                }
            }
            b'\'' => {
                have = true;
                i += 1;
                loop {
                    match line.get(i) {
                        None => return Err("unterminated quote"),
                        Some(b'\'') => break,
                        Some(&q) => cur.push(q),
                    }
                    i += 1;
                }
            }
            b'"' => {
                have = true;
                i += 1;
                loop {
                    match line.get(i) {
                        None => return Err("unterminated quote"),
                        Some(b'"') => break,
                        Some(b'\\') if matches!(line.get(i + 1), Some(b'"' | b'\\')) => {
                            i += 1;
                            cur.push(line[i]);
                        }
                        Some(&q) => cur.push(q),
                    }
                    i += 1;
                }
            }
            b'|' | b'&' | b';' | b'<' | b'>' | b'$' | b'`' | b'(' | b')' | b'*' | b'?' | b'\\' => {
                return Err(
                    "pipelines, redirection, variables, globbing and jobs belong to the shell on the console; a session runs one command",
                );
            }
            _ => {
                have = true;
                cur.push(c);
            }
        }
        i += 1;
    }
    if have {
        args.push(cur);
    }
    if args.len() > MAX_ARGS {
        return Err("too many arguments");
    }
    Ok(args)
}

impl<R: Runner> Session<R> {
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            disc: Box::new(const { Discipline::new() }),
            state: State::Idle,
            pty: false,
            out: Vec::new(),
            stdin: Vec::new(),
            client_eof: false,
            cmd_eof: false,
        }
    }

    /// `pty-req`.
    pub fn on_pty(&mut self, cols: u32, rows: u32) {
        self.pty = true;
        self.disc.set_size(cols.min(u16::MAX as u32) as u16, rows.min(u16::MAX as u32) as u16);
    }

    pub fn on_resize(&mut self, cols: u32, rows: u32) {
        self.disc.set_size(cols.min(u16::MAX as u32) as u16, rows.min(u16::MAX as u32) as u16);
    }

    /// `shell`: the prompt.
    pub fn on_shell(&mut self) {
        if !matches!(self.state, State::Idle) {
            return;
        }
        self.disc.set_echo(self.pty);
        self.emit(b"AzOS console over ssh: one command per line (ls, cat, ps ...); help lists them, exit leaves\n");
        self.prompt();
    }

    /// `exec`: run the command line, then end.
    pub fn on_exec(&mut self, line: &[u8], now_ms: u64) {
        if !matches!(self.state, State::Idle) {
            return;
        }
        self.disc.set_echo(self.pty);
        match self.start(line, now_ms, false) {
            Ok(()) => {}
            Err((msg, status)) => {
                self.say(msg);
                self.state = State::Done(status);
            }
        }
    }

    /// Bytes the client sent.
    pub fn on_data(&mut self, bytes: &[u8], now_ms: u64) {
        match &self.state {
            State::Idle | State::Done(_) => {}
            State::Prompt => {
                self.disc.push(bytes);
                self.drain_prompt(now_ms);
            }
            State::Running { .. } => {
                if self.pty {
                    self.disc.push(bytes);
                    self.drain_running(now_ms);
                } else if self.stdin.len() < OUT_HIGH {
                    self.stdin.extend_from_slice(bytes);
                }
            }
        }
    }

    /// The client sent EOF on the channel.
    pub fn on_eof(&mut self, now_ms: u64) {
        self.client_eof = true;
        if matches!(self.state, State::Prompt) {
            self.drain_prompt(now_ms);
        }
    }

    /// The client went away: stop what runs.
    pub fn on_close(&mut self) {
        if let State::Running { .. } = self.state {
            self.runner.stop(true);
        }
    }

    /// Bytes ready for the channel.
    pub fn output(&self) -> &[u8] {
        &self.out
    }

    /// `n` bytes of [`Session::output`] were sent.
    pub fn consumed(&mut self, n: usize) {
        self.out.drain(..n.min(self.out.len()));
    }

    /// The status to report once everything is sent, when the session is over.
    pub fn finished(&self) -> Option<u32> {
        match self.state {
            State::Done(s) if self.out.is_empty() => Some(s),
            _ => None,
        }
    }

    /// Move the session on: feed the command's stdin, read its output, notice
    /// its exit. Returns whether anything moved.
    pub fn pump(&mut self, now_ms: u64) -> bool {
        let mut moved = false;
        if let State::Running { .. } = &self.state {
            // Stdin.
            if !self.stdin.is_empty() {
                let n = self.runner.write_stdin(&self.stdin);
                if n > 0 {
                    self.stdin.drain(..n);
                    moved = true;
                }
            }
            if (self.client_eof || self.cmd_eof) && self.stdin.is_empty() {
                if let State::Running { stdin_open, .. } = &mut self.state {
                    if *stdin_open {
                        *stdin_open = false;
                        self.runner.close_stdin();
                        moved = true;
                    }
                }
            }
            // Output, while the channel is not backed up.
            let mut buf = [0u8; 1024];
            while self.out.len() < OUT_HIGH {
                match self.runner.read_output(&mut buf) {
                    Read::Data(n) => {
                        self.emit(&buf[..n]);
                        moved = true;
                    }
                    Read::Empty | Read::Eof => break,
                }
            }
            // The stop that waited out its grace.
            if let State::Running { stop_at: Some(t), forced, .. } = &mut self.state {
                if !*forced && now_ms.saturating_sub(*t) >= GRACE_MS {
                    *forced = true;
                    self.runner.stop(true);
                }
            }
            // Exit.
            if let State::Running { status, .. } = &mut self.state {
                if status.is_none() {
                    *status = self.runner.exit_status();
                }
            }
            let ended = matches!(self.state, State::Running { status: Some(_), .. });
            // What the command wrote is read before it is over: a command that
            // exits leaves its output in the pipe. (Not to the pipe's end: a
            // child of the command may hold it open.)
            if ended {
                let mut drained = false;
                while self.out.len() < OUT_HIGH {
                    match self.runner.read_output(&mut buf) {
                        Read::Data(n) => self.emit(&buf[..n]),
                        _ => {
                            drained = true;
                            break;
                        }
                    }
                }
                if drained {
                    self.command_over(now_ms);
                    moved = true;
                }
            }
        }
        moved
    }

    // ── internals ───────────────────────────────────────────────────────────

    fn command_over(&mut self, now_ms: u64) {
        let State::Running { interactive, status, .. } = self.state else { return };
        let status = status.unwrap_or(0);
        self.stdin.clear();
        self.cmd_eof = false;
        if interactive {
            self.prompt();
            // Lines typed ahead while the command ran.
            self.drain_prompt(now_ms);
        } else {
            self.state = State::Done(status as u32);
        }
    }

    /// Output to the channel, `\n` as `\r\n` on a terminal.
    fn emit(&mut self, b: &[u8]) {
        if !self.pty {
            self.out.extend_from_slice(b);
            return;
        }
        let mut prev = 0u8;
        for &c in b {
            if c == b'\n' && prev != b'\r' {
                self.out.push(b'\r');
            }
            self.out.push(c);
            prev = c;
        }
    }

    fn say(&mut self, msg: &str) {
        self.emit(msg.as_bytes());
        self.emit(b"\n");
    }

    fn flush_disc(&mut self) {
        let o = self.disc.take_output().to_vec();
        if !o.is_empty() {
            self.emit(&o);
        }
    }

    fn prompt(&mut self) {
        self.state = State::Prompt;
        self.disc.set_foreground(0);
        self.disc.set_prompt(if self.pty { PROMPT } else { b"" });
        self.disc.begin_line();
        self.flush_disc();
    }

    /// Start `line` as a command.
    fn start(&mut self, line: &[u8], now_ms: u64, interactive: bool) -> Result<(), (&'static str, u32)> {
        let _ = now_ms;
        let args = parse(line).map_err(|m| (m, 2))?;
        if args.is_empty() {
            return Err(("", 0));
        }
        self.runner.spawn(&args).map_err(|m| (m, 127))?;
        self.stdin.clear();
        self.cmd_eof = false;
        if self.pty {
            // The command reads the terminal: edit its lines, no prompt.
            self.disc.set_prompt(b"");
            self.disc.begin_line();
            self.flush_disc();
        }
        self.state = State::Running { interactive, stdin_open: true, stop_at: None, forced: false, status: None };
        Ok(())
    }

    /// The prompt's bytes: complete lines run.
    fn drain_prompt(&mut self, now_ms: u64) {
        loop {
            let ev = self.disc.step();
            self.flush_disc();
            match ev {
                None => {
                    // Everything the client typed has run: if it is done
                    // typing, so is the session.
                    if self.client_eof && matches!(self.state, State::Prompt) {
                        self.state = State::Done(0);
                    }
                    return;
                }
                Some(DEvent::Line) => {
                    let line = self.disc.line().to_vec();
                    if self.line(&line, now_ms) {
                        return;
                    }
                }
                Some(DEvent::Interrupt(_)) => {
                    self.disc.begin_line();
                    self.flush_disc();
                }
                Some(DEvent::Eof) => {
                    self.emit(b"logout\n");
                    self.state = State::Done(0);
                    return;
                }
                Some(DEvent::Bytes(_)) => {}
            }
        }
    }

    /// Handle one line at the prompt. True if the state changed.
    fn line(&mut self, line: &[u8], now_ms: u64) -> bool {
        let words = match parse(line) {
            Ok(w) => w,
            Err(m) => {
                self.say(m);
                self.prompt();
                return false;
            }
        };
        match words.first().map(|w| w.as_slice()) {
            None => {
                self.prompt();
                false
            }
            Some(b"exit") | Some(b"logout") => {
                let code = words.get(1).and_then(|c| core::str::from_utf8(c).ok()).and_then(|c| c.parse::<u32>().ok()).unwrap_or(0);
                self.state = State::Done(code);
                true
            }
            Some(b"help") => {
                self.say("a command is an applet of TOOLBOX.ELF (args cat echo false inspect ls ps sleep spin true wc yes) or another image the server's row may start (NAME or NAME.ELF); exit leaves");
                self.prompt();
                false
            }
            Some(_) => match self.start(line, now_ms, true) {
                Ok(()) => true,
                Err((m, _)) => {
                    self.say(m);
                    self.prompt();
                    false
                }
            },
        }
    }

    /// Bytes typed while a command runs on a terminal: its lines (to its
    /// stdin), `^C` (stop it), `^D` on an empty line (end of its input).
    fn drain_running(&mut self, now_ms: u64) {
        loop {
            let ev = self.disc.step();
            self.flush_disc();
            match ev {
                None => return,
                Some(DEvent::Line) => {
                    let mut l = self.disc.line().to_vec();
                    l.push(b'\n');
                    self.stdin.extend_from_slice(&l);
                }
                Some(DEvent::Interrupt(_)) => {
                    if let State::Running { stop_at, forced, .. } = &mut self.state {
                        if stop_at.is_none() {
                            *stop_at = Some(now_ms);
                            self.runner.stop(false);
                        } else if !*forced {
                            *forced = true;
                            self.runner.stop(true);
                        }
                    }
                    self.disc.begin_line();
                    self.flush_disc();
                }
                Some(DEvent::Eof) => self.cmd_eof = true,
                Some(DEvent::Bytes(_)) => {}
            }
        }
    }
}
