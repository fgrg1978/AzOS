// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SH.ELF`: the AzOS user shell.
//!
//! A ring-3 program with no hardware authority. It does not read the console:
//! it is a client of the `Terminal` object (`userspace/lib/term`) that
//! `TERMD.ELF` serves over the `endpoint.term` endpoint its row holds
//! `WRITE` on. The terminal server owns console input and does the line
//! editing, echo and history; the shell asks it for a line, and for typed
//! events while a job runs. It parses the line (`parse.rs`), and runs each
//! command as a child with `SYS_SPAWN_EX` under the child's OWN seccomp
//! profile and topology row: the shell can start only the images its row
//! holds a `Cap<Launch>` for, and lends them nothing but the descriptors it
//! moves to them and the pipe ends it shares with them (a pipe is a byte ring
//! in a shared region, `azos_libsys::pipe`; the stage gets the region in the
//! move list, the end named by its fd). `^C` reaches the shell as a typed
//! `Interrupt` event naming the foreground job; the shell asks the job to
//! stop (`SYS_ALERT`, then force after 300 ms or a second `^C`).
//!
//! Every syscall goes through `sys::name(..)`, so `tests/host/seccomp-tests`
//! derives this image's exact profile from these sources.

#![no_std]
#![no_main]

mod ident;
mod parse;
mod path;
#[allow(dead_code)]
mod req;

use azos_idl as idl;
use azos_libsys as sys;
use azos_names::{Call, NamesCall, NamesClient, Renewing};
use azos_term::{
    pack_bytes, unpack_chunk, unpack_event, unpack_size, Event, IdlError, Kind, MsgDesc, TerminalCall, TerminalClient,
    Transport, CHUNK_BYTES, LINE_MAX, PROMPT_WORDS, WAIT_FOREVER,
};
use parse::{parse, Pipeline, Redir, Vars};
use req::{Fd, ReqBuilder};

/// The prompt. Distinct from the kernel recovery console's `robot> `.
const PROMPT: &[u8] = b"azos$ ";
/// Environment strings kept, and their bytes.
const ENV_MAX: usize = 16;
const ENV_BYTES: usize = 1024;
/// Background jobs remembered.
const JOBS: usize = 8;
/// How long a stop request has before `^C` forces the job, in ms.
const GRACE_MS: u64 = 300;
/// The signal a `^C` carries (SIGINT): its exit code is 130.
const SIGINT: u64 = 2;
/// The terminal is polled this often while a foreground job runs: from the
/// first to the last, doubling. A blocked call to the terminal server does
/// not wake when a child exits, so the shell asks with a timeout and looks
/// at its jobs in between.
const POLL_MIN_MS: u32 = 1;
const POLL_MAX_MS: u32 = 32;
/// The same, at the prompt, while background jobs exist.
const BG_POLL_MS: u32 = 100;
/// At the prompt with no job, the shell still polls now and then for what it
/// adopted: it is a child subreaper, and an orphan of a finished job can exit
/// while the shell waits for a line (a blocked call to the terminal server
/// does not wake on a child's exit). `ORPHAN_POLLS` polls `ORPHAN_POLL_MS`
/// apart per prompt, then it waits for a line without waking. An orphan that
/// outlives that is reaped, and reported, at the next prompt that polls or at
/// the next job.
const ORPHAN_POLL_MS: u32 = 250;
const ORPHAN_POLLS: u32 = 40;
/// How long the shell waits for the terminal server to take its first call
/// (the server starts after the shell and claims its endpoint then).
const CONNECT_MS: u64 = 20_000;

// `open` flags (`crates/fs/fs/src/vfs.rs`).
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_CREAT: u64 = 0x40;
const O_TRUNC: u64 = 0x200;
const O_APPEND: u64 = 0x400;


// ── Output ──────────────────────────────────────────────────────────────────

fn out(b: &[u8]) {
    let _ = sys::console_write(sys::STDOUT, b);
}

fn out_num(v: i64) {
    let mut d = [0u8; 21];
    let mut i = d.len();
    let neg = v < 0;
    let mut u = v.unsigned_abs();
    loop {
        i -= 1;
        d[i] = b'0' + (u % 10) as u8;
        u /= 10;
        if u == 0 {
            break;
        }
    }
    if neg {
        i -= 1;
        d[i] = b'-';
    }
    out(&d[i..]);
}

fn fmt_num(v: i64, buf: &mut [u8; 21]) -> usize {
    let mut d = [0u8; 21];
    let mut i = d.len();
    let neg = v < 0;
    let mut u = v.unsigned_abs();
    loop {
        i -= 1;
        d[i] = b'0' + (u % 10) as u8;
        u /= 10;
        if u == 0 {
            break;
        }
    }
    if neg {
        i -= 1;
        d[i] = b'-';
    }
    let n = d.len() - i;
    buf[..n].copy_from_slice(&d[i..]);
    n
}

fn err_line(what: &[u8], why: &[u8]) {
    out(b"sh: ");
    out(what);
    out(b": ");
    out(why);
    out(b"\n");
}

/// Where a builtin's standard output goes.
#[derive(Clone, Copy)]
enum Sink {
    Console,
    Handle(u32),
}

impl Sink {
    fn put(self, b: &[u8]) {
        match self {
            Sink::Console => out(b),
            Sink::Handle(h) => {
                let _ = sys::file_write_typed(h, b);
            }
        }
    }
}

// ── The environment ─────────────────────────────────────────────────────────

struct Env {
    buf: [u8; ENV_BYTES],
    len: usize,
    n: usize,
}

impl Env {
    const fn new() -> Self {
        Self { buf: [0; ENV_BYTES], len: 0, n: 0 }
    }

    fn entries(&self) -> impl Iterator<Item = &[u8]> {
        self.buf[..self.len].split(|&b| b == 0).take(self.n)
    }

    fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.entries().find_map(|kv| kv.strip_prefix(key).and_then(|r| r.strip_prefix(b"=")))
    }

    fn unset(&mut self, key: &[u8]) {
        let mut copy = [0u8; ENV_BYTES];
        let mut len = 0;
        let mut n = 0;
        for kv in self.buf[..self.len].split(|&b| b == 0).take(self.n) {
            if kv.strip_prefix(key).is_some_and(|r| r.first() == Some(&b'=')) {
                continue;
            }
            copy[len..len + kv.len()].copy_from_slice(kv);
            len += kv.len() + 1;
            n += 1;
        }
        self.buf = copy;
        self.len = len;
        self.n = n;
    }

    fn set(&mut self, key: &[u8], val: &[u8]) -> bool {
        if key.is_empty() || key.contains(&b'=') || key.contains(&0) || val.contains(&0) {
            return false;
        }
        self.unset(key);
        let need = key.len() + 1 + val.len() + 1;
        if self.n == ENV_MAX || self.len + need > ENV_BYTES {
            return false;
        }
        let at = self.len;
        self.buf[at..at + key.len()].copy_from_slice(key);
        self.buf[at + key.len()] = b'=';
        self.buf[at + key.len() + 1..at + need - 1].copy_from_slice(val);
        self.buf[at + need - 1] = 0;
        self.len += need;
        self.n += 1;
        true
    }
}

/// The variables a line expands: the environment, and `$?`.
struct Scope<'a> {
    env: &'a Env,
    status: &'a [u8],
}

impl Vars for Scope<'_> {
    fn get(&self, name: &[u8]) -> Option<&[u8]> {
        if name == b"?" { Some(self.status) } else { self.env.get(name) }
    }
}

// ── Jobs ────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Job {
    used: bool,
    tids: [u32; parse::MAX_STAGES],
    done: [bool; parse::MAX_STAGES],
    n: usize,
    /// The last stage's exit code, once it is reaped.
    status: i32,
}

const NO_JOB: Job = Job { used: false, tids: [0; parse::MAX_STAGES], done: [false; parse::MAX_STAGES], n: 0, status: 0 };

impl Job {
    fn finished(&self) -> bool {
        self.done[..self.n].iter().all(|&d| d)
    }

    /// Reap whatever of this job has exited. Returns whether anything did.
    fn reap(&mut self) -> bool {
        let mut any = false;
        for i in 0..self.n {
            if self.done[i] {
                continue;
            }
            let mut st: i32 = 0;
            let r = sys::waitpid(self.tids[i], &mut st as *mut i32);
            if r > 0 || r == -10 {
                // -ECHILD: already gone (reaped elsewhere); count it done.
                self.done[i] = true;
                if i == self.n - 1 {
                    self.status = if r > 0 { st } else { 127 };
                }
                any = true;
            }
        }
        any
    }

    fn stop(&self, force: bool) {
        for i in 0..self.n {
            if !self.done[i] {
                let how = if force { sys::KILL_FORCE } else { sys::KILL_REQUEST };
                let _ = sys::task_kill(self.tids[i], how, SIGINT, sys::KILL_SUBTREE);
            }
        }
    }
}

// ── The shell ───────────────────────────────────────────────────────────────

struct Shell {
    /// The root `Cap<Dir>` the row grants, which every redirection and `cat` is
    /// opened beneath; `None` when the row grants none (then nothing opens).
    root: Option<u32>,
    env: Env,
    cwd: [u8; path::PATH_MAX],
    cwd_len: usize,
    status: i32,
    jobs: [Job; JOBS],
    line: Pipeline,
    /// The terminal: the `Terminal` object over the endpoint the name server
    /// lends, asked for again when the lease lapses.
    term: TerminalClient<Renewing<SysCall>>,
    /// The line the terminal delivered last.
    text: [u8; LINE_MAX],
    text_len: usize,
}

/// The transport of the `Terminal` client: the v2 call through the
/// `Cap<Endpoint>` `endpoint.term`.
struct Ep(u32);

impl Transport for Ep {
    fn call(&self, msg: &mut MsgDesc) -> idl::Result {
        match sys::ipc_call_v2(self.0, msg) {
            0 => Ok(()),
            rc => Err(IdlError::Transport(rc)),
        }
    }
}

/// The v2 call and the close of a handle, for [`Renewing`].
struct SysCall;

impl Call for SysCall {
    fn call(&self, handle: u32, msg: &mut MsgDesc) -> isize {
        sys::ipc_call_v2(handle, msg) as isize
    }

    fn close(&self, handle: u32) {
        let _ = sys::close_typed(handle);
    }
}

/// The `Cap<Endpoint>` this row holds: its call right on `endpoint.names`,
/// which the kernel gives a row that has `imports` (stamped with the row's
/// identity), and the only endpoint it holds at start. Ring 3 has no by-name
/// lookup, so scan the pool indexes; everything else the shell reaches, it
/// asks the name server for.
fn find_names_endpoint() -> Option<u32> {
    (0..16u32).find_map(|i| {
        let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), i);
        (h > 0).then_some(h as u32)
    })
}

/// What asking the name server for the terminal came to.
enum Lookup {
    /// The call right on the terminal server, lent (derived, call-only).
    Lent(u32),
    /// The name server answered and lent nothing: the row's `imports` do not
    /// allow the name, or the server does not hold it. Final.
    Refused,
    /// The name server did not answer (not serving yet).
    Unreachable,
}

/// Ask the name server (`names`, from [`find_names_endpoint`]) for `term`.
fn lookup_terminal(names: u32) -> Lookup {
    let Some(name) = azos_names::pack_name(b"term") else { return Lookup::Refused };
    match NamesClient::new(Ep(names)).lookup(name) {
        Ok(l) => l.get().map_or(Lookup::Refused, |c| Lookup::Lent(c.raw())),
        Err(_) => Lookup::Unreachable,
    }
}

impl Shell {
    fn cwd(&self) -> &[u8] {
        &self.cwd[..self.cwd_len]
    }

    fn absolute(&self, p: &[u8], buf: &mut [u8; path::PATH_MAX]) -> Option<usize> {
        path::join(self.cwd(), p, buf).ok()
    }

    /// The terminal server is gone (its call failed): nothing to read. Exit
    /// non-zero, so the supervisor restarts the shell, which reconnects to the
    /// restarted server (an exit 0 would leave a console held by a server
    /// with no client).
    fn terminal_gone(&mut self) -> ! {
        out(b"sh: the terminal server is gone\n");
        sys::exit(1)
    }

    /// The next terminal event, waiting at most `ms`.
    fn next_event(&mut self, ms: u32) -> Event {
        match self.term.read_event(ms) {
            Ok(w) => unpack_event(&w).unwrap_or(Event::new(Kind::Timeout)),
            Err(_) => self.terminal_gone(),
        }
    }

    /// End the session: tell the terminal server the status, then exit. A
    /// failing shell (`exit 1`) fails the session, so the supervisor restarts
    /// the server with it; `exit 0` gives the console back to the kernel.
    fn quit(&mut self, code: i32) -> ! {
        let _ = self.term.hangup(code);
        sys::exit(code)
    }

    /// The rest of a line the terminal delivered: `first` is the event, whose
    /// inline bytes come first and `line_chunk` gives the others.
    fn line_of(&mut self, first: &Event, buf: &mut [u8; LINE_MAX]) -> usize {
        let total = (first.len as usize).min(LINE_MAX);
        let inline = first.inline();
        let mut got = inline.len().min(total);
        buf[..got].copy_from_slice(&inline[..got]);
        while got < total {
            let c = match self.term.line_chunk(got as u32) {
                Ok(w) => unpack_chunk(&w),
                Err(_) => self.terminal_gone(),
            };
            if !c.valid {
                break;
            }
            let n = (total - got).min(CHUNK_BYTES);
            buf[got..got + n].copy_from_slice(&c.data[..n]);
            got += n;
        }
        got
    }

    /// History line `back` (0 = newest) of the terminal, or `None`.
    fn history_line(&mut self, back: u32, buf: &mut [u8; LINE_MAX]) -> Option<usize> {
        let mut got = 0usize;
        let mut total = LINE_MAX;
        loop {
            let c = match self.term.history(back, got as u32) {
                Ok(w) => unpack_chunk(&w),
                Err(_) => self.terminal_gone(),
            };
            if !c.valid {
                return (got > 0 || total == 0).then_some(got);
            }
            if got == 0 {
                total = (c.total as usize).min(LINE_MAX);
            }
            let n = (total - got).min(CHUNK_BYTES);
            buf[got..got + n].copy_from_slice(&c.data[..n]);
            got += n;
            if got >= total {
                return Some(got);
            }
        }
    }

    /// Read one line. `None` at end of input (`^D` on an empty line).
    fn read_line(&mut self) -> Option<()> {
        let _ = self.term.begin_line();
        let mut orphan_polls = ORPHAN_POLLS;
        loop {
            let ms = if self.jobs.iter().any(|j| j.used) {
                BG_POLL_MS
            } else if orphan_polls > 0 {
                ORPHAN_POLL_MS
            } else {
                WAIT_FOREVER
            };
            let ev = self.next_event(ms);
            match ev.kind {
                Kind::Line => {
                    let mut buf = [0u8; LINE_MAX];
                    let n = self.line_of(&ev, &mut buf);
                    self.text[..n].copy_from_slice(&buf[..n]);
                    self.text_len = n;
                    return Some(());
                }
                // The terminal showed `^C` and cleared the line.
                Kind::Interrupt => {
                    self.status = 130;
                    let _ = self.term.begin_line();
                }
                Kind::Eof => {
                    out(b"exit\n");
                    return None;
                }
                Kind::Timeout | Kind::Bytes => {
                    orphan_polls = orphan_polls.saturating_sub(1);
                    if self.reap_background() {
                        let _ = self.term.redraw();
                    }
                }
            }
        }
    }

    /// Reap finished background jobs and say which. Returns whether any.
    fn reap_background(&mut self) -> bool {
        let mut said = false;
        for (j, job) in self.jobs.iter_mut().enumerate() {
            if job.used && job.reap() && job.finished() {
                if !said {
                    out(b"\n");
                }
                out(b"[");
                out_num(j as i64 + 1);
                out(b"] done, status ");
                out_num(job.status as i64);
                out(b"\n");
                job.used = false;
                said = true;
            }
        }
        // A child nobody waits for (a job given up on, or — wave 13 — an
        // orphan of a job, which this shell adopts as a child subreaper):
        // reap it so its notice does not wake every later wait, and say so.
        let mut st = 0i32;
        loop {
            let t = sys::wait_status(&mut st as *mut i32);
            if t <= 0 {
                break;
            }
            if !said {
                out(b"\n");
            }
            out(b"[reaped] tid ");
            out_num(t as i64);
            out(b", status ");
            out_num(st as i64);
            out(b"\n");
            said = true;
        }
        said
    }

    fn run_line(&mut self) {
        let mut status_buf = [0u8; 21];
        let sn = fmt_num(self.status as i64, &mut status_buf);
        let mut line = [0u8; LINE_MAX];
        let ll = self.text_len;
        line[..ll].copy_from_slice(&self.text[..ll]);
        let scope = Scope { env: &self.env, status: &status_buf[..sn] };
        let mut p = Pipeline::new();
        if let Err(e) = parse(&line[..ll], &scope, &mut p) {
            err_line(b"syntax", e.message());
            self.status = 2;
            return;
        }
        if p.n == 0 {
            return;
        }
        self.line = p;
        let name = self.line.arg(0, 0);
        if self.line.n == 1 && !self.line.background && is_builtin(name) {
            self.status = self.builtin_with_redirect();
            return;
        }
        self.status = self.run_pipeline();
    }

    // ── Builtins ────────────────────────────────────────────────────────────

    /// Open a redirection target, or a file `cat` reads, beneath the root
    /// directory: `p` is resolved against the working directory and the open is
    /// `NODE_OPENAT` on that name without its leading `/`. Returns a
    /// `Cap<File>` handle.
    fn open_redirect(&self, p: &[u8], write: bool, append: bool) -> Result<u32, isize> {
        let mut abs = [0u8; path::PATH_MAX + 1];
        let mut tmp = [0u8; path::PATH_MAX];
        let n = self.absolute(p, &mut tmp).ok_or(sys::E_INVAL)?;
        abs[..n].copy_from_slice(&tmp[..n]);
        abs[n] = 0;
        let flags = if write {
            O_WRONLY | O_CREAT | if append { O_APPEND } else { O_TRUNC }
        } else {
            O_RDONLY
        };
        let root = self.root.ok_or(sys::E_BADF)?;
        let h = sys::open_at(root, sys::below_root(&abs[..n + 1]), flags);
        if h < 0 { Err(h) } else { Ok(h as u32) }
    }

    fn builtin_with_redirect(&mut self) -> i32 {
        let c = self.line.cmds[0];
        let mut sink = Sink::Console;
        let mut opened = None;
        if let Redir::File { path, append } = c.stdout {
            let mut pb = [0u8; path::PATH_MAX];
            let w = self.line.word(path);
            pb[..w.len()].copy_from_slice(w);
            match self.open_redirect(&pb[..w.len()], true, append) {
                Ok(h) => {
                    sink = Sink::Handle(h);
                    opened = Some(h);
                }
                Err(e) => {
                    err_line(w, b"cannot open for writing");
                    return if e == -13 { 126 } else { 1 };
                }
            }
        }
        let st = self.builtin(sink);
        if let Some(h) = opened {
            let _ = sys::close_typed(h);
        }
        st
    }

    fn arg(&self, i: usize) -> &[u8] {
        self.line.arg(0, i)
    }

    fn builtin(&mut self, o: Sink) -> i32 {
        let argc = self.line.cmds[0].argc;
        let mut name = [0u8; 16];
        let nl = self.arg(0).len().min(16);
        name[..nl].copy_from_slice(&self.arg(0)[..nl]);
        match &name[..nl] {
            b"help" => {
                o.put(b"builtins: help echo cd pwd exit export unset env jobs wait kill history\n\
                        \x20         true false ls cat mkdir rm uptime type\n\
                        tools (TOOLBOX.ELF): args beep cat echo false host input inspect log ls ntp ps sleep spin true vm wc window yes\n\
                        privileged tools: power flight behavior config ota (own row each)\n\
                        other commands: /fat/<NAME>.ELF (8.3 names), run under their own row\n\
                        syntax: a | b | c, < f, > f, >> f, 2> f, 2>&1, &, 'quotes', \"$VAR\", $?\n");
                0
            }
            b"echo" => {
                for i in 1..argc {
                    if i > 1 {
                        o.put(b" ");
                    }
                    o.put(self.arg(i));
                }
                o.put(b"\n");
                0
            }
            b"true" => 0,
            b"false" => 1,
            b"pwd" => {
                o.put(self.cwd());
                o.put(b"\n");
                0
            }
            b"cd" => {
                let target: &[u8] = if argc > 1 { self.arg(1) } else { b"/" };
                let mut abs = [0u8; path::PATH_MAX];
                let Some(n) = self.absolute(target, &mut abs) else {
                    err_line(target, b"path too long");
                    return 1;
                };
                if n > azos_abi::ushell::SPAWN_CWD_MAX {
                    err_line(target, b"path too long");
                    return 1;
                }
                if !is_dir(&abs[..n]) {
                    err_line(target, b"not a directory");
                    return 1;
                }
                self.cwd[..n].copy_from_slice(&abs[..n]);
                self.cwd_len = n;
                0
            }
            b"exit" => {
                let code = if argc > 1 { parse_num(self.arg(1)).unwrap_or(2) as i32 } else { self.status };
                self.quit(code)
            }
            b"export" => {
                for i in 1..argc {
                    let mut kv = [0u8; 128];
                    let a = self.arg(i);
                    let n = a.len().min(kv.len());
                    kv[..n].copy_from_slice(&a[..n]);
                    let kv = &kv[..n];
                    let ok = match kv.iter().position(|&b| b == b'=') {
                        Some(eq) => self.env.set(&kv[..eq], &kv[eq + 1..]),
                        None => self.env.get(kv).is_some() || self.env.set(kv, b""),
                    };
                    if !ok {
                        err_line(kv, b"environment full or bad name");
                        return 1;
                    }
                }
                0
            }
            b"unset" => {
                for i in 1..argc {
                    let mut k = [0u8; 64];
                    let a = self.arg(i);
                    let n = a.len().min(k.len());
                    k[..n].copy_from_slice(&a[..n]);
                    self.env.unset(&k[..n]);
                }
                0
            }
            b"env" => {
                for kv in self.env.entries() {
                    o.put(kv);
                    o.put(b"\n");
                }
                0
            }
            b"history" => {
                // The terminal keeps it; ask for it oldest first.
                let mut buf = [0u8; LINE_MAX];
                let mut n = 0u32;
                while n < 64 && self.history_line(n, &mut buf).is_some() {
                    n += 1;
                }
                for back in (0..n).rev() {
                    if let Some(l) = self.history_line(back, &mut buf) {
                        o.put(&buf[..l]);
                        o.put(b"\n");
                    }
                }
                0
            }
            b"jobs" => {
                for (j, job) in self.jobs.iter().enumerate() {
                    if job.used {
                        out(b"[");
                        out_num(j as i64 + 1);
                        out(b"] running, tids");
                        for i in 0..job.n {
                            out(b" ");
                            out_num(job.tids[i] as i64);
                        }
                        out(b"\n");
                    }
                }
                0
            }
            b"wait" => {
                let mut st = 0;
                for j in 0..JOBS {
                    if self.jobs[j].used {
                        st = self.wait_job(j);
                        self.jobs[j].used = false;
                    }
                }
                st
            }
            b"kill" => self.kill_builtin(),
            b"uptime" => {
                let ms = sys::vdso_uptime_ms();
                out(b"up ");
                out_num((ms / 1000) as i64);
                out(b".");
                let frac = ms % 1000;
                if frac < 100 {
                    out(b"0");
                }
                if frac < 10 {
                    out(b"0");
                }
                out_num(frac as i64);
                out(b" s\n");
                0
            }
            b"ls" => {
                let target: &[u8] = if argc > 1 { self.arg(1) } else { b"." };
                let mut abs = [0u8; path::PATH_MAX + 1];
                let mut tmp = [0u8; path::PATH_MAX];
                let Some(n) = self.absolute(target, &mut tmp) else { return 1 };
                abs[..n].copy_from_slice(&tmp[..n]);
                abs[n] = 0;
                let mut idx = 0u64;
                loop {
                    let mut nm = [0u8; sys::READDIR_NAME_BYTES];
                    let (mut size, mut isdir) = (0u32, 0u32);
                    if sys::readdir(&abs[..n + 1], idx, &mut nm, &mut size, &mut isdir) != 0 {
                        break;
                    }
                    let l = nm.iter().position(|&b| b == 0).unwrap_or(nm.len());
                    o.put(&nm[..l]);
                    if isdir != 0 {
                        o.put(b"/");
                    }
                    o.put(b"\n");
                    idx += 1;
                }
                if idx == 0 && !is_dir(&abs[..n]) {
                    err_line(target, b"no such directory");
                    return 1;
                }
                0
            }
            b"cat" => {
                let mut st = 0;
                for i in 1..argc {
                    let mut pb = [0u8; path::PATH_MAX];
                    let a = self.arg(i);
                    let al = a.len().min(pb.len());
                    pb[..al].copy_from_slice(&a[..al]);
                    match self.open_redirect(&pb[..al], false, false) {
                        Ok(h) => {
                            let mut b = [0u8; 512];
                            loop {
                                let r = sys::file_read_typed(h, &mut b);
                                if r <= 0 {
                                    break;
                                }
                                o.put(&b[..r as usize]);
                            }
                            let _ = sys::close_typed(h);
                        }
                        Err(_) => {
                            err_line(&pb[..al], b"no such file");
                            st = 1;
                        }
                    }
                }
                st
            }
            b"mkdir" | b"rm" => {
                let mut st = 0;
                for i in 1..argc {
                    let mut abs = [0u8; path::PATH_MAX + 1];
                    let mut tmp = [0u8; path::PATH_MAX];
                    let Some(n) = self.absolute(self.arg(i), &mut tmp) else { return 1 };
                    abs[..n].copy_from_slice(&tmp[..n]);
                    abs[n] = 0;
                    let r = if &name[..nl] == b"mkdir" {
                        sys::mkdir(&abs[..n + 1])
                    } else {
                        sys::unlink(&abs[..n + 1])
                    };
                    if r < 0 {
                        err_line(&abs[..n], if r == -13 { b"permission denied" } else { b"failed" });
                        st = 1;
                    }
                }
                st
            }
            b"type" => {
                for i in 1..argc {
                    let a = self.arg(i);
                    o.put(a);
                    if is_builtin(a) {
                        o.put(b": builtin\n");
                    } else if path::is_applet(a) {
                        o.put(b": TOOLBOX.ELF applet\n");
                    } else {
                        let mut pb = [0u8; path::PATH_MAX];
                        match self.resolve(a, &mut pb) {
                            Ok(n) => {
                                o.put(b": ");
                                o.put(&pb[..n]);
                                o.put(b"\n");
                            }
                            Err(e) => {
                                o.put(b": ");
                                o.put(e.message());
                                o.put(b"\n");
                            }
                        }
                    }
                }
                0
            }
            _ => 127,
        }
    }

    fn kill_builtin(&mut self) -> i32 {
        let argc = self.line.cmds[0].argc;
        let mut force = false;
        let mut first = 1;
        if argc > 1 && (self.arg(1) == b"-9" || self.arg(1) == b"-KILL") {
            force = true;
            first = 2;
        }
        let mut st = 0;
        for i in first..argc {
            let a = self.arg(i);
            if let Some(j) = a.strip_prefix(b"%") {
                match parse_num(j).filter(|&j| j >= 1 && (j as usize) <= JOBS && self.jobs[j as usize - 1].used) {
                    Some(j) => self.jobs[j as usize - 1].stop(force),
                    None => {
                        err_line(a, b"no such job");
                        st = 1;
                    }
                }
                continue;
            }
            match parse_num(a) {
                Some(t) if t > 0 => {
                    let how = if force { sys::KILL_FORCE } else { sys::KILL_REQUEST };
                    let sig = if force { 9 } else { 15 };
                    if sys::task_kill(t as u32, how, sig, sys::KILL_SUBTREE) < 0 {
                        err_line(a, b"no such descendant (only the shell's own children can be stopped)");
                        st = 1;
                    }
                }
                _ => {
                    err_line(a, b"not a TID or %job");
                    st = 1;
                }
            }
        }
        st
    }

    // ── Running programs ───────────────────────────────────────────────────

    fn resolve(&self, name: &[u8], out_path: &mut [u8; path::PATH_MAX]) -> Result<usize, path::PathError> {
        let pv: &[u8] = self.env.get(b"PATH").unwrap_or(path::DEFAULT_PATH);
        let mut pvb = [0u8; 128];
        let pl = pv.len().min(pvb.len());
        pvb[..pl].copy_from_slice(&pv[..pl]);
        let mut exists = |p: &[u8]| is_file(p);
        path::resolve(name, self.cwd(), &pvb[..pl], &mut exists, out_path)
    }

    /// Spawn every stage, connected by pipes; wait for a foreground job.
    fn run_pipeline(&mut self) -> i32 {
        let n = self.line.n;
        let mut tids = [0u32; parse::MAX_STAGES];
        let mut spawned = 0usize;
        // The read end (a pipe token) the next stage takes as fd 0.
        let mut prev_read: Option<u32> = None;
        let mut failure = 0i32;
        for s in 0..n {
            let c = self.line.cmds[s];
            let name = self.line.arg(s, 0);
            // The image and its argv[0].
            let mut image = [0u8; path::PATH_MAX + 1];
            let il;
            if path::is_applet(name) {
                il = path::TOOLBOX.len();
                image[..il].copy_from_slice(path::TOOLBOX);
            } else if is_builtin(name) {
                err_line(name, b"builtin cannot run in a pipeline or in the background");
                failure = 2;
                break;
            } else {
                let mut pb = [0u8; path::PATH_MAX];
                match self.resolve(name, &mut pb) {
                    Ok(len) => {
                        image[..len].copy_from_slice(&pb[..len]);
                        il = len;
                    }
                    Err(e) => {
                        err_line(name, e.message());
                        failure = 127;
                        break;
                    }
                }
            }
            image[il] = 0;

            let mut rb = ReqBuilder::new();
            for i in 0..c.argc {
                if !rb.arg(self.line.arg(s, i)) {
                    err_line(name, b"arguments too long");
                    failure = 2;
                    break;
                }
            }
            if failure != 0 {
                break;
            }
            for kv in self.env.entries() {
                let _ = rb.env(kv);
            }
            rb.cwd(self.cwd());

            // fd 0: the previous stage's pipe, `< f`, or closed.
            let mut opened: [Option<u32>; 3] = [None; 3];
            // The pipe ends this stage is given (shared with it, not moved:
            // the kernel counts them for the child in the spawn, the shell
            // keeps its own and closes them once the child runs) and what fd 1
            // names, for `2>&1`.
            let mut shared_in: Option<u32> = None;
            let mut shared_out: Option<u32> = None;
            let mut stdout_h: Option<u32> = None;
            if let Some(r) = prev_read.take() {
                match sys::pipe::region_of(r) {
                    Ok((cap, _)) => {
                        rb.fd(0, Fd::Handle(cap));
                        shared_in = Some(r);
                    }
                    Err(_) => {
                        err_line(b"pipe", b"cannot share the pipe with the next stage");
                        failure = 1;
                        let _ = sys::pipe::close(r);
                        break;
                    }
                }
            } else if let Some(sp) = c.stdin {
                let mut pb = [0u8; path::PATH_MAX];
                let w = self.line.word(sp);
                pb[..w.len()].copy_from_slice(w);
                match self.open_redirect(&pb[..w.len()], false, false) {
                    Ok(h) => {
                        rb.fd(0, Fd::Handle(h));
                        opened[0] = Some(h);
                    }
                    Err(_) => {
                        err_line(w, b"cannot open for reading");
                        failure = 1;
                        break;
                    }
                }
            }
            // fd 1: the next stage's pipe, `> f`, or the console.
            let mut next_read = None;
            if s + 1 < n {
                let ends = match sys::pipe::create() {
                    Ok(e) => e,
                    Err(_) => {
                        err_line(b"pipe", b"no pipe available");
                        failure = 1;
                        if let Some(h) = opened[0] {
                            let _ = sys::close_typed(h);
                        }
                        if let Some(r) = shared_in {
                            let _ = sys::pipe::close(r);
                        }
                        break;
                    }
                };
                match sys::pipe::region_of(ends[1]) {
                    Ok((cap, _)) => {
                        rb.fd(1, Fd::Handle(cap));
                        stdout_h = Some(cap);
                        shared_out = Some(ends[1]);
                    }
                    Err(_) => {
                        err_line(b"pipe", b"cannot share the pipe with the stage");
                        failure = 1;
                        let _ = sys::pipe::close(ends[0]);
                        let _ = sys::pipe::close(ends[1]);
                        if let Some(h) = opened[0] {
                            let _ = sys::close_typed(h);
                        }
                        if let Some(r) = shared_in {
                            let _ = sys::pipe::close(r);
                        }
                        break;
                    }
                }
                next_read = Some(ends[0]);
            } else if let Redir::File { path: sp, append } = c.stdout {
                let mut pb = [0u8; path::PATH_MAX];
                let w = self.line.word(sp);
                pb[..w.len()].copy_from_slice(w);
                match self.open_redirect(&pb[..w.len()], true, append) {
                    Ok(h) => {
                        rb.fd(1, Fd::Handle(h));
                        opened[1] = Some(h);
                        stdout_h = Some(h);
                    }
                    Err(_) => {
                        err_line(w, b"cannot open for writing");
                        failure = 1;
                        if let Some(h) = opened[0] {
                            let _ = sys::close_typed(h);
                        }
                        if let Some(r) = shared_in {
                            let _ = sys::pipe::close(r);
                        }
                        break;
                    }
                }
            } else {
                rb.fd(1, Fd::Console);
            }
            // fd 2: `2>&1`, `2> f`, or the console.
            match c.stderr {
                Redir::ToStdout => match stdout_h {
                    Some(h) => rb.fd(2, Fd::Handle(h)),
                    None => rb.fd(2, Fd::Console),
                },
                Redir::File { path: sp, append } => {
                    let mut pb = [0u8; path::PATH_MAX];
                    let w = self.line.word(sp);
                    pb[..w.len()].copy_from_slice(w);
                    match self.open_redirect(&pb[..w.len()], true, append) {
                        Ok(h) => {
                            rb.fd(2, Fd::Handle(h));
                            opened[2] = Some(h);
                        }
                        Err(_) => {
                            err_line(w, b"cannot open for writing");
                            rb.fd(2, Fd::Console);
                        }
                    }
                }
                Redir::None => rb.fd(2, Fd::Console),
            }

            // Wave 13: the first stage of a foreground job with no input
            // redirection reads the terminal: the console is lent to it (the
            // kernel does so only for a Linux image) until it exits.
            let console_in = !self.line.background && spawned == 0 && c.stdin.is_none();
            let r = rb.finish(sys::SPAWN_F_DIE_WITH_PARENT | if console_in { sys::SPAWN_F_CONSOLE_IN } else { 0 });
            let tid = sys::spawn_ex(&image[..il + 1], Some(&r));
            if tid <= 0 {
                spawn_error(name, tid);
                failure = match tid {
                    -13 => 126,
                    _ => 127,
                };
                // Nothing moved: the files are still ours, and so are the pipe
                // ends (a refused spawn counted none for the child).
                for h in opened.iter().flatten() {
                    let _ = sys::close_typed(*h);
                }
                for t in [shared_in, shared_out].into_iter().flatten() {
                    let _ = sys::pipe::close(t);
                }
                if let Some(nr) = next_read {
                    let _ = sys::pipe::close(nr);
                }
                break;
            }
            // The child holds its ends; this shell's own are done with (a
            // writer end kept here would hold the next stage's input open).
            for t in [shared_in, shared_out].into_iter().flatten() {
                let _ = sys::pipe::close(t);
            }
            tids[spawned] = tid as u32;
            spawned += 1;
            prev_read = next_read;
        }
        if let Some(r) = prev_read {
            let _ = sys::pipe::close(r);
        }
        let mut job = NO_JOB;
        job.used = true;
        job.n = spawned;
        job.tids = tids;
        if failure != 0 {
            // Stop what did start: its peers are not coming.
            job.stop(true);
            let _ = self.wait_job_inline(&mut job);
            return failure;
        }
        if self.line.background {
            match self.jobs.iter().position(|j| !j.used) {
                Some(j) => {
                    self.jobs[j] = job;
                    out(b"[");
                    out_num(j as i64 + 1);
                    out(b"]");
                    for i in 0..spawned {
                        out(b" ");
                        out_num(tids[i] as i64);
                    }
                    out(b"\n");
                    0
                }
                None => {
                    out(b"sh: job table full; running in the foreground\n");
                    self.wait_job_inline(&mut job)
                }
            }
        } else {
            self.wait_job_inline(&mut job)
        }
    }

    fn wait_job(&mut self, j: usize) -> i32 {
        let mut job = self.jobs[j];
        let st = self.wait_job_inline(&mut job);
        self.jobs[j] = job;
        st
    }

    /// Wait for `job`, with the terminal's focus on it: `^C` arrives as an
    /// `Interrupt` event for the job and asks it to stop, then forces it
    /// after the grace or a second `^C`. Other typing is the terminal's to
    /// hold for the next prompt (type-ahead).
    fn wait_job_inline(&mut self, job: &mut Job) -> i32 {
        let mut asked_at: Option<u64> = None;
        let mut forced = false;
        let mut poll = POLL_MIN_MS;
        // The job's id for the terminal: its first task.
        let _ = self.term.set_foreground(if job.n > 0 { job.tids[0] } else { 1 });
        loop {
            job.reap();
            if job.finished() {
                break;
            }
            let ev = self.next_event(poll);
            match ev.kind {
                Kind::Interrupt => {
                    // The terminal has shown `^C`.
                    if asked_at.is_none() {
                        job.stop(false);
                        asked_at = Some(sys::vdso_uptime_ms());
                    } else if !forced {
                        job.stop(true);
                        forced = true;
                    }
                    poll = POLL_MIN_MS;
                }
                _ => poll = (poll * 2).min(POLL_MAX_MS),
            }
            if let Some(t) = asked_at {
                if !forced && sys::vdso_uptime_ms().saturating_sub(t) >= GRACE_MS {
                    job.stop(true);
                    forced = true;
                }
            }
        }
        let _ = self.term.set_foreground(0);
        job.status
    }
}

fn spawn_error(name: &[u8], rc: isize) {
    let why: &[u8] = match rc {
        -13 => b"not permitted (no profile, no topology row, or no launch grant for this image)",
        -200 => b"a redirection named the wrong kind of handle",
        -201 => b"a redirection asked for rights the shell does not hold",
        -202 => b"a redirection's handle is stale",
        -24 => b"too many handles for the child",
        -22 => b"bad request",
        -12 => b"no room for the arguments",
        _ => b"could not start",
    };
    err_line(name, why);
}

const BUILTINS: &[&[u8]] = &[
    b"help", b"echo", b"cd", b"pwd", b"exit", b"export", b"unset", b"env", b"jobs", b"wait", b"kill",
    b"history", b"true", b"false", b"ls", b"cat", b"mkdir", b"rm", b"uptime", b"type",
];

fn is_builtin(name: &[u8]) -> bool {
    BUILTINS.iter().any(|b| *b == name)
}

fn parse_num(s: &[u8]) -> Option<i64> {
    if s.is_empty() || s.len() > 18 {
        return None;
    }
    let mut v: i64 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as i64;
    }
    Some(v)
}

fn stat_mode(p: &[u8]) -> Option<u32> {
    let mut z = [0u8; path::PATH_MAX + 1];
    let n = p.len().min(path::PATH_MAX);
    z[..n].copy_from_slice(&p[..n]);
    let mut st = [0u8; azos_abi::syscall_nr::STAT_BYTES];
    if sys::stat(&z[..n + 1], &mut st) != 0 {
        return None;
    }
    let o = azos_abi::syscall_nr::STAT_OFF_MODE;
    Some(u32::from_le_bytes([st[o], st[o + 1], st[o + 2], st[o + 3]]))
}

fn is_dir(p: &[u8]) -> bool {
    p == b"/" || stat_mode(p).is_some_and(|m| m & azos_abi::syscall_nr::STAT_S_IFMT == azos_abi::syscall_nr::STAT_S_IFDIR)
}

fn is_file(p: &[u8]) -> bool {
    stat_mode(p).is_some_and(|m| m & azos_abi::syscall_nr::STAT_S_IFMT != azos_abi::syscall_nr::STAT_S_IFDIR)
}

struct ShellCell(core::cell::UnsafeCell<Shell>);
// SAFETY: one thread.
unsafe impl Sync for ShellCell {}

static SHELL: ShellCell = ShellCell(core::cell::UnsafeCell::new(Shell {
    root: None,
    env: Env::new(),
    cwd: [0; path::PATH_MAX],
    cwd_len: 0,
    status: 0,
    jobs: [NO_JOB; JOBS],
    line: Pipeline::new(),
    term: TerminalClient::new(Renewing::new(SysCall, 0, [0; azos_names::NAME_WORDS], 0)),
    text: [0; LINE_MAX],
    text_len: 0,
}));

#[sys::main(panic_exit = 70)]
fn main() -> ! {
    // SAFETY: the one reference, for the life of the program.
    let sh = unsafe { &mut *SHELL.0.get() };
    sh.root = u32::try_from(sys::root_dir()).ok();
    let start = sys::cwd();
    sh.cwd[..start.len()].copy_from_slice(start);
    sh.cwd_len = start.len();
    let _ = sh.env.set(b"PATH", path::DEFAULT_PATH);
    // A session the console login started carries the user's name.
    let user = sys::getenv(b"USER");
    if let Some(u) = user {
        let _ = sh.env.set(b"USER", u);
    }
    // Wave 13: a child subreaper (`DOMAIN_SUBREAPER`), so what a job
    // leaves running when it exits is adopted here and reaped above
    // (`reap_background`), not left with no parent.
    let _ = sys::task_subreaper(sys::SUBREAPER_SET);

    // The terminal: the endpoint the name server lends for `term`, and the
    // server behind it. The name server starts before this shell, but ask
    // again until it answers (it may not have run yet).
    let Some(names) = find_names_endpoint() else {
        out(b"sh: no name service (the row imports nothing)\n");
        sys::exit(1);
    };
    let t0 = sys::vdso_uptime_ms();
    let ep = loop {
        match lookup_terminal(names) {
            Lookup::Lent(ep) => break ep,
            Lookup::Refused => {
                out(b"sh: the name server lends no terminal (is `term` in this row's imports?)\n");
                sys::exit(1);
            }
            Lookup::Unreachable if sys::vdso_uptime_ms().saturating_sub(t0) < CONNECT_MS => sys::sleep(10),
            Lookup::Unreachable => {
                out(b"sh: the name server did not answer\n");
                sys::exit(1);
            }
        }
    };
    let Some(term_name) = azos_names::pack_name(b"term") else { sys::exit(1) };
    sh.term = TerminalClient::new(Renewing::new(SysCall, names, term_name, ep));
    let t0 = sys::vdso_uptime_ms();
    let size = loop {
        match sh.term.size() {
            Ok(v) => break v,
            Err(_) if sys::vdso_uptime_ms().saturating_sub(t0) < CONNECT_MS => sys::sleep(10),
            Err(_) => {
                out(b"sh: the terminal server did not answer\n");
                sys::exit(1);
            }
        }
    };
    let (cols, rows) = unpack_size(size);
    let mut nb = [0u8; 21];
    let n = fmt_num(cols as i64, &mut nb);
    let _ = sh.env.set(b"COLUMNS", &nb[..n]);
    let n = fmt_num(rows as i64, &mut nb);
    let _ = sh.env.set(b"LINES", &nb[..n]);
    // The terminal outlives a shell that died: put it in the state this shell
    // expects (cooked, echoing, the shell in focus) rather than the dead one's.
    let _ = sh.term.set_mode(false);
    let _ = sh.term.set_echo(true);
    let _ = sh.term.set_foreground(0);
    let mut text = [0u8; 32];
    let plen = ident::prompt(user, PROMPT, &mut text);
    let mut prompt = [0u64; PROMPT_WORDS];
    pack_bytes(&text[..plen], &mut prompt);
    let _ = sh.term.set_prompt(plen as u32, prompt);

    out(b"[sh] AzOS user shell; 'help' lists what it runs\n");
    loop {
        if sh.read_line().is_none() {
            sh.quit(0);
        }
        sh.run_line();
    }
}
