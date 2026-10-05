// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SH.ELF`: the AzOS user shell (RFC-0055).
//!
//! A ring-3 program with no hardware authority. It reads raw console bytes
//! with `SYS_CONSOLE_WAIT` (it is the console's one input owner), edits the
//! line itself (`edit.rs`), parses it (`parse.rs`), and runs each command as a
//! child with `SYS_SPAWN_EX` under the child's OWN seccomp profile and
//! topology row: the shell can start only the images its row holds a
//! `Cap<Launch>` for, and lends them nothing but the descriptors and pipe
//! ends it moves to them. `^C` asks the foreground job to stop
//! (`SYS_TASK_KILL`, then force after 300 ms or a second `^C`).
//!
//! Every syscall goes through `sys::name(..)`, so `tests/host/seccomp-tests`
//! derives this image's exact profile from these sources.

#![no_std]
#![no_main]

#[allow(dead_code)]
mod edit;
mod parse;
mod path;
#[allow(dead_code)]
mod req;

use edit::{Editor, Event, History};
use parse::{parse, Pipeline, Redir, Vars};
use req::{Fd, ReqBuilder};
use azos_libsys as sys;

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

// `open` flags (`crates/fs/fs/src/vfs.rs`).
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_CREAT: u64 = 0x40;
const O_TRUNC: u64 = 0x200;
const O_APPEND: u64 = 0x400;

const NS_PER_MS: u64 = 1_000_000;

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
    env: Env,
    cwd: [u8; path::PATH_MAX],
    cwd_len: usize,
    status: i32,
    jobs: [Job; JOBS],
    hist: History,
    ed: Editor,
    line: Pipeline,
    /// Bytes typed while a job ran, replayed at the next prompt.
    ahead: [u8; 256],
    ahead_len: usize,
}

fn flush_editor(ed: &mut Editor) {
    let o = ed.take_output();
    if !o.is_empty() {
        out(o);
    }
}

impl Shell {
    fn cwd(&self) -> &[u8] {
        &self.cwd[..self.cwd_len]
    }

    fn absolute(&self, p: &[u8], buf: &mut [u8; path::PATH_MAX]) -> Option<usize> {
        path::join(self.cwd(), p, buf).ok()
    }

    /// Read one line. `None` at end of input (`^D` on an empty line).
    fn read_line(&mut self) -> Option<()> {
        self.ed.set_prompt(PROMPT);
        self.ed.start();
        flush_editor(&mut self.ed);
        let mut pending = [0u8; 256];
        let np = self.ahead_len;
        pending[..np].copy_from_slice(&self.ahead[..np]);
        self.ahead_len = 0;
        if let Some(r) = self.feed(&pending[..np]) {
            return r;
        }
        loop {
            let mut buf = [0u8; 64];
            let n = sys::console_wait(&mut buf, sys::CONSOLE_WAIT_FOREVER);
            if n == sys::E_INTR {
                if self.reap_background() {
                    self.ed.redraw();
                    flush_editor(&mut self.ed);
                }
                continue;
            }
            if n == -16 {
                out(b"sh: console input belongs to another task\n");
                sys::exit(0);
            }
            if n <= 0 {
                continue;
            }
            if let Some(r) = self.feed(&buf[..n as usize]) {
                return r;
            }
        }
    }

    /// Feed typed bytes to the editor. `Some(Some(()))`: a line is ready;
    /// `Some(None)`: end of input; `None`: keep reading. Bytes after the
    /// line's end are kept for the next prompt.
    fn feed(&mut self, bytes: &[u8]) -> Option<Option<()>> {
        for (i, &b) in bytes.iter().enumerate() {
            let ev = self.ed.feed(b, &self.hist);
            flush_editor(&mut self.ed);
            match ev {
                Event::None => {}
                Event::Line => {
                    let rest = &bytes[i + 1..];
                    let n = rest.len().min(self.ahead.len());
                    self.ahead[..n].copy_from_slice(&rest[..n]);
                    self.ahead_len = n;
                    return Some(Some(()));
                }
                Event::Interrupt => {
                    out(b"^C\n");
                    self.status = 130;
                    self.ed.start();
                    flush_editor(&mut self.ed);
                }
                Event::Eof => {
                    out(b"exit\n");
                    return Some(None);
                }
            }
        }
        None
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
        let mut line = [0u8; edit::LINE_MAX];
        let ll = self.ed.line().len();
        line[..ll].copy_from_slice(self.ed.line());
        self.hist.push(&line[..ll]);
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

    /// Open a redirection target. Returns a `Cap<File>` handle.
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
        let h = sys::open(&abs[..n + 1], flags);
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
                        tools (TOOLBOX.ELF): args cat echo false ls ps sleep spin true wc yes\n\
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
                sys::exit(code)
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
                for i in (0..self.hist.len()).rev() {
                    if let Some(l) = self.hist.get(i) {
                        o.put(l);
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
        // The read end the next stage takes as fd 0.
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
            if let Some(r) = prev_read.take() {
                rb.fd(0, Fd::Handle(r));
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
                let mut ends = [0u32; 2];
                let r = sys::pipe_typed(&mut ends, 0);
                if r < 0 {
                    err_line(b"pipe", b"no pipe available");
                    failure = 1;
                    if let Some(h) = opened[0] {
                        let _ = sys::close_typed(h);
                    }
                    break;
                }
                rb.fd(1, Fd::Handle(ends[1]));
                opened[1] = Some(ends[1]);
                next_read = Some(ends[0]);
            } else if let Redir::File { path: sp, append } = c.stdout {
                let mut pb = [0u8; path::PATH_MAX];
                let w = self.line.word(sp);
                pb[..w.len()].copy_from_slice(w);
                match self.open_redirect(&pb[..w.len()], true, append) {
                    Ok(h) => {
                        rb.fd(1, Fd::Handle(h));
                        opened[1] = Some(h);
                    }
                    Err(_) => {
                        err_line(w, b"cannot open for writing");
                        failure = 1;
                        if let Some(h) = opened[0] {
                            let _ = sys::close_typed(h);
                        }
                        break;
                    }
                }
            } else {
                rb.fd(1, Fd::Console);
            }
            // fd 2: `2>&1`, `2> f`, or the console.
            match c.stderr {
                Redir::ToStdout => match opened[1] {
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
                // Nothing moved: the handles are still ours.
                for h in opened.iter().flatten() {
                    let _ = sys::close_typed(*h);
                }
                if let Some(nr) = next_read {
                    let _ = sys::close_typed(nr);
                }
                break;
            }
            tids[spawned] = tid as u32;
            spawned += 1;
            prev_read = next_read;
        }
        if let Some(r) = prev_read {
            let _ = sys::close_typed(r);
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

    /// Wait for `job`, reading the console meanwhile: `^C` asks it to stop,
    /// then forces it after the grace or a second `^C`; other bytes are kept
    /// for the next prompt.
    fn wait_job_inline(&mut self, job: &mut Job) -> i32 {
        let mut asked_at: Option<u64> = None;
        let mut forced = false;
        loop {
            job.reap();
            if job.finished() {
                break;
            }
            let timeout = match asked_at {
                Some(_) if !forced => GRACE_MS * NS_PER_MS / 3,
                _ => sys::CONSOLE_WAIT_FOREVER,
            };
            let mut buf = [0u8; 64];
            let n = sys::console_wait(&mut buf, timeout);
            if n > 0 {
                for &b in &buf[..n as usize] {
                    if b == 0x03 {
                        out(b"^C\n");
                        if asked_at.is_none() {
                            job.stop(false);
                            asked_at = Some(sys::vdso_uptime_ms());
                        } else if !forced {
                            job.stop(true);
                            forced = true;
                        }
                    } else if self.ahead_len < self.ahead.len() {
                        self.ahead[self.ahead_len] = b;
                        self.ahead_len += 1;
                    }
                }
            }
            if let Some(t) = asked_at {
                if !forced && sys::vdso_uptime_ms().saturating_sub(t) >= GRACE_MS {
                    job.stop(true);
                    forced = true;
                }
            }
        }
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
    env: Env::new(),
    cwd: [0; path::PATH_MAX],
    cwd_len: 0,
    status: 0,
    jobs: [NO_JOB; JOBS],
    hist: History::new(),
    ed: Editor::new(),
    line: Pipeline::new(),
    ahead: [0; 256],
    ahead_len: 0,
}));

#[no_mangle]
pub extern "C" fn _start(_a0: usize, a1: usize) -> ! {
    sys::startup_init(a1);
    // SAFETY: the one reference, for the life of the program.
    let sh = unsafe { &mut *SHELL.0.get() };
    let start = sys::cwd();
    sh.cwd[..start.len()].copy_from_slice(start);
    sh.cwd_len = start.len();
    let _ = sh.env.set(b"PATH", path::DEFAULT_PATH);
    let _ = sh.env.set(b"COLUMNS", b"80");
    let _ = sh.env.set(b"LINES", b"24");
    // Wave 13: a child subreaper (`SYS_TASK_SUBREAPER`), so what a job
    // leaves running when it exits is adopted here and reaped above
    // (`reap_background`), not left with no parent.
    let _ = sys::task_subreaper(sys::SUBREAPER_SET);
        out(b"[sh] AzOS user shell (RFC-0055); 'help' lists what it runs\n");
    loop {
        if sh.read_line().is_none() {
            sys::exit(0);
        }
        sh.run_line();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(70);
}
