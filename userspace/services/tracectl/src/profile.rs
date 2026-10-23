// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `tracectl profile`: the sampling profiler's reader (Kconfig `PROFILER`).
//!
//! ```text
//! tracectl profile [-t MS] [-p MS] [-k KERNEL_ELF] [-u USER_ELF]
//!                  [-o FOLDED_FILE] [-j PERFETTO_FILE]
//! ```
//!
//! Switches the `prof` class on, drains every CPU's ring for MS milliseconds
//! (default 3000, polling every -p MS, default 2), puts the mask back, and
//! writes
//!
//! * the **folded stacks** (one line per distinct stack,
//!   `mode:tidN;outermost;...;innermost COUNT`, the input of
//!   `flamegraph.pl` / `inferno`) to FOLDED_FILE, or to the console without -o;
//! * with -j, a **Perfetto trace** (Chrome trace-event JSON, loads in
//!   `ui.perfetto.dev`): one track per CPU, each sample a stack of nested
//!   slices, in time.
//!
//! The kernel records addresses, not names; the names come from here, after
//! the run, out of the symbol tables of the ELF files given: -k for kernel
//! frames, -u for user frames (one user program: its frames are its own
//! addresses; other programs' frames print as hex). An address no symbol
//! covers, or every address without the files, prints as `0xADDR`, which
//! `addr2line -f -e FILE` resolves on the host. A file without a symbol
//! table (stripped) is reported and treated as absent.
//!
//! The summary counts the samples by origin: `tick` (the scheduler tick),
//! `pmu` (the PMU sampling counter's overflow, Kconfig `PROFILER_PMU`) and
//! `rt` (a real-time CPU's tick: its PMU sampling refused, the PC only).
//!
//! Exit 0 on success, 1 when the kernel refused or the profiler is compiled
//! out, 2 on a usage error.

use super::*;

#[allow(dead_code)]
#[path = "../../../../crates/core/trace/src/prof.rs"]
mod prof;

use prof::{Assembler, ElfError, Names, Origin, ReadAt, Resolver, SampleLog, StackTable, Stop, MAX_DEPTH};

/// Distinct stacks kept, and samples logged for the Perfetto export.
const MAX_STACKS: usize = 128;
const MAX_LOGGED: usize = 1024;
/// Distinct addresses named, and bytes of names, per ELF file.
const MAX_ADDRS: usize = 256;
const NAME_BYTES: usize = 16 * 1024;

type Table = StackTable<MAX_STACKS, MAX_DEPTH>;
type Log = SampleLog<MAX_LOGGED>;
type Syms = Resolver<MAX_ADDRS, NAME_BYTES>;

/// Everything a run accumulates, in `.bss`: it does not fit the stack.
struct State {
    table: Table,
    log: Log,
    asm: [Assembler; MAX_RINGS],
    kernel: Syms,
    user: Syms,
    /// The ELF being read: its 4 KiB window would not fit the stack.
    file: FileAt,
}

struct Shared(core::cell::UnsafeCell<State>);
// SAFETY: this program is single-threaded.
unsafe impl Sync for Shared {}
static STATE: Shared = Shared(core::cell::UnsafeCell::new(State {
    table: Table::new(),
    log: Log::new(),
    asm: [const { Assembler::new() }; MAX_RINGS],
    kernel: Syms::new(),
    user: Syms::new(),
    file: FileAt::new(),
}));

/// [`Out`] as the profiler library's sink.
struct OutSink<'a>(&'a mut Out);

impl prof::Sink for OutSink<'_> {
    fn put(&mut self, b: &[u8]) {
        self.0.s(b);
    }
}

// ── Reading an ELF file ─────────────────────────────────────────────────────

const WINDOW: usize = 4096;

/// A file read at arbitrary offsets over a forward-only capability: a
/// 4 KiB window, refilled by skipping forward, or by opening the file again
/// when the offset is behind it. The symbol table is read in order, so the
/// reopen happens a few times, not per read.
struct FileAt {
    /// The directory `path` is opened beneath (a `Cap<Dir>`).
    dir: u32,
    /// NUL-terminated, without a leading `/`.
    path: [u8; 64],
    cap: Option<u32>,
    /// The file offset the next read of `cap` starts at.
    pos: u64,
    win: [u8; WINDOW],
    win_off: u64,
    win_len: usize,
}

impl FileAt {
    const fn new() -> FileAt {
        FileAt { dir: 0, path: [0; 64], cap: None, pos: 0, win: [0; WINDOW], win_off: 0, win_len: 0 }
    }

    /// Open `path` (not NUL-terminated; a leading `/` names the same file as
    /// none) beneath `dir`; whether it opened.
    fn open(&mut self, dir: u32, path: &[u8]) -> bool {
        let path = sys::below_root(path);
        if path.len() >= 64 {
            return false;
        }
        self.dir = dir;
        self.path = [0; 64];
        self.path[..path.len()].copy_from_slice(path);
        self.reopen()
    }

    fn close(&mut self) {
        if let Some(c) = self.cap.take() {
            let _ = sys::close_typed(c);
        }
    }

    fn reopen(&mut self) -> bool {
        if let Some(c) = self.cap.take() {
            let _ = sys::close_typed(c);
        }
        let n = self.path.iter().position(|&b| b == 0).unwrap_or(0);
        let c = sys::open_at(self.dir, &self.path[..n + 1], 0);
        if c < 0 {
            return false;
        }
        self.cap = Some(c as u32);
        self.pos = 0;
        self.win_len = 0;
        true
    }

    /// Fill the window with the file's bytes at `want` (4 KiB aligned);
    /// whether any were there.
    fn fill(&mut self, want: u64) -> bool {
        if want < self.pos && !self.reopen() {
            return false;
        }
        let Some(cap) = self.cap else { return false };
        while self.pos < want {
            let n = ((want - self.pos) as usize).min(WINDOW);
            let r = sys::file_read_typed(cap, &mut self.win[..n]);
            if r <= 0 {
                return false;
            }
            self.pos += r as u64;
        }
        let mut len = 0;
        while len < WINDOW {
            let r = sys::file_read_typed(cap, &mut self.win[len..]);
            if r <= 0 {
                break;
            }
            len += r as usize;
        }
        self.pos += len as u64;
        self.win_off = want;
        self.win_len = len;
        len != 0
    }
}

impl ReadAt for FileAt {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> usize {
        let mut done = 0;
        while done < buf.len() {
            let at = off + done as u64;
            if !(at >= self.win_off && at < self.win_off + self.win_len as u64) {
                if !self.fill(at & !(WINDOW as u64 - 1)) || !(at >= self.win_off && at < self.win_off + self.win_len as u64) {
                    break;
                }
            }
            let k = (at - self.win_off) as usize;
            let n = (buf.len() - done).min(self.win_len - k);
            buf[done..done + n].copy_from_slice(&self.win[k..k + n]);
            done += n;
        }
        done
    }
}

// ── Arguments ───────────────────────────────────────────────────────────────

struct Opts {
    ms: u64,
    poll_ms: u64,
    kernel: Option<&'static [u8]>,
    user: Option<&'static [u8]>,
    folded: Option<&'static [u8]>,
    perfetto: Option<&'static [u8]>,
}

fn parse_opts() -> Option<Opts> {
    let mut o = Opts { ms: 3000, poll_ms: 2, kernel: None, user: None, folded: None, perfetto: None };
    let mut i = 2;
    while let Some(a) = sys::arg(i) {
        let v = sys::arg(i + 1)?;
        match a {
            b"-t" => o.ms = parse_dec(v).filter(|&n| n > 0)?,
            b"-p" => o.poll_ms = parse_dec(v).filter(|&n| n > 0 && n <= 1000)?,
            b"-k" => o.kernel = Some(v),
            b"-u" => o.user = Some(v),
            b"-o" => o.folded = Some(v),
            b"-j" => o.perfetto = Some(v),
            _ => return None,
        }
        i += 2;
    }
    Some(o)
}

fn profile_usage() -> i32 {
    put(
        2,
        b"usage: tracectl profile [-t MS] [-p MS] [-k KERNEL_ELF] [-u USER_ELF] [-o FOLDED_FILE] [-j PERFETTO_FILE]\n",
    );
    2
}

/// Create (or truncate) `path` beneath `root` for writing; a capability.
fn create(root: u32, path: &[u8]) -> Result<u32, i32> {
    if path.len() >= 64 {
        return Err(profile_usage());
    }
    let f = open_beneath(root, path, O_WRONLY | O_CREAT | O_TRUNC);
    if f < 0 {
        return Err(err_rc(b"open", f));
    }
    Ok(f as u32)
}

fn close_out(out: &mut Out) {
    out.flush();
    if let Some(f) = out.file.take() {
        let _ = sys::fsync_typed(f);
        let _ = sys::close_typed(f);
    }
}

// ── The run ─────────────────────────────────────────────────────────────────

fn ns_of(ts: u64, hz: u64) -> u64 {
    if hz != 0 { (ts as u128 * 1_000_000_000 / hz as u128) as u64 } else { ts }
}

/// How reading a symbol file went.
enum Outcome {
    CannotOpen,
    Failed(ElfError),
    Named(usize),
}

/// Load `path`'s symbols into `r` through `f`.
fn load_symbols(r: &mut Syms, f: &mut FileAt, root: u32, path: &[u8]) -> Outcome {
    if !f.open(root, path) {
        return Outcome::CannotOpen;
    }
    let res = r.load(f);
    f.close();
    match res {
        Ok(n) => Outcome::Named(n),
        Err(e) => Outcome::Failed(e),
    }
}

/// One console line on how a symbol file went (its own frame, so its buffer
/// is not on the stack while the symbols are read).
#[inline(never)]
fn say_symbols(what: &[u8], path: &[u8], res: &Outcome, asked: usize, refused: u64) {
    let mut o = Out { buf: [0; 2048], len: 0, file: None, quiet: false };
    o.s(b"tracectl: symbols ");
    o.s(what);
    o.s(b" ");
    o.s(path);
    match res {
        Outcome::CannotOpen => o.s(b": cannot open it"),
        Outcome::Failed(ElfError::NotElf) => o.s(b": not a 64-bit little-endian ELF file"),
        Outcome::Failed(ElfError::Truncated) => o.s(b": the file is truncated"),
        Outcome::Failed(ElfError::NoSymtab) => o.s(b": no symbol table (stripped?)"),
        Outcome::Named(n) => {
            o.s(b": named ");
            o.dec(*n as u64);
            o.s(b" of ");
            o.dec(asked as u64);
            o.s(b" addresses");
            if refused != 0 {
                o.s(b" (");
                o.dec(refused);
                o.s(b" refused for room)");
            }
        }
    }
    o.s(b"\n");
    o.flush();
}

/// What the drain saw, for the summary.
struct Run {
    ncpu: usize,
    records: u64,
    lost: u64,
    drops: u64,
    elapsed_ms: u64,
    stops: [u64; 8],
    /// Samples by [`Origin`]: tick, pmu, rt.
    origins: [u64; 3],
}

pub(crate) fn run() -> i32 {
    let Some(opts) = parse_opts() else { return profile_usage() };
    // The directory every file below is opened beneath.
    let root = match root_dir() {
        Ok(r) => r,
        Err(code) => return code,
    };
    // The output files are opened before the mask is touched, so a refusal
    // leaves nothing switched on.
    let (mut folded, mut perfetto) = (None, None);
    if let Some(p) = opts.folded {
        match create(root, p) {
            Ok(f) => folded = Some(f),
            Err(code) => return code,
        }
    }
    if let Some(p) = opts.perfetto {
        match create(root, p) {
            Ok(f) => perfetto = Some(f),
            Err(code) => {
                if let Some(f) = folded {
                    let _ = sys::close_typed(f);
                }
                return code;
            }
        }
    }
    // SAFETY: the one reference to the static state, in a single-threaded program.
    let st = unsafe { &mut *STATE.0.get() };
    let r = match drain(&opts, st, perfetto.is_some()) {
        Ok(r) => r,
        Err(code) => {
            for f in [folded, perfetto].into_iter().flatten() {
                let _ = sys::close_typed(f);
            }
            return code;
        }
    };
    report(&opts, st, root, folded, perfetto, &r);
    0
}

/// Switch the class on, drain every ring for the run's time, put the mask back.
#[inline(never)]
fn drain(opts: &Opts, st: &mut State, log_wanted: bool) -> Result<Run, i32> {
    let c = cap();
    let compiled = ctl(c, sys::invoke_abi::LOG_TRACE_INFO, 0);
    if compiled < 0 {
        return Err(err_rc(b"info", compiled));
    }
    if compiled as u32 & (1 << TRACE_CLASS_PROF) == 0 {
        err(b"the profiler is compiled out (Kconfig PROFILER)");
        return Err(1);
    }
    let (base, g) = map(c)?;
    let ncpu = (g.ncpu as usize).min(MAX_RINGS);
    let mut cons = [None::<TraceConsumer>; MAX_RINGS];
    let mut drops0 = [0u32; MAX_RINGS];
    // What an earlier session left is not this run's.
    for cpu in 0..ncpu {
        let mut k = TraceConsumer::new(base, &g, cpu as u32);
        while let Pop::Rec(_) | Pop::Lost(_) = k.pop() {}
        k.release();
        drops0[cpu] = k.drops();
        cons[cpu] = Some(k);
    }
    let prev = ctl(c, sys::invoke_abi::LOG_TRACE_SET_MASK, 1 << TRACE_CLASS_PROF);
    if prev < 0 {
        return Err(err_rc(b"start", prev));
    }
    {
        let mut hello = Out { buf: [0; 2048], len: 0, file: None, quiet: false };
        hello.s(b"tracectl: profile");
        hello.kx(b"mask", TraceGeometry::mask(base) as u64);
        hello.kv(b"cpus", ncpu as u64);
        hello.kv(b"ms", opts.ms);
        hello.s(b"\n");
        hello.flush();
    }
    let t0 = sys::vdso_now_ns();
    let deadline = t0 + opts.ms * 1_000_000;
    let (mut records, mut lost) = (0u64, 0u64);
    let mut stops = [0u64; 8];
    let mut origins = [0u64; 3];
    loop {
        let mut any = false;
        for cpu in 0..ncpu {
            let k = cons[cpu].as_mut().unwrap();
            loop {
                match k.pop() {
                    Pop::Rec(r) => {
                        any = true;
                        records += 1;
                        if let Some(s) = st.asm[cpu].feed(r.ts, r.event, r.args) {
                            origins[s.origin as usize] += 1;
                            // A real-time CPU's PC-only sample walked nothing.
                            if s.origin != Origin::RtTick {
                                stops[s.stop as usize] += 1;
                            }
                            if let Some(i) = st.table.add(s.tid, s.user, s.frames()) {
                                if log_wanted {
                                    st.log.push(ns_of(s.ts, g.ts_hz), cpu as u16, i);
                                }
                            }
                        }
                    }
                    Pop::Lost(l) => lost += l as u64,
                    Pop::Empty => break,
                }
            }
            k.release();
        }
        if sys::vdso_now_ns() >= deadline {
            break;
        }
        if !any {
            sys::sleep(opts.poll_ms);
        }
    }
    let elapsed_ms = (sys::vdso_now_ns() - t0) / 1_000_000;
    ctl(c, sys::invoke_abi::LOG_TRACE_SET_MASK, prev as u64);
    let mut drops = 0u64;
    for cpu in 0..ncpu {
        drops += cons[cpu].as_ref().unwrap().drops().wrapping_sub(drops0[cpu]) as u64;
    }
    Ok(Run { ncpu, records, lost, drops, elapsed_ms, stops, origins })
}

/// Name the addresses, write the outputs and the summary.
#[inline(never)]
fn report(opts: &Opts, st: &mut State, root: u32, folded: Option<u32>, perfetto: Option<u32>, r: &Run) {
    for s in st.table.stacks() {
        for &f in s.frames() {
            if s.user { st.user.add(f) } else { st.kernel.add(f) }
        }
    }
    for (path, what, user) in [(opts.kernel, &b"kernel"[..], false), (opts.user, &b"user"[..], true)] {
        let Some(path) = path else { continue };
        let syms = if user { &mut st.user } else { &mut st.kernel };
        let asked = syms.len();
        let res = load_symbols(syms, &mut st.file, root, path);
        say_symbols(what, path, &res, asked, syms.overflow);
    }
    let names = Names { kernel: &st.kernel, user: &st.user };

    let mut out = Out { buf: [0; 2048], len: 0, file: folded, quiet: false };
    prof::write_folded(&st.table, &names, &mut OutSink(&mut out));
    close_out(&mut out);
    if let Some(f) = perfetto {
        out.file = Some(f);
        prof::write_perfetto(&st.table, &st.log, &names, &mut OutSink(&mut out));
        close_out(&mut out);
    }

    let torn: u64 = st.asm[..r.ncpu].iter().map(|a| a.torn).sum();
    let samples: u64 = st.asm[..r.ncpu].iter().map(|a| a.samples).sum();
    let mut s = Out { buf: [0; 2048], len: 0, file: None, quiet: false };
    s.s(b"tracectl: profile read ");
    s.dec(samples);
    s.s(b" samples (");
    s.dec(r.records);
    s.s(b" records) from ");
    s.dec(r.ncpu as u64);
    s.s(b" cpus in ");
    s.dec(r.elapsed_ms);
    s.s(b" ms,");
    s.kv(b"stacks", st.table.stacks().len() as u64);
    s.kv(b"stacks_lost", st.table.lost);
    s.kv(b"log_dropped", st.log.dropped);
    s.kv(b"torn", torn);
    s.kv(b"drops", r.drops);
    s.kv(b"lost", r.lost);
    s.s(b"\ntracectl: profile origins:");
    s.kv(b"tick", r.origins[Origin::Tick as usize]);
    s.kv(b"pmu", r.origins[Origin::Pmu as usize]);
    s.kv(b"rt", r.origins[Origin::RtTick as usize]);
    s.s(b"\ntracectl: profile walks ended:");
    for (i, n) in r.stops.iter().enumerate() {
        if *n != 0 {
            s.s(b" ");
            s.s(Stop::from_bits(i as u32).name().as_bytes());
            s.s(b"=");
            s.dec(*n);
        }
    }
    s.s(b"\n");
    s.flush();
}
