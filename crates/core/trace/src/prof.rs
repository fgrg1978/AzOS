// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sampling profiler's pure core (Kconfig `PROFILER`, trace class
//! `prof`): the stack walker, the sample record format, the aggregation and
//! the offline symbolization and output.
//!
//! Three programs share this file, which is why it touches nothing but
//! `core` and the event ids of `azos_abi::trace`:
//!
//! * the kernel (`kernel/src/prof.rs`) walks the interrupted stack in the
//!   scheduler tick, or in the PMU sampling counter's overflow interrupt
//!   ([`walk`]), and writes the sample into the CPU's trace ring
//!   ([`encode`]), marked with its [`Origin`];
//! * `tracectl profile` reads the rings back ([`Assembler`]), aggregates
//!   ([`StackTable`], [`SampleLog`]), symbolizes from ELF files ([`Resolver`])
//!   and writes folded stacks ([`write_folded`]) and a Perfetto trace
//!   ([`write_perfetto`]) through a [`Sink`]; it includes this file by path;
//! * the host test suite (`tests/host/trace-tests`) includes it the same way
//!   and runs the walker on synthetic stacks.
//!
//! # The walk
//!
//! Every ISA saves a frame pointer and a return address per call when the
//! code is built with `-C force-frame-pointers=yes` (the profiler's build
//! sets it for the kernel and the user images). Where the pair lives
//! relative to the frame pointer is the whole of an ISA's difference
//! ([`Layout`]). The first frame is the interrupted PC; each link after it
//! is a return address. A link is believed only when
//!
//! * the frame pointer is non-zero and aligned for the ISA,
//! * both words of its record lie inside the stack the sample came from
//!   (`lo..hi`: the interrupted stack pointer up to the stack's top),
//! * it is above the previous frame's (stacks grow down, so a chain that
//!   does not climb is a loop or a stale register),
//! * the memory read succeeds (a user stack page that is not mapped does
//!   not fault the kernel: the reader is the caller's), and
//! * the return address points into code (the caller's predicate).
//!
//! The first check that fails ends the walk and the sample says which
//! ([`Stop`]): a half-truthful stack is better than none, a lying one is
//! worse than either. A function interrupted before its prologue has set
//! the frame pointer up (or after the epilogue took it down) skips its
//! caller: the cost of walking frame pointers rather than unwinding tables.

use azos_abi::trace::{TRACE_EV_PROF_FRAMES, TRACE_EV_PROF_SAMPLE};

// ── The walker ──────────────────────────────────────────────────────────────

/// Where an ISA keeps the caller's frame pointer and the return address, as
/// byte offsets from the frame pointer, and the alignment a frame pointer
/// has there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// The return address (to the caller).
    pub ra_off: i64,
    /// The caller's frame pointer.
    pub fp_off: i64,
    /// Frame pointers are multiples of this.
    pub align: u64,
}

/// riscv64: `fp` is the canonical frame address (the stack pointer at
/// entry); the return address is saved at `fp - 8`, the caller's `fp` at
/// `fp - 16`.
pub const RISCV64: Layout = Layout { ra_off: -8, fp_off: -16, align: 16 };
/// aarch64: `x29` points at the record `[caller x29, x30]`.
pub const AARCH64: Layout = Layout { ra_off: 8, fp_off: 0, align: 16 };
/// x86_64: `rbp` points at the record `[caller rbp, return address]`. Kernel
/// assembly stubs keep 8-byte alignment, so no more is asked.
pub const X86_64: Layout = Layout { ra_off: 8, fp_off: 0, align: 8 };

/// Why a walk ended. The values are the record format's (3 bits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Stop {
    /// The chain reached its end: a zero frame pointer or return address.
    End = 0,
    /// The frame limit was reached.
    Depth = 1,
    /// A frame pointer was not aligned.
    Misaligned = 2,
    /// A frame record lies outside the stack.
    Bounds = 3,
    /// A frame pointer did not climb: a loop, or a stale register.
    NotAscending = 4,
    /// A return address does not point into code.
    BadReturn = 5,
    /// A memory read failed (an unmapped user page).
    ReadFault = 6,
    /// There was no stack to walk (the interrupted stack pointer is not on
    /// a stack the kernel knows): only the PC is recorded.
    NoStack = 7,
}

impl Stop {
    /// From the 3 bits of a record's `meta`.
    pub const fn from_bits(b: u32) -> Stop {
        match b & 7 {
            0 => Stop::End,
            1 => Stop::Depth,
            2 => Stop::Misaligned,
            3 => Stop::Bounds,
            4 => Stop::NotAscending,
            5 => Stop::BadReturn,
            6 => Stop::ReadFault,
            _ => Stop::NoStack,
        }
    }

    /// The reason as `tracectl` prints it.
    pub const fn name(self) -> &'static str {
        match self {
            Stop::End => "end",
            Stop::Depth => "depth",
            Stop::Misaligned => "misaligned",
            Stop::Bounds => "bounds",
            Stop::NotAscending => "not-ascending",
            Stop::BadReturn => "bad-return",
            Stop::ReadFault => "read-fault",
            Stop::NoStack => "no-stack",
        }
    }
}

/// What a walk produced: `out[..depth]` are the frames (the PC first), and
/// `stop` is why there are no more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Walk {
    pub depth: usize,
    pub stop: Stop,
}

/// Walk the frame-pointer chain starting at `pc` / `fp`.
///
/// `lo..hi` bound the stack the sample was taken on (the interrupted stack
/// pointer to the stack's top): a frame record must lie wholly inside.
/// `ret_ok` says whether a return address points into code. `read` loads
/// the 8-byte word at an address, or `None` when it cannot (it is only
/// called for addresses inside `lo..hi`). `out[0]` is always `pc`.
pub fn walk(
    layout: &Layout,
    pc: u64,
    fp: u64,
    lo: u64,
    hi: u64,
    ret_ok: impl Fn(u64) -> bool,
    mut read: impl FnMut(u64) -> Option<u64>,
    out: &mut [u64],
) -> Walk {
    if out.is_empty() {
        return Walk { depth: 0, stop: Stop::Depth };
    }
    out[0] = pc;
    let mut n = 1;
    let mut cur = fp;
    let mut prev: Option<u64> = None;
    // A word at `a` lies inside the stack.
    let inside = |a: u64| a >= lo && a.checked_add(8).is_some_and(|e| e <= hi);
    loop {
        if n == out.len() {
            return Walk { depth: n, stop: Stop::Depth };
        }
        if cur == 0 {
            return Walk { depth: n, stop: Stop::End };
        }
        if cur % layout.align != 0 {
            return Walk { depth: n, stop: Stop::Misaligned };
        }
        if prev.is_some_and(|p| cur <= p) {
            return Walk { depth: n, stop: Stop::NotAscending };
        }
        let ra_at = cur.wrapping_add_signed(layout.ra_off);
        let fp_at = cur.wrapping_add_signed(layout.fp_off);
        if !inside(ra_at) || !inside(fp_at) {
            return Walk { depth: n, stop: Stop::Bounds };
        }
        let (Some(ra), Some(next)) = (read(ra_at), read(fp_at)) else {
            return Walk { depth: n, stop: Stop::ReadFault };
        };
        if ra == 0 {
            return Walk { depth: n, stop: Stop::End };
        }
        if !ret_ok(ra) {
            return Walk { depth: n, stop: Stop::BadReturn };
        }
        out[n] = ra;
        n += 1;
        prev = Some(cur);
        cur = next;
    }
}

// ── The record format ───────────────────────────────────────────────────────

/// Frames a sample can carry (the PC included): Kconfig `PROFILER_DEPTH`'s
/// ceiling.
pub const MAX_DEPTH: usize = 32;

/// What took a sample. The values are the record format's (2 bits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Origin {
    /// The scheduler tick (every `PROFILER_TICK_DIV`-th).
    Tick = 0,
    /// The overflow of the CPU's PMU sampling counter (Kconfig
    /// `PROFILER_PMU`).
    Pmu = 1,
    /// The tick of a real-time CPU, whose PMU sampling is refused: the
    /// interrupted PC only, no walk.
    RtTick = 2,
}

impl Origin {
    /// From the 2 bits of a record's `meta`; `None` for the unused value.
    pub const fn from_bits(b: u32) -> Option<Origin> {
        match b & 3 {
            0 => Some(Origin::Tick),
            1 => Some(Origin::Pmu),
            2 => Some(Origin::RtTick),
            _ => None,
        }
    }
}

/// `meta` of a sample header: frames (bits 0..=7), user mode (bit 8), the
/// stop reason (bits 9..=11), the origin (bits 12..=13).
pub const fn meta(depth: usize, user: bool, stop: Stop, origin: Origin) -> u32 {
    (depth as u32 & 0xff) | (user as u32) << 8 | (stop as u32) << 9 | (origin as u32) << 12
}

/// Records after the header for a sample of `depth` frames (two frames a
/// record; the PC rides in the header).
pub const fn frame_records(depth: usize) -> usize {
    depth.saturating_sub(1).div_ceil(2)
}

/// Turn a walk into trace records: the header, then the frames two a
/// record. `emit` gets `(event, args)` in ring order.
pub fn encode(tid: u32, user: bool, origin: Origin, w: Walk, frames: &[u64], mut emit: impl FnMut(u16, [u32; 4])) {
    let depth = w.depth.min(frames.len()).min(MAX_DEPTH);
    if depth == 0 {
        return;
    }
    emit(TRACE_EV_PROF_SAMPLE, [tid, meta(depth, user, w.stop, origin), frames[0] as u32, (frames[0] >> 32) as u32]);
    for pair in frames[1..depth].chunks(2) {
        let b = pair.get(1).copied().unwrap_or(0);
        emit(TRACE_EV_PROF_FRAMES, [pair[0] as u32, (pair[0] >> 32) as u32, b as u32, (b >> 32) as u32]);
    }
}

/// One sample, reassembled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    /// The time of the header record (the ring's timestamp unit).
    pub ts: u64,
    pub tid: u32,
    pub user: bool,
    pub stop: Stop,
    pub origin: Origin,
    pub depth: usize,
    pub frames: [u64; MAX_DEPTH],
}

impl Sample {
    /// The frames, innermost first.
    pub fn frames(&self) -> &[u64] {
        &self.frames[..self.depth]
    }
}

/// Reassembles one ring's samples from its records, in ring order. One per
/// CPU: the kernel writes a sample's records back to back from one
/// interrupt, so within a ring they never interleave. A sample whose head
/// the ring overwrote, or whose tail has not been written yet, is counted
/// ([`Assembler::torn`]) and never reported.
pub struct Assembler {
    cur: Sample,
    /// Frame records still to come for `cur`; 0 when none is open.
    missing: usize,
    got: usize,
    /// Torn samples and orphan frame records seen.
    pub torn: u64,
    /// Samples completed.
    pub samples: u64,
}

impl Assembler {
    pub const fn new() -> Assembler {
        Assembler {
            cur: Sample { ts: 0, tid: 0, user: false, stop: Stop::End, origin: Origin::Tick, depth: 0, frames: [0; MAX_DEPTH] },
            missing: 0,
            got: 0,
            torn: 0,
            samples: 0,
        }
    }

    /// Feed one record. Returns the sample it completed, if any; events of
    /// other classes are ignored.
    pub fn feed(&mut self, ts: u64, event: u16, a: [u32; 4]) -> Option<&Sample> {
        match event {
            TRACE_EV_PROF_SAMPLE => {
                if self.missing != 0 {
                    self.torn += 1;
                    self.missing = 0;
                }
                let depth = (a[1] & 0xff) as usize;
                let origin = Origin::from_bits(a[1] >> 12);
                let Some(origin) = origin.filter(|_| depth != 0 && depth <= MAX_DEPTH) else {
                    self.torn += 1;
                    return None;
                };
                self.cur.ts = ts;
                self.cur.tid = a[0];
                self.cur.user = a[1] >> 8 & 1 != 0;
                self.cur.stop = Stop::from_bits(a[1] >> 9);
                self.cur.origin = origin;
                self.cur.depth = depth;
                self.cur.frames[0] = a[2] as u64 | (a[3] as u64) << 32;
                self.got = 1;
                self.missing = frame_records(depth);
                if self.missing == 0 {
                    self.samples += 1;
                    return Some(&self.cur);
                }
                None
            }
            TRACE_EV_PROF_FRAMES => {
                if self.missing == 0 {
                    self.torn += 1;
                    return None;
                }
                for k in 0..2 {
                    if self.got < self.cur.depth {
                        self.cur.frames[self.got] = a[2 * k] as u64 | (a[2 * k + 1] as u64) << 32;
                        self.got += 1;
                    }
                }
                self.missing -= 1;
                if self.missing == 0 {
                    self.samples += 1;
                    return Some(&self.cur);
                }
                None
            }
            _ => None,
        }
    }
}

// ── Aggregation ─────────────────────────────────────────────────────────────

/// One distinct stack and how many samples had it.
#[derive(Clone, Copy)]
pub struct Stack<const D: usize> {
    pub tid: u32,
    pub user: bool,
    pub count: u32,
    pub depth: u8,
    /// Innermost first.
    pub frames: [u64; D],
}

impl<const D: usize> Stack<D> {
    pub fn frames(&self) -> &[u64] {
        &self.frames[..self.depth as usize]
    }
}

/// Distinct stacks by `(user, tid, frames)`, counted. `S` stacks of at most
/// `D` frames; a sample deeper than `D` keeps its innermost `D`, and one
/// that finds the table full is counted in `lost`.
pub struct StackTable<const S: usize, const D: usize> {
    stacks: [Stack<D>; S],
    len: usize,
    pub samples: u64,
    pub lost: u64,
}

impl<const S: usize, const D: usize> StackTable<S, D> {
    pub const fn new() -> Self {
        StackTable {
            stacks: [Stack { tid: 0, user: false, count: 0, depth: 0, frames: [0; D] }; S],
            len: 0,
            samples: 0,
            lost: 0,
        }
    }

    pub fn stacks(&self) -> &[Stack<D>] {
        &self.stacks[..self.len]
    }

    /// Count one sample; its stack's index, or `None` when the table is full.
    pub fn add(&mut self, tid: u32, user: bool, frames: &[u64]) -> Option<usize> {
        self.samples += 1;
        let f = &frames[..frames.len().min(D)];
        if let Some(i) = self.stacks[..self.len]
            .iter()
            .position(|s| s.tid == tid && s.user == user && s.frames() == f)
        {
            self.stacks[i].count += 1;
            return Some(i);
        }
        if self.len == S {
            self.lost += 1;
            return None;
        }
        let s = &mut self.stacks[self.len];
        *s = Stack { tid, user, count: 1, depth: f.len() as u8, frames: [0; D] };
        s.frames[..f.len()].copy_from_slice(f);
        self.len += 1;
        Some(self.len - 1)
    }
}

/// One logged sample for the timeline export.
#[derive(Clone, Copy)]
pub struct Logged {
    /// Nanoseconds.
    pub ts_ns: u64,
    pub cpu: u16,
    /// Index into the [`StackTable`].
    pub stack: u16,
}

/// The first `N` samples in arrival order, for [`write_perfetto`].
pub struct SampleLog<const N: usize> {
    log: [Logged; N],
    len: usize,
    /// Samples that did not fit.
    pub dropped: u64,
}

impl<const N: usize> SampleLog<N> {
    pub const fn new() -> Self {
        SampleLog { log: [Logged { ts_ns: 0, cpu: 0, stack: 0 }; N], len: 0, dropped: 0 }
    }

    pub fn push(&mut self, ts_ns: u64, cpu: u16, stack: usize) {
        if self.len == N || stack > u16::MAX as usize {
            self.dropped += 1;
            return;
        }
        self.log[self.len] = Logged { ts_ns, cpu, stack: stack as u16 };
        self.len += 1;
    }

    pub fn entries(&self) -> &[Logged] {
        &self.log[..self.len]
    }
}

// ── Output ──────────────────────────────────────────────────────────────────

/// Where text goes: a buffer flushed to a file or the console.
pub trait Sink {
    fn put(&mut self, b: &[u8]);
}

/// The name of an address, or `None` when it is not known.
pub trait Namer {
    fn name(&self, addr: u64, user: bool) -> Option<&[u8]>;
}

fn put_dec(o: &mut dyn Sink, mut v: u64) {
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
    o.put(&d[i..]);
}

fn put_hex(o: &mut dyn Sink, v: u64) {
    let mut d = [0u8; 18];
    let mut i = d.len();
    let mut v = v;
    loop {
        i -= 1;
        d[i] = b"0123456789abcdef"[(v & 15) as usize];
        v >>= 4;
        if v == 0 {
            break;
        }
    }
    i -= 2;
    d[i] = b'0';
    d[i + 1] = b'x';
    o.put(&d[i..]);
}

/// A frame as text: its name with the characters the format uses as
/// separators replaced (or escaped, in JSON), or its address.
fn put_frame(o: &mut dyn Sink, names: &dyn Namer, addr: u64, user: bool, json: bool) {
    match names.name(addr, user) {
        Some(n) => {
            for &c in n {
                if json && (c == b'"' || c == b'\\') {
                    o.put(b"\\");
                }
                let c = match c {
                    b';' | b' ' if !json => b'_',
                    c if c < 0x20 => b'?',
                    c => c,
                };
                o.put(&[c]);
            }
        }
        None => put_hex(o, addr),
    }
}

/// Folded stacks (Brendan Gregg's flame-graph input): one line per distinct
/// stack, `mode:tidN;outermost;...;innermost COUNT`.
pub fn write_folded<const S: usize, const D: usize>(t: &StackTable<S, D>, names: &dyn Namer, o: &mut dyn Sink) {
    for s in t.stacks() {
        o.put(if s.user { b"user:tid" } else { b"kernel:tid" });
        put_dec(o, s.tid as u64);
        for &f in s.frames().iter().rev() {
            o.put(b";");
            put_frame(o, names, f, s.user, false);
        }
        o.put(b" ");
        put_dec(o, s.count as u64);
        o.put(b"\n");
    }
}

/// CPUs the timeline export tracks.
const TL_CPUS: usize = 64;

/// The sampling period the log implies: the mean gap between consecutive
/// samples on one CPU, over the CPUs with at least two (0 with none).
pub fn period_ns<const N: usize>(l: &SampleLog<N>) -> u64 {
    let mut first = [u64::MAX; TL_CPUS];
    let mut last = [0u64; TL_CPUS];
    let mut count = [0u64; TL_CPUS];
    for e in l.entries() {
        let c = e.cpu as usize % TL_CPUS;
        first[c] = first[c].min(e.ts_ns);
        last[c] = last[c].max(e.ts_ns);
        count[c] += 1;
    }
    let (mut gaps, mut span) = (0u64, 0u64);
    for c in 0..TL_CPUS {
        if count[c] >= 2 {
            gaps += count[c] - 1;
            span += last[c] - first[c];
        }
    }
    span.checked_div(gaps).unwrap_or(0)
}

fn put_us(o: &mut dyn Sink, ns: u64) {
    put_dec(o, ns / 1000);
    o.put(b".");
    let f = ns % 1000;
    o.put(&[b'0' + (f / 100) as u8, b'0' + (f / 10 % 10) as u8, b'0' + (f % 10) as u8]);
}

/// A Perfetto-loadable trace (Chrome trace-event JSON, which
/// `ui.perfetto.dev` opens): one track per CPU, and every sample is a stack
/// of nested slices, the root naming the task, lasting until the CPU's next
/// sample (at most 1.5 sampling periods, so an idle gap does not stretch the
/// last one).
pub fn write_perfetto<const S: usize, const D: usize, const N: usize>(
    t: &StackTable<S, D>,
    l: &SampleLog<N>,
    names: &dyn Namer,
    o: &mut dyn Sink,
) {
    let period = period_ns(l);
    let cap = if period == 0 { 1_000_000 } else { period + period / 2 };
    o.put(b"{\"traceEvents\":[\n");
    let mut seen = [false; TL_CPUS];
    let mut first = true;
    let ents = l.entries();
    for e in ents {
        let c = e.cpu as usize;
        if c < TL_CPUS && !seen[c] {
            seen[c] = true;
            if !first {
                o.put(b",\n");
            }
            first = false;
            o.put(b"{\"name\":\"thread_name\",\"ph\":\"M\",\"pid\":0,\"tid\":");
            put_dec(o, c as u64);
            o.put(b",\"args\":{\"name\":\"cpu ");
            put_dec(o, c as u64);
            o.put(b"\"}}");
        }
    }
    for (i, e) in ents.iter().enumerate() {
        let Some(s) = t.stacks().get(e.stack as usize) else { continue };
        // Until the next sample on the same CPU.
        let next = ents[i + 1..].iter().find(|n| n.cpu == e.cpu).map(|n| n.ts_ns);
        let dur = next.map_or(cap, |n| n.saturating_sub(e.ts_ns).min(cap)).max(1000);
        // Root first, then the frames outermost to innermost: each slice
        // starts with the same time and duration, so they nest.
        for depth in 0..=s.frames().len() {
            if !first {
                o.put(b",\n");
            }
            first = false;
            o.put(b"{\"name\":\"");
            if depth == 0 {
                o.put(if s.user { b"user tid " } else { b"kernel tid " });
                put_dec(o, s.tid as u64);
            } else {
                put_frame(o, names, s.frames()[s.frames().len() - depth], s.user, true);
            }
            o.put(if s.user { b"\",\"cat\":\"user\",\"ph\":\"X\",\"ts\":" } else { b"\",\"cat\":\"kernel\",\"ph\":\"X\",\"ts\":" });
            put_us(o, e.ts_ns);
            o.put(b",\"dur\":");
            put_us(o, dur);
            o.put(b",\"pid\":0,\"tid\":");
            put_dec(o, e.cpu as u64);
            o.put(b"}");
        }
    }
    o.put(b"\n]}\n");
}

// ── Symbolization ───────────────────────────────────────────────────────────

/// Random access to a file's bytes. `read_at` returns how many bytes it
/// put in `buf` (fewer than asked only at the end of the file; 0 on error).
pub trait ReadAt {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> usize;
}

/// Why a symbol table could not be loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    /// Not a 64-bit little-endian ELF file.
    NotElf,
    /// A header or table runs past the end of the file.
    Truncated,
    /// The file has no symbol table (it was stripped).
    NoSymtab,
}

fn le16(b: &[u8], o: usize) -> u64 {
    u16::from_le_bytes([b[o], b[o + 1]]) as u64
}
fn le32(b: &[u8], o: usize) -> u64 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as u64
}
fn le64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// Longest name kept (after demangling).
const NAME_MAX: usize = 96;

/// The names of up to `N` addresses, looked up in an ELF file's symbol table
/// (`P` bytes for the names). Add the addresses with [`Resolver::add`], load
/// once with [`Resolver::load`], then ask [`Resolver::name_of`].
///
/// The table is read once, in order, in 768-byte pieces: a symbol with a size
/// covers the addresses inside it, the innermost wins, and symbols without a
/// size (assembly labels) are not used. An address no symbol covers stays
/// unnamed and prints as its hex value.
pub struct Resolver<const N: usize, const P: usize> {
    addrs: [u64; N],
    n: usize,
    // Per address, while loading: the best symbol so far (its start and its
    // name's offset in the string table).
    sym_val: [u64; N],
    sym_name: [u32; N],
    found: [bool; N],
    // After loading: the demangled name in the pool.
    pool: [u8; P],
    pool_len: usize,
    name_at: [u32; N],
    name_len: [u8; N],
    /// Addresses or names refused for lack of room.
    pub overflow: u64,
}

impl<const N: usize, const P: usize> Resolver<N, P> {
    pub const fn new() -> Self {
        Resolver {
            addrs: [0; N],
            n: 0,
            sym_val: [0; N],
            sym_name: [0; N],
            found: [false; N],
            pool: [0; P],
            pool_len: 0,
            name_at: [0; N],
            name_len: [0; N],
            overflow: 0,
        }
    }

    /// Addresses added so far.
    pub fn len(&self) -> usize {
        self.n
    }

    /// Ask for `addr`'s name.
    pub fn add(&mut self, addr: u64) {
        if let Err(i) = self.addrs[..self.n].binary_search(&addr) {
            if self.n == N {
                self.overflow += 1;
                return;
            }
            let n = self.n;
            self.addrs.copy_within(i..n, i + 1);
            self.addrs[i] = addr;
            self.n += 1;
        }
    }

    /// The name of `addr`, if it was added and some symbol covers it.
    pub fn name_of(&self, addr: u64) -> Option<&[u8]> {
        let i = self.addrs[..self.n].binary_search(&addr).ok()?;
        let l = self.name_len[i] as usize;
        (l != 0).then(|| &self.pool[self.name_at[i] as usize..self.name_at[i] as usize + l])
    }

    /// Read `f`'s symbol table and name every added address it covers; how
    /// many got a name.
    pub fn load(&mut self, f: &mut dyn ReadAt) -> Result<usize, ElfError> {
        let mut h = [0u8; 64];
        if f.read_at(0, &mut h) < 64 {
            return Err(ElfError::Truncated);
        }
        // 0x7f ELF, class 64, little endian.
        if &h[..4] != b"\x7fELF" || h[4] != 2 || h[5] != 1 {
            return Err(ElfError::NotElf);
        }
        let (shoff, shentsize, shnum) = (le64(&h, 0x28), le16(&h, 0x3a), le16(&h, 0x3c));
        if shoff == 0 || shnum == 0 || shentsize < 64 {
            return Err(ElfError::NoSymtab);
        }
        let sh = |f: &mut dyn ReadAt, i: u64| -> Result<[u8; 64], ElfError> {
            let mut s = [0u8; 64];
            if f.read_at(shoff + i * shentsize, &mut s) < 64 {
                return Err(ElfError::Truncated);
            }
            Ok(s)
        };
        // SHT_SYMTAB (2) and the string table its link names.
        let mut symtab = None;
        for i in 0..shnum {
            let s = sh(f, i)?;
            if le32(&s, 4) == 2 {
                symtab = Some(s);
                break;
            }
        }
        let st = symtab.ok_or(ElfError::NoSymtab)?;
        let (sym_off, sym_bytes) = (le64(&st, 0x18), le64(&st, 0x20));
        let link = le32(&st, 0x28);
        if link >= shnum {
            return Err(ElfError::Truncated);
        }
        let str_off = le64(&sh(f, link)?, 0x18);

        const PIECE: usize = 32;
        let mut buf = [0u8; PIECE * 24];
        let total = sym_bytes / 24;
        let mut i = 0u64;
        while i < total {
            let want = (total - i).min(PIECE as u64) as usize;
            let got = f.read_at(sym_off + i * 24, &mut buf[..want * 24]);
            if got < 24 {
                return Err(ElfError::Truncated);
            }
            for k in 0..got / 24 {
                let e = &buf[k * 24..k * 24 + 24];
                let (info, shndx, val, size) = (e[4], le16(e, 6), le64(e, 8), le64(e, 16));
                // FUNC (2) or NOTYPE (0), defined in a real section, sized.
                if size == 0 || shndx == 0 || shndx >= 0xff00 || !matches!(info & 0xf, 0 | 2) {
                    continue;
                }
                self.cover(val, val.saturating_add(size), le32(e, 0) as u32);
            }
            i += (got / 24) as u64;
        }
        // The names.
        let mut named = 0;
        for k in 0..self.n {
            if !self.found[k] {
                continue;
            }
            let mut raw = [0u8; 256];
            let got = f.read_at(str_off + self.sym_name[k] as u64, &mut raw);
            let end = raw[..got].iter().position(|&c| c == 0).unwrap_or(got);
            if end == 0 {
                continue;
            }
            let mut dm = [0u8; NAME_MAX];
            let len = demangle(&raw[..end], &mut dm);
            if self.pool_len + len > P {
                self.overflow += 1;
                continue;
            }
            self.pool[self.pool_len..self.pool_len + len].copy_from_slice(&dm[..len]);
            self.name_at[k] = self.pool_len as u32;
            self.name_len[k] = len as u8;
            self.pool_len += len;
            named += 1;
        }
        Ok(named)
    }

    /// A symbol covering `[val, end)`: the innermost (largest start) wins.
    fn cover(&mut self, val: u64, end: u64, name: u32) {
        let first = self.addrs[..self.n].partition_point(|&a| a < val);
        for k in first..self.n {
            if self.addrs[k] >= end {
                break;
            }
            if !self.found[k] || val > self.sym_val[k] {
                self.found[k] = true;
                self.sym_val[k] = val;
                self.sym_name[k] = name;
            }
        }
    }
}

/// Kernel and user addresses, resolved against their own files.
pub struct Names<'a, const N: usize, const P: usize> {
    pub kernel: &'a Resolver<N, P>,
    pub user: &'a Resolver<N, P>,
}

impl<const N: usize, const P: usize> Namer for Names<'_, N, P> {
    fn name(&self, addr: u64, user: bool) -> Option<&[u8]> {
        if user { self.user.name_of(addr) } else { self.kernel.name_of(addr) }
    }
}

/// Demangle a Rust symbol into `out`: the v0 scheme (`_R…`, rustc's default
/// since 2025) or the legacy one (`_ZN…E`, the hash dropped); generic
/// arguments are left out, a name is `crate::module::function` or
/// `<Type as Trait>::function`. Anything else, or a symbol that does not
/// parse, is copied as it is. The length written (truncated to `out`).
pub fn demangle(sym: &[u8], out: &mut [u8]) -> usize {
    if let Some(rest) = sym.strip_prefix(b"_R") {
        let mut v = V0 { s: rest, pos: 0, out, w: 0, depth: 0, steps: 0 };
        v.skip_version();
        if v.path(true).is_some() {
            // A suffix the compiler or linker added (`.0`, `.llvm.…`).
            if v.peek() == Some(b'.') {
                let tail = &v.s[v.pos..];
                v.put(tail);
            }
            return v.w;
        }
        let out = v.out;
        let n = sym.len().min(out.len());
        out[..n].copy_from_slice(&sym[..n]);
        return n;
    }
    demangle_legacy(sym, out)
}

fn demangle_legacy(sym: &[u8], out: &mut [u8]) -> usize {
    fn copy(out: &mut [u8], w: &mut usize, b: &[u8]) {
        for &c in b {
            if *w < out.len() {
                out[*w] = c;
                *w += 1;
            }
        }
    }
    let mut w = 0;
    let Some(mut rest) = sym.strip_prefix(b"_ZN") else {
        copy(out, &mut w, sym);
        return w;
    };
    // The segments: length-prefixed identifiers up to `E`.
    let mut segs = 0;
    loop {
        let digits = rest.iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 || digits > 4 {
            break;
        }
        let len = rest[..digits].iter().fold(0usize, |a, &c| a * 10 + (c - b'0') as usize);
        let body = &rest[digits..];
        if len > body.len() {
            // Not a well-formed name: show it raw.
            segs = 0;
            break;
        }
        let (seg, tail) = body.split_at(len);
        rest = tail;
        // `h` and 16 hex digits, last: the hash.
        if seg.len() == 17 && seg[0] == b'h' && seg[1..].iter().all(|c| c.is_ascii_hexdigit()) && rest.first() == Some(&b'E') {
            break;
        }
        if segs > 0 {
            copy(out, &mut w, b"::");
        }
        segs += 1;
        put_segment(seg, &mut |b| copy(out, &mut w, b));
    }
    if segs == 0 {
        w = 0;
        copy(out, &mut w, sym);
    }
    w
}

/// One identifier with Rust's `$xx$` escapes and `..` (for `::`) decoded.
fn put_segment(seg: &[u8], put: &mut dyn FnMut(&[u8])) {
    // `_$` marks an identifier that would start with a `$`.
    let mut s = if seg.starts_with(b"_$") { &seg[1..] } else { seg };
    while let Some(&c) = s.first() {
        if c == b'$' {
            if let Some(end) = s[1..].iter().position(|&c| c == b'$') {
                let rep: &[u8] = match &s[1..1 + end] {
                    b"LT" => b"<",
                    b"GT" => b">",
                    b"RF" => b"&",
                    b"BP" => b"*",
                    b"LP" => b"(",
                    b"RP" => b")",
                    b"C" => b",",
                    b"SP" => b"@",
                    b"u20" => b" ",
                    b"u27" => b"'",
                    b"u5b" => b"[",
                    b"u5d" => b"]",
                    b"u7b" => b"{",
                    b"u7d" => b"}",
                    b"u3b" => b";",
                    b"u2b" => b"+",
                    b"u22" => b"\"",
                    _ => b"?",
                };
                put(rep);
                s = &s[end + 2..];
                continue;
            }
        }
        if c == b'.' && s.get(1) == Some(&b'.') {
            put(b"::");
            s = &s[2..];
            continue;
        }
        put(&[c]);
        s = &s[1..];
    }
}

// ── The v0 mangling ─────────────────────────────────────────────────────────

/// A parser of the grammar of rustc's v0 symbol mangling that prints as it
/// goes (`emit`) or only advances (a backreference's target, a generic
/// argument). Bounded: nesting by `depth`, work by `steps`, and a
/// backreference must point before itself.
struct V0<'a> {
    /// The mangled name after `_R`; backreferences count from its start.
    s: &'a [u8],
    pos: usize,
    out: &'a mut [u8],
    w: usize,
    depth: u32,
    steps: u32,
}

const V0_DEPTH: u32 = 24;
const V0_STEPS: u32 = 4000;

impl<'a> V0<'a> {
    fn put(&mut self, b: &[u8]) {
        for &c in b {
            if self.w < self.out.len() {
                self.out[self.w] = c;
                self.w += 1;
            }
        }
    }

    fn put_if(&mut self, emit: bool, b: &[u8]) {
        if emit {
            self.put(b);
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn eat(&mut self, c: u8) -> bool {
        let yes = self.peek() == Some(c);
        self.pos += yes as usize;
        yes
    }

    /// The optional decimal version after `_R` (none exists yet).
    fn skip_version(&mut self) {
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.pos += 1;
        }
    }

    /// `<base-62-number> "_"`: `_` alone is 0, else the digits' value + 1.
    fn base62(&mut self) -> Option<u64> {
        let (mut v, mut digits) = (0u64, 0);
        loop {
            let c = self.next()?;
            let d = match c {
                b'_' => return if digits == 0 { Some(0) } else { v.checked_add(1) },
                b'0'..=b'9' => c - b'0',
                b'a'..=b'z' => c - b'a' + 10,
                b'A'..=b'Z' => c - b'A' + 36,
                _ => return None,
            };
            v = v.checked_mul(62)?.checked_add(d as u64)?;
            digits += 1;
        }
    }

    /// `[disambiguator] [u] <decimal> [_] <bytes>`: the identifier, and its
    /// disambiguator (0 when absent).
    fn ident(&mut self) -> Option<(&'a [u8], u64)> {
        // The disambiguator counts from 1 when written (`s_`), from 0 when not.
        let dis = if self.eat(b's') { self.base62()?.checked_add(1)? } else { 0 };
        self.eat(b'u');
        let mut len = 0usize;
        let mut digits = 0;
        while let Some(c) = self.peek().filter(u8::is_ascii_digit) {
            len = len.checked_mul(10)?.checked_add((c - b'0') as usize)?;
            self.pos += 1;
            digits += 1;
        }
        if digits == 0 {
            return None;
        }
        self.eat(b'_');
        let end = self.pos.checked_add(len)?;
        let id = self.s.get(self.pos..end)?;
        self.pos = end;
        Some((id, dis))
    }

    /// Follow a backreference (`B` and its number already read) and parse
    /// there with `f`, then come back.
    fn back<T>(&mut self, at: usize, f: impl FnOnce(&mut Self) -> Option<T>) -> Option<T> {
        let target = self.base62()? as usize;
        // It must point strictly before the `B` it is written at.
        if target >= at || self.depth >= V0_DEPTH {
            return None;
        }
        let resume = self.pos;
        self.pos = target;
        self.depth += 1;
        let r = f(self);
        self.depth -= 1;
        self.pos = resume;
        r
    }

    fn path(&mut self, emit: bool) -> Option<()> {
        self.steps += 1;
        if self.steps > V0_STEPS || self.depth >= V0_DEPTH {
            return None;
        }
        let at = self.pos;
        match self.next()? {
            b'C' => {
                let (id, _) = self.ident()?;
                if emit {
                    self.put(id);
                }
            }
            b'M' => {
                self.eat_impl_disambiguator()?;
                self.depth += 1;
                self.path(false)?;
                self.put_if(emit, b"<");
                self.ty(emit)?;
                self.put_if(emit, b">");
                self.depth -= 1;
            }
            b'X' => {
                self.eat_impl_disambiguator()?;
                self.depth += 1;
                self.path(false)?;
                self.put_if(emit, b"<");
                self.ty(emit)?;
                self.put_if(emit, b" as ");
                self.path(emit)?;
                self.put_if(emit, b">");
                self.depth -= 1;
            }
            b'Y' => {
                self.depth += 1;
                self.put_if(emit, b"<");
                self.ty(emit)?;
                self.put_if(emit, b" as ");
                self.path(emit)?;
                self.put_if(emit, b">");
                self.depth -= 1;
            }
            b'N' => {
                let ns = self.next()?;
                self.depth += 1;
                self.path(emit)?;
                let (id, dis) = self.ident()?;
                self.depth -= 1;
                if emit {
                    self.put(b"::");
                    match ns {
                        b'C' | b'S' => {
                            self.put(if ns == b'C' { b"{closure" } else { b"{shim" });
                            if !id.is_empty() {
                                self.put(b":");
                                self.put(id);
                            }
                            self.put(b"#");
                            let mut d = [0u8; 20];
                            let mut i = d.len();
                            let mut v = dis;
                            loop {
                                i -= 1;
                                d[i] = b'0' + (v % 10) as u8;
                                v /= 10;
                                if v == 0 {
                                    break;
                                }
                            }
                            self.put(&d[i..]);
                            self.put(b"}");
                        }
                        _ => self.put(id),
                    }
                }
            }
            b'I' => {
                self.depth += 1;
                self.path(emit)?;
                while self.peek()? != b'E' {
                    self.generic_arg()?;
                }
                self.pos += 1;
                self.depth -= 1;
            }
            b'B' => return self.back(at, |v| v.path(emit)),
            _ => return None,
        }
        Some(())
    }

    /// `impl-path = [disambiguator] path`: the disambiguator (`s` and a
    /// number) before the path.
    fn eat_impl_disambiguator(&mut self) -> Option<()> {
        if self.eat(b's') {
            self.base62()?;
        }
        Some(())
    }

    fn generic_arg(&mut self) -> Option<()> {
        self.steps += 1;
        if self.steps > V0_STEPS {
            return None;
        }
        match self.peek()? {
            b'L' => {
                self.pos += 1;
                self.base62()?;
            }
            b'K' => {
                self.pos += 1;
                self.konst(false)?;
            }
            _ => self.ty(false)?,
        }
        Some(())
    }

    /// A const generic argument or array length: a placeholder, a
    /// backreference, or `<type> [n] <hex digits> _`; integers print in
    /// decimal, anything else as `_`.
    fn konst(&mut self, emit: bool) -> Option<()> {
        let at = self.pos;
        match self.peek()? {
            b'p' => {
                self.pos += 1;
                self.put_if(emit, b"_");
            }
            b'B' => {
                self.pos += 1;
                return self.back(at, |v| v.konst(emit));
            }
            _ => {
                self.ty(false)?;
                let neg = self.eat(b'n');
                let mut v = Some(0u64);
                while let Some(d) = self.peek().and_then(|c| (c as char).to_digit(16)) {
                    v = v.and_then(|x| x.checked_mul(16)).and_then(|x| x.checked_add(d as u64));
                    self.pos += 1;
                }
                if !self.eat(b'_') {
                    return None;
                }
                match v {
                    Some(mut v) if emit => {
                        if neg {
                            self.put(b"-");
                        }
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
                        self.put(&d[i..]);
                    }
                    None if emit => self.put(b"_"),
                    _ => {}
                }
            }
        }
        Some(())
    }

    fn ty(&mut self, emit: bool) -> Option<()> {
        self.steps += 1;
        if self.steps > V0_STEPS || self.depth >= V0_DEPTH {
            return None;
        }
        let at = self.pos;
        let c = self.peek()?;
        if c.is_ascii_lowercase() {
            self.pos += 1;
            let name: &[u8] = match c {
                b'a' => b"i8",
                b'b' => b"bool",
                b'c' => b"char",
                b'd' => b"f64",
                b'e' => b"str",
                b'f' => b"f32",
                b'h' => b"u8",
                b'i' => b"isize",
                b'j' => b"usize",
                b'l' => b"i32",
                b'm' => b"u32",
                b'n' => b"i128",
                b'o' => b"u128",
                b'p' => b"_",
                b's' => b"i16",
                b't' => b"u16",
                b'u' => b"()",
                b'v' => b"...",
                b'x' => b"i64",
                b'y' => b"u64",
                b'z' => b"!",
                _ => return None,
            };
            self.put_if(emit, name);
            return Some(());
        }
        self.depth += 1;
        let r = (|| -> Option<()> {
            match c {
                b'A' => {
                    self.pos += 1;
                    self.put_if(emit, b"[");
                    self.ty(emit)?;
                    self.put_if(emit, b"; ");
                    self.konst(emit)?;
                    self.put_if(emit, b"]");
                }
                b'S' => {
                    self.pos += 1;
                    self.put_if(emit, b"[");
                    self.ty(emit)?;
                    self.put_if(emit, b"]");
                }
                b'T' => {
                    self.pos += 1;
                    self.put_if(emit, b"(");
                    let mut first = true;
                    while self.peek()? != b'E' {
                        if !first {
                            self.put_if(emit, b", ");
                        }
                        first = false;
                        self.ty(emit)?;
                    }
                    self.pos += 1;
                    self.put_if(emit, b")");
                }
                b'R' | b'Q' => {
                    self.pos += 1;
                    if self.eat(b'L') {
                        self.base62()?;
                    }
                    self.put_if(emit, if c == b'R' { b"&" } else { b"&mut " });
                    self.ty(emit)?;
                }
                b'P' | b'O' => {
                    self.pos += 1;
                    self.put_if(emit, if c == b'P' { b"*const " } else { b"*mut " });
                    self.ty(emit)?;
                }
                b'F' => {
                    self.pos += 1;
                    self.binder()?;
                    self.eat(b'U');
                    if self.eat(b'K') && !self.eat(b'C') {
                        self.ident()?;
                    }
                    while self.peek()? != b'E' {
                        self.ty(false)?;
                    }
                    self.pos += 1;
                    self.ty(false)?;
                    self.put_if(emit, b"fn(..)");
                }
                b'D' => {
                    self.pos += 1;
                    self.binder()?;
                    self.put_if(emit, b"dyn ");
                    let mut first = true;
                    while self.peek()? != b'E' {
                        self.path(emit && first)?;
                        first = false;
                        // Associated-type bindings: `p <ident> <type>`.
                        while self.eat(b'p') {
                            self.ident()?;
                            self.ty(false)?;
                        }
                    }
                    self.pos += 1;
                    if self.eat(b'L') {
                        self.base62()?;
                    }
                }
                b'B' => {
                    self.pos += 1;
                    return self.back(at, |v| v.ty(emit));
                }
                _ => return self.path(emit),
            }
            Some(())
        })();
        self.depth -= 1;
        r
    }

    /// `[G <base-62-number>]`: the lifetimes a binder introduces.
    fn binder(&mut self) -> Option<()> {
        if self.eat(b'G') {
            self.base62()?;
        }
        Some(())
    }
}
