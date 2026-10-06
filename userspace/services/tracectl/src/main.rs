// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `TRACECTL.ELF`: the kernel tracer's reader (wave 15, TRACE).
//!
//! Its topology row is the whole of its authority: `Cap<Trace>` (found with
//! `SYS_CAP_LOOKUP`, presented to `SYS_TRACE_CTL_TYPED` on every call) and
//! `/fat` read-write for a trace file. Without the capability it still asks,
//! with handle 0, so the refusal is the kernel's and is recorded.
//!
//! The kernel writes one ring per CPU in one shared region
//! (`azos_spsc::trace`); this program maps it, is the single consumer of
//! every ring, and polls: the producer rings no doorbell, which is what keeps
//! a record to one cache line. Two readers at once would race each other's
//! tails; run one.
//!
//! ```text
//! tracectl info                      geometry, classes, mask, per-CPU drops
//! tracectl start [CLASSES]           start recording (default: every class)
//! tracectl stop                      stop recording (mask 0)
//! tracectl stream [-n N] [-t MS] [-c CLASSES] [-p MS] [-m N] [-q] [-o FILE]
//!     record CLASSES (default: every class) and stream decoded records
//!     until N records or MS milliseconds (default 5000 ms), polling every
//!     -p MS (default 2); -q prints only the summary; -o writes the records
//!     to FILE (e.g. /fat/TRACE.TXT). The mask is put back as found. A
//!     change of the runtime mask while it streams opens a segment; the
//!     summary counts each segment's records per class, those of a masked
//!     class near a boundary ("late") and past it ("outside", which must be
//!     0). -m N stops 300 ms after the Nth change.
//! CLASSES: all | a comma list of sched,irq,syscall,ipc,fault,proc,lat | 0xMASK
//! ```
//!
//! Exit 0 on success, 1 when the kernel refused or the tracer is compiled
//! out, 2 on a usage error.

#![no_std]
#![no_main]

use azos_libsys as sys;
use azos_spsc::trace::{Pop, TraceConsumer, TraceGeometry, TraceRecord};
use azos_abi::trace::*;

// ── Output ──────────────────────────────────────────────────────────────────

fn put(fd: u64, b: &[u8]) {
    let mut done = 0usize;
    while done < b.len() {
        let r = sys::write(fd, &b[done..]);
        if r <= 0 {
            return;
        }
        done += r as usize;
    }
}

/// A line buffer flushed to the console or to a `Cap<File>`.
struct Out {
    buf: [u8; 2048],
    len: usize,
    /// `Some(cap)`: a file; `None`: stdout.
    file: Option<u32>,
    quiet: bool,
}

impl Out {
    fn flush(&mut self) {
        if self.len == 0 {
            return;
        }
        match self.file {
            Some(cap) => {
                let mut done = 0;
                while done < self.len {
                    let r = sys::file_write_typed(cap, &self.buf[done..self.len]);
                    if r <= 0 {
                        break;
                    }
                    done += r as usize;
                }
            }
            None => put(1, &self.buf[..self.len]),
        }
        self.len = 0;
    }
    fn s(&mut self, b: &[u8]) {
        if self.quiet {
            return;
        }
        if self.len + b.len() > self.buf.len() {
            self.flush();
        }
        let n = b.len().min(self.buf.len());
        self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
    }
    fn dec(&mut self, v: u64) {
        let mut d = [0u8; 20];
        let n = fmt_dec(v, &mut d);
        self.s(&d[20 - n..]);
    }
    fn dec_pad(&mut self, v: u64, width: usize) {
        let mut d = [0u8; 20];
        let n = fmt_dec(v, &mut d);
        for _ in n..width {
            self.s(b"0");
        }
        self.s(&d[20 - n..]);
    }
    fn hex(&mut self, v: u64) {
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
        self.s(&d[i..]);
    }
    fn kv(&mut self, k: &[u8], v: u64) {
        self.s(b" ");
        self.s(k);
        self.s(b"=");
        self.dec(v);
    }
    fn kvi(&mut self, k: &[u8], v: i64) {
        self.s(b" ");
        self.s(k);
        self.s(b"=");
        if v < 0 {
            self.s(b"-");
        }
        self.dec(v.unsigned_abs());
    }
    fn kx(&mut self, k: &[u8], v: u64) {
        self.s(b" ");
        self.s(k);
        self.s(b"=");
        self.hex(v);
    }
}

/// Write `v` right-aligned into `d`; the number of digits.
fn fmt_dec(mut v: u64, d: &mut [u8; 20]) -> usize {
    let mut i = d.len();
    loop {
        i -= 1;
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    d.len() - i
}

fn err(msg: &[u8]) {
    put(2, b"tracectl: ");
    put(2, msg);
    put(2, b"\n");
}

fn err_rc(what: &[u8], r: isize) -> i32 {
    let mut o = Out { buf: [0; 2048], len: 0, file: None, quiet: false };
    o.s(b"tracectl: ");
    o.s(what);
    if r == -(azos_abi::error::Errno::ENOSYS as isize) {
        o.s(b": the tracer is compiled out (KTRACE)\n");
    } else {
        o.s(b" refused: ");
        o.kvi(b"rc", r as i64);
        o.s(b"\n");
    }
    let n = o.len;
    put(2, &o.buf[..n]);
    1
}

// ── Arguments ───────────────────────────────────────────────────────────────

fn parse_dec(a: &[u8]) -> Option<u64> {
    if a.is_empty() || a.len() > 12 {
        return None;
    }
    let mut v = 0u64;
    for &b in a {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (b - b'0') as u64;
    }
    Some(v)
}

/// `all`, `0xMASK`, or a comma list of class names.
fn parse_classes(a: &[u8]) -> Option<u32> {
    if a == b"all" {
        return Some(TRACE_MASK_ALL);
    }
    if let Some(h) = a.strip_prefix(b"0x") {
        let mut v = 0u32;
        if h.is_empty() || h.len() > 8 {
            return None;
        }
        for &b in h {
            let d = (b as char).to_digit(16)?;
            v = (v << 4) | d;
        }
        return Some(v);
    }
    let mut m = 0u32;
    for name in a.split(|&b| b == b',') {
        let c = (0..TRACE_CLASSES).find(|&c| trace_class_name(c).as_bytes() == name)?;
        m |= 1 << c;
    }
    (m != 0).then_some(m)
}

fn usage() -> i32 {
    put(
        2,
        b"usage: tracectl info | start [CLASSES] | stop |\n       \
          stream [-n N] [-t MS] [-c CLASSES] [-p MS] [-m N] [-q] [-o FILE]\n\
          CLASSES: all | sched,irq,syscall,ipc,fault,proc,lat | 0xMASK\n",
    );
    2
}

// ── The tracer ──────────────────────────────────────────────────────────────

fn cap() -> u32 {
    // Handle 0 when the row grants none: the kernel refuses and records it.
    let found = sys::cap_lookup(sys::CapKind::Trace as u8, 0);
    if found >= 0 {
        found as u32
    } else {
        0
    }
}

fn ctl(cap: u32, op: u64, arg: u64) -> isize {
    sys::trace_ctl_typed(cap, op, arg)
}

/// The region, mapped, and its geometry.
fn map(cap: u32) -> Result<(usize, TraceGeometry), i32> {
    let bytes = ctl(cap, TRACE_OP_REGION_BYTES, 0);
    if bytes < 0 {
        return Err(err_rc(b"region", bytes));
    }
    let base = ctl(cap, TRACE_OP_MAP, 0);
    if base < 0 {
        return Err(err_rc(b"map", base));
    }
    match TraceGeometry::from_header(base as usize, bytes as usize) {
        Some(g) => Ok((base as usize, g)),
        None => {
            err(b"the trace region's header is not one this reader knows");
            Err(1)
        }
    }
}

fn info() -> i32 {
    let c = cap();
    let classes = ctl(c, TRACE_OP_INFO, 0);
    if classes < 0 {
        return err_rc(b"info", classes);
    }
    let (base, g) = match map(c) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let mut o = Out { buf: [0; 2048], len: 0, file: None, quiet: false };
    o.s(b"tracectl:");
    o.kv(b"cpus", g.ncpu as u64);
    o.kv(b"entries", g.entries as u64);
    o.s(if g.policy == azos_spsc::trace::POLICY_OVERWRITE { b" policy=overwrite" } else { b" policy=drop" });
    o.s(if g.ts_source == azos_spsc::trace::TS_CYCLES { b" ts=cycles" } else { b" ts=timebase" });
    o.kv(b"hz", g.ts_hz);
    o.kx(b"classes", classes as u64);
    o.kx(b"mask", TraceGeometry::mask(base) as u64);
    o.s(b"\n");
    for cpu in 0..g.ncpu {
        let cons = TraceConsumer::new(base, &g, cpu);
        o.s(b"tracectl: cpu");
        o.dec(cpu as u64);
        o.kv(b"drops", cons.drops() as u64);
        o.kv(b"tail", cons.tail() as u64);
        o.s(b"\n");
    }
    o.flush();
    0
}

fn set_mask(mask: u32, what: &[u8]) -> i32 {
    let c = cap();
    let prev = ctl(c, TRACE_OP_SET_MASK, mask as u64);
    if prev < 0 {
        return err_rc(what, prev);
    }
    let now = ctl(c, TRACE_OP_GET_MASK, 0);
    let mut o = Out { buf: [0; 2048], len: 0, file: None, quiet: false };
    o.s(b"tracectl: ");
    o.s(what);
    o.kx(b"mask", now.max(0) as u64);
    o.kx(b"was", prev as u64);
    o.s(b"\n");
    o.flush();
    0
}

/// Mask segments a stream tracks (the first, and one per observed change).
const MAX_SEGS: usize = 8;
/// A record of a class outside its segment's mask is "late" (in flight
/// across the change, or seen before this reader noticed it) when it lies
/// within this many nanoseconds of a boundary whose other side has the
/// class; past that it is "outside", which the mask forbids.
const SEG_GRACE_NS: u64 = 20_000_000;
/// With `-m N`: how long to keep reading after the Nth change.
const SEG_TAIL_MS: u64 = 300;

/// One stretch of the stream under one runtime mask, as the reader saw it.
#[derive(Clone, Copy)]
struct Seg {
    start_ns: u64,
    mask: u32,
    counts: [u64; TRACE_CLASSES as usize],
    late: u64,
    outside: u64,
    /// The first "outside" record's time (ns). Printed with the segment's
    /// start (`at_ns`, the kernel-dated change): what a reader needs to see
    /// how far past the boundary a stray record was.
    first_outside_ns: u64,
}

impl Seg {
    const fn new(start_ns: u64, mask: u32) -> Seg {
        Seg { start_ns, mask, counts: [0; TRACE_CLASSES as usize], late: 0, outside: 0, first_outside_ns: 0 }
    }
}

/// Book a record of `class` at `ns` into the segment it falls in.
fn seg_book(segs: &mut [Seg], class: u32, ns: u64) {
    let Some(k) = segs.iter().rposition(|s| s.start_ns <= ns) else { return };
    let bit = 1u32 << class;
    segs[k].counts[class as usize] += 1;
    if segs[k].mask & bit != 0 {
        return;
    }
    let near_prev = k > 0 && segs[k - 1].mask & bit != 0 && ns < segs[k].start_ns + SEG_GRACE_NS;
    let near_next = k + 1 < segs.len() && segs[k + 1].mask & bit != 0 && ns + SEG_GRACE_NS >= segs[k + 1].start_ns;
    if near_prev || near_next {
        segs[k].late += 1;
    } else {
        if segs[k].outside == 0 {
            segs[k].first_outside_ns = ns;
        }
        segs[k].outside += 1;
    }
}

/// Rings this reader drains: the layout's bound (a region never has more).
const MAX_RINGS: usize = azos_spsc::trace::TRACE_MAX_CPUS as usize;

/// Per-CPU records taken per poll before the merge.
const BATCH: usize = 64;

/// The per-poll batches, in `.bss`: 16 KiB would not fit the stack.
struct Batches(core::cell::UnsafeCell<[[TraceRecord; BATCH]; MAX_RINGS]>);
// SAFETY: this program is single-threaded.
unsafe impl Sync for Batches {}
static BATCH_BUF: Batches = Batches(core::cell::UnsafeCell::new(
    [[TraceRecord { ts: 0, seq: 0, event: 0, cpu: 0, flags: 0, args: [0; 4] }; BATCH]; MAX_RINGS],
));

/// Decode one record as a text line (ftrace-like).
fn emit(o: &mut Out, r: &TraceRecord, hz: u64) {
    o.s(b"[cpu");
    o.dec(r.cpu as u64);
    o.s(b"] ");
    if hz != 0 {
        let ns = (r.ts as u128 * 1_000_000_000 / hz as u128) as u64;
        o.dec(ns / 1_000_000_000);
        o.s(b".");
        o.dec_pad(ns % 1_000_000_000, 9);
    } else {
        o.dec(r.ts);
    }
    o.s(b" ");
    o.s(trace_event_name(r.event).as_bytes());
    let a = r.args;
    match r.event {
        TRACE_EV_SCHED_SWITCH => {
            o.kv(b"prev", a[0] as u64);
            o.kv(b"next", a[1] as u64);
            o.kv(b"prev_state", a[2] as u64);
            o.s(match a[3] {
                0 => b" reason=voluntary" as &[u8],
                1 => b" reason=preempted",
                _ => b" reason=ipc-handoff",
            });
        }
        TRACE_EV_SCHED_WAKEUP => {
            o.kv(b"tid", a[0] as u64);
            o.kv(b"cpu", a[1] as u64);
            o.kv(b"waker", a[2] as u64);
        }
        TRACE_EV_IRQ_ENTRY | TRACE_EV_IRQ_EXIT => o.kv(b"irq", a[0] as u64),
        TRACE_EV_SYS_ENTER => {
            o.kv(b"nr", a[0] as u64);
            o.kv(b"tid", a[1] as u64);
            o.kx(b"a0", a[2] as u64);
            o.kx(b"a1", a[3] as u64);
        }
        TRACE_EV_SYS_EXIT => {
            o.kv(b"nr", a[0] as u64);
            o.kv(b"tid", a[1] as u64);
            o.kvi(b"ret", (a[2] as u64 | (a[3] as u64) << 32) as i64);
        }
        TRACE_EV_SYS_DENY => {
            o.kv(b"nr", a[0] as u64);
            o.kv(b"tid", a[1] as u64);
        }
        TRACE_EV_IPC_CALL => {
            o.kv(b"caller", a[0] as u64);
            o.kv(b"server", a[1] as u64);
            o.kx(b"label", a[2] as u64);
        }
        TRACE_EV_IPC_REPLY => {
            o.kv(b"server", a[0] as u64);
            o.kv(b"caller", a[1] as u64);
            o.kv(b"status", a[2] as u64);
        }
        TRACE_EV_PAGE_FAULT => {
            o.kx(b"addr", a[0] as u64 | (a[1] as u64) << 32);
            o.kv(b"cause", a[2] as u64);
            o.kv(b"tid", a[3] as u64);
        }
        TRACE_EV_PROC_SPAWN => {
            o.kv(b"child", a[0] as u64);
            o.kv(b"parent", a[1] as u64);
        }
        TRACE_EV_PROC_EXIT => {
            o.kv(b"tid", a[0] as u64);
            o.kvi(b"code", a[1] as i32 as i64);
        }
        TRACE_EV_PROC_SIGNAL => {
            o.kv(b"tid", a[0] as u64);
            o.kv(b"signo", a[1] as u64);
            o.kv(b"sender", a[2] as u64);
            o.kv(b"action", a[3] as u64);
        }
        TRACE_EV_LAT_IRQSOFF | TRACE_EV_LAT_PREEMPTOFF => {
            o.kv(b"ticks", a[0] as u64 | (a[1] as u64) << 32);
            o.kx(b"open", a[2] as u64);
            o.kx(b"close", a[3] as u64);
        }
        _ => {
            for (i, v) in a.iter().enumerate() {
                o.kx([b"a0", b"a1", b"a2", b"a3"][i], *v as u64);
            }
        }
    }
    o.s(b"\n");
}

struct Opts {
    count: u64,
    ms: u64,
    poll_ms: u64,
    classes: Option<u32>,
    quiet: bool,
    file: Option<&'static [u8]>,
    /// Stop [`SEG_TAIL_MS`] after this many changes of the runtime mask.
    mask_changes: u64,
}

fn parse_stream_opts() -> Option<Opts> {
    let mut o = Opts { count: u64::MAX, ms: 0, poll_ms: 2, classes: None, quiet: false, file: None, mask_changes: 0 };
    let mut i = 2;
    while let Some(a) = sys::arg(i) {
        match a {
            b"-q" => o.quiet = true,
            b"-n" | b"-t" | b"-p" | b"-c" | b"-o" | b"-m" => {
                let v = sys::arg(i + 1)?;
                match a {
                    b"-n" => o.count = parse_dec(v).filter(|&n| n > 0)?,
                    b"-t" => o.ms = parse_dec(v).filter(|&n| n > 0)?,
                    b"-p" => o.poll_ms = parse_dec(v).filter(|&n| n > 0 && n <= 1000)?,
                    b"-c" => o.classes = Some(parse_classes(v)?),
                    b"-m" => o.mask_changes = parse_dec(v).filter(|&n| n > 0 && n < MAX_SEGS as u64)?,
                    _ => o.file = Some(v),
                }
                i += 1;
            }
            _ => return None,
        }
        i += 1;
    }
    if o.ms == 0 && o.count == u64::MAX {
        o.ms = 5000;
    }
    Some(o)
}

fn stream() -> i32 {
    let Some(opts) = parse_stream_opts() else { return usage() };
    let c = cap();
    let compiled = ctl(c, TRACE_OP_INFO, 0);
    if compiled < 0 {
        return err_rc(b"info", compiled);
    }
    let (base, g) = match map(c) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let ncpu = (g.ncpu as usize).min(MAX_RINGS);
    let mut cons = [None::<TraceConsumer>; MAX_RINGS];
    let mut drops0 = [0u32; MAX_RINGS];
    // Records left by an earlier session are not this one's: skip them, and
    // count drops from here on.
    let mut stale = 0u64;
    for cpu in 0..ncpu {
        let mut k = TraceConsumer::new(base, &g, cpu as u32);
        while let Pop::Rec(_) | Pop::Lost(_) = k.pop() {
            stale += 1;
        }
        k.release();
        drops0[cpu] = k.drops();
        cons[cpu] = Some(k);
    }
    let want = opts.classes.unwrap_or(TRACE_MASK_ALL) & compiled as u32;
    let prev = ctl(c, TRACE_OP_SET_MASK, want as u64);
    if prev < 0 {
        return err_rc(b"start", prev);
    }
    let file = match opts.file {
        Some(path) => {
            // NUL-terminated for the kernel.
            let mut p = [0u8; 64];
            if path.len() >= p.len() {
                ctl(c, TRACE_OP_SET_MASK, prev as u64);
                return usage();
            }
            p[..path.len()].copy_from_slice(path);
            const O_WRONLY: u64 = 1;
            const O_CREAT: u64 = 0x40;
            const O_TRUNC: u64 = 0x200;
            let f = sys::file_open_typed(&p[..path.len() + 1], O_WRONLY | O_CREAT | O_TRUNC);
            if f < 0 {
                ctl(c, TRACE_OP_SET_MASK, prev as u64);
                return err_rc(b"open", f);
            }
            Some(f as u32)
        }
        None => None,
    };
    // Always printed, `-q` or not: a controller started beside this stream
    // waits for it, so its mask change cannot land before this one.
    {
        let mut hello = Out { buf: [0; 2048], len: 0, file: None, quiet: false };
        hello.s(b"tracectl: stream");
        hello.kx(b"mask", TraceGeometry::mask(base) as u64);
        hello.kv(b"cpus", ncpu as u64);
        hello.s(b"\n");
        hello.flush();
    }
    let mut out = Out { buf: [0; 2048], len: 0, file, quiet: opts.quiet };
    let t0 = sys::vdso_now_ns();
    let mut segs = [Seg::new(0, 0); MAX_SEGS];
    let mut nsegs = 1;
    segs[0] = Seg::new(t0, TraceGeometry::mask(base));
    let mut changes_done_at: Option<u64> = None;
    let deadline = if opts.ms == 0 { u64::MAX } else { t0 + opts.ms * 1_000_000 };
    let (mut read, mut lost) = (0u64, 0u64);
    let mut per_class = [0u64; TRACE_CLASSES as usize];
    // SAFETY: the one reference to the static batch, in a single-threaded program.
    let batch = unsafe { &mut *BATCH_BUF.0.get() };
    let mut n = [0usize; MAX_RINGS];
    'outer: loop {
        let mut any = false;
        for cpu in 0..ncpu {
            let k = cons[cpu].as_mut().unwrap();
            n[cpu] = 0;
            while n[cpu] < BATCH {
                match k.pop() {
                    Pop::Rec(r) => {
                        batch[cpu][n[cpu]] = r;
                        n[cpu] += 1;
                    }
                    Pop::Lost(l) => lost += l as u64,
                    Pop::Empty => break,
                }
            }
            k.release();
            any |= n[cpu] != 0;
        }
        // A mask change (by `tracectl start`/`stop`, or anyone holding
        // Cap<Trace>) opens a new segment.
        // Checked after the batches were taken and before they are booked:
        // a record of this batch that is later than the change belongs to
        // the new segment.
        let now = sys::vdso_now_ns();
        let m = TraceGeometry::mask(base);
        if m != segs[nsegs - 1].mask && nsegs < MAX_SEGS {
            // Dated by the kernel's clock when it can be (the same timebase
            // as the records), else by when this reader saw it.
            let kts = TraceGeometry::mask_ts(base);
            let at = if g.ts_hz != 0 && kts != 0 { (kts as u128 * 1_000_000_000 / g.ts_hz as u128) as u64 } else { now };
            segs[nsegs] = Seg::new(at, m);
            nsegs += 1;
            if opts.mask_changes != 0 && nsegs as u64 > opts.mask_changes && changes_done_at.is_none() {
                changes_done_at = Some(now);
            }
        }
        // Merge the CPUs' batches by timestamp (each batch is in order).
        let mut at = [0usize; MAX_RINGS];
        loop {
            let mut best: Option<usize> = None;
            for cpu in 0..ncpu {
                if at[cpu] < n[cpu] && best.is_none_or(|b| batch[cpu][at[cpu]].ts < batch[b][at[b]].ts) {
                    best = Some(cpu);
                }
            }
            let Some(cpu) = best else { break };
            let r = batch[cpu][at[cpu]];
            at[cpu] += 1;
            emit(&mut out, &r, g.ts_hz);
            let class = trace_event_class(r.event) as usize;
            if class < per_class.len() {
                per_class[class] += 1;
                if g.ts_hz != 0 {
                    let ns = (r.ts as u128 * 1_000_000_000 / g.ts_hz as u128) as u64;
                    seg_book(&mut segs[..nsegs], class as u32, ns);
                }
            }
            read += 1;
            if read >= opts.count {
                break 'outer;
            }
        }
        let now = sys::vdso_now_ns();
        if now >= deadline {
            break;
        }
        if changes_done_at.is_some_and(|t| now >= t + SEG_TAIL_MS * 1_000_000) {
            break;
        }
        if !any {
            sys::sleep(opts.poll_ms);
        }
    }
    let elapsed_ms = (sys::vdso_now_ns() - t0) / 1_000_000;
    // Put the mask back as found.
    ctl(c, TRACE_OP_SET_MASK, prev as u64);
    out.flush();
    if let Some(f) = file {
        let _ = sys::fsync_typed(f);
        let _ = sys::close_typed(f);
    }
    let mut drops = 0u64;
    for cpu in 0..ncpu {
        let k = cons[cpu].as_ref().unwrap();
        drops += k.drops().wrapping_sub(drops0[cpu]) as u64;
    }
    let mut s = Out { buf: [0; 2048], len: 0, file: None, quiet: false };
    s.s(b"tracectl: read ");
    s.dec(read);
    s.s(b" records from ");
    s.dec(ncpu as u64);
    s.s(b" cpus in ");
    s.dec(elapsed_ms);
    s.s(b" ms,");
    s.kv(b"drops", drops);
    s.kv(b"lost", lost);
    s.kv(b"skipped", stale);
    s.s(b"\ntracectl: classes");
    for (cl, v) in per_class.iter().enumerate() {
        if compiled as u32 & (1 << cl) != 0 {
            s.kv(trace_class_name(cl as u32).as_bytes(), *v);
        }
    }
    s.s(b" \n");
    if nsegs > 1 || opts.mask_changes != 0 {
        for (k, seg) in segs[..nsegs].iter().enumerate() {
            s.s(b"tracectl: segment ");
            s.dec(k as u64);
            s.kx(b"mask", seg.mask as u64);
            for (cl, v) in seg.counts.iter().enumerate() {
                if compiled as u32 & (1 << cl) != 0 {
                    s.kv(trace_class_name(cl as u32).as_bytes(), *v);
                }
            }
            s.kv(b"late", seg.late);
            s.kv(b"outside", seg.outside);
            s.kv(b"at_ns", seg.start_ns);
            if seg.outside != 0 {
                s.kv(b"first_outside_ns", seg.first_outside_ns);
            }
            s.s(b" \n");
        }
    }
    s.flush();
    0
}

fn run() -> i32 {
    match sys::arg(1).unwrap_or(b"") {
        b"info" if sys::arg(2).is_none() => info(),
        b"start" => match sys::arg(2) {
            None => set_mask(TRACE_MASK_ALL, b"start"),
            Some(a) if sys::arg(3).is_none() => match parse_classes(a) {
                Some(m) => set_mask(m, b"start"),
                None => usage(),
            },
            _ => usage(),
        },
        b"stop" if sys::arg(2).is_none() => set_mask(0, b"stop"),
        b"stream" => stream(),
        _ => usage(),
    }
}

#[no_mangle]
pub extern "C" fn _start(_a0: usize, a1: usize) -> ! {
    sys::startup_init(a1);
    let code = run();
    sys::exit(code)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(70);
}
