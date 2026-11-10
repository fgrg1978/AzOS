// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `LOGD.ELF`: the sink of the kernel's records (Kconfig `KLOG`).
//!
//! The kernel writes its log lines, its decision records and the actuation
//! telemetry into one region, a ring per source behind one envelope
//! (`azos_records`, layout `azos_rings::region::record`), and grants it by the
//! topology row `MemObj klog.ring` (`READ|MAP`). This program maps it, polls
//! it every `LOGD_POLL_MS`, reads every ring with one reader that hands the
//! records out oldest first (`Merge`), and appends them as text lines to a
//! ring of files (`KLOGn.TXT`, `store.rs`) under the tree its row grants:
//! one append and one `fsync` per period, never one per line. It holds no
//! other authority: it cannot write the region, and it has no endpoint to
//! serve and none to call. The toolbox's `log` reads the files.
//!
//! Nothing here waits on the kernel and the kernel never waits on this: a
//! ring overwrites its oldest record, and a period in which a ring lapped the
//! reader writes a `lost` line saying how many. A record whose envelope names
//! a stale sequence is dropped and counted (a `stale` line). A write the
//! volume refuses puts the reader back where it was, so the next period
//! offers the same records again (the rings are the buffer).
//!
//! A start that finds nothing to do (no region granted, one of another layout,
//! no directory) says so and exits 0: the supervisor restarts a failure, and a
//! restart would find the same.
//!
//! Real-time tasks never do block I/O (owner rule): this program runs at the
//! tools' priority, far from the real-time band.

#![no_std]
#![no_main]

use azos_libsys as sys;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::{addr_of, addr_of_mut};

// The source the kernel pushes with; this side reads and writes text, so the
// producer half is unused here.
#[allow(dead_code)]
#[path = "../../../../crates/drivers/sys/src/klog/wire.rs"]
mod wire;
mod keep;
mod stall;
mod store;

use keep::{Keep, Sample, SAMPLE_BYTES};
use stall::Stall;
use store::{Store, Vol, START_FRESH};
// The record substrate's reader, named by path (the seccomp scanner reads
// `use sys::` lists as function imports).
type Envelope = sys::record::Envelope;
type Merge<const P: usize> = sys::record::Merge<P>;
type Region = sys::record::Region;
type Step = sys::record::Step;
const SOURCE_KLOG: u8 = sys::record::SOURCE_KLOG;
const SOURCE_DECISION: u8 = sys::record::SOURCE_DECISION;
const SOURCE_TELEMETRY: u8 = sys::record::SOURCE_TELEMETRY;
const SOURCE_SECURITY: u8 = sys::record::SOURCE_SECURITY;
use wire::{Record, LINE_MAX};

// A security record's line fits a line's room whole.
const _: () = assert!(20 + 1 + 20 + 1 + 3 + 1 + 2 + 1 + wire::SECURITY_MODULE.len() + 1 + azos_seclog::text::MSG_MAX + 1 <= LINE_MAX);

/// Telemetry budgets tracked in a period (Kconfig `LOGD_TELEMETRY_KEYS`).
const KEYS: usize = azos_limits::LOGD_TELEMETRY_KEYS as usize;

/// Payload bytes the reader keeps per ring: the largest, the kernel log's.
const PAYLOAD: usize = wire::PAYLOAD_BYTES;

/// `O_WRONLY`, `O_CREAT`, `O_TRUNC`, `O_APPEND` (`azos_fs` values).
const O_WRONLY: u64 = 0x1;
const O_CREAT: u64 = 0x40;
const O_TRUNC: u64 = 0x200;
const O_APPEND: u64 = 0x400;

/// The tree the row grants, beneath the root directory.
const DIR: &[u8] = b"fat/";

/// Bytes of one batch: the lines a period's write carries at most.
const BATCH: usize = 4096;

/// The volume, over libsys: opens are beneath the root `Cap<Dir>`, and the
/// write authority is the row's `/fat` tree.
struct SysVol {
    root: u32,
}

impl SysVol {
    /// `fat/KLOGn.TXT\0` for `name`.
    fn path(name: &[u8]) -> ([u8; 32], usize) {
        let mut p = [0u8; 32];
        p[..DIR.len()].copy_from_slice(DIR);
        p[DIR.len()..DIR.len() + name.len()].copy_from_slice(name);
        (p, DIR.len() + name.len())
    }
}

impl Vol for SysVol {
    fn read_file(&mut self, name: &[u8], f: &mut dyn FnMut(&[u8])) -> bool {
        let (p, n) = Self::path(name);
        let h = sys::open_at(self.root, &p[..n], 0);
        if h < 0 {
            return false;
        }
        let mut buf = [0u8; 512];
        loop {
            let r = sys::file_read_typed(h as u32, &mut buf);
            if r <= 0 {
                break;
            }
            f(&buf[..r as usize]);
        }
        let _ = sys::close_typed(h as u32);
        true
    }

    fn append(&mut self, name: &[u8], truncate: bool, data: &[u8]) -> bool {
        let (p, n) = Self::path(name);
        let flags = O_WRONLY | O_CREAT | if truncate { O_TRUNC } else { O_APPEND };
        let h = sys::open_at(self.root, &p[..n], flags);
        if h < 0 {
            return false;
        }
        let mut done = 0;
        while done < data.len() {
            let r = sys::file_write_typed(h as u32, &data[done..]);
            if r <= 0 {
                let _ = sys::close_typed(h as u32);
                return false;
            }
            done += r as usize;
        }
        let ok = sys::fsync_typed(h as u32) >= 0;
        let _ = sys::close_typed(h as u32) >= 0;
        ok
    }
}

/// The sink's page, when the row grants it (Kconfig `SEC_LOG`).
fn map_ack() -> Option<&'static azos_seclog::ack::Page> {
    let (base, bytes) = map_region(azos_abi::cap::SHM_KLOG_ACK)?;
    (bytes >= core::mem::size_of::<azos_seclog::ack::Page>() && base % 8 == 0).then(|| {
        // SAFETY: a read-write mapping of the kernel's page, held for the
        // life of the program, large and aligned enough; every field is an
        // atomic the kernel only reads.
        unsafe { &*(base as *const azos_seclog::ack::Page) }
    })
}

fn say(b: &[u8]) {
    let _ = sys::console_write(sys::STDOUT, b);
}

/// Map the ring the row grants: `(base, bytes)`.
fn map_ring() -> Option<(usize, usize)> {
    map_region(azos_abi::cap::SHM_KLOG_RING)
}

/// Map the kernel-owned region of key `key` the row grants: `(base, bytes)`.
fn map_region(key: u32) -> Option<(usize, usize)> {
    let cap = sys::cap_lookup(sys::ty::SHM.raw(), key);
    if cap < 0 {
        return None;
    }
    let mut info = [0u8; sys::SHM_INFO_BYTES];
    if sys::shm_acquire_typed(cap as u32, &mut info) < 0 {
        return None;
    }
    let pages = u32::from_le_bytes([info[0], info[1], info[2], info[3]]) as usize;
    let va = sys::shm_map_typed(cap as u32);
    (va > 0).then_some((va as usize, pages * sys::PAGE_SIZE))
}

/// A line `logd` itself writes: a notice, under its own module.
fn notice(out: &mut [u8], level: u8, seq: u64, ts: u64, hz: u64, msg: &[u8]) -> usize {
    let r = Record::make(seq, ts, level, 0, 0, "logd", msg);
    wire::line(&r, hz, out)
}

/// Decimal digits of `v` appended to `out` at `*n`.
fn put_dec(out: &mut [u8], n: &mut usize, mut v: u64) {
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
    for &b in &d[i..] {
        if *n < out.len() {
            out[*n] = b;
            *n += 1;
        }
    }
}

fn put(out: &mut [u8], n: &mut usize, b: &[u8]) {
    for &x in b {
        if *n < out.len() {
            out[*n] = x;
            *n += 1;
        }
    }
}

/// `n` in decimal after `prefix`, as a message.
fn msg_num(prefix: &[u8], n: u64, out: &mut [u8; 96]) -> usize {
    let mut k = 0;
    put(out, &mut k, prefix);
    put_dec(out, &mut k, n);
    k
}

fn word(p: &[u8], i: usize) -> u64 {
    p.get(i * 8..i * 8 + 8).map_or(0, |b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// The text of a record of another source than the kernel log (a decision
/// record, a telemetry event): its numbers, under the module
/// [`wire::DECISION_MODULE`] / [`wire::TELEMETRY_MODULE`]; `why` and the
/// exporters name them.
fn other_msg(env: &Envelope, payload: &[u8], out: &mut [u8; 160]) -> usize {
    let mut n = 0;
    if env.source == SOURCE_DECISION {
        // The id `why` and a receipt name: the ring index plus one.
        put(out, &mut n, b"id=");
        put_dec(out, &mut n, env.seq + 1);
        put(out, &mut n, b" rule=");
        put_dec(out, &mut n, (env.kind & 0xff) as u64);
        put(out, &mut n, b" verdict=");
        put_dec(out, &mut n, (env.kind >> 8) as u64);
        put(out, &mut n, b" subject=");
        put_dec(out, &mut n, word(payload, 0));
        put(out, &mut n, b" n=");
        for i in 0..3 {
            if i > 0 {
                put(out, &mut n, b",");
            }
            put_dec(out, &mut n, word(payload, 1 + i));
        }
        if env.flags & sys::record::FLAG_CLOCK_UNCALIBRATED != 0 {
            put(out, &mut n, b" clock=uncalibrated");
        }
    } else {
        put(out, &mut n, b"kind=");
        put_dec(out, &mut n, env.kind as u64);
        put(out, &mut n, b" flags=");
        put_dec(out, &mut n, env.flags as u64);
        put(out, &mut n, b" payload=");
        for &b in &payload[..(env.len as usize).min(payload.len())] {
            put(out, &mut n, &[b"0123456789abcdef"[(b >> 4) as usize], b"0123456789abcdef"[(b & 15) as usize]]);
        }
    }
    n
}

/// The line of one record of the region, whatever its source.
fn render(env: &Envelope, payload: &[u8], hz: u64, out: &mut [u8]) -> Option<usize> {
    match env.source {
        SOURCE_KLOG => {
            if env.kind as u8 > azos_limits::LOGD_MAX_LEVEL as u8 {
                return None;
            }
            let r = Record::decode(env.seq, env.ts, env.kind as u8, env.flags, env.cpu, env.len, payload);
            Some(wire::line(&r, hz, out))
        }
        SOURCE_SECURITY => {
            // Longer than a kernel log record's message: rendered whole, never cut.
            let mut m = [0u8; azos_seclog::text::MSG_MAX];
            let k = azos_seclog::text::render(env, payload, &mut m);
            Some(wire::line_of(env.seq, env.ts, hz, env.cpu, wire::LEVEL_INFO, false, wire::SECURITY_MODULE, &m[..k], out))
        }
        SOURCE_DECISION | SOURCE_TELEMETRY => {
            let module = if env.source == SOURCE_DECISION { wire::DECISION_MODULE } else { wire::TELEMETRY_MODULE };
            let mut m = [0u8; 160];
            let k = other_msg(env, payload, &mut m);
            let r = Record::make(env.seq, env.ts, wire::LEVEL_INFO, 0, env.cpu, core::str::from_utf8(module).unwrap_or("-"), &m[..k]);
            Some(wire::line(&r, hz, out))
        }
        _ => None,
    }
}

fn sample_of(env: &Envelope, payload: &[u8]) -> Sample {
    let mut p = [0u8; SAMPLE_BYTES];
    let n = payload.len().min(SAMPLE_BYTES);
    p[..n].copy_from_slice(&payload[..n]);
    Sample { seq: env.seq, ts: env.ts, kind: env.kind, flags: env.flags, cpu: env.cpu, len: env.len, payload: p }
}

fn env_of(s: &Sample) -> (Envelope, [u8; SAMPLE_BYTES]) {
    let env = Envelope { seq: s.seq, ts: s.ts, clock: 0, source: SOURCE_TELEMETRY, kind: s.kind, len: s.len, cpu: s.cpu, flags: s.flags };
    (env, s.payload)
}

/// The ring of `source` in the region, if it has one.
fn ring_index(region: &Region, source: u8) -> Option<usize> {
    (0..region.rings()).find(|&i| region.ring(i).is_some_and(|r| r.source() == source))
}

/// The sink's state, in `.bss`: two readers of every ring and the batch are
/// over half the stack the image asks for.
struct SinkCell(UnsafeCell<MaybeUninit<Sink>>);
// SAFETY: logd runs one thread, and only `run`, entered once, reaches it.
unsafe impl Sync for SinkCell {}
static SINK: SinkCell = SinkCell(UnsafeCell::new(MaybeUninit::uninit()));

/// The sink's state: the region, the files, and how far it has read.
struct Sink {
    vol: SysVol,
    store: Store,
    hz: u64,
    /// The reader: a cursor per ring.
    rd: Merge<PAYLOAD>,
    /// The reader as of the last write the files hold: a failed write puts
    /// `rd` back to it.
    committed: Merge<PAYLOAD>,
    /// The unfinished record the reader is waiting on.
    stall: Stall,
    /// Which decision records reach the files.
    keep: Keep<KEYS>,
    /// Periods whose write the volume took, up to the two that print the
    /// marker the gate's read-back row waits for.
    written: u32,
    batch: [u8; BATCH],
    n: usize,
    /// The security ring, and the page where the sink says which of its
    /// records it lost (`MemObj klog.ack`).
    sec: Option<usize>,
    ack: Option<&'static azos_seclog::ack::Page>,
}

impl Sink {
    /// The security records from `first`, `count` of them, will never be
    /// written: say so on the page, for the kernel to declare.
    fn claim(&self, ring: usize, first: u64, count: u64) {
        if let (Some(p), true) = (self.ack, self.sec == Some(ring)) {
            p.claim(first, count);
        }
    }

    /// The tick of `now`, in the region's timebase.
    fn ticks(&self) -> u64 {
        (sys::vdso_now_ns() as u128 * self.hz as u128 / 1_000_000_000) as u64
    }

    /// Write the batch. False (and the reader back at the last write) when
    /// the volume refused.
    fn flush(&mut self) -> bool {
        if self.n == 0 {
            self.committed = self.rd;
            return true;
        }
        let ts = self.ticks();
        if self.store.write(&mut self.vol, &self.batch[..self.n], ts, self.hz) {
            self.n = 0;
            self.committed = self.rd;
            if let (Some(p), Some(i)) = (self.ack, self.sec) {
                p.next.store(self.rd.cursor(i), core::sync::atomic::Ordering::Release);
            }
            true
        } else {
            self.n = 0;
            self.rd = self.committed;
            false
        }
    }

    /// Add a notice: ring `ring`'s source, `prefix` and `count`, at that
    /// ring's cursor.
    fn note(&mut self, ring: usize, prefix: &[u8], count: u64) {
        let name: &[u8] = match self.rd.region().ring(ring).map(|r| r.source()) {
            Some(SOURCE_KLOG) => b"klog: ",
            Some(SOURCE_DECISION) => b"decision: ",
            Some(SOURCE_TELEMETRY) => b"telemetry: ",
            Some(SOURCE_SECURITY) => b"security: ",
            _ => b"",
        };
        let mut p = [0u8; 64];
        p[..name.len()].copy_from_slice(name);
        p[name.len()..name.len() + prefix.len()].copy_from_slice(prefix);
        let mut m = [0u8; 96];
        let k = msg_num(&p[..name.len() + prefix.len()], count, &mut m);
        let ts = self.ticks();
        let seq = self.rd.cursor(ring).saturating_sub(1);
        self.n += notice(&mut self.batch[self.n..], wire::LEVEL_WARN, seq, ts, self.hz, &m[..k]);
    }

    /// Is a ring other than `ring` more than half a lap past the reader?
    fn other_ring_late(&self, ring: usize) -> bool {
        (0..self.rd.region().rings()).filter(|&i| i != ring).any(|i| {
            self.rd.region().ring(i).is_some_and(|r| r.head().saturating_sub(self.rd.cursor(i)) > r.entries() / 2)
        })
    }

    /// One period: everything the region has, in as few writes as fit.
    fn drain(&mut self) {
        let mut env = Envelope::default();
        let mut payload = [0u8; PAYLOAD];
        loop {
            if self.n + LINE_MAX > BATCH && !self.flush() {
                return;
            }
            match self.rd.next(&mut env, &mut payload) {
                Step::Record { .. } => {
                    self.stall.clear();
                    if env.source == SOURCE_DECISION && !self.keep.admit((env.kind >> 8) as u8) {
                        continue;
                    }
                    if env.source == SOURCE_TELEMETRY && !self.keep.admit_telemetry(&sample_of(&env, &payload)) {
                        continue;
                    }
                    if let Some(k) = render(&env, &payload, self.hz, &mut self.batch[self.n..]) {
                        self.n += k;
                    }
                }
                Step::Lost { ring, n } => {
                    let c = self.rd.cursor(ring);
                    self.claim(ring, c.saturating_sub(n), n);
                    self.note(ring, b"records lost: ", n)
                }
                Step::Stale { ring } => self.note(ring, b"records dropped (stale sequence): ", self.rd.stale(ring)),
                Step::Pending { ring } => {
                    // A producer claimed it and has not finished: try again
                    // next period, and give up on it if it never does.
                    let c = self.rd.cursor(ring);
                    let (head, entries) = self.rd.region().ring(ring).map_or((c, 0), |r| (r.head(), r.entries()));
                    let late = self.other_ring_late(ring);
                    if self.stall.give_up(ring, c, head.saturating_sub(c), entries, late) {
                        self.rd.skip(ring);
                        self.claim(ring, self.rd.cursor(ring).saturating_sub(1), 1);
                        self.note(ring, b"records lost: ", 1);
                        continue;
                    }
                    break;
                }
                Step::Empty => break,
            }
        }
        let held = self.keep.period();
        if held > 0 {
            if let Some(i) = ring_index(self.rd.region(), SOURCE_DECISION) {
                self.note(i, b"records held back by LOGD_DECISIONS_PER_SEC: ", held);
            }
        }
        // What the budgets held back: each bucket's newest sample, then the count.
        while let Some((sample, held)) = self.keep.telemetry_held() {
            let (env, payload) = env_of(&sample);
            if self.n + LINE_MAX > BATCH && !self.flush() {
                return;
            }
            if let Some(k) = render(&env, &payload, self.hz, &mut self.batch[self.n..]) {
                self.n += k;
            }
            if let Some(i) = ring_index(self.rd.region(), SOURCE_TELEMETRY) {
                self.note(i, b"records held back by LOGD_TELEMETRY_PER_SEC: ", held);
            }
        }
        let unplaced = self.keep.telemetry_period();
        if unplaced > 0 {
            if let Some(i) = ring_index(self.rd.region(), SOURCE_TELEMETRY) {
                self.note(i, b"records held back for want of LOGD_TELEMETRY_KEYS: ", unplaced);
            }
        }
        if self.flush() && self.written < 2 {
            self.written += 1;
            if self.written == 2 {
                say(b"[logd] two periods on the volume\n");
            }
        }
    }
}

/// `region`'s reader from every ring's oldest record, into `m`: the value is
/// built on this frame, not on the caller's.
#[inline(never)]
fn reader_into(m: &mut MaybeUninit<Merge<PAYLOAD>>, region: Region) {
    m.write(Merge::oldest(region));
}

/// Find the files' state and set the sink up in its cell, resumed after the
/// files' last records when it can be (true). Its own frame, not `run`'s: the
/// files' scan and the resume's line are several KiB, and the drain never
/// needs them.
#[inline(never)]
fn open(region: Region, root: u32) -> (&'static mut Sink, bool) {
    let mut vol = SysVol { root };
    let limit = azos_limits::LOGD_FILE_KB as u64 * 1024;
    let (store, tail) = Store::recover(&mut vol, azos_limits::LOGD_FILES_KEEP as u8, limit);
    let hz = region.ts_hz();
    let keep = Keep::<KEYS>::new(azos_limits::LOGD_DECISIONS_ALL, azos_limits::LOGD_DECISIONS_PER_SEC as u64,
        azos_limits::LOGD_TELEMETRY_PER_SEC as u64, azos_limits::LOGD_POLL_MS as u64);
    let p: *mut Sink = SINK.0.get().cast();
    // SAFETY: one thread, and `open` is called once: nothing else reaches the
    // cell. Field by field, in place (a `Sink` value would be built on this
    // frame first), and the reference is taken after the last field.
    let sink = unsafe {
        reader_into(&mut *addr_of_mut!((*p).rd).cast(), region);
        addr_of_mut!((*p).committed).copy_from_nonoverlapping(addr_of!((*p).rd), 1);
        addr_of_mut!((*p).batch).write_bytes(0, 1);
        addr_of_mut!((*p).vol).write(vol);
        addr_of_mut!((*p).store).write(store);
        addr_of_mut!((*p).hz).write(hz);
        addr_of_mut!((*p).stall).write(Stall::new());
        addr_of_mut!((*p).keep).write(keep);
        addr_of_mut!((*p).written).write(0);
        addr_of_mut!((*p).n).write(0);
        addr_of_mut!((*p).sec).write(ring_index(&region, SOURCE_SECURITY));
        addr_of_mut!((*p).ack).write(map_ack());
        &mut *p
    };
    let rd = &mut sink.rd;

    // Resume after the files' last records when the kernel log's ring still
    // holds the last one (the same boot): every ring after its own last line.
    // Anything else starts every ring at its oldest record.
    let mut resumed = false;
    if let (Some(t), Some(k)) = (&tail, ring_index(&region, SOURCE_KLOG)) {
        if let (Some(seq), Some(ring)) = (t.rec_seq(), region.ring(k)) {
            let (mut c, mut env, mut payload) = (seq, Envelope::default(), [0u8; PAYLOAD]);
            if ring.read(&mut c, &mut env, &mut payload) == sys::record::Read::Record {
                let mut line = [0u8; LINE_MAX];
                let r = Record::decode(env.seq, env.ts, env.kind as u8, env.flags, env.cpu, env.len, &payload);
                let n = wire::line(&r, hz, &mut line);
                if t.matches(seq, &line[..n - 1]) {
                    rd.seek(k, (seq + 1).min(ring.head()));
                    for (source, last) in
                        [(SOURCE_DECISION, t.last_decision), (SOURCE_TELEMETRY, t.last_telemetry), (SOURCE_SECURITY, t.last_security)]
                    {
                        if let (Some(i), Some(s)) = (ring_index(&region, source), last) {
                            let r = region.ring(i);
                            rd.seek(i, (s + 1).max(r.map_or(0, |r| r.oldest())).min(r.map_or(0, |r| r.head())));
                        }
                    }
                    resumed = true;
                }
            }
        }
    }
    sink.committed = sink.rd;
    (sink, resumed)
}

#[sys::main(panic_exit = 70)]
fn run() -> i32 {
    let Some((base, bytes)) = map_ring() else {
        // Nothing to sink, and a restart would not change it.
        say(b"logd: no klog.ring granted (Kconfig KLOG off, or the row has none)\n");
        return 0;
    };
    // SAFETY: a read-only mapping of the kernel's region, held for the life
    // of the program; `open` checks it is one.
    let Some(region) = (unsafe { sys::record::Region::open(base as *const u8, bytes) }) else {
        say(b"logd: the klog.ring is not a record region this build reads\n");
        return 0;
    };
    let root = sys::root_dir();
    if root < 0 {
        say(b"logd: no root directory granted\n");
        return 0;
    }
    let (sink, resumed) = open(region, root as u32);
    let hz = sink.hz;
    say(b"[logd] AzOS record sink (klog.ring to KLOGn.TXT)\n");
    // What the ring dropped before this run read it, and no earlier run
    // wrote (the page's `next` is where the last one stopped): lost.
    if let (Some(p), Some(i)) = (sink.ack, sink.sec) {
        let (start, before) = (sink.rd.cursor(i), p.next.load(core::sync::atomic::Ordering::Acquire));
        if start > before {
            sink.claim(i, before, start - before);
        }
    }
    // The start line: where this run begins, so a reader of the files sees the
    // seam (a new boot, or a restart).
    {
        let ts = sink.ticks();
        let seq = ring_index(&region, SOURCE_KLOG).map_or(0, |k| sink.rd.cursor(k)).saturating_sub(1);
        let msg: &[u8] = if resumed { b"start: resumed after the last record" } else { START_FRESH };
        sink.n += notice(&mut sink.batch, wire::LEVEL_INFO, seq, ts, hz, msg);
        // The security records' reader starts afresh too: the verifier's seam.
        if !resumed && ring_index(&region, SOURCE_SECURITY).is_some() {
            let mut m = [0u8; 16];
            let k = azos_seclog::text::render_seam(&mut m);
            let n = sink.n;
            sink.n += notice(&mut sink.batch[n..], wire::LEVEL_INFO, seq, ts, hz, &m[..k]);
        }
    }
    let period_ns = azos_limits::LOGD_POLL_MS as u64 * 1_000_000;
    let mut next = sys::vdso_now_ns() + period_ns;
    loop {
        sink.drain();
        if let Some(p) = sink.ack {
            p.beat.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        let _ = sys::sleep_until_ns(next);
        next = next.max(sys::vdso_now_ns()) + period_ns;
    }
}
