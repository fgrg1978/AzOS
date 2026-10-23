// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of the block request layer (`crates/drivers/block/src/queue.rs`,
//! the real file) over a fake hardware queue: a RAM disk with a controller's
//! shape (a few command slots, completions that arrive on `reap`, a volatile
//! cache that only a flush makes durable) and a log of every command the
//! layer started.

use crate::queue::*;
use azos_devif::block::{BlockRequest, FLAG_FUA, FLAG_PREFLUSH, OWNER_NONE, REQ_DISCARD};
use azos_devif::outcome;
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

thread_local! {
    /// The CPU the current test thread "runs on".
    static CPU: Cell<usize> = const { Cell::new(0) };
}

/// One command the layer started.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Started {
    op: HwOp,
    lba: u64,
    sectors: u32,
    fua: bool,
    segs: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ev {
    Start(HwOp),
    Done(HwOp),
}

struct Slot {
    cmd: Started,
    status: HwStatus,
    data: Vec<u8>,
}

struct Inner {
    /// What a power cut leaves.
    durable: Vec<u8>,
    /// What a read sees: durable plus the writes the cache still holds.
    cache: Vec<u8>,
    slots: Vec<Option<Slot>>,
    /// Slots whose command the device has finished (reaped on the next call).
    finished: Vec<u8>,
    log: Vec<Started>,
    events: Vec<Ev>,
    in_flight_max: usize,
}

struct Fake {
    inner: Mutex<Inner>,
    sectors: u64,
    max_sectors: u32,
    /// Sectors a discard command covers at most (0: the device has none).
    max_discard: u32,
    /// The device has a native FUA.
    fua: bool,
    /// Completions are held until `thaw`.
    hold: AtomicBool,
    dead: AtomicBool,
    /// The next command the layer starts never completes: after
    /// `STALL_BUDGET_MS` in the device `reap` reports it `HwStatus::Timeout`
    /// and the device is dead (a driver's budget running out).
    stall: AtomicBool,
    stuck: Mutex<Vec<(u8, std::time::Instant)>>,
    /// The next write command fails.
    fail_write: AtomicBool,
    /// The next command is abandoned by a reset of the device (another
    /// command's budget ran out): `HwStatus::Reset`, the device alive.
    abandon: AtomicBool,
    /// Flush answers.
    flush_status: Mutex<HwStatus>,
    /// Discard answers.
    discard_status: Mutex<HwStatus>,
    starts: AtomicUsize,
    /// Microseconds a `reap` takes (widens the window in which tasks
    /// interleave).
    reap_us: AtomicUsize,
    /// Milliseconds a `wait` sleeps in the "device" (0: it does not sleep).
    wait_ms: AtomicUsize,
}

impl Fake {
    fn new(sectors: u64, max_sectors: u32, tags: usize) -> Fake {
        let bytes = sectors as usize * SECTOR;
        Fake {
            inner: Mutex::new(Inner {
                durable: vec![0; bytes],
                cache: vec![0; bytes],
                slots: (0..tags).map(|_| None).collect(),
                finished: Vec::new(),
                log: Vec::new(),
                events: Vec::new(),
                in_flight_max: 0,
            }),
            sectors,
            max_sectors,
            max_discard: 8,
            fua: true,
            hold: AtomicBool::new(false),
            dead: AtomicBool::new(false),
            stall: AtomicBool::new(false),
            stuck: Mutex::new(Vec::new()),
            fail_write: AtomicBool::new(false),
            abandon: AtomicBool::new(false),
            flush_status: Mutex::new(HwStatus::Ok),
            discard_status: Mutex::new(HwStatus::Ok),
            starts: AtomicUsize::new(0),
            reap_us: AtomicUsize::new(0),
            wait_ms: AtomicUsize::new(0),
        }
    }

    fn thaw(&self) {
        self.hold.store(false, Ordering::SeqCst);
    }

    fn log(&self) -> Vec<Started> {
        self.inner.lock().unwrap().log.clone()
    }

    fn events(&self) -> Vec<Ev> {
        self.inner.lock().unwrap().events.clone()
    }

    fn count(&self, op: HwOp) -> usize {
        self.log().iter().filter(|c| c.op == op).count()
    }

    fn medium(&self, sector: u64, count: u32) -> Vec<u8> {
        let g = self.inner.lock().unwrap();
        g.cache[sector as usize * SECTOR..(sector as usize + count as usize) * SECTOR].to_vec()
    }

    fn durable(&self, sector: u64, count: u32) -> Vec<u8> {
        let g = self.inner.lock().unwrap();
        g.durable[sector as usize * SECTOR..(sector as usize + count as usize) * SECTOR].to_vec()
    }
}

/// How long `Fake` lets a stalled command sit before it reports the timeout.
const STALL_BUDGET_MS: u64 = 5;

/// What the request layer reported through its sink: `(action, sector,
/// waited_ms)`. Process-wide, so each test reads only the sectors it owns.
static REPORTED: Mutex<Vec<(TimeoutAction, u64, u64)>> = Mutex::new(Vec::new());

fn capture(action: TimeoutAction, sector: u64, waited_ms: u64) {
    REPORTED.lock().unwrap().push((action, sector, waited_ms));
}

fn reported_for(sectors: &[u64]) -> Vec<(TimeoutAction, u64, u64)> {
    set_timeout_sink(capture);
    REPORTED.lock().unwrap().iter().copied().filter(|r| sectors.contains(&r.1)).collect()
}

impl HwQueue for Fake {
    fn caps(&self) -> HwCaps {
        HwCaps { sectors: self.sectors, max_sectors: self.max_sectors, max_discard_sectors: self.max_discard, fua: self.fua }
    }

    fn cpu(&self) -> usize {
        CPU.with(|c| c.get())
    }

    fn claim(&self) -> Claim {
        if self.dead.load(Ordering::SeqCst) {
            return Claim::Dead;
        }
        let mut g = self.inner.lock().unwrap();
        // A claimed-but-not-started slot is marked by a placeholder.
        for (i, s) in g.slots.iter_mut().enumerate() {
            if s.is_none() {
                *s = Some(Slot {
                    cmd: Started { op: HwOp::Flush, lba: 0, sectors: 0, fua: false, segs: 0 },
                    status: HwStatus::Ok,
                    data: Vec::new(),
                });
                return Claim::Tag(i as u8);
            }
        }
        Claim::Busy
    }

    fn start(&self, tag: u8, cmd: &HwCmd<'_>) -> Result<(), ()> {
        if self.dead.load(Ordering::SeqCst) {
            return Err(());
        }
        self.starts.fetch_add(1, Ordering::SeqCst);
        let mut g = self.inner.lock().unwrap();
        let started =
            Started { op: cmd.op, lba: cmd.lba, sectors: cmd.sectors, fua: cmd.fua, segs: cmd.segs.len() };
        g.log.push(started.clone());
        g.events.push(Ev::Start(cmd.op));
        let mut status = HwStatus::Ok;
        let (lo, hi) = (cmd.lba as usize * SECTOR, (cmd.lba as usize + cmd.sectors as usize) * SECTOR);
        let mut data = Vec::new();
        match cmd.op {
            HwOp::Write => {
                if self.fail_write.swap(false, Ordering::SeqCst) {
                    status = HwStatus::Io;
                } else {
                    let mut at = lo;
                    for s in cmd.segs {
                        g.cache[at..at + s.len()].copy_from_slice(s);
                        if cmd.fua {
                            g.durable[at..at + s.len()].copy_from_slice(s);
                        }
                        at += s.len();
                    }
                    assert_eq!(at, hi, "the segments cover the command");
                }
            }
            HwOp::Read => data = g.cache[lo..hi].to_vec(),
            HwOp::Flush => {
                status = *self.flush_status.lock().unwrap();
                if status == HwStatus::Ok {
                    let c = g.cache.clone();
                    g.durable = c;
                }
            }
            HwOp::Discard => {
                status = *self.discard_status.lock().unwrap();
                if status == HwStatus::Ok {
                    for b in &mut g.cache[lo..hi] {
                        *b = 0;
                    }
                }
            }
        }
        if self.abandon.swap(false, Ordering::SeqCst) {
            status = HwStatus::Reset;
        }
        let busy = g.slots.iter().filter(|s| s.is_some()).count();
        g.in_flight_max = g.in_flight_max.max(busy);
        g.slots[tag as usize] = Some(Slot { cmd: started, status, data });
        if self.stall.swap(false, Ordering::SeqCst) {
            self.stuck.lock().unwrap().push((tag, std::time::Instant::now()));
        } else {
            g.finished.push(tag);
        }
        Ok(())
    }

    fn reap(&self, out: &mut [HwDone; HW_TAGS_MAX]) -> usize {
        if self.hold.load(Ordering::SeqCst) {
            return 0;
        }
        let us = self.reap_us.load(Ordering::SeqCst);
        if us > 0 {
            std::thread::sleep(std::time::Duration::from_micros(us as u64));
        }
        let mut g = self.inner.lock().unwrap();
        let tags: Vec<u8> = g.finished.drain(..).collect();
        for (n, &t) in tags.iter().enumerate() {
            let (op, status) = {
                let s = g.slots[t as usize].as_ref().unwrap();
                (s.cmd.op, s.status)
            };
            g.events.push(Ev::Done(op));
            out[n] = HwDone { tag: t, status };
        }
        let mut n = tags.len();
        let mut stuck = self.stuck.lock().unwrap();
        stuck.retain(|&(t, since)| {
            if since.elapsed() < std::time::Duration::from_millis(STALL_BUDGET_MS) {
                return true;
            }
            self.dead.store(true, Ordering::SeqCst);
            out[n] = HwDone { tag: t, status: HwStatus::Timeout };
            n += 1;
            false
        });
        n
    }

    fn copy_out(&self, tag: u8, off: usize, dst: &mut [u8]) {
        let g = self.inner.lock().unwrap();
        let s = g.slots[tag as usize].as_ref().unwrap();
        dst.copy_from_slice(&s.data[off..off + dst.len()]);
    }

    fn release(&self, tag: u8) {
        self.inner.lock().unwrap().slots[tag as usize] = None;
    }

    fn wait(&self, _until_ns: u64) -> bool {
        match self.wait_ms.load(Ordering::SeqCst) {
            0 => false,
            ms => {
                std::thread::sleep(std::time::Duration::from_millis(ms as u64));
                true
            }
        }
    }
}

/// A queue under the plain deadline scheduler: every slot is an ordinary
/// request's, and the order is the deadline's. The tests of the other
/// schedulers say so ([`queue_with`]).
fn queue() -> &'static ReqQueue {
    queue_with(Sched::MqDeadline)
}

fn queue_with(sched: Sched) -> &'static ReqQueue {
    Box::leak(Box::new(ReqQueue::with_sched(sched)))
}

const ALL_SCHEDS: [Sched; 3] = [Sched::None, Sched::MqDeadline, Sched::RtDeadline];

thread_local! {
    /// Whether the requests this test thread submits serve a durable record
    /// that waits for the medium, as the request layer is told (the kernel's
    /// source is the flight recorder's flusher and the write-back passes).
    static SERVES_RECORD: Cell<bool> = const { Cell::new(false) };
}

fn serves_record_now() -> bool {
    SERVES_RECORD.with(|d| d.get())
}

fn set_serving_record(on: bool) {
    set_rt_class_source(serves_record_now);
    SERVES_RECORD.with(|d| d.set(on));
}

fn pattern(sector: u64, count: u32, salt: u8) -> Vec<u8> {
    (0..count as usize * SECTOR).map(|i| (i as u64 + sector * 31 + salt as u64) as u8 ^ (i >> 9) as u8).collect()
}

fn write(q: &ReqQueue, hw: &Fake, sector: u64, count: u32, flags: u32, salt: u8) -> Result<(), Failure> {
    let mut b = pattern(sector, count, salt);
    q.transfer(hw, 7, true, sector, count, flags, b.as_mut_ptr(), b.len())
}

fn read(q: &ReqQueue, hw: &Fake, sector: u64, count: u32) -> Result<Vec<u8>, Failure> {
    let mut b = vec![0u8; count as usize * SECTOR];
    q.transfer(hw, 7, false, sector, count, 0, b.as_mut_ptr(), b.len())?;
    Ok(b)
}

/// Submit a write of `count` sectors plugged and return its ticket and
/// buffer (kept alive by the caller until the ticket is waited for).
fn plugged_write(p: &Plug<'_>, owner: u32, sector: u64, count: u32, flags: u32, buf: &mut Vec<u8>) -> Ticket {
    *buf = pattern(sector, count, 1);
    let mut r = BlockRequest::rw(true, sector, count, owner);
    r.flags = flags;
    // SAFETY: the test waits for the ticket before `buf` is dropped.
    unsafe { p.submit(&r, buf.as_mut_ptr()).unwrap() }
}

// ── Round trips ─────────────────────────────────────────────────────────

/// **`enqueue_only` queues and starts nothing** (the io_ring submit: owner
/// rule, only enqueue). The device sees no command until somebody waits; the
/// wait starts every request queued so far, in one pass, and the data is the
/// submitter's.
///
/// **Canary.** Make `enqueue_only` pump (`submit`): the log is not empty
/// before the wait.
#[test]
fn an_enqueued_request_starts_nothing_until_somebody_waits() {
    let (q, hw) = (queue(), Fake::new(64, 8, 4));
    let mut a = pattern(4, 2, 5);
    let mut b = pattern(6, 2, 6);
    // SAFETY: both buffers outlive the waits below.
    let ta = unsafe { q.enqueue_only(&hw, &BlockRequest::rw(true, 4, 2, 7), a.as_mut_ptr()) }.unwrap();
    let tb = unsafe { q.enqueue_only(&hw, &BlockRequest::rw(true, 6, 2, 7), b.as_mut_ptr()) }.unwrap();
    assert!(hw.log().is_empty(), "an enqueue started a command");
    assert_eq!(hw.starts.load(Ordering::SeqCst), 0);
    // Waiting for the OLDER one runs the device for both: the neighbours merge.
    assert_eq!(q.wait(&hw, ta), Outcome::Ok);
    assert_eq!(hw.log().len(), 1, "two adjacent requests were not one command");
    assert_eq!(q.wait(&hw, tb), Outcome::Ok);
    assert_eq!(hw.medium(4, 2), pattern(4, 2, 5));
    assert_eq!(hw.medium(6, 2), pattern(6, 2, 6));
    // A full hart queue is `Full`, never a sleep.
    let mut bufs = Vec::new();
    let mut tickets = Vec::new();
    loop {
        let mut buf = pattern(0, 1, 0);
        match unsafe { q.enqueue_only(&hw, &BlockRequest::rw(true, 20 + tickets.len() as u64 * 2, 1, 7), buf.as_mut_ptr()) } {
            Ok(t) => tickets.push(t),
            Err(Failure::Full) => break,
            Err(e) => panic!("{e:?}"),
        }
        bufs.push(buf);
    }
    assert!(!tickets.is_empty());
    for t in tickets {
        assert_eq!(q.wait(&hw, t), Outcome::Ok);
    }
}

#[test]
fn a_transfer_cut_into_commands_reads_back_what_was_written() {
    let (q, hw) = (queue(), Fake::new(256, 8, 4));
    write(q, &hw, 20, 43, 0, 3).unwrap();
    // 43 sectors at 8 per command: six requests (the last one 3 sectors),
    // none adjacent-and-queued-together beyond the device's largest command.
    assert_eq!(hw.medium(20, 43), pattern(20, 43, 3));
    assert!(hw.log().iter().all(|c| c.sectors <= 8));
    assert_eq!(hw.log().iter().map(|c| c.sectors).sum::<u32>(), 43);
    assert_eq!(read(q, &hw, 20, 43).unwrap(), pattern(20, 43, 3));
    // Nothing is left in a slot.
    assert!(hw.inner.lock().unwrap().slots.iter().all(|s| s.is_none()));
}

#[test]
fn a_transfer_longer_than_the_queue_is_depth_limited_not_stuck() {
    // More chunks than one hart queue has slots.
    let (q, hw) = (queue(), Fake::new(2048, 1, 2));
    write(q, &hw, 5, 100, 0, 9).unwrap();
    assert_eq!(read(q, &hw, 5, 100).unwrap(), pattern(5, 100, 9));
    assert!(hw.inner.lock().unwrap().in_flight_max <= 2, "never more commands than the device has slots");
}

#[test]
fn out_of_range_and_oversized_requests_are_refused_not_queued() {
    let (q, hw) = (queue(), Fake::new(64, 8, 2));
    let mut b = vec![0u8; 512];
    let r = BlockRequest::rw(false, 64, 1, 7);
    // SAFETY: refused before it is queued; `b` is alive anyway.
    let e = unsafe { q.submit(&hw, &r, b.as_mut_ptr()) };
    assert_eq!(e.unwrap_err(), Failure::Refused(outcome::BAD_ARGUMENT), "one past the medium");
    let too_long = BlockRequest::rw(false, 0, 9, 7);
    let e = unsafe { q.submit(&hw, &too_long, b.as_mut_ptr()) };
    assert_eq!(e.unwrap_err(), Failure::Refused(outcome::BAD_ARGUMENT), "more than one command");
    assert_eq!(q.transfer(&hw, 7, false, 60, 8, 0, b.as_mut_ptr(), 8 * 512), Err(Failure::Refused(outcome::BAD_ARGUMENT)));
    assert_eq!(hw.starts.load(Ordering::SeqCst), 0);
}

// ── The owner ───────────────────────────────────────────────────────────

/// CANARY: a request with no owner is refused, before anything is queued or
/// started, and the layer is unharmed.
#[test]
fn a_request_without_an_owner_is_refused() {
    let (q, hw) = (queue(), Fake::new(64, 8, 2));
    let mut b = vec![0u8; 512];
    let r = BlockRequest::rw(false, 4, 1, OWNER_NONE);
    // SAFETY: refused before it is queued.
    let e = unsafe { q.submit(&hw, &r, b.as_mut_ptr()) };
    assert_eq!(e.unwrap_err(), Failure::Refused(outcome::REFUSED));
    assert_eq!(hw.starts.load(Ordering::SeqCst), 0, "nothing reached the device");
    // The plugged path refuses the same way.
    {
        let p = q.plug(&hw);
        let e = unsafe { p.submit(&r, b.as_mut_ptr()) };
        assert_eq!(e.unwrap_err(), Failure::Refused(outcome::REFUSED));
    }
    assert_eq!(q.transfer(&hw, OWNER_NONE, false, 4, 1, 0, b.as_mut_ptr(), 512), Err(Failure::Refused(outcome::REFUSED)));
    assert_eq!(q.flush(&hw, OWNER_NONE), Err(Failure::Refused(outcome::REFUSED)));
    assert_eq!(hw.starts.load(Ordering::SeqCst), 0);
    // And a request with an owner still goes through.
    assert!(q.transfer(&hw, 7, false, 4, 1, 0, b.as_mut_ptr(), 512).is_ok());
    assert_eq!(hw.starts.load(Ordering::SeqCst), 1);
}

#[test]
fn a_request_naming_a_memobj_is_unsupported_here() {
    let (q, hw) = (queue(), Fake::new(64, 8, 2));
    let mut b = vec![0u8; 512];
    let r = BlockRequest { mem: 3, mem_off: 0, ..BlockRequest::rw(false, 4, 1, 7) };
    let e = unsafe { q.submit(&hw, &r, b.as_mut_ptr()) };
    assert_eq!(e.unwrap_err(), Failure::Refused(outcome::UNSUPPORTED));
}

// ── Plug and merge ──────────────────────────────────────────────────────

#[test]
fn a_plug_holds_requests_back_until_it_drops() {
    let (q, hw) = (queue(), Fake::new(64, 16, 4));
    let mut b = Vec::new();
    let t;
    {
        let p = q.plug(&hw);
        t = plugged_write(&p, 7, 8, 4, 0, &mut b);
        q.pump(&hw);
        assert_eq!(hw.starts.load(Ordering::SeqCst), 0, "a pump of another task does not take a plugged request");
    }
    assert_eq!(hw.starts.load(Ordering::SeqCst), 1, "unplugging started it");
    assert_eq!(q.wait(&hw, t), Outcome::Ok);
}

#[test]
fn adjacent_requests_of_one_owner_from_two_harts_are_one_command() {
    // One device slot, taken by a blocker: the two requests of two harts pile
    // up in the queues, and are one command when the slot frees.
    let (q, hw) = (queue(), Fake::new(128, 16, 1));
    hw.hold.store(true, Ordering::SeqCst);
    let (mut blocker, mut b1, mut b2) = (vec![0u8; 512], pattern(8, 4, 1), pattern(12, 4, 1));
    // SAFETY: every ticket is waited for below, before the buffers drop.
    let (tb, t1, t2) = unsafe {
        CPU.with(|c| c.set(0));
        let tb = q.submit(&hw, &BlockRequest::rw(false, 100, 1, 7), blocker.as_mut_ptr()).unwrap();
        let t1 = q.submit(&hw, &BlockRequest::rw(true, 8, 4, 7), b1.as_mut_ptr()).unwrap();
        CPU.with(|c| c.set(1));
        let t2 = q.submit(&hw, &BlockRequest::rw(true, 12, 4, 7), b2.as_mut_ptr()).unwrap();
        (tb, t1, t2)
    };
    CPU.with(|c| c.set(0));
    hw.thaw();
    for t in [tb, t1, t2] {
        assert_eq!(q.wait(&hw, t), Outcome::Ok);
    }
    assert_eq!(
        hw.log(),
        vec![
            Started { op: HwOp::Read, lba: 100, sectors: 1, fua: false, segs: 0 },
            Started { op: HwOp::Write, lba: 8, sectors: 8, fua: false, segs: 2 },
        ]
    );
    assert_eq!(hw.medium(8, 4), pattern(8, 4, 1));
    assert_eq!(hw.medium(12, 4), pattern(12, 4, 1));
}

#[test]
fn a_neighbour_in_front_merges_too_and_keeps_its_bytes_in_place() {
    let (q, hw) = (queue(), Fake::new(128, 16, 4));
    let (mut b1, mut b2, mut b3) = (Vec::new(), Vec::new(), Vec::new());
    let (t1, t2, t3);
    {
        let p = q.plug(&hw);
        // Submitted out of order: 16, 8, 12.
        t1 = plugged_write(&p, 7, 16, 4, 0, &mut b1);
        t2 = plugged_write(&p, 7, 8, 4, 0, &mut b2);
        t3 = plugged_write(&p, 7, 12, 4, 0, &mut b3);
    }
    for t in [t1, t2, t3] {
        assert_eq!(q.wait(&hw, t), Outcome::Ok);
    }
    assert_eq!(hw.log(), vec![Started { op: HwOp::Write, lba: 8, sectors: 12, fua: false, segs: 3 }]);
    for s in [8u64, 12, 16] {
        assert_eq!(hw.medium(s, 4), pattern(s, 4, 1), "sector {s}");
    }
}

#[test]
fn reads_merged_into_one_command_each_get_their_own_bytes() {
    let (q, hw) = (queue(), Fake::new(128, 16, 4));
    write(q, &hw, 0, 32, 0, 5).unwrap();
    let before = hw.log().len();
    let (mut b1, mut b2) = (vec![0u8; 4 * SECTOR], vec![0u8; 4 * SECTOR]);
    let (t1, t2);
    {
        let p = q.plug(&hw);
        let r1 = BlockRequest::rw(false, 4, 4, 7);
        let r2 = BlockRequest::rw(false, 8, 4, 7);
        // SAFETY: both are waited for below, before the buffers drop.
        t1 = unsafe { p.submit(&r1, b1.as_mut_ptr()).unwrap() };
        t2 = unsafe { p.submit(&r2, b2.as_mut_ptr()).unwrap() };
    }
    assert_eq!(q.wait(&hw, t1), Outcome::Ok);
    assert_eq!(q.wait(&hw, t2), Outcome::Ok);
    assert_eq!(hw.log().len() - before, 1, "one read command");
    assert_eq!(b1, pattern(0, 32, 5)[4 * SECTOR..8 * SECTOR]);
    assert_eq!(b2, pattern(0, 32, 5)[8 * SECTOR..12 * SECTOR]);
}

#[test]
fn requests_of_different_owners_do_not_merge() {
    let (q, hw) = (queue(), Fake::new(128, 16, 4));
    let (mut b1, mut b2) = (Vec::new(), Vec::new());
    let (t1, t2);
    {
        let p = q.plug(&hw);
        t1 = plugged_write(&p, 7, 8, 4, 0, &mut b1);
        t2 = plugged_write(&p, 9, 12, 4, 0, &mut b2);
    }
    assert_eq!((q.wait(&hw, t1), q.wait(&hw, t2)), (Outcome::Ok, Outcome::Ok));
    assert_eq!(hw.count(HwOp::Write), 2);
}

#[test]
fn gaps_flags_and_the_command_size_stop_a_merge() {
    let (q, hw) = (queue(), Fake::new(256, 8, 8));
    let mut bufs: Vec<Vec<u8>> = (0..6).map(|_| Vec::new()).collect();
    let mut t = Vec::new();
    {
        let p = q.plug(&hw);
        // 0..4 and 4..8 fill a command (8 sectors); 8..12 would exceed it.
        t.push(plugged_write(&p, 7, 0, 4, 0, &mut bufs[0]));
        t.push(plugged_write(&p, 7, 4, 4, 0, &mut bufs[1]));
        t.push(plugged_write(&p, 7, 8, 4, 0, &mut bufs[2]));
        // A gap.
        t.push(plugged_write(&p, 7, 40, 4, 0, &mut bufs[3]));
        // Adjacent to the gap one but with FUA.
        t.push(plugged_write(&p, 7, 44, 4, FLAG_FUA, &mut bufs[4]));
    }
    for x in t {
        assert_eq!(q.wait(&hw, x), Outcome::Ok);
    }
    let mut log = hw.log();
    log.sort_by_key(|c| c.lba);
    let shape: Vec<(u64, u32, bool)> = log.iter().map(|c| (c.lba, c.sectors, c.fua)).collect();
    assert_eq!(shape, vec![(0, 8, false), (8, 4, false), (40, 4, false), (44, 4, true)]);
}

#[test]
fn a_merge_stops_at_the_configured_request_count() {
    // MERGE_MAX adjacent one-sector requests plus one more.
    let (q, hw) = (queue(), Fake::new(256, 64, 8));
    let n = 8 + 1; // BLK_MERGE_MAX is 8 in the default configuration
    let n = n.max(azos_limits::BLK_MERGE_MAX as usize + 1);
    let mut bufs: Vec<Vec<u8>> = (0..n).map(|_| Vec::new()).collect();
    let mut t = Vec::new();
    {
        let p = q.plug(&hw);
        for i in 0..n {
            t.push(plugged_write(&p, 7, 10 + i as u64, 1, 0, &mut bufs[i]));
        }
    }
    for x in t {
        assert_eq!(q.wait(&hw, x), Outcome::Ok);
    }
    let log = hw.log();
    assert!(log.iter().all(|c| c.segs <= azos_limits::BLK_MERGE_MAX as usize));
    assert_eq!(log.iter().map(|c| c.sectors).sum::<u32>() as usize, n);
    assert!(log.len() >= 2);
}

// ── Order, deadlines ────────────────────────────────────────────────────

#[test]
fn the_earliest_deadline_is_started_first() {
    let (q, hw) = (queue(), Fake::new(256, 8, 1));
    let (mut b1, mut b2, mut b3) = (vec![0u8; 512], vec![0u8; 512], vec![0u8; 512]);
    let mut r1 = BlockRequest::rw(false, 10, 1, 7);
    r1.deadline_ns = 50_000_000_000;
    let mut r2 = BlockRequest::rw(false, 100, 1, 7);
    r2.deadline_ns = 10_000_000_000;
    let r3 = BlockRequest::rw(false, 200, 1, 7); // no deadline: last
    let (t1, t2, t3);
    {
        let p = q.plug(&hw);
        // SAFETY: waited for below.
        unsafe {
            t1 = p.submit(&r1, b1.as_mut_ptr()).unwrap();
            t3 = p.submit(&r3, b3.as_mut_ptr()).unwrap();
            t2 = p.submit(&r2, b2.as_mut_ptr()).unwrap();
        }
    }
    for t in [t1, t2, t3] {
        assert_eq!(q.wait(&hw, t), Outcome::Ok);
    }
    let order: Vec<u64> = hw.log().iter().map(|c| c.lba).collect();
    assert_eq!(order, vec![100, 10, 200]);
}

#[test]
fn a_request_past_its_deadline_is_not_started() {
    let (q, hw) = (queue(), Fake::new(256, 8, 1));
    // Keep the device busy so the second request has to wait.
    hw.hold.store(true, Ordering::SeqCst);
    let (mut b1, mut b2) = (vec![0u8; 512], vec![0u8; 512]);
    let r1 = BlockRequest::rw(false, 10, 1, 7);
    let mut r2 = BlockRequest::rw(false, 100, 1, 7);
    r2.deadline_ns = 1; // gone as soon as the clock moves
    // SAFETY: waited for below.
    let t1 = unsafe { q.submit(&hw, &r1, b1.as_mut_ptr()).unwrap() };
    let t2 = unsafe { q.submit(&hw, &r2, b2.as_mut_ptr()).unwrap() };
    std::thread::sleep(std::time::Duration::from_millis(2));
    hw.thaw();
    assert_eq!(q.wait(&hw, t1), Outcome::Ok);
    assert_eq!(q.wait(&hw, t2), Outcome::Deadline);
    assert_eq!(hw.log().iter().map(|c| c.lba).collect::<Vec<_>>(), vec![10], "the late one never reached the device");
}

// ── Scheduler and request class (Kconfig BLK_IOSCHED) ───────────────────

/// Submit the three requests of `the_earliest_deadline_is_started_first`
/// (sector 10 with a late deadline, 200 with none, 100 with an early one) and
/// the order the device saw them in.
fn deadline_order(sched: Sched) -> Vec<u64> {
    let (q, hw) = (queue_with(sched), Fake::new(256, 8, 1));
    let (mut b1, mut b2, mut b3) = (vec![0u8; 512], vec![0u8; 512], vec![0u8; 512]);
    let mut r1 = BlockRequest::rw(false, 10, 1, 7);
    r1.deadline_ns = 50_000_000_000;
    let mut r2 = BlockRequest::rw(false, 100, 1, 7);
    r2.deadline_ns = 10_000_000_000;
    let r3 = BlockRequest::rw(false, 200, 1, 7);
    let (t1, t2, t3);
    {
        let p = q.plug(&hw);
        // SAFETY: waited for below.
        unsafe {
            t1 = p.submit(&r1, b1.as_mut_ptr()).unwrap();
            t3 = p.submit(&r3, b3.as_mut_ptr()).unwrap();
            t2 = p.submit(&r2, b2.as_mut_ptr()).unwrap();
        }
    }
    for t in [t1, t2, t3] {
        assert_eq!(q.wait(&hw, t), Outcome::Ok);
    }
    hw.log().iter().map(|c| c.lba).collect()
}

/// `none` is arrival order; the two deadline schedulers sort by deadline.
/// Canary: a pick that ignored the scheduler would give the same order for
/// both.
#[test]
fn none_starts_the_oldest_and_the_deadline_schedulers_the_earliest_deadline() {
    assert_eq!(deadline_order(Sched::None), vec![10, 200, 100], "arrival order: the deadline moves nothing");
    assert_eq!(deadline_order(Sched::MqDeadline), vec![100, 10, 200]);
    assert_eq!(deadline_order(Sched::RtDeadline), vec![100, 10, 200], "no real-time request: the same order");
}

/// A request past its deadline still ends with a miss under `none`.
#[test]
fn none_still_ends_a_request_past_its_deadline() {
    let (q, hw) = (queue_with(Sched::None), Fake::new(256, 8, 1));
    hw.hold.store(true, Ordering::SeqCst);
    let (mut b1, mut b2) = (vec![0u8; 512], vec![0u8; 512]);
    let r1 = BlockRequest::rw(false, 10, 1, 7);
    let mut r2 = BlockRequest::rw(false, 100, 1, 7);
    r2.deadline_ns = 1;
    // SAFETY: waited for below.
    let t1 = unsafe { q.submit(&hw, &r1, b1.as_mut_ptr()).unwrap() };
    let t2 = unsafe { q.submit(&hw, &r2, b2.as_mut_ptr()).unwrap() };
    std::thread::sleep(std::time::Duration::from_millis(2));
    hw.thaw();
    assert_eq!(q.wait(&hw, t1), Outcome::Ok);
    assert_eq!(q.wait(&hw, t2), Outcome::Deadline);
}

/// Fill the hart's queue with requests of `owner`, one sector each and not
/// adjacent (no merge), through `try_submit` until it answers `Full`; the
/// tickets and their buffers.
fn fill(q: &ReqQueue, hw: &Fake, owner: u32) -> (Vec<Ticket>, Vec<Vec<u8>>) {
    let mut tickets = Vec::new();
    let mut bufs: Vec<Vec<u8>> = (0..azos_limits::BLK_QUEUE_DEPTH as usize).map(|_| vec![0u8; SECTOR]).collect();
    for (i, b) in bufs.iter_mut().enumerate() {
        let r = BlockRequest::rw(false, i as u64 * 4, 1, owner);
        // SAFETY: the caller waits for every ticket before the buffers drop.
        match unsafe { q.try_submit(hw, &r, b.as_mut_ptr()) } {
            Ok(t) => tickets.push(t),
            Err(e) => {
                assert_eq!(e, Failure::Full);
                break;
            }
        }
    }
    (tickets, bufs)
}

/// The reserved slot: ordinary requests leave one slot of the hart's queue
/// free, and only a request that serves a waiting durable record takes it.
#[test]
fn an_ordinary_request_leaves_the_last_slot_to_the_real_time_class() {
    let depth = azos_limits::BLK_QUEUE_DEPTH as usize;
    let hw = Fake::new(8192, 1, 1);
    let q = queue_with(Sched::RtDeadline);
    set_serving_record(false);
    let (tickets, _bufs) = fill(q, &hw, 30);
    assert_eq!(tickets.len(), depth - 1, "an ordinary request takes every slot but one");

    let mut b = vec![0u8; SECTOR];
    let rt_req = BlockRequest::rw(false, 6000, 1, 30);
    // A request that serves no record is ordinary, whoever owns it.
    assert_eq!(unsafe { q.try_submit(&hw, &rt_req, b.as_mut_ptr()) }.unwrap_err(), Failure::Full);
    // One that does takes the reserved slot (the class follows the source's
    // answer for the submitting task, not the request's owner).
    set_serving_record(true);
    let t = unsafe { q.try_submit(&hw, &rt_req, b.as_mut_ptr()).unwrap() };
    let mut b2 = vec![0u8; SECTOR];
    let rt_req2 = BlockRequest::rw(false, 6200, 1, 30);
    assert_eq!(unsafe { q.try_submit(&hw, &rt_req2, b2.as_mut_ptr()) }.unwrap_err(), Failure::Full, "the reserve is ONE slot");
    set_serving_record(false);
    assert_eq!(q.wait(&hw, t), Outcome::Ok);
    for t in tickets {
        assert_eq!(q.wait(&hw, t), Outcome::Ok);
    }
}

/// Without `rt-deadline` there is no reserve and no class: every slot is
/// anyone's, whatever the source says.
#[test]
fn the_other_schedulers_keep_no_slot_and_know_no_class() {
    let depth = azos_limits::BLK_QUEUE_DEPTH as usize;
    for sched in [Sched::None, Sched::MqDeadline] {
        let hw = Fake::new(8192, 1, 1);
        let q = queue_with(sched);
        set_serving_record(true);
        let (tickets, _bufs) = fill(q, &hw, 30);
        assert_eq!(tickets.len(), depth, "{sched:?}: every slot is an ordinary request's");
        set_serving_record(false);
        for t in tickets {
            assert_eq!(q.wait(&hw, t), Outcome::Ok);
        }
    }
}

/// The class is picked first, ahead of an older request with a deadline.
/// Canary: the class ignored (the same inputs under `mq-deadline`) starts the
/// deadline's request first.
#[test]
fn a_real_time_request_is_started_before_an_older_one_with_an_earlier_deadline() {
    let order = |sched: Sched| -> Vec<u64> {
        let (q, hw) = (queue_with(sched), Fake::new(256, 8, 1));
        let (mut b1, mut b2) = (vec![0u8; 512], vec![0u8; 512]);
        let mut ordinary = BlockRequest::rw(false, 10, 1, 7);
        ordinary.deadline_ns = 10_000_000_000;
        let record = BlockRequest::rw(false, 100, 1, 7);
        let (t1, t2);
        {
            let p = q.plug(&hw);
            // SAFETY: waited for below.
            unsafe {
                set_serving_record(false);
                t1 = p.submit(&ordinary, b1.as_mut_ptr()).unwrap();
                set_serving_record(true);
                t2 = p.submit(&record, b2.as_mut_ptr()).unwrap();
            }
        }
        set_serving_record(false);
        for t in [t1, t2] {
            assert_eq!(q.wait(&hw, t), Outcome::Ok);
        }
        hw.log().iter().map(|c| c.lba).collect()
    };
    assert_eq!(order(Sched::RtDeadline), vec![100, 10]);
    assert_eq!(order(Sched::MqDeadline), vec![10, 100]);
}

/// A real-time request is not merged into an ordinary one, nor the reverse:
/// the class decides the order of the command.
#[test]
fn requests_of_different_classes_do_not_merge() {
    let (q, hw) = (queue_with(Sched::RtDeadline), Fake::new(64, 8, 4));
    let (mut b1, mut b2) = (vec![0u8; 512], vec![0u8; 512]);
    let ordinary = BlockRequest::rw(false, 10, 1, 7);
    let record = BlockRequest::rw(false, 11, 1, 7);
    let (t1, t2);
    {
        let p = q.plug(&hw);
        // SAFETY: waited for below.
        unsafe {
            set_serving_record(false);
            t1 = p.submit(&ordinary, b1.as_mut_ptr()).unwrap();
            set_serving_record(true);
            t2 = p.submit(&record, b2.as_mut_ptr()).unwrap();
        }
    }
    set_serving_record(false);
    for t in [t1, t2] {
        assert_eq!(q.wait(&hw, t), Outcome::Ok);
    }
    assert_eq!(hw.log().len(), 2, "adjacent, one owner, one operation: two classes, two commands");
    // The same pair of one class is one command.
    let hw = Fake::new(64, 8, 4);
    let (t1, t2);
    {
        let p = q.plug(&hw);
        // SAFETY: waited for below.
        unsafe {
            t1 = p.submit(&ordinary, b1.as_mut_ptr()).unwrap();
            t2 = p.submit(&record, b2.as_mut_ptr()).unwrap();
        }
    }
    for t in [t1, t2] {
        assert_eq!(q.wait(&hw, t), Outcome::Ok);
    }
    assert_eq!(hw.log().len(), 1);
}

// ── Flush, FUA, PREFLUSH ────────────────────────────────────────────────

#[test]
fn fua_goes_to_the_device_and_the_data_is_durable() {
    let (q, hw) = (queue(), Fake::new(64, 8, 2));
    write(q, &hw, 4, 4, FLAG_FUA, 2).unwrap();
    assert_eq!(hw.log(), vec![Started { op: HwOp::Write, lba: 4, sectors: 4, fua: true, segs: 1 }]);
    assert_eq!(hw.durable(4, 4), pattern(4, 4, 2));
    write(q, &hw, 20, 4, 0, 2).unwrap();
    assert_eq!(hw.durable(20, 4), vec![0u8; 4 * SECTOR], "a plain write is only in the cache");
}

#[test]
fn a_flush_request_makes_completed_writes_durable() {
    let (q, hw) = (queue(), Fake::new(64, 8, 2));
    write(q, &hw, 20, 4, 0, 2).unwrap();
    q.flush(&hw, 7).unwrap();
    assert_eq!(hw.durable(20, 4), pattern(20, 4, 2));
    *hw.flush_status.lock().unwrap() = HwStatus::Unsupported;
    assert_eq!(q.flush(&hw, 7), Err(Failure::Ended(Outcome::Unsupported)), "never Ok without a flush");
    *hw.flush_status.lock().unwrap() = HwStatus::Io;
    assert_eq!(q.flush(&hw, 7), Err(Failure::Ended(Outcome::Io)));
}

#[test]
fn preflush_puts_one_flush_ahead_of_a_whole_plugged_transfer() {
    let (q, hw) = (queue(), Fake::new(256, 8, 4));
    write(q, &hw, 100, 4, 0, 4).unwrap(); // an earlier write: cached, not durable
    assert_eq!(hw.durable(100, 4), vec![0u8; 4 * SECTOR]);
    // A 40-sector write needs five requests of 8; each carries PREFLUSH.
    write(q, &hw, 0, 40, FLAG_PREFLUSH, 6).unwrap();
    let ev = hw.events();
    let first_flush = ev.iter().position(|e| *e == Ev::Start(HwOp::Flush)).expect("a flush was started");
    let first_data_after = ev.iter().skip(1).position(|e| *e == Ev::Start(HwOp::Write)).unwrap() + 1;
    assert_eq!(hw.count(HwOp::Flush), 1, "ONE flush serves the whole transfer: {ev:?}");
    // The earlier write is durable by the time the transfer's first write starts.
    let writes_before_flush = ev[..first_flush].iter().filter(|e| **e == Ev::Start(HwOp::Write)).count();
    assert_eq!(writes_before_flush, 1, "only the earlier write precedes the flush");
    assert!(first_data_after > first_flush);
    let done_flush = ev.iter().position(|e| *e == Ev::Done(HwOp::Flush)).unwrap();
    let second_write_start = ev.iter().enumerate().filter(|(_, e)| **e == Ev::Start(HwOp::Write)).nth(1).unwrap().0;
    assert!(second_write_start > done_flush, "no write of the transfer starts before the flush is done: {ev:?}");
    assert_eq!(hw.durable(100, 4), pattern(100, 4, 4), "the flush made the earlier write durable");
    assert_eq!(hw.medium(0, 40), pattern(0, 40, 6));
}

#[test]
fn a_preflush_request_submitted_during_a_flush_gets_its_own() {
    let (q, hw) = (queue(), Fake::new(256, 8, 4));
    hw.hold.store(true, Ordering::SeqCst); // the first flush stays in the device
    let (mut b1, mut b2) = (vec![1u8; 512], vec![2u8; 512]);
    let mut r1 = BlockRequest::rw(true, 10, 1, 7);
    r1.flags = FLAG_PREFLUSH;
    let r2 = BlockRequest { sector: 50, ..r1 };
    // SAFETY: waited for below.
    let t1 = unsafe { q.submit(&hw, &r1, b1.as_mut_ptr()).unwrap() };
    assert_eq!(hw.count(HwOp::Flush), 1);
    let t2 = unsafe { q.submit(&hw, &r2, b2.as_mut_ptr()).unwrap() };
    assert_eq!(hw.count(HwOp::Flush), 1, "one flush at a time; the second request waits for it");
    hw.thaw();
    assert_eq!((q.wait(&hw, t1), q.wait(&hw, t2)), (Outcome::Ok, Outcome::Ok));
    assert_eq!(hw.count(HwOp::Flush), 2, "the later request is not covered by a flush that began before it");
    assert_eq!(hw.count(HwOp::Write), 2);
}

#[test]
fn preflush_proceeds_when_the_device_has_nothing_to_flush_and_stops_when_it_fails() {
    let (q, hw) = (queue(), Fake::new(64, 8, 2));
    *hw.flush_status.lock().unwrap() = HwStatus::Unsupported;
    write(q, &hw, 4, 4, FLAG_PREFLUSH, 1).unwrap();
    assert_eq!(hw.count(HwOp::Write), 1, "Unsupported: nothing to order, the write goes");

    let (q, hw) = (queue(), Fake::new(64, 8, 2));
    *hw.flush_status.lock().unwrap() = HwStatus::Io;
    let e = write(q, &hw, 4, 4, FLAG_PREFLUSH, 1);
    assert_eq!(e, Err(Failure::Ended(Outcome::Io)));
    assert_eq!(hw.count(HwOp::Write), 0, "a failed flush: the write is never started");
}

// ── Discard ─────────────────────────────────────────────────────────────

#[test]
fn discard_reaches_a_device_that_has_it_and_is_refused_by_one_that_has_not() {
    let (q, hw) = (queue(), Fake::new(256, 8, 2));
    write(q, &hw, 8, 8, 0, 1).unwrap();
    q.discard(&hw, 7, &[(8, 20)], false).unwrap();
    // 20 sectors at 8 per command.
    assert_eq!(hw.log().iter().filter(|c| c.op == HwOp::Discard).map(|c| c.sectors).collect::<Vec<_>>(), vec![8, 8, 4]);
    assert_eq!(hw.medium(8, 8), vec![0u8; 8 * SECTOR]);

    let (q, mut hw) = (queue(), Fake::new(64, 8, 2));
    hw.max_discard = 0;
    assert_eq!(q.discard(&hw, 7, &[(8, 4)], false), Err(Failure::Refused(outcome::UNSUPPORTED)));
    let r = BlockRequest { op: REQ_DISCARD, ..BlockRequest::rw(false, 8, 4, 7) };
    assert_eq!(unsafe { q.submit(&hw, &r, core::ptr::null_mut()) }.unwrap_err(), Failure::Refused(outcome::UNSUPPORTED));
    assert_eq!(hw.starts.load(Ordering::SeqCst), 0);
}

/// A discard is cut at the device's largest DISCARD, which is not the largest
/// transfer: a device may take a long discard in one command.
#[test]
fn a_discard_is_cut_at_the_discard_limit_not_the_transfer_limit() {
    let (q, mut hw) = (queue(), Fake::new(512, 8, 2));
    hw.max_discard = 64;
    q.discard(&hw, 7, &[(0, 150)], false).unwrap();
    assert_eq!(hw.log().iter().map(|c| c.sectors).collect::<Vec<_>>(), vec![64, 64, 22]);
    // A request over the limit is refused, not truncated.
    let r = BlockRequest { op: REQ_DISCARD, ..BlockRequest::rw(false, 0, 65, 7) };
    assert_eq!(unsafe { q.submit(&hw, &r, core::ptr::null_mut()) }.unwrap_err(), Failure::Refused(outcome::BAD_ARGUMENT));
}

/// Several ranges: one at a time, or all in the device together; either way
/// each is covered and the call returns only when the last is done.
#[test]
fn discard_ranges_go_one_at_a_time_or_together() {
    let ranges = [(0u64, 8u32), (16, 8), (32, 8), (48, 8)];
    for (together, at_most_one) in [(false, true), (true, false)] {
        let (q, hw) = (queue(), Fake::new(256, 8, 4));
        for (s, n) in ranges {
            write(q, &hw, s, n, 0, 3).unwrap();
        }
        hw.inner.lock().unwrap().in_flight_max = 0;
        // Completions are held, so what the layer keeps in the device shows; a
        // helper thaws them after a moment (every discard is waited for).
        hw.hold.store(true, Ordering::SeqCst);
        std::thread::scope(|sc| {
            sc.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(50));
                hw.thaw();
            });
            q.discard(&hw, 7, &ranges, together).unwrap();
        });
        let mut lbas: Vec<u64> = hw.log().iter().filter(|c| c.op == HwOp::Discard).map(|c| c.lba).collect();
        lbas.sort();
        assert_eq!(lbas, vec![0, 16, 32, 48], "every range, once");
        for (s, n) in ranges {
            assert_eq!(hw.medium(s, n), vec![0u8; n as usize * SECTOR], "range {s} is discarded");
        }
        let max = hw.inner.lock().unwrap().in_flight_max;
        assert_eq!(max <= 1, at_most_one, "together={together}: {max} in the device at once");
        assert!(hw.inner.lock().unwrap().slots.iter().all(|s| s.is_none()), "every ticket collected");
    }
}

/// The first failing range is the answer, and the others are still waited for.
#[test]
fn a_discard_batch_that_fails_still_waits_for_the_rest() {
    let (q, hw) = (queue(), Fake::new(256, 8, 4));
    *hw.discard_status.lock().unwrap() = HwStatus::Unsupported;
    let r = q.discard(&hw, 7, &[(0, 8), (16, 8), (32, 8)], true);
    assert_eq!(r, Err(Failure::Ended(Outcome::Unsupported)));
    assert!(hw.inner.lock().unwrap().slots.iter().all(|s| s.is_none()), "no ticket left behind");
}

/// FUA is a bit of the write command: a device without it is not asked.
#[test]
fn fua_is_refused_by_a_device_that_has_none() {
    let (q, mut hw) = (queue(), Fake::new(64, 8, 2));
    hw.fua = false;
    assert_eq!(write(q, &hw, 4, 4, FLAG_FUA, 2), Err(Failure::Refused(outcome::UNSUPPORTED)));
    assert_eq!(hw.starts.load(Ordering::SeqCst), 0);
    // A plain write and a PREFLUSH write still go.
    write(q, &hw, 4, 4, FLAG_PREFLUSH, 2).unwrap();
}

// ── Failures ────────────────────────────────────────────────────────────

#[test]
fn a_failed_command_fails_every_request_it_carries_and_only_those() {
    let (q, hw) = (queue(), Fake::new(128, 16, 4));
    let (mut b1, mut b2, mut b3) = (Vec::new(), Vec::new(), Vec::new());
    hw.fail_write.store(true, Ordering::SeqCst);
    let (t1, t2, t3);
    {
        let p = q.plug(&hw);
        t1 = plugged_write(&p, 7, 8, 4, 0, &mut b1);
        t2 = plugged_write(&p, 7, 12, 4, 0, &mut b2); // merged with the first
        t3 = plugged_write(&p, 7, 60, 4, 0, &mut b3); // a command of its own
    }
    let outs = [q.wait(&hw, t1), q.wait(&hw, t2), q.wait(&hw, t3)];
    // The merged command is started first (earlier arrival) and fails.
    assert_eq!(outs, [Outcome::Io, Outcome::Io, Outcome::Ok]);
    assert_eq!(hw.medium(60, 4), pattern(60, 4, 1));
}

#[test]
fn a_dead_device_ends_the_request_instead_of_hanging_it() {
    let (q, hw) = (queue(), Fake::new(64, 8, 2));
    hw.dead.store(true, Ordering::SeqCst);
    assert_eq!(write(q, &hw, 4, 4, 0, 1), Err(Failure::Ended(Outcome::Io)));
    assert_eq!(read(q, &hw, 4, 4).unwrap_err(), Failure::Ended(Outcome::Io));
    assert_eq!(q.flush(&hw, 7), Err(Failure::Ended(Outcome::Io)));
}

#[test]
fn a_command_that_times_out_fails_its_request_and_is_reported_once() {
    set_timeout_sink(capture);
    let (q, hw) = (queue(), Fake::new(1024, 8, 2));
    hw.stall.store(true, Ordering::SeqCst);
    assert_eq!(write(q, &hw, 400, 4, 0, 1), Err(Failure::Ended(Outcome::Io)), "the waiter is released with an error");
    // The device is dead now: the next requests end at once, and the layer
    // reports the offline device ONCE, however many requests find it so.
    assert_eq!(write(q, &hw, 440, 4, 0, 1), Err(Failure::Ended(Outcome::Io)));
    assert_eq!(read(q, &hw, 480, 4).unwrap_err(), Failure::Ended(Outcome::Io));
    let r = reported_for(&[400, 440, 480]);
    assert_eq!(r.len(), 2, "{r:?}");
    assert_eq!((r[0].0, r[0].1), (TimeoutAction::Failed, 400));
    assert!(r[0].2 >= STALL_BUDGET_MS, "waited {} ms: the time in the device, not zero", r[0].2);
    assert_eq!(r[1], (TimeoutAction::Offline, 440, 0));
}

/// **Discriminates.** A command the device's reset abandoned
/// (`HwStatus::Reset`: another command timed out and the driver reset the
/// controller with this one in it) ends its request with the typed
/// `Outcome::Reset`, not retried and not reported as a timeout, and the
/// device carries on. Canary: map `HwStatus::Reset` to `Outcome::Ok` in
/// `complete` (the write "succeeds" with nothing on the medium).
#[test]
fn a_command_a_reset_abandoned_ends_its_request_with_a_typed_error() {
    set_timeout_sink(capture);
    let (q, hw) = (queue(), Fake::new(1024, 8, 2));
    hw.abandon.store(true, Ordering::SeqCst);
    assert_eq!(write(q, &hw, 700, 4, 0, 1), Err(Failure::Ended(Outcome::Reset)));
    assert_eq!(hw.count(HwOp::Write), 1, "the layer retried the abandoned write");
    hw.abandon.store(true, Ordering::SeqCst);
    assert_eq!(read(q, &hw, 700, 4).unwrap_err(), Failure::Ended(Outcome::Reset));
    assert_eq!(write(q, &hw, 740, 4, 0, 1), Ok(()), "the device is alive after its reset");
    assert!(reported_for(&[700, 740]).is_empty(), "an abandoned command is not a timeout");
    assert_eq!(Outcome::Reset.code(), azos_devif::outcome::FAULT);
}

#[test]
fn an_ordinary_io_error_is_not_a_timeout() {
    set_timeout_sink(capture);
    let (q, hw) = (queue(), Fake::new(1024, 8, 2));
    hw.fail_write.store(true, Ordering::SeqCst);
    assert_eq!(write(q, &hw, 520, 4, 0, 1), Err(Failure::Ended(Outcome::Io)));
    assert_eq!(write(q, &hw, 560, 4, 0, 1), Ok(()), "the device is alive");
    assert!(reported_for(&[520, 560]).is_empty());
}

#[test]
fn a_flush_that_times_out_fails_the_write_that_waited_for_it() {
    set_timeout_sink(capture);
    let (q, hw) = (queue(), Fake::new(1024, 8, 2));
    // PREFLUSH: the first command the layer starts is the flush, sector 0.
    hw.stall.store(true, Ordering::SeqCst);
    assert_eq!(write(q, &hw, 600, 4, FLAG_PREFLUSH, 1), Err(Failure::Ended(Outcome::Io)));
    let r = reported_for(&[0, 600]);
    assert!(r.iter().any(|&(a, s, _)| a == TimeoutAction::Failed && s == 0), "{r:?}");
    assert_eq!(hw.count(HwOp::Write), 0, "the write never reached a device that could not flush");
}

#[test]
fn fewer_device_slots_than_requests_still_completes_everything() {
    let (q, hw) = (queue(), Fake::new(512, 4, 1));
    let mut bufs: Vec<Vec<u8>> = (0..12).map(|_| Vec::new()).collect();
    let mut t = Vec::new();
    {
        let p = q.plug(&hw);
        for i in 0..12 {
            // Not adjacent, so every request is its own command.
            t.push(plugged_write(&p, 7, i as u64 * 20, 2, 0, &mut bufs[i]));
        }
    }
    for x in t {
        assert_eq!(q.wait(&hw, x), Outcome::Ok);
    }
    assert_eq!(hw.count(HwOp::Write), 12);
    assert_eq!(hw.inner.lock().unwrap().in_flight_max, 1);
}

// ── Concurrency ─────────────────────────────────────────────────────────

#[test]
fn several_tasks_on_several_harts_each_get_their_own_data() {
    let (q, hw) = (queue(), &*Box::leak(Box::new(Fake::new(4096, 8, 3))));
    let handles: Vec<_> = (0..4usize)
        .map(|n| {
            std::thread::spawn(move || {
                CPU.with(|c| c.set(n));
                let base = n as u64 * 1000;
                for round in 0..20u64 {
                    let sector = base + round * 40;
                    let salt = (n * 16 + round as usize) as u8;
                    let mut b = pattern(sector, 37, salt);
                    q.transfer(hw, 10 + n as u32, true, sector, 37, 0, b.as_mut_ptr(), b.len()).unwrap();
                    let mut r = vec![0u8; 37 * SECTOR];
                    q.transfer(hw, 10 + n as u32, false, sector, 37, 0, r.as_mut_ptr(), r.len()).unwrap();
                    assert_eq!(r, pattern(sector, 37, salt), "task {n} round {round}");
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert!(hw.inner.lock().unwrap().slots.iter().all(|s| s.is_none()));
}

// ── The facade ──────────────────────────────────────────────────────────

/// `blkdev` over a bound device: the `BlockDevice` calls become requests, the
/// owner is the registered source's (and the kernel's where it has none), and
/// `write_run` carries its PREFLUSH to the device as one flush ahead of the
/// data. The only test that binds the global queue (no other test calls
/// `blkdev`).
#[test]
fn blkdev_over_a_bound_device_is_the_synchronous_facade_of_the_queue() {
    let hw: &'static Fake = Box::leak(Box::new(Fake::new(256, 8, 3)));
    assert!(crate::queue::bound().is_none());
    crate::queue::bind(hw);
    // No owner source registered yet: the kernel's.
    assert_eq!(crate::blkdev::init(), Ok(()));
    assert_eq!(crate::blkdev::capacity_sectors(), 256);
    let data = pattern(30, 20, 8);
    crate::blkdev::write(30, 20, &data).unwrap();
    let mut back = vec![0u8; 20 * SECTOR];
    crate::blkdev::read(30, 20, &mut back).unwrap();
    assert_eq!(back, data);
    // A source that answers "no Domain" is the kernel too; one that names a
    // Domain is used.
    crate::blkdev::set_owner_source(|| 0);
    crate::blkdev::read(30, 1, &mut back[..SECTOR]).unwrap();
    crate::blkdev::set_owner_source(|| 0x0002_0007);
    crate::blkdev::read(30, 1, &mut back[..SECTOR]).unwrap();
    assert_eq!(hw.durable(30, 20), vec![0u8; 20 * SECTOR], "a plain write is not durable until flushed");
    // The epoch rule in one call: one flush, then the data.
    let before = hw.events().len();
    crate::blkdev::write_run(100, 8, &pattern(100, 8, 1), true, false).unwrap();
    let ev: Vec<Ev> = hw.events()[before..].to_vec();
    assert_eq!(ev, vec![Ev::Start(HwOp::Flush), Ev::Done(HwOp::Flush), Ev::Start(HwOp::Write), Ev::Done(HwOp::Write)]);
    assert_eq!(hw.durable(30, 20), data, "the flush ahead of the run made the earlier write durable");
    assert_eq!(hw.durable(100, 8), vec![0u8; 8 * SECTOR], "the run itself is only cached");
    assert_eq!(crate::blkdev::flush(), Ok(()));
    assert_eq!(hw.durable(100, 8), pattern(100, 8, 1));
    *hw.flush_status.lock().unwrap() = HwStatus::Unsupported;
    assert_eq!(crate::blkdev::flush(), Err(azos_drv_api::block::FlushError::Unsupported));
    *hw.flush_status.lock().unwrap() = HwStatus::Io;
    assert_eq!(crate::blkdev::flush(), Err(azos_drv_api::block::FlushError::Io));
    assert!(crate::blkdev::write_run(100, 8, &pattern(100, 8, 1), true, false).is_err(), "a failed flush: no write");
    *hw.flush_status.lock().unwrap() = HwStatus::Ok;
    // A commit that needs no flush behind it: PREFLUSH + FUA, durable at once,
    // on a device whose FUA is native (Kconfig BLK_FUA is on in the tests'
    // configuration).
    assert_eq!(crate::blkdev::fua_commit(), azos_limits::BLK_FUA);
    if azos_limits::BLK_FUA {
        let before = hw.events().len();
        crate::blkdev::write_run(110, 4, &pattern(110, 4, 5), true, true).unwrap();
        let ev: Vec<Ev> = hw.events()[before..].to_vec();
        assert_eq!(ev, vec![Ev::Start(HwOp::Flush), Ev::Done(HwOp::Flush), Ev::Start(HwOp::Write), Ev::Done(HwOp::Write)]);
        assert!(hw.log().last().unwrap().fua);
        assert_eq!(hw.durable(110, 4), pattern(110, 4, 5), "FUA: stable when the call returns");
    }
    // Discard through the facade: ranges, the device's answer mapped.
    if crate::blkdev::DISCARD {
        crate::blkdev::discard(&[(30, 4), (40, 4)]).unwrap();
        assert_eq!(hw.medium(30, 4), vec![0u8; 4 * SECTOR]);
        *hw.discard_status.lock().unwrap() = HwStatus::Unsupported;
        assert_eq!(crate::blkdev::discard(&[(30, 4)]), Err(crate::blkdev::DiscardError::Unsupported));
        *hw.discard_status.lock().unwrap() = HwStatus::Io;
        assert_eq!(crate::blkdev::discard(&[(30, 4)]), Err(crate::blkdev::DiscardError::Io));
        assert_eq!(crate::blkdev::discard(&[]), Ok(()));
    }
    assert!(crate::blkdev::write(300, 1, &[0u8; SECTOR]).is_err(), "past the medium");

    // **Canary: an RT task submitting block I/O is still refused.** The
    // real-time request class is not a way in for a real-time task: every
    // entry of the facade runs the kernel's check (which panics naming the
    // task, Kconfig RT_BLOCK_IO_CHECK) before a request exists, and so
    // before any class is decided, with a durable record waiting or not.
    // Make an entry skip `rt_io_check` (say, one for the class's own use) and
    // its count stays behind.
    if azos_limits::RT_BLOCK_IO_CHECK {
        static REFUSALS: AtomicUsize = AtomicUsize::new(0);
        crate::blkdev::set_rt_io_check(|| {
            REFUSALS.fetch_add(1, Ordering::SeqCst);
        });
        set_serving_record(true);
        crate::blkdev::set_owner_source(|| 0);
        let entries: [&dyn Fn(); 6] = [
            &|| { let _ = crate::blkdev::read(30, 1, &mut [0u8; SECTOR]); },
            &|| { let _ = crate::blkdev::read_quiet(30, 1, &mut [0u8; SECTOR]); },
            &|| { let _ = crate::blkdev::write(30, 1, &[0u8; SECTOR]); },
            &|| { let _ = crate::blkdev::write_quiet(30, 1, &[0u8; SECTOR]); },
            &|| { let _ = crate::blkdev::write_run(30, 1, &[0u8; SECTOR], false, false); },
            &|| { let _ = crate::blkdev::flush(); },
        ];
        for (n, entry) in entries.iter().enumerate() {
            let before = REFUSALS.load(Ordering::SeqCst);
            entry();
            assert_eq!(REFUSALS.load(Ordering::SeqCst), before + 1, "facade entry {n} did not run the RT check");
        }
        set_serving_record(false);
    }
}

/// Two tasks on ONE hart, each moving more requests than the hart's queue
/// holds. Their tickets together outnumber the slots: a task that slept for a
/// free slot while holding finished requests nobody collects would starve the
/// other, and the other it (a deadlock the one-CPU-per-thread test above
/// cannot meet).
#[test]
fn two_tasks_on_one_hart_with_more_requests_than_slots_do_not_starve_each_other() {
    for sched in ALL_SCHEDS {
        two_tasks_on_one_hart_do_not_starve(sched);
    }
}

fn two_tasks_on_one_hart_do_not_starve(sched: Sched) {
    let depth = azos_limits::BLK_QUEUE_DEPTH as usize;
    let (q, hw) = (queue_with(sched), &*Box::leak(Box::new(Fake::new(8192, 1, 1))));
    hw.reap_us.store(30, Ordering::SeqCst);
    let (tx, rx) = std::sync::mpsc::channel();
    for n in 0..2usize {
        let tx = tx.clone();
        std::thread::spawn(move || {
            CPU.with(|c| c.set(0));
            let count = (depth * 3 + 5) as u32;
            let sector = n as u64 * 4000;
            for round in 0..40u8 {
                let mut b = pattern(sector, count, n as u8 + round);
                q.transfer(hw, 20 + n as u32, true, sector, count, 0, b.as_mut_ptr(), b.len()).unwrap();
                let mut r = vec![0u8; b.len()];
                q.transfer(hw, 20 + n as u32, false, sector, count, 0, r.as_mut_ptr(), r.len()).unwrap();
                assert_eq!(r, b);
            }
            tx.send(n).unwrap();
        });
    }
    for _ in 0..2 {
        rx.recv_timeout(std::time::Duration::from_secs(60)).expect("both transfers finish: no deadlock on a shared hart queue");
    }
}

/// A full hart queue answers `Full` to a caller that may hold tickets, and a
/// collected ticket frees the slot: the primitive the transfer's refill rests
/// on.
#[test]
fn a_full_queue_answers_full_to_a_task_that_holds_tickets_and_a_collect_frees_a_slot() {
    for sched in ALL_SCHEDS {
        a_full_queue_answers_full(sched);
    }
}

fn a_full_queue_answers_full(sched: Sched) {
    // Under `rt-deadline` the last slot is not an ordinary request's.
    let depth = azos_limits::BLK_QUEUE_DEPTH as usize - if sched == Sched::RtDeadline { 1 } else { 0 };
    let (q, hw) = (queue_with(sched), Fake::new(8192, 1, 1));
    let mut bufs: Vec<Vec<u8>> = (0..depth + 1).map(|_| vec![0u8; SECTOR]).collect();
    let mut tickets = Vec::new();
    // Two tasks' worth of requests fill the hart's queue (not adjacent: no merge).
    for i in 0..depth {
        let r = BlockRequest::rw(false, i as u64 * 4, 1, 30 + (i % 2) as u32);
        // SAFETY: every ticket is waited for below.
        tickets.push(unsafe { q.try_submit(&hw, &r, bufs[i].as_mut_ptr()).unwrap() });
    }
    let r = BlockRequest::rw(false, 4000, 1, 30);
    let e = unsafe { q.try_submit(&hw, &r, bufs[depth].as_mut_ptr()) };
    assert_eq!(e.unwrap_err(), Failure::Full, "no slot: told so, not put to sleep");
    {
        let p = q.plug(&hw);
        assert_eq!(unsafe { p.submit(&r, bufs[depth].as_mut_ptr()) }.unwrap_err(), Failure::Full);
    }
    assert_eq!(q.wait(&hw, tickets.remove(0)), Outcome::Ok);
    tickets.push(unsafe { q.try_submit(&hw, &r, bufs[depth].as_mut_ptr()).unwrap() });
    for t in tickets {
        assert_eq!(q.wait(&hw, t), Outcome::Ok);
    }
}

// ── The write ledger ────────────────────────────────────────────────────

static LEDGER: Mutex<Vec<(u32, u64)>> = Mutex::new(Vec::new());

/// The sink under test. The hook is global and the other tests write too, so
/// it keeps only the owners this test makes up.
fn ledger_sink(owner: u32, bytes: u64) {
    if owner >> 16 == 0xA11C {
        LEDGER.lock().unwrap().push((owner, bytes));
    }
}

fn ledger_of(owner: u32) -> u64 {
    LEDGER.lock().unwrap().iter().filter(|e| e.0 == owner).map(|e| e.1).sum()
}

/// **The bytes of a write the device completed are accounted to the owner that
/// made the request, member by member of a merged command; a read, a flush and
/// a write that failed account nothing.**
#[test]
fn completed_writes_are_accounted_to_their_owner() {
    crate::write_observer::set_account(ledger_sink);
    let (a, b) = (0xA11C_0001u32, 0xA11C_0002u32);
    let (q, hw) = (queue(), Fake::new(1024, 16, 4));
    let mut bufs: Vec<Vec<u8>> = (0..4).map(|_| Vec::new()).collect();
    let mut t = Vec::new();
    {
        let p = q.plug(&hw);
        // `a` twice, adjacent: one command, two members; `b` once, elsewhere.
        t.push(plugged_write(&p, a, 16, 4, 0, &mut bufs[0]));
        t.push(plugged_write(&p, a, 20, 4, 0, &mut bufs[1]));
        t.push(plugged_write(&p, b, 100, 2, 0, &mut bufs[2]));
        t.push(plugged_write(&p, a, 200, 1, 0, &mut bufs[3]));
    }
    for ticket in t {
        assert_eq!(q.wait(&hw, ticket), Outcome::Ok);
    }
    assert_eq!(ledger_of(a), 9 * SECTOR as u64);
    assert_eq!(ledger_of(b), 2 * SECTOR as u64);
    // Not writes, or not completed.
    let mut rb = vec![0u8; 4 * SECTOR];
    q.transfer(&hw, a, false, 16, 4, 0, rb.as_mut_ptr(), rb.len()).unwrap();
    q.flush(&hw, a).unwrap();
    hw.fail_write.store(true, Ordering::SeqCst);
    let mut wb = pattern(300, 4, 1);
    assert_eq!(
        q.transfer(&hw, a, true, 300, 4, 0, wb.as_mut_ptr(), wb.len()),
        Err(Failure::Ended(Outcome::Io))
    );
    assert_eq!(ledger_of(a), 9 * SECTOR as u64, "a read, a flush and a failed write count nothing");
}

// ── Sleeping without being woken ────────────────────────────────────────
//
// The kernel's sleep is a timer block plus a TID wake that leaves a stamp when
// the task has not blocked yet. The model below is that, per test thread: a
// stamp per TID, a block that ends on a stamp or on the deadline.

mod sleep_model {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex, Once};
    use std::time::{Duration, Instant};

    pub static WAKES: AtomicBool = AtomicBool::new(true);
    /// The block ignores the deadline (a timer that never fires): only a wake
    /// ends it, or `GIVE_UP_MS`.
    pub static IGNORE_DEADLINE: AtomicBool = AtomicBool::new(false);
    pub const GIVE_UP_MS: u64 = 3_000;
    pub static BLOCKS: AtomicUsize = AtomicUsize::new(0);
    pub static WAKE_CALLS: AtomicUsize = AtomicUsize::new(0);
    /// The longest span a sleeper asked to sleep, in nanoseconds.
    pub static LONGEST_ASK_NS: AtomicUsize = AtomicUsize::new(0);
    /// Held by a test for its whole run: the hooks and these knobs are global.
    pub static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    static STAMPS: Mutex<Option<HashMap<u32, bool>>> = Mutex::new(None);
    static CV: Condvar = Condvar::new();
    static INSTALL: Once = Once::new();

    fn block_until(deadline: u64) -> bool {
        let tid = azos_sync::waitqueue::caller_tid();
        let now = azos_drv_sys::timebase::now();
        let ask_ns = (deadline.saturating_sub(now) as u128 * 1_000_000_000 / azos_drv_sys::timebase::TIMER_FREQ as u128) as usize;
        BLOCKS.fetch_add(1, Ordering::SeqCst);
        LONGEST_ASK_NS.fetch_max(ask_ns, Ordering::SeqCst);
        let limit = if IGNORE_DEADLINE.load(Ordering::SeqCst) {
            Duration::from_millis(GIVE_UP_MS)
        } else {
            Duration::from_nanos(ask_ns as u64)
        };
        let end = Instant::now() + limit;
        let mut g = STAMPS.lock().unwrap();
        loop {
            let stamps = g.get_or_insert_with(HashMap::new);
            if stamps.insert(tid, false) == Some(true) {
                return true;
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                stamps.remove(&tid);
                return true;
            }
            g = CV.wait_timeout(g, left).unwrap().0;
            // A stamp that arrived while asleep is consumed at the top.
            if g.as_ref().is_some_and(|m| m.get(&tid) == Some(&true)) {
                g.as_mut().unwrap().remove(&tid);
                return true;
            }
        }
    }

    fn wake(tid: u32) {
        WAKE_CALLS.fetch_add(1, Ordering::SeqCst);
        if !WAKES.load(Ordering::SeqCst) {
            return;
        }
        STAMPS.lock().unwrap().get_or_insert_with(HashMap::new).insert(tid, true);
        CV.notify_all();
    }

    /// Install the hooks (once per process) and reset the knobs.
    pub fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        INSTALL.call_once(|| super::set_sleep_hooks(block_until, wake));
        WAKES.store(true, Ordering::SeqCst);
        IGNORE_DEADLINE.store(false, Ordering::SeqCst);
        BLOCKS.store(0, Ordering::SeqCst);
        WAKE_CALLS.store(0, Ordering::SeqCst);
        LONGEST_ASK_NS.store(0, Ordering::SeqCst);
        *STAMPS.lock().unwrap() = None;
        g
    }
}

/// Two tasks wait on a device that holds its completions: the first becomes the
/// reaper (it sleeps in the device `wait_ms` at a time), the second sleeps in
/// the layer. The device is let go after `hold_ms`. Returns how long the
/// second one took to finish.
fn reaper_and_sleeper(hold_ms: u64) -> std::time::Duration {
    let (q, hw) = (queue(), &*Box::leak(Box::new(Fake::new(256, 8, 4))));
    hw.hold.store(true, Ordering::SeqCst);
    hw.wait_ms.store(5, Ordering::SeqCst);
    let started = std::time::Instant::now();
    let reaper = std::thread::spawn(move || {
        azos_sync::waitqueue::set_caller_tid(101);
        CPU.with(|c| c.set(0));
        let mut b = pattern(0, 1, 1);
        q.transfer(hw, 10, true, 0, 1, 0, b.as_mut_ptr(), b.len()).unwrap();
    });
    // The reaper is in the device before the sleeper arrives.
    std::thread::sleep(std::time::Duration::from_millis(2));
    let sleeper = std::thread::spawn(move || {
        azos_sync::waitqueue::set_caller_tid(102);
        CPU.with(|c| c.set(1));
        let mut b = pattern(8, 1, 2);
        q.transfer(hw, 11, true, 8, 1, 0, b.as_mut_ptr(), b.len()).unwrap();
        std::time::Instant::now()
    });
    std::thread::sleep(std::time::Duration::from_millis(hold_ms));
    hw.thaw();
    reaper.join().unwrap();
    sleeper.join().unwrap().duration_since(started)
}

/// A waiter sleeps on a timer, never indefinitely: with every wake dropped it
/// still finishes, and no sleep it asked for is longer than a slice (the
/// queue's wait used to be a `WaitQueue` sleep, which a lost wake leaves
/// asleep for good). Canary: before the change the hook was never called
/// (`BLOCKS` 0).
#[test]
fn a_waiter_whose_wake_never_arrives_wakes_on_its_slice() {
    let _one = sleep_model::begin();
    sleep_model::WAKES.store(false, Ordering::SeqCst);
    let took = reaper_and_sleeper(40);
    assert!(sleep_model::BLOCKS.load(Ordering::SeqCst) > 0, "the waiter never slept on a timer");
    let longest = sleep_model::LONGEST_ASK_NS.load(Ordering::SeqCst);
    assert!(longest <= 10_000_000 + 2_000_000, "a sleep of {longest} ns is longer than the longest slice");
    assert!(took.as_millis() < 1_000, "finished after {took:?}");
}

/// The wake path itself: with the timer that never fires (only a wake ends a
/// sleep) the waiter is still released the moment the reaper signals. Run many
/// times so the wake lands between the sleeper's look at the epoch and its
/// block (the stamp must carry it). Canary: with the wake dropped the same
/// run ends only at `GIVE_UP_MS`.
#[test]
fn a_waiter_is_woken_by_the_reaper_and_not_only_by_its_timer() {
    let _one = sleep_model::begin();
    sleep_model::IGNORE_DEADLINE.store(true, Ordering::SeqCst);
    for round in 0..40u64 {
        let took = reaper_and_sleeper(round % 7);
        assert!(took.as_millis() < (sleep_model::GIVE_UP_MS / 2) as u128, "round {round}: asleep for {took:?} despite the wake");
    }
    assert!(sleep_model::WAKE_CALLS.load(Ordering::SeqCst) > 0);
}

// ── Sleeps that end by their deadline are counted ───────────────────────

/// A waiter whose wake never arrives sleeps its slice out; when what it waits
/// for happened meanwhile (the reaper bumps the epoch) the expiry is booked as
/// LOST at `block_done`: the evidence a board boot reads to confirm a dropped
/// wake. The same run books expiries in general.
///
/// **Canary.** Delete the `note_expiry` call in `Sleepers::sleep`: both
/// deltas are 0.
#[test]
fn a_waiter_whose_wake_is_dropped_books_its_expiry_and_the_lost_wake() {
    let _one = sleep_model::begin();
    sleep_model::WAKES.store(false, Ordering::SeqCst);
    let (e0, l0) = azos_sync::waitstat::stats(azos_sync::waitstat::Site::BlockDone);
    let took = reaper_and_sleeper(40);
    let (e1, l1) = azos_sync::waitstat::stats(azos_sync::waitstat::Site::BlockDone);
    assert!(took.as_millis() < 1_000, "finished after {took:?}");
    assert!(e1 > e0, "the sleeper's slices ended at their deadline: expired {e0} -> {e1}");
    assert!(l1 > l0, "the reaper signalled, the wake was dropped, the slice ended with the epoch moved: lost {l0} -> {l1}");
}

// ── A device wait must not sleep through an event posted before the listing ──

mod device_wait {
    use azos_drv_api::block::DeviceWait;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// The event came and its wake found nobody listed (the sleeper was not in
    /// yet): the sleeper's re-check, after it lists itself, sees the event and
    /// it does not block. This is the USB disk's old lost wake: it listed itself
    /// and blocked with no re-check, so the `usb` task's turn before the listing
    /// cost the reaper its whole slice.
    ///
    /// **Canary.** Drop the `ready()` call in `DeviceWait::park` (block always):
    /// the `block` closure runs and the test fails.
    #[test]
    fn an_event_before_the_listing_is_seen_by_the_recheck_and_not_slept_through() {
        let w = DeviceWait::new();
        let event = AtomicBool::new(false);
        // The waker: the event first, then who is listed (nobody).
        event.store(true, Ordering::SeqCst);
        assert_eq!(w.sleeper(), 0, "nobody was listed: this wake reaches no one");
        let slept = w.park(7, || event.load(Ordering::SeqCst), || panic!("blocked with its event already posted"));
        assert!(slept, "the caller looks again at once");
        assert_eq!(w.sleeper(), 0, "the sleeper leaves the slot when it returns");
    }

    /// A listed sleeper is what the waker finds, and only while it is in.
    #[test]
    fn a_listed_sleeper_is_found_by_the_waker() {
        let w = DeviceWait::new();
        let found = AtomicUsize::new(0);
        let slept = w.park(7, || false, || {
            found.store(w.sleeper() as usize, Ordering::SeqCst);
            true
        });
        assert!(slept);
        assert_eq!(found.load(Ordering::SeqCst), 7);
        assert_eq!(w.sleeper(), 0);
    }

    /// The store-then-load pair on both sides (the store buffer litmus): over
    /// many rounds, a sleeper that blocks must have been found by a waker that
    /// posted its event first. Without the fences both loads may read the old
    /// values; x86 shows it within a few thousand rounds.
    ///
    /// **Canary.** Remove the `fence` calls in `DeviceWait::park` and
    /// `sleeper` (and make the accesses Acquire/Release): `missed` becomes
    /// non-zero (measured on x86_64; the order is the same on the other ISAs'
    /// weaker models, where the fence is what the kernel relies on).
    #[test]
    fn a_sleeper_that_blocks_is_always_found_by_a_waker_that_posted_first() {
        const ROUNDS: usize = 300_000;
        let w = DeviceWait::new();
        let event = AtomicBool::new(false);
        let blocked = AtomicBool::new(false);
        let found = AtomicUsize::new(0);
        // Lockstep: both threads wait for the round number, run, then report.
        let round = AtomicUsize::new(0);
        let done = AtomicUsize::new(0);
        let missed = AtomicUsize::new(0);
        // Set by the waker once it has looked at who is listed: a sleeper that
        // blocks stays blocked until then (it is only woken by that look).
        let looked = AtomicBool::new(false);
        std::thread::scope(|s| {
            s.spawn(|| {
                for r in 1..=ROUNDS {
                    while round.load(Ordering::Acquire) != r {
                        std::hint::spin_loop();
                    }
                    w.park(7, || event.load(Ordering::SeqCst), || {
                        blocked.store(true, Ordering::SeqCst);
                        while !looked.load(Ordering::SeqCst) {
                            std::hint::spin_loop();
                        }
                        true
                    });
                    done.fetch_add(1, Ordering::AcqRel);
                }
            });
            s.spawn(|| {
                for r in 1..=ROUNDS {
                    while round.load(Ordering::Acquire) != r {
                        std::hint::spin_loop();
                    }
                    event.store(true, Ordering::SeqCst);
                    found.store(w.sleeper() as usize, Ordering::SeqCst);
                    looked.store(true, Ordering::SeqCst);
                    done.fetch_add(1, Ordering::AcqRel);
                }
            });
            for r in 1..=ROUNDS {
                event.store(false, Ordering::SeqCst);
                blocked.store(false, Ordering::SeqCst);
                found.store(0, Ordering::SeqCst);
                looked.store(false, Ordering::SeqCst);
                done.store(0, Ordering::SeqCst);
                round.store(r, Ordering::Release);
                while done.load(Ordering::Acquire) != 2 {
                    std::hint::spin_loop();
                }
                // The sleeper blocked (saw no event) and the waker, which
                // posted the event first, found nobody to wake: a lost wake.
                if blocked.load(Ordering::SeqCst) && found.load(Ordering::SeqCst) == 0 {
                    missed.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        assert_eq!(missed.load(Ordering::Relaxed), 0, "rounds in which the sleeper blocked and the waker found no one");
    }
}
