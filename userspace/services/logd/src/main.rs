// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `LOGD.ELF`: the sink of the structured kernel log (Kconfig `KLOG`).
//!
//! The kernel pushes every log line as a record `{ts, level, module, msg}`
//! into one ring (`azos_drv_sys::klog`) and grants it by the topology row
//! `MemObj klog.ring` (`READ|MAP`). This program maps it, polls it every
//! `LOGD_POLL_MS`, and appends what arrived to a ring of files
//! (`KLOGn.TXT`, `store.rs`) under the tree its row grants: one append and one
//! `fsync` per period, never one per line. It holds no other authority: it
//! cannot write the ring, and it has no endpoint to serve and none to call.
//! The toolbox's `log` reads the files.
//!
//! Nothing here waits on the kernel and the kernel never waits on this: the
//! ring overwrites its oldest record, and a period in which more than
//! `KLOG_ENTRIES` lines arrived writes a `lost` line saying how many.
//! A write the volume refuses leaves the cursor where it was, so the next
//! period offers the same records again (the ring is the buffer).
//!
//! A start that finds nothing to do (no ring granted, a ring of another layout,
//! no directory) says so and exits 0: the supervisor restarts a failure, and a
//! restart would find the same.
//!
//! Real-time tasks never do block I/O (owner rule): this program runs at the
//! tools' priority, far from the real-time band.

#![no_std]
#![no_main]

use azos_libsys as sys;

// The source the kernel pushes with; this side reads and writes text, so the
// producer half is unused here.
#[allow(dead_code)]
#[path = "../../../../crates/drivers/sys/src/klog/wire.rs"]
mod wire;
mod store;

use store::{Store, Vol};
use wire::{Next, Reader, Record, LINE_MAX};

/// `O_WRONLY`, `O_CREAT`, `O_TRUNC`, `O_APPEND` (`azos_fs` values).
const O_WRONLY: u64 = 0x1;
const O_CREAT: u64 = 0x40;
const O_TRUNC: u64 = 0x200;
const O_APPEND: u64 = 0x400;

/// The tree the row grants, beneath the root directory.
const DIR: &[u8] = b"fat/";

/// Bytes of one batch: the lines a period's write carries at most.
const BATCH: usize = 4096;

/// Polls a record can stay unfinished before the sink gives up on it.
const STUCK_POLLS: u32 = 5;

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

fn say(b: &[u8]) {
    let _ = sys::console_write(sys::STDOUT, b);
}

/// Map the ring the row grants: `(base, bytes)`.
fn map_ring() -> Option<(usize, usize)> {
    let cap = sys::cap_lookup(sys::ty::SHM.raw(), azos_abi::cap::SHM_KLOG_RING);
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

/// `n` in decimal after `prefix`, as a message.
fn msg_num(prefix: &[u8], n: u64, out: &mut [u8; 48]) -> usize {
    out[..prefix.len()].copy_from_slice(prefix);
    let mut d = [0u8; 20];
    let mut i = d.len();
    let mut v = n;
    loop {
        i -= 1;
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out[prefix.len()..prefix.len() + d.len() - i].copy_from_slice(&d[i..]);
    prefix.len() + d.len() - i
}

/// The sink's state: the ring, the files, and how far it has read.
struct Sink {
    rd: Reader,
    vol: SysVol,
    store: Store,
    /// The next record to read.
    cursor: u64,
    /// Up to where the files hold: a failed write returns the cursor here.
    committed: u64,
    /// The record `cursor` is stuck on and for how many polls.
    stuck: (u64, u32),
    batch: [u8; BATCH],
    n: usize,
}

impl Sink {
    /// The tick of `now`, in the ring's timebase.
    fn ticks(&self) -> u64 {
        (sys::vdso_now_ns() as u128 * self.rd.ts_hz() as u128 / 1_000_000_000) as u64
    }

    /// Write the batch. False (and the cursor back at the last write) when the
    /// volume refused.
    fn flush(&mut self) -> bool {
        if self.n == 0 {
            self.committed = self.cursor;
            return true;
        }
        let ts = self.ticks();
        if self.store.write(&mut self.vol, &self.batch[..self.n], ts, self.rd.ts_hz()) {
            self.n = 0;
            self.committed = self.cursor;
            true
        } else {
            self.n = 0;
            self.cursor = self.committed;
            false
        }
    }

    /// Add a notice about `lost` records, ending at the cursor.
    fn lost(&mut self, lost: u64) {
        let mut m = [0u8; 48];
        let k = msg_num(b"records lost: ", lost, &mut m);
        let ts = self.ticks();
        let seq = self.cursor.saturating_sub(1);
        self.n += notice(&mut self.batch[self.n..], wire::LEVEL_WARN, seq, ts, self.rd.ts_hz(), &m[..k]);
    }

    /// One period: everything the ring has, in as few writes as fit.
    fn drain(&mut self) {
        let mut rec = Record::empty();
        loop {
            if self.n + LINE_MAX > BATCH && !self.flush() {
                return;
            }
            match self.rd.next(&mut self.cursor, &mut rec) {
                Next::Record => {
                    self.stuck = (0, 0);
                    if rec.level <= azos_limits::LOGD_MAX_LEVEL as u8 {
                        self.n += wire::line(&rec, self.rd.ts_hz(), &mut self.batch[self.n..]);
                    }
                }
                Next::Lost(n) => self.lost(n),
                Next::Pending => {
                    // A producer claimed it and has not finished: try again
                    // next period, and give up on it if it never does.
                    self.stuck = if self.stuck.0 == self.cursor { (self.cursor, self.stuck.1 + 1) } else { (self.cursor, 1) };
                    if self.stuck.1 >= STUCK_POLLS {
                        self.rd.skip(&mut self.cursor);
                        self.stuck = (0, 0);
                        self.lost(1);
                        continue;
                    }
                    break;
                }
                Next::Empty => break,
            }
        }
        self.flush();
    }
}

#[sys::main(panic_exit = 70)]
fn run() -> i32 {
    let Some((base, bytes)) = map_ring() else {
        // Nothing to sink, and a restart would not change it.
        say(b"logd: no klog.ring granted (Kconfig KLOG off, or the row has none)\n");
        return 0;
    };
    // SAFETY: a read-only mapping of the kernel's ring, held for the life of
    // the program; `open` checks it is one.
    let Some(rd) = (unsafe { Reader::open(base as *const u8, bytes) }) else {
        say(b"logd: the klog.ring is not a ring this build reads\n");
        return 0;
    };
    let root = sys::root_dir();
    if root < 0 {
        say(b"logd: no root directory granted\n");
        return 0;
    }
    let mut vol = SysVol { root: root as u32 };
    let limit = azos_limits::LOGD_FILE_KB as u64 * 1024;
    let (store, tail) = Store::recover(&mut vol, azos_limits::LOGD_FILES_KEEP as u8, limit);

    // Resume after the file's last record when the ring still holds it, else
    // start at the ring's oldest.
    let mut cursor = rd.oldest();
    let mut resumed = false;
    if let Some(t) = &tail {
        if let Some(seq) = t.rec_seq() {
            let (mut c, mut rec) = (seq, Record::empty());
            if rd.next(&mut c, &mut rec) == Next::Record {
                let mut line = [0u8; LINE_MAX];
                let n = wire::line(&rec, rd.ts_hz(), &mut line);
                if t.matches(seq, &line[..n - 1]) {
                    cursor = (t.last_seq + 1).min(rd.head());
                    resumed = true;
                }
            }
        }
    }
    say(b"[logd] AzOS kernel log sink (klog.ring to KLOGn.TXT)\n");
    let mut sink = Sink { rd, vol, store, cursor, committed: cursor, stuck: (0, 0), batch: [0; BATCH], n: 0 };
    // The start line: where this run begins, so a reader of the files sees the
    // seam (a new boot, or a restart).
    {
        let ts = sink.ticks();
        let seq = sink.cursor.saturating_sub(1);
        let msg: &[u8] = if resumed { b"start: resumed after the last record" } else { b"start: from the oldest record in the ring" };
        sink.n += notice(&mut sink.batch, wire::LEVEL_INFO, seq, ts, sink.rd.ts_hz(), msg);
    }
    let period_ns = azos_limits::LOGD_POLL_MS as u64 * 1_000_000;
    let mut next = sys::vdso_now_ns() + period_ns;
    loop {
        sink.drain();
        let _ = sys::sleep_until_ns(next);
        next = next.max(sys::vdso_now_ns()) + period_ns;
    }
}
