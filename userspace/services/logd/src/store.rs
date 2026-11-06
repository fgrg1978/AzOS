// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The files `logd` keeps: a ring of `KLOGn.TXT`, appended to until one holds
//! `limit` bytes, then the next is truncated and started (Kconfig
//! `LOGD_FILE_KB`, `LOGD_FILES_KEEP`), so the log never takes more than
//! `keep x limit` of the volume. Pure: the volume is a trait, the host tests
//! run this file as it ships (`tests/host/libsys-tests`).
//!
//! **Order.** The kernel's sequence numbers start again at every boot, so the
//! files cannot be ordered by them. Each file opens with a line `file N`
//! (`wire::file_head`), N one more than the file before it: the newest file is
//! the one with the highest N, and `log` reads them in that order.
//!
//! **Where to resume.** After a restart the sink must neither write a record
//! twice nor skip one. The newest file's last kernel log line is compared,
//! byte for byte, with the same sequence number rendered from the kernel log's
//! ring ([`Tail::matches`]): equal means the region still is the stream that
//! line came from, and the sink resumes every ring after its own last line
//! (the decisions' and the telemetry's by their sequence numbers); anything
//! else (a new boot, a ring that lapped the line) restarts every ring at its
//! oldest record.

use crate::wire::{self, Lines, LINE_MAX};

/// The volume: two operations, so a test can script it.
pub trait Vol {
    /// Stream the file `name` (NUL-terminated) to `f`; false when it cannot be
    /// opened.
    fn read_file(&mut self, name: &[u8], f: &mut dyn FnMut(&[u8])) -> bool;
    /// Append `data` to the file `name` (NUL-terminated), creating it, after
    /// emptying it when `truncate`; durable (`fsync`) when it returns true.
    fn append(&mut self, name: &[u8], truncate: bool, data: &[u8]) -> bool;
}

/// What the newest file ends with.
pub struct Tail {
    /// The last line a kernel log record made (not `logd`'s own, not another
    /// source's), without its newline, and its sequence number.
    rec: Option<(u64, [u8; LINE_MAX], usize)>,
    /// The sequence number of the last decision record line.
    pub last_decision: Option<u64>,
    /// The sequence number of the last telemetry line.
    pub last_telemetry: Option<u64>,
}

impl Tail {
    /// Is `ring_line` (record `seq` of the ring, rendered) the line this file
    /// last recorded for that sequence number?
    pub fn matches(&self, seq: u64, ring_line: &[u8]) -> bool {
        match &self.rec {
            Some((s, line, n)) => *s == seq && &line[..*n] == ring_line,
            None => false,
        }
    }
    /// The sequence number of the last kernel record in the file.
    pub fn rec_seq(&self) -> Option<u64> {
        self.rec.as_ref().map(|r| r.0)
    }
}

/// What reading one file found.
struct Scan {
    size: u64,
    serial: Option<u64>,
    tail: Option<Tail>,
}

fn scan<V: Vol>(vol: &mut V, slot: u8) -> Option<Scan> {
    let mut lines = Lines::new();
    let mut s = Scan { size: 0, serial: None, tail: None };
    let mut first = true;
    let name = wire::file_name(slot);
    let ok = vol.read_file(&name, &mut |chunk: &[u8]| {
        s.size += chunk.len() as u64;
        lines.feed(chunk, &mut |text: &[u8]| {
            let Some(l) = wire::parse(text) else { return };
            if first {
                first = false;
                s.serial = wire::head_serial(&l);
            }
            let tail = s.tail.get_or_insert(Tail { rec: None, last_decision: None, last_telemetry: None });
            if l.module == wire::DECISION_MODULE {
                tail.last_decision = Some(l.seq);
            } else if l.module == wire::TELEMETRY_MODULE {
                tail.last_telemetry = Some(l.seq);
            } else if l.module != wire::LOGD_MODULE {
                let mut b = [0u8; LINE_MAX];
                b[..text.len()].copy_from_slice(text);
                tail.rec = Some((l.seq, b, text.len()));
            }
        });
    });
    ok.then_some(s)
}

/// The ring of files: which one is open, how full it is.
pub struct Store {
    slot: u8,
    /// The serial of the open file; 0 before any file exists.
    serial: u64,
    size: u64,
    keep: u8,
    limit: u64,
}

impl Store {
    /// Find the newest file (the highest serial among the `keep` slots) and
    /// what it ends with. A volume with no file starts at slot 0.
    pub fn recover<V: Vol>(vol: &mut V, keep: u8, limit: u64) -> (Store, Option<Tail>) {
        let keep = keep.clamp(1, wire::FILE_SLOTS_MAX as u8);
        let mut best: Option<(u8, u64, Scan)> = None;
        for slot in 0..keep {
            let Some(s) = scan(vol, slot) else { continue };
            let Some(serial) = s.serial else { continue };
            if best.as_ref().map_or(true, |b| serial > b.1) {
                best = Some((slot, serial, s));
            }
        }
        let Some((slot, serial, s)) = best else {
            return (Store { slot: 0, serial: 0, size: 0, keep, limit }, None);
        };
        // A source with no line in the newest file (it was rotated in a
        // moment ago) resumes by the file before it, not from its ring's
        // oldest record, which would write its lines twice.
        let mut tail = s.tail;
        if tail.as_ref().map_or(true, |t| t.rec.is_none() || t.last_decision.is_none() || t.last_telemetry.is_none()) {
            let prev = (0..keep).filter_map(|k| scan(vol, k)).find(|p| p.serial == Some(serial - 1)).and_then(|p| p.tail);
            if let Some(p) = prev {
                let t = tail.get_or_insert(Tail { rec: None, last_decision: None, last_telemetry: None });
                if t.rec.is_none() {
                    t.rec = p.rec;
                }
                t.last_decision = t.last_decision.or(p.last_decision);
                t.last_telemetry = t.last_telemetry.or(p.last_telemetry);
            }
        }
        (Store { slot, serial, size: s.size, keep, limit }, tail)
    }

    /// Append `batch` (whole lines). Opens the next file first when it would
    /// not fit the open one, writing that file's opening line with `ts` (the
    /// timebase tick, in `hz`). False when the volume refused; the state then
    /// says what is on it.
    pub fn write<V: Vol>(&mut self, vol: &mut V, batch: &[u8], ts: u64, hz: u64) -> bool {
        if self.serial == 0 || (self.size > 0 && self.size + batch.len() as u64 > self.limit) {
            let slot = if self.serial == 0 { 0 } else { (self.slot + 1) % self.keep };
            let serial = self.serial + 1;
            let mut msg = [0u8; 24];
            let n = wire::file_head(serial, &mut msg);
            let rec = wire::Record::make(0, ts, wire::LEVEL_INFO, 0, 0, "logd", &msg[..n]);
            let mut head = [0u8; LINE_MAX];
            let h = wire::line(&rec, hz, &mut head);
            if !vol.append(&wire::file_name(slot), true, &head[..h]) {
                return false;
            }
            (self.slot, self.serial, self.size) = (slot, serial, h as u64);
        }
        if batch.is_empty() {
            return true;
        }
        if !vol.append(&wire::file_name(self.slot), false, batch) {
            return false;
        }
        self.size += batch.len() as u64;
        true
    }
}
