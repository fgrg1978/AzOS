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
//! (the decisions', the telemetry's and the security records' by their
//! sequence numbers); anything
//! else (a new boot, a ring that lapped the line) restarts every ring at its
//! oldest record. A restart that starts every ring afresh writes the line
//! [`START_FRESH`]: a seam, the files before it belong to another boot, and
//! resuming never looks across it (a record number of another boot would skip
//! records of this one).

use crate::wire::{self, Lines, LINE_MAX};

/// The message of the start line of a run that read every ring from its oldest
/// record: a new boot, or a ring the files no longer matched.
pub const START_FRESH: &[u8] = b"start: from the oldest record in the ring";

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
    /// The sequence number of the last security record line.
    pub last_security: Option<u64>,
}

impl Tail {
    const EMPTY: Tail = Tail { rec: None, last_decision: None, last_telemetry: None, last_security: None };

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
    /// The file holds a [`START_FRESH`] line; `tail` is what follows the last.
    seam: bool,
}

impl Scan {
    const EMPTY: Scan = Scan { size: 0, serial: None, tail: None, seam: false };
}

/// Read file `slot` into `s`; false when it cannot be opened. Into the caller's
/// value, not a returned one: each holds a line, and the startup's frames are
/// on the program's stack.
fn scan<V: Vol>(vol: &mut V, slot: u8, s: &mut Scan) -> bool {
    let mut lines = Lines::new();
    *s = Scan::EMPTY;
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
            let tail = s.tail.get_or_insert(Tail::EMPTY);
            // Canary: a start line is no seam.
            #[cfg(feature = "canary-logd-resume-across-seam")]
            let fresh = false;
            #[cfg(not(feature = "canary-logd-resume-across-seam"))]
            let fresh = l.module == wire::LOGD_MODULE && l.msg == START_FRESH;
            if fresh {
                s.seam = true;
                tail.rec = None;
                tail.last_decision = None;
                tail.last_telemetry = None;
                tail.last_security = None;
            } else if l.module == wire::DECISION_MODULE {
                tail.last_decision = Some(l.seq);
            } else if l.module == wire::TELEMETRY_MODULE {
                tail.last_telemetry = Some(l.seq);
            } else if l.module == wire::SECURITY_MODULE {
                tail.last_security = Some(l.seq);
            } else if l.module != wire::LOGD_MODULE {
                let mut b = [0u8; LINE_MAX];
                b[..text.len()].copy_from_slice(text);
                tail.rec = Some((l.seq, b, text.len()));
            }
        });
    });
    ok
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
    #[inline(never)]
    pub fn recover<V: Vol>(vol: &mut V, keep: u8, limit: u64) -> (Store, Option<Tail>) {
        let keep = keep.clamp(1, wire::FILE_SLOTS_MAX as u8);
        // The newest file's scan in `s`, the one under way in `p`.
        let (mut s, mut p) = (Scan::EMPTY, Scan::EMPTY);
        let mut best: Option<(u8, u64)> = None;
        for slot in 0..keep {
            if !scan(vol, slot, &mut p) {
                continue;
            }
            let Some(serial) = p.serial else { continue };
            if best.map_or(true, |b| serial > b.1) {
                best = Some((slot, serial));
                core::mem::swap(&mut s, &mut p);
            }
        }
        let Some((slot, serial)) = best else {
            return (Store { slot: 0, serial: 0, size: 0, keep, limit }, None);
        };
        // A source with no line in the newest file (it was rotated in a
        // moment ago, or the source is rare) resumes by the files before it,
        // newest first, not from its ring's oldest record, which would write
        // its lines twice.
        let tail = s.tail.get_or_insert(Tail::EMPTY);
        let mut crossed = s.seam;
        // Canary: look no further back than the file before the newest.
        #[cfg(feature = "canary-logd-resume-one-file")]
        let reach = 2;
        #[cfg(not(feature = "canary-logd-resume-one-file"))]
        let reach = u64::from(keep);
        for back in 1..reach {
            if crossed {
                break;
            }
            if tail.rec.is_some() && tail.last_decision.is_some() && tail.last_telemetry.is_some() && tail.last_security.is_some() {
                break;
            }
            let Some(want) = serial.checked_sub(back).filter(|&w| w > 0) else { break };
            // Serial n was written to slot (n - 1) % keep: the files rotate in order.
            if !scan(vol, ((want - 1) % u64::from(keep)) as u8, &mut p) || p.serial != Some(want) {
                break;
            }
            crossed = p.seam;
            let Some(p) = &mut p.tail else { break };
            if tail.rec.is_none() {
                tail.rec = p.rec.take();
            }
            tail.last_decision = tail.last_decision.or(p.last_decision);
            tail.last_telemetry = tail.last_telemetry.or(p.last_telemetry);
            tail.last_security = tail.last_security.or(p.last_security);
        }
        let any = tail.rec.is_some() || tail.last_decision.is_some() || tail.last_telemetry.is_some() || tail.last_security.is_some();
        (Store { slot, serial, size: s.size, keep, limit }, if any { s.tail } else { None })
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
