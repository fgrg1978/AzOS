// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sealer's pass over the security ring: pure, so the kernel's `seclog`
//! task and the host tests run the same code.
//!
//! A pass reads the ring from where the last one stopped and folds every
//! record into the chain. What it declares, in records that are themselves
//! in the chain: what the ring overwrote before it read it, or a record a
//! producer never finished (still pending three passes later), with the
//! classes the producers copied and no pass folded (`loss`, an upper bound:
//! a record copied while the pass ran counts too); what the producers' rate
//! cap held back, by class and by the subjects held most (`held`); and what
//! the sink says on its page it never wrote (`sink-loss`), the part the ring
//! has really dropped, with the classes the pass folded. A claim of records
//! still in the ring waits until the ring drops them.
//!
//! It seals at its first pass, every `seal_s`, `urgent_s` after a record of
//! a high-value class, at once after it declared a loss (so the declaration
//! is covered), and when forced. A seal that is not due by the period is
//! urgent: at most `urgent_per_day` of them in any day, `urgent_s` apart, so
//! no trigger can wear the TPM faster than `86400 / seal_s + urgent_per_day`
//! seals a day.

use crate::ack::{Page, CLAIMS};
use crate::chain::Sealer;
use crate::{kind, Event, Hash, Held, Loss, Seal, CLASSES, FLAG_DIVERGED, PAYLOAD};
use azos_rings::region::record::{Envelope, Read, Ring};

/// The hardware a boot seals to (the TPM's indexes).
pub trait Hw {
    /// Increment the counter: its value after; `None` when not taken.
    fn increment(&mut self) -> Option<u64>;
    /// Extend the anchor with a seal's data; false when not taken.
    fn extend(&mut self, data: &Hash) -> bool;
    /// The anchor's value now; `None` when it cannot be read.
    fn read(&mut self) -> Option<Hash>;
}

/// What the pass needs of the kernel.
pub trait Host {
    /// The timebase now.
    fn now(&self) -> u64;
    /// The producers' copies and what their cap held back, by class, and the
    /// subjects it held most: `(subject, count)`.
    fn tally(&self) -> ([u32; CLASSES], [u32; CLASSES], [(u32, u32); Held::SUBJECTS]);
    /// Publish a record of `kind` to the security ring: its sequence number.
    fn publish(&mut self, kind: u16, payload: &[u8]) -> u64;
    /// A seal was taken (the console line).
    fn sealed(&mut self, seal: &Seal, hardware: bool);
    /// Something the console should say.
    fn note(&mut self, n: Note);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Note {
    /// The hardware refused a seal: the boot's seals are advisory from here.
    Refused,
    /// The anchor read back is not the one the extend gives.
    Diverged,
    /// The sink wrote more claims than its page holds between two passes.
    ClaimsLapped,
    /// An urgent seal was due and the day's budget was spent.
    UrgentBudget,
}

/// The pass's numbers (Kconfig `SEC_LOG_SEAL_S`, `SEC_LOG_SEAL_URGENT_S`,
/// `SEC_LOG_URGENT_PER_DAY`, the timebase's rate).
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub hz: u64,
    pub seal_s: u64,
    pub urgent_s: u64,
    pub urgent_per_day: u32,
}

/// Passes a record may stay pending before the sealer declares it lost.
const PENDING_PASSES: u32 = 3;

/// The sealer across passes; `LOG` records' classes remembered by sequence
/// number (what a `sink-loss` can name).
pub struct Pass<const LOG: usize> {
    s: Sealer,
    cursor: u64,
    pending: u32,
    folded: [u32; CLASSES],
    declared: [u32; CLASSES],
    held_seen: [u32; CLASSES],
    classes: [u8; LOG],
    loss: Option<(u64, u64)>,
    sink_seen: u64,
    /// Sink claims not yet declared whole: `(first, end)`.
    claims: [(u64, u64); CLAIMS],
    nclaims: usize,
    last_seal: u64,
    urgent_since: Option<u64>,
    /// The urgent seals of the day that began at `day`.
    day: u64,
    urgent_used: u32,
    sealed: bool,
    /// A declaration no seal covers yet.
    uncovered: bool,
    hw_failed: bool,
    flags: u8,
    /// The sink's heartbeat as last seen, and when it last moved.
    beat: u64,
    beat_at: u64,
}

impl<const LOG: usize> Pass<LOG> {
    /// A boot's pass: the sealer it folds into, the flags its seals carry
    /// (`FLAG_UNDELETABLE`), and the time it starts.
    pub fn new(s: Sealer, flags: u8, now: u64) -> Self {
        Pass {
            s,
            cursor: 0,
            pending: 0,
            folded: [0; CLASSES],
            declared: [0; CLASSES],
            held_seen: [0; CLASSES],
            classes: [0; LOG],
            loss: None,
            sink_seen: 0,
            claims: [(0, 0); CLAIMS],
            nclaims: 0,
            last_seal: now,
            urgent_since: None,
            day: now,
            urgent_used: 0,
            sealed: false,
            uncovered: false,
            hw_failed: false,
            flags,
            beat: 0,
            beat_at: now,
        }
    }

    pub fn sealer(&self) -> &Sealer {
        &self.s
    }

    /// When the sink's heartbeat last moved.
    pub fn sink_alive_at(&self) -> u64 {
        self.beat_at
    }

    /// Fold what the ring holds, declare what was lost or held, and seal if
    /// one is due (or `force`d): the seal record's sequence number when one
    /// was taken.
    pub fn run(
        &mut self, ring: &Ring, sink: Option<&Page>, hw: Option<&mut dyn Hw>, host: &mut dyn Host, cfg: &Config, force: bool,
    ) -> Option<u64> {
        let now = host.now();
        let mut declared = self.drain(ring, host, now);
        declared |= self.declare(ring, sink, host, now);
        if declared {
            // What it just declared is folded now, so this seal covers it.
            self.drain(ring, host, now);
            self.flush_loss(host);
            self.drain(ring, host, now);
            self.uncovered = true;
        }
        if self.s.unsealed() == 0 {
            return None;
        }
        let period = !self.sealed || now.wrapping_sub(self.last_seal) >= cfg.seal_s * cfg.hz;
        let wanted = self.uncovered || self.urgent_since.is_some_and(|t| now.wrapping_sub(t) >= cfg.urgent_s * cfg.hz);
        if !(force || period || wanted) {
            return None;
        }
        if !(force || period) {
            if now.wrapping_sub(self.day) >= 86_400 * cfg.hz {
                (self.day, self.urgent_used) = (now, 0);
            }
            let spaced = now.wrapping_sub(self.last_seal) >= cfg.urgent_s * cfg.hz;
            if !spaced {
                return None;
            }
            if self.urgent_used >= cfg.urgent_per_day {
                host.note(Note::UrgentBudget);
                return None;
            }
            self.urgent_used += 1;
        }
        Some(self.seal(hw, host, now))
    }

    /// Read and fold what the ring holds: whether a loss was declared.
    fn drain(&mut self, ring: &Ring, host: &mut dyn Host, now: u64) -> bool {
        let mut declared = false;
        let (mut env, mut p) = (Envelope::default(), [0u8; PAYLOAD]);
        loop {
            match ring.read(&mut self.cursor, &mut env, &mut p) {
                Read::Record => {
                    self.pending = 0;
                    let skipped = self.s.skip_to(env.seq);
                    declared |= self.note_loss(skipped, host);
                    if self.s.fold(&env, &p) {
                        let class = (env.kind == kind::EVENT).then(|| Event::decode(&p).map(|e| e.class)).flatten();
                        self.classes[(env.seq % LOG as u64) as usize] = class.map_or(0, |c| c as u8);
                        if let Some(c) = class {
                            self.folded[c as usize] += 1;
                            if c.high_value() && self.urgent_since.is_none() {
                                self.urgent_since = Some(now);
                            }
                        }
                    }
                }
                Read::Pending if self.pending < PENDING_PASSES => {
                    self.pending += 1;
                    break;
                }
                Read::Pending => {
                    self.pending = 0;
                    ring.skip(&mut self.cursor);
                    let skipped = self.s.skip_to(self.cursor);
                    declared |= self.note_loss(skipped, host);
                }
                Read::Lost(_) | Read::Stale => {
                    let skipped = self.s.skip_to(self.cursor);
                    declared |= self.note_loss(skipped, host);
                }
                Read::Empty => break,
            }
        }
        declared
    }

    /// A loss: merged with the one before when they touch, else the one
    /// before is declared now.
    fn note_loss(&mut self, l: Option<(u64, u64)>, host: &mut dyn Host) -> bool {
        let Some((first, count)) = l else { return false };
        self.loss = Some(match self.loss {
            Some((f, c)) if f + c == first => (f, c + count),
            Some(prev) => {
                self.publish_loss(prev, host);
                (first, count)
            }
            None => (first, count),
        });
        true
    }

    fn flush_loss(&mut self, host: &mut dyn Host) {
        if let Some(l) = self.loss.take() {
            self.publish_loss(l, host);
        }
    }

    /// The loss, with the classes the producers copied and no pass folded.
    fn publish_loss(&mut self, (first, count): (u64, u64), host: &mut dyn Host) {
        let (copied, _, _) = host.tally();
        let mut by_class = [0u32; CLASSES];
        for c in 0..CLASSES {
            by_class[c] = copied[c].saturating_sub(self.folded[c]).saturating_sub(self.declared[c]);
            self.declared[c] += by_class[c];
        }
        host.publish(kind::LOSS, &Loss { first, count, by_class }.encode());
    }

    /// Declare the pass's loss, what the cap held back and what the sink
    /// claims: whether a loss was declared.
    fn declare(&mut self, ring: &Ring, sink: Option<&Page>, host: &mut dyn Host, now: u64) -> bool {
        let mut declared = self.loss.is_some();
        self.flush_loss(host);
        let (_, held, subjects) = host.tally();
        let mut delta = [0u32; CLASSES];
        for c in 0..CLASSES {
            delta[c] = held[c].wrapping_sub(self.held_seen[c]);
        }
        if delta.iter().any(|&d| d != 0) {
            self.held_seen = held;
            host.publish(kind::HELD, &Held { by_class: delta, subjects }.encode());
        }
        let Some(page) = sink else { return declared };
        let b = page.beat.load(core::sync::atomic::Ordering::Relaxed);
        if b != self.beat {
            (self.beat, self.beat_at) = (b, now);
        }
        let (oldest, head, next) = (ring.oldest(), ring.head(), self.s.next());
        let mut lapped = false;
        let mut fresh = [(0u64, 0u64); CLAIMS];
        let mut nfresh = 0;
        self.sink_seen = page.read_claims(self.sink_seen, |c| match c {
            Some((first, count)) if nfresh < CLAIMS => {
                fresh[nfresh] = (first, first.saturating_add(count));
                nfresh += 1;
            }
            _ => lapped = true,
        });
        if lapped {
            host.note(Note::ClaimsLapped);
        }
        for &(first, end) in &fresh[..nfresh] {
            // A claim of records not yet written is no loss.
            if first < head && first < end {
                if self.nclaims == CLAIMS {
                    self.claims.copy_within(1.., 0);
                    self.nclaims -= 1;
                    host.note(Note::ClaimsLapped);
                }
                self.claims[self.nclaims] = (first, end.min(head));
                self.nclaims += 1;
            }
        }
        // Only what the ring has dropped and the pass has read; the rest of
        // a claim waits for the ring to drop it.
        let mut i = 0;
        while i < self.nclaims {
            let (first, end) = self.claims[i];
            let upto = end.min(oldest).min(next);
            if upto > first {
                self.publish_sink_loss(first, upto - first, host);
                declared = true;
            }
            if upto >= end {
                self.claims.copy_within(i + 1..self.nclaims, i);
                self.nclaims -= 1;
            } else {
                self.claims[i].0 = first.max(upto);
                i += 1;
            }
        }
        declared
    }

    fn publish_sink_loss(&mut self, first: u64, count: u64, host: &mut dyn Host) {
        let next = self.s.next();
        let end = first + count;
        // The classes the log still has; the rest (index 0) not known.
        let known_from = first.max(next.saturating_sub(LOG as u64));
        let known_to = end.min(next);
        let mut by_class = [0u32; CLASSES];
        let mut known = 0u64;
        for seq in known_from..known_to.max(known_from) {
            by_class[self.classes[(seq % LOG as u64) as usize] as usize] += 1;
            known += 1;
        }
        by_class[0] = by_class[0].saturating_add((count - known).min(u32::MAX as u64) as u32);
        self.s.sink_lost(first, count);
        host.publish(kind::SINK_LOSS, &Loss { first, count, by_class }.encode());
    }

    fn seal(&mut self, hw: Option<&mut dyn Hw>, host: &mut dyn Host, now: u64) -> u64 {
        let hw = hw.filter(|_| !self.hw_failed);
        let present = hw.is_some();
        let (hardware, counter, held) = match hw {
            Some(h) => match h.increment() {
                Some(c) => {
                    let ok = h.extend(&self.s.data(c));
                    (ok, c, if ok { h.read() } else { None })
                }
                None => (false, 0, None),
            },
            None => (false, 0, None),
        };
        if present && !hardware {
            self.hw_failed = true;
            host.note(Note::Refused);
        }
        let seal = self.s.seal(hardware, counter, held, self.flags);
        if seal.flags & FLAG_DIVERGED != 0 {
            host.note(Note::Diverged);
        }
        let seq = host.publish(kind::SEAL, &seal.encode());
        host.sealed(&seal, hardware);
        (self.last_seal, self.urgent_since, self.sealed, self.uncovered) = (now, None, true, false);
        seq
    }
}
