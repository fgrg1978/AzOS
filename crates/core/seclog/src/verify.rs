// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The verifier: an exported log's security records, in file order, checked
//! against the chain and the seals they carry.
//!
//! It recomputes every head and compares it with each seal's, recomputes
//! every anchor from the boot's [`Anchor`] record, and links each boot's
//! anchor to the previous boot's last seal. It reports what it finds
//! ([`Finding`]) as it goes and never stops at the first: a rewrite is
//! reported, the chain resynchronised on the seal, and the records after it
//! checked again.
//!
//! What it cannot do offline: an export rewritten whole, every head and
//! anchor recomputed, is consistent with itself. Only the anchor the hardware
//! holds now, or seals a receiver kept off the device, refute it; the tool
//! compares those ([`Summary::last_anchor`], [`Summary::seals`]).

use crate::chain::{extend, fold_canon, genesis};
use crate::{canon, kind, Anchor, Backend, Envelope, Hash, Loss, Seal, CANON_MAX};

/// Records kept to recompute a seal's head (a seal covers the records before
/// `through`, and records published while it was taken come before it).
pub const HISTORY: usize = 1024;
/// Gaps held until the next seal says whether the kernel declared them.
const GAPS: usize = 32;

/// What the verifier found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finding {
    /// The boot's records in the export begin at `first`, not 0: the files
    /// rotated them out, or they were removed.
    Truncated { boot: u32, first: u64 },
    /// `count` records from `first` are not in the export. `declared`: the
    /// kernel's own [`Loss`] record names them (the sealer never saw them).
    Gap { boot: u32, first: u64, count: u64, declared: bool },
    /// Record `seq` came after record `after`.
    Reorder { boot: u32, seq: u64, after: u64 },
    /// The seal at `seq` names a head the records before it do not give: a
    /// record was rewritten, inserted or removed.
    Rewrite { boot: u32, seq: u64 },
    /// The seal at `seq` cannot be checked: records it covers are missing.
    Unverifiable { boot: u32, seq: u64 },
    /// The seal at `seq` names an anchor its head does not give from the one
    /// before it: a seal was forged or one is missing.
    AnchorMismatch { boot: u32, seq: u64 },
    /// The boot's anchor is not the previous boot's last seal: the previous
    /// boot's sealed tail is not in the export, or the anchor was reset.
    LinkBroken { boot: u32 },
    /// `count` records after the boot's last seal: no seal covers them.
    Unsealed { boot: u32, count: u64 },
    /// The boot's seals are not held by hardware (the forward-only backend,
    /// or a commit the hardware refused).
    Advisory { boot: u32 },
    /// A record whose payload does not decode as its kind.
    Malformed { boot: u32, seq: u64 },
}

impl Finding {
    /// Evidence of tampering (or of a loss nobody declared), as opposed to
    /// what an honest log can also show.
    pub fn is_evidence(&self) -> bool {
        match *self {
            Finding::Gap { declared, .. } => !declared,
            Finding::Reorder { .. }
            | Finding::Rewrite { .. }
            | Finding::Unverifiable { .. }
            | Finding::AnchorMismatch { .. }
            | Finding::LinkBroken { .. }
            | Finding::Malformed { .. } => true,
            Finding::Truncated { .. } | Finding::Unsealed { .. } | Finding::Advisory { .. } => false,
        }
    }
}

/// Totals over the export.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub boots: u32,
    pub records: u64,
    pub events: u64,
    /// Seals seen, and of those the ones whose head and anchor checked out.
    pub seals: u64,
    pub seals_verified: u64,
    /// Seals the hardware holds.
    pub seals_hardware: u64,
    pub evidence: u64,
    /// The last boot's backend, and the anchor its last seal (or, with none,
    /// its boot anchor) names: what a live TPM index must hold if the export
    /// is whole.
    pub backend: Option<Backend>,
    pub last_anchor: Option<Hash>,
}

#[derive(Clone, Copy)]
struct Hist {
    seq: u64,
    head: Hash,
    canon: [u8; CANON_MAX],
    len: u8,
}

const NO_HIST: Hist = Hist { seq: u64::MAX, head: [0; 32], canon: [0; CANON_MAX], len: 0 };

#[derive(Clone, Copy)]
struct Gap {
    first: u64,
    count: u64,
    declared: bool,
}

pub struct Verifier {
    boot: u32,
    last: Option<u64>,
    head: Hash,
    anchor: Option<Hash>,
    advisory: bool,
    hist: [Hist; HISTORY],
    /// The history's next slot and how many it holds.
    at: usize,
    held: usize,
    gaps: [Gap; GAPS],
    ngaps: usize,
    /// A gap left the head unknown until a seal resyncs it.
    broken: bool,
    /// The boot's first records are not in the export: the head is unknown
    /// until the first seal, which is adopted unchecked.
    unknown: bool,
    seam: bool,
    since_seal: u64,
    prev_anchor: Option<Hash>,
    sum: Summary,
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier {
    pub fn new() -> Verifier {
        Verifier {
            boot: 0,
            last: None,
            head: genesis(),
            anchor: None,
            advisory: false,
            hist: [NO_HIST; HISTORY],
            at: 0,
            held: 0,
            gaps: [Gap { first: 0, count: 0, declared: false }; GAPS],
            ngaps: 0,
            broken: false,
            unknown: false,
            seam: false,
            since_seal: 0,
            prev_anchor: None,
            sum: Summary::default(),
        }
    }

    /// `logd` started reading the ring afresh here: the next record may begin
    /// a boot.
    pub fn seam(&mut self) {
        self.seam = true;
    }

    fn emit(&mut self, f: Finding, out: &mut dyn FnMut(Finding)) {
        if f.is_evidence() {
            self.sum.evidence += 1;
        }
        out(f);
    }

    fn start_boot(&mut self, first: u64, out: &mut dyn FnMut(Finding)) {
        self.boot += 1;
        self.sum.boots += 1;
        self.head = genesis();
        self.anchor = None;
        self.advisory = false;
        (self.at, self.held, self.ngaps, self.since_seal) = (0, 0, 0, 0);
        self.broken = false;
        self.unknown = first != 0;
        self.last = None;
        if first != 0 {
            self.emit(Finding::Truncated { boot: self.boot, first }, out);
        }
    }

    fn end_boot(&mut self, out: &mut dyn FnMut(Finding)) {
        if self.boot == 0 {
            return;
        }
        self.flush_gaps(out);
        if self.since_seal > 0 {
            self.emit(Finding::Unsealed { boot: self.boot, count: self.since_seal }, out);
        }
        if self.advisory {
            self.emit(Finding::Advisory { boot: self.boot }, out);
        }
        self.prev_anchor = self.anchor;
    }

    fn flush_gaps(&mut self, out: &mut dyn FnMut(Finding)) {
        for i in 0..self.ngaps {
            let g = self.gaps[i];
            self.emit(Finding::Gap { boot: self.boot, first: g.first, count: g.count, declared: g.declared }, out);
        }
        self.ngaps = 0;
    }

    fn gap(&mut self, first: u64, count: u64, out: &mut dyn FnMut(Finding)) {
        if cfg!(feature = "canary-no-gap-check") {
            return;
        }
        self.broken = true;
        if self.ngaps == GAPS {
            self.flush_gaps(out);
        }
        self.gaps[self.ngaps] = Gap { first, count, declared: false };
        self.ngaps += 1;
    }

    fn declare(&mut self, l: &Loss) {
        let end = l.first.saturating_add(l.count);
        let mut all = true;
        for g in &mut self.gaps[..self.ngaps] {
            if g.first >= l.first && g.first + g.count <= end {
                g.declared = true;
            }
            all &= g.declared;
        }
        // Every gap since the last seal is the kernel's own: the head is
        // still the one the sealer computed.
        if all && self.ngaps > 0 {
            self.broken = false;
        }
    }

    fn head_before(&self, through: u64) -> Option<Hash> {
        if through == 0 {
            return Some(genesis());
        }
        (0..self.held)
            .map(|k| &self.hist[(self.at + HISTORY - 1 - k) % HISTORY])
            .find(|h| h.seq < through)
            .map(|h| h.head)
    }

    /// Head := the seal's, refolding the held records it does not cover.
    fn resync(&mut self, s: &Seal) {
        let mut head = s.head;
        for k in (0..self.held).rev() {
            let i = (self.at + HISTORY - 1 - k) % HISTORY;
            if self.hist[i].seq >= s.through {
                let h = &mut self.hist[i];
                head = fold_canon(&head, &h.canon[..h.len as usize]);
                h.head = head;
            }
        }
        self.head = head;
        self.broken = false;
        self.unknown = false;
    }

    fn check_seal(&mut self, seq: u64, s: &Seal, out: &mut dyn FnMut(Finding)) {
        self.sum.seals += 1;
        if s.hardware {
            self.sum.seals_hardware += 1;
        } else {
            self.advisory = true;
        }
        let want = self.head_before(s.through);
        let head_ok = cfg!(feature = "canary-no-chain-check") || want == Some(s.head);
        if !head_ok {
            if self.broken || (want.is_none() && !self.unknown) {
                self.emit(Finding::Unverifiable { boot: self.boot, seq }, out);
            } else if !self.unknown {
                self.emit(Finding::Rewrite { boot: self.boot, seq }, out);
            }
            self.resync(s);
        }
        self.unknown = false;
        self.sum.backend = Some(s.backend);
        let anchor_ok = cfg!(feature = "canary-no-anchor-check") || self.anchor.map(|a| extend(&a, &s.head)) == Some(s.anchor);
        if !anchor_ok && self.anchor.is_some() {
            self.emit(Finding::AnchorMismatch { boot: self.boot, seq }, out);
        }
        if head_ok && anchor_ok {
            self.sum.seals_verified += 1;
        }
        self.anchor = Some(s.anchor);
        self.flush_gaps(out);
        self.since_seal = 0;
    }

    fn check_anchor(&mut self, a: &Anchor, out: &mut dyn FnMut(Finding)) {
        if !a.hardware {
            self.advisory = true;
        } else if let Some(p) = self.prev_anchor {
            if p != a.value && !cfg!(feature = "canary-no-anchor-check") {
                self.emit(Finding::LinkBroken { boot: self.boot }, out);
            }
        }
        self.anchor = Some(a.value);
        self.sum.backend = Some(a.backend);
    }

    /// The next record of the export.
    pub fn record(&mut self, env: &Envelope, payload: &[u8], out: &mut dyn FnMut(Finding)) {
        let seq = env.seq;
        let new_boot = match self.last {
            None => true,
            Some(last) => seq <= last && (self.seam || seq == 0),
        };
        if new_boot {
            self.end_boot(out);
            self.start_boot(seq, out);
        } else if let Some(last) = self.last {
            if seq <= last {
                if !cfg!(feature = "canary-no-order-check") {
                    self.emit(Finding::Reorder { boot: self.boot, seq, after: last }, out);
                }
            } else if seq > last + 1 {
                self.gap(last + 1, seq - last - 1, out);
            }
        }
        self.seam = false;
        self.sum.records += 1;
        let len = (env.len as usize).min(payload.len());
        let p = &payload[..len];
        let malformed = match env.kind {
            kind::EVENT => {
                self.sum.events += 1;
                crate::Event::decode(p).is_none()
            }
            kind::SEAL => match Seal::decode(p) {
                Some(s) => {
                    self.check_seal(seq, &s, out);
                    false
                }
                None => true,
            },
            kind::ANCHOR => match Anchor::decode(p) {
                Some(a) => {
                    self.check_anchor(&a, out);
                    false
                }
                None => true,
            },
            kind::LOSS => match Loss::decode(p) {
                Some(l) => {
                    self.declare(&l);
                    false
                }
                None => true,
            },
            _ => true,
        };
        if malformed {
            self.emit(Finding::Malformed { boot: self.boot, seq }, out);
        }
        let mut c = [0u8; CANON_MAX];
        let n = canon(env, payload, &mut c);
        self.head = fold_canon(&self.head, &c[..n]);
        self.hist[self.at] = Hist { seq, head: self.head, canon: c, len: n as u8 };
        self.at = (self.at + 1) % HISTORY;
        self.held = (self.held + 1).min(HISTORY);
        if env.kind != kind::SEAL {
            self.since_seal += 1;
        }
        self.last = Some(self.last.map_or(seq, |l| l.max(seq)));
    }

    /// The end of the export.
    pub fn finish(&mut self, out: &mut dyn FnMut(Finding)) -> Summary {
        self.end_boot(out);
        self.sum.last_anchor = self.anchor;
        self.sum
    }
}
