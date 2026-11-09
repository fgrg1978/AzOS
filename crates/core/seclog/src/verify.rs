// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The verifier: an exported log's security records, in file order, checked
//! against the chain and the seals they carry.
//!
//! It recomputes every head and compares it with each seal's, checks every
//! seal's anchor from the one before it, and links each boot, through the
//! boot anchor every seal carries, to the last value the hardware took
//! before it, so a boot whose first records are gone is still linked. It
//! reports what it finds ([`Finding`]) and never stops at the first: a
//! rewrite is reported, the chain resynchronised on the seal, and the records
//! after it checked again. What depends on a declaration that may come later
//! in the boot (a loss the kernel declares for the sealer or for the sink) is
//! decided when the boot ends.
//!
//! What it cannot do offline: an export rewritten whole, every head and
//! anchor recomputed, is consistent with itself. Only the anchor and counter
//! the hardware holds now, or seals a receiver kept off the device, refute
//! it; the tool compares those ([`Verifier::live`], [`Summary::seals`]).

use crate::chain::{data_of, declaration, extend, fold_canon, genesis, seal_data, SealNumbers};
use crate::{
    canon, kind, Anchor, Backend, Class, Envelope, Hash, Held, Loss, Reason, Seal, CANON_MAX, CLASSES, FLAG_DIVERGED,
};

/// Records kept to recompute a seal's head (a seal covers the records before
/// `through`, and records published while it was taken come before it).
pub const HISTORY: usize = 1024;
/// Gaps, declared ranges and unverifiable seals a boot holds until it ends.
const PENDING: usize = 64;
/// Records after a seam held while they repeat what the boot already gave.
const DUPS: usize = 64;

/// Who declared a gap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum By {
    /// Nobody: records were removed.
    Nobody,
    /// The kernel's sealer never saw them ([`kind::LOSS`]).
    Sealer,
    /// The sink lost them and the kernel says so ([`kind::SINK_LOSS`]).
    Sink,
}

/// What the verifier found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finding {
    /// The boot's records in the export begin at `first`, not 0.
    /// `explained`: the boot is the export's first (rotation drops the oldest
    /// file) or the kernel declared the loss of the records before `first`.
    Truncated { boot: u32, first: u64, explained: bool },
    /// `count` records from `first` are not in the export.
    Gap { boot: u32, first: u64, count: u64, by: By },
    /// Record `seq` came after record `after`.
    Reorder { boot: u32, seq: u64, after: u64 },
    /// The seal at `seq` names a head the records before it do not give: a
    /// record was rewritten, inserted or removed.
    Rewrite { boot: u32, seq: u64 },
    /// The seal at `seq` cannot be checked: records it covers are missing.
    /// `declared`: the kernel declared every one of them lost by the sink.
    Unverifiable { boot: u32, seq: u64, declared: bool },
    /// The seal at `seq` names an anchor the one before it and its data do
    /// not give: a seal was forged, or one is missing.
    AnchorMismatch { boot: u32, seq: u64 },
    /// The seal at `seq` found the hardware holding a value its extend does
    /// not give: something else extended the index.
    Diverged { boot: u32, seq: u64 },
    /// The boot's anchor is not a value the hardware held after the last
    /// seal it took before the boot: that seal's boot is not in the export,
    /// or the anchor was reset.
    LinkBroken { boot: u32 },
    /// The hardware's counter at the seal at `seq` (or at the boot's anchor,
    /// `seq` = `u64::MAX`) does not follow the last one: seals are missing.
    CounterGap { boot: u32, seq: u64 },
    /// The boot reached a seal with no anchor record. `explained`: the
    /// anchor was among the records the boot's start lost, and that is
    /// explained (see [`Finding::Truncated`]).
    AnchorMissing { boot: u32, explained: bool },
    /// `count` records after the boot's last seal: no seal covers them.
    Unsealed { boot: u32, count: u64 },
    /// The hardware took a seal of the boot whose record is not in the
    /// export (the boot ended before the sink wrote it): it covers the
    /// records before `through`, which it verifies.
    CrashSeal { boot: u32, through: u64 },
    /// The boot's seals are not held by hardware.
    Advisory { boot: u32 },
    /// The boot seals forward-only after a boot the hardware sealed.
    Downgrade { boot: u32, reason: Reason },
    /// `count` records of class `class` (0: not known) were lost before
    /// they were sealed (`sink`: false) or written (`sink`: true). Declared
    /// by the kernel, so not evidence; [`Finding::high_value_loss`] says
    /// whether it hides what spyware does.
    ClassLost { boot: u32, class: u8, count: u32, sink: bool },
    /// The rate cap held back `count` records of class `class`.
    Held { boot: u32, class: u8, count: u32 },
    /// A record whose payload does not decode as its kind, or a seal or
    /// anchor of a shape the kernel never writes.
    Malformed { boot: u32, seq: u64 },
    /// The sink-loss declarations before the seal at `seq` do not add up to
    /// what the seal says the kernel declared: one was added or removed.
    DeclarationMismatch { boot: u32, seq: u64 },
    /// A loss declared at `seq` that no seal covers (after the boot's last
    /// seal): it explains nothing, and anyone who can write the volume can
    /// add one. `at_end`: it is in the export's last boot, after its last
    /// seal, which a crash in the seconds before the next seal, or an export
    /// taken from a live device, also gives; still not excused.
    UncoveredDeclaration { boot: u32, seq: u64, at_end: bool },
}

impl Finding {
    /// Evidence of tampering (or of a loss nobody declared), as opposed to
    /// what an honest log can also show.
    pub fn is_evidence(&self) -> bool {
        match *self {
            Finding::Truncated { explained, .. } | Finding::AnchorMissing { explained, .. } => !explained,
            Finding::Gap { by, .. } => by == By::Nobody,
            Finding::Unverifiable { declared, .. } => !declared,
            Finding::Downgrade { reason, .. } => reason == Reason::IndexUnusable,
            Finding::Reorder { .. }
            | Finding::Rewrite { .. }
            | Finding::AnchorMismatch { .. }
            | Finding::Diverged { .. }
            | Finding::LinkBroken { .. }
            | Finding::CounterGap { .. }
            | Finding::DeclarationMismatch { .. }
            | Finding::UncoveredDeclaration { .. }
            | Finding::Malformed { .. } => true,
            // A loss the kernel declared, by class: what was lost is named
            // (the tool prints it), and an honest flood shows it too.
            Finding::Unsealed { .. }
            | Finding::CrashSeal { .. }
            | Finding::Advisory { .. }
            | Finding::Held { .. }
            | Finding::ClassLost { .. } => false,
        }
    }
}

impl Finding {
    /// A declared loss of records of a class whose loss hides what spyware
    /// does (or of records whose class is not known).
    pub fn high_value_loss(&self) -> bool {
        matches!(*self, Finding::ClassLost { class, .. } if Class::from_u8(class).is_none_or(|c| c.high_value()))
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
    /// The last boot's backend, and the last value and counter the export
    /// says the hardware holds (the last seal it took, or a boot anchor read
    /// from it): what a live TPM must hold if the export is whole. `None`: no
    /// hardware held any.
    pub backend: Option<Backend>,
    pub last_anchor: Option<Hash>,
    pub last_counter: Option<u64>,
    /// The last boot's seals say both its TPM indexes are undeletable: a
    /// rewrite cannot be replayed into them.
    pub undeletable: bool,
}

/// How the hardware's live value relates to the export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Live {
    /// It is the export's last.
    Whole,
    /// It is the anchor of a seal the export says the hardware refused: the
    /// TPM took it and the answer was lost.
    Refused,
    /// It is a seal of the last boot whose record is not in the export, over
    /// the records before `through`.
    CrashSeal { through: u64 },
    /// It is neither: seals are missing from the export, or it was rewritten.
    Differs,
}

#[derive(Clone, Copy)]
struct Hist {
    seq: u64,
    head: Hash,
    canon: [u8; CANON_MAX],
    len: u16,
}

const NO_HIST: Hist = Hist { seq: u64::MAX, head: [0; 32], canon: [0; CANON_MAX], len: 0 };

#[derive(Clone, Copy, Default)]
struct Range {
    first: u64,
    end: u64,
}

#[derive(Clone, Copy)]
struct Ranges {
    r: [Range; PENDING],
    n: usize,
}

const NO_RANGES: Ranges = Ranges { r: [Range { first: 0, end: 0 }; PENDING], n: 0 };

impl Ranges {
    /// Add `count` from `first`, merged with a range it touches. Full, the
    /// oldest goes: what the ranges are for (declarations, pending gaps) is
    /// resolved at every seal, so only a seal interval's worth is ever held.
    fn add(&mut self, first: u64, count: u64) {
        let end = first.saturating_add(count);
        if count == 0 {
            return;
        }
        if let Some(r) = self.r[..self.n].iter_mut().find(|r| r.first <= end && first <= r.end) {
            (r.first, r.end) = (r.first.min(first), r.end.max(end));
            return;
        }
        if self.n == PENDING {
            self.r.copy_within(1.., 0);
            self.n -= 1;
        }
        self.r[self.n] = Range { first, end };
        self.n += 1;
    }

    fn remove(&mut self, i: usize) {
        self.r.copy_within(i + 1..self.n, i);
        self.n -= 1;
    }

    fn covers(&self, first: u64, end: u64) -> bool {
        // A run of adjacent or overlapping ranges covers what their union does.
        let mut at = first;
        loop {
            if at >= end {
                return true;
            }
            match self.r[..self.n].iter().filter(|r| r.first <= at && r.end > at).map(|r| r.end).max() {
                Some(e) => at = e,
                None => return false,
            }
        }
    }

    fn contains(&self, seq: u64) -> bool {
        self.r[..self.n].iter().any(|r| r.first <= seq && seq < r.end)
    }
}

/// A boot of the export: what is known of it, and what waits for its end.
#[derive(Clone, Copy)]
struct Boot {
    first: u64,
    last: Option<u64>,
    /// The head after the last folded record; `None` until the boot's start
    /// is known (its anchor record) or a seal resynchronises it.
    head: Option<Hash>,
    /// The boot anchor and nonce (from its anchor record, else its first seal).
    id: Option<(Hash, u64)>,
    backend: Option<Backend>,
    has_anchor: bool,
    hardware: bool,
    linked: bool,
    last_seal: Option<Seal>,
    last_seal_seq: u64,
    advisory: bool,
    since_seal: u64,
    /// Gaps no declaration has explained yet, and those since the last seal.
    gaps: Ranges,
    recent: Ranges,
    /// What the sealer declared it never folded (checked by the heads), and
    /// what the sink lost and a seal's count confirmed.
    sealer_loss: Ranges,
    sink_loss: Ranges,
    /// Sink-loss declarations no seal has confirmed yet: `(seq, first,
    /// count)`, and whether more came than fit.
    pending: [Declared; UNVERIFIED],
    npending: usize,
    pending_over: bool,
    /// The sealer-loss declaration no seal covers yet (its sequence number).
    loss_uncovered: Option<u64>,
    /// The sink's count of the last seal whose anchor checked out.
    sink_lost: Option<(u64, Hash)>,
    /// Where the sink started this boot, from a seal whose anchor checked
    /// out and whose boot is linked.
    sink_start: u64,
    link_ok: bool,
    /// Seals whose head did not match with gaps before them.
    unverified: [Unverified; UNVERIFIED],
    nunverified: usize,
}

/// A seal whose head did not match with gaps before it: decided once
/// declarations explain its gaps, or the boot ends.
#[derive(Clone, Copy)]
struct Unverified {
    seq: u64,
    gaps: [Range; 8],
    n: usize,
}

/// A sink-loss declaration no seal has confirmed yet.
#[derive(Clone, Copy)]
struct Declared {
    seq: u64,
    first: u64,
    count: u64,
    by_class: [u32; CLASSES],
}

const NO_DECLARED: Declared = Declared { seq: 0, first: 0, count: 0, by_class: [0; CLASSES] };

/// Seals pending a decision, and sink-loss declarations pending a seal.
const UNVERIFIED: usize = 16;

const NEW_BOOT: Boot = Boot {
    first: 0,
    last: None,
    head: None,
    id: None,
    backend: None,
    has_anchor: false,
    hardware: false,
    linked: false,
    last_seal: None,
    last_seal_seq: 0,
    advisory: false,
    since_seal: 0,
    gaps: NO_RANGES,
    recent: NO_RANGES,
    sealer_loss: NO_RANGES,
    sink_loss: NO_RANGES,
    pending: [NO_DECLARED; UNVERIFIED],
    npending: 0,
    pending_over: false,
    loss_uncovered: None,
    sink_lost: None,
    sink_start: 0,
    link_ok: false,
    unverified: [Unverified { seq: 0, gaps: [Range { first: 0, end: 0 }; 8], n: 0 }; UNVERIFIED],
    nunverified: 0,
};

/// What a boot that ended leaves for the next one's link and the live check:
/// the seals the hardware may have taken whose records are not in the export.
#[derive(Clone, Copy)]
struct Ended {
    id: (Hash, u64),
    /// The value the hardware held after the boot's last seal it took.
    prev: Hash,
    count: u32,
    counter: u64,
    sink_lost: u64,
    sink_start: u64,
    sink_digest: Hash,
    /// The heads after each record past the boot's last seal: `(through, head)`.
    tail: [(u64, Hash); DUPS],
    ntail: usize,
}

pub struct Verifier {
    boot: u32,
    b: Boot,
    hist: [Hist; HISTORY],
    /// The history's next slot and how many it holds.
    at: usize,
    held: usize,
    seam: bool,
    /// After a seam: records that repeat the boot's own, held in case they
    /// turn out to start another boot.
    dups: [Hist; DUPS],
    ndups: usize,
    rereading: bool,
    /// The last value the hardware is known to hold, across boots; its
    /// counter; the anchor of a refused seal (verified) after it, which the
    /// hardware may have taken anyway; whether any boot was hardware-sealed.
    hw: Option<Hash>,
    hw_counter: Option<u64>,
    refused: Option<Hash>,
    any_hw: bool,
    ended: Option<Ended>,
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
            b: NEW_BOOT,
            hist: [NO_HIST; HISTORY],
            at: 0,
            held: 0,
            seam: false,
            dups: [NO_HIST; DUPS],
            ndups: 0,
            rereading: false,
            hw: None,
            hw_counter: None,
            refused: None,
            any_hw: false,
            ended: None,
            sum: Summary::default(),
        }
    }

    /// `logd` started reading the ring afresh here: the next record may begin
    /// a boot, or repeat records of this one.
    pub fn seam(&mut self) {
        // A re-read before it was the boot's own: what it held is dropped.
        (self.seam, self.rereading, self.ndups) = (true, false, 0);
    }

    fn emit(&mut self, f: Finding, out: &mut dyn FnMut(Finding)) {
        if f.is_evidence() {
            self.sum.evidence += 1;
        }
        out(f);
    }

    fn start_boot(&mut self, first: u64) {
        self.boot += 1;
        self.sum.boots += 1;
        self.b = NEW_BOOT;
        self.b.first = first;
        (self.at, self.held) = (0, 0);
    }

    /// The records before `first` are gone honestly: this is the export's
    /// first boot (rotation drops the oldest file), or a seal of the boot
    /// says the sink started reading at or after `first`.
    fn start_explained(&self) -> bool {
        self.boot == 1 || self.b.sink_start >= self.b.first
    }

    /// Decide the gaps and unverified seals the declarations now explain;
    /// at the boot's end (`last`), all that is left.
    fn resolve(&mut self, last: bool, out: &mut dyn FnMut(Finding)) {
        let by = |b: &Boot, g: &Range| {
            if b.sealer_loss.covers(g.first, g.end) {
                Some(By::Sealer)
            } else if b.sink_loss.covers(g.first, g.end) {
                Some(By::Sink)
            } else if last {
                Some(By::Nobody)
            } else {
                None
            }
        };
        let mut i = 0;
        while i < self.b.gaps.n {
            let g = self.b.gaps.r[i];
            match by(&self.b, &g) {
                Some(by) => {
                    self.emit(Finding::Gap { boot: self.boot, first: g.first, count: g.end - g.first, by }, out);
                    self.b.gaps.remove(i);
                }
                None => i += 1,
            }
        }
        let mut i = 0;
        while i < self.b.nunverified {
            let u = self.b.unverified[i];
            let bys: [Option<By>; 8] = core::array::from_fn(|k| if k < u.n { by(&self.b, &u.gaps[k]) } else { Some(By::Sealer) });
            if bys.iter().any(|b| b.is_none()) {
                i += 1;
                continue;
            }
            let f = if bys.iter().all(|&b| b == Some(By::Sealer)) {
                // The sealer never folded those records: its head is the
                // present records', which did not match.
                Finding::Rewrite { boot: self.boot, seq: u.seq }
            } else {
                Finding::Unverifiable { boot: self.boot, seq: u.seq, declared: !bys.contains(&Some(By::Nobody)) }
            };
            self.emit(f, out);
            self.b.unverified.copy_within(i + 1..self.b.nunverified, i);
            self.b.nunverified -= 1;
        }
    }

    fn end_boot(&mut self, at_end: bool, out: &mut dyn FnMut(Finding)) {
        if self.boot == 0 {
            return;
        }
        let b = self.b;
        if b.first != 0 {
            let explained = self.start_explained();
            self.emit(Finding::Truncated { boot: self.boot, first: b.first, explained }, out);
            if !b.has_anchor && b.last_seal.is_some() {
                self.emit(Finding::AnchorMissing { boot: self.boot, explained }, out);
            }
        } else if !b.has_anchor && b.last_seal.is_some() {
            self.emit(Finding::AnchorMissing { boot: self.boot, explained: false }, out);
        }
        // A declaration no seal covers (after the last one, or more than
        // could be held) explains nothing: anyone who can write the volume
        // can add one.
        let uncovered = if b.npending > 0 || b.pending_over { Some(b.pending[0].seq) } else { b.loss_uncovered };
        if let Some(seq) = uncovered {
            self.emit(Finding::UncoveredDeclaration { boot: self.boot, seq, at_end }, out);
        }
        self.resolve(true, out);
        if b.since_seal > 0 {
            self.emit(Finding::Unsealed { boot: self.boot, count: b.since_seal }, out);
        }
        if b.advisory {
            self.emit(Finding::Advisory { boot: self.boot }, out);
        }
        self.ended = self.ended_state();
    }

    fn ended_state(&self) -> Option<Ended> {
        let id = self.b.id?;
        if !self.b.hardware {
            return None;
        }
        let count = self.b.last_seal.map_or(0, |s| s.count);
        let prev = self.hw.unwrap_or(id.0);
        let (sink_lost, sink_start, sink_digest) =
            self.b.last_seal.map_or((0, 0, [0; 32]), |s| (s.sink_lost, s.sink_start, s.sink_digest));
        let mut e = Ended {
            id,
            prev,
            count,
            counter: self.hw_counter.unwrap_or(0),
            sink_lost,
            sink_start,
            sink_digest,
            tail: [(0, [0; 32]); DUPS],
            ntail: 0,
        };
        let from = self.b.last_seal.map_or(self.b.first, |_| self.b.last_seal_seq);
        let mut k = 0;
        while k < self.held && e.ntail < DUPS {
            let h = &self.hist[(self.at + HISTORY - 1 - k) % HISTORY];
            if h.seq < from {
                break;
            }
            e.tail[e.ntail] = (h.seq + 1, h.head);
            e.ntail += 1;
            k += 1;
        }
        Some(e)
    }

    /// The `through` of a seal the hardware took after boot `e`'s last one,
    /// whose anchor is `target`.
    fn crash_seal(e: &Ended, target: &Hash) -> Option<u64> {
        e.tail[..e.ntail].iter().find_map(|&(through, head)| {
            let n = SealNumbers {
                count: e.count + 1,
                counter: e.counter + 1,
                through,
                sink_lost: e.sink_lost,
                sink_start: e.sink_start,
                sink_digest: e.sink_digest,
            };
            let data = seal_data(&e.id.0, e.id.1, &n, &head);
            (extend(&e.prev, &data) == *target).then_some(through)
        })
    }

    /// Link the boot, whose anchor is `boot_anchor` and whose counter at boot
    /// is `counter` (`None`: not known), to the hardware's last value.
    fn link(&mut self, boot_anchor: &Hash, counter: Option<u64>, out: &mut dyn FnMut(Finding)) {
        self.b.linked = true;
        let Some(hw) = self.hw else {
            self.hw_counter = counter.filter(|&c| c != 0).or(self.hw_counter);
            self.b.link_ok = true;
            return;
        };
        let mut want_counter = self.hw_counter;
        let linked = if hw == *boot_anchor || self.refused == Some(*boot_anchor) {
            // Counted and not extended: a power cut between the two.
            if counter.is_some() && counter == self.hw_counter.map(|c| c + 1) {
                want_counter = counter;
            }
            true
        } else if let Some(through) = self.ended.as_ref().and_then(|e| Self::crash_seal(e, boot_anchor)) {
            self.emit(Finding::CrashSeal { boot: self.boot - 1, through }, out);
            want_counter = self.hw_counter.map(|c| c + 1);
            true
        } else {
            false
        };
        if !linked && !cfg!(feature = "canary-no-anchor-check") {
            self.emit(Finding::LinkBroken { boot: self.boot }, out);
        }
        self.b.link_ok = linked;
        if let (Some(c), Some(w)) = (counter, want_counter) {
            if c != w && !cfg!(feature = "canary-no-anchor-check") {
                self.emit(Finding::CounterGap { boot: self.boot, seq: u64::MAX }, out);
            }
        }
        if let Some(c) = counter.filter(|&c| c != 0) {
            self.hw_counter = Some(c);
        }
        (self.hw, self.refused) = (Some(*boot_anchor), None);
    }

    fn head_before(&self, through: u64) -> Option<Hash> {
        if through == self.b.first && self.b.first == 0 {
            return self.b.id.map(|(a, n)| genesis(&a, n));
        }
        if self.b.head.is_none() {
            return None;
        }
        (0..self.held)
            .map(|k| &self.hist[(self.at + HISTORY - 1 - k) % HISTORY])
            .find(|h| h.seq < through && !self.b.sealer_loss.contains(h.seq))
            .map(|h| h.head)
            .or_else(|| (self.b.first == 0).then(|| self.b.id.map(|(a, n)| genesis(&a, n))).flatten())
    }

    /// Refold the held records from `start` (the head before the oldest
    /// held one), skipping what the sealer declared it never folded.
    fn refold(&mut self, start: Hash, from_seq: u64) {
        let mut head = start;
        for k in (0..self.held).rev() {
            let i = (self.at + HISTORY - 1 - k) % HISTORY;
            let h = self.hist[i];
            if h.seq < from_seq {
                head = h.head;
                continue;
            }
            if !self.b.sealer_loss.contains(h.seq) {
                head = fold_canon(&head, &h.canon[..h.len as usize]);
            }
            self.hist[i].head = head;
        }
        self.b.head = Some(head);
    }

    /// Head := the seal's, refolding the held records it does not cover.
    fn resync(&mut self, s: &Seal) {
        let mut head = s.head;
        for k in (0..self.held).rev() {
            let i = (self.at + HISTORY - 1 - k) % HISTORY;
            if self.hist[i].seq >= s.through {
                if !self.b.sealer_loss.contains(self.hist[i].seq) {
                    let h = &self.hist[i];
                    head = fold_canon(&head, &h.canon[..h.len as usize]);
                }
                self.hist[i].head = head;
            }
        }
        self.b.head = Some(head);
    }

    fn check_seal(&mut self, seq: u64, s: &Seal, out: &mut dyn FnMut(Finding)) {
        self.sum.seals += 1;
        let boot = self.boot;
        let hardware = s.hardware();
        if hardware {
            self.sum.seals_hardware += 1;
        } else {
            self.b.advisory = true;
        }
        let shape_ok = !(s.backend == Backend::Forward && (hardware || s.counter != 0))
            && s.through <= seq
            && s.count != 0
            && s.backend == self.b.backend.unwrap_or(s.backend)
            && self.b.id.is_none_or(|id| id == (s.boot_anchor, s.nonce))
            && (s.backend != Backend::Forward || s.boot_anchor == [0; 32]);
        let step_ok = match &self.b.last_seal {
            Some(l) => s.count == l.count + 1,
            None => self.b.first != 0 || s.count == 1,
        };
        if !shape_ok || !step_ok {
            self.emit(Finding::Malformed { boot, seq }, out);
        }
        if self.b.id.is_none() {
            self.b.id = Some((s.boot_anchor, s.nonce));
            self.b.backend = Some(s.backend);
            self.b.hardware = s.backend == Backend::TpmNv;
            if self.b.first == 0 {
                self.from_genesis_now();
            }
        }
        if !self.b.linked && s.backend == Backend::TpmNv {
            // The counter at boot: one increment per seal before this one.
            let counter = (s.counter != 0).then(|| s.counter.saturating_sub(s.count as u64));
            self.link(&s.boot_anchor, counter, out);
        }
        // The anchor: from the one before, which the seal names and which
        // must be the previous seal's (or the boot anchor).
        let prev_ok = match &self.b.last_seal {
            Some(l) => s.prev == l.anchor,
            None => self.b.first != 0 || s.prev == s.boot_anchor,
        };
        let diverged = s.flags & FLAG_DIVERGED != 0;
        let anchor_ok =
            cfg!(feature = "canary-no-anchor-check") || (prev_ok && (diverged || extend(&s.prev, &data_of(s)) == s.anchor));
        if !anchor_ok {
            self.emit(Finding::AnchorMismatch { boot, seq }, out);
        }
        if diverged {
            self.emit(Finding::Diverged { boot, seq }, out);
        }
        // The head.
        let want = self.head_before(s.through);
        let head_ok = cfg!(feature = "canary-no-chain-check") || want == Some(s.head);
        if !head_ok {
            if self.b.recent.n > 0 {
                let mut u = Unverified { seq, gaps: [Range { first: 0, end: 0 }; 8], n: 0 };
                for r in &self.b.recent.r[..self.b.recent.n] {
                    if u.n == 8 {
                        // More gaps than kept: the last one stands for the rest.
                        u.gaps[7].end = r.end;
                    } else {
                        u.gaps[u.n] = *r;
                        u.n += 1;
                    }
                }
                if self.b.nunverified == UNVERIFIED {
                    self.emit(Finding::Unverifiable { boot, seq, declared: false }, out);
                } else {
                    self.b.unverified[self.b.nunverified] = u;
                    self.b.nunverified += 1;
                }
            } else if want.is_some() {
                self.emit(Finding::Rewrite { boot, seq }, out);
            }
            self.resync(s);
        }
        self.confirm_declarations(seq, s, anchor_ok, out);
        // The counter: one increment per seal the hardware counted.
        if s.counter != 0 && s.backend == Backend::TpmNv {
            // The boot's first seal in the export follows the counter at boot
            // by its own number: the seals before it took one each.
            let step = if self.b.last_seal.is_none() { s.count as u64 } else { 1 };
            if let Some(c) = self.hw_counter {
                if s.counter != c + step && !cfg!(feature = "canary-no-anchor-check") {
                    self.emit(Finding::CounterGap { boot, seq }, out);
                }
            }
            self.hw_counter = Some(s.counter);
        }
        let verified = head_ok && anchor_ok && want.is_some();
        if head_ok && anchor_ok {
            self.sum.seals_verified += 1;
        }
        if hardware && (anchor_ok || diverged) {
            (self.hw, self.refused) = (Some(s.anchor), None);
            self.any_hw = true;
        } else if !hardware && s.counter != 0 && verified && self.refused.is_none() {
            self.refused = Some(s.anchor);
        }
        self.sum.backend = Some(s.backend);
        self.sum.undeletable = hardware && s.flags & crate::FLAG_UNDELETABLE != 0;
        self.b.last_seal = Some(*s);
        self.b.last_seal_seq = seq;
        self.b.recent = NO_RANGES;
        self.b.since_seal = 0;
        self.resolve(false, out);
    }

    /// The sink-loss declarations the seal covers: their counts must add up to
    /// what the seal (whose anchor checked out) says the kernel declared since
    /// the last such seal. Then they explain gaps; a mismatch is evidence.
    fn confirm_declarations(&mut self, seq: u64, s: &Seal, anchor_ok: bool, out: &mut dyn FnMut(Finding)) {
        let boot = self.boot;
        if self.b.loss_uncovered.is_some_and(|l| l < s.through) {
            self.b.loss_uncovered = None;
        }
        if !anchor_ok {
            return;
        }
        if s.backend == Backend::Forward || self.b.link_ok {
            self.b.sink_start = self.b.sink_start.max(s.sink_start);
        }
        let base = match self.b.sink_lost {
            Some(v) => Some(v),
            None if self.b.first == 0 || s.sink_start >= self.b.first => Some((0, [0; 32])),
            None => None,
        };
        let (mut sum, mut i) = (0u64, 0);
        let mut digest = base.map_or([0; 32], |b| b.1);
        let covered: [Declared; UNVERIFIED] = self.b.pending;
        let mut kept = [NO_DECLARED; UNVERIFIED];
        let mut nkept = 0;
        for d in &covered[..self.b.npending] {
            if d.seq < s.through {
                sum += d.count;
                digest = declaration(&digest, d.first, d.count, &d.by_class);
                i += 1;
            } else {
                kept[nkept] = *d;
                nkept += 1;
            }
        }
        // The count and the digest of every declaration since the last seal
        // that confirmed one: an edited range or class is not the kernel's.
        let confirmed = !self.b.pending_over
            && base.is_some_and(|b| s.sink_lost.checked_sub(b.0) == Some(sum) && s.sink_digest == digest);
        if confirmed || cfg!(feature = "canary-no-declaration-check") {
            for d in &covered[..self.b.npending] {
                if d.seq < s.through {
                    self.b.sink_loss.add(d.first, d.count);
                }
            }
        } else if i > 0 || self.b.pending_over || base.is_some_and(|b| s.sink_lost != b.0 || s.sink_digest != b.1) {
            self.emit(Finding::DeclarationMismatch { boot, seq }, out);
        }
        (self.b.pending, self.b.npending, self.b.pending_over) = (kept, nkept, false);
        self.b.sink_lost = Some((s.sink_lost, s.sink_digest));
    }

    /// The boot's start became known: fold every held record from genesis.
    fn from_genesis_now(&mut self) {
        if let Some((a, n)) = self.b.id {
            self.refold(genesis(&a, n), 0);
        }
    }

    fn check_anchor(&mut self, seq: u64, a: &Anchor, out: &mut dyn FnMut(Finding)) {
        let hardware = a.hardware();
        let shape_ok = (hardware == (a.reason == Reason::Hardware))
            && (a.backend == Backend::TpmNv || (!hardware && a.value == [0; 32] && a.counter == 0))
            && !self.b.has_anchor
            && self.b.last_seal.is_none();
        if !shape_ok {
            self.emit(Finding::Malformed { boot: self.boot, seq }, out);
        }
        self.b.has_anchor = true;
        self.b.id = Some((a.value, a.nonce));
        self.b.backend = Some(a.backend);
        self.b.hardware = hardware;
        self.sum.backend = Some(a.backend);
        if !hardware {
            self.b.advisory = true;
            if self.any_hw && a.backend == Backend::Forward {
                self.emit(Finding::Downgrade { boot: self.boot, reason: a.reason }, out);
            }
        } else {
            self.link(&a.value, Some(a.counter), out);
            self.any_hw = true;
        }
        if self.b.first == 0 {
            self.from_genesis_now();
        }
    }

    fn classes(&mut self, by_class: &[u32; CLASSES], f: impl Fn(u8, u32) -> Finding, out: &mut dyn FnMut(Finding)) {
        for (c, &n) in by_class.iter().enumerate() {
            if n != 0 {
                self.emit(f(c as u8, n), out);
            }
        }
    }

    fn same_as_held(&self, seq: u64, c: &[u8]) -> bool {
        (0..self.held)
            .map(|k| &self.hist[(self.at + HISTORY - 1 - k) % HISTORY])
            .find(|h| h.seq == seq)
            .is_some_and(|h| &h.canon[..h.len as usize] == c)
    }

    /// The next record of the export.
    pub fn record(&mut self, env: &Envelope, payload: &[u8], out: &mut dyn FnMut(Finding)) {
        let mut c = [0u8; CANON_MAX];
        let n = canon(env, payload, &mut c);
        let seq = env.seq;
        // After a seam, records the boot already gave are a re-read, not a
        // new boot: held until one differs (a new boot, which they begin)
        // or one comes after the boot's last (the same boot, going on).
        if self.seam || self.rereading {
            if let Some(last) = self.b.last {
                if seq <= last && self.same_as_held(seq, &c[..n]) {
                    if self.ndups < DUPS {
                        self.dups[self.ndups] = Hist { seq, head: [0; 32], canon: c, len: n as u16 };
                        self.ndups += 1;
                    }
                    self.rereading = true;
                    self.seam = false;
                    return;
                }
                if self.rereading && seq > last {
                    (self.rereading, self.ndups) = (false, 0);
                } else if self.rereading {
                    // A differing record: the held ones began another boot.
                    let held = self.ndups;
                    (self.rereading, self.ndups, self.seam) = (false, 0, true);
                    let dups = self.dups;
                    for d in &dups[..held] {
                        self.replay(d, out);
                    }
                    if held > 0 {
                        self.seam = false;
                    }
                }
            }
        }
        self.take(env, payload, &c[..n], out);
    }

    fn replay(&mut self, d: &Hist, out: &mut dyn FnMut(Finding)) {
        let c = &d.canon[..d.len as usize];
        // canon: version, seq, ts, clock, kind, cpu, flags, len, payload.
        let le = |a: usize, w: usize| c[a..a + w].iter().rev().fold(0u64, |v, &b| v << 8 | b as u64);
        let env = Envelope {
            seq: le(1, 8),
            ts: le(9, 8),
            clock: c[17],
            source: 0,
            kind: le(18, 2) as u16,
            len: le(22, 2) as u16,
            cpu: c[20],
            flags: c[21],
        };
        self.take(&env, &c[24..], c, out);
    }

    fn take(&mut self, env: &Envelope, payload: &[u8], c: &[u8], out: &mut dyn FnMut(Finding)) {
        let seq = env.seq;
        let new_boot = match self.b.last {
            None => true,
            Some(last) => seq <= last && (self.seam || seq == 0),
        };
        if new_boot {
            self.end_boot(false, out);
            self.start_boot(seq);
        } else if let Some(last) = self.b.last {
            if seq <= last {
                if !cfg!(feature = "canary-no-order-check") {
                    self.emit(Finding::Reorder { boot: self.boot, seq, after: last }, out);
                }
            } else if seq > last + 1 && !cfg!(feature = "canary-no-gap-check") {
                self.b.gaps.add(last + 1, seq - last - 1);
                self.b.recent.add(last + 1, seq - last - 1);
            }
        }
        self.seam = false;
        self.sum.records += 1;
        let len = (env.len as usize).min(payload.len());
        let p = &payload[..len];
        // The record is folded before a seal reads the head (a seal does not
        // cover itself) and after an anchor gave the boot's start.
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
                    self.check_anchor(seq, &a, out);
                    false
                }
                None => true,
            },
            kind::LOSS | kind::SINK_LOSS => match Loss::decode(p) {
                Some(l) => {
                    let sink = env.kind == kind::SINK_LOSS;
                    if sink {
                        if self.b.npending == UNVERIFIED {
                            self.b.pending_over = true;
                        } else {
                            self.b.pending[self.b.npending] = Declared { seq, first: l.first, count: l.count, by_class: l.by_class };
                            self.b.npending += 1;
                        }
                    } else {
                        self.b.loss_uncovered = self.b.loss_uncovered.or(Some(seq));
                        self.b.sealer_loss.add(l.first, l.count);
                        // Records of the range logd did write were folded
                        // here and never by the sealer: fold again without them.
                        if let Some(start) = self.head_before(l.first) {
                            self.refold(start, l.first);
                        }
                    }
                    let boot = self.boot;
                    self.classes(&l.by_class, |class, count| Finding::ClassLost { boot, class, count, sink }, out);
                    false
                }
                None => true,
            },
            kind::HELD => match Held::decode(p) {
                Some(h) => {
                    let boot = self.boot;
                    self.classes(&h.by_class, |class, count| Finding::Held { boot, class, count }, out);
                    false
                }
                None => true,
            },
            _ => true,
        };
        if malformed {
            self.emit(Finding::Malformed { boot: self.boot, seq }, out);
        }
        let mut canon = [0u8; CANON_MAX];
        canon[..c.len()].copy_from_slice(c);
        let head = match self.b.head {
            Some(h) if !self.b.sealer_loss.contains(seq) => Some(fold_canon(&h, c)),
            h => h,
        };
        self.b.head = head;
        self.hist[self.at] = Hist { seq, head: head.unwrap_or([0; 32]), canon, len: c.len() as u16 };
        self.at = (self.at + 1) % HISTORY;
        self.held = (self.held + 1).min(HISTORY);
        if env.kind != kind::SEAL {
            self.b.since_seal += 1;
        }
        self.b.last = Some(self.b.last.map_or(seq, |l| l.max(seq)));
    }

    /// The end of the export.
    pub fn finish(&mut self, out: &mut dyn FnMut(Finding)) -> Summary {
        self.end_boot(true, out);
        self.sum.last_anchor = self.hw;
        self.sum.last_counter = self.hw_counter;
        self.sum
    }

    /// After [`finish`](Self::finish): how the hardware's live anchor (and
    /// counter, if read) relate to the export.
    pub fn live(&self, anchor: &Hash, counter: Option<u64>) -> Live {
        let counter_is = |want: Option<u64>| counter.is_none() || counter == want;
        if self.hw == Some(*anchor) {
            if counter_is(self.hw_counter) {
                return Live::Whole;
            }
            // Counted, not extended: a power cut between the two.
            if counter_is(self.hw_counter.map(|c| c + 1)) {
                return Live::CrashSeal { through: 0 };
            }
            return Live::Differs;
        }
        if self.refused == Some(*anchor) && counter_is(self.hw_counter) {
            return Live::Refused;
        }
        if let Some(through) = self.ended.as_ref().and_then(|e| Self::crash_seal(e, anchor)) {
            if counter_is(self.hw_counter.map(|c| c + 1)) {
                return Live::CrashSeal { through };
            }
        }
        Live::Differs
    }
}
