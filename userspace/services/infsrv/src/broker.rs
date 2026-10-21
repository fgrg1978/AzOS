// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The broker: which variant of which model runs for this call, or why none
//! does, now.
//!
//! # Admission
//!
//! A call names a model, may carry a deadline, and comes from a context (the
//! badge of the endpoint capability it came through). The broker walks the
//! model's fallback list, the publisher's order of preference, and takes the
//! first variant that passes four checks, each of them against the **signed**
//! cost row of the variant and none against a measurement:
//!
//! 1. its blob is loaded (the machine has the backend and the arena had room);
//! 2. its working memory fits what a run may use (`INFSRV_WORK_KIB`);
//! 3. its worst-case time fits the time left to the caller's deadline;
//! 4. its energy fits what is left of the context's quota for the window.
//!
//! With the energy hint `low-energy` it takes, among the variants that pass,
//! the one with the lowest signed energy instead of the first.
//!
//! When none passes the call is **refused now**, with the outcome of the check
//! the best candidate failed (`UNSUPPORTED` for 1, `BUSY` for 2, `REFUSED` for
//! 3 and 4): a model that cannot make the deadline is told so at once and the
//! caller degrades, instead of learning it late. Every refusal is a decision
//! record of Rule `accel-admission` and its id, the **receipt**, goes back to
//! the caller in the verdict. An admission is recorded when it changes the
//! variant a model runs on (the first call, or a degrade and its recovery),
//! not on every call: a control loop at 100 Hz would otherwise fill the
//! journal with the same sentence.
//!
//! The record's three numbers are the rule's (`accel`, `need_kib`,
//! `free_kib`), with the reason in the upper half of the third, as the
//! run-time reservation record carries its own (`deadline-admission`):
//!
//! * `accel`: `backend << 32 | variant id` of the candidate;
//! * `need_kib`: the candidate's working memory, KiB rounded up;
//! * `free_kib | reason << 32`: what a run may use, and why ([`reason`]).
//!
//! The record's `image_hash_prefix` is the model's reference and its subject
//! the context's badge.
//!
//! # The journal
//!
//! A ring-3 server cannot write the kernel's decision journal, so the broker
//! keeps its own in the same full form (`ProvenanceRecord`), as
//! `userspace/lib/rpc` does for its links. The ids it hands out are its own,
//! from 1. It is served as the `Decisions` object ([`View`] is its `Source`), so
//! a receipt is read back with the same client the kernel's are. The journal is
//! one for all contexts but a client sees only the records that explain its own
//! calls ([`Journal::view`]): a receipt names the model another context asked
//! for and why it was refused, which is that context's business.
//!
//! # Charging a run
//!
//! The energy of the chosen variant is reserved at admission, and settled when
//! the run ends ([`Broker::settle`]): a run that took longer than its signed
//! worst case is charged for the excess at the variant's own rate (signed
//! energy per signed microsecond), so the next call of the context sees less
//! of its quota, and the figure the caller is told is the energy it was
//! actually charged. A run that did not happen (the backend failed) gives its
//! reservation back.

use crate::config::{CONTEXTS, ENERGY_QUOTA_UJ, ENERGY_WINDOW_NS, JOURNAL_ENTRIES, MODELS, WORK_BYTES};
use crate::load::{Model, Slot};
use azos_decision::{ProvenanceRecord, Rule, Verdict as Decision};
use azos_decisions::{Filter, Source};
use azos_devif::outcome::{BUSY, REFUSED, UNSUPPORTED};
use azos_ml::bundle::Variant;

/// Why a call was refused or admitted: the upper half of the third number of
/// the `accel-admission` record.
pub mod reason {
    /// Admitted.
    pub const ADMITTED: u32 = 0;
    /// No variant has a backend that is present and a blob that loaded.
    pub const NO_BACKEND: u32 = 1;
    /// A variant has its blob, but none has the working memory.
    pub const NO_MEMORY: u32 = 2;
    /// A variant has blob and memory, but its signed worst case is longer
    /// than the time left to the deadline.
    pub const DEADLINE: u32 = 3;
    /// A variant fits in time but its signed energy is more than the context
    /// has left of its quota.
    pub const ENERGY: u32 = 4;
    /// The context table is full and this badge is not in it.
    pub const CONTEXTS: u32 = 5;
}

/// The numbers the broker is configured with.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Working memory a run may use, bytes.
    pub work_bytes: u32,
    /// Energy a context may use per window, microjoules; 0 = no quota.
    pub quota_uj: u64,
    /// The window, nanoseconds.
    pub window_ns: u64,
}

impl Limits {
    /// The Kconfig values (`INFSRV_*`).
    pub const fn from_config() -> Limits {
        Limits { work_bytes: WORK_BYTES, quota_uj: ENERGY_QUOTA_UJ, window_ns: ENERGY_WINDOW_NS }
    }
}

// ── the journal ──────────────────────────────────────────────────────────

/// The receipts: the last [`JOURNAL_ENTRIES`] decisions, oldest overwritten.
pub struct Journal {
    recs: [ProvenanceRecord; JOURNAL_ENTRIES],
    total: u64,
}

impl Journal {
    pub const fn new() -> Journal {
        Journal { recs: [ProvenanceRecord::new(0, 0, 0, [0; 3]); JOURNAL_ENTRIES], total: 0 }
    }

    /// Store `r` and give it the next id (never 0).
    fn push(&mut self, mut r: ProvenanceRecord) -> u64 {
        self.total += 1;
        r.seq = self.total;
        self.recs[(self.total - 1) as usize % JOURNAL_ENTRIES] = r;
        self.total
    }

    /// Id of the oldest record still held.
    fn first(&self) -> u64 {
        (self.total + 1).saturating_sub(JOURNAL_ENTRIES as u64).max(1)
    }
}

impl Journal {
    /// What the caller badged `badge` may read of the journal: its own
    /// receipts. A record carries the badge of the context it explains
    /// (`subject`), and the journal is shared by every context, so a view
    /// without a badge, or of another badge, shows nothing of it.
    pub fn view(&self, badge: Option<u32>) -> View<'_> {
        View { journal: self, badge }
    }

    /// Decisions recorded since boot, every context's.
    pub fn total(&self) -> u64 {
        self.total
    }

    fn held(&self, id: u64) -> Option<ProvenanceRecord> {
        if id == 0 || id > self.total || id < self.first() {
            return None;
        }
        Some(self.recs[(id - 1) as usize % JOURNAL_ENTRIES])
    }
}

/// One context's window on the journal ([`Journal::view`]), served as its
/// `Decisions` object.
pub struct View<'a> {
    journal: &'a Journal,
    badge: Option<u32>,
}

impl View<'_> {
    fn own(&self, p: &ProvenanceRecord) -> bool {
        self.badge == Some(p.subject)
    }
}

impl Source for View<'_> {
    /// The receipts of the context that are still held: not the count of
    /// everybody's decisions, which would tell a client how busy the others
    /// are.
    fn total(&self) -> u64 {
        let j = self.journal;
        (j.first()..=j.total).filter_map(|id| j.held(id)).filter(|p| self.own(p)).count() as u64
    }

    fn query(&self, f: &Filter, out: &mut [u64]) -> usize {
        let j = self.journal;
        let mut k = 0;
        let mut id = j.first().max(f.after.saturating_add(1));
        while id <= j.total && k < out.len() {
            if let Some(p) = j.held(id) {
                if self.own(&p) && f.matches(&p) {
                    out[k] = id;
                    k += 1;
                }
            }
            id += 1;
        }
        k
    }

    fn lookup(&self, id: u64) -> Option<ProvenanceRecord> {
        self.journal.held(id).filter(|p| self.own(p))
    }
}

// ── the energy accounts ──────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Account {
    badge: u32,
    live: bool,
    used_uj: u64,
    window_start_ns: u64,
}

/// What each context has used of its quota in the current window.
struct Ledger {
    acct: [Account; CONTEXTS],
}

impl Ledger {
    const fn new() -> Ledger {
        Ledger { acct: [Account { badge: 0, live: false, used_uj: 0, window_start_ns: 0 }; CONTEXTS] }
    }

    /// The slot of `badge`, given one if it has none. `None`: the table is
    /// full of other badges (no eviction: a flood of fresh badges would reset
    /// every other context's account).
    fn slot_of(&mut self, badge: u32) -> Option<usize> {
        if let Some(i) = self.acct.iter().position(|a| a.live && a.badge == badge) {
            return Some(i);
        }
        let i = self.acct.iter().position(|a| !a.live)?;
        self.acct[i] = Account { badge, live: true, used_uj: 0, window_start_ns: 0 };
        Some(i)
    }

    /// Energy left in the window `now` is in; `None` with no quota.
    fn left(&mut self, slot: usize, now_ns: u64, lim: &Limits) -> Option<u64> {
        if lim.quota_uj == 0 {
            return None;
        }
        let a = &mut self.acct[slot];
        // A window is counted from the first call after the last one ended.
        if a.window_start_ns == 0 || now_ns.saturating_sub(a.window_start_ns) >= lim.window_ns {
            a.window_start_ns = now_ns.max(1);
            a.used_uj = 0;
        }
        Some(lim.quota_uj.saturating_sub(a.used_uj))
    }

    fn charge(&mut self, slot: usize, uj: u64, lim: &Limits) {
        if lim.quota_uj != 0 {
            self.acct[slot].used_uj = self.acct[slot].used_uj.saturating_add(uj);
        }
    }

    fn refund(&mut self, slot: usize, uj: u64) {
        self.acct[slot].used_uj = self.acct[slot].used_uj.saturating_sub(uj);
    }
}

// ── the broker ───────────────────────────────────────────────────────────

/// A call, as the broker needs it.
#[derive(Clone, Copy, Debug)]
pub struct Request {
    /// The badge of the capability the call came through.
    pub badge: u32,
    pub model_ref: u64,
    /// `HINT_LOW_ENERGY`.
    pub low_energy: bool,
    /// Microseconds left to the deadline; `None`: no deadline.
    pub budget_us: Option<u32>,
    /// The clock, nanoseconds (MONO).
    pub now_ns: u64,
}

/// A call admitted: the variant to run and what is owed at its end.
#[derive(Clone, Copy, Debug)]
pub struct Admitted {
    /// Index of the model.
    pub model: usize,
    /// The variant chosen, with its blob.
    pub slot: Slot,
    /// The context's slot in the ledger (and in the verdict log).
    pub ctx: usize,
    /// The id of the admission record, 0 when this call recorded none (the
    /// variant is the one the model already runs on).
    pub receipt: u64,
}

/// A call refused now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The outcome the caller is answered with (`azos_devif::outcome`).
    pub code: u32,
    /// Why ([`reason`]).
    pub reason: u32,
    /// The decision record's id.
    pub receipt: u64,
    /// The context's slot, when it has one.
    pub ctx: Option<usize>,
    /// The candidate the refusal is about: `(backend, variant id)`.
    pub candidate: Option<(u32, u32)>,
}

/// What a finished run cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settled {
    /// Wall time of the run, microseconds, rounded up.
    pub latency_us: u32,
    /// The energy charged: the signed figure plus the overrun's.
    pub energy_uj: u32,
    /// How far the run went past its signed worst case, microseconds.
    pub overrun_us: u32,
}

/// Why a bundle was not added.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddError {
    /// [`MODELS`] bundles are held.
    Full,
    /// A bundle with the same manifest is held.
    Duplicate,
}

pub struct Broker {
    models: [Option<Model>; MODELS],
    /// The variant id each model last ran on (to record a change only).
    last: [Option<u32>; MODELS],
    ledger: Ledger,
    pub journal: Journal,
    lim: Limits,
}

fn kib(bytes: u32) -> u64 {
    (bytes as u64).div_ceil(1024)
}

impl Broker {
    pub const fn new(lim: Limits) -> Broker {
        Broker { models: [None; MODELS], last: [None; MODELS], ledger: Ledger::new(), journal: Journal::new(), lim }
    }

    /// Keep a loaded bundle.
    pub fn add(&mut self, m: Model) -> Result<usize, AddError> {
        if self.models.iter().flatten().any(|h| h.model_ref == m.model_ref) {
            return Err(AddError::Duplicate);
        }
        let i = self.models.iter().position(|h| h.is_none()).ok_or(AddError::Full)?;
        self.models[i] = Some(m);
        Ok(i)
    }

    /// Forget every model: the arena their blobs were in is gone. The
    /// contexts' accounts and the journal stay, so a quota already spent and a
    /// receipt already handed out mean the same after the models are loaded
    /// again.
    pub fn forget_models(&mut self) {
        self.models = [None; MODELS];
        self.last = [None; MODELS];
    }

    /// The model called `model_ref`.
    pub fn find(&self, model_ref: u64) -> Option<(usize, &Model)> {
        self.models.iter().enumerate().find_map(|(i, m)| m.as_ref().filter(|m| m.model_ref == model_ref).map(|m| (i, m)))
    }

    /// The context slot of `badge`, given one if it has none.
    pub fn context(&mut self, badge: u32) -> Option<usize> {
        self.ledger.slot_of(badge)
    }

    fn record(&mut self, verdict: Decision, r: &Request, model_ref: u64, cand: &Variant, why: u32) -> u64 {
        // The room is rounded down and the need up: a figure that errs towards
        // refusing, as the decision the record explains did.
        let free_kib = self.lim.work_bytes as u64 / 1024;
        let mut rec = ProvenanceRecord::new(
            Rule::AccelAdmission as u8,
            verdict as u8,
            r.badge,
            [(cand.backend as u64) << 32 | cand.id as u64, kib(cand.mem_bytes), free_kib | (why as u64) << 32],
        );
        rec.image_hash_prefix = model_ref;
        rec.clock_ns = r.now_ns;
        self.journal.push(rec)
    }

    /// Choose the variant of the model `r` names, or refuse. `Err(None)`:
    /// there is no such model (nothing was admitted or refused, so nothing is
    /// recorded).
    pub fn admit(&mut self, r: &Request) -> Result<Admitted, Option<Refusal>> {
        let Some((mi, model)) = self.find(r.model_ref) else { return Err(None) };
        let model = *model;
        let Some(ctx) = self.ledger.slot_of(r.badge) else {
            let cand = model.variants()[0].v;
            let receipt = self.record(Decision::Refuse, r, model.model_ref, &cand, reason::CONTEXTS);
            return Err(Some(Refusal {
                code: BUSY,
                reason: reason::CONTEXTS,
                receipt,
                ctx: None,
                candidate: Some((cand.backend, cand.id)),
            }));
        };
        let left = self.ledger.left(ctx, r.now_ns, &self.lim);

        // Walk the publisher's order. `rank` is how far the best candidate got
        // (-1 no variant has a blob, 0 a blob, 1 and the memory, 2 and the
        // time, 3 and the energy) and `furthest` the first variant that got
        // that far: the refusal is about that one.
        let (mut rank, mut furthest) = (-1i8, 0usize);
        let mut best: Option<usize> = None;
        for (i, s) in model.variants().iter().enumerate() {
            if s.span.is_none() {
                continue;
            }
            let mut reached = 0i8;
            if s.v.mem_bytes <= self.lim.work_bytes {
                reached = 1;
                if !r.budget_us.is_some_and(|b| s.v.wcet_us > b) {
                    reached = 2;
                    if !left.is_some_and(|l| s.v.energy_uj as u64 > l) {
                        reached = 3;
                    }
                }
            }
            if reached > rank {
                rank = reached;
                furthest = i;
            }
            if reached == 3 {
                match best {
                    None => best = Some(i),
                    Some(b) if r.low_energy && s.v.energy_uj < model.slots[b].v.energy_uj => best = Some(i),
                    Some(_) => {}
                }
                if !r.low_energy {
                    break;
                }
            }
        }

        let Some(bi) = best else {
            let (code, why) = match rank {
                -1 => (UNSUPPORTED, reason::NO_BACKEND),
                0 => (BUSY, reason::NO_MEMORY),
                1 => (REFUSED, reason::DEADLINE),
                _ => (REFUSED, reason::ENERGY),
            };
            let cand = model.slots[furthest].v;
            let receipt = self.record(Decision::Refuse, r, model.model_ref, &cand, why);
            return Err(Some(Refusal { code, reason: why, receipt, ctx: Some(ctx), candidate: Some((cand.backend, cand.id)) }));
        };

        let slot = model.slots[bi];
        self.ledger.charge(ctx, slot.v.energy_uj as u64, &self.lim);
        let receipt = if self.last[mi] != Some(slot.v.id) {
            self.last[mi] = Some(slot.v.id);
            self.record(Decision::Admit, r, model.model_ref, &slot.v, reason::ADMITTED)
        } else {
            0
        };
        Ok(Admitted { model: mi, slot, ctx, receipt })
    }

    /// A run ended. `ran`: the backend produced an answer; `elapsed_ns`: how
    /// long it took.
    pub fn settle(&mut self, a: &Admitted, ran: bool, elapsed_ns: u64) -> Settled {
        let v = &a.slot.v;
        if !ran {
            self.ledger.refund(a.ctx, v.energy_uj as u64);
            return Settled { latency_us: 0, energy_uj: 0, overrun_us: 0 };
        }
        let latency_us = u32::try_from(elapsed_ns.div_ceil(1000)).unwrap_or(u32::MAX);
        let overrun_us = latency_us.saturating_sub(v.wcet_us);
        // The signed rate: energy per signed microsecond (the manifest checks
        // `wcet_us` is not 0).
        let extra = v.energy_uj as u64 * overrun_us as u64 / v.wcet_us as u64;
        self.ledger.charge(a.ctx, extra, &self.lim);
        Settled { latency_us, energy_uj: u32::try_from(v.energy_uj as u64 + extra).unwrap_or(u32::MAX), overrun_us }
    }
}
