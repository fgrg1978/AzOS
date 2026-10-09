// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Explainable decision records (Kconfig `DECISION_RECORDS`, kernel cargo
//! feature `decisions`).
//!
//! An admission, placement or refusal path writes one [`Record`]: the rule
//! that decided ([`Rule`]), the verdict, the subject (a task id, a topology
//! row, a CPU count), up to three numbers the rule compared, and, from the
//! rule's table entry, the alternative it rejected. The kernel renders the
//! ring at `/proc/decisions`, one line per record, oldest first.
//!
//! The ring holds `DECISION_RECORDS_ENTRIES` records; the oldest is
//! overwritten. It is lock-free so the wake path, which runs with the
//! scheduler's locks held and interrupts masked, can write to it: a writer
//! claims a sequence number, clears the slot's sequence word, writes the
//! fields and publishes the sequence with Release; a reader takes a slot
//! only if its sequence reads the same before and after the fields. Records
//! carry numbers only (no pointers), so a torn read is dropped, never
//! misread.
//!
//! Off (feature `on` absent, every deployment profile): [`record`] is empty
//! and the ring is not linked. On: about 40 instructions and five stores
//! per record, `DECISION_RECORDS_ENTRIES` x 40 bytes of `.bss`.
#![no_std]

use core::sync::atomic::{fence, AtomicBool, AtomicU64, Ordering};

/// Built in.
pub const ON: bool = cfg!(feature = "on");

/// Ring depth (Kconfig `DECISION_RECORDS_ENTRIES`).
pub const ENTRIES: usize = azos_limits::DECISION_RECORDS_ENTRIES as usize;
const _: () = assert!(ENTRIES >= 8);

/// The rules that write a record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Rule {
    /// Boot deadline admission of the topology's real-time rows.
    DeadlineAdmission = 0,
    /// The real-time band cap (`RT_BAND_CAP_PCT`) on one CPU.
    RtBandCap = 1,
    /// Boot memory admission of the topology's ring-3 rows.
    MemoryAdmission = 2,
    /// A woken, unpinned task placed on a CPU other than its last one.
    WakePlacement = 3,
    /// A typed capability check refused a handle.
    CapDenial = 4,
}

/// The verdict of a record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Verdict {
    Admit = 0,
    Refuse = 1,
    Place = 2,
    Deny = 3,
}
const VERDICTS: [&str; 4] = ["admit", "refuse", "place", "deny"];

/// One rule's names: what it is called, what its three numbers are, and the
/// alternative it rejected for each verdict it can give.
pub struct RuleInfo {
    pub name: &'static str,
    pub subject: &'static str,
    pub fields: [&'static str; 3],
    /// Rejected alternative when the verdict is Admit / Place.
    pub rejected_if_yes: &'static str,
    /// Rejected alternative when the verdict is Refuse / Deny.
    pub rejected_if_no: &'static str,
}

/// The table, by [`Rule`] index.
pub const RULES: [RuleInfo; 5] = [
    RuleInfo {
        name: "deadline-admission",
        subject: "cpus",
        fields: ["placed", "rows", "-"],
        rejected_if_yes: "refuse the topology: no CPU's density bound is exceeded",
        rejected_if_no: "run the rows: some row cannot meet its deadline on these CPUs",
    },
    RuleInfo {
        name: "rt-band-cap",
        subject: "cpus",
        fields: ["placed", "cap_pct", "-"],
        rejected_if_yes: "refuse the topology: every CPU's band stays under the cap",
        rejected_if_no: "run the rows: the band's rows on one CPU exceed the cap",
    },
    RuleInfo {
        name: "memory-admission",
        subject: "rows",
        fields: ["need_pages", "free_pages", "reserve_pages"],
        rejected_if_yes: "refuse the topology: need fits in free",
        rejected_if_no: "run the rows and let one fault at run time: need exceeds free",
    },
    RuleInfo {
        name: "wake-placement",
        subject: "tid",
        fields: ["cpu", "last_cpu", "prio"],
        rejected_if_yes: "stay on last_cpu: another CPU ranked better (blocking, then load)",
        rejected_if_no: "-",
    },
    RuleInfo {
        name: "cap-denial",
        subject: "tid",
        fields: ["kind", "reason", "-"],
        rejected_if_yes: "-",
        rejected_if_no: "grant: the handle is stale (1), of another kind (2) or lacks the rights (3)",
    },
];

/// A record as read back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub seq: u64,
    pub rule: u8,
    pub verdict: u8,
    pub subject: u32,
    pub n: [u64; 3],
}

impl Record {
    pub fn rule_info(&self) -> Option<&'static RuleInfo> {
        RULES.get(self.rule as usize)
    }
    pub fn verdict_name(&self) -> &'static str {
        VERDICTS.get(self.verdict as usize).copied().unwrap_or("?")
    }
    /// The alternative the rule rejected.
    pub fn rejected(&self) -> &'static str {
        match self.rule_info() {
            Some(r) if self.verdict == Verdict::Admit as u8 || self.verdict == Verdict::Place as u8 => r.rejected_if_yes,
            Some(r) => r.rejected_if_no,
            None => "?",
        }
    }
}

struct Slot {
    seq: AtomicU64,
    head: AtomicU64,
    n: [AtomicU64; 3],
}
#[allow(clippy::declare_interior_mutable_const)]
const SLOT: Slot = Slot { seq: AtomicU64::new(0), head: AtomicU64::new(0), n: [const { AtomicU64::new(0) }; 3] };
static RING: [Slot; ENTRIES] = [SLOT; ENTRIES];
static SEQ: AtomicU64 = AtomicU64::new(0);
/// Gate canary `canary=decision-skip`: [`record`] writes nothing.
static SKIP: AtomicBool = AtomicBool::new(false);

/// Write one record. Empty when off.
#[inline(always)]
pub fn record(rule: Rule, verdict: Verdict, subject: u32, n: [u64; 3]) {
    if ON {
        write(rule, verdict, subject, n);
    }
}

#[inline(never)]
fn write(rule: Rule, verdict: Verdict, subject: u32, n: [u64; 3]) {
    if SKIP.load(Ordering::Relaxed) {
        return;
    }
    let seq = SEQ.fetch_add(1, Ordering::Relaxed) + 1;
    let s = &RING[(seq % ENTRIES as u64) as usize];
    s.seq.store(0, Ordering::Relaxed);
    fence(Ordering::Release);
    s.head.store(rule as u64 | (verdict as u64) << 8 | (subject as u64) << 32, Ordering::Relaxed);
    for (d, v) in s.n.iter().zip(n) {
        d.store(v, Ordering::Relaxed);
    }
    s.seq.store(seq, Ordering::Release);
}

/// Records written since boot (the newest record's sequence number).
pub fn total() -> u64 {
    SEQ.load(Ordering::Relaxed)
}

/// Record `seq`, if it is still in the ring and was not being rewritten.
pub fn get(seq: u64) -> Option<Record> {
    if seq == 0 {
        return None;
    }
    let s = &RING[(seq % ENTRIES as u64) as usize];
    if s.seq.load(Ordering::Acquire) != seq {
        return None;
    }
    let head = s.head.load(Ordering::Relaxed);
    let n = [s.n[0].load(Ordering::Relaxed), s.n[1].load(Ordering::Relaxed), s.n[2].load(Ordering::Relaxed)];
    fence(Ordering::Acquire);
    if s.seq.load(Ordering::Relaxed) != seq {
        return None;
    }
    Some(Record { seq, rule: head as u8, verdict: (head >> 8) as u8, subject: (head >> 32) as u32, n })
}

/// Every record still in the ring, oldest first.
pub fn for_each(mut f: impl FnMut(&Record)) {
    let last = total();
    let first = last.saturating_sub(ENTRIES as u64 - 1).max(1);
    for seq in first..=last {
        if let Some(r) = get(seq) {
            f(&r);
        }
    }
}

/// Gate canary `canary=decision-skip` (the kernel calls it at boot).
pub fn set_skip() {
    SKIP.store(true, Ordering::Relaxed);
}
