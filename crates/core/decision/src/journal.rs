// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The journal: the last `DECISION_JOURNAL_ENTRIES` decisions that went down
//! the durable path, whole ([`ProvenanceRecord`], as words).
//!
//! The durable sink writes a 20-byte receipt to the flight recorder and the
//! RAM that held the record is gone; a `why` asked a minute later would have
//! the recorder's file and nothing to join it to. The journal is that RAM,
//! kept: lock-free like the ring (a writer clears the slot's sequence word,
//! writes the words and publishes the sequence with Release; a reader takes
//! a slot only if its sequence reads the same before and after the words),
//! indexed by id, newest overwrites oldest. It is written from `durable`
//! only, so it exists exactly when the durable sink does (Kconfig
//! `DECISION_REFUSALS_DURABLE`) and costs `DECISION_JOURNAL_ENTRIES` x 112
//! bytes of `.bss` then; without `durable` nothing refers to it and it is not
//! linked.
use crate::{ProvenanceRecord, JOURNAL_ENTRIES, PROVENANCE_WORDS};
use crate::a64::AtomicU64;
use core::sync::atomic::{fence, Ordering};

struct Slot {
    seq: AtomicU64,
    w:   [AtomicU64; PROVENANCE_WORDS],
}
#[allow(clippy::declare_interior_mutable_const)]
const SLOT: Slot = Slot { seq: AtomicU64::new(0), w: [const { AtomicU64::new(0) }; PROVENANCE_WORDS] };
static JOURNAL: [Slot; JOURNAL_ENTRIES] = [SLOT; JOURNAL_ENTRIES];

/// Keep `p` (its `seq`, not 0, is its id and its slot).
pub(crate) fn store(p: &ProvenanceRecord) {
    let s = &JOURNAL[(p.seq % JOURNAL_ENTRIES as u64) as usize];
    s.seq.store(0, Ordering::Relaxed);
    fence(Ordering::Release);
    for (d, v) in s.w.iter().zip(p.to_words()) {
        d.store(v, Ordering::Relaxed);
    }
    s.seq.store(p.seq, Ordering::Release);
}

/// Record `id`, if the journal still holds it and it was not being rewritten.
pub(crate) fn get(id: u64) -> Option<ProvenanceRecord> {
    if id == 0 {
        return None;
    }
    let s = &JOURNAL[(id % JOURNAL_ENTRIES as u64) as usize];
    if s.seq.load(Ordering::Acquire) != id {
        return None;
    }
    let mut w = [0u64; PROVENANCE_WORDS];
    for (v, d) in w.iter_mut().zip(&s.w) {
        *v = d.load(Ordering::Relaxed);
    }
    fence(Ordering::Acquire);
    if s.seq.load(Ordering::Relaxed) != id {
        return None;
    }
    Some(ProvenanceRecord::from_words(&w))
}
