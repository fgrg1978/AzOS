// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The query over the stored decisions: [`lookup`] one by id, [`query`] many
//! by a [`Filter`]. The `Decisions` interface (`userspace/lib/decisions`) and
//! the recovery console's `why` are these two functions; nothing here
//! parses text.
//!
//! Sources, in order: the ring (Kconfig `DECISION_RECORDS_DEV`, every verdict,
//! widened with [`ProvenanceRecord::from_record`]) and the journal (`journal`,
//! the durable ones, whole). A record in both is the same decision. The
//! journal holds the last `DECISION_JOURNAL_ENTRIES` durable records however
//! many ids the ring's records claimed in between, so a query reads it
//! whole, not only the ids the ring still spans.
use crate::{journal, ProvenanceRecord, DURABLE, ENTRIES, ON};

/// What a [`query`] selects. Unset fields match everything; `after` is
/// exclusive (0: from the oldest still held).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    pub rule: Option<u8>,
    pub verdict: Option<u8>,
    pub subject: Option<u32>,
    pub after: u64,
}

const HAS_RULE: u64 = 1;
const HAS_VERDICT: u64 = 2;
const HAS_SUBJECT: u64 = 4;

impl Filter {
    /// Everything.
    pub const ANY: Filter = Filter { rule: None, verdict: None, subject: None, after: 0 };

    /// The two words it travels as: `rule | verdict << 8 | set-flags << 16 |
    /// subject << 32`, then `after`.
    pub const fn pack(&self) -> [u64; 2] {
        let mut flags = 0;
        let mut rule = 0;
        let mut verdict = 0;
        let mut subject = 0;
        if let Some(r) = self.rule {
            flags |= HAS_RULE;
            rule = r as u64;
        }
        if let Some(v) = self.verdict {
            flags |= HAS_VERDICT;
            verdict = v as u64;
        }
        if let Some(s) = self.subject {
            flags |= HAS_SUBJECT;
            subject = s as u64;
        }
        [rule | verdict << 8 | flags << 16 | subject << 32, self.after]
    }

    /// [`Self::pack`] undone. Flag bits this version does not know are ignored.
    pub const fn unpack(w: [u64; 2]) -> Filter {
        let flags = (w[0] >> 16) & 0xff;
        Filter {
            rule: if flags & HAS_RULE != 0 { Some(w[0] as u8) } else { None },
            verdict: if flags & HAS_VERDICT != 0 { Some((w[0] >> 8) as u8) } else { None },
            subject: if flags & HAS_SUBJECT != 0 { Some((w[0] >> 32) as u32) } else { None },
            after: w[1],
        }
    }

    /// Does `p` pass?
    pub fn matches(&self, p: &ProvenanceRecord) -> bool {
        self.rule.is_none_or(|r| r == p.rule)
            && self.verdict.is_none_or(|v| v == p.verdict)
            && self.subject.is_none_or(|s| s == p.subject)
    }
}

/// Decision `id`, if it is still held and was not being rewritten.
pub fn lookup(id: u64) -> Option<ProvenanceRecord> {
    if id == 0 {
        return None;
    }
    if ON {
        if let Some(r) = crate::get(id) {
            return Some(ProvenanceRecord::from_record(&r));
        }
    }
    if DURABLE {
        return journal::get(id);
    }
    None
}

/// Every record still held after id `after`, to `f`: first the journal's
/// older than the ring's oldest, in their journal places (two made at once
/// may hold them in the other order than their ids), each one whatever `f`
/// returns; then the ring's, in id order, until `f` returns false.
fn walk(after: u64, mut f: impl FnMut(&ProvenanceRecord) -> bool) {
    let last = crate::total();
    // The ring's oldest id; with no ring, every record is the journal's.
    let ring_first = if ON { last.saturating_sub(ENTRIES as u64 - 1).max(1) } else { u64::MAX };
    if DURABLE {
        journal::for_each(|p| {
            if p.seq > after && p.seq < ring_first && p.seq <= last {
                f(p);
            }
        });
    }
    if ON {
        for id in after.saturating_add(1).max(ring_first)..=last {
            if let Some(p) = lookup(id) {
                if !f(&p) {
                    return;
                }
            }
        }
    }
}

/// Every record still held, the oldest roughly first (see [`walk`]).
pub fn for_each_held(mut f: impl FnMut(&ProvenanceRecord)) {
    walk(0, |p| {
        f(p);
        true
    });
}

/// The ids of the stored decisions that pass `f`, oldest first, after
/// `f.after`, into `out`; how many. A caller with more to read asks again
/// with `after` set to the last id it got.
pub fn query(f: &Filter, out: &mut [u64]) -> usize {
    let mut n = 0;
    if out.is_empty() {
        return 0;
    }
    walk(f.after, |p| {
        let id = p.seq;
        // Kept in id order: the journal's come in place order.
        if f.matches(p) && (n < out.len() || id < out[n - 1]) {
            let at = out[..n].partition_point(|&q| q < id);
            n = (n + 1).min(out.len());
            out.copy_within(at..n - 1, at + 1);
            out[at] = id;
        }
        n < out.len()
    });
    n
}

#[cfg(all(test, feature = "durable"))]
mod tests {
    extern crate std;
    use super::*;
    use crate::{record, Rule, Verdict, JOURNAL_ENTRIES};
    use std::sync::Mutex;
    use std::vec::Vec;

    /// The statics are the process's: one test at a time.
    static GUARD: Mutex<()> = Mutex::new(());

    fn refuse(subject: u32, n: [u64; 3]) -> u64 {
        record(Rule::DeadlineAdmission, Verdict::Refuse, subject, n);
        crate::total()
    }

    fn all(f: &Filter) -> Vec<u64> {
        let mut out = [0u64; 64];
        let n = query(f, &mut out);
        out[..n].to_vec()
    }

    /// A refusal is found by its id, whole, with the numbers it compared.
    /// **Canary.** Delete the `journal::store` call in `durable`: the lookup
    /// of a refusal returns `None` with the ring off, red.
    #[test]
    fn a_refusal_resolves_by_id() {
        let _g = GUARD.lock().unwrap();
        let id = refuse(7, [500, 1000, 2 << 32]);
        let p = lookup(id).expect("the refusal is in the journal");
        assert_eq!((p.rule, p.verdict, p.subject, p.n), (Rule::DeadlineAdmission as u8, Verdict::Refuse as u8, 7, [500, 1000, 2 << 32]));
        assert_eq!(p.seq, id);
        assert_eq!(lookup(0), None);
        assert_eq!(lookup(id + 1_000_000), None);
    }

    /// An admission is not durable: no journal entry, so with the ring off
    /// there is nothing to find (with it on the ring has it).
    #[test]
    fn only_durable_verdicts_reach_the_journal() {
        let _g = GUARD.lock().unwrap();
        let t0 = crate::total();
        record(Rule::DeadlineAdmission, Verdict::Admit, 9, [1, 2, 3]);
        let found = all(&Filter { subject: Some(9), verdict: Some(Verdict::Admit as u8), after: t0, ..Filter::ANY });
        assert_eq!(found.len(), if ON { 1 } else { 0 });
    }

    /// The filter selects on rule, verdict and subject, pages with `after`,
    /// and ids come back oldest first.
    #[test]
    fn the_filter_selects_and_pages() {
        let _g = GUARD.lock().unwrap();
        let t0 = crate::total();
        let a = refuse(101, [1, 1, 0]);
        let b = refuse(102, [2, 2, 0]);
        let c = refuse(101, [3, 3, 0]);
        let mine = Filter { rule: Some(Rule::DeadlineAdmission as u8), verdict: Some(Verdict::Refuse as u8), after: t0, ..Filter::ANY };
        assert_eq!(all(&mine), [a, b, c]);
        assert_eq!(all(&Filter { subject: Some(101), ..mine }), [a, c]);
        assert_eq!(all(&Filter { subject: Some(103), ..mine }), Vec::<u64>::new());
        assert_eq!(all(&Filter { rule: Some(Rule::MemoryAdmission as u8), ..mine }), Vec::<u64>::new());
        assert_eq!(all(&Filter { after: a, ..mine }), [b, c]);
        let mut two = [0u64; 2];
        assert_eq!(query(&mine, &mut two), 2);
        assert_eq!(two, [a, b]);
        assert_eq!(query(&Filter { after: two[1], ..mine }, &mut two), 1);
        assert_eq!(two[0], c);
        assert_eq!(query(&mine, &mut []), 0);
    }

    /// The journal keeps the last `JOURNAL_ENTRIES`: the oldest is gone, the
    /// newest is not. Not a canary for the slot policy: every id is durable
    /// here, so keyed by id or by place the slots are the same (decisions-tests
    /// `a_durable_record_outlives_the_ids_the_ring_claims`, with the ring).
    #[test]
    fn the_journal_forgets_the_oldest() {
        let _g = GUARD.lock().unwrap();
        let first = refuse(200, [1, 0, 0]);
        let mut last = first;
        for i in 0..JOURNAL_ENTRIES as u64 {
            last = refuse(200, [i + 2, 0, 0]);
        }
        if !ON {
            assert_eq!(lookup(first), None, "the oldest survived a full wrap");
        }
        assert_eq!(lookup(last).map(|p| p.subject), Some(200));
    }

    #[test]
    fn the_filter_survives_its_wire_form() {
        for f in [
            Filter::ANY,
            Filter { rule: Some(0), verdict: Some(0), subject: Some(0), after: 0 },
            Filter { rule: Some(8), verdict: Some(3), subject: Some(u32::MAX), after: u64::MAX },
            Filter { rule: None, verdict: Some(1), subject: None, after: 5 },
        ] {
            assert_eq!(Filter::unpack(f.pack()), f);
        }
        // Some(0) is not None: the flag, not the value, says it is set.
        assert_ne!(Filter { rule: Some(0), ..Filter::ANY }.pack(), Filter::ANY.pack());
    }

    /// The word form is the record: every field through `to_words` and back.
    #[test]
    fn the_word_form_round_trips() {
        let p = ProvenanceRecord {
            rule: 4,
            verdict: 3,
            subject: 0x0A0B_0C0D,
            seq: 0x1111_2222_3333_4444,
            cap_slot: [1, 2],
            parent_cap: [3, 4],
            topology_row_id: 0x55,
            node_id: 0x66,
            image_hash_prefix: 0x7777_8888_9999_AAAA,
            session_id: 0xBBBB,
            n: [0xC1, 0xC2, 0xC3],
            clock_ns: 0xDDDD,
        };
        assert_eq!(ProvenanceRecord::from_words(&p.to_words()), p);
    }
}
