// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Decisions` object: the question "why was this refused" as a typed
//! interface, not a log to grep.
//!
//! Every admission, placement and refusal path in the kernel writes a
//! decision (`azos_decision`): the rule that decided, the verdict, the
//! subject, the numbers it compared, and the provenance known for it. The
//! ones that went down the durable path are kept whole in the kernel's
//! journal and appear in `/proc/decisions.bin` as fixed-size binary records.
//! `userspace/services/decisd` serves this interface over the
//! `endpoint.decisions` endpoint its topology row declares; `why` (and any
//! other client holding a call capability on that endpoint) asks it.
//!
//! * [`Decisions::query`] lists decision ids: a [`Filter`] on rule, verdict
//!   and subject, paged by the last id seen. Ids are the kernel's sequence
//!   numbers: unique since boot, they restart at a reset.
//! * [`Decisions::get`] returns one decision. A reply holds seven words and a
//!   [`ProvenanceRecord`] is thirteen, so it comes in [`PARTS`] parts (the
//!   Terminal's `line_chunk` pattern); [`fetch`] asks for both and joins them.
//!
//! No text is parsed on either side: the filter and the record travel as
//! words, and the chain a human reads is printed from the record by the
//! client ([`ProvenanceRecord::write_chain`]).
//!
//! # Wire form
//!
//! `query` request: the filter as two words ([`Filter::pack`]). Reply word 0
//! is `count | total << 8` (`count` ids follow, at most [`QUERY_IDS`]; `total`
//! is the number of decisions since boot, 56 bits), then the ids, oldest
//! first.
//!
//! `get` request: the id, the part. Part 0 is the first seven words of
//! [`ProvenanceRecord::to_words`]; its word 1 is the id again, and 0 there
//! means the decision is not held (gone from the journal, or never made).
//! Part 1 is the id, then the last six words. A client that reads part 1 and
//! finds another id than part 0's had the slot rewritten in between and asks
//! again ([`fetch`]).
#![no_std]

pub use azos_decision::{Filter, ProvenanceRecord, PROVENANCE_SIZE, PROVENANCE_WORDS, RULES, VERDICTS};
pub use azos_idl::{IdlError, MsgDesc, Transport};
use azos_idl::azos_interface;

/// The interface id (ASCII "DECI").
pub const DECISIONS_ID: u32 = 0x4445_4349;
/// Ids in one `query` reply.
pub const QUERY_IDS: usize = 6;
/// Words in one reply: the status takes the eighth.
pub const REPLY_WORDS: usize = 7;
/// Parts of a `get`.
pub const PARTS: u32 = 2;
/// The endpoint a topology row declares for this object.
pub const ENDPOINT: &str = "endpoint.decisions";

const _: () = assert!(REPLY_WORDS == 1 + QUERY_IDS);
// Part 0 takes seven words of the record, part 1 the id and the other six.
const _: () = assert!(PROVENANCE_WORDS == REPLY_WORDS + (REPLY_WORDS - 1));

/// The Decisions interface. A server holds the records; every op reads.
#[azos_interface(id = 0x4445_4349, level = 1, words = 8)]
pub trait Decisions {
    /// The ids of the decisions that pass `filter` ([`Filter::pack`]), oldest
    /// first, after the filter's `after`: word 0 is `count | total << 8`, then
    /// up to [`QUERY_IDS`] ids. More to read: ask again with `after` set to
    /// the last id.
    #[idempotent]
    fn query(&self, filter: [u64; 2]) -> [u64; REPLY_WORDS];
    /// Part `part` ([`PARTS`] of them) of decision `id`.
    #[idempotent]
    fn get(&self, id: u64, part: u32) -> [u64; REPLY_WORDS];
}

/// `query`'s reply word 0.
pub const fn pack_count(count: usize, total: u64) -> u64 {
    count as u64 & 0xff | total << 8
}

/// `(count, total)` out of a `query` reply.
pub const fn unpack_count(w0: u64) -> (usize, u64) {
    ((w0 & 0xff) as usize, w0 >> 8)
}

/// Part `part` of `p` as a reply. `None` for a part past [`PARTS`].
pub fn pack_part(p: &ProvenanceRecord, part: u32) -> Option<[u64; REPLY_WORDS]> {
    let w = p.to_words();
    let mut out = [0u64; REPLY_WORDS];
    match part {
        0 => out.copy_from_slice(&w[..REPLY_WORDS]),
        1 => {
            out[0] = p.seq;
            out[1..].copy_from_slice(&w[REPLY_WORDS..]);
        }
        _ => return None,
    }
    Some(out)
}

/// The record two parts make, `None` if they are not of one decision (the
/// ids differ, or part 0 says the decision is not held).
pub fn join_parts(a: &[u64; REPLY_WORDS], b: &[u64; REPLY_WORDS]) -> Option<ProvenanceRecord> {
    if a[1] == 0 || a[1] != b[0] {
        return None;
    }
    let mut w = [0u64; PROVENANCE_WORDS];
    w[..REPLY_WORDS].copy_from_slice(a);
    w[REPLY_WORDS..].copy_from_slice(&b[1..]);
    Some(ProvenanceRecord::from_words(&w))
}

/// Decision `id` from a server: both parts, joined. `Ok(None)`: not held (or
/// rewritten twice while asking).
pub fn fetch<C: DecisionsCall>(c: &C, id: u64) -> Result<Option<ProvenanceRecord>, IdlError> {
    // A part read twice that disagrees means the server's slot was rewritten
    // between the calls; the answer is then the new decision or none. Two
    // tries, then give up rather than spin on a busy server.
    for _ in 0..2 {
        let a = c.get(id, 0)?;
        if a[1] == 0 {
            return Ok(None);
        }
        let b = c.get(id, 1)?;
        if let Some(p) = join_parts(&a, &b) {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

/// Up to `out.len()` ids that pass `f`, oldest first, paging through
/// [`Decisions::query`]; how many, and the decisions since boot the server
/// reports.
pub fn list<C: DecisionsCall>(c: &C, f: &Filter, out: &mut [u64]) -> Result<(usize, u64), IdlError> {
    let mut f = *f;
    let (mut n, mut total) = (0, 0);
    while n < out.len() {
        let r = c.query(f.pack())?;
        let (count, t) = unpack_count(r[0]);
        total = t;
        let count = count.min(QUERY_IDS).min(out.len() - n);
        if count == 0 {
            break;
        }
        out[n..n + count].copy_from_slice(&r[1..1 + count]);
        n += count;
        f.after = r[count];
        if count < QUERY_IDS {
            break;
        }
    }
    Ok((n, total))
}

/// What a server answers from: the stored decisions, however it holds them.
/// The kernel's own implementation is `azos_decision`'s free functions;
/// `decisd` reads `/proc/decisions.bin`; a test uses a vector.
pub trait Source {
    /// Decisions made since boot.
    fn total(&self) -> u64;
    /// The ids that pass `f`, oldest first, into `out`; how many.
    fn query(&self, f: &Filter, out: &mut [u64]) -> usize;
    /// Decision `id`, if held.
    fn lookup(&self, id: u64) -> Option<ProvenanceRecord>;
}

/// The Decisions object served from a [`Source`].
pub struct Service<S: Source>(pub S);

impl<S: Source> Decisions for Service<S> {
    fn query(&self, filter: [u64; 2]) -> [u64; REPLY_WORDS] {
        let mut ids = [0u64; QUERY_IDS];
        let n = self.0.query(&Filter::unpack(filter), &mut ids);
        let mut out = [0u64; REPLY_WORDS];
        out[0] = pack_count(n, self.0.total());
        out[1..1 + n].copy_from_slice(&ids[..n]);
        out
    }

    fn get(&self, id: u64, part: u32) -> [u64; REPLY_WORDS] {
        match self.0.lookup(id).and_then(|p| pack_part(&p, part)) {
            Some(w) => w,
            None => [0; REPLY_WORDS],
        }
    }
}
