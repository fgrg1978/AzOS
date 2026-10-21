// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The provenance a node keeps of what it minted for, or over, a link.
//!
//! The kernel's decision record already has the fields Phase 9 was to fill
//! (`ProvenanceRecord::node_id`, `session_id`, `seq`, `cap_slot`,
//! `parent_cap`); a ring-3 server cannot write the kernel's journal, so it keeps
//! its own, in the same full form (`to_bytes`), and both nodes append to theirs:
//! the node that exports records the warrant it derived for the peer, the node
//! that imports records the authority its caller was given over the session.
//! A record on one side names the other (`node_id`) and the shared session
//! (`session_id`), so the two journals join on the session.

use azos_decision::{ProvenanceRecord, Rule, Verdict};

use crate::{NodeId, JOURNAL_CAP};

/// A bounded ring of records, oldest overwritten.
pub struct Journal {
    recs: [ProvenanceRecord; JOURNAL_CAP],
    total: u64,
}

impl Journal {
    /// Empty.
    pub const fn new() -> Journal {
        Journal {
            recs: [ProvenanceRecord::new(0, 0, 0, [0; 3]); JOURNAL_CAP],
            total: 0,
        }
    }

    /// Records appended since the start (not the ones still held).
    pub fn total(&self) -> u64 {
        self.total
    }

    /// The records held, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &ProvenanceRecord> {
        let held = (self.total as usize).min(JOURNAL_CAP);
        let first = self.total as usize - held;
        (first..self.total as usize).map(move |i| &self.recs[i % JOURNAL_CAP])
    }

    fn push(&mut self, r: ProvenanceRecord) {
        self.recs[self.total as usize % JOURNAL_CAP] = r;
        self.total += 1;
    }

    /// A warrant or a re-minted object: `handle` was derived from `parent`
    /// for the session with `peer`. `subject` is whoever the authority is for
    /// (the badge of the local caller on the importing side, the session on the
    /// exporting one); `n` is (interface id, op, expiry in ns, 0 = none) in the
    /// first three: `[iface, op, expiry]`.
    #[allow(clippy::too_many_arguments)]
    pub fn derive(&mut self, now: u64, peer: NodeId, session: u32, seq: u64, subject: u32, handle: u32, parent: u32, n: [u64; 3]) {
        let mut r = ProvenanceRecord::new(Rule::CapDerive as u8, Verdict::Admit as u8, subject, n);
        r.seq = seq;
        r.node_id = peer;
        r.session_id = session as u64;
        r.cap_slot = [handle as u64, 0];
        r.parent_cap = [parent as u64, 0];
        r.clock_ns = now;
        self.push(r);
    }

    /// Everything minted over the session with `peer` was revoked: `count`
    /// handles closed, and `calls` calls abandoned.
    pub fn revoke(&mut self, now: u64, peer: NodeId, session: u32, count: u64, calls: u64) {
        let mut r = ProvenanceRecord::new(Rule::CapRevoke as u8, Verdict::Deny as u8, session, [0, calls, count]);
        r.node_id = peer;
        r.session_id = session as u64;
        r.clock_ns = now;
        self.push(r);
    }

    /// The authority over `iface` that `peer` (boot epoch `peer_epoch`)
    /// derived from was withdrawn and the revocation took effect:
    /// `Rule::RemoteRevoke` (`[domain, cap, epoch]`: the interface, the
    /// handles closed, the peer's epoch). `notice` is the notice's number,
    /// the same on both nodes. Written by the node that ran the revocation
    /// when it ran, and by the node that withdrew when the ack arrived, so
    /// the record's clock is the instant after which no effect remains.
    pub fn remote_revoke(&mut self, now: u64, peer: NodeId, session: u32, notice: u64, n: [u64; 3]) {
        let mut r = ProvenanceRecord::new(Rule::RemoteRevoke as u8, Verdict::Admit as u8, peer, n);
        r.seq = notice;
        r.node_id = peer;
        r.session_id = session as u64;
        r.clock_ns = now;
        self.push(r);
    }

    /// The same notice went unanswered for the whole bound: the revocation
    /// could not be confirmed and the session is broken (which revokes
    /// everything minted over it).
    pub fn remote_revoke_unconfirmed(&mut self, now: u64, peer: NodeId, session: u32, notice: u64, n: [u64; 3]) {
        let mut r = ProvenanceRecord::new(Rule::RemoteRevoke as u8, Verdict::Refuse as u8, peer, n);
        r.seq = notice;
        r.node_id = peer;
        r.session_id = session as u64;
        r.clock_ns = now;
        self.push(r);
    }

    /// A call was refused before it crossed or before it ran, and why (`n[0]`
    /// the interface id, `n[1]` the op, `n[2]` the status).
    pub fn refuse(&mut self, now: u64, peer: NodeId, session: u32, seq: u64, subject: u32, n: [u64; 3]) {
        let mut r = ProvenanceRecord::new(Rule::CapDenial as u8, Verdict::Deny as u8, subject, n);
        r.seq = seq;
        r.node_id = peer;
        r.session_id = session as u64;
        r.clock_ns = now;
        self.push(r);
    }
}
