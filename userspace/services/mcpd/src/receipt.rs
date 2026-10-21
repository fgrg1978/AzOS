// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The receipt of a call: the newest decision record the kernel wrote for it.
//!
//! A call to an endpoint is two kernel acts, the derive of its warrant and the
//! call through it, and each can leave a record in the decision journal that
//! the `Decisions` object serves. The bridge reads the journal's total before
//! the call and finds the records after it:
//!
//! * a **refusal** is written under the bridge's task id (the capability
//!   denial of a call the kernel did not admit);
//! * the **derive** of an admitted warrant is written under the bridge's
//!   Domain, not its task id, with the warrant's expiry as its third number. The
//!   expiry the bridge asked for is a nanosecond clock reading no other task's
//!   derive carries, so it tells the record (kept only when the kernel keeps
//!   admissions, Kconfig `DECISION_RECORDS_DEV`; otherwise an admitted call has
//!   no receipt and the answer says so with 0).
//!
//! The newest of the two is the receipt. The bridge makes one call at a time,
//! so a refusal under its task id after the mark is the call's own.

use crate::bridge::Host;
use azos_decision::{Rule, Verdict};
use azos_decisions::{DecisionsCall, DecisionsClient, Filter, ProvenanceRecord, QUERY_IDS};
use azos_idl::{IdlError, MsgDesc, Transport};
use core::cell::RefCell;

/// Pages of one search (each holds [`QUERY_IDS`] ids).
const PAGES: usize = 8;

/// The decisions endpoint as a transport for the generated client.
struct Dec<'a, H: Host>(RefCell<&'a mut H>);

impl<H: Host> Transport for Dec<'_, H> {
    fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
        self.0.borrow_mut().decisions(msg).map_err(|rc| IdlError::Transport(rc as isize))
    }
}

/// The decision total now (the newest id held when nothing newer is asked for).
fn total<C: DecisionsCall>(c: &C) -> Option<u64> {
    let r = c.query(Filter { after: u64::MAX, ..Filter::ANY }.pack()).ok()?;
    Some(azos_decisions::unpack_count(r[0]).1)
}

/// The newest decision of `subject` after `mark`.
fn newest_of<C: DecisionsCall>(c: &C, subject: u32, mark: u64) -> Option<ProvenanceRecord> {
    let mut f = Filter { subject: Some(subject), after: mark, ..Filter::ANY };
    let mut newest = 0;
    for _ in 0..PAGES {
        let r = c.query(f.pack()).ok()?;
        let n = azos_decisions::unpack_count(r[0]).0.min(QUERY_IDS);
        if n == 0 {
            break;
        }
        newest = r[n];
        f.after = newest;
        if n < QUERY_IDS {
            break;
        }
    }
    if newest == 0 {
        return None;
    }
    azos_decisions::fetch(c, newest).ok().flatten()
}

/// The derive record of the warrant minted with `expiry_ns`, after `mark`.
fn derive_of<C: DecisionsCall>(c: &C, mark: u64, expiry_ns: u64) -> Option<ProvenanceRecord> {
    let mut f = Filter {
        rule: Some(Rule::CapDerive as u8),
        verdict: Some(Verdict::Admit as u8),
        after: mark,
        ..Filter::ANY
    };
    for _ in 0..PAGES {
        let r = c.query(f.pack()).ok()?;
        let n = azos_decisions::unpack_count(r[0]).0.min(QUERY_IDS);
        for &id in &r[1..1 + n] {
            if let Some(p) = azos_decisions::fetch(c, id).ok().flatten() {
                if p.n[2] == expiry_ns {
                    return Some(p);
                }
            }
        }
        if n < QUERY_IDS {
            break;
        }
        f.after = r[n];
    }
    None
}

/// The decision total now: take it before the call.
pub fn mark<H: Host>(host: &mut H) -> u64 {
    total(&DecisionsClient::new(Dec(RefCell::new(host)))).unwrap_or(0)
}

/// The receipt of the call made after `mark`: the newest of the bridge's own
/// decisions (`me`, its task id) and its warrant's derive record
/// (`expiry_ns`, 0 when none was minted).
pub fn find<H: Host>(host: &mut H, me: u32, mark: u64, expiry_ns: u64) -> Option<ProvenanceRecord> {
    let c = DecisionsClient::new(Dec(RefCell::new(host)));
    let own = newest_of(&c, me, mark);
    let derive = if expiry_ns != 0 { derive_of(&c, mark, expiry_ns) } else { None };
    match (own, derive) {
        (Some(a), Some(b)) => Some(if a.seq > b.seq { a } else { b }),
        (a, b) => a.or(b),
    }
}
