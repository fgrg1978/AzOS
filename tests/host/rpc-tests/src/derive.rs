// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The warrant a token becomes: `ENDPOINT_DERIVE` with the token's caveats,
//! cached per interface, caveat set and expiry (`Host::derive`, `Rpc::warrant`).
//!
//! A peer node (a `Forger`, which holds the session key) sends the same read
//! under tokens it narrows differently; the fake host keeps what the kernel
//! keeps of a derive (the caveat list of each warrant) and evaluates it on a
//! call as the kernel's resolve does (`World`'s `gate`). The guarantees: a call
//! never runs under the caveats (or the expiry) of another token, a `QUOTA`
//! counts for the lineage of the token however its holder narrows it, and a
//! token whose `OP_MASK` the call could never discharge is refused before a
//! derive.

use crate::world::*;
use azos_idl::IdlError;
use azos_rpc::wire::{cav, put_desc, put_token, Caveat, Kind};
use azos_rpc::{QUOTAS_MAX, WARRANTS_MAX};

/// A session of the forger `f` with B, B serving `probe`.
fn session() -> (World, Forger) {
    let mut w = World::new();
    let f = Forger::dial(&mut w, A);
    (w, f)
}

/// One `read` request under a token narrowed by `caveats`, as `f` sends it
/// (seq `seq`); the first status word of the answer (0: B ran it).
fn read(w: &mut World, f: &mut Forger, seq: u64, caveats: &[Caveat]) -> u64 {
    let d = raw_req(ProbeIdl::ID, ProbeIdl::OP_READ, &[5]);
    let mut tok = f.token(ProbeIdl::ID);
    for c in caveats {
        tok.attenuate(*c).unwrap();
    }
    let mut body = vec![0u8; 512];
    let mut at = 0;
    put_desc(&d, &mut body, &mut at).unwrap();
    put_token(&tok, &mut body, &mut at).unwrap();
    let frames = f.seal(Kind::Req, seq, &body[..at]);
    f.status(w, &frames)
}

/// The caveat lists the warrants of B were derived with, in derive order.
fn derived(w: &World) -> Vec<Vec<(u8, u64)>> {
    let st = w.b.st.borrow();
    st.derives.iter().map(|d| st.caveats.get(&d.0).cloned().unwrap_or_default()).collect()
}

const RECEIPT_X: Caveat = Caveat::new(cav::RECEIPT, 0x0103_0000_0000_01F4);
const RECEIPT_Y: Caveat = Caveat::new(cav::RECEIPT, 0x0104_0000_0000_01F4);

/// **Two tokens with different caveats get different local warrants, and a
/// token with none is not served by either.** The same token again reuses
/// its warrant (one derive), a token that adds a caveat gets its own, and each
/// warrant carries exactly the caveats of the token that made it.
///
/// **Canary.** Key `Rpc::warrant`'s lookup by interface alone (drop the
/// `w.caveats[..] == *g.list()` comparison in `warrant_slot`): the second
/// token finds the first's warrant, `derived` has one entry, red. Pass an empty
/// list to `Host::derive`: every entry is `[]`, red.
#[test]
fn tokens_with_different_caveats_get_different_warrants() {
    let (mut w, mut f) = session();
    let ok = 0;
    assert_eq!(read(&mut w, &mut f, 10, &[RECEIPT_X]), ok);
    assert_eq!(read(&mut w, &mut f, 11, &[RECEIPT_X]), ok, "the same token again");
    assert_eq!(derived(&w), vec![vec![(cav::RECEIPT, RECEIPT_X.arg)]], "one derive for both");
    assert_eq!(read(&mut w, &mut f, 12, &[RECEIPT_Y]), ok);
    assert_eq!(read(&mut w, &mut f, 13, &[]), ok, "a token with no caveat");
    assert_eq!(read(&mut w, &mut f, 14, &[RECEIPT_X, RECEIPT_Y]), ok);
    assert_eq!(
        derived(&w),
        vec![
            vec![(cav::RECEIPT, RECEIPT_X.arg)],
            vec![(cav::RECEIPT, RECEIPT_Y.arg)],
            vec![],
            vec![(cav::RECEIPT, RECEIPT_X.arg), (cav::RECEIPT, RECEIPT_Y.arg)],
        ],
    );
    let st = w.b.st.borrow();
    let handles: Vec<u32> = st.derives.iter().map(|d| d.0).collect();
    assert_eq!(handles.len(), 4);
    assert!(handles.windows(2).all(|p| p[0] != p[1]) && st.warrants().len() == 4, "four warrants");
    assert_eq!(w.b.svc.borrow().reads, 5, "and every call ran");
}

/// **A `QUOTA` counts for the lineage of the token, not for a warrant or a
/// token value: `n` calls run, the next is refused, and nothing a holder does
/// with its copy renews the count.** The count is the session's; the warrant
/// carries no `QUOTA` (the kernel would count per warrant, which a narrowed
/// copy or an evicted warrant starts over).
///
/// **Canaries.** Key the budget by the whole token instead of the chain up to
/// its `QUOTA` (`Session::remint`: `sigs[tok.caveats().len() - 1]`): every
/// narrowed copy of a spent token has a lineage of its own and runs (red). Put the `QUOTA` back in the derive list: the kernel's count (per warrant)
/// is again renewable by a narrowed copy (red).
#[test]
fn a_quota_counts_for_the_token_lineage_whatever_the_holder_does() {
    let (mut w, mut f) = session();
    let refused = IdlError::Refused.status();
    let q = |n| [Caveat::new(cav::QUOTA, n)];
    for seq in 0..4 {
        assert_eq!(read(&mut w, &mut f, 10 + seq, &q(4)), 0, "use {}", seq + 1);
    }
    for seq in 4..8 {
        assert_eq!(read(&mut w, &mut f, 10 + seq, &q(4)), refused, "spent: call {}", seq + 1);
    }
    assert_eq!(w.b.svc.borrow().reads, 4, "nothing ran past the count");
    assert_eq!(derived(&w), vec![vec![]], "one warrant, with no QUOTA; a refusal derives nothing");
    // The holder narrows the spent token: a smaller quota, a larger one, another
    // caveat, an expiry. Every copy is the same lineage, so every copy is spent.
    for (k, extra) in [q(3).to_vec(), q(1).to_vec(), q(9).to_vec(), vec![RECEIPT_X], vec![RECEIPT_X, Caveat::new(cav::QUOTA, 2)]].into_iter().enumerate() {
        let mut caveats = q(4).to_vec();
        caveats.extend(extra);
        assert_eq!(read(&mut w, &mut f, 30 + k as u64, &caveats), refused, "narrowed copy {k}");
    }
    assert_eq!(w.b.svc.borrow().reads, 4);
    // Another token with another quota is another lineage, with a count of its own.
    assert_eq!(read(&mut w, &mut f, 40, &q(1)), 0);
    assert_eq!(read(&mut w, &mut f, 41, &q(1)), refused);
    // A quota beside another caveat is part of the same chain.
    assert_eq!(read(&mut w, &mut f, 42, &[RECEIPT_X, Caveat::new(cav::QUOTA, 2)]), 0);
    assert_eq!(derived(&w), vec![vec![], vec![(cav::RECEIPT, RECEIPT_X.arg)]]);
}

/// **A budget is shared by the copies that narrow it, each nested budget on
/// its own too:** a token of five uses narrowed to two runs two calls and no
/// more, and what it spent comes out of the five.
///
/// **Canary.** Take a use from the last `QUOTA` of the chain only (`spend`:
/// iterate `budgets.last()`): the parent keeps five after the child spent two
/// (red).
#[test]
fn a_nested_quota_spends_from_every_budget_it_follows() {
    let (mut w, mut f) = session();
    let refused = IdlError::Refused.status();
    let parent = [Caveat::new(cav::QUOTA, 5)];
    let child = [Caveat::new(cav::QUOTA, 5), Caveat::new(cav::QUOTA, 2)];
    assert_eq!(read(&mut w, &mut f, 10, &child), 0);
    assert_eq!(read(&mut w, &mut f, 11, &child), 0);
    assert_eq!(read(&mut w, &mut f, 12, &child), refused, "the child's two");
    for seq in 0..3 {
        assert_eq!(read(&mut w, &mut f, 20 + seq, &parent), 0, "the parent's {} left", 3 - seq);
    }
    assert_eq!(read(&mut w, &mut f, 30, &parent), refused, "five in all");
    assert_eq!(w.b.svc.borrow().reads, 5);
}

/// **A spent budget survives the warrant cache being full, and a budget that
/// cannot be counted is refused.** Evicting a warrant (sixteen caveat sets,
/// then one more) must not give its token a fresh count; with every budget
/// slot taken a token with a new `QUOTA` is refused, and one use is taken from
/// all of its budgets or from none.
///
/// **Canary.** Count the quota in the warrant again (derive with a `QUOTA`):
/// the evicted token's warrant is derived anew with a fresh count (red). Evict
/// a spent entry for room in `Session::spend`: the spent token runs (red).
/// Take the uses before looking for room: the failed two-budget call spends
/// the first (red).
#[test]
fn a_spent_budget_outlives_the_warrant_cache_and_the_table_refuses_what_it_cannot_count() {
    let (mut w, mut f) = session();
    let refused = IdlError::Refused.status();
    let q = |n| Caveat::new(cav::QUOTA, n);
    let mut seq = 10;
    let mut go = |w: &mut World, f: &mut Forger, c: &[Caveat]| {
        seq += 1;
        read(w, f, seq, c)
    };
    assert_eq!(go(&mut w, &mut f, &[q(1)]), 0);
    assert_eq!(go(&mut w, &mut f, &[q(1)]), refused);
    // Sixteen other caveat sets take every warrant slot: the quota token's goes.
    for k in 0..WARRANTS_MAX as u64 {
        assert_eq!(go(&mut w, &mut f, &[Caveat::new(cav::RECEIPT, 0x0103_0000_0000_0000 | k)]), 0, "set {k}");
        w.advance(MS);
    }
    assert!(w.b.st.borrow().derives.len() > WARRANTS_MAX);
    assert_eq!(go(&mut w, &mut f, &[q(1)]), refused, "evicted, still spent");
    // Fill the budget table (the spent one holds a slot), then a new quota.
    assert_eq!(go(&mut w, &mut f, &[q(2)]), 0, "one of two");
    for k in 0..QUOTAS_MAX as u64 - 2 {
        assert_eq!(go(&mut w, &mut f, &[q(100 + k)]), 0, "budget {k}");
    }
    assert_eq!(go(&mut w, &mut f, &[q(999)]), refused, "no room to count it");
    assert_eq!(go(&mut w, &mut f, &[q(2), q(7)]), refused, "a new budget behind a known one");
    assert_eq!(go(&mut w, &mut f, &[q(1)]), refused, "and the table evicted nothing");
    let before = w.b.svc.borrow().reads;
    assert_eq!(go(&mut w, &mut f, &[q(2)]), 0, "the failed call took no use from q(2)");
    assert_eq!(go(&mut w, &mut f, &[q(2)]), refused);
    assert_eq!(w.b.svc.borrow().reads, before + 1);
}

/// **A warrant that outlives the token is not used for it.** A token with the
/// same caveats and an earlier `EXPIRY` than the cached warrant's gets a
/// warrant of its own, lapsing at the token's; a token that lapses later (or
/// never) is served by the earlier one.
///
/// **Canary.** Drop the `outlives` test from `Rpc::warrant_slot`: the short
/// token finds the long warrant, one derive, red.
#[test]
fn a_warrant_that_outlives_the_token_is_a_miss() {
    let (mut w, mut f) = session();
    let ttl = 10_000 * MS;
    let expiry = |e| [Caveat::new(cav::EXPIRY, e)];
    let t0 = w.b.st.borrow().now();
    assert_eq!(read(&mut w, &mut f, 10, &[]), 0, "no EXPIRY: the TTL");
    assert_eq!(read(&mut w, &mut f, 11, &expiry(4_000 * MS)), 0);
    {
        let st = w.b.st.borrow();
        assert_eq!(st.derives.len(), 2, "the short token did not take the long warrant");
        assert_eq!((st.derives[0].4, st.derives[1].4), (t0 + ttl, t0 + 4_000 * MS));
    }
    assert_eq!(read(&mut w, &mut f, 12, &expiry(6_000 * MS)), 0, "later than the short warrant: served by it");
    assert_eq!(read(&mut w, &mut f, 13, &[]), 0);
    assert_eq!(read(&mut w, &mut f, 14, &expiry(4_000 * MS)), 0);
    assert_eq!(w.b.st.borrow().derives.len(), 2, "every one of them found a warrant");
    assert_eq!(w.b.svc.borrow().reads, 5);
}

/// **A token whose `OP_MASK` (or `DECLASSIFY`) the call could never discharge
/// is refused here, before any derive.** The call names no op, so the kernel's
/// resolve refuses every use of a warrant carrying one; deriving it would
/// leave a dead warrant, and dropping the caveat would serve a call the
/// token's holder was not allowed. The refusal is in the journal, and the
/// session goes on serving other tokens.
///
/// **Canary.** Make `Grant::usable` return `true`: the token is derived with
/// its mask, the fake kernel refuses the use and `derived` has an entry (red);
/// strip the mask from the list instead, and the call runs (red).
#[test]
fn an_op_mask_is_refused_before_a_warrant_is_derived() {
    let (mut w, mut f) = session();
    let refused = IdlError::Refused.status();
    for (seq, c) in [Caveat::new(cav::OP_MASK, 0b11), Caveat::new(cav::DECLASSIFY, 7)].into_iter().enumerate() {
        assert_eq!(read(&mut w, &mut f, 10 + seq as u64, &[c]), refused, "kind {}", c.kind);
        assert_eq!(read(&mut w, &mut f, 20 + seq as u64, &[Caveat::new(cav::QUOTA, 3), c]), refused, "kind {} with a quota", c.kind);
    }
    assert_eq!(w.b.svc.borrow().reads, 0, "nothing ran");
    assert!(w.b.st.borrow().derives.is_empty(), "and nothing was derived");
    // A mask that leaves no op never reached here (`Refusal::NoOps`), and a
    // token without one still runs.
    assert_eq!(read(&mut w, &mut f, 30, &[RECEIPT_X]), 0);
    assert_eq!(w.b.svc.borrow().reads, 1);
}

/// **With every slot of the session taken, a new caveat set closes the warrant
/// that lapses first and runs.** One interface can hold more warrants than it
/// has interfaces; the cache is bounded by `WARRANTS_MAX` per session.
///
/// **Canary.** Make `warrant` return `None` when no slot is free: the
/// seventeenth set is refused (red).
#[test]
fn a_full_cache_closes_the_warrant_that_lapses_first() {
    let (mut w, mut f) = session();
    for k in 0..WARRANTS_MAX as u64 + 1 {
        assert_eq!(read(&mut w, &mut f, 10 + k, &[Caveat::new(cav::RECEIPT, 0x0103_0000_0000_0000 | k)]), 0, "set {k}");
        w.advance(MS);
    }
    let st = w.b.st.borrow();
    assert_eq!(st.derives.len(), WARRANTS_MAX + 1);
    assert_eq!(st.warrants().len(), WARRANTS_MAX, "one closed to make room");
    assert!(st.closed.contains(&st.derives[0].0), "the oldest, which lapses first");
}
