// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Authority across nodes: a revocation that reaches the peers holding what
//! descends from it within a bound.
//!
//! The world is the usual pair: B exports `probe`, A imports it. Revocation
//! starts at B (its export endpoint is withdrawn); the notice, the ack, the
//! resends and the broken session are the engine's, over the in-memory link
//! that can drop a frame. The fake host keeps the objects of each node, so
//! "revoked" is read off the tables. A `Forger` is a peer holding the session
//! key.
//!
//! Canary discipline: every test says which line of `userspace/lib/rpc` to
//! break and which assertion goes red.

use crate::world::*;
use azos_decision::{ProvenanceRecord, Rule, Verdict};
use azos_idl::IdlError;
use azos_rpc::wire::Kind;
use azos_rpc::State;
use std::cell::RefCell;

const ID: u32 = ProbeIdl::ID;

fn up() -> RefCell<World> {
    let w = RefCell::new(World::new());
    w.borrow_mut().establish();
    w
}

/// The records of `rule` in a journal.
fn recs(j: &azos_rpc::journal::Journal, rule: Rule) -> Vec<ProvenanceRecord> {
    j.iter().filter(|r| r.rule == rule as u8).copied().collect()
}

fn is_up(w: &World, a_side: bool) -> bool {
    let s = if a_side { w.a.rpc.session_with(B) } else { w.b.rpc.session_with(A) };
    s.is_some_and(|s| s.state == State::Up)
}

// ── revocation ──────────────────────────────────────────────────────────

/// **A withdrawn export is revoked on the importer and acknowledged**, both
/// sides record it under the same notice, and the session stays up.
///
/// B closes what it lent (its warrants), stops granting `probe` and tells A;
/// A stops offering it to its callers, revokes the object it re-minted from
/// B's reply (closing it, which revokes what hangs from it) and answers.
///
/// **Canaries.** Skip the `offered` removal in `on_revoke`: the call at the
/// end goes through to B and the `offers` assertion goes red. Skip the
/// `close` of the minted objects: the fetched object is
/// still held. Skip `send_notice` in `revoke_export`: no `Revoke` is sent and
/// the A-side assertions go red. Drop the ack's `send_msg`: B never records
/// its side.
#[test]
fn a_withdrawn_export_is_revoked_on_the_importer_and_acked() {
    let w = up();
    let fetched = probe(&w).fetch(100).unwrap().get().expect("lent").raw();
    assert_eq!(probe(&w).read(4), Ok(8));
    {
        let w = w.borrow();
        assert!(!w.b.st.borrow().warrants().is_empty(), "B derived a warrant for A");
        assert!(w.a.st.borrow().objs.contains_key(&fetched), "A holds the object re-minted from the reply");
        assert!(w.a.rpc.session_with(B).unwrap().offers(ID));
    }
    let id = {
        let mut wm = w.borrow_mut();
        let id = wm.b.rpc.session_with(A).unwrap().id;
        wm.b.rpc.revoke_export(ID);
        wm.pump();
        id
    };

    let wb = w.borrow();
    assert_eq!((wb.sent(B, Kind::Revoke), wb.sent(A, Kind::RevokeAck)), (1, 1), "one notice, one ack");
    assert!(is_up(&wb, true) && is_up(&wb, false), "a revocation is not a broken session");
    assert!(!wb.a.rpc.session_with(B).unwrap().offers(ID), "A no longer offers it");
    assert!(!wb.b.rpc.session_with(A).unwrap().grants(ID), "B no longer grants it");
    assert!(wb.b.st.borrow().warrants().is_empty(), "B closed what it lent");
    assert!(!wb.a.st.borrow().objs.contains_key(&fetched), "A revoked the object it re-minted");

    // Both sides record it, under the same notice and session, each naming the other.
    let (ra, rb) = (recs(wb.a.rpc.journal(), Rule::RemoteRevoke), recs(wb.b.rpc.journal(), Rule::RemoteRevoke));
    assert_eq!((ra.len(), rb.len()), (1, 1), "{ra:?} {rb:?}");
    assert_eq!((ra[0].seq, rb[0].seq), (1, 1), "the notice's number");
    assert_eq!((ra[0].session_id, rb[0].session_id), (id as u64, id as u64));
    assert_eq!((ra[0].node_id, rb[0].node_id), (B, A));
    assert_eq!((ra[0].subject, rb[0].subject), (B, A), "the subject of the rule is the node");
    assert_eq!((ra[0].verdict, rb[0].verdict), (Verdict::Admit as u8, Verdict::Admit as u8));
    assert_eq!(ra[0].n, [ID as u64, 1, 1], "A: the interface, the object it revoked, B's epoch");
    assert_eq!(rb[0].n[0], ID as u64);
    assert!(rb[0].n[1] >= 1, "B: the warrants it closed: {:?}", rb[0].n);
    drop(wb);

    // The interface is withdrawn for good on this session: A refuses at once.
    assert_eq!(probe(&w).read(4), Err(IdlError::Refused));
    assert_eq!(w.borrow().sent(A, Kind::Req), 2, "the refused call never crossed");
}

/// A notice only reaches a peer that holds something derived from the
/// withdrawn authority: the interface it was granted. A peer the interface
/// was never granted to is not told. **Canary.** Drop the `grants(iface)`
/// test in `revoke_export`: a notice goes to every session and this goes red.
#[test]
fn only_the_peers_that_hold_the_interface_are_told() {
    let mut w = World::new();
    w.establish();
    // A grants nothing to B (it exports nothing), so A has nobody to tell.
    w.a.rpc.revoke_export(ID);
    w.pump();
    assert_eq!(w.sent(A, Kind::Revoke), 0);
    // An interface nobody was granted.
    w.b.rpc.revoke_export(ID + 1);
    w.pump();
    assert_eq!(w.sent(B, Kind::Revoke), 0);
    assert!(is_up(&w, true) && is_up(&w, false));
}

/// **A peer that cannot ack within the bound has its session broken**, which
/// revokes everything minted over it. The notice is resent every `rto` until
/// then; the session is up one tick before the bound and gone one tick after;
/// and the record on the withdrawing side says the revocation was not
/// confirmed. With the whole link cut the notice never arrives, with only the
/// answer lost it does: either way the withdrawer cannot know, and acts alike.
///
/// **Canaries.** Never compare against the bound in `chase_notices`: the
/// session is still up at the end. Compare against `0`: it breaks at the first
/// tick, and the "still up" assertion goes red. Skip the resend: the count of
/// `Revoke` frames stays 1.
#[test]
fn a_peer_that_cannot_ack_within_the_bound_has_its_session_broken() {
    for cut_everything in [true, false] {
        let mut w = World::new();
        w.establish();
        probe_read_once(&mut w);
        w.b.rpc.set_revoke_bound(500 * MS);
        if cut_everything {
            w.rule(|_| Fate::Drop);
        } else {
            w.rule(|s| if s.kind == Kind::RevokeAck { Fate::Drop } else { Fate::Deliver });
        }
        let id = w.b.rpc.session_with(A).unwrap().id;
        w.b.rpc.revoke_export(ID);
        w.pump();
        assert!(w.b.st.borrow().warrants().is_empty(), "B closes its own side at once, whatever the link does");

        w.run_for(490 * MS);
        assert!(is_up(&w, false), "cut_everything={cut_everything}: the bound has not run out");
        assert!(w.sent(B, Kind::Revoke) >= 4, "resent every rto: {}", w.sent(B, Kind::Revoke));
        assert_eq!(w.sent(B, Kind::Bye), 0);
        w.run_for(20 * MS);
        // (With the link alive A redials at once; the session B had is the one that is gone.)
        let gone = w.b.rpc.session_with(A).is_none_or(|s| s.state != State::Up || s.id != id);
        assert!(gone, "cut_everything={cut_everything}: broken at the bound");
        assert_eq!(w.sent(B, Kind::Bye), 1, "B tells A, in case the link carries that");

        let rb = recs(w.b.rpc.journal(), Rule::RemoteRevoke);
        assert_eq!(rb.len(), 1);
        assert_eq!((rb[0].verdict, rb[0].seq, rb[0].session_id), (Verdict::Refuse as u8, 1, id as u64), "unconfirmed");
        assert_eq!(recs(w.b.rpc.journal(), Rule::CapRevoke).len(), 1, "and the break revoked what was minted");
        // A's side: with the link cut it never heard; with the ack lost it did.
        let ra = recs(w.a.rpc.journal(), Rule::RemoteRevoke);
        assert_eq!(ra.len(), usize::from(!cut_everything), "cut_everything={cut_everything}");
    }
}

/// With the bound very long, a cut link is held by the probes instead: the
/// session is still up well past the default patience, and the notice keeps
/// being resent. **Canary.** Use `rto * (retries + 1)` always in
/// `revoke_bound`: the session is gone at 400 ms and this goes red.
#[test]
fn the_bound_is_the_configured_one() {
    let mut w = World::new();
    w.establish();
    w.b.rpc.set_revoke_bound(60_000 * MS);
    w.rule(|s| if s.from == A { Fate::Drop } else { Fate::Deliver });
    w.b.rpc.revoke_export(ID);
    w.run_for(2_500 * MS);
    assert!(is_up(&w, false), "a bound of a minute, a link cut for 2.5 s: still up");
    assert!(w.sent(B, Kind::Revoke) > 20);
}

/// Unset, the bound is the patience of a call: `rto * (retries + 1)`
/// (400 ms in this world).
#[test]
fn unset_the_bound_is_the_patience_of_a_call() {
    let mut w = World::new();
    w.establish();
    w.rule(|s| if s.from == A { Fate::Drop } else { Fate::Deliver });
    w.b.rpc.revoke_export(ID);
    w.run_for(390 * MS);
    assert!(is_up(&w, false));
    w.run_for(30 * MS);
    assert!(!is_up(&w, false));
}

/// A lost ack costs a resend, not a second revocation: A processes the repeat,
/// finds nothing left, answers again and records nothing more; B sees the ack
/// and the session stands. **Canary.** Record on every notice in `on_revoke`
/// (drop the `held || closed > 0` test): A has two records.
#[test]
fn a_lost_ack_is_resent_and_the_repeat_changes_nothing() {
    let mut w = World::new();
    w.establish();
    probe_read_once(&mut w);
    let mut dropped = false;
    w.rule(move |s| {
        if s.kind == Kind::RevokeAck && !dropped {
            dropped = true;
            Fate::Drop
        } else {
            Fate::Deliver
        }
    });
    w.b.rpc.revoke_export(ID);
    w.pump();
    w.run_for(300 * MS);
    assert!(is_up(&w, false) && is_up(&w, true));
    assert_eq!(w.sent(A, Kind::RevokeAck), 2, "answered twice");
    assert_eq!(w.sent(B, Kind::Revoke), 2, "resent once");
    assert_eq!(recs(w.a.rpc.journal(), Rule::RemoteRevoke).len(), 1, "the repeat recorded nothing");
    let rb = recs(w.b.rpc.journal(), Rule::RemoteRevoke);
    assert_eq!((rb.len(), rb[0].verdict), (1, Verdict::Admit as u8), "B was confirmed");
    w.run_for(2_000 * MS);
    assert!(is_up(&w, false), "and nothing breaks later");
}

/// An ack nobody asked for (another notice number, another interface) clears
/// nothing: the notice is still pending and the bound still runs. **Canary.**
/// Match the ack by session alone in `on_revoke_ack`: the forged ack clears it
/// and the session is still up at the end.
#[test]
fn an_ack_that_is_not_for_the_pending_notice_does_not_clear_it() {
    let mut w = World::new();
    let mut f = Forger::dial(&mut w, A);
    w.b.rpc.set_revoke_bound(300 * MS);
    w.b.rpc.revoke_export(ID);
    let (h, body) = f.answer(&mut w).expect("the notice");
    assert_eq!((h.kind, h.seq, body), (Kind::Revoke, 1, ID.to_le_bytes().to_vec()));
    for (seq, iface) in [(2u64, ID), (1, ID + 1), (7, 0)] {
        let frames = f.seal(Kind::RevokeAck, seq, &iface.to_le_bytes());
        f.send(&mut w, &frames);
    }
    // A short body is not an ack either.
    let frames = f.seal(Kind::RevokeAck, 1, &[1, 0]);
    f.send(&mut w, &frames);
    assert!(w.b.rpc.session_with(A).is_some_and(|s| s.state == State::Up));
    tick_b_for(&mut w, 320 * MS);
    assert!(w.b.rpc.session_with(A).is_none_or(|s| s.state != State::Up), "none of them cleared it");
    // The right one does.
    let mut w = World::new();
    let mut f = Forger::dial(&mut w, A);
    w.b.rpc.set_revoke_bound(300 * MS);
    w.b.rpc.revoke_export(ID);
    f.answer(&mut w).expect("the notice");
    let frames = f.seal(Kind::RevokeAck, 1, &ID.to_le_bytes());
    f.send(&mut w, &frames);
    tick_b_for(&mut w, 320 * MS);
    assert!(w.b.rpc.session_with(A).is_some_and(|s| s.state == State::Up), "the right ack cleared it");
    assert_eq!(recs(w.b.rpc.journal(), Rule::RemoteRevoke).len(), 1);
}

/// **The engine finds a withdrawn export itself.** The endpoint behind it is
/// closed while the session is up: the housekeeping tick notices, withdraws the
/// interface and tells A, with nobody calling `revoke_export`.
///
/// **Canary.** Drop `check_exports` from `tick`: nothing is sent and the
/// assertions go red.
#[test]
fn the_tick_finds_a_closed_endpoint() {
    let mut w = World::new();
    w.establish();
    close_export(&w);
    w.run_for(30 * MS);
    assert_eq!(w.sent(B, Kind::Revoke), 1);
    assert!(!w.a.rpc.session_with(B).unwrap().offers(ID));
    assert!(is_up(&w, true) && is_up(&w, false));
    // Once told, it is not told again.
    w.run_for(3_000 * MS);
    assert_eq!(w.sent(B, Kind::Revoke), 1);
}

/// **A request that finds the endpoint gone withdraws the export**, and is
/// refused. **Canary.** Drop the `revoke_export` in `serve_req`'s missing
/// endpoint arm: the call is refused but no notice is sent.
#[test]
fn a_request_for_a_closed_endpoint_withdraws_the_export() {
    let w = up();
    close_export(&w.borrow());
    assert_eq!(probe(&w).read(4), Err(IdlError::Refused));
    w.borrow_mut().pump();
    let w = w.borrow();
    assert_eq!(w.sent(B, Kind::Revoke), 1);
    assert!(!w.a.rpc.session_with(B).unwrap().offers(ID), "A was told");
    assert!(!w.b.rpc.session_with(A).unwrap().grants(ID));
}

/// **A derive the kernel refuses as stale withdraws the export too**: the
/// endpoint handle is held but its capability lapsed (revoked from above).
/// **Canary.** Treat every derive failure alike in `warrant`: a transient
/// `EPERM` withdraws too, and the second half goes red.
#[test]
fn a_stale_endpoint_capability_withdraws_the_export() {
    let w = up();
    {
        let w = w.borrow();
        let mut st = w.b.st.borrow_mut();
        let root = st.eps[&PROBE_INDEX];
        let Some(Obj::Ep { expiry, .. }) = st.objs.get_mut(&root) else { panic!() };
        *expiry = 1; // lapsed: the derive answers ECAPSTALE
    }
    assert_eq!(probe(&w).read(4), Err(IdlError::Refused));
    w.borrow_mut().pump();
    {
        let w = w.borrow();
        assert_eq!(w.sent(B, Kind::Revoke), 1);
        assert!(!w.a.rpc.session_with(B).unwrap().offers(ID));
    }
    // A derive that fails for another reason (the source cannot be duplicated)
    // refuses the call and withdraws nothing.
    let w = up();
    {
        let w = w.borrow();
        let mut st = w.b.st.borrow_mut();
        let root = st.eps[&PROBE_INDEX];
        let Some(Obj::Ep { rights, .. }) = st.objs.get_mut(&root) else { panic!() };
        *rights = azos_abi::cap::CapPerms::WRITE.bits() as u16; // no DUP: EPERM
    }
    assert_eq!(probe(&w).read(4), Err(IdlError::Refused));
    assert_eq!(w.borrow().sent(B, Kind::Revoke), 0);
    assert!(w.borrow().a.rpc.session_with(B).unwrap().offers(ID));
}

/// A notice that is not well formed, or names the zero interface, changes
/// nothing and is not answered. **Canary.** Parse the body loosely (accept a
/// longer one, or accept 0) in `on_revoke`: A answers and the count goes red.
#[test]
fn a_malformed_notice_is_ignored() {
    let mut w = World::new();
    let mut f = Forger::dial(&mut w, A);
    // B is the one that serves; the forger plays the exporter's role towards B
    // only for the frame shapes: B must not act on what does not parse.
    for body in [vec![], vec![1, 0, 0], ID.to_le_bytes().iter().copied().chain([0u8]).collect(), vec![0, 0, 0, 0]] {
        let frames = f.seal(Kind::Revoke, 9, &body);
        f.send(&mut w, &frames);
        assert!(f.answer(&mut w).is_none(), "no answer to {body:?}");
    }
    assert!(w.b.rpc.session_with(A).is_some_and(|s| s.state == State::Up));
}


// ── helpers ─────────────────────────────────────────────────────────────

/// One call, so B holds a warrant for A's session.
fn probe_read_once(w: &mut World) {
    let mut m = raw_req(ID, ProbeIdl::OP_READ, &[2]);
    w.call_a(&mut m);
    assert_eq!(m.words[0], 0, "the read was served");
}

/// B's endpoint behind the export is closed (the real service goes on).
fn close_export(w: &World) {
    let mut st = w.b.st.borrow_mut();
    let root = st.eps.remove(&PROBE_INDEX).expect("B holds the export");
    st.close_tree(root);
}

/// Run B alone for `ns`, ticking every 10 ms and delivering frames: for the
/// tests whose peer is a `Forger`, which A's own engine would replace.
fn tick_b_for(w: &mut World, ns: u64) {
    let mut left = ns;
    while left > 0 {
        let step = (10 * MS).min(left);
        w.advance(step);
        left -= step;
        w.b.rpc.tick();
        w.pump();
    }
}
