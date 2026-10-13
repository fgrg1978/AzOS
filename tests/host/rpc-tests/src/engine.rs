// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The engine, two servers at a time.
//!
//! Canary discipline: every test says which line of `userspace/lib/rpc` to
//! break and which assertion goes red.

use crate::world::*;
use azos_abi::cap::CapPerms;
use azos_abi::ipc_msg::{CapDesc, MsgDesc, CAP_MODE_DUP};
use azos_decision::{ProvenanceRecord, Rule};
use azos_idl::{Cap, IdlError};
use azos_rpc::wire::{frags_for, get_desc, get_header, put_desc, put_header, Header, Kind, FRAG_BODY, HEADER_BYTES};
use azos_rpc::State;
use std::cell::RefCell;

fn up() -> RefCell<World> {
    let w = RefCell::new(World::new());
    w.borrow_mut().establish();
    w
}

fn sid(w: &RefCell<World>) -> u32 {
    let w = w.borrow();
    let (a, b) = (w.a.rpc.session_with(B).unwrap().id, w.b.rpc.session_with(A).unwrap().id);
    assert_eq!(a, b, "both nodes name the session alike");
    a
}

/// The records of `rule` in a journal.
fn recs(j: &azos_rpc::journal::Journal, rule: Rule) -> Vec<ProvenanceRecord> {
    j.iter().filter(|r| r.rule == rule as u8).copied().collect()
}

/// A request frame as A would send it on session `id`, number `seq`, split
/// into frames: for what no stub would send.
fn forged(id: u32, seq: u64, body: &[u8]) -> Vec<Vec<u8>> {
    let cnt = frags_for(body.len());
    (0..cnt)
        .map(|i| {
            let (lo, hi) = (i * FRAG_BODY, ((i + 1) * FRAG_BODY).min(body.len()));
            let mut h = Header::new(Kind::Req, id, seq, A, 1);
            h.frag_idx = i as u16;
            h.frag_cnt = cnt as u16;
            let mut f = vec![0u8; HEADER_BYTES + hi - lo];
            put_header(&h, &mut f);
            f[HEADER_BYTES..].copy_from_slice(&body[lo..hi]);
            f
        })
        .collect()
}

fn forged_desc(id: u32, seq: u64, d: &MsgDesc) -> Vec<Vec<u8>> {
    let mut body = vec![0u8; 512];
    let mut at = 0;
    put_desc(d, &mut body, &mut at).unwrap();
    forged(id, seq, &body[..at])
}

/// Feed `frames` to B and take the first status word of the answer it queued.
fn status_from_b(w: &mut World, frames: &[Vec<u8>]) -> u64 {
    let World { b, net, .. } = w;
    for f in frames {
        b.rpc.on_frame(&mut b.asm, f);
    }
    let rep = net.borrow_mut().q[0].pop_front().expect("an answer");
    let (h, body) = get_header(&rep).unwrap();
    assert_eq!(h.kind, Kind::Rep);
    get_desc(body, &mut 0).unwrap().words[0]
}

/// **A call crosses as the IDL stub made it and comes back as the real service
/// answered it**, for each delivery attribute, with the session numbered the
/// same on both nodes.
///
/// **Canaries.** Make `serve_req` answer `put_status(Refused)` always: every
/// `Ok` goes red. Send the reply with the wrong `seq`: `on_rep` drops it and
/// the call never finishes (the harness panics).
#[test]
fn a_call_crosses_as_the_stub_made_it_and_comes_back() {
    let w = up();
    let mut c = probe(&w);
    assert_eq!(c.read(21), Ok(42));
    assert_eq!(c.bump(5), Ok(5));
    assert_eq!(c.bump(2), Ok(7));
    assert_eq!(c.fire(3), Ok(3));
    let w = w.borrow();
    let svc = w.b.svc.borrow();
    assert_eq!((svc.reads, svc.counter, svc.fired), (1, 7, 3), "each ran once");
    // The service was reached through a warrant, with the session as its badge.
    assert!(w.b.st.borrow().calls.iter().all(|c| c.badge != 0));
}

/// **The lower node id dials, the higher answers**: two nodes never make two
/// sessions.
///
/// **Canary.** Drop the `self.cfg.node >= peer` test of `connect`: both dial
/// and the Hello count of B goes non-zero.
#[test]
fn the_lower_node_dials_and_only_the_higher_answers() {
    let mut w = World::new();
    for _ in 0..5 {
        w.tick();
        w.pump();
        w.advance(110 * MS);
    }
    assert_eq!(w.sent(A, Kind::Hello), 1);
    assert_eq!(w.sent(B, Kind::Hello), 0, "the higher node never dials");
    assert_eq!(w.sent(B, Kind::HelloAck), 1);
    assert_eq!(w.a.rpc.session_with(B).unwrap().state, State::Up);
    assert_eq!(w.b.rpc.session_with(A).unwrap().state, State::Up);
}

/// A Hello from a node no peer class lists is not answered.
///
/// **Canary.** Drop the `class_of` check of `on_hello`: the unknown node gets
/// a session and the assertion goes red.
#[test]
fn a_hello_from_a_stranger_is_not_answered() {
    let mut w = World::with("peer fleet 2\n", "peer fleet 3\nexport probe 7 fleet\n");
    for _ in 0..5 {
        w.tick();
        w.pump();
        w.advance(110 * MS);
    }
    assert!(w.b.rpc.session_with(A).is_none(), "node 1 is in no class of B's");
    assert_eq!(w.sent(B, Kind::HelloAck), 0);
    assert!(w.b.st.borrow().log.contains("no peer class lists"));
}

/// **Export is the only way out.** A node whose class has no export line gets
/// `Refused` from its own server, and so does a request forged past it: the
/// exporting node checks again, answers `Refused`, runs nothing and writes a
/// provenance record of the refusal.
///
/// **Canaries.** Drop the `grants(id)` filter of `serve_req`: the forged
/// request runs and the service count goes red. Make `begin` answer
/// `NoConnection` when every peer is up: the first assertion goes red.
#[test]
fn nothing_leaves_a_node_except_through_an_export_to_the_callers_class() {
    // B exports nothing to anyone.
    let w = RefCell::new(World::with(POLICY_A, "peer fleet 1\n"));
    w.borrow_mut().establish();
    assert_eq!(probe(&w).read(1), Err(IdlError::Refused));
    assert_eq!(w.borrow().sent(A, Kind::Req), 0, "refused before it crossed");

    // B exports it to another class: the node is in `lab`, the export is to `fleet`.
    let w = RefCell::new(World::with(POLICY_A, "peer lab 1\nexport probe 7 fleet\n"));
    w.borrow_mut().establish();
    assert_eq!(probe(&w).read(1), Err(IdlError::Refused));

    // A forged request, built by hand with the session's own numbers.
    let mut wb = w.borrow_mut();
    let id = wb.a.rpc.session_with(B).unwrap().id;
    let st = status_from_b(&mut wb, &forged_desc(id, 1, &raw_req(ProbeIdl::ID, ProbeIdl::OP_READ, &[5])));
    assert_eq!(st, IdlError::Refused.status());
    assert_eq!(wb.b.svc.borrow().reads, 0, "nothing ran");
    let refused = recs(wb.b.rpc.journal(), Rule::CapDenial);
    assert_eq!(refused.len(), 1);
    assert_eq!((refused[0].node_id, refused[0].session_id), (A, id as u64));
}

/// **The warrant is a child of the exported endpoint**, attenuated to the call
/// right (no `DUP`: the service cannot pass it on), badged with the session,
/// expiring at the TTL; one per session and interface, reused by the next call.
///
/// **Canaries.** Derive with `CapPerms::ALL` rights: the rights assertion goes
/// red. Pass `expiry` 0: the expiry assertion goes red. Derive on every call:
/// the "one warrant" assertion goes red.
#[test]
fn the_warrant_is_attenuated_badged_expiring_and_a_child_of_the_export() {
    let w = up();
    assert_eq!(probe(&w).read(1), Ok(2));
    assert_eq!(probe(&w).read(2), Ok(4));
    let id = sid(&w);
    let w = w.borrow();
    let b = w.b.st.borrow();
    assert_eq!(b.derives.len(), 1, "one warrant, reused");
    let (h, parent, rights, badge, expiry) = b.derives[0];
    let root = b.eps[&PROBE_INDEX];
    assert_eq!(parent, root, "a child of B's own capability on the endpoint");
    assert_eq!(rights, CapPerms::WRITE.bits() as u16, "the call right and nothing else");
    assert_eq!(badge, id, "the session is the badge");
    assert!(expiry > b.now() && expiry <= b.now() + 10_000 * MS, "lapses within the TTL");
    assert!(b.calls.iter().all(|c| c.badge == id));
    assert!(b.warrants().contains(&h));
}

/// **A warrant is renewed before it lapses, and a lapse under the call is
/// survived once**: the old one is closed, a new one derived, the call retried
/// with the same request.
///
/// **Canaries.** Never renew: the second assertion goes red (one derive).
/// Skip the retry after `-EPERM`: the lapse call answers `Refused`.
#[test]
fn a_warrant_is_renewed_and_a_lapse_under_the_call_is_survived() {
    let w = up();
    assert_eq!(probe(&w).read(1), Ok(2));
    let first = w.borrow().b.st.borrow().derives[0].0;
    // Past three quarters of its life: the next call derives a fresh one.
    w.borrow_mut().run_for(8_000 * MS);
    assert_eq!(probe(&w).read(2), Ok(4));
    {
        let w = w.borrow();
        let b = w.b.st.borrow();
        assert_eq!(b.derives.len(), 2, "renewed");
        assert!(!b.objs.contains_key(&first), "the old warrant was closed");
        assert_eq!(b.warrants().len(), 1);
    }
    // The warrant lapses under the call (the kernel says -EPERM once).
    w.borrow().b.st.borrow_mut().lapse_once = true;
    assert_eq!(probe(&w).read(3), Ok(6));
    assert_eq!(w.borrow().b.st.borrow().derives.len(), 3, "a fresh warrant for the retry");
    assert_eq!(w.borrow().b.svc.borrow().reads, 3);
}

/// A warrant that nobody used lapses and is swept.
///
/// **Canary.** Skip `sweep`: the closed list stays empty and the assertion
/// goes red.
#[test]
fn a_lapsed_warrant_is_swept() {
    let w = up();
    assert_eq!(probe(&w).read(1), Ok(2));
    let first = w.borrow().b.st.borrow().derives[0].0;
    w.borrow_mut().run_for(11_000 * MS);
    let w2 = w.borrow();
    assert!(w2.b.st.borrow().closed.contains(&first));
    assert!(w2.b.st.borrow().warrants().is_empty());
}

/// **A broken session revokes everything minted over it, on both nodes,** and
/// the calls waiting on it are told `NoConnection`.
///
/// Built up: B holds a warrant and a re-minted object (and the copy lent to the
/// service); A holds an object re-minted from a reply. The link dies; three
/// `NoConnection`s in a row break the session on A, which sends a Bye (lost),
/// and B's own probes give up too.
///
/// **Canaries.** Skip the warrant loop of `break_session`: B's warrant
/// assertion goes red. Skip the `minted` loop: the object assertions go red.
#[test]
fn a_broken_session_revokes_everything_minted_over_it() {
    let w = up();
    let id = sid(&w);
    let data: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
    let mem = w.borrow_mut().a_mem(data.clone());
    assert_eq!(probe(&w).store(Cap::from_raw(mem)), Ok(data.iter().map(|&b| b as u32).sum()));
    let fetched = probe(&w).fetch(100).unwrap().get().expect("lent").raw();
    let b_before = {
        let w = w.borrow();
        let b = w.b.st.borrow();
        assert_eq!(b.warrants().len(), 1);
        let derived_mems: Vec<u32> = b.mems().into_iter().filter(|m| matches!(b.objs[m], Obj::Mem { parent: Some(_), .. }) || true).collect();
        assert!(derived_mems.len() >= 2, "the re-minted pages and the copy lent to the service: {derived_mems:?}");
        assert!(w.a.st.borrow().objs.contains_key(&fetched), "A holds the object re-minted from the reply");
        (b.warrants(), derived_mems)
    };

    // The link dies. Three calls in a row get no answer.
    w.borrow().rule(|_| Fate::Drop);
    for n in 0..3 {
        assert_eq!(probe(&w).read(n), Err(IdlError::NoConnection), "call {n}");
    }
    assert!(w.borrow().a.rpc.session_with(B).is_none_or(|s| s.state != State::Up), "A broke the session");
    // B's probes go unanswered too.
    w.borrow_mut().run_for(8_000 * MS);
    {
        let wb = w.borrow();
        assert!(wb.b.rpc.session_with(A).is_none(), "B broke its side");
        let b = wb.b.st.borrow();
        assert!(b.warrants().is_empty(), "B's warrant is gone");
        // What the session minted on B is closed: the copy lent to the service is
        // gone with its parent; only an object the service made itself remains.
        for m in &b_before.1 {
            if let Some(Obj::Mem { parent, .. }) = b.objs.get(m) {
                assert!(parent.is_none(), "a derived copy outlived the session: {m}");
            }
        }
        assert!(!wb.a.st.borrow().objs.contains_key(&fetched), "A's re-minted object is closed");
        // Both journals say so, under the same session id.
        let (ra, rb) = (recs(wb.a.rpc.journal(), Rule::CapRevoke), recs(wb.b.rpc.journal(), Rule::CapRevoke));
        assert_eq!((ra.len(), rb.len()), (1, 1));
        assert_eq!((ra[0].session_id, rb[0].session_id), (id as u64, id as u64));
        assert_eq!((ra[0].node_id, rb[0].node_id), (B, A), "each names the other");
        assert!(rb[0].n[2] >= 2, "B revoked its warrant and the pages: {:?}", rb[0].n);
        assert_eq!(ra[0].n[2], 1, "A revoked the object it had re-minted");
    }

    // The link heals: A dials again, a new session, and the old warrant stays dead.
    w.borrow().heal();
    w.borrow_mut().run_for(1_000 * MS);
    let id2 = sid(&w);
    assert_ne!(id, id2);
    assert_eq!(probe(&w).read(4), Ok(8));
    assert_ne!(w.borrow().b.st.borrow().derives.last().unwrap().0, b_before.0[0]);
}

/// A silent peer is probed, and broken after `miss_limit` probes go
/// unanswered; a peer that answers is not.
///
/// **Canary.** Never reset `misses`: a quiet but live link breaks (the first
/// half goes red). Never increment it: the second half goes red.
#[test]
fn a_silent_peer_is_probed_and_then_broken() {
    let mut w = World::new();
    w.establish();
    // Quiet but alive: no break over a minute.
    w.run_for(60_000 * MS);
    assert!(w.a.rpc.session_with(B).is_some_and(|s| s.state == State::Up));
    assert!(w.sent(A, Kind::Ping) > 10, "probes went out");
    // Silent.
    w.rule(|_| Fate::Drop);
    w.run_for(10_000 * MS);
    assert!(w.a.rpc.session_with(B).is_none_or(|s| s.state != State::Up), "A gave up on it (and is dialing again)");
    assert!(w.b.rpc.session_with(A).is_none(), "and so did B");
}

/// **`NoConnection` is not `PeerDied`.** A dead link is the first, a dead far
/// server the second; the stub tells them apart and the link stays up for the
/// second.
///
/// **Canaries.** Map `EPEERDIED` to `NoConnection` in `serve_req`: the first
/// assertion goes red. Report a lost answer as `PeerDied`: the last goes red.
#[test]
fn no_connection_is_not_peer_died() {
    let w = up();
    w.borrow().b.st.borrow_mut().dead = true;
    assert_eq!(probe(&w).read(1), Err(IdlError::PeerDied));
    assert!(w.borrow().a.rpc.session_with(B).is_some_and(|s| s.state == State::Up), "the link is fine");
    w.borrow().b.st.borrow_mut().dead = false;
    assert_eq!(probe(&w).read(1), Ok(2));
    w.borrow().rule(|_| Fate::Drop);
    assert_eq!(probe(&w).read(1), Err(IdlError::NoConnection));
    assert_ne!(IdlError::NoConnection, IdlError::PeerDied);
}

/// **`once_only` is sent once and never retried**: the answer is lost, the
/// request crossed once, the service ran once, and the caller is told the
/// outcome is unknown. A duplicate datagram does not run it twice either.
///
/// **Canaries.** Resend on timeout for every delivery in `poll`: the Req count
/// goes red. Skip the dedupe for `OnceOnly`: the duplicate-datagram part goes red.
#[test]
fn once_only_is_sent_once_and_never_retried() {
    let w = up();
    // The answer to the request is lost.
    w.borrow().rule(|s| if s.kind == Kind::Rep { Fate::Drop } else { Fate::Deliver });
    assert_eq!(probe(&w).fire(1), Err(IdlError::NoConnection));
    assert_eq!(w.borrow().sent(A, Kind::Req), 1, "one transmission, however long it waited");
    assert_eq!(w.borrow().b.svc.borrow().fired, 1, "the service ran");
    // The link repeats a request: still once.
    w.borrow().rule(|s| if s.kind == Kind::Req { Fate::Dup } else { Fate::Deliver });
    assert_eq!(probe(&w).fire(1), Ok(2));
    assert_eq!(w.borrow().b.svc.borrow().fired, 2, "the duplicate was answered, not run");
}

/// **`at_most_once` is resent with the same number and runs once**: the first
/// answers are lost, the resend is answered from the window.
///
/// **Canaries.** Skip `dedupe.record`: the counter reaches 9 and the first
/// assertion goes red. Number the resend anew: same.
#[test]
fn at_most_once_is_resent_and_runs_once() {
    let w = up();
    let mut dropped = 0;
    w.borrow().rule(move |s| {
        if s.kind == Kind::Rep && dropped < 2 {
            dropped += 1;
            Fate::Drop
        } else {
            Fate::Deliver
        }
    });
    assert_eq!(probe(&w).bump(3), Ok(3), "the answer of the first run, found in the window");
    assert_eq!(w.borrow().b.svc.borrow().counter, 3, "it ran once");
    assert!(w.borrow().sent(A, Kind::Req) >= 3, "resent");
    assert_eq!(probe(&w).bump(3), Ok(6));
}

/// What the window can no longer tell, it says so: a call number pushed out
/// is `NoConnection`, not a second run.
///
/// **Canary.** Treat `Unknown` as `Fresh`: the replay runs and the counter
/// goes red.
#[test]
fn a_replay_the_window_forgot_is_not_run_again() {
    let w = up();
    for _ in 0..6 {
        assert!(probe(&w).bump(1).is_ok());
    }
    assert_eq!(w.borrow().b.svc.borrow().counter, 6);
    // The first call's number is long out of the 4-entry window: replay it by hand.
    let mut wb = w.borrow_mut();
    let id = wb.a.rpc.session_with(B).unwrap().id;
    let st = status_from_b(&mut wb, &forged_desc(id, 1, &raw_req(ProbeIdl::ID, ProbeIdl::OP_BUMP, &[1])));
    assert_eq!(st, IdlError::NoConnection.status());
    assert_eq!(wb.b.svc.borrow().counter, 6, "not run again");
}

/// **`idempotent` is resent until answered**: the first two requests are lost.
///
/// **Canary.** Resend only `AtMostOnce`: the call gives up and the assertion
/// goes red.
#[test]
fn idempotent_is_resent_until_answered() {
    let w = up();
    let mut dropped = 0;
    w.borrow().rule(move |s| {
        if s.kind == Kind::Req && dropped < 2 {
            dropped += 1;
            Fate::Drop
        } else {
            Fate::Deliver
        }
    });
    assert_eq!(probe(&w).read(9), Ok(18));
    assert_eq!(w.borrow().sent(A, Kind::Req), 3);
    assert_eq!(w.borrow().b.svc.borrow().reads, 1);
}

/// An op that declares nothing crosses no link; an interface or op the server
/// does not carry is named for what it is.
///
/// **Canary.** Treat `delivery() == None` as idempotent: the first assertion
/// goes red (it would be sent).
#[test]
fn an_op_that_declares_nothing_crosses_no_link() {
    let w = up();
    assert_eq!(probe(&w).plain(1), Err(IdlError::Refused));
    assert_eq!(w.borrow().sent(A, Kind::Req), 0);
    let mut m = raw_req(0x1234_5678, 1, &[]);
    w.borrow_mut().call_a(&mut m);
    assert_eq!(m.words[0], IdlError::BadInterface.status());
    let mut m = raw_req(ProbeIdl::ID, 99, &[]);
    w.borrow_mut().call_a(&mut m);
    assert_eq!(m.words[0], IdlError::BadOp.status());
    let mut m = MsgDesc { version: 1, ..MsgDesc::default() };
    w.borrow_mut().call_a(&mut m);
    assert_eq!(m.words[0], IdlError::Malformed.status(), "an empty message has no header");
    assert_eq!(w.borrow().sent(A, Kind::Req), 0);
}

/// **A deadline crosses as the time remaining, on the clock class it was set
/// on, and the far node anchors it on its own clock** (which is a thousand
/// seconds ahead). One already passed is refused before anything is sent; one
/// that passes while waiting ends the call.
///
/// **Canaries.** Send the absolute deadline: the far node sees a deadline
/// 1000 s from its own and the first assertion goes red. Do not recompute
/// the remaining time on a resend: the last assertion goes red.
#[test]
fn a_deadline_crosses_as_remaining_time() {
    let w = up();
    let now_a = w.borrow().clock.get();
    let mut m = raw_req(ProbeIdl::ID, ProbeIdl::OP_READ, &[1]);
    m.deadline = now_a + 5 * MS;
    w.borrow_mut().call_a(&mut m);
    assert_eq!(m.words[0], 0, "answered");
    {
        let w = w.borrow();
        let seen = w.b.st.borrow().calls.last().unwrap().clone();
        assert_eq!(seen.deadline, now_a + SKEW_NS + 5 * MS, "5 ms left, on B's clock");
        assert_eq!(seen.clock_id, 0, "MONO");
        let req = w.net.borrow().log.iter().rev().find(|s| s.kind == Kind::Req).unwrap().remaining_ns;
        assert_eq!(req, 5 * MS, "the frame carries the time remaining");
    }
    // Already passed: nothing is sent.
    let sent = w.borrow().sent(A, Kind::Req);
    let mut m = raw_req(ProbeIdl::ID, ProbeIdl::OP_READ, &[1]);
    m.deadline = w.borrow().clock.get();
    w.borrow_mut().call_a(&mut m);
    assert_eq!(m.words[0], IdlError::DeadlineExpired.status());
    assert_eq!(w.borrow().sent(A, Kind::Req), sent);
    // Passes while the answer is lost: the resends carried less time each.
    w.borrow().rule(|s| if s.kind == Kind::Rep { Fate::Drop } else { Fate::Deliver });
    let mut m = raw_req(ProbeIdl::ID, ProbeIdl::OP_READ, &[1]);
    m.deadline = w.borrow().clock.get() + 250 * MS;
    w.borrow_mut().call_a(&mut m);
    assert_eq!(m.words[0], IdlError::DeadlineExpired.status());
    let mut rems: Vec<u64> = w.borrow().net.borrow().log.iter().rev().filter(|s| s.kind == Kind::Req).take(3).map(|s| s.remaining_ns).collect();
    rems.reverse();
    assert_eq!(rems.len(), 3);
    assert!(rems.windows(2).all(|p| p[0] > p[1]), "{rems:?}");
}

/// A clock class other than the one the nodes serve is refused.
#[test]
fn a_foreign_clock_class_is_refused() {
    let w = up();
    let mut m = raw_req(ProbeIdl::ID, ProbeIdl::OP_READ, &[1]);
    m.clock_id = 1 << 24;
    m.deadline = 1;
    w.borrow_mut().call_a(&mut m);
    assert_eq!(m.words[0], IdlError::Malformed.status());
}

/// **A MemObj's pages move across and are re-minted** on the far node as a
/// new object lent to the service as a copy that lapses; the sender's object
/// is consumed.
///
/// **Canaries.** Skip the `consume` after copying the pages: the original
/// handle survives and the first assertion goes red. Lend with MOVE instead of
/// DUP: the mode assertion goes red. Lend without an expiry: the expiry
/// assertion goes red.
#[test]
fn memobj_pages_move_across_and_are_reminted() {
    let w = up();
    let data: Vec<u8> = (0..8192u32).map(|i| (i * 31 + 7) as u8).collect();
    let mem = w.borrow_mut().a_mem(data.clone());
    // By hand, to see the entry the service gets.
    let mut m = raw_req(ProbeIdl::ID, ProbeIdl::OP_STORE, &[]);
    m.n_caps = 1;
    m.caps[0] = dup_cap(mem);
    w.borrow_mut().call_a(&mut m);
    assert_eq!(m.words[0], 0);
    let w = w.borrow();
    assert!(!w.a.st.borrow().objs.contains_key(&mem), "the sender's object is consumed");
    assert_eq!(w.b.svc.borrow().stored, [data], "the service read the same pages");
    let b = w.b.st.borrow();
    let seen = b.calls.last().unwrap();
    assert_eq!(seen.cap_modes, [CAP_MODE_DUP], "a copy, the parent stays the session's");
    assert_eq!(seen.cap_rights, [RW]);
    assert_eq!(seen.cap_expiry, [b.now() + 10_000 * MS], "lapses with the warrant TTL");
    assert_ne!(seen.cap_handles[0], mem, "a handle of B's own");
    assert_eq!(seen.flags, 0, "no flag the kernel would refuse");
}

/// A reply's object is re-minted for the caller as a DUP entry that lapses, and
/// holds the bytes the far service lent.
#[test]
fn a_reply_object_is_reminted_for_the_caller() {
    let w = up();
    let mut m = raw_req(ProbeIdl::ID, ProbeIdl::OP_FETCH, &[5000]);
    w.borrow_mut().call_a(&mut m);
    assert_eq!((m.words[0], m.n_caps), (0, 1));
    let c = m.caps[0];
    assert_eq!((c.mode, c.rights), (CAP_MODE_DUP, RW));
    let w = w.borrow();
    let a = w.a.st.borrow();
    assert_eq!(c.expiry_ns, a.now() + 10_000 * MS);
    match &a.objs[&c.handle] {
        Obj::Mem { data, .. } => {
            assert!(data[..5000].iter().all(|&b| b == 0x5A), "the bytes the far service lent");
            assert!(data[5000..].iter().all(|&b| b == 0), "the rest of the page is zero");
        }
        _ => panic!("not an object"),
    }
}

/// **Only a MemObj crosses**: an endpoint capability is refused, consumed, and
/// nothing is sent; a DUP entry of an object is refused too (the pages are not
/// shared across nodes), and the far node refuses an entry that is not a MOVE
/// whatever the sender did, re-minting nothing.
///
/// **Canary.** Make the page loop of `begin` skip an object it cannot read
/// instead of refusing the call: the endpoint is sent and the Req count goes red.
#[test]
fn only_a_memobj_crosses() {
    let w = up();
    let ep = w.borrow().a.st.borrow_mut().alloc(Obj::Ep { parent: None, rights: RW, badge: 0, expiry: 0 });
    assert_eq!(probe(&w).give(Cap::from_raw(ep)), Err(IdlError::Refused));
    assert_eq!(w.borrow().sent(A, Kind::Req), 0);
    assert!(!w.borrow().a.st.borrow().objs.contains_key(&ep), "consumed");
    let mem = w.borrow_mut().a_mem(vec![1; 4096]);
    let mut m = raw_req(ProbeIdl::ID, ProbeIdl::OP_STORE, &[]);
    m.n_caps = 1;
    m.caps[0] = CapDesc { handle: mem, mode: CAP_MODE_DUP, _pad: 0, rights: 0, expiry_ns: 0 };
    w.borrow_mut().call_a(&mut m);
    assert_eq!(m.words[0], IdlError::Refused.status());
    assert_eq!(w.borrow().sent(A, Kind::Req), 0);
    // Forged past the sender: a DUP entry with its pages.
    let mut wb = w.borrow_mut();
    let id = wb.a.rpc.session_with(B).unwrap().id;
    let mut body = vec![0u8; 8192];
    let mut at = 0;
    put_desc(&m, &mut body, &mut at).unwrap();
    body[at..at + 4].copy_from_slice(&4096u32.to_le_bytes());
    at += 4 + 4096;
    let st = status_from_b(&mut wb, &forged(id, 1, &body[..at]));
    assert_eq!(st, IdlError::Refused.status());
    assert!(wb.b.svc.borrow().stored.is_empty());
    assert!(wb.b.st.borrow().mems().is_empty(), "nothing re-minted survives a refusal");
}

/// A message of many frames: a lost fragment loses the request, and the
/// at-most-once resend carries it whole.
///
/// **Canary.** Fragment at `FRAG_BODY + 1`: the receiver drops every frame and
/// the call never finishes.
#[test]
fn a_big_message_is_fragmented_and_a_lost_fragment_is_resent() {
    let w = up();
    let data: Vec<u8> = (0..16384u32).map(|i| (i % 253) as u8).collect();
    let mem = w.borrow_mut().a_mem(data.clone());
    let mut dropped = false;
    w.borrow().rule(move |s| {
        if s.kind == Kind::Req && s.frag == 5 && !dropped {
            dropped = true;
            Fate::Drop
        } else {
            Fate::Deliver
        }
    });
    let sum: u32 = data.iter().map(|&b| b as u32).sum();
    assert_eq!(probe(&w).store(Cap::from_raw(mem)), Ok(sum));
    let frags = frags_for(4 + 8 + 16 + 4 + 16384);
    assert!(frags > 10);
    assert_eq!(w.borrow().net.borrow().log.iter().filter(|s| s.kind == Kind::Req).count(), 2 * frags, "sent whole twice");
    assert_eq!(w.borrow().b.svc.borrow().stored.len(), 1, "ran once");
}

/// **A peer that restarts under the same id breaks the sessions it had**: the
/// new epoch is told apart, the old session is revoked and the next dial makes
/// a new one.
///
/// A Hello that repeats the nonce of the session but comes from another boot
/// epoch is a new dial, not a resend: the old session goes.
///
/// **Canary.** Ignore `epoch` in `on_hello`'s resend test (`s.peer_epoch ==
/// h.epoch`): the forged Hello is answered with the old session and the id
/// assertion goes red.
#[test]
fn a_restarted_peer_breaks_the_sessions_it_had() {
    let w = up();
    assert_eq!(probe(&w).read(1), Ok(2));
    let old = sid(&w);
    let warrant = w.borrow().b.st.borrow().warrants()[0];
    // A restarts: a new server under node id 1 with a new epoch, no memory of the session.
    {
        let mut wb = w.borrow_mut();
        let World { a, net, .. } = &mut *wb;
        let mut rpc = Box::new(Node::new(
            FakeHost { st: a.st.clone(), svc: a.svc.clone() },
            MemLink { me: A, net: net.clone() },
            azos_rpc::Claimed,
            &CATALOG,
        ));
        rpc.configure(cfg(A, 2));
        rpc.set_policy(azos_rpc::Policy::parse(POLICY_A.as_bytes()));
        a.rpc = rpc;
    }
    w.borrow_mut().run_for(300 * MS);
    let id = sid(&w);
    assert_ne!(id, old, "a new session");
    assert!(!w.borrow().b.st.borrow().objs.contains_key(&warrant), "the old warrant was revoked with the old session");
    assert_eq!(probe(&w).read(2), Ok(4));

    // The same nonce from another epoch (a clock that restarted at zero can repeat one).
    assert_eq!(probe(&w).read(3), Ok(6));
    let id = sid_of(&w.borrow());
    let nonce = w.borrow().b.rpc.session_with(A).unwrap().nonce;
    let warrant = w.borrow().b.st.borrow().warrants()[0];
    let mut hello = vec![0u8; HEADER_BYTES + 2];
    put_header(&Header::new(Kind::Hello, 0, nonce, A, 3), &mut hello);
    {
        let mut wb = w.borrow_mut();
        let World { b, .. } = &mut *wb;
        b.rpc.on_frame(&mut b.asm, &hello);
    }
    let id2 = w.borrow().b.rpc.session_with(A).unwrap().id;
    assert_ne!(id2, id, "a new session, not the old one answered again");
    assert!(!w.borrow().b.st.borrow().objs.contains_key(&warrant), "and the old one revoked");
}

fn sid_of(w: &World) -> u32 {
    w.b.rpc.session_with(A).unwrap().id
}

/// Unanswered probes count **in a row**: two lost, one answered, one lost is
/// not three.
///
/// **Canary.** Never reset `misses` when a frame arrives: the fourth phase
/// breaks the session and the assertion goes red. (B is made patient, so that
/// its own count does not end the session first.)
#[test]
fn unanswered_probes_must_be_consecutive_to_break_a_session() {
    let mut w = World::with_cfg(POLICY_A, POLICY_B, |c| c.miss_limit = 200);
    w.establish();
    let mut phase = 0u32;
    // Pings are lost in phases 1 and 3; everything else gets through.
    let p = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let q = p.clone();
    w.rule(move |s| if (q.get() == 1 || q.get() == 3) && s.kind == Kind::Ping { Fate::Drop } else { Fate::Deliver });
    let id = w.a.rpc.session_with(B).unwrap().id;
    for (ph, ms) in [(0u32, 2_000u64), (1, 2_900), (2, 5_000), (3, 2_900)] {
        phase += 1;
        p.set(ph);
        w.run_for(ms * MS);
        // The same session throughout: a break would be followed by a redial at once.
        assert!(w.a.rpc.session_with(B).is_some_and(|s| s.state == State::Up && s.id == id), "phase {phase}");
    }
}

/// A request on a session the far node does not have is answered with a Bye,
/// and the caller learns `NoConnection` and dials again.
///
/// **Canary.** Drop the Bye in `dispatch`: the call burns its retries and the
/// Bye count goes red.
#[test]
fn a_request_on_an_unknown_session_gets_a_bye() {
    let w = up();
    {
        // B forgets the session (it restarted without a trace).
        let mut wb = w.borrow_mut();
        let si = (0..azos_rpc::MAX_SESSIONS).find(|&i| wb.b.rpc.session_with(A).is_some() && i == 0).unwrap();
        wb.b.rpc.break_session(si, false);
    }
    assert_eq!(probe(&w).read(1), Err(IdlError::NoConnection));
    assert!(w.borrow().sent(B, Kind::Bye) >= 1);
    w.borrow_mut().run_for(500 * MS);
    assert_eq!(probe(&w).read(2), Ok(4), "redialed");
}

/// **Provenance is appended on both sides**, in the kernel's own record: B for
/// the warrant it derived (the handle, its parent and the peer), A for the
/// authority its caller was given across the session; both name the other node
/// and the same session.
///
/// **Canary.** Drop the `journal.derive` in `warrant()`: B's record goes missing.
#[test]
fn provenance_is_appended_on_both_sides() {
    let w = up();
    assert_eq!(probe(&w).read(1), Ok(2));
    let id = sid(&w) as u64;
    let w = w.borrow();
    let b = w.b.st.borrow();
    let (h, parent, _, _, expiry) = b.derives[0];
    let rb = recs(w.b.rpc.journal(), Rule::CapDerive);
    assert_eq!(rb.len(), 1);
    assert_eq!((rb[0].node_id, rb[0].session_id), (A, id));
    assert_eq!((rb[0].cap_slot[0], rb[0].parent_cap[0]), (h as u64, parent as u64));
    assert_eq!(rb[0].n[2], expiry);
    assert_eq!(rb[0].clock_ns, b.now());
    let ra = recs(w.a.rpc.journal(), Rule::CapDerive);
    assert_eq!(ra.len(), 1);
    assert_eq!((ra[0].node_id, ra[0].session_id), (B, id));
    assert_eq!(ra[0].subject, 0x77, "the caller the authority was for");
    assert_eq!((ra[0].n[0], ra[0].n[1]), (ProbeIdl::ID as u64, ProbeIdl::OP_READ as u64));
    // The record is the full kernel form: it round-trips through its bytes.
    let bytes = rb[0].to_bytes();
    assert_eq!(ProvenanceRecord::from_bytes(&bytes).unwrap(), rb[0]);
}

/// A second call while one is outstanding is refused rather than mixed up with it.
#[test]
fn a_busy_server_refuses_a_second_call() {
    let mut w = World::new();
    w.establish();
    w.rule(|s| if s.kind == Kind::Rep { Fate::Drop } else { Fate::Deliver });
    let m = raw_req(ProbeIdl::ID, ProbeIdl::OP_READ, &[1]);
    let first = w.a.rpc.begin(&m, 1);
    assert!(matches!(first, azos_rpc::Started::Pending(_)));
    match w.a.rpc.begin(&m, 2) {
        azos_rpc::Started::Done(d) => assert_eq!(d.words[0], IdlError::Refused.status()),
        _ => panic!("a second call went out"),
    }
}

/// A bad proof refuses the session: the handshake is an interface and a
/// verifier that says no keeps the peer out.
///
/// **Canary.** Ignore the result of `verify` in `on_hello`: the session comes up.
#[test]
fn a_handshake_that_refuses_keeps_the_peer_out() {
    struct No;
    impl azos_rpc::Handshake for No {
        fn prove(&mut self, _: u32, _: &mut [u8; azos_rpc::PROOF_MAX]) -> usize {
            3
        }
        fn verify(&mut self, _: u32, _: &[u8]) -> bool {
            false
        }
    }
    let mut w = World::new();
    // B's server with a handshake that believes no proof.
    let mut rpc = Box::new(azos_rpc::Rpc::new(
        FakeHost { st: w.b.st.clone(), svc: w.b.svc.clone() },
        MemLink { me: B, net: w.net.clone() },
        No,
        &CATALOG,
    ));
    rpc.configure(cfg(B, 1));
    rpc.set_policy(azos_rpc::Policy::parse(POLICY_B.as_bytes()));
    let mut asm = Box::new(azos_rpc::wire::Asm::new());
    for _ in 0..5 {
        w.a.rpc.tick();
        loop {
            let f = w.net.borrow_mut().q[1].pop_front();
            let Some(f) = f else { break };
            rpc.on_frame(&mut asm, &f);
        }
        loop {
            let f = w.net.borrow_mut().q[0].pop_front();
            let Some(f) = f else { break };
            w.a.rpc.on_frame(&mut w.a.asm, &f);
        }
        w.advance(110 * MS);
    }
    assert!(rpc.session_with(A).is_none());
    assert!(w.a.rpc.session_with(B).is_none_or(|s| s.state != State::Up));
}

/// **One out-of-range datagram from a stranger does nothing.** The frame is
/// the largest fragment count's last index with more body than `MSG_CAP`
/// leaves; it names no session and carries no proof, and it must neither
/// panic the server (`rpcsrv` would `exit(70)`) nor be answered.
///
/// **Canary.** Remove the bound in `get_header` and in `Asm::push`: the
/// `on_frame` call panics on the slice.
#[test]
fn an_oversized_last_fragment_from_anyone_is_dropped() {
    use azos_rpc::wire::{FRAGS_MAX, MSG_CAP};
    let w = up();
    let mut wb = w.borrow_mut();
    let mut h = Header::new(Kind::Req, 0xDEAD, 1, A, 1);
    h.frag_cnt = FRAGS_MAX as u16;
    h.frag_idx = (FRAGS_MAX - 1) as u16;
    let body = vec![0x41u8; MSG_CAP - (FRAGS_MAX - 1) * FRAG_BODY + 1];
    let mut f = vec![0u8; HEADER_BYTES + body.len()];
    put_header(&h, &mut f);
    f[HEADER_BYTES..].copy_from_slice(&body);
    let before = wb.net.borrow().log.len();
    let World { b, .. } = &mut *wb;
    b.rpc.on_frame(&mut b.asm, &f);
    assert_eq!(wb.net.borrow().log.len(), before, "not answered");
    assert!(wb.b.rpc.session_with(A).is_some_and(|s| s.state == State::Up), "the session is untouched");
}

/// **A multi-object request that fails midway leaves nothing for a later
/// close to hit.** The kernel hands a closed handle's number out again; if the
/// failure path closed an object the session still lists, the sweep or the
/// break of the session would close that number a second time, then another
/// object's.
///
/// **Canary.** Close in the failure path of `serve_req` with `host.close` (the
/// record stays live): the unrelated object dies with the session.
#[test]
fn a_request_that_fails_midway_does_not_close_a_recycled_handle_later() {
    let w = up();
    let id = sid(&w);
    w.borrow().b.st.borrow_mut().recycle = true;
    // The first object is re-minted, the second finds no memory.
    w.borrow().b.st.borrow_mut().mem_fail_after = Some(1);
    let m1 = w.borrow_mut().a_mem(vec![1; 4096]);
    let m2 = w.borrow_mut().a_mem(vec![2; 4096]);
    let mut m = raw_req(ProbeIdl::ID, ProbeIdl::OP_STORE, &[]);
    m.n_caps = 2;
    m.caps[0] = dup_cap(m1);
    m.caps[1] = dup_cap(m2);
    w.borrow_mut().call_a(&mut m);
    assert_eq!(m.words[0], IdlError::Refused.status(), "the second object could not be made");
    let wb = w.borrow();
    assert!(wb.b.svc.borrow().stored.is_empty(), "the service never ran");
    let freed = {
        let b = wb.b.st.borrow();
        assert!(b.mems().is_empty(), "what the request made is closed");
        assert_eq!(b.closed.len(), 1);
        b.closed[0]
    };
    // An unrelated object takes the freed number (premise: the number is reused).
    let x = wb.b.st.borrow_mut().alloc(Obj::Ep { parent: None, rights: RW, badge: 0, expiry: 0 });
    assert_eq!(x, freed, "the premise: the freed number is handed out again");
    drop(wb);
    // The peer ends the session; B revokes what it minted over it.
    let mut bye = vec![0u8; HEADER_BYTES];
    put_header(&Header::new(Kind::Bye, id, 0, A, 1), &mut bye);
    {
        let mut wb = w.borrow_mut();
        let World { b, .. } = &mut *wb;
        b.rpc.on_frame(&mut b.asm, &bye);
        assert!(b.rpc.session_with(A).is_none(), "the session is broken");
    }
    assert!(w.borrow().b.st.borrow().alive(x), "an object that is not the session's survives its break");
}

/// **The call into the real service never waits longer than the caller
/// would**, whatever deadline the frame carried (none, or an hour): it holds
/// the engine's lock, and a slow service must not freeze the link thread. A
/// shorter deadline is kept.
///
/// **Canary.** Set `abs_deadline` from `remaining_ns` alone: the first two
/// assertions go red.
#[test]
fn an_exported_call_has_a_bounded_deadline() {
    let w = up();
    let patience = 100 * MS * 4; // rto * (retries + 1) of the test config
    let mut m = raw_req(ProbeIdl::ID, ProbeIdl::OP_READ, &[1]);
    w.borrow_mut().call_a(&mut m);
    assert_eq!(m.words[0], 0);
    {
        let wb = w.borrow();
        let b = wb.b.st.borrow();
        assert_eq!(b.calls.last().unwrap().deadline, b.now() + patience, "no deadline sent: the bound");
    }
    let mut m = raw_req(ProbeIdl::ID, ProbeIdl::OP_READ, &[1]);
    m.deadline = w.borrow().clock.get() + 3_600_000 * MS;
    w.borrow_mut().call_a(&mut m);
    assert_eq!(m.words[0], 0);
    {
        let wb = w.borrow();
        let b = wb.b.st.borrow();
        assert_eq!(b.calls.last().unwrap().deadline, b.now() + patience, "an hour sent: the bound");
    }
    let mut m = raw_req(ProbeIdl::ID, ProbeIdl::OP_READ, &[1]);
    m.deadline = w.borrow().clock.get() + 5 * MS;
    w.borrow_mut().call_a(&mut m);
    let wb = w.borrow();
    let b = wb.b.st.borrow();
    assert_eq!(b.calls.last().unwrap().deadline, b.now() + 5 * MS, "5 ms sent: kept");
}

/// **A full table of re-minted objects closes the one that lapses first, and
/// an object that never lapses is the last to go.** (Expiry 0 means none; it
/// must not sort before every real expiry.)
///
/// **Canary.** Order the eviction by raw `expiry_ns`: the never-expiring
/// object (first, expiry 0) is the one closed and the last assertion goes red.
#[test]
fn eviction_of_reminted_objects_spares_the_one_that_never_lapses() {
    use azos_rpc::MINTED_CAP;
    // B lends with no TTL of its own: an object lapses only when its caller said so.
    let w = RefCell::new(World::with_cfg(POLICY_A, POLICY_B, |c| c.warrant_ttl_ns = 0));
    w.borrow_mut().establish();
    let store = |w: &RefCell<World>, expiry_after_ms: u64| {
        let mem = w.borrow_mut().a_mem(vec![9; 4096]);
        let mut m = raw_req(ProbeIdl::ID, ProbeIdl::OP_STORE, &[]);
        m.n_caps = 1;
        m.caps[0] = dup_cap(mem);
        if expiry_after_ms != 0 {
            m.caps[0].expiry_ns = w.borrow().clock.get() + expiry_after_ms * MS;
        }
        w.borrow_mut().call_a(&mut m);
        assert_eq!(m.words[0], 0);
    };
    let roots = |w: &RefCell<World>| -> Vec<u32> {
        let wb = w.borrow();
        let b = wb.b.st.borrow();
        b.mems().into_iter().filter(|h| matches!(b.objs[h], Obj::Mem { parent: None, .. })).collect()
    };
    store(&w, 0);
    let never = roots(&w);
    assert_eq!(never.len(), 1);
    for k in 1..MINTED_CAP as u64 {
        store(&w, 600_000 + k);
    }
    assert_eq!(roots(&w).len(), MINTED_CAP, "the table is full");
    store(&w, 700_000);
    let after = roots(&w);
    assert_eq!(after.len(), MINTED_CAP, "one made room for one");
    assert!(after.contains(&never[0]), "the object that never lapses stays");
}
