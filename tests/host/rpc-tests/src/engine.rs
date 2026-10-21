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
use azos_idl::{header_id, Cap, IdlError};
use azos_rpc::wire::{frags_for, get_header, put_desc, put_header, put_token, Header, Kind, FRAG_BODY, HEADER_BYTES, TAG_BYTES};
use azos_rpc::{NodeId, State};
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

/// A request for `d` numbered `seq`, as `f` (a node holding a session key with B)
/// would send it: for what no stub would send.
fn req_frames(f: &mut Forger, seq: u64, d: &MsgDesc) -> Vec<Vec<u8>> {
    let mut body = vec![0u8; 512];
    let mut at = 0;
    put_desc(d, &mut body, &mut at).unwrap();
    put_token(&f.token(header_id(d.words[0])), &mut body, &mut at).unwrap();
    f.seal(Kind::Req, seq, &body[..at])
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
    let mut w = World::with(&policy_a(), &(peer("fleet", C, C) + "export probe 7 fleet\n"));
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
    let w = RefCell::new(World::with(&policy_a(), &peer("fleet", A, A)));
    w.borrow_mut().establish();
    assert_eq!(probe(&w).read(1), Err(IdlError::Refused));
    assert_eq!(w.borrow().sent(A, Kind::Req), 0, "refused before it crossed");

    // B exports it to another class: the node is in `lab`, the export is to `fleet`.
    let w = RefCell::new(World::with(&policy_a(), &(peer("lab", A, A) + "export probe 7 fleet\n")));
    w.borrow_mut().establish();
    assert_eq!(probe(&w).read(1), Err(IdlError::Refused));

    // A request forged past the sender, on a session of node 1 (a peer whose
    // keys B agreed, whatever its class allows).
    let mut wb = w.borrow_mut();
    let mut f = Forger::dial(&mut wb, A);
    let frames = req_frames(&mut f, 1, &raw_req(ProbeIdl::ID, ProbeIdl::OP_READ, &[5]));
    let st = f.status(&mut wb, &frames);
    assert_eq!(st, IdlError::Refused.status());
    assert_eq!(wb.b.svc.borrow().reads, 0, "nothing ran");
    let refused = recs(wb.b.rpc.journal(), Rule::CapDenial);
    assert_eq!(refused.len(), 1);
    assert_eq!((refused[0].node_id, refused[0].session_id), (A, f.session as u64));
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
    let mut w = World::new();
    let mut f = Forger::dial(&mut w, A);
    for seq in 1..=6 {
        let frames = req_frames(&mut f, seq, &raw_req(ProbeIdl::ID, ProbeIdl::OP_BUMP, &[1]));
        assert_ne!(f.status(&mut w, &frames), IdlError::NoConnection.status());
    }
    assert_eq!(w.b.svc.borrow().counter, 6);
    // The first call's number is long out of the 4-entry window: the same call
    // sealed again (a new packet, so the transport lets it by) is the window's to refuse.
    let frames = req_frames(&mut f, 1, &raw_req(ProbeIdl::ID, ProbeIdl::OP_BUMP, &[1]));
    assert_eq!(f.status(&mut w, &frames), IdlError::NoConnection.status());
    assert_eq!(w.b.svc.borrow().counter, 6, "not run again");
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
    let mut f = Forger::dial(&mut wb, A);
    let mut body = vec![0u8; 8192];
    let mut at = 0;
    put_desc(&m, &mut body, &mut at).unwrap();
    put_token(&f.token(ProbeIdl::ID), &mut body, &mut at).unwrap();
    body[at..at + 4].copy_from_slice(&4096u32.to_le_bytes());
    at += 4 + 4096;
    let frames = f.seal(Kind::Req, 1, &body[..at]);
    let st = f.status(&mut wb, &frames);
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
/// epoch is a new dial, not a resend: once the dialer confirms it with a first
/// sealed frame, the old session goes.
///
/// **Canary.** Ignore `epoch` in `on_hello`'s repeat test (`s.peer_epoch ==
/// h.epoch`): the Hello is ignored as a repeat and the id assertion goes red.
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
            &CATALOG,
        ));
        rpc.configure(cfg(A, 2));
        rpc.set_policy(policy_of(&policy_a()));
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
    Forger::try_dial(&mut w.borrow_mut(), A, sk(A), 3, nonce).expect("a dial from a new epoch is answered");
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
    let mut w = World::with_cfg(&policy_a(), &policy_b(), |c| c.miss_limit = 200);
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

/// A request on a session the far node does not have is dropped: the node has
/// no keys for it, so it cannot say so (a Bye would have to be forged). The
/// caller learns `NoConnection` when its resends run out, its probes go
/// unanswered until the session is broken, and it dials again.
///
/// **Canary.** Make `dispatch` answer a frame of an unknown session with a Bye
/// (unsealed): the Bye count goes red.
#[test]
fn a_request_on_an_unknown_session_is_dropped_and_the_caller_redials() {
    let w = up();
    {
        // B forgets the session (it restarted without a trace).
        let mut wb = w.borrow_mut();
        let si = (0..azos_rpc::MAX_SESSIONS).find(|&i| wb.b.rpc.session_with(A).is_some() && i == 0).unwrap();
        wb.b.rpc.break_session(si, false);
    }
    assert_eq!(probe(&w).read(1), Err(IdlError::NoConnection));
    assert_eq!(w.borrow().sent(B, Kind::Bye), 0);
    w.borrow_mut().run_for(6_000 * MS);
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

/// Ticks and frames until quiet, for a world whose session never comes up.
fn dial_for_a_while(w: &mut World) {
    for _ in 0..8 {
        w.tick();
        w.pump();
        w.advance(110 * MS);
    }
}

/// **A dialer whose key is not the pinned one never gets a session.** IK
/// proves the dialer holds some key; the topology says which one node 1 must
/// hold. B pins another: B refuses, sends no answer, and A's caller is told
/// `NoConnection` (a peer is not up), never a made-up success.
///
/// **Canary.** Drop the `ct_eq(remote_static, dialer_pk)` checks of
/// `chan::answer`: the session comes up and the assertions go red.
#[test]
fn a_dialer_with_a_key_the_topology_does_not_pin_is_refused() {
    let mut w = World::with(&policy_a(), &(peer("fleet", A, C) + "export probe 7 fleet\n"));
    dial_for_a_while(&mut w);
    assert!(w.b.rpc.session_with(A).is_none());
    assert_eq!(w.sent(B, Kind::HelloAck), 0, "refused without an answer");
    assert!(w.b.st.borrow().log.contains("hello refused"));
    assert!(w.a.rpc.session_with(B).is_none_or(|s| s.state != State::Up));
    let w = RefCell::new(w);
    assert_eq!(probe(&w).read(1), Err(IdlError::NoConnection));
}

/// **The same from the other side**: A pins a key B does not hold (an
/// impostor holding node 2's id, or the key of B rotated and A not told). The
/// Hello is encrypted to the wrong static key, B cannot read it, and nothing
/// comes up.
///
/// **Canary.** Make `dial` ignore the pinned key and use B's: the session comes
/// up and the assertion goes red.
#[test]
fn an_answerer_that_does_not_hold_the_pinned_key_gets_no_session() {
    let mut w = World::with(&peer("fleet", B, C), &policy_b());
    dial_for_a_while(&mut w);
    assert!(w.b.rpc.session_with(A).is_none());
    assert!(w.a.rpc.session_with(B).is_none_or(|s| s.state != State::Up));
    assert_eq!(w.sent(B, Kind::HelloAck), 0);
    // B holds another key than the one A pins: the same.
    let mut w = World::new();
    w.b.st.borrow_mut().sk = Some(sk(C));
    dial_for_a_while(&mut w);
    assert!(w.b.rpc.session_with(A).is_none());
    assert!(w.a.rpc.session_with(B).is_none_or(|s| s.state != State::Up));
}

/// **A node id is not an identity.** A node that states id 1 and holds another
/// key (or the id of a node no class lists) is refused, whatever else it
/// gets right; the real key of node 1 is answered.
///
/// **Canary.** Skip the pinned-key comparison in `answer`: the impostor gets a
/// session.
#[test]
fn a_node_id_without_the_pinned_key_is_refused() {
    let mut w = World::new();
    assert!(Forger::try_dial(&mut w, A, sk(C), 9, 0x2000_0001).is_none(), "id 1 with the key of node 3");
    assert!(Forger::try_dial(&mut w, C, sk(C), 9, 0x2000_0003).is_none(), "id 3: in no class of B's");
    assert!(w.b.rpc.session_with(A).is_none() && w.b.rpc.session_with(C).is_none());
    assert!(Forger::try_dial(&mut w, A, sk(A), 9, 0x2000_0005).is_some(), "the key the topology pins");
    assert_eq!(w.b.rpc.session_with(A).unwrap().state, State::Up);
}

/// A header edited after the dialer wrote it fails the handshake: the node ids,
/// the epoch and the nonce are in the Noise prologue.
///
/// **Canary.** Build the prologue from constants: the edited Hello is answered.
#[test]
fn a_hello_whose_header_was_edited_fails_the_handshake() {
    let mut w = World::new();
    let pro = azos_rpc::chan::prologue(A, B, 9, 77);
    let mut hello = [0u8; azos_rpc::wire::HELLO_MAX];
    let eph = [0xE1u8; 32];
    let (_, n) = azos_rpc::chan::dial(&sk(A), &pk(B), &pro, &eph, &[0u8], &mut hello).unwrap();
    let send = |w: &mut World, epoch: u32, nonce: u64| {
        let mut f = vec![0u8; HEADER_BYTES + n];
        put_header(&Header::new(Kind::Hello, 0, nonce, A, epoch), &mut f);
        f[HEADER_BYTES..].copy_from_slice(&hello[..n]);
        w.b.rpc.on_frame(&mut w.b.asm, &f);
    };
    send(&mut w, 10, 77);
    send(&mut w, 9, 78);
    assert_eq!(w.sent(B, Kind::HelloAck), 0, "an epoch or a nonce changed in flight");
    send(&mut w, 9, 77);
    assert_eq!(w.sent(B, Kind::HelloAck), 1, "the Hello as written");
}

/// A node without a key, or without entropy, neither dials nor answers.
///
/// **Canary.** Treat `None` as an all-zero key: the session comes up.
#[test]
fn a_node_without_a_key_or_entropy_has_no_sessions() {
    let mut w = World::new();
    w.a.st.borrow_mut().sk = None;
    dial_for_a_while(&mut w);
    assert_eq!(w.sent(A, Kind::Hello), 0);
    let mut w = World::new();
    w.a.st.borrow_mut().dry = true;
    dial_for_a_while(&mut w);
    assert_eq!(w.sent(A, Kind::Hello), 0);
    let mut w = World::new();
    w.b.st.borrow_mut().sk = None;
    dial_for_a_while(&mut w);
    assert_eq!(w.sent(B, Kind::HelloAck), 0);
    assert!(w.b.rpc.session_with(A).is_none());
}

/// An answer that does not verify is ignored by the dialer, not obeyed: anyone
/// who saw the Hello knows the nonce to put on one, and one forged answer must
/// not end the dial.
///
/// **Canary.** Free the session on a failed answer: the dial dies and the
/// session never comes up.
#[test]
fn a_forged_answer_does_not_end_the_dial() {
    let mut w = World::new();
    w.a.rpc.tick();
    let nonce = w.a.rpc.session_with(B).unwrap().nonce;
    let mut f = vec![0u8; HEADER_BYTES + 81];
    put_header(&Header::new(Kind::HelloAck, 5, nonce, B, 1), &mut f);
    f[HEADER_BYTES..].fill(0x33);
    w.a.rpc.on_frame(&mut w.a.asm, &f);
    assert_eq!(w.a.rpc.session_with(B).unwrap().state, State::Dialing);
    assert!(w.a.st.borrow().log.contains("hello answer refused"));
    w.net.borrow_mut().q[1].clear();
    w.net.borrow_mut().q[0].clear();
    w.a.rpc.tick();
    w.advance(250 * MS);
    w.establish();
}

/// **Nothing readable crosses the link**: the arguments of a call and the pages
/// of an object are in no frame as they are, and the frames of a session are
/// all different (the packet counter is the nonce).
///
/// **Canary.** Send the body unsealed in `Channel::seal`: the marker is found
/// on the wire.
#[test]
fn nothing_readable_crosses_the_link() {
    let w = up();
    assert_eq!(probe(&w).read(0xDEAD_BEEF), Ok(0xDEAD_BEEFu32.wrapping_mul(2)));
    let mem = w.borrow_mut().a_mem(vec![0xC3; 4096]);
    assert!(probe(&w).store(Cap::from_raw(mem)).is_ok());
    let wb = w.borrow();
    let net = wb.net.borrow();
    let wire: Vec<&Vec<u8>> = net.raw.iter().map(|(_, f)| f).collect();
    assert!(wire.len() >= 6);
    let marker = 0xDEAD_BEEFu32.to_le_bytes();
    for f in &wire {
        assert!(!f.windows(4).any(|x| x == marker), "an argument in the clear");
        assert!(!f.windows(16).any(|x| x == [0xC3u8; 16]), "pages in the clear");
    }
    let mut ctrs: Vec<(NodeId, u64)> = vec![];
    for (from, f) in &net.raw {
        let (h, _) = get_header(f).unwrap();
        if h.kind != Kind::Hello && h.kind != Kind::HelloAck {
            assert!(!ctrs.contains(&(*from, h.ctr)), "a counter repeated under the session keys");
            ctrs.push((*from, h.ctr));
        }
    }
}

/// **A captured request replayed is refused.** The datagram is byte for byte
/// the one that ran; its counter was seen, so the transport drops it before
/// anything is decrypted and the service is not asked again (`read` is
/// idempotent, so only the transport stands between a replay and a second
/// run). A reply replayed to the caller is dropped the same way.
///
/// **Canary.** Skip `win.fresh` in `Channel::open`: the service count goes to 2.
#[test]
fn a_captured_request_replayed_is_refused() {
    let w = up();
    assert_eq!(probe(&w).read(1), Ok(2));
    let mut wb = w.borrow_mut();
    let (req, rep) = {
        let net = wb.net.borrow();
        let find = |from: NodeId, kind: Kind| net.raw.iter().rev().find(|(f, fr)| *f == from && get_header(fr).unwrap().0.kind == kind).unwrap().1.clone();
        (find(A, Kind::Req), find(B, Kind::Rep))
    };
    assert_eq!(wb.b.svc.borrow().reads, 1);
    let sent = wb.net.borrow().raw.len();
    let World { a, b, .. } = &mut *wb;
    b.rpc.on_frame(&mut b.asm, &req);
    a.rpc.on_frame(&mut a.asm, &rep);
    assert_eq!(wb.b.svc.borrow().reads, 1, "not run again");
    assert_eq!(wb.net.borrow().raw.len(), sent, "and not answered again");
}

/// A frame altered in flight is dropped: a flipped bit in the body, or in a
/// header field (the header is the associated data), and nothing runs. The
/// frame as sent still opens afterwards: a forgery does not spend the counter.
///
/// **Canary.** Leave the header out of the associated data in `Channel::seal`
/// and `open`: the edited-header frame runs.
#[test]
fn a_frame_altered_in_flight_is_dropped() {
    let mut w = World::new();
    let mut f = Forger::dial(&mut w, A);
    let good = req_frames(&mut f, 1, &raw_req(ProbeIdl::ID, ProbeIdl::OP_READ, &[5]));
    assert_eq!(good.len(), 1);
    for at in [HEADER_BYTES + 3, good[0].len() - 1, 8 /* seq */, 24 /* node */, 4 /* session */] {
        let mut bad = good[0].clone();
        bad[at] ^= 1;
        f.send(&mut w, &[bad]);
        assert!(w.net.borrow().q[0].is_empty(), "byte {at}: not answered");
    }
    assert_eq!(w.b.svc.borrow().reads, 0);
    assert_eq!(f.status(&mut w, &good), azos_idl::STATUS_OK, "the frame as sent");
    assert_eq!(w.b.svc.borrow().reads, 1);
}

/// Datagrams arrive in any order: the receiver takes the counter from the
/// packet, so a frame that was overtaken still opens, once; one that fell more
/// than 64 behind does not.
///
/// **Canary.** Decrypt with the implicit in-order counter: the reordered
/// frames are dropped.
#[test]
fn datagrams_may_arrive_out_of_order_inside_the_window_only() {
    let mut w = World::new();
    let mut f = Forger::dial(&mut w, A);
    let pings: Vec<Vec<Vec<u8>>> = (0..70).map(|i| f.seal(Kind::Ping, 100 + i, &[])).collect();
    // 3, 1, 2: each answered once.
    for i in [2usize, 0, 1] {
        f.send(&mut w, &pings[i]);
    }
    assert_eq!(w.net.borrow().q[0].len(), 3);
    w.net.borrow_mut().q[0].clear();
    for i in [2usize, 0, 1] {
        f.send(&mut w, &pings[i]);
    }
    assert!(w.net.borrow().q[0].is_empty(), "a repeat is not answered");
    // The newest (counter 70), then one 59 behind it, then one 66 behind it.
    f.send(&mut w, &pings[69]);
    w.net.borrow_mut().q[0].clear();
    f.send(&mut w, &pings[10]);
    assert_eq!(w.net.borrow().q[0].len(), 1, "inside the window");
    w.net.borrow_mut().q[0].clear();
    f.send(&mut w, &pings[3]);
    assert!(w.net.borrow().q[0].is_empty(), "66 behind: out of the window");
    let old = f.seal(Kind::Ping, 500, &[]);
    let late = f.seal(Kind::Ping, 501, &[]);
    for _ in 0..70 {
        let p = f.seal(Kind::Ping, 502, &[]);
        f.send(&mut w, &p);
    }
    w.net.borrow_mut().q[0].clear();
    f.send(&mut w, &old);
    f.send(&mut w, &late);
    assert!(w.net.borrow().q[0].is_empty(), "out of the window");
}

/// **A Hello replayed after the session is up changes nothing**: the session,
/// its warrants and the calls on it carry on.
///
/// **Canary.** Answer a repeated Hello of the live session with a new session:
/// the session id changes and the warrant is revoked.
#[test]
fn a_hello_replayed_after_the_session_is_up_changes_nothing() {
    let w = up();
    assert_eq!(probe(&w).read(1), Ok(2));
    let (id, warrant) = (sid(&w), w.borrow().b.st.borrow().warrants()[0]);
    let hello = w.borrow().net.borrow().raw.iter().find(|(f, fr)| *f == A && get_header(fr).unwrap().0.kind == Kind::Hello).unwrap().1.clone();
    {
        let mut wb = w.borrow_mut();
        let World { b, .. } = &mut *wb;
        b.rpc.on_frame(&mut b.asm, &hello);
        wb.pump();
        wb.run_for(2_500 * MS);
    }
    assert_eq!(sid(&w), id);
    assert!(w.borrow().b.st.borrow().objs.contains_key(&warrant), "the warrant lives");
    assert_eq!(probe(&w).read(2), Ok(4));
}

/// **A Hello from an earlier boot, replayed, cannot replace the live session.**
/// A passive observer kept A's first Hello; A restarted since. The Hello is a
/// valid handshake, so B answers it, but nobody can confirm it (the replayer
/// holds no key): the session that is up stands, its calls run, and the pending
/// answer lapses on its own.
///
/// **Canary.** Install the session when the Hello is answered (not when the
/// first sealed frame opens): the session id changes and the next call fails.
#[test]
fn an_old_hello_replayed_cannot_replace_a_live_session() {
    let w = up();
    let old_hello = w.borrow().net.borrow().raw.iter().find(|(f, fr)| *f == A && get_header(fr).unwrap().0.kind == Kind::Hello).unwrap().1.clone();
    // A restarts (epoch 2) and dials again.
    {
        let mut wb = w.borrow_mut();
        let World { a, net, .. } = &mut *wb;
        let mut rpc = Box::new(Node::new(FakeHost { st: a.st.clone(), svc: a.svc.clone() }, MemLink { me: A, net: net.clone() }, &CATALOG));
        rpc.configure(cfg(A, 2));
        rpc.set_policy(policy_of(&policy_a()));
        a.rpc = rpc;
    }
    w.borrow_mut().run_for(300 * MS);
    let id = sid(&w);
    assert_eq!(probe(&w).read(1), Ok(2));
    {
        let mut wb = w.borrow_mut();
        let World { b, .. } = &mut *wb;
        b.rpc.on_frame(&mut b.asm, &old_hello);
    }
    w.borrow_mut().net.borrow_mut().q[0].clear(); // the answer goes to a node that never asked
    assert_eq!(sid(&w), id, "the session that was up is still the one");
    assert_eq!(probe(&w).read(2), Ok(4));
    w.borrow_mut().run_for(2_500 * MS);
    assert_eq!(sid(&w), id);
}

/// The answerer is up only when the dialer's first sealed frame opens: if that
/// Ping is lost the dialer resends it every `rto` (not at the next probe, a
/// `ping` away), so the session is there within a few round trips, and the
/// answerer's pending handshake is still waiting for it.
///
/// **Canary.** Resend the confirmation at `ping_ns`: B is not up after 300 ms.
#[test]
fn a_lost_confirmation_is_resent_at_rto() {
    let mut w = World::new();
    let dropped = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let d = dropped.clone();
    w.rule(move |s| {
        if s.from == A && s.kind == Kind::Ping && d.get() == 0 {
            d.set(1);
            Fate::Drop
        } else {
            Fate::Deliver
        }
    });
    w.tick();
    w.pump();
    assert_eq!(dropped.get(), 1, "the confirming Ping was the first one lost");
    assert!(w.a.rpc.session_with(B).is_some_and(|s| s.state == State::Up), "A has the keys");
    assert!(w.b.rpc.session_with(A).is_none(), "B waits for the confirmation");
    w.run_for(300 * MS);
    assert!(w.b.rpc.session_with(A).is_some_and(|s| s.state == State::Up));
    assert_eq!(sid_of(&w), w.a.rpc.session_with(B).unwrap().id);
}

/// **A forged Bye does not break a session**: a Bye ends one only if it opens
/// under the session's keys.
///
/// **Canary.** Break the session on an unsealed Bye in `on_frame`: it goes.
#[test]
fn a_forged_bye_does_not_break_a_session() {
    let w = up();
    let id = sid(&w);
    let mut wb = w.borrow_mut();
    let World { b, .. } = &mut *wb;
    for tag in [0x00u8, 0xFF] {
        let mut bye = vec![tag; HEADER_BYTES + TAG_BYTES];
        put_header(&Header::new(Kind::Bye, id, 0, A, 1), &mut bye);
        b.rpc.on_frame(&mut b.asm, &bye);
    }
    assert!(b.rpc.session_with(A).is_some_and(|s| s.state == State::Up && s.id == id));
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
    // One byte more than the message cap leaves, and the tag after it.
    let body = vec![0x41u8; MSG_CAP - (FRAGS_MAX - 1) * FRAG_BODY + 1 + TAG_BYTES];
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
    // (A's engine says so itself: its Bye is sealed under the session's keys.)
    {
        let mut wb = w.borrow_mut();
        let si = (0..azos_rpc::MAX_SESSIONS).find(|&i| wb.a.rpc.session_with(B).is_some() && i == 0).unwrap();
        wb.a.rpc.break_session(si, true);
        wb.pump();
        assert!(wb.b.rpc.session_with(A).is_none(), "the session is broken");
    }
    let _ = id;
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
    let w = RefCell::new(World::with_cfg(&policy_a(), &policy_b(), |c| c.warrant_ttl_ns = 0));
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

/// **A call is served only with a warrant token that holds**: the request body
/// is the descriptor, then the token the sender started under the session key.
/// The serving node refuses a request with no token (`Malformed`), one whose
/// chain was started under another key or whose caveat was edited or dropped,
/// one issued for another interface, one narrowed to another node, one whose
/// op mask leaves no op, and one issued by the wrong node; the same request
/// with the token the sender makes is served. Nothing runs for a refusal.
///
/// **Canaries.** Skip `remint` in `serve_req`: every refusal row goes red (the
/// service runs). Make `remint` skip the chain check: the forged-key and the
/// widened rows go red. Drop the `NODE` check: the other-node row goes red.
#[test]
fn a_request_is_served_only_with_a_token_that_holds() {
    use azos_rpc::wire::{cav, Caveat, Token};
    let mut w = World::new();
    let mut f = Forger::dial(&mut w, A);
    let d = raw_req(ProbeIdl::ID, ProbeIdl::OP_READ, &[5]);
    let key = *f.chan.mac_key().unwrap();
    let sid = f.session;
    let mine = |iface: u32| Token::mint(&key, sid, A, iface);
    let to_b = |mut t: Token| {
        t.attenuate(Caveat::new(cav::NODE, u64::from(B))).unwrap();
        t
    };
    let send = |w: &mut World, f: &mut Forger, seq: u64, t: Option<Token>| {
        let mut body = vec![0u8; 512];
        let mut at = 0;
        put_desc(&d, &mut body, &mut at).unwrap();
        if let Some(t) = t {
            put_token(&t, &mut body, &mut at).unwrap();
        }
        let frames = f.seal(Kind::Req, seq, &body[..at]);
        f.status(w, &frames)
    };
    let refused = IdlError::Refused.status();
    let other_ep = [0x77u8; 32];
    let mut no_ops = to_b(mine(ProbeIdl::ID));
    no_ops.attenuate(Caveat::new(cav::OP_MASK, 0)).unwrap();
    let rows: Vec<(&str, Option<Token>, u64)> = vec![
        ("no token", None, IdlError::Malformed.status()),
        ("a chain started under another key", Some(to_b(Token::mint(&other_ep, sid, A, ProbeIdl::ID))), refused),
        ("another session's chain", Some(to_b(Token::mint(&key, sid ^ 1, A, ProbeIdl::ID))), refused),
        ("another interface", Some(to_b(mine(ProbeIdl::ID ^ 1))), refused),
        ("narrowed to another node", Some({
            let mut t = mine(ProbeIdl::ID);
            t.attenuate(Caveat::new(cav::NODE, 99)).unwrap();
            t
        }), refused),
        ("issued by B itself", Some(to_b(Token::mint(&key, sid, B, ProbeIdl::ID))), refused),
        ("an op mask that leaves no op", Some(no_ops), refused),
    ];
    for (k, (what, t, want)) in rows.into_iter().enumerate() {
        assert_eq!(send(&mut w, &mut f, 10 + k as u64, t), want, "{what}");
        assert_eq!(w.b.svc.borrow().reads, 0, "{what}: nothing ran");
    }
    // The token the sender makes is served, with or without more caveats.
    let t = f.token(ProbeIdl::ID);
    assert_eq!(send(&mut w, &mut f, 30, Some(t)), 0);
    assert_eq!(w.b.svc.borrow().reads, 1);
    let mut narrowed = f.token(ProbeIdl::ID);
    narrowed.attenuate(Caveat::new(cav::QUOTA, 5)).unwrap();
    assert_eq!(send(&mut w, &mut f, 31, Some(narrowed)), 0);
    assert_eq!(w.b.svc.borrow().reads, 2);
}

/// **The sender attaches the token:** a call through the stub is served by B, so
/// the token `begin` put in the request verified under the key the two
/// handshakes agreed (the warrant's TTL is pinned by the warrant test above).
///
/// **Canary.** Make `begin` skip `put_token`: the call comes back `Malformed`.
#[test]
fn a_stub_call_carries_a_token_b_accepts() {
    let w = up();
    assert_eq!(probe(&w).read(8), Ok(16));
    assert_eq!(w.borrow().b.svc.borrow().reads, 1);
}
