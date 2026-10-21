// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The endpoint end to end, in one process: the generated client stubs on one
//! side of a loopback, the real dispatchers and the service on the other, host
//! memory under the tensors. A call runs the model, a call that cannot make its
//! deadline is refused now with a receipt that reads back through the
//! `Decisions` object, and the verdict of each call is in the log a reader polls
//! with no call.

use azos_abi::ipc_msg::{CAP_MODE_DUP, MSG_BADGED};
use azos_decision::{Rule, Verdict as Decision};
use azos_decisions::{fetch, list, DecisionsClient, Filter};
use azos_devif::infer::{Arena, CmdQueue, DoneQueue, Done, InferCall, InferClient, Tensor};
use azos_devif::outcome::{self, Out};
use azos_idl::{Cap, IdlError, MsgDesc};
use azos_infsrv_tests::*;
use infsrv::broker::{reason, Limits};
use infsrv::config::CONTEXTS;
use infsrv::service::{InferLogCall, InferLogClient, LOG_ID};
use infsrv::verdict::{LogReader, Publisher, Verdict};
use std::cell::RefCell;

const BADGE: u32 = 0x77;

struct Rig {
    host: Host,
    arena: Vec<u8>,
}

fn rig() -> Rig {
    Rig { host: Host::new(), arena: vec![0u8; 64 * 1024] }
}

fn call(c: &mut InferClient<Loopback<'_, '_>>, model_ref: u64, caps: (u32, u32), hint: u32) -> Out<Done> {
    c.infer(model_ref, Cap::<Tensor>::from_raw(caps.0), Cap::<Tensor>::from_raw(caps.1), hint).expect("the call reached the service")
}

fn model_ref() -> u64 {
    let (file, _) = three();
    let d = azos_crypto::sha256::sha256(&file[..azos_ml::bundle::manifest_len(3)]);
    azos_devif::infer::model_ref(&d)
}

/// A call runs the first variant of the publisher's list, writes the model's
/// answer, and reports which variant ran, where and at what cost; both tensors
/// are given back.
///
/// **Canary.** Answer `energy_uj: 0`: the cost row is red.
#[test]
fn a_call_runs_the_model_and_answers_the_cost() {
    let mut r = rig();
    let b = three();
    let svc = RefCell::new(service(&mut r.arena, &r.host, limits(), &[b], None));
    let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 });
    r.host.run_ns.set(450_000);
    let x = [0.8f32, 0.3, 0.5, 0.9];
    let caps = r.host.tensors(10, &x);
    let out = call(&mut c, model_ref(), caps, 0);
    assert_eq!(
        out,
        Out::ok(Done { model_hash: model_ref(), variant_id: 1, backend: 1, latency_us: 450, energy_uj: 400 })
    );
    assert_eq!(r.host.output(caps.1, 2), model_answer(x));
    assert_eq!(*r.host.released.borrow(), [10, 11], "both tensors were given back");
}

/// The deadline travels in the message and picks the variant: a client that
/// sets one 1 ms away gets the 800 us variant, 400 us away the 300 us one, and
/// 200 us away is refused now: nothing ran, the output is untouched, and the
/// tensors are given back.
///
/// **Canary.** Read the deadline as relative instead of absolute in `infer`:
/// the 1 ms row takes id 1.
#[test]
fn the_deadline_in_the_message_picks_the_variant_and_a_miss_is_refused_now() {
    let mut r = rig();
    let b = three();
    let svc = RefCell::new(service(&mut r.arena, &r.host, limits(), &[b], None));
    let now = r.host.now.get();
    let rig_call = |rest_ns: u64, base: u32| {
        let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 }).with_deadline(now + rest_ns);
        let caps = r.host.tensors(base, &[1.0, 1.0, 0.0, 0.0]);
        (call(&mut c, model_ref(), caps, 0), caps)
    };
    assert_eq!(rig_call(1_000_000, 10).0.value.variant_id, 2);
    assert_eq!(rig_call(400_000, 12).0.value.variant_id, 3);
    let (out, caps) = rig_call(200_000, 14);
    assert_eq!(out, Out::err(outcome::REFUSED));
    assert_eq!(r.host.output(caps.1, 1)[0].to_bits(), 0xEEEE_EEEE, "the output was not touched");
    assert!(r.host.released.borrow().ends_with(&[14, 15]));
    // A deadline that has already passed is the same.
    let (out, _) = rig_call(0, 16);
    assert_eq!(out.code, outcome::REFUSED);
    let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 }).with_deadline(now - 1);
    let caps = r.host.tensors(18, &[1.0; 4]);
    assert_eq!(call(&mut c, model_ref(), caps, 0).code, outcome::REFUSED);
}

/// A run that overran its signed worst case reports the overrun's energy on
/// top, in the answer and in the verdict.
#[test]
fn an_overrun_is_in_the_answer_and_the_verdict() {
    let mut r = rig();
    let b = three();
    let (publisher, regions) = shared_regions();
    let svc = RefCell::new(service(&mut r.arena, &r.host, limits(), &[b], Some(publisher)));
    // Id 3: wcet 300 us, 40 uJ. It takes 450 us.
    r.host.run_ns.set(450_000);
    let caps = r.host.tensors(10, &[1.0; 4]);
    let now = r.host.now.get();
    let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 }).with_deadline(now + 400_000);
    let out = call(&mut c, model_ref(), caps, 0);
    // 150 us over 300 at 40 uJ per 300 us = 20 uJ.
    assert_eq!((out.value.variant_id, out.value.latency_us, out.value.energy_uj), (3, 450, 60));
    // SAFETY: the region of the caller's context; the writer is the service.
    let ctx = svc.borrow_mut().broker.context(BADGE).unwrap();
    let reader = unsafe { LogReader::open(regions[ctx].0, regions[ctx].1) }.unwrap();
    let (seq, v) = reader.latest();
    assert_eq!(seq, 1);
    assert_eq!((v.code, v.variant_id, v.latency_us, v.energy_uj, v.overrun_us), (outcome::OK, 3, 450, 60, 150));
}

/// Every call leaves its verdict in the log of its context, and a reader that
/// holds the region reads it with no call: the refusal's code, the reason, and
/// the receipt, which is a record of Rule `accel-admission` that reads back
/// through the `Decisions` object of the same endpoint.
///
/// **Canary.** Publish nothing on a refusal: the refusal row here is red.
#[test]
fn the_verdict_log_holds_the_latest_verdict_and_its_receipt_reads_back() {
    let mut r = rig();
    let b = three();
    let (publisher, regions) = shared_regions();
    let svc = RefCell::new(service(&mut r.arena, &r.host, limits(), &[b], Some(publisher)));
    let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 });
    let ctx = svc.borrow_mut().broker.context(BADGE).unwrap();
    // SAFETY: a mapping of the same region, read only through `latest`.
    let reader = unsafe { LogReader::open(regions[ctx].0, regions[ctx].1) }.expect("the region is a verdict log");
    assert_eq!(reader.latest(), (0, Verdict::default()), "nothing yet");

    let caps = r.host.tensors(10, &[1.0; 4]);
    assert!(call(&mut c, model_ref(), caps, 0).is_ok());
    let (seq, v) = reader.latest();
    assert_eq!((seq, v.code, v.variant_id, v.backend, v.reason, v.model_ref), (1, outcome::OK, 1, 1, 0, model_ref()));
    assert!(v.receipt != 0, "the first call chose a variant: that is recorded");

    // The next call is refused.
    let now = r.host.now.get();
    let mut tight = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 }).with_deadline(now + 100_000);
    let caps = r.host.tensors(12, &[1.0; 4]);
    assert_eq!(call(&mut tight, model_ref(), caps, 0).code, outcome::REFUSED);
    let (seq, v) = reader.latest();
    assert_eq!((seq, v.code, v.reason, v.latency_us, v.energy_uj), (2, outcome::REFUSED, reason::DEADLINE, 0, 0));
    assert!(v.receipt != 0);

    // The receipt, through the Decisions object.
    let d = DecisionsClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 });
    let rec = fetch(&d, v.receipt).unwrap().expect("the record is held");
    assert_eq!((rec.rule, rec.verdict, rec.subject, rec.seq), (Rule::AccelAdmission as u8, Decision::Refuse as u8, BADGE, v.receipt));
    assert_eq!(rec.image_hash_prefix, model_ref());
    let mut ids = [0u64; 8];
    let (n, total) = list(&d, &Filter { verdict: Some(Decision::Refuse as u8), ..Filter::ANY }, &mut ids).unwrap();
    assert_eq!((n, total, ids[0]), (1, 2, v.receipt));
    assert!(fetch(&d, 99).unwrap().is_none());
}

/// Another context has a log object of its own; one context's verdicts do not
/// show in another's.
///
/// **Canary.** Publish every verdict to slot 0: the second context's object
/// shows the first's call.
#[test]
fn each_context_reads_its_own_object() {
    let mut r = rig();
    let b = three();
    let (publisher, regions) = shared_regions();
    let svc = RefCell::new(service(&mut r.arena, &r.host, limits(), &[b], Some(publisher)));
    let mut a = InferClient::new(Loopback { svc: &svc, badge: Some(1), clock: 0 });
    let mut b = InferClient::new(Loopback { svc: &svc, badge: Some(2), clock: 0 });
    let caps = r.host.tensors(10, &[1.0; 4]);
    assert!(call(&mut a, model_ref(), caps, 0).is_ok());
    let (sa, sb) = {
        let mut s = svc.borrow_mut();
        (s.broker.context(1).unwrap(), s.broker.context(2).unwrap())
    };
    assert!(sa != sb);
    // SAFETY: the regions are the service's objects, read only through `latest`.
    let (ra, rb) = unsafe {
        (LogReader::open(regions[sa].0, regions[sa].1).unwrap(), LogReader::open(regions[sb].0, regions[sb].1).unwrap())
    };
    assert_eq!(ra.latest().0, 1);
    assert_eq!(rb.latest().0, 0, "the other context has no verdict yet");
    let caps = r.host.tensors(12, &[1.0; 4]);
    assert!(call(&mut b, model_ref(), caps, 0).is_ok());
    assert_eq!((ra.latest().0, rb.latest().0), (1, 1));
}

/// The lease: `log` lends the caller's own object (read and map, as a
/// duplicate), a different capability for each context; a call through no
/// badge, a service with no log and a full context table are each told so.
///
/// **Canary.** Lend the object of slot 0 whoever asks: the two contexts get the
/// same capability.
#[test]
fn the_log_lease_lends_the_contexts_own_object_read_only() {
    let mut r = rig();
    let b = three();
    r.host.log.set(Some(55));
    let svc = RefCell::new(service(&mut r.arena, &r.host, limits(), &[b], None));
    let mut log = InferLogClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 });
    let out = log.log().unwrap();
    assert!(out.is_ok());
    let mine = svc.borrow_mut().broker.context(BADGE).unwrap() as u32;
    assert_eq!((out.value.bytes, out.value.region.get().map(|c| c.raw())), (4096, Some(55 + mine)));

    // Another badge is lent another object.
    let mut other = InferLogClient::new(Loopback { svc: &svc, badge: Some(BADGE + 1), clock: 0 });
    let theirs = svc.borrow_mut().broker.context(BADGE + 1).unwrap() as u32;
    assert!(theirs != mine);
    assert_eq!(other.log().unwrap().value.region.get().map(|c| c.raw()), Some(55 + theirs));

    // What the kernel is asked to do with the entry: duplicate it with READ and
    // MAP, nothing else.
    let mut rep = MsgDesc::default();
    svc.borrow_mut().handle(&raw_request(LOG_ID, 1, Some(BADGE)), &mut rep);
    assert_eq!(rep.n_caps, 1);
    assert_eq!((rep.caps[0].handle, rep.caps[0].mode, rep.caps[0].rights), (55 + mine, CAP_MODE_DUP, 0b10_0001));

    // No badge: no context.
    let mut anon = InferLogClient::new(Loopback { svc: &svc, badge: None, clock: 0 });
    assert_eq!(anon.log().unwrap().code, outcome::NO_RESOURCE);
    // No log made.
    r.host.log.set(None);
    assert_eq!(log.log().unwrap().code, outcome::NOT_READY);
    // A full table of other badges.
    r.host.log.set(Some(55));
    for badge in 0..CONTEXTS as u32 {
        let _ = InferLogClient::new(Loopback { svc: &svc, badge: Some(1000 + badge), clock: 0 }).log().unwrap();
    }
    let mut late = InferLogClient::new(Loopback { svc: &svc, badge: Some(9999), clock: 0 });
    assert_eq!(late.log().unwrap().code, outcome::BUSY);
}

/// A context's log object is made when it first asks for its lease, not at
/// start: until then the service holds none for it (the system-wide table of
/// memory objects is small; eight made at start filled it and the shell's
/// pipes were refused), and its verdicts are published once it has one. A
/// second ask lends the same object and makes none.
///
/// **Canary.** Do not give the fresh object to the publisher: the verdict
/// after the lease is not in the log.
#[test]
fn a_contexts_log_is_made_on_its_first_ask() {
    let mut r = rig();
    let b = three();
    *r.host.lazy.borrow_mut() = lazy_regions();
    let regions = r.host.lazy.borrow().clone();
    let svc = RefCell::new(service(&mut r.arena, &r.host, limits(), &[b], Some(Publisher::new())));
    let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 });
    let caps = r.host.tensors(10, &[1.0; 4]);
    assert!(call(&mut c, model_ref(), caps, 0).is_ok());
    assert!(r.host.made.borrow().is_empty(), "a call makes no log object");

    let mut log = InferLogClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 });
    let ctx = svc.borrow_mut().broker.context(BADGE).unwrap();
    let out = log.log().unwrap();
    assert!(out.is_ok());
    assert_eq!(out.value.region.get().map(|c| c.raw()), Some(LAZY_CAP + ctx as u32));
    assert_eq!(*r.host.made.borrow(), vec![ctx]);
    // SAFETY: the region the service was handed, read only through `latest`.
    let reader = unsafe { LogReader::open(regions[ctx].0, regions[ctx].1) }.expect("the service made it a verdict log");
    assert_eq!(reader.latest().0, 0, "the call before the lease was published nowhere");

    let caps = r.host.tensors(12, &[1.0; 4]);
    assert!(call(&mut c, model_ref(), caps, 0).is_ok());
    assert_eq!(reader.latest().0, 1);
    // The same object again; nothing made.
    assert_eq!(log.log().unwrap().value.region.get().map(|c| c.raw()), Some(LAZY_CAP + ctx as u32));
    assert_eq!(r.host.made.borrow().len(), 1);
}

/// The receipts are the context's own: a client lists and fetches the records
/// of its badge, and neither lists nor fetches another's (the id of a record of
/// another context answers as if it were not held), and the count it is told is
/// its own. A call with no badge reads nothing.
///
/// **Canary.** Serve the whole journal to every caller (the view ignores the
/// badge): the second context lists the first's refusal.
#[test]
fn a_context_reads_only_its_own_receipts() {
    let mut r = rig();
    let b = three();
    let svc = RefCell::new(service(&mut r.arena, &r.host, limits(), &[b], None));
    let now = r.host.now.get();
    // Context 1 is refused twice (a deadline nothing makes), context 2 once.
    let mut ids = [Vec::new(), Vec::new()];
    for (who, badge) in [(0usize, 1u32), (0, 1), (1, 2)] {
        let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(badge), clock: 0 }).with_deadline(now + 100_000);
        let caps = r.host.tensors(10 + 2 * ids[0].len() as u32 + 4 * ids[1].len() as u32, &[1.0; 4]);
        assert_eq!(call(&mut c, model_ref(), caps, 0).code, outcome::REFUSED);
        let d = DecisionsClient::new(Loopback { svc: &svc, badge: Some(badge), clock: 0 });
        let mut got = [0u64; 8];
        let (n, _) = list(&d, &Filter::ANY, &mut got).unwrap();
        ids[who].push(got[n - 1]);
    }
    let d1 = DecisionsClient::new(Loopback { svc: &svc, badge: Some(1), clock: 0 });
    let d2 = DecisionsClient::new(Loopback { svc: &svc, badge: Some(2), clock: 0 });
    let mut got = [0u64; 8];
    let (n, total) = list(&d1, &Filter::ANY, &mut got).unwrap();
    assert_eq!((n, total, &got[..n]), (2, 2, &ids[0][..]));
    let (n, total) = list(&d2, &Filter::ANY, &mut got).unwrap();
    assert_eq!((n, total, &got[..n]), (1, 1, &ids[1][..]));
    // A filter naming another subject cannot widen the view.
    let (n, _) = list(&d2, &Filter { subject: Some(1), ..Filter::ANY }, &mut got).unwrap();
    assert_eq!(n, 0);
    // The id of another's record is not held, as far as this caller can tell.
    assert!(fetch(&d2, ids[0][0]).unwrap().is_none());
    assert_eq!(fetch(&d2, ids[1][0]).unwrap().map(|p| p.subject), Some(2));
    // No badge, no receipts.
    let anon = DecisionsClient::new(Loopback { svc: &svc, badge: None, clock: 0 });
    assert_eq!(list(&anon, &Filter::ANY, &mut got).unwrap().0, 0);
    assert!(fetch(&anon, ids[0][0]).unwrap().is_none());
}

/// The quota of a context is spent by runs, not by calls that did not run: a
/// tensor that is too small, an output that is read-only and a capability that
/// maps to nothing each answer `BAD_ARGUMENT`, give their reservation back, and
/// leave the context with all of its quota.
///
/// **Canary.** Settle every run as having happened, whatever the tensors did:
/// the final call is refused.
#[test]
fn a_call_with_bad_tensors_costs_no_quota() {
    let mut r = rig();
    let b = three();
    let lim = Limits { quota_uj: 400, ..limits() };
    let svc = RefCell::new(service(&mut r.arena, &r.host, lim, &[b], None));
    let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 });

    // Too small: 8 bytes for a 16-byte input.
    {
        let mut m = r.host.mem.borrow_mut();
        m.insert(10, Region { bytes: vec![0; 8], writable: false });
        m.insert(11, Region { bytes: vec![0; PAGE], writable: true });
    }
    assert_eq!(call(&mut c, model_ref(), (10, 11), 0).code, outcome::BAD_ARGUMENT);
    // Output read-only.
    {
        let mut m = r.host.mem.borrow_mut();
        m.insert(12, Region { bytes: vec![0; PAGE], writable: false });
        m.insert(13, Region { bytes: vec![0; PAGE], writable: false });
    }
    assert_eq!(call(&mut c, model_ref(), (12, 13), 0).code, outcome::BAD_ARGUMENT);
    // Not memory at all.
    assert_eq!(call(&mut c, model_ref(), (14, 15), 0).code, outcome::BAD_ARGUMENT);
    // All 400 are still there.
    let caps = r.host.tensors(20, &[1.0; 4]);
    let ok = call(&mut c, model_ref(), caps, 0);
    assert_eq!((ok.code, ok.value.variant_id), (outcome::OK, 1));
}

/// What cannot be served is refused before anything runs, and what the call
/// moved is given back: no badge (`NO_RESOURCE`), a model nobody holds
/// (`NO_RESOURCE`, and no decision record), a hint the interface does not
/// define and a clock the kernel does not serve (`BAD_ARGUMENT`).
///
/// **Canary.** Skip `drop_cap` in `refused`: the released-list rows are red.
#[test]
fn what_cannot_be_served_is_refused_and_gives_its_capabilities_back() {
    let mut r = rig();
    let b = three();
    let svc = RefCell::new(service(&mut r.arena, &r.host, limits(), &[b], None));
    let at = |badge, clock| InferClient::new(Loopback { svc: &svc, badge, clock });

    let caps = r.host.tensors(10, &[1.0; 4]);
    assert_eq!(call(&mut at(None, 0), model_ref(), caps, 0).code, outcome::NO_RESOURCE);
    assert_eq!(*r.host.released.borrow(), [10, 11]);
    let caps = r.host.tensors(12, &[1.0; 4]);
    assert_eq!(call(&mut at(Some(1), 0), model_ref() ^ 1, caps, 0).code, outcome::NO_RESOURCE);
    assert_eq!(svc.borrow().broker.journal.total(), 0, "an unknown model is no decision");
    let caps = r.host.tensors(14, &[1.0; 4]);
    assert_eq!(call(&mut at(Some(1), 0), model_ref(), caps, 2).code, outcome::BAD_ARGUMENT);
    let caps = r.host.tensors(16, &[1.0; 4]);
    assert_eq!(call(&mut at(Some(1), 1), model_ref(), caps, 0).code, outcome::BAD_ARGUMENT);
    assert_eq!(*r.host.released.borrow(), [10, 11, 12, 13, 14, 15, 16, 17]);
    assert_eq!(svc.borrow().broker.journal.total(), 0, "nothing was admitted or refused");
}

/// The accelerator form of the interface is not driven by this service: `attach`
/// says `UNSUPPORTED` and gives the three objects back; `detach`, with nothing
/// attached, has nothing to stop.
#[test]
fn the_queue_form_is_unsupported_and_gives_its_objects_back() {
    let mut r = rig();
    let b = three();
    let svc = RefCell::new(service(&mut r.arena, &r.host, limits(), &[b], None));
    let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 });
    let out = c.attach(Cap::<CmdQueue>::from_raw(30), Cap::<DoneQueue>::from_raw(31), Cap::<Arena>::from_raw(32)).unwrap();
    assert_eq!(out.code, outcome::UNSUPPORTED);
    assert_eq!(*r.host.released.borrow(), [30, 31, 32]);
    assert!(c.detach().unwrap().is_ok());
}

/// A request for an interface the endpoint does not serve, or for an op that
/// does not exist, is answered with the IDL's own status, not served.
#[test]
fn a_foreign_interface_or_op_is_answered_with_a_status() {
    let mut r = rig();
    let b = three();
    let svc = RefCell::new(service(&mut r.arena, &r.host, limits(), &[b], None));
    let mut rep = MsgDesc::default();
    svc.borrow_mut().handle(&raw_request(0xDEAD_0001, 1, Some(BADGE)), &mut rep);
    assert_eq!(rep.words[0], IdlError::BadInterface.status());
    svc.borrow_mut().handle(&raw_request(azos_devif::infer::INFER_ID, 99, Some(BADGE)), &mut rep);
    assert_eq!(rep.words[0], IdlError::BadOp.status());
    // A message with no words at all.
    svc.borrow_mut().handle(&MsgDesc { version: azos_abi::ipc_msg::MSG_VERSION, flags: MSG_BADGED, ..MsgDesc::default() }, &mut rep);
    assert!(rep.words[0] != 0);
}
