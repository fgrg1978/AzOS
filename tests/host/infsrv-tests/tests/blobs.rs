// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The blob arena is memory the system may take back between calls: the
//! service holds it while a call runs, parks it after, and when it finds it
//! gone makes it again from the signed bundles and goes on. The platform here
//! plays the kernel's side (`Host::blobs`): the tests say when the arena was
//! purged, and read what the service did to it.

use azos_devif::infer::{Done, InferCall, InferClient, Tensor};
use azos_devif::outcome::{self, Out};
use azos_idl::Cap;
use azos_infsrv_tests::*;
use infsrv::broker::Limits;
use std::cell::RefCell;

const BADGE: u32 = 0x77;
const STORAGE: usize = 64 * 1024;

fn call(c: &mut InferClient<Loopback<'_, '_>>, model_ref: u64, caps: (u32, u32)) -> Out<Done> {
    c.infer(model_ref, Cap::<Tensor>::from_raw(caps.0), Cap::<Tensor>::from_raw(caps.1), 0).expect("the call reached the service")
}

fn model_ref() -> u64 {
    let (file, _) = three();
    azos_devif::infer::model_ref(&azos_crypto::sha256::sha256(&file[..azos_ml::bundle::manifest_len(3)]))
}

/// A host whose rebuild reloads `three()` into `STORAGE` bytes, and the
/// storage the service starts with.
fn rig() -> (Host, Vec<u8>) {
    let host = Host::new();
    {
        let mut b = host.blobs.borrow_mut();
        b.bundles = vec![three()];
        b.storage = STORAGE;
    }
    (host, vec![0u8; STORAGE])
}

fn log(h: &Host) -> Vec<&'static str> {
    std::mem::take(&mut h.blobs.borrow_mut().log)
}

/// Every call that reads the arena holds it first and parks it after; one that
/// is refused before it needs the blobs (no badge) only parks, which a platform
/// answers without a call when the arena is already droppable.
///
/// **Canary.** Skip `blobs_park` in `Infer::infer`: the log has no `park`.
#[test]
fn a_call_holds_the_arena_and_parks_it() {
    let (host, mut storage) = rig();
    let svc = RefCell::new(service(&mut storage, &host, limits(), &[three()], None));
    let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 });
    let caps = host.tensors(10, &[1.0; 4]);
    assert_eq!(call(&mut c, model_ref(), caps).code, outcome::OK);
    assert_eq!(log(&host), ["resume", "park"]);

    let mut nobody = InferClient::new(Loopback { svc: &svc, badge: None, clock: 0 });
    let caps = host.tensors(12, &[1.0; 4]);
    assert_eq!(call(&mut nobody, model_ref(), caps).code, outcome::NO_RESOURCE);
    assert_eq!(log(&host), ["park"], "a call refused before it needs a blob does not hold the arena");
}

/// The arena was taken back while it was droppable: the call that finds out
/// loads the bundles into new storage, and runs. The contexts' accounts and the
/// journal are the broker's, not the arena's: the energy already spent in the
/// window is still spent (the next call is refused for it) and the receipt ids
/// go on counting.
///
/// **Canary.** Make `Broker::forget_models` also clear the ledger: the second
/// call runs (its quota came back) instead of being refused.
#[test]
fn a_purged_arena_is_rebuilt_and_the_accounts_survive() {
    let (host, mut storage) = rig();
    let lim = Limits { quota_uj: 400, ..limits() };
    let svc = RefCell::new(service(&mut storage, &host, lim, &[three()], None));
    let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 });

    // Variant 1 takes the whole quota; its admission is receipt 1.
    let caps = host.tensors(10, &[0.8, 0.3, 0.5, 0.9]);
    let first = call(&mut c, model_ref(), caps);
    assert_eq!((first.code, first.value.variant_id), (outcome::OK, 1));
    assert_eq!(svc.borrow().broker.journal.total(), 1);
    log(&host);

    // The system takes the arena back. The call is the quota's refusal (receipt
    // 2), and only after the models were made again, which the log shows.
    host.blobs.borrow_mut().purged = true;
    let caps = host.tensors(12, &[1.0; 4]);
    assert_eq!(call(&mut c, model_ref(), caps).code, outcome::REFUSED);
    assert_eq!(log(&host), ["resume", "rebuild", "park"]);
    assert_eq!(svc.borrow().broker.journal.total(), 2, "the journal went on, it was not started again");

    // A fresh context runs on the rebuilt arena and answers what the model does.
    let mut other = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE + 1), clock: 0 });
    let x = [0.8f32, 0.3, 0.5, 0.9];
    let caps = host.tensors(14, &x);
    let out = call(&mut other, model_ref(), caps);
    assert_eq!((out.code, out.value.variant_id), (outcome::OK, 1));
    assert_eq!(host.output(caps.1, 2), model_answer(x), "the blob read is the one loaded again");
    assert_eq!(log(&host), ["resume", "park"], "kept again: no second rebuild");
}

/// Getting the blobs back is time the caller's deadline pays for: the budget is
/// read after it. A call 1 ms from its deadline that finds the arena gone and
/// spends 900 us making it again has 100 us left, which no variant (300 us at
/// best) fits: it is refused now, with a receipt. The same call with the arena
/// kept runs.
///
/// **Canary.** Read the clock before `resume_blobs` in `run_call`: the purged
/// call runs, and the refusal row is red.
#[test]
fn the_rebuild_is_out_of_the_callers_deadline() {
    let (host, mut storage) = rig();
    let svc = RefCell::new(service(&mut storage, &host, limits(), &[three()], None));
    let ask = |base: u32| {
        let now = host.now.get();
        let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 }).with_deadline(now + 1_000_000);
        let caps = host.tensors(base, &[1.0; 4]);
        call(&mut c, model_ref(), caps)
    };
    assert_eq!(ask(10).code, outcome::OK, "kept: 1 ms is enough for variant 2");

    host.blobs.borrow_mut().rebuild_ns = 900_000;
    host.blobs.borrow_mut().purged = true;
    assert_eq!(ask(12).code, outcome::REFUSED, "900 us of rebuild leave 100 us");
    assert_eq!(ask(14).code, outcome::OK, "the arena is back: the next call pays nothing");
}

/// A rebuild that finds no storage leaves no model, and the call is told so
/// (`NO_RESOURCE`) instead of reading a span of the storage that is gone. The
/// next call tries again and, with storage, runs.
///
/// **Canary.** Skip `broker.forget_models()` in `resume_blobs`: the first call
/// finds the old model and reads a blob of an arena that is empty.
#[test]
fn no_storage_means_no_model_not_a_stale_read() {
    let (host, mut storage) = rig();
    let svc = RefCell::new(service(&mut storage, &host, limits(), &[three()], None));
    let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 });
    {
        let mut b = host.blobs.borrow_mut();
        b.purged = true;
        b.storage = 0;
    }
    let caps = host.tensors(10, &[1.0; 4]);
    assert_eq!(call(&mut c, model_ref(), caps).code, outcome::NO_RESOURCE);
    assert_eq!(svc.borrow().arena.free(), 0, "no storage behind the arena");

    host.blobs.borrow_mut().purged = true;
    host.blobs.borrow_mut().storage = STORAGE;
    let caps = host.tensors(12, &[1.0; 4]);
    assert_eq!(call(&mut c, model_ref(), caps).code, outcome::OK);
}

/// The Domain's pressure rose: the call that sees it still answers from the
/// arena it holds, and then gives the arena back instead of parking it. The
/// next call rebuilds it (once), and the ones after it keep it: a rise is
/// reported once, so a level that stays up does not make every call load the
/// bundles again.
///
/// **Canary.** Ignore `pressure_rose` in `Infer::infer`: the first call parks,
/// and the log has no `give-back`.
#[test]
fn a_rise_in_pressure_gives_the_arena_back_once() {
    let (host, mut storage) = rig();
    let svc = RefCell::new(service(&mut storage, &host, limits(), &[three()], None));
    let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 });
    let x = [0.8f32, 0.3, 0.5, 0.9];

    host.blobs.borrow_mut().pressure_rose = true;
    let caps = host.tensors(10, &x);
    assert_eq!(call(&mut c, model_ref(), caps).code, outcome::OK, "the call that saw the rise ran");
    assert_eq!(host.output(caps.1, 2), model_answer(x));
    assert_eq!(log(&host), ["resume", "give-back"]);
    assert_eq!(svc.borrow().arena.free(), 0, "the arena is empty: nothing may read the storage that went");

    let caps = host.tensors(12, &x);
    assert_eq!(call(&mut c, model_ref(), caps).code, outcome::OK);
    assert_eq!(host.output(caps.1, 2), model_answer(x));
    assert_eq!(log(&host), ["resume", "rebuild", "park"], "the next call loads the bundles again");

    let caps = host.tensors(14, &x);
    assert_eq!(call(&mut c, model_ref(), caps).code, outcome::OK);
    assert_eq!(log(&host), ["resume", "park"], "no rise since: kept");
}
