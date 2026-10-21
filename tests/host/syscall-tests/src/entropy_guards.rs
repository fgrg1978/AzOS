// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the kernel-hosted `Entropy` interface (wave 9 P9, an endpoint
// op since D6 part A) -- `crates/core/syscall/src/entropy.rs::Server`, and
// `crates/core/syscall/src/khost.rs::serve` in front of it.
//
// Included inside `mod handlers { .. }` like `link_key_guards.rs`, and reaches
// the server through `crate::entropy::...` for the same reason that file
// gives.
//
// Every test counts the fill hook's calls, so "refused before the pool was
// touched" is asserted, not inferred from the outcome.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_devif::{key, outcome, Entropy, EntropyIdl, Out};
use azos_devif::entropy::DRAW_WORDS;
use azos_idl::{header, MsgDesc, Writer, MSG_VERSION};
use crate::khost::Caller;
use std::sync::atomic::{AtomicU32, Ordering};

/// Cap-store pool slot for this file; no other file in this crate binds 44.
const SLOT: usize = 44;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e40_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

static FILLS: AtomicU32 = AtomicU32::new(0);
static RECORDED: AtomicU32 = AtomicU32::new(0);
static RECORDED_TID: AtomicU32 = AtomicU32::new(0);

/// A seeded pool: byte `i` is `0xA0 ^ i`.
fn seeded_fill(out: &mut [u8]) -> bool {
    FILLS.fetch_add(1, Ordering::SeqCst);
    for (i, b) in out.iter_mut().enumerate() {
        *b = 0xA0 ^ (i as u8);
    }
    true
}

/// An unseeded pool: writes nothing, refuses.
fn unseeded_fill(_out: &mut [u8]) -> bool {
    FILLS.fetch_add(1, Ordering::SeqCst);
    false
}

/// A fill that wrote a prefix and then refused (`Pool::fill` across the
/// reseed interval). Nothing it wrote may reach the caller.
fn partial_fill(out: &mut [u8]) -> bool {
    FILLS.fetch_add(1, Ordering::SeqCst);
    for b in out.iter_mut() {
        *b = 0x5A;
    }
    false
}

fn recorder(tid: u32) {
    RECORDED.fetch_add(1, Ordering::SeqCst);
    RECORDED_TID.store(tid, Ordering::SeqCst);
}

fn setup(fill: Option<fn(&mut [u8]) -> bool>) -> u32 {
    crate::entropy::__entropy_clear_for_tests();
    FILLS.store(0, Ordering::SeqCst);
    RECORDED.store(0, Ordering::SeqCst);
    RECORDED_TID.store(0, Ordering::SeqCst);
    if let Some(f) = fill {
        crate::entropy::set_entropy_hooks(f, recorder);
    }
    let tid = fresh_tid();
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0);
    azos_sched::set_current_task_tid(tid);
    tid
}

/// The server for a caller holding `rights` on the endpoint (badge 0).
fn server(tid: u32, rights: CapPerms) -> crate::entropy::Server {
    crate::entropy::Server(Caller { tid, badge: 0, rights })
}

/// The bytes a draw's words are.
fn bytes(w: &[u64]) -> Vec<u8> {
    w.iter().flat_map(|x| x.to_le_bytes()).collect()
}

/// A holder with `READ` on a seeded pool gets exactly the bytes the pool
/// produced, in little-endian words, and the rest of the reply is zero.
///
/// **Canary.** Copy `buf[..len]` after the wipe instead of before it: the
/// byte assertion reads zeros.
#[test]
fn seeded_pool_fills_the_words() {
    let _g = serial();
    let tid = setup(Some(seeded_fill));
    let out = server(tid, CapPerms::READ).draw(4);
    assert!(out.is_ok());
    for (i, b) in bytes(&out.value[..4]).iter().enumerate() {
        assert_eq!(*b, 0xA0 ^ (i as u8), "byte {i} is not the pool's");
    }
    assert_eq!(out.value[4..], [0, 0], "words past the request are zero");
    assert_eq!(FILLS.load(Ordering::SeqCst), 1);
    assert_eq!(RECORDED.load(Ordering::SeqCst), 0, "a successful read records nothing");
    crate::entropy::__entropy_clear_for_tests();
}

/// The bound is inclusive at `DRAW_WORDS` and refuses one past it and zero,
/// without touching the pool.
///
/// **Canary.** Change the bound to `>=`: the full draw answers `BAD_ARGUMENT`.
#[test]
fn length_bound_is_checked_before_the_pool() {
    let _g = serial();
    let tid = setup(Some(seeded_fill));
    let mut s = server(tid, CapPerms::READ);
    assert!(s.draw(DRAW_WORDS as u32).is_ok());
    assert_eq!(FILLS.load(Ordering::SeqCst), 1);
    assert_eq!(s.draw(DRAW_WORDS as u32 + 1).code, outcome::BAD_ARGUMENT);
    assert_eq!(s.draw(0).code, outcome::BAD_ARGUMENT);
    assert_eq!(FILLS.load(Ordering::SeqCst), 1, "no refused length may reach the pool");
    crate::entropy::__entropy_clear_for_tests();
}

/// A capability without `READ` (none, or `WRITE` alone: the other op
/// classes) is refused before the pool.
///
/// **Canary.** Skip the `allows` check: the `WRITE`-only caller reads words.
#[test]
fn the_right_is_checked_first() {
    let _g = serial();
    let tid = setup(Some(seeded_fill));
    for rights in [CapPerms::NONE, CapPerms::WRITE, CapPerms::EXEC] {
        let out = server(tid, rights).draw(2);
        assert_eq!(out, Out::err(outcome::DENIED), "{rights:?}");
    }
    assert_eq!(FILLS.load(Ordering::SeqCst), 0, "a refused capability must not reach the pool");
    crate::entropy::__entropy_clear_for_tests();
}

/// An unseeded pool answers `NOT_READY`, writes nothing, and the FIRST
/// refusal of the boot -- only the first -- goes to the recorder, with the
/// caller's TID. Every refusal is counted.
///
/// **Canary.** Drop the `REFUSAL_RECORDED` swap: `RECORDED` reads 3.
/// Answer `BUSY` instead: the first assertion fails.
#[test]
fn unseeded_pool_refuses_and_records_once() {
    let _g = serial();
    let tid = setup(Some(unseeded_fill));
    let mut s = server(tid, CapPerms::READ);
    for _ in 0..3 {
        assert_eq!(s.draw(4), Out::err(outcome::NOT_READY));
    }
    assert_eq!(RECORDED.load(Ordering::SeqCst), 1, "one record per boot, not one per call");
    assert_eq!(RECORDED_TID.load(Ordering::SeqCst), tid, "the record names the caller");
    assert_eq!(crate::entropy::entropy_refusals(), 3, "every refusal is counted");
    crate::entropy::__entropy_clear_for_tests();
}

/// A fill that wrote a prefix and then refused leaks none of it.
///
/// **Canary.** Copy the words out before the `got` check: the caller sees 0x5A.
#[test]
fn a_partial_fill_leaks_nothing() {
    let _g = serial();
    let tid = setup(Some(partial_fill));
    let out = server(tid, CapPerms::READ).draw(6);
    assert_eq!(out, Out::err(outcome::NOT_READY));
    assert!(out.value.iter().all(|w| *w == 0));
    crate::entropy::__entropy_clear_for_tests();
}

/// No fill hook installed fails CLOSED, as an unseeded pool.
///
/// **Canary.** Answer a draw when the hook is `None`: this reads OK.
#[test]
fn no_hook_fails_closed() {
    let _g = serial();
    let tid = setup(None);
    assert_eq!(server(tid, CapPerms::READ).draw(2), Out::err(outcome::NOT_READY));
    assert_eq!(crate::entropy::entropy_refusals(), 1);
    crate::entropy::__entropy_clear_for_tests();
}

/// The wire: a request in the IDL's form, served through `khost::serve` by
/// host key, comes back as the generated client reads it; an unknown key is
/// the IDL's bad-interface status, not silence.
///
/// **Canary.** Route `key::ENTROPY` to the wrong arm: the status word is not 0.
#[test]
fn served_through_the_host_key_over_the_wire() {
    let _g = serial();
    let tid = setup(Some(seeded_fill));
    let who = Caller { tid, badge: 0, rights: CapPerms::READ };
    let mut req = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    {
        let mut w = Writer::new(&mut req);
        w.word(header(EntropyIdl::ID, EntropyIdl::LEVEL, EntropyIdl::OP_DRAW));
        w.word(2);
        w.finish();
    }
    let mut rep = MsgDesc::default();
    crate::khost::serve(key::ENTROPY, &who, &req, &mut rep);
    assert_eq!(rep.words[0], azos_idl::STATUS_OK);
    assert_eq!(rep.words[1] as u32, outcome::OK);
    assert_eq!(bytes(&rep.words[2..4])[0], 0xA0);

    // The register form pads the request to four words; the decoder takes it.
    let regs = crate::khost::serve_regs(key::ENTROPY, &who, [req.words[0], 1, 0, 0]);
    assert_eq!((regs[0], regs[1] as u32), (azos_idl::STATUS_OK, outcome::OK));

    let mut rep = MsgDesc::default();
    crate::khost::serve(0x7000, &who, &req, &mut rep);
    assert_ne!(rep.words[0], azos_idl::STATUS_OK, "an unhosted key is refused with a status");
    crate::entropy::__entropy_clear_for_tests();
}
