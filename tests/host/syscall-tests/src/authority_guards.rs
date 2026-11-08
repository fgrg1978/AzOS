// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the `Authority` interface the kernel hosts,
// `crates/core/syscall/src/authority_host.rs`: a frame staged in pieces
// reaches the extension's handler whole and once, only for a `WRITE` holder,
// contained or not; a stage is the caller's own; no handler is `UNSUPPORTED`.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_devif::authority::{submit, PUT_BYTES};
use azos_devif::{outcome, Authority, Out};
use crate::authority_host::{clear_handler_for_tests, release, set_handler, Server};
use crate::khost::Caller;
use std::sync::Mutex;

static SEEN: Mutex<Vec<(u8, Vec<u8>, u32)>> = Mutex::new(Vec::new());

fn record(kind: u8, payload: &[u8], tid: u32) {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((kind, payload.to_vec(), tid));
}

fn seen() -> Vec<(u8, Vec<u8>, u32)> {
    std::mem::take(&mut *SEEN.lock().unwrap_or_else(|e| e.into_inner()))
}

fn server(tid: u32, rights: CapPerms) -> Server {
    Server(Caller { tid, badge: 0, rights })
}

/// The register form's client, served by `s` directly.
struct Direct<'a>(&'a mut Server);

impl azos_devif::AuthorityCall for Direct<'_> {
    fn put(&mut self, offset: u32, words: [u64; azos_devif::authority::PUT_WORDS]) -> azos_idl::Result<Out<()>> {
        Ok(self.0.put(offset, words))
    }
    fn frame(&mut self, kind: u32, len: u32) -> azos_idl::Result<Out<()>> {
        Ok(self.0.frame(kind, len))
    }
}

/// A 76-byte release frame (two pieces) reaches the handler byte for byte,
/// with its kind and caller, once; the stage is then empty.
///
/// **Canary.** Copy only the first piece in `put`: the bytes differ.
#[test]
fn a_staged_frame_reaches_the_handler_whole_and_once() {
    let _g = serial();
    set_handler(record);
    let _ = seen();
    let payload: Vec<u8> = (0..76u8).map(|b| b.wrapping_mul(7).wrapping_add(1)).collect();
    let mut s = server(0x7a01, CapPerms::WRITE);
    assert_eq!(submit(&mut Direct(&mut s), 0x82, &payload), Ok(()));
    assert_eq!(seen(), vec![(0x82, payload, 0x7a01)]);
    assert_eq!(s.frame(0x82, 4), Out::ok(()));
    assert_eq!(seen(), vec![(0x82, vec![0; 4], 0x7a01)], "a second frame reused the stage");
    clear_handler_for_tests();
}

/// Without `WRITE` nothing is staged or answered; containment refuses
/// neither (an e-stop and a release must reach a contained system).
///
/// **Canary.** Check `allows` instead of `holds`: the contained frame is
/// `DENIED`.
#[test]
fn write_is_needed_and_containment_refuses_nothing() {
    let _g = serial();
    set_handler(record);
    let _ = seen();
    let mut r = server(0x7a02, CapPerms::READ);
    assert_eq!(r.put(0, [1; 6]).code, outcome::DENIED);
    assert_eq!(r.frame(0x84, 0).code, outcome::DENIED);
    assert!(seen().is_empty());
    azos_ipc::cap::degraded_set(true);
    let mut w = server(0x7a02, CapPerms::WRITE);
    let got = w.frame(0x84, 0);
    azos_ipc::cap::degraded_set(false);
    assert_eq!(got, Out::ok(()));
    assert_eq!(seen(), vec![(0x84, vec![], 0x7a02)]);
    clear_handler_for_tests();
}

/// A stage is its task's: another task's piece never reaches this one's
/// frame, a full table is `NO_RESOURCE`, and an exit frees the slot.
///
/// **Canary.** Look the slot up without the tid: the other task's bytes
/// appear in this frame.
#[test]
fn a_stage_is_the_callers_own() {
    let _g = serial();
    set_handler(record);
    let _ = seen();
    let tids = [0x7b01u32, 0x7b02, 0x7b03, 0x7b04];
    for (i, t) in tids.iter().enumerate() {
        assert_eq!(server(*t, CapPerms::WRITE).put(0, [i as u64 + 1; 6]), Out::ok(()));
    }
    assert_eq!(server(0x7b05, CapPerms::WRITE).put(0, [9; 6]).code, outcome::NO_RESOURCE);
    release(tids[3]);
    assert_eq!(server(0x7b05, CapPerms::WRITE).put(0, [9; 6]), Out::ok(()));
    assert_eq!(server(tids[0], CapPerms::WRITE).frame(0x83, 2), Out::ok(()));
    assert_eq!(seen(), vec![(0x83, vec![1, 0], tids[0])]);
    for t in [tids[1], tids[2], 0x7b05] {
        release(t);
    }
    clear_handler_for_tests();
}

/// Out-of-range pieces, lengths and kinds are refused; no handler is
/// `UNSUPPORTED`.
#[test]
fn bad_arguments_and_no_handler_are_refused() {
    let _g = serial();
    clear_handler_for_tests();
    let mut w = server(0x7a03, CapPerms::WRITE);
    assert_eq!(w.frame(0x82, 0).code, outcome::UNSUPPORTED);
    set_handler(record);
    let _ = seen();
    assert_eq!(w.put(1, [0; 6]).code, outcome::BAD_ARGUMENT);
    assert_eq!(w.put((2 * PUT_BYTES) as u32, [0; 6]).code, outcome::BAD_ARGUMENT);
    assert_eq!(w.frame(0x82, 97).code, outcome::BAD_ARGUMENT);
    assert_eq!(w.frame(0x1_00, 0).code, outcome::BAD_ARGUMENT);
    assert!(seen().is_empty());
    release(0x7a03);
    clear_handler_for_tests();
}
