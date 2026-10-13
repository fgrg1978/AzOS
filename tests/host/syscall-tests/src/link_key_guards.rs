// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the kernel-hosted `LinkKey` interface (U06-9, an endpoint op
// since D6 part A) -- `crates/core/syscall/src/link_key.rs::Server`.
//
// The server lives at THIS crate's root (`crate::link_key`, pulled in with
// `#[path]` by `lib.rs`, the same way `crate::motor_cmd` is: it names
// `crate::handlers::{E_CONTAINED, note_typed_denial_for}`, both `pub(crate)`,
// so it has to sit where `mod handlers` is a sibling rather than a parent).
// This file is included inside `mod handlers { .. }` in `lib.rs` like every
// other guard file in this crate, and reaches the server under test through
// the full path `crate::link_key::...`.
//
// Three outcomes: (a) a holder of `READ` reads the key; (b) a caller without
// `READ` is refused before the hook ran; (c) an absent or all-zero key is
// `NOT_READY` and no byte of it leaves.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_devif::{outcome, LinkKey, Out};
use crate::khost::Caller;
use std::sync::atomic::{AtomicU32, Ordering};

/// TIDs no other file in this crate uses.
static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e00_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// How many times a hook ran.
static HOOK_CALLS: AtomicU32 = AtomicU32::new(0);

/// The known-good key `ok_hook` hands back.
const TEST_KEY: [u8; crate::link_key::LINK_KEY_BYTES] = [0x42; crate::link_key::LINK_KEY_BYTES];

fn ok_hook(out: &mut [u8; crate::link_key::LINK_KEY_BYTES]) -> bool {
    HOOK_CALLS.fetch_add(1, Ordering::SeqCst);
    *out = TEST_KEY;
    true
}

fn absent_hook(_out: &mut [u8; crate::link_key::LINK_KEY_BYTES]) -> bool {
    HOOK_CALLS.fetch_add(1, Ordering::SeqCst);
    false
}

fn server(rights: CapPerms) -> crate::link_key::Server {
    crate::link_key::Server(Caller { tid: fresh_tid(), badge: 0, rights })
}

/// The words of a key.
fn words(k: &[u8; 32]) -> [u64; 4] {
    core::array::from_fn(|i| u64::from_le_bytes(k[i * 8..i * 8 + 8].try_into().unwrap()))
}

/// (a) Pass: a holder of `READ` gets exactly the key the hook produced.
///
/// **Canary.** Return the words of an all-zero key: the equality fails.
#[test]
fn a_holder_of_read_reads_the_key() {
    let _g = serial();
    HOOK_CALLS.store(0, Ordering::SeqCst);
    crate::link_key::set_link_key_read_hook(ok_hook);
    assert_eq!(server(CapPerms::READ).read(), Out::ok(words(&TEST_KEY)));
    assert_eq!(HOOK_CALLS.load(Ordering::SeqCst), 1);
    crate::link_key::__link_key_read_hook_clear_for_tests();
}

/// (b) Refused: no `READ` (none, `WRITE`, `EXEC`). The reserved sector is
/// never read, and nothing of the key is in the answer.
///
/// **Canary.** Skip the `allows` check in `Server::read`: this reads the key.
#[test]
fn a_caller_without_read_is_refused_before_the_hook_runs() {
    let _g = serial();
    HOOK_CALLS.store(0, Ordering::SeqCst);
    crate::link_key::set_link_key_read_hook(ok_hook);
    for rights in [CapPerms::NONE, CapPerms::WRITE, CapPerms::EXEC] {
        assert_eq!(server(rights).read(), Out::err(outcome::DENIED), "{rights:?}");
    }
    assert_eq!(HOOK_CALLS.load(Ordering::SeqCst), 0, "a refused caller reached the sector");
    crate::link_key::__link_key_read_hook_clear_for_tests();
}

/// (c) A holder of `READ` with no key behind it: `NOT_READY`, the zero words.
/// Also with no hook installed (fails closed, like an absent key).
///
/// **Canary.** Answer `OK` when the hook says no: this reads OK.
#[test]
fn an_absent_key_or_no_hook_is_not_ready() {
    let _g = serial();
    HOOK_CALLS.store(0, Ordering::SeqCst);
    crate::link_key::set_link_key_read_hook(absent_hook);
    assert_eq!(server(CapPerms::READ).read(), Out::err(outcome::NOT_READY));
    assert_eq!(HOOK_CALLS.load(Ordering::SeqCst), 1);
    crate::link_key::__link_key_read_hook_clear_for_tests();
    assert_eq!(server(CapPerms::READ).read(), Out::err(outcome::NOT_READY), "no hook installed");
}
