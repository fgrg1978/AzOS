// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The compile-time link policy (`link-provisioning-enforced`) and the session's
//! end.
//!
//! The brain link has one mode, the Noise session; what the policy decides is
//! the provisioning around it (no boot without a key, no handshake without
//! seeded entropy, no UART bridge), read by the kernel through
//! `link_provisioning_enforced()`. Run both ways; the first test asserts different
//! things in each:
//!
//! ```text
//! cd tests/host/aead-link-tests
//! cargo test --release
//! cargo test --release --features enforced
//! ```

mod common;
use azos_crypto::secure_channel::*;
use common::*;

#[test]
fn policy_const_matches_the_feature_that_was_actually_enabled() {
    // The guard against a mis-forwarded feature: with `--features enforced`
    // the policy must read ON, without it OFF. A suite that passed either way
    // would let the policy be disarmed without a failure anywhere.
    assert_eq!(link_provisioning_enforced(), cfg!(feature = "enforced"));
}

#[test]
// REQ-012
fn a_terminal_event_ends_the_session_at_the_event() {
    let mut s = ik();
    assert!(s.robot.is_established());
    let mut f = brain_seal(&mut s.brain_send, b"forged");
    f[3] ^= 1;
    assert!(robot_open(&mut s.robot, &f).is_err());
    // Not at the drop: a session that failed one frame carries no more.
    assert!(!s.robot.is_established());
    let good = brain_seal(&mut s.brain_send, b"after");
    assert!(robot_open(&mut s.robot, &good).is_err(), "a closed session opened a frame");
}

#[test]
fn a_session_still_round_trips_in_this_target() {
    let mut s = xx();
    let f = {
        let mut out = vec![0u8; sealed_len_max(5)];
        let n = s.robot.seal_message(b"hello", &mut out).unwrap();
        out.truncate(n);
        out
    };
    assert_eq!(brain_open(&mut s.brain_recv, &f).unwrap(), b"hello");
}
