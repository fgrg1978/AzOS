// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for provenance-attenuated envelopes (innovation B4), the
//! descriptor half: the label word of `MsgDesc` (`crates/core/abi/src/ipc_msg.rs`,
//! mounted as `ipc_msg`) and how a label grows along a path. The fast-call
//! record keeping the label is the `ep_queue.rs` test
//! `the_label_travels_with_the_request_and_the_answer`; the per-task tables
//! are `endpoint.rs`'s `label` suite.

use crate::ipc_msg::{
    principal_bit, send_label, MsgDesc, CapDesc, LABEL_AGENT, LABEL_KNOWN, LABEL_SERVICE, LABEL_SYSTEM, LABEL_USER,
};

/// The reserved word became the label without growing the descriptor: the
/// size is still 224 bytes and the label is the last word, at 220.
/// **Canary.** Add a field to `MsgDesc`: the compile-time asserts in
/// `ipc_msg.rs` (and the size here) go red.
#[test]
fn the_label_is_the_reserved_word_and_the_size_is_unchanged() {
    assert_eq!(core::mem::size_of::<MsgDesc>(), 224);
    assert_eq!(core::mem::size_of::<CapDesc>(), 16);
    assert_eq!(core::mem::offset_of!(MsgDesc, label), 220);
    assert_eq!(core::mem::offset_of!(MsgDesc, clock_id), 216);
    assert_eq!(MsgDesc::default().label, 0, "an old sender's zero means no upstream provenance");
}

/// One bit per principal kind, in the topology's numbering (System 0,
/// Service 1, User 2, Agent 3); a kind the ABI does not know has no bit, and
/// the bits that are not kinds are refused as reserved.
#[test]
fn a_kind_is_one_bit_and_the_rest_of_the_word_is_reserved() {
    assert_eq!([principal_bit(0), principal_bit(1), principal_bit(2), principal_bit(3)],
               [LABEL_SYSTEM, LABEL_SERVICE, LABEL_USER, LABEL_AGENT]);
    assert_eq!(principal_bit(4), 0);
    assert_eq!(principal_bit(255), 0);
    assert_eq!(LABEL_KNOWN, 0b1111);
    let ok = MsgDesc { version: 1, label: LABEL_AGENT | LABEL_USER, ..MsgDesc::default() };
    assert!(ok.well_formed());
    for bit in 4..32 {
        let bad = MsgDesc { version: 1, label: 1 << bit, ..MsgDesc::default() };
        assert!(!bad.well_formed(), "reserved bit {bit}");
    }
}

/// Two hops: the brain (an agent) sends to the planner (a service), the
/// planner forwards to the actuator (another service). Each hop ORs the
/// sender's principal into what it carries, so the actuator reads both
/// kinds; the label never shrinks along the way, whatever a sender writes in
/// its own word. **Canary.** Replace the OR by an assignment in `send_label`:
/// the planner's hop loses the agent, red.
#[test]
fn a_label_propagates_across_two_hops_and_only_grows() {
    let brain = principal_bit(3);
    let planner = principal_bit(1);
    let actuator = principal_bit(1);

    let hop1 = send_label(0, brain);
    assert_eq!(hop1, LABEL_AGENT);
    // The planner copies what it read into the message it sends.
    let hop2 = send_label(hop1, planner);
    assert_eq!(hop2, LABEL_AGENT | LABEL_SERVICE, "the actuator reads the agent through the service");
    // A third hop by a service adds nothing it already has, and nobody can
    // clear a bit by sending.
    let hop3 = send_label(hop2, actuator);
    assert_eq!(hop3, hop2);
    for l in 0..=LABEL_KNOWN {
        for p in [0, LABEL_SYSTEM, LABEL_SERVICE, LABEL_USER, LABEL_AGENT] {
            assert_eq!(send_label(l, p) & l, l, "label {l:#b} lost a bit to sender {p:#b}");
        }
    }
    // A sender with no principal (a task without a row) adds nothing.
    assert_eq!(send_label(hop1, 0), hop1);
}
