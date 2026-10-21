// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Provenance labels (innovation B4) at the syscall layer: what a send may put
// in the descriptor's label word. `ipc_deadline::check` is the rule every v2
// call passes before anything is queued (`ipc_v2::xfers` repeats the label
// test for the reply, which has no deadline). The sender's own principal is
// added after this check by `ipc_v2` from the per-task table
// (`azos_ipc::endpoint::label`, tested with `endpoint.rs`); this suite holds
// the descriptor's side, against the real `azos_abi` layout.

use super::harness::serial;
use crate::ipc_deadline::check;
use azos_abi::error::Errno;
use azos_abi::ipc_msg::{MsgDesc, LABEL_AGENT, LABEL_KNOWN, LABEL_SERVICE, LABEL_SYSTEM, LABEL_USER, MSG_VERSION};

const NOW: u64 = 2_000_000;

fn labelled(label: u32) -> MsgDesc {
    MsgDesc { version: MSG_VERSION, label, ..MsgDesc::default() }
}

/// A label that arrives is provenance, not an error: every combination of the
/// known kinds passes the check (the call is not refused for carrying what an
/// upstream sender put in it). **Canary.** Test `d.label != 0` in
/// `ipc_deadline::check` (the old reserved-word rule): every combination but
/// the empty one goes red.
#[test]
fn a_label_of_known_kinds_is_not_refused() {
    let _g = serial();
    for label in 0..=LABEL_KNOWN {
        assert_eq!(check(&labelled(label), NOW, 0xB4_1001), Ok(()), "label {label:#b}");
    }
    assert_eq!(LABEL_KNOWN, LABEL_SYSTEM | LABEL_SERVICE | LABEL_USER | LABEL_AGENT);
}

/// A bit that is not a kind is reserved and refused with `-EINVAL`, and it is
/// not a deadline refusal: no decision record (the descriptor is malformed,
/// not late). **Canary.** Accept any label in `check`: all 28 go red.
#[test]
fn a_reserved_label_bit_is_refused_as_malformed() {
    let _g = serial();
    let before = azos_decision::total();
    for bit in 4..32 {
        assert_eq!(
            check(&labelled(LABEL_AGENT | 1 << bit), NOW, 0xB4_1002),
            Err(Errno::EINVAL.to_syscall_ret()),
            "bit {bit}"
        );
    }
    assert_eq!(azos_decision::total(), before, "a malformed label is not a decision");
}

/// The label is the descriptor's last word and the descriptor did not grow:
/// a user copy of `DESC_BYTES` still covers it.
#[test]
fn the_label_sits_in_the_tail_of_the_unchanged_descriptor() {
    assert_eq!(core::mem::size_of::<MsgDesc>(), 224);
    assert_eq!(core::mem::offset_of!(MsgDesc, label), 220);
    let mut d = MsgDesc::default();
    d.label = LABEL_AGENT;
    // SAFETY: `MsgDesc` is `repr(C)` plain data; the last four bytes are the label.
    let bytes: [u8; 224] = unsafe { core::mem::transmute(d) };
    assert_eq!(u32::from_ne_bytes([bytes[220], bytes[221], bytes[222], bytes[223]]), LABEL_AGENT);
}

/// A task started by an agent, a user's session or a service is that principal
/// unless its own row says otherwise: the most restrictive kind wins when the
/// parent is several (a thread of an agent in a user's session), and a parent
/// that is `System` or has no principal gives nothing. **Canary.** Return
/// `None` for every parent and a user's session starts system tasks.
#[test]
fn a_child_takes_the_most_restrictive_principal_of_its_spawner() {
    use azos_abi::ipc_msg::{inherited_principal, principal_bit};
    // The kinds are numbered like the label bits: System 0, Service 1, User 2, Agent 3.
    for (bits, want) in [
        (0, None),
        (LABEL_SYSTEM, None),
        (LABEL_SERVICE, Some(1)),
        (LABEL_USER, Some(2)),
        (LABEL_AGENT, Some(3)),
        (LABEL_SYSTEM | LABEL_USER, Some(2)),
        (LABEL_SERVICE | LABEL_USER, Some(2)),
        (LABEL_USER | LABEL_AGENT, Some(3)),
        (LABEL_KNOWN, Some(3)),
    ] {
        assert_eq!(inherited_principal(bits), want, "{bits:#b}");
    }
    for kind in 1..4u8 {
        assert_eq!(inherited_principal(principal_bit(kind)), Some(kind));
    }
}
