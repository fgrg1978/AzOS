// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Rights S3, the descriptor half: a message's capability entry names the
//! rights the receiver gets in a 16-bit field (`CapDesc::rights`), and the
//! derive words in a byte (`EndpointDerive::rights`). `TRANSFER` and `MAP`
//! took the fifth and sixth bit; the kernel's check is `rights & !ALL == 0`
//! (`ipc_v2`, `caps::sys_cap_derive`, `invoke::endpoint_derive`), so the width
//! of `ALL` is what a seventh right would have to grow consciously. The
//! enforcement (`cap_store::move_caps`) is `cap-tests/src/rights.rs`; the map
//! is `syscall-tests/src/rights.rs`.
//!
//! Mounted with `abi/src/cap.rs` as `cap` (`#[path]`, no dependencies).

use crate::cap::CapPerms;
use crate::ipc_msg::{CapDesc, MsgDesc, CAP_MODE_DUP, CAP_MODE_MOVE, MSG_VERSION};

const SINGLES: [CapPerms; 6] =
    [CapPerms::READ, CapPerms::WRITE, CapPerms::EXEC, CapPerms::DUP, CapPerms::TRANSFER, CapPerms::MAP];

/// The six rights are six distinct bits, all of them below the byte the derive
/// words carry, and `ALL` is exactly their union: no right aliases another and
/// none falls outside the mask a descriptor entry is checked against.
///
/// **Canary.** Give `MAP` the value of `TRANSFER`: the distinctness assertion
/// goes red; widen `ALL` past six bits: the count goes red.
#[test]
fn the_six_rights_are_distinct_bits_and_all_is_their_union() {
    let mut seen = 0u8;
    for r in SINGLES {
        assert_eq!(r.bits().count_ones(), 1, "{r:?} is one bit");
        assert_eq!(seen & r.bits(), 0, "{r:?} aliases another right");
        seen |= r.bits();
    }
    assert_eq!(seen, CapPerms::ALL.bits());
    assert_eq!(CapPerms::ALL.bits().count_ones(), 6);
    assert!(u16::from(CapPerms::ALL.bits()) <= u16::from(u8::MAX), "the derive words carry a byte");
    assert_eq!(CapPerms::DELEGATE.bits(), CapPerms::DUP.bits() | CapPerms::TRANSFER.bits());
    assert_eq!(CapPerms::from_bits_truncate(!0), CapPerms::ALL, "a seventh bit is not a right");
}

/// An entry carries every right the receiver can be given, in either mode,
/// through a copy of the descriptor, and the entry stays 16 bytes (the
/// descriptor 224).
#[test]
fn an_entry_carries_all_six_rights_in_either_mode() {
    assert_eq!(core::mem::size_of::<CapDesc>(), 16);
    assert_eq!(core::mem::size_of::<MsgDesc>(), 224);
    let mut d = MsgDesc { version: MSG_VERSION, n_caps: 2, ..MsgDesc::default() };
    let kept = CapPerms::TRANSFER.union(CapPerms::MAP).union(CapPerms::READ);
    d.caps[0] = CapDesc { handle: 7, mode: CAP_MODE_MOVE, _pad: 0, rights: u16::from(CapPerms::ALL.bits()), expiry_ns: 0 };
    d.caps[1] = CapDesc { handle: 9, mode: CAP_MODE_DUP, _pad: 0, rights: u16::from(kept.bits()), expiry_ns: 5 };
    let copy = d;
    assert!(copy.well_formed());
    assert_eq!(CapPerms::from_bits_truncate(copy.caps[0].rights as u8), CapPerms::ALL);
    assert_eq!(CapPerms::from_bits_truncate(copy.caps[1].rights as u8), kept, "MAP and TRANSFER survive a DUP entry");
    // The entry's check: anything outside ALL is a malformed entry.
    let outside = |r: u16| r & !u16::from(CapPerms::ALL.bits()) != 0;
    assert!(!outside(copy.caps[0].rights) && !outside(copy.caps[1].rights));
    assert!(outside(0x40) && outside(0x80) && outside(0x100), "bits past the sixth are refused");
}
