// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Rights S3: `TRANSFER` is the right to give a capability to another Domain,
// `DUP` the right to copy it, `MAP` the right to have a region in an address
// space. Table-level checks of the first two and of what the weak mask keeps;
// the map itself is `memobj.rs`'s test and `syscall-tests/src/rights.rs`.
//
// A child module of `cap_store_tests` (`mod rights { include!("rights.rs"); }`,
// next to `b4`): the module lock, the test clock and the slot helpers are the
// ones the warrant tests use. Each test names the break that turns it red.

use super::*;
use crate::cap_store::CapXfer;

const RW_T: CapPerms = CapPerms::RW.union(CapPerms::TRANSFER);
const RW_D: CapPerms = CapPerms::RW.union(CapPerms::DUP);

/// A MOVE entry of `h` (the sender loses it).
fn mv(from: &Task, to: &Task, h: CapHandle) -> Result<CapHandle, CapError> {
    let mut out = [CapHandle(0); 1];
    cap_store::move_caps(from.tid, to.tid, &[CapXfer::new(h, false)], true, &mut out).map(|_| out[0])
}

/// Which of the three ways a task can send `perms` to another Domain succeed:
/// `move_cap`, a MOVE entry of a message, a DUP entry of a message. A fresh
/// capability each time, so one attempt cannot spend another's.
fn outcomes(perms: CapPerms, res: u32) -> [bool; 3] {
    let (a, b) = (wtask(44), wtask(45));
    let by_move_cap = cap_store::move_cap(a.tid, b.tid, root(&a, perms, res), None).is_ok();
    let by_move_entry = mv(&a, &b, root(&a, perms, res + 1)).is_ok();
    let by_dup_entry = dup(&a, &b, root(&a, perms, res + 2)).is_ok();
    [by_move_cap, by_move_entry, by_dup_entry]
}

/// `TRANSFER` gates giving a capability away and `DUP` gates copying it; the
/// two are separate bits, and a DUP entry (the sender keeps its own) needs both.
///
/// **Canary.** Make `move_locked` ask `DUP` instead of `TRANSFER`: the
/// `TRANSFER`-only row reads refused and the `DUP`-only row reads moved.
/// Make `xfer_plan` ask `TRANSFER` alone of a DUP entry: the `TRANSFER`-only
/// row copies.
#[test]
fn transfer_gates_giving_away_dup_gates_copying_and_a_copy_needs_both() {
    let _g = wguard();
    //                                   move_cap move_entry dup_entry
    assert_eq!(outcomes(CapPerms::RW, 10), [false, false, false], "neither right: nothing leaves");
    assert_eq!(outcomes(RW_D, 20), [false, false, false], "DUP alone copies inside the table, it gives nothing away");
    assert_eq!(outcomes(RW_T, 30), [true, true, false], "TRANSFER alone: it may move, it may not be copied out");
    assert_eq!(outcomes(CapPerms::RW_DELEGATE, 40), [true, true, true], "both: any of the three");
}

/// A refusal changes nothing: the sender keeps the capability, the receiver
/// gets none, and a message with one entry short of `TRANSFER` lands none of
/// its entries.
///
/// **Canary.** Move the `TRANSFER` check of `xfer_plan` after the first entry
/// lands: the receiver holds one capability.
#[test]
fn a_message_with_one_entry_short_of_transfer_lands_none() {
    let _g = wguard();
    let (a, b) = (wtask(44), wtask(45));
    let ok = root(&a, RW_T, 1);
    let short = root(&a, RW_D, 2);
    let mut out = [CapHandle(0); 2];
    let xs = [CapXfer::new(ok, false), CapXfer::new(short, false)];
    assert_eq!(cap_store::move_caps(a.tid, b.tid, &xs, true, &mut out), Err(CapError::MissingPerms));
    assert_eq!((cap_store::occupied(a.tid), cap_store::occupied(b.tid)), (2, 0), "nothing moved");
    assert!(live(&a, ok) && live(&a, short), "the sender keeps both");
}

/// A task moving a capability to itself gives nothing to anyone: it needs no
/// `TRANSFER`.
#[test]
fn a_move_to_oneself_needs_no_transfer() {
    let _g = wguard();
    let a = wtask(44);
    let h = root(&a, CapPerms::RW, 5);
    assert_eq!(cap_store::move_cap(a.tid, a.tid, h, None), Ok(h), "the same handle, the same table");
}

/// The kernel putting a capability back where it came from (a call refused
/// before a server took it) is no transfer by a task: the copy that arrived
/// was attenuated below `TRANSFER` and the undo still lands.
///
/// **Canary.** Pass `need_transfer = true` from `move_back`: the sender loses
/// the capability for good (`lost == 1`).
#[test]
fn undoing_a_transfer_needs_no_transfer_on_the_attenuated_copy() {
    let _g = wguard();
    let (a, b) = (wtask(44), wtask(45));
    let h = root(&a, CapPerms::RW_DELEGATE, 6);
    let x = CapXfer { rights: Some(CapPerms::READ), ..CapXfer::new(h, false) };
    let mut out = [CapHandle(0); 1];
    assert_eq!(cap_store::move_caps(a.tid, b.tid, &[x], false, &mut out), Ok(1));
    assert!(!live(&a, h), "moved");
    let held = cap_store::with_table(b.tid, |t| t.peek_raw(out[0])).flatten().unwrap().1;
    assert_eq!(held, CapPerms::READ, "the copy cannot be moved on by a task");
    assert_eq!(mv(&b, &a, out[0]), Err(CapError::MissingPerms));
    assert_eq!(cap_store::undo_move_caps(a.tid, b.tid, &[x], &out), 0, "none lost");
    assert_eq!(cap_store::occupied(a.tid), 1, "the sender holds it again");
    assert_eq!(cap_store::occupied(b.tid), 0);
}

/// A move may lower rights, never raise them, and the receiver's rights are
/// exactly the ones asked for: lowering `TRANSFER` away makes the copy
/// non-transferable, and `MAP` travels like any other bit.
#[test]
fn the_receiver_gets_exactly_the_rights_asked_for_transfer_and_map_included() {
    let _g = wguard();
    let (a, b, c) = (wtask(44), wtask(45), wtask(46));
    let view = CapPerms::READ.union(CapPerms::MAP);
    let h = root(&a, view.union(CapPerms::DELEGATE), 7);
    let got = dup_rights(&a, &b, h, view.union(CapPerms::TRANSFER)).expect("keep TRANSFER, drop DUP");
    let held = cap_store::with_table(b.tid, |t| t.peek_raw(got)).flatten().unwrap().1;
    assert_eq!(held, view.union(CapPerms::TRANSFER), "MAP and TRANSFER arrive as asked");
    assert!(mv(&b, &c, got).is_ok(), "and it can be moved on");
    let again = dup_rights(&a, &b, h, view).expect("drop both");
    assert_eq!(mv(&b, &c, again), Err(CapError::MissingPerms), "a copy without TRANSFER stays");
    assert_eq!(
        dup_rights(&a, &b, h, view.union(CapPerms::WRITE)),
        Err(CapError::MissingPerms),
        "raising WRITE is refused"
    );
    let no_map = root(&a, CapPerms::RW_DELEGATE, 8);
    assert_eq!(
        dup_rights(&a, &b, no_map, CapPerms::READ.union(CapPerms::MAP)),
        Err(CapError::MissingPerms),
        "MAP cannot be conjured by a copy of a capability that has none"
    );
}

/// A weak slot (a shadow task's, or anything derived from a weak root) reads
/// `READ` and `MAP` only: it can still map a region read-only, and it holds
/// neither `TRANSFER` nor `DUP` to give away.
///
/// **Canary.** Drop `MAP` from `slot_word::WEAK_KEEPS`: the first assertion
/// goes red (a shadow task could no longer map what it could read). Widen it
/// to `ALL`: the move assertions go red.
#[test]
fn a_weak_slot_maps_read_only_and_gives_nothing_away() {
    let _g = wguard();
    let (a, b) = (wtask(44), wtask(45));
    let weak = root_with(&a, CapPerms::RW.union(CapPerms::MAP).union(CapPerms::DELEGATE), 9, Warrant::WEAK_ROOT);
    assert_eq!(cap_store::get(a.tid, ch(weak), CapPerms::READ.union(CapPerms::MAP)), Ok(9));
    for denied in [CapPerms::WRITE, CapPerms::DUP, CapPerms::TRANSFER] {
        assert_eq!(cap_store::get(a.tid, ch(weak), denied), Err(CapError::MissingPerms), "{denied:?}");
    }
    assert_eq!(mv(&a, &b, weak), Err(CapError::MissingPerms), "MOVE");
    assert_eq!(dup(&a, &b, weak), Err(CapError::MissingPerms), "DUP");
    assert_eq!(cap_store::move_cap(a.tid, b.tid, weak, None), Err(CapError::MissingPerms), "move_cap");
    let raw = cap_store::with_table(a.tid, |t| t.peek_stored(weak)).flatten().unwrap().1;
    assert!(raw.contains(CapPerms::DELEGATE), "the stored rights are as granted: the mask is what refuses");
}

/// `MAP` is a right like the others at the table: asked of a capability that
/// reads and writes it is refused, asked of one that has it it resolves, and
/// `READ` is not implied by it.
#[test]
fn map_is_its_own_bit_at_the_table() {
    let _g = wguard();
    let a = wtask(44);
    let rw = root(&a, CapPerms::RW, 11);
    let map = root(&a, CapPerms::MAP, 12);
    let both = root(&a, CapPerms::READ.union(CapPerms::MAP), 13);
    let mapped = |h: CapHandle| cap_store::get(a.tid, ch(h), CapPerms::READ.union(CapPerms::MAP));
    assert_eq!(mapped(rw), Err(CapError::MissingPerms), "RW is no window");
    assert_eq!(mapped(map), Err(CapError::MissingPerms), "MAP without READ reads nothing");
    assert_eq!(mapped(both), Ok(13));
    assert_eq!(cap_store::get(a.tid, ch(rw), CapPerms::READ), Ok(11), "READ still resolves for what is not a map");
}
