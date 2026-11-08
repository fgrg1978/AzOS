// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// `SYS_SPAWN_EX`'s endpoint entries (`MOVE_KIND_ENDPOINT`,
// `crates/core/syscall/src/spawn_handoff.rs`, pulled in with `#[path]`), over
// the real capability tables, endpoint registry and topology slot.
//
// The scene is the terminal's: a server serves `endpoint.ho_term` and mints a
// badged call right from its own, lends it to a "shell" (a DUP, call right and
// `TRANSFER`), and the shell hands it to a "job" whose row (`HOJOB.ELF` in
// `subtree_policy`'s topology) receives `ho_term`. What the kernel checks of
// the caller's capability is `check_held` on what the table holds; what it
// asks of the child's row is `row_receives`; the move is `hand`.

use super::harness::serial;
use crate::spawn_handoff::{check_held, hand, row_decision, row_receives, take_back, HANDED_RIGHTS};
use azos_abi::cap::{ty, CapHandle, CapPerms, CapType};
use azos_abi::error::Errno;
use azos_ipc::cap_store::{self, CapXfer};
use azos_ipc::endpoint::{endpoint_named_cap, endpoint_release_all};

/// Cap-store pool slots and TIDs no other file binds.
const SLOT_SERVER: usize = 34;
const SLOT_SHELL: usize = 35;
const SLOT_CHILD: usize = 36;
const SERVER: u32 = 6701;
const SHELL: u32 = 6702;
const CHILD: u32 = 6703;
/// The job id the server stamps.
const BADGE: u32 = 7;

/// What a table holds under a handle: kind, rights, resource, badge.
fn held(tid: u32, h: CapHandle) -> Option<(CapType, CapPerms, u32, u32)> {
    cap_store::read_table(tid, |t| t.peek_raw(h).zip(t.ext_of(h)).map(|((k, p, r), e)| (k, p, r, e.badge))).flatten()
}

/// The row index of `name` in the installed topology.
fn row(name: &[u8]) -> Option<usize> {
    let t = azos_topology::get()?;
    t.tasks().iter().position(|r| r.name.as_bytes() == name)
}

struct Scene {
    /// The server's own unbadged right (`READ`, `WRITE`, `DUP`, `TRANSFER`).
    root: CapHandle,
    /// The server's badged copy: the job's revocation root.
    badged: CapHandle,
    /// The shell's lent copy.
    lent: CapHandle,
    /// The endpoint's packed reference.
    resource: u32,
}

/// Three empty tables, the server serving `ho_term` with a badged copy lent
/// to the shell with `lent_rights`.
fn scene(lent_rights: CapPerms) -> Scene {
    super::subtree_policy::topology();
    for (tid, slot) in [(SERVER, SLOT_SERVER), (SHELL, SLOT_SHELL), (CHILD, SLOT_CHILD)] {
        ipc_task_pool::shim_bind(tid, slot);
        cap_store::reset(tid);
    }
    azos_ipc::cap::senders::set_hooks(azos_ipc::endpoint::sender_delta, azos_ipc::endpoint::flush_notices);
    let root = endpoint_named_cap(SERVER, CapPerms::RW_DELEGATE, b"ho_term").expect("the server's grant").raw();
    let resource = held(SERVER, root).unwrap().2;
    let badged = cap_store::mint_badged(SERVER, root, BADGE, CapPerms::WRITE.union(CapPerms::DELEGATE)).unwrap();
    let mut x = CapXfer::new(badged, true);
    x.rights = Some(lent_rights);
    let mut out = [CapHandle::from_raw(0); 1];
    cap_store::move_caps(SERVER, SHELL, &[x], true, &mut out).expect("the lend");
    Scene { root, badged, lent: out[0], resource }
}

fn teardown() {
    endpoint_release_all(SERVER);
    for tid in [SERVER, SHELL, CHILD] {
        cap_store::reset(tid);
    }
}

/// **A badged call right moves with the call right alone and its badge.**
/// The shell's handle goes stale; the child's copy is the same endpoint, the
/// same badge, and nothing to pass on.
///
/// **Canaries.** Give `hand` no rights (`x.rights = None`): the child keeps
/// `TRANSFER` and the rights assertion goes red. Make `hand` grant a fresh
/// unbadged copy (`grant::<Endpoint>(child, WRITE, resource)`): the badge
/// assertion goes red.
#[test]
fn a_badged_call_right_moves_with_the_call_right_alone_and_its_badge() {
    let _g = serial();
    let s = scene(CapPerms::WRITE.union(CapPerms::TRANSFER));
    let (kind, perms, _, badge) = held(SHELL, s.lent).unwrap();
    assert_eq!(check_held(kind, perms, badge), Ok(()));
    let c = hand(SHELL, CHILD, s.lent).expect("the hand-off");
    assert_eq!(held(SHELL, s.lent), None, "the shell kept a copy");
    let (kind, perms, resource, badge) = held(CHILD, c).expect("the child's copy");
    assert_eq!(kind, ty::ENDPOINT);
    assert_eq!(perms, HANDED_RIGHTS, "the child can pass it on");
    assert_eq!(perms, CapPerms::WRITE);
    assert_eq!(resource, s.resource);
    assert_eq!(badge, BADGE, "the server would not see who calls");
    teardown();
}

/// **Revoking the badge at its server reaches the child**: the moved copy
/// kept its place in the warrant tree, under the server's badged copy.
///
/// **Canary.** Make `hand` grant a fresh copy instead of moving it
/// (`grant_badged::<Endpoint>(child, WRITE, resource, badge)`): the revoke
/// leaves the child's copy live and this goes red.
#[test]
fn revoking_the_badge_at_its_server_reaches_the_child() {
    let _g = serial();
    let s = scene(CapPerms::WRITE.union(CapPerms::TRANSFER));
    let c = hand(SHELL, CHILD, s.lent).unwrap();
    assert!(held(CHILD, c).is_some());
    let renewed = cap_store::revoke_derived(SERVER, s.badged).expect("the server revokes its badge");
    assert_eq!(held(CHILD, c), None, "the child still holds the revoked badge");
    assert!(held(SERVER, renewed).is_some(), "the server keeps its own");
    assert!(held(SERVER, s.root).is_some(), "the server's root is untouched");
    teardown();
}

/// **No transfer right, no hand-off**: a lent copy without `TRANSFER` is
/// refused by the check (`ECAPPERMS`) and by the move itself, which leaves it
/// where it was.
///
/// **Canary.** Drop the `TRANSFER` test from `check_held`: the first
/// assertion goes red.
#[test]
fn a_call_right_without_transfer_is_refused_and_stays() {
    let _g = serial();
    let s = scene(CapPerms::WRITE);
    let (kind, perms, _, badge) = held(SHELL, s.lent).unwrap();
    assert_eq!(check_held(kind, perms, badge), Err(Errno::ECAPPERMS));
    assert!(hand(SHELL, CHILD, s.lent).is_err());
    assert!(held(SHELL, s.lent).is_some(), "a refused move consumed the shell's copy");
    teardown();
}

/// **Only an endpoint call right, badged, without `READ`.** Any other kind is
/// `ECAPKIND`; the server's own right (`READ`) and an unbadged one are
/// `ECAPPERMS`, read from what the tables hold.
///
/// **Canaries.** Drop the kind test from `check_held`: the `FILE` and `SHM`
/// assertions go red. Drop the badge test: the unbadged assertion goes red.
/// Drop the `READ` test: the server's-right assertion goes red.
#[test]
fn only_a_badged_call_right_without_read_may_be_handed() {
    let _g = serial();
    let s = scene(CapPerms::WRITE.union(CapPerms::TRANSFER));
    let call = CapPerms::WRITE.union(CapPerms::TRANSFER);
    assert_eq!(check_held(ty::FILE, call, BADGE), Err(Errno::ECAPKIND));
    assert_eq!(check_held(ty::SHM, call, BADGE), Err(Errno::ECAPKIND));
    let (kind, perms, _, badge) = held(SERVER, s.root).unwrap();
    assert_eq!(badge, 0);
    assert_eq!(check_held(kind, perms, BADGE), Err(Errno::ECAPPERMS), "the server's own right left its server");
    assert_eq!(check_held(kind, call, badge), Err(Errno::ECAPPERMS), "an unbadged right is the spawner to its server");
    assert_eq!(check_held(kind, CapPerms::TRANSFER, BADGE), Err(Errno::ECAPPERMS), "no call right");
    teardown();
}

/// **The child's row must name the endpoint.** `HOJOB.ELF` receives
/// `ho_term`; `PLAIN.ELF` receives nothing; no row receives `ho_other`; no
/// row at all is no. A row that does not receive it refuses a required entry
/// (`EACCES`) and skips an offered one.
///
/// **Canary.** Make `row_receives` answer `true` once a topology exists: the
/// `PLAIN.ELF` and `ho_other` assertions go red.
#[test]
fn a_row_that_does_not_receive_the_endpoint_refuses_it() {
    let _g = serial();
    let s = scene(CapPerms::WRITE.union(CapPerms::TRANSFER));
    let other = endpoint_named_cap(SERVER, CapPerms::READ, b"ho_other").unwrap().raw();
    let other_ref = held(SERVER, other).unwrap().2;
    let (job, plain) = (row(b"HOJOB.ELF"), row(b"PLAIN.ELF"));
    assert!(job.is_some() && plain.is_some());
    assert!(row_receives(job, s.resource));
    assert!(!row_receives(plain, s.resource), "a row that names nothing received it");
    assert!(!row_receives(job, other_ref), "a row received an endpoint it does not name");
    assert!(!row_receives(None, s.resource), "no row received it");
    assert_eq!(row_decision(true, false), Ok(true));
    assert_eq!(row_decision(true, true), Ok(true));
    assert_eq!(row_decision(false, true), Ok(false), "an offered entry is skipped");
    assert_eq!(row_decision(false, false), Err(Errno::EACCES));
    teardown();
}

/// **A spawn that does not go ahead gives the right back**: the child's copy
/// is gone, and the shell holds a right again (under a fresh handle).
///
/// **Canary.** Make `take_back` do nothing: the child's copy stays and the
/// first assertion goes red.
#[test]
fn a_hand_off_taken_back_leaves_the_child_nothing() {
    let _g = serial();
    let s = scene(CapPerms::WRITE.union(CapPerms::TRANSFER));
    let c = hand(SHELL, CHILD, s.lent).unwrap();
    take_back(SHELL, CHILD, s.lent, c);
    assert_eq!(held(CHILD, c), None, "the child kept the right of a spawn that failed");
    assert_eq!(cap_store::occupied(SHELL), 1, "the shell did not get it back");
    teardown();
}
