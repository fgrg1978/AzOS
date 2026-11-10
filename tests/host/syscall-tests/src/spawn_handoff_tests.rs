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
use crate::spawn_handoff::{
    check_held, drop_handed, hand, holds_client_right, plan, row_decision, row_receives, Moving, HANDED_RIGHTS,
};
use azos_abi::cap::{ty, CapHandle, CapPerms, CapType};
use azos_abi::error::Errno;
use azos_abi::ushell::{Move, StartupFd, FD_CLOSED, FD_CONSOLE, FD_HANDLE, MOVE_CONSOLE, MOVE_F_OFFER, MOVE_KIND_ENDPOINT, MOVE_KIND_FD, STARTUP_FDS};
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
    assert_eq!(check_held(kind, perms, badge, false), Ok(()));
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
    assert_eq!(check_held(kind, perms, badge, false), Err(Errno::ECAPPERMS));
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
    assert_eq!(check_held(ty::FILE, call, BADGE, false), Err(Errno::ECAPKIND));
    assert_eq!(check_held(ty::SHM, call, BADGE, false), Err(Errno::ECAPKIND));
    let (kind, perms, _, badge) = held(SERVER, s.root).unwrap();
    assert_eq!(badge, 0);
    assert_eq!(check_held(kind, perms, BADGE, false), Err(Errno::ECAPPERMS), "the server's own right left its server");
    assert_eq!(check_held(kind, call, badge, false), Err(Errno::ECAPPERMS), "an unbadged right is the spawner to its server");
    assert_eq!(check_held(kind, CapPerms::TRANSFER, BADGE, false), Err(Errno::ECAPPERMS), "no call right");
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

/// **A spawn that does not go ahead destroys the right it handed**: the
/// child's copy is gone and nothing comes back to the shell under a handle it
/// was never told (it asks the server to lend another).
///
/// **Canary.** Make `drop_handed` do nothing: the child's copy stays and the
/// first assertion goes red.
#[test]
fn a_hand_off_undone_leaves_the_child_and_the_shell_nothing() {
    let _g = serial();
    let s = scene(CapPerms::WRITE.union(CapPerms::TRANSFER));
    let c = hand(SHELL, CHILD, s.lent).unwrap();
    drop_handed(CHILD, c);
    assert_eq!(held(CHILD, c), None, "the child kept the right of a spawn that failed");
    assert_eq!(cap_store::occupied(CHILD), 0);
    assert_eq!(cap_store::occupied(SHELL), 0, "an unnamed copy came back to the shell");
    teardown();
}

/// An endpoint entry at `fd`.
fn entry(fd: u32, handle: CapHandle, offered: bool) -> Move {
    Move { child_fd: fd, handle: handle.as_raw(), perms: 0, kind: MOVE_KIND_ENDPOINT | if offered { MOVE_F_OFFER } else { 0 } }
}

/// **A badge the kernel stamped at seeding is never handed on**, nor any copy
/// of it: the grant carries `Warrant::STAMPED`, every derive and move keeps
/// it, and its server may read authority into the badge. A DUP through a
/// message gives the copy a parent, so "a root" would not have caught it. Only
/// a badge a server minted from an unbadged source goes.
///
/// **Canaries.** Drop the `stamped` test from `check_held`: the seeded grant
/// and its DUP are planned. Seed `grant_badged` without `STAMPED`: the same.
#[test]
fn a_kernel_stamped_badge_and_its_copies_are_refused() {
    let _g = serial();
    let s = scene(CapPerms::WRITE.union(CapPerms::TRANSFER));
    let rights = CapPerms::WRITE.union(CapPerms::DELEGATE);
    let seeded = cap_store::grant_badged::<azos_ipc::cap::targets::Endpoint>(SHELL, rights, s.resource, 5)
        .expect("a seeded badged grant")
        .raw();
    assert_eq!(plan(SHELL, &[entry(0, seeded, false)]).err(), Some(Errno::ECAPPERMS), "a seeded badge was handed on");
    // The same stamp, DUPed to the shell by a peer through a message.
    let peer_seeded = cap_store::grant_badged::<azos_ipc::cap::targets::Endpoint>(CHILD, rights, s.resource, 6).unwrap().raw();
    let mut x = CapXfer::new(peer_seeded, true);
    x.rights = Some(CapPerms::WRITE.union(CapPerms::TRANSFER));
    let mut out = [CapHandle::from_raw(0); 1];
    cap_store::move_caps(CHILD, SHELL, &[x], true, &mut out).expect("the DUP");
    let w = cap_store::read_table(SHELL, |t| t.warrant_of(out[0])).flatten().unwrap();
    assert_ne!(w.parent, 0, "the DUP has a parent: a root test would let it through");
    assert_eq!(plan(SHELL, &[entry(0, out[0], false)]).err(), Some(Errno::ECAPPERMS), "a stamped badge's copy was handed on");
    assert!(plan(SHELL, &[entry(0, s.lent, false)]).is_ok(), "the server's derived badge is refused");
    teardown();
}

/// **`sys_spawn_ex`'s plan of a move list**, as it runs it: the caller's
/// table checked entry by entry (`check_held` on an endpoint entry, the kind
/// an fd entry may carry), the rows asked once the child's is known, a skipped
/// entry out of the moves and its fd closed, a moved one at its fd.
///
/// **Canaries.** Take the `check_held` call out of `plan`: the unbadged entry
/// is planned. Let `decide_rows` keep going past a refusal (`.unwrap_or(true)`):
/// the required entry is not refused. Let `order` keep a skipped entry: it is
/// in the moves.
#[test]
fn the_spawn_plan_checks_entries_asks_the_row_and_closes_a_skipped_fd() {
    let _g = serial();
    let s = scene(CapPerms::WRITE.union(CapPerms::TRANSFER));
    let (job, plainr) = (row(b"HOJOB.ELF"), row(b"PLAIN.ELF"));
    // An endpoint given as a descriptor entry, and a stale handle.
    let as_fd = Move { child_fd: 0, handle: s.lent.as_raw(), perms: 0, kind: MOVE_KIND_FD };
    assert_eq!(plan(SHELL, &[as_fd]).err(), Some(Errno::ECAPKIND));
    assert_eq!(plan(SHELL, &[entry(0, CapHandle::from_raw(0x7777), false)]).err(), Some(Errno::ECAPSTALE));
    // An unbadged call right (the shell's own) is refused by the plan itself.
    let own = azos_ipc::endpoint::endpoint_named_cap(SHELL, CapPerms::WRITE.union(CapPerms::DELEGATE), b"ho_term").unwrap().raw();
    assert_eq!(plan(SHELL, &[entry(0, own, false)]).err(), Some(Errno::ECAPPERMS), "an unbadged right was planned");
    // Required, into a row that does not receive it: refused.
    let mut p = plan(SHELL, &[entry(0, s.lent, false)]).unwrap();
    assert_eq!(p.decide_rows(plainr), Err(Errno::EACCES));
    // Offered, into that row: skipped, out of the moves, fd 0 closed.
    let console = Move { child_fd: 1, handle: MOVE_CONSOLE, perms: 0, kind: MOVE_KIND_FD };
    let mut p = plan(SHELL, &[entry(0, s.lent, true), console]).unwrap();
    assert_eq!(p.decide_rows(plainr), Ok(()));
    assert_eq!(p.order().1, 0, "a skipped entry is moved");
    let mut fds = [StartupFd::default(); STARTUP_FDS];
    p.startup_fds(&mut fds);
    assert_eq!((fds[0].kind, fds[1].kind), (FD_CLOSED, FD_CONSOLE));
    // Into the row that receives it: moved, at its fd.
    let mut p = plan(SHELL, &[entry(0, s.lent, true)]).unwrap();
    assert_eq!(p.decide_rows(job), Ok(()));
    let (o, n) = p.order();
    assert_eq!(n, 1);
    let c = hand(SHELL, CHILD, CapHandle::from_raw(p.moving[o[0]].handle)).unwrap();
    p.moving[o[0]].moved = c.as_raw();
    let mut fds = [StartupFd::default(); STARTUP_FDS];
    p.startup_fds(&mut fds);
    assert_eq!(fds[0], StartupFd { kind: FD_HANDLE, handle: c.as_raw() });
    teardown();
}

/// **Endpoints move last**: whatever the list's order, every other entry moves
/// first, so nothing after a handed endpoint can fail but another endpoint.
///
/// **Canary.** Make `order` one pass in list order: the endpoint comes first
/// and this goes red.
#[test]
fn the_endpoints_move_after_every_other_entry() {
    let _g = serial();
    let mut p = plan(SHELL, &[]).unwrap();
    let one = |kind: CapType| Moving { handle: 1, kind, rights: CapPerms::WRITE, resource: 0, moved: 0, ends: 0, offered: false, skipped: false, landed: false };
    p.moving[0] = one(ty::ENDPOINT);
    p.moving[1] = one(ty::FILE);
    p.moving[2] = one(ty::SHM);
    p.n = 3;
    let (o, n) = p.order();
    assert_eq!(&o[..n], &[1, 2, 0]);
}

/// **Console input is lent on behalf of the owner's own client only**: the
/// shell's unbadged call right on the terminal makes it one, a job's badged
/// copy does not, and a right on another server's endpoint does not.
///
/// **Canary.** Drop the `badge == 0` test of `holds_client_right`: the job is
/// a client and this goes red.
#[test]
fn only_an_unbadged_call_right_makes_a_client_of_the_console_owner() {
    let _g = serial();
    let s = scene(CapPerms::WRITE.union(CapPerms::TRANSFER));
    let c = hand(SHELL, CHILD, s.lent).unwrap();
    assert!(held(CHILD, c).is_some());
    assert!(!holds_client_right(CHILD, SERVER), "a job's badged copy made it the owner's client");
    let _own = azos_ipc::endpoint::endpoint_named_cap(SHELL, CapPerms::WRITE, b"ho_term").unwrap();
    assert!(holds_client_right(SHELL, SERVER));
    assert!(!holds_client_right(SHELL, CHILD), "a right on one server is a client of another");
    teardown();
}

/// **The row's name is the endpoint's, in the generation it had**: an
/// endpoint destroyed and made again under the same name is another, and a
/// capability on the old one is not received.
///
/// **Canary.** Drop the generation test of `ref_is_named`: the old reference
/// is still received and this goes red.
#[test]
fn an_endpoint_made_again_under_the_name_is_another() {
    let _g = serial();
    let s = scene(CapPerms::WRITE.union(CapPerms::TRANSFER));
    let job = row(b"HOJOB.ELF");
    assert!(row_receives(job, s.resource));
    azos_ipc::endpoint::destroy_ref(s.resource).expect("the endpoint goes");
    cap_store::reset(SERVER);
    let again = endpoint_named_cap(SERVER, CapPerms::RW_DELEGATE, b"ho_term").expect("made again").raw();
    let fresh = held(SERVER, again).unwrap().2;
    assert_ne!(fresh, s.resource);
    assert!(row_receives(job, fresh));
    assert!(!row_receives(job, s.resource), "a capability on the old endpoint was received");
    teardown();
}

/// The owner moves the undo makes (`FileOps::set_owner`): `(fd, from, to)`.
static OWNERS: std::sync::Mutex<Vec<(i32, u32, u32)>> = std::sync::Mutex::new(Vec::new());

struct Owners;

impl crate::file_ops::FileOps for Owners {
    fn open_at(&self, _: &[u8], _: &[u8], _: u32) -> i64 { -1 }
    fn close(&self, _: i32) -> i64 { 0 }
    fn read(&self, _: i32, _: &mut [u8]) -> i64 { -1 }
    fn write(&self, _: i32, _: &[u8]) -> i64 { -1 }
    fn lseek(&self, _: i32, _: i64, _: i32) -> i64 { -1 }
    fn dup(&self, _: i32) -> i64 { -1 }
    fn mkdir(&self, _: &[u8], _: &[u8]) -> i64 { -1 }
    fn unlink(&self, _: &[u8], _: &[u8]) -> i64 { -1 }
    fn readdir(&self, _: &[u8], _: u32) -> Option<([u8; azos_abi::syscall_nr::READDIR_NAME_BYTES], u32, bool)> { None }
    fn release_all(&self, _: u32) -> usize { 0 }
    fn read_whole(&self, _: &[u8], _: &mut [u8]) -> usize { 0 }
    fn set_owner(&self, fd: i32, from: u32, to: u32) -> i64 {
        OWNERS.lock().unwrap().push((fd, from, to));
        0
    }
}

static OWNERS_OPS: Owners = Owners;

/// A file descriptor the shell holds (a non-tree `Cap<File>`, `TRANSFER`).
const FD: u32 = 33;

/// **`sys_spawn_ex`'s undo at each point a spawn can fail after moving**: a
/// file whose owner moved goes back with its owner, one whose owner did not
/// goes back alone, a pipe's shared copy is dropped in the child (the shell
/// kept its own), a handed endpoint is destroyed, an entry that did not move is
/// left, and a second undo does nothing.
///
/// **Canaries.** Skip the owner's restore: the owner assertion goes red. Keep
/// `moved` after the undo: the second undo restores the owner again. Skip the
/// pipe copy's delete or the endpoint's `drop_handed`: the child still holds
/// a capability.
#[test]
fn the_undo_puts_back_what_moved_at_each_failure_point() {
    use azos_ipc::cap::targets::{File, Shm};
    let _g = serial();
    let s = scene(CapPerms::WRITE.union(CapPerms::TRANSFER));
    crate::file_ops::set_file_ops(&OWNERS_OPS);
    OWNERS.lock().unwrap().clear();
    let file = cap_store::grant::<File>(SHELL, CapPerms::RW.union(CapPerms::TRANSFER), FD).unwrap().raw();
    let shm = cap_store::grant::<Shm>(SHELL, CapPerms::RW.union(CapPerms::DELEGATE), 44).unwrap().raw();
    let fd_entry = |fd: u32, h: CapHandle| Move { child_fd: fd, handle: h.as_raw(), perms: 0, kind: MOVE_KIND_FD };
    let mut p = plan(SHELL, &[entry(0, s.lent, false), fd_entry(1, file), fd_entry(2, shm)]).unwrap();
    assert_eq!(p.decide_rows(row(b"HOJOB.ELF")), Ok(()));
    let (o, n) = p.order();
    assert_eq!(n, 3);
    // Every entry moved, the way `sys_spawn_ex` moves them: the file with its
    // owner, the pipe's region shared (its reference was refused: not landed),
    // the endpoint handed.
    for &i in &o[..n] {
        let m = p.moving[i];
        let h = CapHandle::from_raw(m.handle);
        let (moved, landed) = match m.kind {
            ty::FILE => {
                let c = cap_store::move_cap(SHELL, CHILD, h, Some(m.rights)).unwrap();
                OWNERS.lock().unwrap().clear();
                (c, true)
            }
            ty::SHM => {
                let mut x = CapXfer::new(h, true);
                x.rights = Some(m.rights);
                let mut out = [CapHandle::from_raw(0); 1];
                cap_store::move_caps(SHELL, CHILD, &[x], false, &mut out).unwrap();
                (out[0], false)
            }
            _ => (hand(SHELL, CHILD, h).unwrap(), true),
        };
        p.moving[i].moved = moved.as_raw();
        p.moving[i].landed = landed;
    }
    assert_eq!(cap_store::occupied(CHILD), 3);
    p.undo(SHELL, CHILD);
    assert_eq!(cap_store::occupied(CHILD), 0, "the child kept a capability of a spawn that failed");
    assert_eq!(*OWNERS.lock().unwrap(), [(FD as i32, CHILD, SHELL)], "the file's owner did not come back");
    let back = cap_store::read_table(SHELL, |t| t.lookup(ty::FILE, FD)).flatten();
    assert!(back.is_some(), "the file did not come back to the shell");
    assert!(held(SHELL, shm).is_some(), "the shell lost its own pipe region");
    assert_eq!(held(SHELL, s.lent), None, "a handed endpoint came back unnamed");
    p.undo(SHELL, CHILD);
    assert_eq!(OWNERS.lock().unwrap().len(), 1, "a second undo moved the owner again");

    // A file that moved and whose owner did not: back alone. An entry that did
    // not move: left.
    OWNERS.lock().unwrap().clear();
    let file = back.unwrap();
    let mut p = plan(SHELL, &[fd_entry(1, file)]).unwrap();
    p.moving[0].moved = cap_store::move_cap(SHELL, CHILD, file, None).unwrap().as_raw();
    p.undo(SHELL, CHILD);
    assert!(OWNERS.lock().unwrap().is_empty(), "the owner of a file it never got was moved back");
    assert_eq!(cap_store::occupied(CHILD), 0);
    let file = cap_store::read_table(SHELL, |t| t.lookup(ty::FILE, FD)).flatten().unwrap();
    let mut p = plan(SHELL, &[fd_entry(1, file)]).unwrap();
    p.undo(SHELL, CHILD);
    assert!(held(SHELL, file).is_some(), "an entry that never moved was touched");
    crate::file_ops::__file_ops_clear_for_tests();
    teardown();
}
