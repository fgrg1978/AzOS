// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The endpoint entries of a `SYS_SPAWN_EX` move list (`MOVE_KIND_ENDPOINT`):
//! a call capability the spawner hands its child, the way a shell hands a job
//! its terminal.
//!
//! **What may go.** A `Cap<Endpoint>` with the call right (`WRITE`), held with
//! `TRANSFER`, without `READ` (a server's right never leaves its server), and
//! badged: the server tells the child from the spawner by the badge, and an
//! unbadged copy would be the spawner as far as the server can see.
//!
//! **How it goes.** It is MOVED, with the call right alone: the spawner's
//! handle goes stale and the child's copy keeps the place the spawner's had in
//! the warrant tree, so whoever derived it (the server that minted the badge)
//! still revokes it where it now sits. A DUP would leave the spawner a second
//! copy it has no use for, and a slot it must remember to close; the
//! revocation the child must not outlive is the server's, not the spawner's.
//!
//! **Where it may go.** Only into a row that names the endpoint in its
//! `receives` list (CAPS.TOML format 8): no row receives anything it does not
//! say, and the row grants nothing itself.
//!
//! **Whose badge.** Only a badge a server minted for the purpose
//! (`ENDPOINT_DERIVE`, a link of the warrant tree with a parent) is handed on.
//! A badge the kernel stamped at seeding is a topology root, and its server may
//! read authority into it (the `power` and `input` classes do): handed to a
//! child narrowed to WRITE, it would still say what the row was granted.
//!
//! The move list as a whole is planned here too ([`plan`], [`Plan`]): every
//! entry checked against the caller's table before anything moves, the rows
//! asked once the child's is known, the endpoint entries moved last, and the
//! child's descriptors laid out from what landed. `ushell.rs` does the moves
//! of the other kinds; `tests/host/syscall-tests` pulls this file in with
//! `#[path]` and drives the plan over the real tables and topology slot.

use azos_abi::cap::{ty, CapHandle, CapPerms, CapType};
use azos_abi::error::Errno;
use azos_abi::ushell::{Move, StartupFd, FD_CONSOLE, FD_HANDLE, MOVE_CONSOLE, SPAWN_MAX_MOVES, STARTUP_FDS};

/// The rights the child's copy carries: the call right, nothing to pass on.
pub const HANDED_RIGHTS: CapPerms = CapPerms::WRITE;

/// May the capability the caller holds as `(kind, held, badge)` be handed to
/// a child, `root` saying it has no parent in the warrant tree? `ECAPKIND`
/// for anything but an endpoint; `ECAPPERMS` for one without the call right,
/// without `TRANSFER`, with `READ`, unbadged, or badged by the kernel at
/// seeding (a root).
pub fn check_held(kind: CapType, held: CapPerms, badge: u32, root: bool) -> Result<(), Errno> {
    if kind != ty::ENDPOINT {
        return Err(Errno::ECAPKIND);
    }
    if !held.contains(CapPerms::WRITE) || !held.contains(CapPerms::TRANSFER) || held.contains(CapPerms::READ) {
        return Err(Errno::ECAPPERMS);
    }
    if badge == 0 || root {
        return Err(Errno::ECAPPERMS);
    }
    Ok(())
}

/// What a row's answer means for an entry: `Ok(true)` hand it, `Ok(false)`
/// leave it with the caller (an offered entry the row does not receive),
/// `EACCES` refuse the spawn (a required one).
pub fn row_decision(received: bool, offered: bool) -> Result<bool, Errno> {
    match (received, offered) {
        (true, _) => Ok(true),
        (false, true) => Ok(false),
        (false, false) => Err(Errno::EACCES),
    }
}

/// Does topology row `row` (the one the child was seeded from) receive the
/// endpoint the packed reference `resource` names? `false` without a row or a
/// topology.
pub fn row_receives(row: Option<usize>, resource: u32) -> bool {
    let Some(topo) = azos_topology::get() else { return false };
    let Some(task) = row.and_then(|r| topo.tasks().get(r)) else { return false };
    topo.receives_of(task).iter().any(|n| azos_ipc::endpoint::ref_is_named(resource, n.as_bytes()))
}

/// Move the caller's `handle` into `child`'s table with [`HANDED_RIGHTS`]:
/// the child's handle. The badge travels with it, and so does its place in
/// the warrant tree. A refusal leaves the caller's table as it was.
pub fn hand(caller: u32, child: u32, handle: CapHandle) -> Result<CapHandle, azos_ipc::cap::CapError> {
    let mut x = azos_ipc::cap_store::CapXfer::new(handle, false);
    x.rights = Some(HANDED_RIGHTS);
    let mut out = [CapHandle::from_raw(0); 1];
    azos_ipc::cap_store::move_caps(caller, child, &[x], true, &mut out).map(|_| out[0])
}

/// Undo a [`hand`] whose spawn did not go ahead: the child's copy is
/// destroyed, not given back. Back, it would be a WRITE-only copy under a
/// handle the caller was never told; the server that minted it lends another.
pub fn drop_handed(child: u32, moved: CapHandle) {
    let _ = azos_ipc::cap_store::delete_moved(child, moved);
}

/// Does `tid` hold an unbadged call right on an endpoint task `owner` serves?
/// What lending console input asks of a task that is not its owner: the
/// owner's own client (the shell, through the right its row imports), not a
/// job holding a badged copy the owner lent it.
pub fn holds_client_right(tid: u32, owner: u32) -> bool {
    let call = |_: u32, badge: u32, p: CapPerms| badge == 0 && p.contains(CapPerms::WRITE);
    (0..).map_while(|k| azos_ipc::cap_store::with_table(tid, |t| t.handles_where(ty::ENDPOINT, call).nth(k)).flatten())
        .any(|h| azos_ipc::endpoint::endpoint_dest_for(tid, h.as_raw()) == Ok(owner))
}

/// The end of a POSIX pipe a child's `fd` names (fd 0 reads, any other fd
/// writes; `azos_bytepipe`'s rule, the one `libsys` adopts the region by).
fn pipe_end_of_fd(fd: usize) -> u8 {
    if fd == 0 { azos_ipc::memobj::PIPE_END_READ } else { azos_ipc::memobj::PIPE_END_WRITE }
}

/// One distinct handle of a move list, validated.
#[derive(Clone, Copy)]
pub struct Moving {
    pub handle: u32,
    pub kind: CapType,
    /// Rights the child gets.
    pub rights: CapPerms,
    /// The descriptor, the region or the endpoint's packed reference.
    pub resource: u32,
    /// The handle it takes in the child's table, once moved (0 before).
    pub moved: u32,
    /// For a pipe's region: the ends the child holds, by the fds it takes it at.
    pub ends: u8,
    /// An endpoint entry the child may go without (`MOVE_F_OFFER`).
    pub offered: bool,
    /// An offered endpoint the child's row does not receive: it stays with the
    /// caller and the child's fd is closed.
    pub skipped: bool,
    /// Every step of its move landed (for a file, its owner too).
    pub landed: bool,
}

const NOT_MOVING: Moving = Moving {
    handle: 0, kind: CapType::NULL, rights: CapPerms::NONE, resource: 0, moved: 0, ends: 0, offered: false,
    skipped: false, landed: false,
};

/// A move list, checked: what moves, and which child fd each names.
pub struct Plan {
    pub moving: [Moving; SPAWN_MAX_MOVES],
    pub n: usize,
    console: [bool; STARTUP_FDS],
    fd_slot: [usize; STARTUP_FDS],
}

/// Check the move list `moves` against `me`'s table, whole, before anything
/// moves: each distinct handle once (a descriptor named at two fds, `2>&1`,
/// with the same rights; an endpoint at one), a non-tree `Cap<File>` (moved,
/// `TRANSFER`), a pipe's `Cap<Shm>` (shared, `DUP` and `TRANSFER`), rights
/// kept or lowered; or an endpoint entry ([`check_held`]). `ECAPSTALE` for a
/// handle `me` does not hold, `ECAPKIND` for a kind its entry may not carry,
/// `ECAPPERMS` for missing rights, `EINVAL` for a repeat that disagrees.
pub fn plan(me: u32, moves: &[Move]) -> Result<Plan, Errno> {
    let mut p = Plan { moving: [NOT_MOVING; SPAWN_MAX_MOVES], n: 0, console: [false; STARTUP_FDS], fd_slot: [usize::MAX; STARTUP_FDS] };
    for m in moves {
        let fd = m.child_fd as usize;
        if m.handle == MOVE_CONSOLE {
            p.console[fd] = true;
            continue;
        }
        if let Some(i) = p.moving[..p.n].iter().position(|x| x.handle == m.handle) {
            if m.is_endpoint() || p.moving[i].kind == ty::ENDPOINT {
                return Err(Errno::EINVAL);
            }
            let want = if m.perms == 0 {
                p.moving[i].rights
            } else {
                CapPerms::from_bits_truncate(m.perms as u8).union(CapPerms::DELEGATE)
            };
            if want != p.moving[i].rights {
                return Err(Errno::EINVAL);
            }
            p.fd_slot[fd] = i;
            p.moving[i].ends |= pipe_end_of_fd(fd);
            continue;
        }
        let h = CapHandle::from_raw(m.handle);
        let peek = azos_ipc::cap_store::with_table(me, |t| t.peek_raw(h)).flatten();
        let Some((kind, held, resource)) = peek else { return Err(Errno::ECAPSTALE) };
        let entry = if m.is_endpoint() {
            let (badge, root) = azos_ipc::cap_store::with_table(me, |t| {
                (t.ext_of(h).map_or(0, |e| e.badge), t.warrant_of(h).map_or(true, |w| w.parent == 0))
            })
            .unwrap_or((0, true));
            check_held(kind, held, badge, root)?;
            Moving { handle: m.handle, kind, rights: HANDED_RIGHTS, resource, offered: m.offered(), ..NOT_MOVING }
        } else {
            match kind {
                ty::SHM => {}
                ty::FILE if !azos_ipc::file_cap::is_tree_resource(resource) => {}
                _ => return Err(Errno::ECAPKIND),
            }
            let want = if m.perms == 0 {
                held
            } else {
                CapPerms::from_bits_truncate(m.perms as u8).union(CapPerms::DELEGATE)
            };
            let needs = if kind == ty::SHM { CapPerms::DELEGATE } else { CapPerms::TRANSFER };
            if !held.contains(needs) || !held.contains(want) {
                return Err(Errno::ECAPPERMS);
            }
            Moving { handle: m.handle, kind, rights: want, resource, ends: pipe_end_of_fd(fd), ..NOT_MOVING }
        };
        p.moving[p.n] = entry;
        p.fd_slot[fd] = p.n;
        p.n += 1;
    }
    Ok(p)
}

impl Plan {
    /// Ask the child's row (`row`, the one it was seeded from) of every
    /// endpoint entry ([`row_receives`], [`row_decision`]): an offered one it
    /// does not receive is skipped, a required one refuses the spawn.
    pub fn decide_rows(&mut self, row: Option<usize>) -> Result<(), Errno> {
        for mv in self.moving[..self.n].iter_mut().filter(|m| m.kind == ty::ENDPOINT) {
            mv.skipped = !row_decision(row_receives(row, mv.resource), mv.offered)?;
        }
        Ok(())
    }

    /// The order the entries move in: every other kind first, the endpoints
    /// last, so that nothing after an endpoint's move can fail but another
    /// endpoint's. Skipped entries are not in it.
    pub fn order(&self) -> ([usize; SPAWN_MAX_MOVES], usize) {
        let mut o = [0usize; SPAWN_MAX_MOVES];
        let mut k = 0;
        for last in [false, true] {
            for (i, m) in self.moving[..self.n].iter().enumerate() {
                if (m.kind == ty::ENDPOINT) == last && !m.skipped {
                    o[k] = i;
                    k += 1;
                }
            }
        }
        (o, k)
    }

    /// The child's descriptors: the console where the list said so, the
    /// handle each moved entry took in the child's table, and nothing (closed)
    /// for a skipped one.
    pub fn startup_fds(&self, fds: &mut [StartupFd; STARTUP_FDS]) {
        for fd in 0..STARTUP_FDS {
            if self.console[fd] {
                fds[fd] = StartupFd { kind: FD_CONSOLE, handle: 0 };
            }
            if let Some(m) = self.moving.get(self.fd_slot[fd]).filter(|m| !m.skipped && m.moved != 0) {
                fds[fd] = StartupFd { kind: FD_HANDLE, handle: m.moved };
            }
        }
    }
}
