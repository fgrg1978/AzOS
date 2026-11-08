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
//! The decisions are pure ([`check_held`], [`row_decision`]); [`row_receives`]
//! and [`hand`] act on the installed topology and the capability tables.
//! `tests/host/syscall-tests` pulls this file in with `#[path]`.

use azos_abi::cap::{ty, CapHandle, CapPerms, CapType};
use azos_abi::error::Errno;

/// The rights the child's copy carries: the call right, nothing to pass on.
pub const HANDED_RIGHTS: CapPerms = CapPerms::WRITE;

/// May the capability the caller holds as `(kind, held, badge)` be handed to
/// a child? `ECAPKIND` for anything but an endpoint; `ECAPPERMS` for one
/// without the call right, without `TRANSFER`, with `READ`, or unbadged.
pub fn check_held(kind: CapType, held: CapPerms, badge: u32) -> Result<(), Errno> {
    if kind != ty::ENDPOINT {
        return Err(Errno::ECAPKIND);
    }
    if !held.contains(CapPerms::WRITE) || !held.contains(CapPerms::TRANSFER) || held.contains(CapPerms::READ) {
        return Err(Errno::ECAPPERMS);
    }
    if badge == 0 {
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

/// Put back a [`hand`] whose spawn did not go ahead: the child's copy returns
/// to the caller (with the rights it has there), or is destroyed if it cannot.
pub fn take_back(caller: u32, child: u32, handle: CapHandle, moved: CapHandle) {
    let x = azos_ipc::cap_store::CapXfer::new(handle, false);
    let _ = azos_ipc::cap_store::undo_move_caps(caller, child, &[x], &[moved]);
}
