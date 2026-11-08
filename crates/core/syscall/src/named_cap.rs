// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SYS_CAP_INFO` `CAP_INFO_ENDPOINT`: the caller's capability on the endpoint
//! called `name`, by the endpoint it names and not by its rights or its slot.
//! A task whose row grants it more than one endpoint right with the same
//! rights (the terminal server: the call right it lends jobs from, and the
//! call right on the login service) tells them apart this way, whatever order
//! the row lists them in and wherever the pool put them.
//!
//! The answer also says whether the row grants such a right at all, so a task
//! whose row grants one it does not hold (a seeding that was refused) fails
//! closed instead of reading "no grant" as "nothing asked of me".
//!
//! Pure over the capability tables, the endpoint registry and the topology
//! slot; `tests/host/syscall-tests` pulls this file in with `#[path]`.

use azos_abi::cap::{ty, CapHandle, CapPerms};
use azos_abi::error::Errno;

/// Does `p` hold every right of `need` and none of `deny`?
fn fits(p: CapPerms, need: CapPerms, deny: CapPerms) -> bool {
    p.contains(need) && p.bits() & deny.bits() == 0
}

/// `tid`'s lowest-slot capability on the live endpoint called `name` whose
/// rights fit `need` and `deny`.
pub fn held(tid: u32, name: &[u8], need: CapPerms, deny: CapPerms) -> Option<CapHandle> {
    let want = |_: u32, _: u32, p: CapPerms| fits(p, need, deny);
    (0..)
        .map_while(|k| azos_ipc::cap_store::with_table(tid, |t| t.handles_where(ty::ENDPOINT, want).nth(k)).flatten())
        .find(|&h| {
            azos_ipc::cap_store::with_table(tid, |t| t.peek_raw(h).map(|(_, _, r)| r))
                .flatten()
                .is_some_and(|r| azos_ipc::endpoint::ref_is_named(r, name))
        })
}

/// Does topology row `row` grant a right on `endpoint.<name>` that fits
/// `need` and `deny`, one the seeding does not withhold on purpose
/// (`builder::login_call_withheld`: the login right of a console no user is
/// enrolled on)?
pub fn row_grants(row: Option<usize>, name: &[u8], need: CapPerms, deny: CapPerms) -> bool {
    let Some(topo) = azos_topology::get() else { return false };
    let Some(task) = row.and_then(|r| topo.tasks().get(r)) else { return false };
    topo.caps_of(task).iter().any(|c| {
        c.kind == azos_abi::cap::CapKind::Endpoint
            && azos_topology::types::endpoint_target(c) == Some(name)
            && fits(c.grant_perms(), need, deny)
            && !azos_topology::builder::login_call_withheld(c, topo.logins().len())
    })
}

/// The answer to `CAP_INFO_ENDPOINT` for `tid`, seeded from `row`: its
/// handle; `ENOENT` when the row grants no such right; `ECAPSTALE` when it
/// grants one and `tid` holds none.
pub fn lookup(tid: u32, row: Option<usize>, name: &[u8], need: CapPerms, deny: CapPerms) -> Result<CapHandle, Errno> {
    if let Some(h) = held(tid, name, need, deny) {
        return Ok(h);
    }
    Err(if row_grants(row, name, need, deny) { Errno::ECAPSTALE } else { Errno::ENOENT })
}

/// `SYS_CAP_INFO` with `CAP_INFO_ENDPOINT`: `name_ptr`/`len` the endpoint's
/// name (without `endpoint.`), `masks` the rights wanted (bits 0..8) and
/// refused (bits 8..16).
pub(crate) fn sys_lookup(name_ptr: u64, len: u64, masks: u64) -> i64 {
    let len = len as usize;
    if len == 0 || len > azos_ipc::endpoint::ENDPOINT_NAME_MAX || masks >> 16 != 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let mut name = [0u8; azos_ipc::endpoint::ENDPOINT_NAME_MAX];
    if azos_sched::UserSlice::<u8>::new(name_ptr, len).read_into(&mut name[..len]).is_err() {
        return Errno::EFAULT.to_syscall_ret();
    }
    let (need, deny) = (CapPerms::from_bits_truncate(masks as u8), CapPerms::from_bits_truncate((masks >> 8) as u8));
    let me = azos_sched::current_task_tid();
    match lookup(me, crate::natfork::row_of(me), &name[..len], need, deny) {
        Ok(h) => h.as_raw() as i64,
        Err(e) => e.to_syscall_ret(),
    }
}
