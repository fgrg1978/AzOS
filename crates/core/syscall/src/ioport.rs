// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `DEVICE_IOPORT_ENABLE`, the one way ring 3 reaches I/O ports.
//!
//! The handle is a `Device` capability that names a range of ports
//! (`ty::IOPORT`, minted by `crates/core/ipc/src/ioport_cap.rs`); the op
//! opens the whole range to the calling thread (`azos_sched::ioport`), whose
//! `in`/`out` on it then run in ring 3 and on any other port fault (#GP, the
//! task's fault: `KILLED_SEGV`).
//!
//! Where the ISA has no port space (riscv64, aarch64: `PORTS` 0) the op
//! answers `-ENODEV` before it looks at the handle: the same seam on every
//! ISA, not a `cfg`.
//!
//! **Revocation.** The ports close with the capability: when it leaves its
//! table (`SYS_CAP_CLOSE` on it, [`ioport_close`], or any revocation or
//! move the capability store tells its event hook of, [`ioport_cap_event`]),
//! every thread of that table that opened its range loses it
//! (`azos_sched::ioport::revoke`). The open runs under the same table lock as
//! the revocation, so a thread never opens a range through a capability that
//! is already gone.

use azos_abi::cap::{ioport_bounds, ty, CapHandle, CapPerms};
use azos_abi::error::Errno;
use azos_abi::invoke::{CLASS_CTL, DEVICE_IOPORT_ENABLE};
use azos_ipc::cap::{targets, Cap, CapError};
use azos_ipc::cap_store::CapEvent;

use crate::invoke::{class_op, errno_cap, Call};

/// Ops on a range of I/O ports the caller holds.
pub(crate) fn ioport_op(c: &mut Call) -> i64 {
    if c.op != DEVICE_IOPORT_ENABLE {
        return Errno::EINVAL.to_syscall_ret();
    }
    if azos_arch_api::ioport::PORTS == 0 {
        return Errno::ENODEV.to_syscall_ret();
    }
    if c.w[..azos_abi::invoke::INVOKE_REG_WORDS].iter().any(|&w| w != 0) {
        return Errno::EINVAL.to_syscall_ret();
    }
    let cap: Cap<targets::IoPorts> = Cap::from_raw(CapHandle::from_raw(c.handle));
    let Some(table) = azos_ipc::cap_store::table_slot(c.tid) else { return errno_cap(CapError::Stale) };
    // A port write reaches the machine: a contained program is refused. The
    // check and the open hold the table's lock, as a revocation does.
    let r = azos_ipc::cap_store::with_table(c.tid, |t| {
        let range = t.get_op(cap, CapPerms::RW, c.op)?;
        Ok(ioport_bounds(range).map(|(first, last)| azos_sched::ioport::enable(first, last, table as u32)))
    });
    match r.unwrap_or(Err(CapError::Stale)) {
        Ok(Some(Ok(()))) => 0,
        Ok(Some(Err(azos_sched::ioport::EnableError::Full))) => Errno::EMFILE.to_syscall_ret(),
        Ok(Some(Err(azos_sched::ioport::EnableError::NoPorts))) => Errno::ENODEV.to_syscall_ret(),
        Ok(None) => Errno::EINVAL.to_syscall_ret(),
        Err(e) => {
            crate::handlers::note_typed_denial_for(c.tid, ty::IOPORT, e);
            errno_cap(e)
        }
    }
}

/// `SYS_CAP_CLOSE` of a port-range capability: the capability is revoked
/// (`cap_store::revoke`: recorded, and told to [`ioport_cap_event`]), so the
/// ports its holder's threads opened through it close. 0, or `-ECAPSTALE`
/// for a handle that names no live slot of the caller's.
pub(crate) fn ioport_close(raw: CapHandle) -> i64 {
    let tid = azos_sched::current_task_tid();
    let cap: Cap<targets::IoPorts> = Cap::from_raw(raw);
    let op = class_op(ty::IOPORT, CLASS_CTL);
    match azos_ipc::cap_store::read_table(tid, |t| t.get_op(cap, CapPerms::NONE, op)).unwrap_or(Err(CapError::Stale)) {
        Ok(_) => {
            azos_ipc::cap_store::revoke(tid, cap);
            0
        }
        Err(e) => {
            crate::handlers::note_typed_denial(ty::IOPORT, e);
            errno_cap(e)
        }
    }
}

/// The capability store's event, for a port-range capability: one that left
/// a table (revoked there, or moved out of it) closes its range in the
/// threads of that table. Runs with the table's lock held
/// (`cap_store::CapEventHook`); takes no other lock but each thread's set's.
/// A wiped table needs nothing: its domain has no thread left.
pub fn ioport_cap_event(e: CapEvent) {
    let (table, resource) = match e {
        CapEvent::Revoked { slot, kind, resource, .. } if kind == ty::IOPORT => (slot, resource),
        CapEvent::Moved { from, kind, resource, .. } if kind == ty::IOPORT => (from, resource),
        _ => return,
    };
    if let Some((first, last)) = ioport_bounds(resource) {
        azos_sched::ioport::revoke(table as u32, first, last);
    }
}
