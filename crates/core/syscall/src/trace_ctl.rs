// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel tracer's control (wave 15, TRACE): the `LOG_TRACE_*` ops of
//! `SYS_INVOKE` on the tracer's `Log` handle, used by the `TRACECTL.ELF` tool.
//!
//! The authority is `Cap<Trace>`, granted only by a topology row
//! (`TRACECTL.ELF`'s): `READ` to read the geometry and the class mask,
//! `WRITE` to change the mask, both to map the rings (the reader stores its
//! tails in the region). The capability is checked FIRST, on every call;
//! a refusal is recorded (`SAFETY_CAP_DENIED_TYPED`, bounded per task as
//! every typed denial) and printed as `[TRACE] ... REFUSED` only when the
//! record was handed to the recorder.
//!
//! Mapping reuses `SYS_MO_MAP`'s path on the tracer's kernel-owned
//! pool region (`azos_ipc::trace::region_ref`): the mapping is booked to
//! the task like any shared-memory mapping and torn down with it, and the
//! trust boundary is `azos_rings::region::trace`'s (the producer reads nothing from
//! the region but the tail, as a number).

use azos_abi::cap::ty;
use azos_abi::cap::{CapHandle, CapPerms};
use azos_abi::error::Errno;
use azos_abi::invoke::{LOG_TRACE_GET_MASK, LOG_TRACE_INFO, LOG_TRACE_MAP, LOG_TRACE_REGION_BYTES, LOG_TRACE_SET_MASK};
use azos_ipc::cap::{targets::Trace, Cap, CapError};

fn errno_for(e: CapError) -> i64 {
    match e {
        CapError::Stale | CapError::Revoked => Errno::ECAPSTALE.to_syscall_ret(),
        CapError::WrongKind => Errno::ECAPKIND.to_syscall_ret(),
        CapError::MissingPerms => Errno::ECAPPERMS.to_syscall_ret(),
        CapError::Contained => crate::handlers::E_CONTAINED,
        CapError::NoSpace => Errno::EMFILE.to_syscall_ret(),
    }
}

/// The permissions operation `op` needs, or `None` for an operation the
/// call does not have.
fn op_perms(op: u16) -> Option<CapPerms> {
    match op {
        LOG_TRACE_INFO | LOG_TRACE_GET_MASK | LOG_TRACE_REGION_BYTES => Some(CapPerms::READ),
        LOG_TRACE_SET_MASK => Some(CapPerms::WRITE),
        LOG_TRACE_MAP => Some(CapPerms::RW),
        _ => None,
    }
}

/// A tracer op: `cap_raw` the `Log` handle of the tracer, `op` one of the
/// `LOG_TRACE_*`, `arg` its argument.
pub fn trace_op(cap_raw: u64, op: u16, arg: u64) -> i64 {
    let Some(perms) = op_perms(op) else {
        return Errno::EINVAL.to_syscall_ret();
    };
    // The capability FIRST: a caller without it learns nothing, not even
    // whether the tracer is compiled in.
    let cap: Cap<Trace> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    if let Err(e) = azos_ipc::cap_store::read_table(tid, |t| t.get_op(cap, perms, op)).unwrap_or(Err(azos_ipc::cap::CapError::Stale)) {
        if crate::handlers::note_typed_denial_recorded(tid, ty::TRACE, e) {
            azos_drv_sys::kwarn!(
                "[TRACE] op {} REFUSED: tid {} (ring 3) lacks Cap<Trace> {} (recorded)",
                op, tid, if perms == CapPerms::READ { "READ" } else if perms == CapPerms::WRITE { "WRITE" } else { "READ|WRITE" });
        }
        return errno_for(e);
    }
    if op != LOG_TRACE_SET_MASK && arg != 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let Some((region, bytes)) = azos_ipc::trace::region_ref() else {
        return Errno::ENOSYS.to_syscall_ret();
    };
    match op {
        LOG_TRACE_INFO => azos_trace::CLASSES as i64,
        LOG_TRACE_GET_MASK => azos_trace::mask() as i64,
        LOG_TRACE_REGION_BYTES => bytes as i64,
        LOG_TRACE_SET_MASK => {
            if arg > u32::MAX as u64 {
                return Errno::EINVAL.to_syscall_ret();
            }
            azos_ipc::trace::set_mask(arg as u32) as i64
        }
        // Booked to the process, as every shared-memory mapping is (wave 15).
        LOG_TRACE_MAP => crate::ipc_handlers::map_region_ref(azos_sched::current_proc_tid(), region, true, true),
        _ => Errno::EINVAL.to_syscall_ret(),
    }
}
