// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SYS_POWER_TYPED` (614): the power family's typed call (RFC-0055 S5), the
//! ring-3 form of the recovery console's `pm suspend`, `reboot`, `shutdown`
//! and `sched_hz`, used by the `POWER.ELF` tool.
//!
//! Which capability an operation needs is not decided here:
//! `azos_ipc::authority_policy::power_op_need` answers it, from the same
//! table the recovery console checks its commands against. What changes is
//! the table it is checked over: the CALLING image's, whose topology row is
//! the whole of its authority. The check is made on every call, not only
//! under the console lockdown.
//!
//! On a refusal nothing of the operation happens, a `SAFETY_CAP_DENIED_TYPED`
//! record is made (bounded per task, as every typed denial), and the kernel
//! prints the console's refusal line, `[AUTHORITY] <cmd> REFUSED`, only when
//! that record was actually handed to the recorder.

use azos_abi::cap::{CapHandle, CapPerms};
use azos_abi::error::Errno;
use azos_abi::power::*;
use azos_ipc::authority_policy::power_op_need;
use azos_ipc::cap::{targets::Power, Cap, CapError};

fn errno_for(e: CapError) -> i64 {
    match e {
        CapError::Stale => Errno::ECAPSTALE.to_syscall_ret(),
        CapError::WrongKind => Errno::ECAPKIND.to_syscall_ret(),
        CapError::MissingPerms => Errno::ECAPPERMS.to_syscall_ret(),
        CapError::Contained => crate::handlers::E_CONTAINED,
        CapError::NoSpace => Errno::EMFILE.to_syscall_ret(),
    }
}

/// `SYS_POWER_TYPED` — `a0 = Cap<Power>`, `a1 = op`, `a2 = arg`. See the
/// number's doc in `azos_abi::syscall_nr`.
pub fn sys_power_typed(cap_raw: u64, op: u64, arg: u64) -> i64 {
    // An operation the family does not have names no right to check.
    let Some(need) = power_op_need(op) else {
        return Errno::EINVAL.to_syscall_ret();
    };
    // The capability FIRST: a caller without it learns nothing about the
    // argument it passed.
    let cap: Cap<Power> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let perms = if need.need_write { CapPerms::WRITE } else { CapPerms::READ };
    if let Err(e) = azos_ipc::cap_store::get(tid, cap, perms) {
        if crate::handlers::note_typed_denial_recorded(tid, need.kind, e) {
            azos_drv_sys::kwarn!(
                "[AUTHORITY] {} REFUSED: tid {} (ring 3) lacks Cap<{:?}> {} (recorded)",
                need.cmd, tid, need.kind, if need.need_write { "WRITE" } else { "READ" });
        }
        return errno_for(e);
    }
    match op {
        POWER_OP_SCHED_HZ_GET => {
            if arg != 0 {
                return Errno::EINVAL.to_syscall_ret();
            }
            azos_drv_sys::timebase::sched_hz_get() as i64
        }
        POWER_OP_SCHED_HZ_SET => {
            if !(POWER_SCHED_HZ_MIN..=POWER_SCHED_HZ_MAX).contains(&arg) {
                return Errno::EINVAL.to_syscall_ret();
            }
            azos_drv_sys::timebase::sched_hz_set(arg);
            azos_drv_sys::kprintln!("[SCHED] Scheduler rate set to {} Hz (tid {}, ring 3)", arg, tid);
            0
        }
        POWER_OP_SUSPEND => {
            if arg != 0 {
                return Errno::EINVAL.to_syscall_ret();
            }
            azos_drv_sys::kprintln!("[PM] Entering suspend... (tid {}, ring 3)", tid);
            // Waits for the next interrupt, as the console's `pm suspend`.
            azos_drv_power::pm::pm_suspend();
            0
        }
        POWER_OP_REBOOT | POWER_OP_SHUTDOWN => {
            if arg != 0 {
                return Errno::EINVAL.to_syscall_ret();
            }
            azos_drv_sys::kprintln!("[POWER] {} by tid {} (ring 3)", need.cmd, tid);
            if op == POWER_OP_REBOOT {
                crate::handlers::reboot_orderly()
            } else {
                crate::handlers::power_off_orderly()
            }
        }
        // `power_op_need` named no other operation.
        _ => Errno::EINVAL.to_syscall_ret(),
    }
}
