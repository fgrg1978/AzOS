// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SYS_FOREIGN_ENTRY`, `SYS_FOREIGN_RESUME` and `SYS_FOREIGN_FORK`: the D6
//! "foreign ABI" family (`azos_abi::foreign`). The state and the mechanics are
//! in `azos_sched::foreign`; these are the entry points, behind the image
//! filter like any native call.

use azos_abi::error::Errno;

/// `SYS_FOREIGN_ENTRY(entry, flags)`.
pub fn sys_foreign_entry(entry: u64, flags: u64) -> i64 {
    if !azos_limits::LINUX_ABI {
        return Errno::ENOSYS.to_syscall_ret();
    }
    if flags != 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    azos_sched::foreign::register(entry)
}

/// `SYS_FOREIGN_RESUME(frame)`. On success the trap return hook restores the
/// frame; the value returned here is overwritten with it.
pub fn sys_foreign_resume(frame: u64) -> i64 {
    if !azos_limits::LINUX_ABI {
        return Errno::ENOSYS.to_syscall_ret();
    }
    azos_sched::foreign::request_resume(frame)
}

/// `SYS_FOREIGN_FORK`: the process copy of a ring-3 runtime hosting a foreign
/// `fork`. Only a thread that registered a foreign entry may ask: a native
/// program has no fork (its creation call is `SYS_SPAWN_EX`), so the entry is
/// the authority, not a flag on the image. `sepc`, `user_sp` and `regs` are
/// the caller's register snapshot at the call.
pub fn sys_foreign_fork(sepc: u64, user_sp: u64, regs: &azos_sched::UserRegs) -> i64 {
    if !azos_limits::LINUX_ABI {
        return Errno::ENOSYS.to_syscall_ret();
    }
    if azos_sched::foreign::current_entry() == 0 {
        return Errno::EPERM.to_syscall_ret();
    }
    crate::handlers::sys_fork(sepc, user_sp, regs)
}

/// Does the call `num` read the caller's register file (a fork hands it to its
/// child)? The trap entries build the snapshot only for these, since it is
/// costly: [`SYS_FOREIGN_FORK`](azos_abi::syscall_nr::SYS_FOREIGN_FORK) is the
/// one native call that needs it.
#[inline]
pub fn needs_user_regs(num: u64) -> bool {
    num == azos_abi::syscall_nr::SYS_FOREIGN_FORK
}
