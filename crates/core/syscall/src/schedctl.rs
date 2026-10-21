// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SYS_SCHEDCTL` (N6b): a task's dispatch class and parameters.
//!
//! Fair is free: a task may move itself to any fair priority. RT (a band
//! priority) and DL (an EDF + CBS reservation, admitted by `rt::reserve`)
//! need a time warrant, a `time` endpoint capability with `WRITE`, checked FIRST and
//! recorded when refused: a task cannot promote itself above the fair
//! class without one. Only the caller may be the target for now; binding
//! another task (a supervisor's job) needs the task-authority check and is
//! refused with `-EPERM`. Leaving the band or a reservation through this
//! call is refused (`-EBUSY`): a reservation is dropped when its task
//! exits, and a band task's priority came from its topology row.

use core::sync::atomic::{AtomicBool, Ordering};

use azos_abi::error::Errno;
use azos_abi::syscall_nr::{SCHEDCTL_CLASS_DL, SCHEDCTL_CLASS_FAIR, SCHEDCTL_CLASS_RT, SCHEDCTL_HINT_QOS};
use azos_ipc::cap::CapError;
use azos_sched::sc::Class;
use azos_sched::{IDLE_PRIORITY, RT_PRIORITY_THRESHOLD};

/// Runtime canary `schedctl-no-warrant`: RT and DL skip the warrant check
/// (ktest `schedctl_self_promotion_refused` goes red).
static CANARY_NO_WARRANT: AtomicBool = AtomicBool::new(false);

/// Arm runtime canary `schedctl-no-warrant` (boot only).
pub fn canary_no_warrant() {
    CANARY_NO_WARRANT.store(true, Ordering::Relaxed);
}

fn errno_for(e: CapError) -> i64 {
    match e {
        CapError::Stale | CapError::Revoked => Errno::ECAPSTALE.to_syscall_ret(),
        CapError::WrongKind => Errno::ECAPKIND.to_syscall_ret(),
        CapError::MissingPerms => Errno::ECAPPERMS.to_syscall_ret(),
        CapError::Contained => crate::handlers::E_CONTAINED,
        CapError::NoSpace => Errno::EMFILE.to_syscall_ret(),
    }
}

/// The caller's time warrant: `Ok` when `warrant` names a live
/// capability to the `time` endpoint with `WRITE` in the caller's table (a refusal is
/// recorded by `handlers::time_warrant_recording`).
fn check_warrant(tid: u32, warrant: u64) -> Result<(), i64> {
    if CANARY_NO_WARRANT.load(Ordering::Relaxed) {
        return Ok(());
    }
    crate::handlers::time_warrant_recording(tid, warrant as u32).map_err(errno_for)
}

/// `SYS_SCHEDCTL` — see the number's doc in `azos_abi::syscall_nr`.
pub fn sys_schedctl(target: u64, class: u64, prio: u64, runtime_us: u64, period_us: u64, warrant: u64) -> i64 {
    let tid = azos_sched::current_task_tid();
    if target != 0 && target != tid as u64 {
        return Errno::EPERM.to_syscall_ret();
    }
    // RT and DL: the warrant FIRST, before anything else is looked at.
    if class == SCHEDCTL_CLASS_RT || class == SCHEDCTL_CLASS_DL {
        if let Err(e) = check_warrant(tid, warrant) {
            return e;
        }
    }
    let Some(idx) = azos_sched::idx_for_tid(tid) else {
        return Errno::EPERM.to_syscall_ret();
    };
    let cur = azos_sched::classes::class_of(idx);
    match class {
        // A hint, not a class: the caller's own QoS level, no warrant.
        SCHEDCTL_HINT_QOS => match azos_sched::classes::sc_of(idx) {
            Some(sc) if u32::try_from(prio).is_ok_and(|q| sc.set_qos(q)) => 0,
            _ => Errno::EINVAL.to_syscall_ret(),
        },
        SCHEDCTL_CLASS_FAIR => {
            if prio < RT_PRIORITY_THRESHOLD as u64 || prio >= IDLE_PRIORITY as u64 {
                return Errno::EINVAL.to_syscall_ret();
            }
            if matches!(cur, Some(Class::Rt | Class::Dl | Class::Stop)) {
                return Errno::EBUSY.to_syscall_ret();
            }
            azos_sched::rt::set_base_priority(idx, prio as u32);
            0
        }
        SCHEDCTL_CLASS_RT | SCHEDCTL_CLASS_DL => {
            if prio >= RT_PRIORITY_THRESHOLD as u64 {
                return Errno::EINVAL.to_syscall_ret();
            }
            if class == SCHEDCTL_CLASS_RT {
                if !azos_limits::SCHED_CLASS_RT {
                    return Errno::ENOSYS.to_syscall_ret();
                }
                if cur == Some(Class::Dl) {
                    return Errno::EBUSY.to_syscall_ret();
                }
                azos_sched::rt::set_base_priority(idx, prio as u32);
                return 0;
            }
            if !azos_limits::SCHED_CLASS_DL {
                return Errno::ENOSYS.to_syscall_ret();
            }
            if cur == Some(Class::Dl) {
                return Errno::EBUSY.to_syscall_ret();
            }
            if runtime_us == 0 || period_us == 0 || runtime_us > period_us {
                return Errno::EINVAL.to_syscall_ret();
            }
            let r = azos_sched::rt::Reservation {
                runtime_us,
                period_us,
                deadline_us: 0,
                hard: true,
                cpu_mask: 0,
                band: true,
                level: prio as u32,
            };
            match azos_sched::rt::reserve(idx, r) {
                Ok(_) => {
                    azos_sched::rt::set_base_priority(idx, prio as u32);
                    0
                }
                // Admission's own errno (`Refusal::errno`), as spawn reports it.
                Err(e) => -(e.errno() as i64),
            }
        }
        _ => Errno::EINVAL.to_syscall_ret(),
    }
}
