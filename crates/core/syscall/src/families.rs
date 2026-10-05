// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The privileged families' typed calls (wave 12, RFC-0055 S5):
//! `SYS_FLIGHT_TYPED` (615), `SYS_BEHAVIOR_TYPED` (616), `SYS_CONFIG_TYPED`
//! (617) and `SYS_OTA_TYPED` (618), the ring-3 forms of the recovery
//! console's `flight`, `behavior`, `config` and `ota` commands, for the
//! `FLIGHT.ELF`, `BEHAVIOR.ELF`, `CONFIG.ELF` and `OTA.ELF` tools.
//!
//! As `SYS_POWER_TYPED`: which capability an operation needs is
//! `azos_ipc::authority_policy::*_op_need`, from the table the console
//! checks; it is checked FIRST, over the CALLING image's table, on every
//! call; a refusal is recorded and does nothing. Flight is pair-wide: the
//! presented `Cap<Motor>` WRITE and both wheels in the table
//! (`motor_cap::drivetrain_write_check`), the console's `flight arm` check.
//!
//! **The operations are the console's own code**, reached through
//! [`FamilyOps`], which the kernel installs at boot over
//! `crates/core/shell`'s family functions — the same functions the
//! console's commands call. This crate is core and cannot name the shell.
//! Without an installed implementation (a kernel built without the Robot
//! domain for flight/behavior) the call answers `-ENOSYS` after the
//! capability check.

use azos_abi::cap::{CapHandle, CapPerms};
use azos_abi::error::Errno;
use azos_abi::families::*;
use azos_ipc::authority_policy::{
    behavior_op_need, config_op_need, flight_op_need, ota_op_need, Ring3Need,
};
use azos_ipc::cap::{targets::{Motor, Power}, Cap, CapError};
use azos_sync::SpinLock;

/// The family operations, implemented by the kernel over the console's code.
/// Each answers as the syscall does: 0 or a value, or a negative errno. The
/// capability has been checked before any of these runs.
pub trait FamilyOps: Sync {
    /// `FLIGHT_OP_ARM` / `FLIGHT_OP_DISARM`. `-ENOSYS` without the Robot domain.
    fn flight(&self, op: u64) -> i64;
    /// `BEHAVIOR_OP_*` on a validated `layer` (0 for the status read).
    fn behavior(&self, op: u64, layer: u64) -> i64;
    /// `config get`: the value of `key` into `out`; its length.
    fn config_get(&self, key: &[u8], out: &mut [u8]) -> i64;
    /// `config set` + apply.
    fn config_set(&self, key: &[u8], val: &[u8]) -> i64;
    /// `OTA_OP_STATUS` (the packed word) / `OTA_OP_ROLLBACK`.
    fn ota(&self, op: u64) -> i64;
}

static FAMILY_OPS: SpinLock<Option<&'static dyn FamilyOps>> = SpinLock::new(None);

/// Install the family operations (kernel boot, `boot/seams.rs`).
pub fn set_family_ops(ops: &'static dyn FamilyOps) {
    *FAMILY_OPS.lock() = Some(ops);
}

/// Back to "nothing installed". Host tests only.
#[cfg(test)]
pub fn __family_ops_clear_for_tests() {
    *FAMILY_OPS.lock() = None;
}

fn family_ops() -> Option<&'static dyn FamilyOps> {
    *FAMILY_OPS.lock()
}

fn errno(e: Errno) -> i64 {
    e.to_syscall_ret()
}

fn cap_errno(e: CapError) -> i64 {
    match e {
        CapError::Stale => errno(Errno::ECAPSTALE),
        CapError::WrongKind => errno(Errno::ECAPKIND),
        CapError::MissingPerms => errno(Errno::ECAPPERMS),
        CapError::Contained => crate::handlers::E_CONTAINED,
        CapError::NoSpace => errno(Errno::EMFILE),
    }
}

/// Record a refusal and print the console's refusal line when the record
/// was handed to the recorder (as `SYS_POWER_TYPED`).
fn refuse(tid: u32, need: &Ring3Need, e: CapError) -> i64 {
    if crate::handlers::note_typed_denial_recorded(tid, need.kind, e) {
        azos_drv_sys::kwarn!(
            "[AUTHORITY] {} REFUSED: tid {} (ring 3) lacks Cap<{:?}> {} (recorded)",
            need.cmd, tid, need.kind, if need.need_write { "WRITE" } else { "READ" });
    }
    cap_errno(e)
}

fn perms(need: &Ring3Need) -> CapPerms {
    if need.need_write { CapPerms::WRITE } else { CapPerms::READ }
}

/// `Cap<Power>` at the needed right, or the refusal's errno.
fn check_power(cap_raw: u64, need: &Ring3Need) -> Result<(), i64> {
    let cap: Cap<Power> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    azos_ipc::cap_store::get(tid, cap, perms(need))
        .map(|_| ())
        .map_err(|e| refuse(tid, need, e))
}

/// `SYS_FLIGHT_TYPED` — `a0 = Cap<Motor>`, `a1 = op`, `a2 = 0`.
pub fn sys_flight_typed(cap_raw: u64, op: u64, arg: u64) -> i64 {
    let Some(need) = flight_op_need(op) else {
        return errno(Errno::EINVAL);
    };
    let cap: Cap<Motor> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let checked = azos_ipc::cap_store::with_table(tid, |t| {
        azos_ipc::motor_cap::drivetrain_write_check(t, cap)
    });
    match checked {
        Some(Ok(())) => {}
        Some(Err(e)) => return refuse(tid, &need, e),
        None => return errno(Errno::EINVAL),
    }
    if arg != 0 {
        return errno(Errno::EINVAL);
    }
    match family_ops() {
        Some(ops) => {
            azos_drv_sys::kprintln!("[FLIGHT] {} by tid {} (ring 3)", need.cmd, tid);
            ops.flight(op)
        }
        None => errno(Errno::ENOSYS),
    }
}

/// `SYS_BEHAVIOR_TYPED` — `a0 = Cap<Power>`, `a1 = op`, `a2 = layer`.
pub fn sys_behavior_typed(cap_raw: u64, op: u64, layer: u64) -> i64 {
    let Some(need) = behavior_op_need(op) else {
        return errno(Errno::EINVAL);
    };
    if let Err(e) = check_power(cap_raw, &need) {
        return e;
    }
    let ok = if op == BEHAVIOR_OP_STATUS { layer == 0 } else { (1..BEHAVIOR_LAYERS).contains(&layer) };
    if !ok {
        return errno(Errno::EINVAL);
    }
    match family_ops() {
        Some(ops) => ops.behavior(op, layer),
        None => errno(Errno::ENOSYS),
    }
}

/// `SYS_CONFIG_TYPED` — `a0 = Cap<Power>`, `a1 = op`, `a2/a3 = key`,
/// `a4/a5 = value` (the value to set, or the buffer to read into).
pub fn sys_config_typed(cap_raw: u64, op: u64, key_ptr: u64, key_len: u64, val_ptr: u64, val_len: u64) -> i64 {
    let Some(need) = config_op_need(op) else {
        return errno(Errno::EINVAL);
    };
    if let Err(e) = check_power(cap_raw, &need) {
        return e;
    }
    if key_len == 0 || key_len > CONFIG_KEY_MAX || val_len > CONFIG_VAL_MAX
        || (op == CONFIG_OP_SET && val_len == 0)
    {
        return errno(Errno::EINVAL);
    }
    let mut key = [0u8; CONFIG_KEY_MAX as usize];
    let kl = key_len as usize;
    if !azos_sched::copy_from_user(key.as_mut_ptr(), key_ptr as usize, kl) {
        return errno(Errno::EFAULT);
    }
    let mut val = [0u8; CONFIG_VAL_MAX as usize];
    let vl = val_len as usize;
    let Some(ops) = family_ops() else {
        return errno(Errno::ENOSYS);
    };
    if op == CONFIG_OP_SET {
        if !azos_sched::copy_from_user(val.as_mut_ptr(), val_ptr as usize, vl) {
            return errno(Errno::EFAULT);
        }
        let tid = azos_sched::current_task_tid();
        let r = ops.config_set(&key[..kl], &val[..vl]);
        if r == 0 {
            azos_drv_sys::kprintln!("[CFG] set by tid {} (ring 3)", tid);
        }
        return r;
    }
    let n = ops.config_get(&key[..kl], &mut val);
    if n < 0 {
        return n;
    }
    let n = n as usize;
    if n > vl {
        return errno(Errno::EINVAL);
    }
    if n > 0 && !azos_sched::copy_to_user(val_ptr as usize, val.as_ptr(), n) {
        return errno(Errno::EFAULT);
    }
    n as i64
}

/// `SYS_OTA_TYPED` — `a0 = Cap<Power>`, `a1 = op`, `a2 = 0`.
pub fn sys_ota_typed(cap_raw: u64, op: u64, arg: u64) -> i64 {
    let Some(need) = ota_op_need(op) else {
        return errno(Errno::EINVAL);
    };
    if let Err(e) = check_power(cap_raw, &need) {
        return e;
    }
    if arg != 0 {
        return errno(Errno::EINVAL);
    }
    match family_ops() {
        Some(ops) => ops.ota(op),
        None => errno(Errno::ENOSYS),
    }
}
