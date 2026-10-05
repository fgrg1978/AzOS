// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for `SYS_POWER_TYPED` (614, RFC-0055 S5) —
// `crates/core/syscall/src/power.rs::sys_power_typed`.
//
// Included inside `mod handlers { .. }` like `entropy_guards.rs`. Every
// refusal is checked three ways: the errno, that the operation did not run
// (the shim's rate cell and suspend counter), and that one
// `SAFETY_CAP_DENIED_TYPED` record under `CapKind::Power` was handed to the
// recorder. Reboot and shutdown are not called: they do not return.

use super::harness::serial;
use azos_abi::cap::{CapKind, CapPerms};
use azos_abi::error::Errno;
use azos_abi::power::*;
use azos_ipc::cap::targets::{Entropy, Power};
use azos_ipc::cap::Cap;
use std::sync::atomic::{AtomicU32, Ordering};

/// Cap-store pool slot for this file; no other file in this crate binds 62.
const SLOT: usize = 62;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e62_0001);
static POWER_RECORDS: AtomicU32 = AtomicU32::new(0);

fn recorder(kind_code: u8, _reason: u32) {
    if kind_code == CapKind::Power.denial_code() {
        POWER_RECORDS.fetch_add(1, Ordering::SeqCst);
    }
}

fn setup() -> u32 {
    crate::handlers::set_cap_deny_typed_recorder(recorder);
    POWER_RECORDS.store(0, Ordering::SeqCst);
    azos_drv_sys::timebase::sched_hz_set(100);
    let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0);
    azos_sched::set_current_task_tid(tid);
    tid
}

fn grant(tid: u32, perms: CapPerms) -> u64 {
    let c: Cap<Power> = azos_ipc::cap_store::grant(tid, perms, 0).expect("grant");
    c.raw().as_raw() as u64
}

fn suspends() -> u32 {
    azos_drv_power::pm::SUSPENDS.load(Ordering::SeqCst)
}

/// With `Cap<Power>` WRITE the rate is set and read back, and a suspend runs.
#[test]
fn a_holder_of_power_write_sets_the_rate_and_suspends() {
    let _g = serial();
    let tid = setup();
    let cap = grant(tid, CapPerms::RW);
    assert_eq!(crate::power::sys_power_typed(cap, POWER_OP_SCHED_HZ_SET, 250), 0);
    assert_eq!(crate::power::sys_power_typed(cap, POWER_OP_SCHED_HZ_GET, 0), 250);
    let before = suspends();
    assert_eq!(crate::power::sys_power_typed(cap, POWER_OP_SUSPEND, 0), 0);
    assert_eq!(suspends(), before + 1);
    assert_eq!(POWER_RECORDS.load(Ordering::SeqCst), 0, "nothing was refused");
}

/// No capability at all (handle 0 on an empty table): refused, nothing runs,
/// one record per call.
///
/// **Canary** (run). Let every `cap_store::get` answer `Ok`: this test and
/// the read-only one fail (the rate moves, no record is made).
#[test]
fn without_cap_power_every_operation_is_refused_recorded_and_not_run() {
    let _g = serial();
    let _tid = setup();
    let before = suspends();
    for (op, arg) in [(POWER_OP_SCHED_HZ_SET, 300), (POWER_OP_SUSPEND, 0), (POWER_OP_SCHED_HZ_GET, 0),
                      (POWER_OP_REBOOT, 0), (POWER_OP_SHUTDOWN, 0)] {
        assert!(crate::power::sys_power_typed(0, op, arg) < 0, "op {op} was not refused");
    }
    assert_eq!(azos_drv_sys::timebase::sched_hz_get(), 100, "the rate moved");
    assert_eq!(suspends(), before, "a suspend ran");
    assert_eq!(POWER_RECORDS.load(Ordering::SeqCst), 5, "one record per refusal");
}

/// READ is enough to read the rate, not to change anything; a capability of
/// another kind is no `Cap<Power>`.
#[test]
fn read_only_reads_and_another_kind_is_refused() {
    let _g = serial();
    let tid = setup();
    let ro = grant(tid, CapPerms::READ);
    assert_eq!(crate::power::sys_power_typed(ro, POWER_OP_SCHED_HZ_GET, 0), 100);
    assert_eq!(crate::power::sys_power_typed(ro, POWER_OP_SCHED_HZ_SET, 300),
               Errno::ECAPPERMS.to_syscall_ret());
    assert_eq!(azos_drv_sys::timebase::sched_hz_get(), 100);
    let other: Cap<Entropy> = azos_ipc::cap_store::grant(tid, CapPerms::RW, 0).expect("grant");
    let other = other.raw().as_raw() as u64;
    assert_eq!(crate::power::sys_power_typed(other, POWER_OP_SCHED_HZ_SET, 300),
               Errno::ECAPKIND.to_syscall_ret());
    assert_eq!(POWER_RECORDS.load(Ordering::SeqCst), 2);
}

/// An unknown operation is `-EINVAL` before any lookup (and records
/// nothing: it names no right); a rate out of range, or an argument where
/// none is taken, is `-EINVAL` after the check, with nothing changed.
#[test]
fn unknown_operations_and_bad_arguments_are_einval() {
    let _g = serial();
    let tid = setup();
    let cap = grant(tid, CapPerms::RW);
    let einval = Errno::EINVAL.to_syscall_ret();
    assert_eq!(crate::power::sys_power_typed(cap, 0, 0), einval);
    assert_eq!(crate::power::sys_power_typed(0, 99, 0), einval);
    assert_eq!(POWER_RECORDS.load(Ordering::SeqCst), 0);
    for hz in [0, POWER_SCHED_HZ_MIN - 1, POWER_SCHED_HZ_MAX + 1] {
        assert_eq!(crate::power::sys_power_typed(cap, POWER_OP_SCHED_HZ_SET, hz), einval, "{hz}");
    }
    assert_eq!(crate::power::sys_power_typed(cap, POWER_OP_SUSPEND, 1), einval);
    assert_eq!(crate::power::sys_power_typed(cap, POWER_OP_SCHED_HZ_GET, 1), einval);
    assert_eq!(azos_drv_sys::timebase::sched_hz_get(), 100);
}
