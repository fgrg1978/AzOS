// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The PID half of `Cap<Motor>`: `SYS_MOTOR_SET_TARGET_TYPED`, `_TICK_`,
// `_ENABLE_`, `_ENABLED_`, `_SET_GAINS_` and `_RESET_TYPED`.
//
// Before this file their only host coverage was `unit6_contain.rs`: the
// forged handle 0 and degraded mode. Neither reaches the rule these calls
// exist to enforce — a pair-wide write needs WRITE on BOTH drivetrain wheels
// (`crates/core/ipc/src/motor_cap.rs`, `require_pair_write`) — nor the wrong kind,
// nor a READ-only capability, nor the admitted path, nor `tick`'s output
// pointer. The capability table, `motor_cap.rs` and `motor_pid.rs` are real.
//
// A refused call must leave the controller as it was, so the refusals toggle
// `enabled` (the one piece of PID state a handler reads back) and check it
// did not move.

use super::harness::serial;
use azos_abi::cap::{CapKind, CapPerms};
use azos_abi::error::Errno;
use azos_abi::syscall_nr::MOTOR_TICK_OUT_BYTES;
use azos_arch_api::PagePerms;

/// The cap-store pool slot this file binds its caller to (unused elsewhere).
const SLOT: usize = 31;
const TID: u32 = 0x5200_0001;
const OUT_VA: usize = 0x0077_0000;
/// Never mapped by this file.
const UNMAPPED_VA: usize = 0x0078_0000;

/// Puts the controller's `enabled` flag back as the test found it.
struct Restore(bool);

impl Drop for Restore {
    fn drop(&mut self) {
        // The PID state is global; put it back through a fresh pair in this
        // caller's own table, the only way a typed call reaches it.
        azos_sched::set_current_task_tid(TID);
        azos_ipc::cap_store::reset(TID);
        let l = held(CapPerms::RW, 0);
        let _r = held(CapPerms::RW, 1);
        let _ = super::sys_motor_enable_typed(l, self.0 as u64);
        azos_ipc::cap_store::reset(TID);
    }
}

/// Ring 3 with an empty table and one writable page at [`OUT_VA`]; returns
/// its host pointer.
fn ring3() -> *mut u8 {
    ipc_task_pool::shim_bind(TID, SLOT);
    azos_ipc::cap_store::reset(TID);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, OUT_VA, phys, PagePerms::USER_RW).expect("map");
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0xEE, 64) };
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(TID);
    phys as *mut u8
}

fn held(perms: CapPerms, wheel: u32) -> u64 {
    azos_ipc::motor_cap::motor_grant_cap(TID, wheel, perms)
        .expect("motor cap not minted")
        .raw()
        .as_raw() as u64
}

fn gpio_cap() -> u64 {
    azos_ipc::cap_store::grant::<azos_ipc::cap::targets::Gpio>(TID, CapPerms::RW, 5)
        .expect("cap table full")
        .raw()
        .as_raw() as u64
}

fn enabled_now(read_cap: u64) -> i64 {
    super::sys_motor_enabled_typed(read_cap)
}

/// The five pair-wide writes, as `(label, fn(cap) -> rc)`.
fn pair_writes() -> [(&'static str, fn(u64) -> i64); 5] {
    [
        ("set_target", |c| super::sys_motor_set_target_typed(c, 10, 10)),
        ("tick", |c| super::sys_motor_tick_typed(c, 0, 0, 0, OUT_VA as u64)),
        ("set_gains", |c| super::sys_motor_set_gains_typed(c, 1, 0, 0)),
        ("reset", super::sys_motor_reset_typed),
        ("enable", |c| super::sys_motor_enable_typed(c, 0)),
    ]
}

fn ecapperms() -> i64 { Errno::ECAPPERMS.to_syscall_ret() }

/// Admitted: WRITE on both wheels. Every write answers 0 (tick: its byte
/// count), `enabled` reads what `enable` set, and `tick` fills the caller's
/// buffer.
#[test]
fn the_pair_holder_drives_the_controller() {
    let _g = serial();
    let out = ring3();
    let l = held(CapPerms::RW, 0);
    let _r = held(CapPerms::RW, 1);
    let _restore = Restore(enabled_now(l) == 1);

    assert_eq!(super::sys_motor_enable_typed(l, 0), 0);
    assert_eq!(enabled_now(l), 0);
    assert_eq!(super::sys_motor_enable_typed(l, 1), 0);
    assert_eq!(enabled_now(l), 1);
    assert_eq!(super::sys_motor_set_gains_typed(l, 2, 1, 0), 0);
    assert_eq!(super::sys_motor_set_target_typed(l, 100, 100), 0);
    assert_eq!(super::sys_motor_reset_typed(l), 0);
    assert_eq!(
        super::sys_motor_tick_typed(l, 0, 0, 0, OUT_VA as u64),
        MOTOR_TICK_OUT_BYTES as i64,
    );
    let written = unsafe { core::slice::from_raw_parts(out, MOTOR_TICK_OUT_BYTES) };
    assert!(written.iter().all(|&b| b != 0xEE), "tick did not write its output: {written:02x?}");
}

/// Refusal: WRITE on ONE wheel is not the pair. `ECAPPERMS` from each write,
/// and the refused `enable(0)` left the controller enabled.
#[test]
fn one_wheel_is_not_the_pair() {
    let _g = serial();
    ring3();
    let l = held(CapPerms::RW, 0);
    let _restore = Restore(enabled_now(l) == 1);
    // Put the controller in a known state through a pair held briefly by
    // this same caller, then take the second wheel away.
    let r = held(CapPerms::RW, 1);
    assert_eq!(super::sys_motor_enable_typed(l, 1), 0);
    let gone = azos_ipc::cap_store::with_table(TID, |t| {
        t.revoke_raw(azos_abi::cap::CapHandle::from_raw(r as u32))
    });
    assert_eq!(gone, Some(true), "could not take the second wheel back");

    for (label, call) in pair_writes() {
        assert_eq!(call(l), ecapperms(), "{label} with one wheel");
    }
    assert_eq!(enabled_now(l), 1, "a refused enable(0) disabled the controller");
}

/// Refusal: READ on both wheels. Every write is `ECAPPERMS`; `enabled`, the
/// one READ, is admitted — and refused to a WRITE-only capability.
#[test]
fn a_read_only_pair_can_read_and_not_write() {
    let _g = serial();
    ring3();
    let l = held(CapPerms::READ, 0);
    let _r = held(CapPerms::READ, 1);
    let before = enabled_now(l);
    assert!(before == 0 || before == 1, "the READ was refused: {before}");
    for (label, call) in pair_writes() {
        assert_eq!(call(l), ecapperms(), "{label} with READ");
    }
    // And the read needs READ: a WRITE-only capability cannot ask.
    let w = held(CapPerms::WRITE, 0);
    assert_eq!(enabled_now(w), ecapperms(), "enabled with WRITE only");
}

/// Refusal: a capability of another kind is `ECAPKIND`, from the writes and
/// the read alike.
#[test]
fn a_gpio_capability_is_the_wrong_kind() {
    let _g = serial();
    ring3();
    let g = gpio_cap();
    for (label, call) in pair_writes() {
        assert_eq!(call(g), Errno::ECAPKIND.to_syscall_ret(), "{label}");
    }
    assert_eq!(enabled_now(g), Errno::ECAPKIND.to_syscall_ret(), "enabled");
}

/// Refusal: `tick` checks its output pointer before the capability — a null
/// pointer is `EINVAL` even for the forged handle 0 — and an unmapped one is
/// `EFAULT`. The EFAULT comes AFTER the controller ticked: the output is lost,
/// the state change is not (the same shape as `SYS_WAIT_STATUS`).
#[test]
fn tick_refuses_a_null_or_unmapped_output_pointer() {
    let _g = serial();
    ring3();
    assert_eq!(super::sys_motor_tick_typed(0, 0, 0, 0, 0), Errno::EINVAL.to_syscall_ret(), "null, forged cap");
    let l = held(CapPerms::RW, 0);
    let _r = held(CapPerms::RW, 1);
    assert_eq!(super::sys_motor_tick_typed(l, 0, 0, 0, 0), Errno::EINVAL.to_syscall_ret(), "null");
    assert_eq!(
        super::sys_motor_tick_typed(l, 0, 0, 0, UNMAPPED_VA as u64),
        Errno::EFAULT.to_syscall_ret(),
        "unmapped",
    );
}
