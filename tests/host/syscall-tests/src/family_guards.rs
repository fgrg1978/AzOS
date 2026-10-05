// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the wave-12 privileged families —
// `crates/core/syscall/src/families.rs`: `SYS_FLIGHT_TYPED` (615),
// `SYS_BEHAVIOR_TYPED` (616), `SYS_CONFIG_TYPED` (617), `SYS_OTA_TYPED` (618).
//
// Included inside `mod handlers { .. }` like `power_guards.rs`. The
// operations are a recording stand-in installed through the same seam the
// kernel uses (`set_family_ops`): every refusal is checked by its errno, by
// the stand-in NOT having been called, and by one `SAFETY_CAP_DENIED_TYPED`
// record under the family's kind.

use super::harness::serial;
use azos_abi::cap::{CapKind, CapPerms};
use azos_abi::error::Errno;
use azos_abi::families::*;
use azos_ipc::cap::targets::{Entropy, Motor, Power};
use azos_ipc::cap::Cap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

/// Cap-store pool slot for this file; no other file in this crate binds 56.
const SLOT: usize = 56;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e56_0001);
static MOTOR_RECORDS: AtomicU32 = AtomicU32::new(0);
static POWER_RECORDS: AtomicU32 = AtomicU32::new(0);
/// Calls the stand-in received, and the last (family, op, arg).
static CALLS: AtomicU32 = AtomicU32::new(0);
static LAST: AtomicU64 = AtomicU64::new(0);
static CONFIG: Mutex<Vec<(Vec<u8>, Vec<u8>)>> = Mutex::new(Vec::new());

struct Rec;

impl crate::families::FamilyOps for Rec {
    fn flight(&self, op: u64) -> i64 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        LAST.store(0x100 | op, Ordering::SeqCst);
        0
    }
    fn behavior(&self, op: u64, layer: u64) -> i64 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        LAST.store(0x200 | op << 4 | layer, Ordering::SeqCst);
        if op == BEHAVIOR_OP_STATUS { 0b1011 } else { 0 }
    }
    fn config_get(&self, key: &[u8], out: &mut [u8]) -> i64 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        match CONFIG.lock().unwrap().iter().find(|(k, _)| k == key) {
            Some((_, v)) => {
                out[..v.len()].copy_from_slice(v);
                v.len() as i64
            }
            None => Errno::ENOENT.to_syscall_ret(),
        }
    }
    fn config_set(&self, key: &[u8], val: &[u8]) -> i64 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        let mut c = CONFIG.lock().unwrap();
        c.retain(|(k, _)| k != key);
        c.push((key.to_vec(), val.to_vec()));
        0
    }
    fn ota(&self, op: u64) -> i64 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        LAST.store(0x400 | op, Ordering::SeqCst);
        if op == OTA_OP_STATUS { ota_status_pack(1, 0, 2, 0) as i64 } else { 1 }
    }
}

static REC: Rec = Rec;

fn recorder(kind_code: u8, _reason: u32) {
    if kind_code == CapKind::Motor.denial_code() {
        MOTOR_RECORDS.fetch_add(1, Ordering::SeqCst);
    }
    if kind_code == CapKind::Power.denial_code() {
        POWER_RECORDS.fetch_add(1, Ordering::SeqCst);
    }
}

fn setup() -> u32 {
    crate::handlers::set_cap_deny_typed_recorder(recorder);
    crate::families::set_family_ops(&REC);
    MOTOR_RECORDS.store(0, Ordering::SeqCst);
    POWER_RECORDS.store(0, Ordering::SeqCst);
    CALLS.store(0, Ordering::SeqCst);
    CONFIG.lock().unwrap().clear();
    let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0);
    azos_sched::set_current_task_tid(tid);
    tid
}

fn power(tid: u32, perms: CapPerms) -> u64 {
    let c: Cap<Power> = azos_ipc::cap_store::grant(tid, perms, 0).expect("grant");
    c.raw().as_raw() as u64
}

fn motor(tid: u32, wheel: u32, perms: CapPerms) -> u64 {
    let c: Cap<Motor> = azos_ipc::cap_store::grant(tid, perms, wheel).expect("grant");
    c.raw().as_raw() as u64
}

fn calls() -> u32 {
    CALLS.load(Ordering::SeqCst)
}

/// Flight is pair-wide: a `Cap<Motor>` WRITE on one wheel arms nothing
/// unless the table also holds WRITE on the other — the console's check.
///
/// **Canary** (run). Make `drivetrain_write_check` check only the presented
/// capability (`table.get(cap, WRITE)`): the one-wheel arm goes through and
/// this test is red.
#[test]
fn flight_needs_write_on_both_wheels() {
    let _g = serial();
    let tid = setup();
    let w0 = motor(tid, 0, CapPerms::RW);
    assert_eq!(crate::families::sys_flight_typed(w0, FLIGHT_OP_ARM, 0),
               Errno::ECAPPERMS.to_syscall_ret(), "one wheel armed");
    assert_eq!(crate::families::sys_flight_typed(0, FLIGHT_OP_DISARM, 0) < 0, true);
    assert_eq!(calls(), 0, "a refused flight op ran");
    assert_eq!(MOTOR_RECORDS.load(Ordering::SeqCst), 2, "one record per refusal");
    let _w1 = motor(tid, 1, CapPerms::RW);
    assert_eq!(crate::families::sys_flight_typed(w0, FLIGHT_OP_ARM, 0), 0);
    assert_eq!(LAST.load(Ordering::SeqCst), 0x100 | FLIGHT_OP_ARM);
    assert_eq!(crate::families::sys_flight_typed(w0, FLIGHT_OP_DISARM, 0), 0);
    assert_eq!(calls(), 2);
    let einval = Errno::EINVAL.to_syscall_ret();
    assert_eq!(crate::families::sys_flight_typed(w0, 3, 0), einval);
    assert_eq!(crate::families::sys_flight_typed(w0, FLIGHT_OP_ARM, 1), einval);
}

/// Behavior: `WRITE` switches a layer 1..3, `READ` reads the mask and
/// switches nothing; layer 0 and out-of-range layers are refused after the
/// capability; another kind is no `Cap<Power>`.
#[test]
fn behavior_switches_layers_with_write_and_reads_with_read() {
    let _g = serial();
    let tid = setup();
    let rw = power(tid, CapPerms::RW);
    assert_eq!(crate::families::sys_behavior_typed(rw, BEHAVIOR_OP_DISABLE, 2), 0);
    assert_eq!(LAST.load(Ordering::SeqCst), 0x200 | BEHAVIOR_OP_DISABLE << 4 | 2);
    let einval = Errno::EINVAL.to_syscall_ret();
    for layer in [0u64, BEHAVIOR_LAYERS, 99] {
        assert_eq!(crate::families::sys_behavior_typed(rw, BEHAVIOR_OP_ENABLE, layer), einval, "{layer}");
    }
    assert_eq!(crate::families::sys_behavior_typed(rw, BEHAVIOR_OP_STATUS, 1), einval);
    let n = calls();
    let tid2 = setup();
    let ro = power(tid2, CapPerms::READ);
    assert_eq!(crate::families::sys_behavior_typed(ro, BEHAVIOR_OP_STATUS, 0), 0b1011);
    assert_eq!(crate::families::sys_behavior_typed(ro, BEHAVIOR_OP_ENABLE, 2),
               Errno::ECAPPERMS.to_syscall_ret());
    let other: Cap<Entropy> = azos_ipc::cap_store::grant(tid2, CapPerms::RW, 0).expect("grant");
    assert_eq!(crate::families::sys_behavior_typed(other.raw().as_raw() as u64, BEHAVIOR_OP_DISABLE, 2),
               Errno::ECAPKIND.to_syscall_ret());
    assert_eq!(calls(), 1, "only the status read ran (calls before setup: {n})");
    assert_eq!(POWER_RECORDS.load(Ordering::SeqCst), 2);
}

/// Config: set needs `WRITE` for ANY key, get `READ`; the key and value are
/// copied in and the value copied out; lengths are checked.
#[test]
fn config_set_needs_write_for_any_key_and_get_copies_out() {
    let _g = serial();
    let tid = setup();
    let ro = power(tid, CapPerms::READ);
    let mut v = *b"2";
    assert_eq!(crate::families::sys_config_typed(ro, CONFIG_OP_SET, b"log_level".as_ptr() as u64, 9,
               v.as_mut_ptr() as u64, 1), Errno::ECAPPERMS.to_syscall_ret());
    assert_eq!(calls(), 0);
    assert_eq!(POWER_RECORDS.load(Ordering::SeqCst), 1);
    let tid = setup();
    let rw = power(tid, CapPerms::RW);
    assert_eq!(crate::families::sys_config_typed(rw, CONFIG_OP_SET, b"log_level".as_ptr() as u64, 9,
               v.as_mut_ptr() as u64, 1), 0);
    assert_eq!(CONFIG.lock().unwrap().as_slice(), &[(b"log_level".to_vec(), b"2".to_vec())]);
    let mut out = [0u8; 8];
    assert_eq!(crate::families::sys_config_typed(rw, CONFIG_OP_GET, b"log_level".as_ptr() as u64, 9,
               out.as_mut_ptr() as u64, out.len() as u64), 1);
    assert_eq!(out[0], b'2');
    assert_eq!(crate::families::sys_config_typed(rw, CONFIG_OP_GET, b"nope".as_ptr() as u64, 4,
               out.as_mut_ptr() as u64, out.len() as u64), Errno::ENOENT.to_syscall_ret());
    let einval = Errno::EINVAL.to_syscall_ret();
    // A buffer shorter than the value, no key, a key past the limit, an empty
    // value to set, an unknown op.
    assert_eq!(crate::families::sys_config_typed(rw, CONFIG_OP_GET, b"log_level".as_ptr() as u64, 9,
               out.as_mut_ptr() as u64, 0), einval);
    assert_eq!(crate::families::sys_config_typed(rw, CONFIG_OP_GET, 0, 0, 0, 0), einval);
    let long = [b'k'; CONFIG_KEY_MAX as usize + 1];
    assert_eq!(crate::families::sys_config_typed(rw, CONFIG_OP_SET, long.as_ptr() as u64, long.len() as u64,
               v.as_mut_ptr() as u64, 1), einval);
    assert_eq!(crate::families::sys_config_typed(rw, CONFIG_OP_SET, b"k".as_ptr() as u64, 1,
               v.as_mut_ptr() as u64, 0), einval);
    assert_eq!(crate::families::sys_config_typed(rw, 9, b"k".as_ptr() as u64, 1, 0, 0), einval);
}

/// OTA: the status word with `READ`, the rollback only with `WRITE`.
#[test]
fn ota_status_reads_and_rollback_needs_write() {
    let _g = serial();
    let tid = setup();
    let ro = power(tid, CapPerms::READ);
    assert_eq!(crate::families::sys_ota_typed(ro, OTA_OP_STATUS, 0), ota_status_pack(1, 0, 2, 0) as i64);
    assert_eq!(crate::families::sys_ota_typed(ro, OTA_OP_ROLLBACK, 0), Errno::ECAPPERMS.to_syscall_ret());
    assert_eq!(calls(), 1, "the refused rollback ran");
    let rw = power(tid, CapPerms::RW);
    assert_eq!(crate::families::sys_ota_typed(rw, OTA_OP_ROLLBACK, 0), 1);
    assert_eq!(crate::families::sys_ota_typed(rw, OTA_OP_ROLLBACK, 7), Errno::EINVAL.to_syscall_ret());
}

/// The capability is checked before anything else: with no implementation
/// installed (an image without the Robot domain) a caller without the
/// capability still gets the capability's errno and a record, and one with
/// it gets `-ENOSYS`.
#[test]
fn the_capability_is_checked_before_the_implementation_is_looked_up() {
    let _g = serial();
    let tid = setup();
    crate::families::__family_ops_clear_for_tests();
    assert!(crate::families::sys_ota_typed(0, OTA_OP_STATUS, 0) < 0);
    assert_ne!(crate::families::sys_ota_typed(0, OTA_OP_STATUS, 0), Errno::ENOSYS.to_syscall_ret());
    assert_eq!(POWER_RECORDS.load(Ordering::SeqCst), 2);
    let rw = power(tid, CapPerms::RW);
    assert_eq!(crate::families::sys_ota_typed(rw, OTA_OP_STATUS, 0), Errno::ENOSYS.to_syscall_ret());
    assert_eq!(crate::families::sys_behavior_typed(rw, BEHAVIOR_OP_STATUS, 0), Errno::ENOSYS.to_syscall_ret());
    crate::families::set_family_ops(&REC);
}
