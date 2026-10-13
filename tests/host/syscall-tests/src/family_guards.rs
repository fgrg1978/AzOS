// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the wave-12 privileged families, kernel-hosted interfaces
// since D6 part A -- `crates/core/syscall/src/families.rs`: `Flight`,
// `Behavior`, `Config` and `Ota`.
//
// Included inside `mod handlers { .. }` like `power_guards.rs`. The
// operations are a recording stand-in installed through the same seam the
// kernel uses (`set_family_ops`): every refusal is checked by its outcome, by
// the stand-in NOT having been called, and by one `SAFETY_CAP_DENIED_TYPED`
// record under `ty::ENDPOINT`.

use super::harness::serial;
use azos_abi::cap::{CapPerms, ty};
use azos_abi::error::Errno;
use azos_abi::families::*;
use azos_devif::{families::{BEHAVIOR_LAYERS, KEY_WORDS, VALUE_WORDS}, outcome, Behavior, Config, Flight, Ota, Out};
use crate::khost::Caller;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

/// Cap-store pool slot for this file; no other file in this crate binds 56.
const SLOT: usize = 56;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e56_0001);
static ENDPOINT_RECORDS: AtomicU32 = AtomicU32::new(0);
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
    if kind_code == ty::ENDPOINT.denial_code() {
        ENDPOINT_RECORDS.fetch_add(1, Ordering::SeqCst);
    }
}

fn setup() -> u32 {
    crate::handlers::set_cap_deny_typed_recorder(recorder);
    crate::families::set_family_ops(&REC);
    ENDPOINT_RECORDS.store(0, Ordering::SeqCst);
    azos_ipc::cap::degraded_set(false);
    CALLS.store(0, Ordering::SeqCst);
    CONFIG.lock().unwrap().clear();
    let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0);
    azos_sched::set_current_task_tid(tid);
    tid
}

fn who(tid: u32, rights: CapPerms) -> Caller {
    Caller { tid, badge: 0, rights }
}

fn calls() -> u32 {
    CALLS.load(Ordering::SeqCst)
}

/// A key or value as the interface carries it: NUL-padded little-endian words.
fn pack<const N: usize>(text: &[u8]) -> [u64; N] {
    let mut b = [0u8; 64];
    b[..text.len()].copy_from_slice(text);
    core::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap()))
}

/// Flight: `WRITE` arms and disarms; a capability without it is refused,
/// recorded, and the operation does not run.
///
/// **Canary** (run). Let `Caller::allows` answer `true`: the refused rows run
/// the stand-in and this test is red.
#[test]
fn flight_needs_write() {
    let _g = serial();
    let tid = setup();
    let mut ro = crate::families::FlightServer(who(tid, CapPerms::READ));
    assert_eq!(ro.arm(), Out::err(outcome::DENIED));
    assert_eq!(ro.disarm(), Out::err(outcome::DENIED));
    assert_eq!(calls(), 0, "a refused flight op ran");
    assert_eq!(ENDPOINT_RECORDS.load(Ordering::SeqCst), 2, "one record per refusal");
    let mut rw = crate::families::FlightServer(who(tid, CapPerms::RW));
    assert_eq!(rw.arm(), Out::ok(()));
    assert_eq!(LAST.load(Ordering::SeqCst), 0x100 | FLIGHT_OP_ARM);
    assert_eq!(rw.disarm(), Out::ok(()));
    assert_eq!(calls(), 2);
}

/// Behavior: `WRITE` switches a layer 1..3, `READ` reads the mask and
/// switches nothing; layer 0 and out-of-range layers are refused after the
/// right.
#[test]
fn behavior_switches_layers_with_write_and_reads_with_read() {
    let _g = serial();
    let tid = setup();
    let mut rw = crate::families::BehaviorServer(who(tid, CapPerms::RW));
    assert_eq!(rw.disable(2), Out::ok(()));
    assert_eq!(LAST.load(Ordering::SeqCst), 0x200 | BEHAVIOR_OP_DISABLE << 4 | 2);
    for layer in [0u32, BEHAVIOR_LAYERS, 99] {
        assert_eq!(rw.enable(layer).code, outcome::BAD_ARGUMENT, "{layer}");
    }
    let n = calls();
    let mut ro = crate::families::BehaviorServer(who(tid, CapPerms::READ));
    assert_eq!(ro.status(), Out::ok(0b1011));
    assert_eq!(ro.enable(2).code, outcome::DENIED);
    assert_eq!(ro.disable(2).code, outcome::DENIED);
    assert_eq!(calls(), n + 1, "only the status read ran");
    assert_eq!(ENDPOINT_RECORDS.load(Ordering::SeqCst), 2);
}

/// Config: set needs `WRITE` for ANY key, get `READ`; the key and value
/// cross as words and the value comes back as words; a key must be text.
#[test]
fn config_set_needs_write_for_any_key_and_get_returns_the_value() {
    let _g = serial();
    let tid = setup();
    let mut ro = crate::families::ConfigServer(who(tid, CapPerms::READ));
    assert_eq!(ro.set(pack::<KEY_WORDS>(b"log_level"), pack::<VALUE_WORDS>(b"2")).code, outcome::DENIED);
    assert_eq!(calls(), 0);
    assert_eq!(ENDPOINT_RECORDS.load(Ordering::SeqCst), 1);
    let mut rw = crate::families::ConfigServer(who(tid, CapPerms::RW));
    assert_eq!(rw.set(pack::<KEY_WORDS>(b"log_level"), pack::<VALUE_WORDS>(b"2")), Out::ok(()));
    assert_eq!(CONFIG.lock().unwrap().as_slice(), &[(b"log_level".to_vec(), b"2".to_vec())]);
    let got = rw.get(pack::<KEY_WORDS>(b"log_level"));
    assert_eq!(got, Out::ok(pack::<VALUE_WORDS>(b"2")));
    assert_eq!(rw.get(pack::<KEY_WORDS>(b"nope")).code, outcome::NO_RESOURCE);
    // An empty key, an empty value to set.
    assert_eq!(rw.get([0; KEY_WORDS]).code, outcome::BAD_ARGUMENT);
    assert_eq!(rw.set(pack::<KEY_WORDS>(b"k"), [0; VALUE_WORDS]).code, outcome::BAD_ARGUMENT);
    assert_eq!(rw.set([0; KEY_WORDS], pack::<VALUE_WORDS>(b"v")).code, outcome::BAD_ARGUMENT);
    // The longest key and value the interface carries.
    let long_key = [b'k'; azos_devif::families::KEY_MAX];
    let long_val = [b'v'; azos_devif::families::VALUE_MAX];
    assert_eq!(rw.set(pack::<KEY_WORDS>(&long_key), pack::<VALUE_WORDS>(&long_val)), Out::ok(()));
    assert_eq!(rw.get(pack::<KEY_WORDS>(&long_key)), Out::ok(pack::<VALUE_WORDS>(&long_val)));
}

/// OTA: the status word with `READ`, the rollback only with `WRITE`.
#[test]
fn ota_status_reads_and_rollback_needs_write() {
    let _g = serial();
    let tid = setup();
    let mut ro = crate::families::OtaServer(who(tid, CapPerms::READ));
    assert_eq!(ro.status(), Out::ok(ota_status_pack(1, 0, 2, 0)));
    assert_eq!(ro.rollback().code, outcome::DENIED);
    assert_eq!(calls(), 1, "the refused rollback ran");
    let mut rw = crate::families::OtaServer(who(tid, CapPerms::RW));
    assert_eq!(rw.rollback(), Out::ok(1));
}

/// The right is checked before anything else: with no implementation
/// installed (an image without the Robot domain) a caller without the right
/// still gets the refusal and a record, and one with it gets `UNSUPPORTED`.
#[test]
fn the_right_is_checked_before_the_implementation_is_looked_up() {
    let _g = serial();
    let tid = setup();
    crate::families::__family_ops_clear_for_tests();
    let none = crate::families::OtaServer(who(tid, CapPerms::NONE));
    assert_eq!(none.status().code, outcome::DENIED);
    assert_eq!(none.status().code, outcome::DENIED);
    assert_eq!(ENDPOINT_RECORDS.load(Ordering::SeqCst), 2);
    let rw = crate::families::OtaServer(who(tid, CapPerms::RW));
    assert_eq!(rw.status().code, outcome::UNSUPPORTED);
    let b = crate::families::BehaviorServer(who(tid, CapPerms::RW));
    assert_eq!(b.status().code, outcome::UNSUPPORTED);
    crate::families::set_family_ops(&REC);
}
