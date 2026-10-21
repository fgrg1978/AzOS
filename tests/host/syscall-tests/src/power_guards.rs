// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the kernel-hosted `Power` interface (the power service, an endpoint
// op since D6 part A) -- `crates/core/syscall/src/power.rs::Server`.
//
// Included inside `mod handlers { .. }` like `entropy_guards.rs`. Every
// refusal is checked three ways: the outcome, that the operation did not run
// (the shim's rate cell and suspend counter), and that one
// `SAFETY_CAP_DENIED_TYPED` record under `ty::ENDPOINT` was handed to the
// recorder. Reboot and shutdown are not called: they do not return.

use super::harness::serial;
use azos_abi::cap::{CapPerms, ty};
use azos_abi::power::*;
use azos_devif::{outcome, Out, Power};
use crate::khost::Caller;
use std::sync::atomic::{AtomicU32, Ordering};

/// Cap-store pool slot for this file; no other file in this crate binds 62.
const SLOT: usize = 62;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e62_0001);
static ENDPOINT_RECORDS: AtomicU32 = AtomicU32::new(0);

fn recorder(kind_code: u8, _reason: u32) {
    if kind_code == ty::ENDPOINT.denial_code() {
        ENDPOINT_RECORDS.fetch_add(1, Ordering::SeqCst);
    }
}

fn setup() -> u32 {
    crate::handlers::set_cap_deny_typed_recorder(recorder);
    ENDPOINT_RECORDS.store(0, Ordering::SeqCst);
    azos_drv_sys::timebase::sched_hz_set(100);
    azos_ipc::cap::degraded_set(false);
    let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0);
    azos_sched::set_current_task_tid(tid);
    tid
}

fn server(tid: u32, rights: CapPerms) -> crate::power::Server {
    crate::power::Server(Caller { tid, badge: 0, rights })
}

fn suspends() -> u32 {
    azos_drv_power::pm::SUSPENDS.load(Ordering::SeqCst)
}

/// With `WRITE` (and `READ`) the rate is set and read back, and a suspend runs.
#[test]
fn a_holder_of_write_sets_the_rate_and_suspends() {
    let _g = serial();
    let tid = setup();
    let mut s = server(tid, CapPerms::RW);
    assert_eq!(s.set_sched_hz(250), Out::ok(()));
    assert_eq!(s.sched_hz(), Out::ok(250));
    let before = suspends();
    assert_eq!(s.suspend(), Out::ok(0));
    assert_eq!(suspends(), before + 1);
    assert_eq!(ENDPOINT_RECORDS.load(Ordering::SeqCst), 0, "nothing was refused");
}

/// A suspend the sequence refuses answers `REFUSED` with the reason's code, so
/// the caller learns why and not only that.
///
/// **Canary** (run). Make `suspend` answer `Out::err(outcome::REFUSED)`: the
/// reason reads back as 0 and this test fails.
#[test]
fn a_refused_suspend_answers_with_its_reason() {
    use azos_drv_power::pm::REFUSE_WITH;
    let _g = serial();
    let tid = setup();
    let mut s = server(tid, CapPerms::RW);
    let before = suspends();
    REFUSE_WITH.store(8, Ordering::SeqCst);
    let out = s.suspend();
    REFUSE_WITH.store(0, Ordering::SeqCst);
    assert_eq!(out, Out::new(outcome::REFUSED, 8));
    assert_eq!(suspends(), before, "a refused suspend counted as taken");
}

/// A capability with no op class the op needs: refused, nothing runs, one
/// record per call.
///
/// **Canary** (run). Let `Caller::allows` answer `true`: this test and the
/// read-only one fail (the rate moves, no record is made).
#[test]
fn without_the_right_every_operation_is_refused_recorded_and_not_run() {
    let _g = serial();
    let tid = setup();
    let before = suspends();
    let mut s = server(tid, CapPerms::NONE);
    assert_eq!(s.set_sched_hz(300).code, outcome::DENIED);
    assert_eq!(s.suspend().code, outcome::DENIED);
    assert_eq!(s.sched_hz().code, outcome::DENIED);
    assert_eq!(azos_drv_sys::timebase::sched_hz_get(), 100, "the rate moved");
    assert_eq!(suspends(), before, "a suspend ran");
    assert_eq!(ENDPOINT_RECORDS.load(Ordering::SeqCst), 3, "one record per refusal");
}

/// `READ` is enough to read the rate, not to change anything; `WRITE` alone
/// changes but does not observe.
#[test]
fn read_only_reads_and_write_only_writes() {
    let _g = serial();
    let tid = setup();
    let mut ro = server(tid, CapPerms::READ);
    assert_eq!(ro.sched_hz(), Out::ok(100));
    assert_eq!(ro.set_sched_hz(300).code, outcome::DENIED);
    assert_eq!(azos_drv_sys::timebase::sched_hz_get(), 100);
    let mut wo = server(tid, CapPerms::WRITE);
    assert_eq!(wo.sched_hz().code, outcome::DENIED);
    assert_eq!(wo.set_sched_hz(300), Out::ok(()));
    assert_eq!(azos_drv_sys::timebase::sched_hz_get(), 300);
    assert_eq!(ENDPOINT_RECORDS.load(Ordering::SeqCst), 2);
}

/// A contained system refuses the acting class and keeps observation live
/// (brain-triggered degraded mode), and the refusal is not a missing-grant record.
///
/// **Canary.** Drop the containment test in `Caller::allows`: the write is
/// served while contained.
#[test]
fn containment_refuses_the_acting_class_only() {
    let _g = serial();
    let tid = setup();
    azos_ipc::cap::degraded_set(true);
    let mut s = server(tid, CapPerms::RW);
    let write = s.set_sched_hz(300);
    let read = s.sched_hz();
    azos_ipc::cap::degraded_set(false);
    assert_eq!(write.code, outcome::DENIED, "a contained system must not change the rate");
    assert_eq!(read, Out::ok(100), "observation stays live");
    assert_eq!(azos_drv_sys::timebase::sched_hz_get(), 100);
}

/// A rate out of range is `BAD_ARGUMENT` after the right was checked, with
/// nothing changed.
#[test]
fn a_rate_out_of_range_is_a_bad_argument() {
    let _g = serial();
    let tid = setup();
    let mut s = server(tid, CapPerms::RW);
    for hz in [0, POWER_SCHED_HZ_MIN - 1, POWER_SCHED_HZ_MAX + 1] {
        assert_eq!(s.set_sched_hz(hz).code, outcome::BAD_ARGUMENT, "{hz}");
    }
    assert_eq!(azos_drv_sys::timebase::sched_hz_get(), 100);
    assert_eq!(ENDPOINT_RECORDS.load(Ordering::SeqCst), 0, "a bad argument is not a refusal");
}

/// The energy policy operations: the right is checked FIRST, exactly as the
/// rest of the interface (a setter needs `WRITE`, a reader `READ`; every
/// refusal is recorded). Only then does the kernel look at the value; this
/// host build has no `energy`, so a holder is answered `UNSUPPORTED`, never
/// served.
///
/// **Canary** (run). Let `allows` answer `true`: the no-right and read-only
/// rows fail.
#[test]
fn the_policy_operations_check_the_right_first() {
    let _g = serial();
    let tid = setup();
    let mut none = server(tid, CapPerms::NONE);
    assert_eq!(none.set_governor(0).code, outcome::DENIED);
    assert_eq!(none.set_opp_range(0, 0, 1).code, outcome::DENIED);
    assert_eq!(none.set_headroom(50).code, outcome::DENIED);
    assert_eq!(none.set_rate_limit(1000).code, outcome::DENIED);
    assert_eq!(none.set_idle_depth(0).code, outcome::DENIED);
    assert_eq!(none.state(0).code, outcome::DENIED);
    assert_eq!(none.stats(0).code, outcome::DENIED);
    assert_eq!(ENDPOINT_RECORDS.load(Ordering::SeqCst), 7);
    let mut ro = server(tid, CapPerms::READ);
    assert_eq!(ro.set_governor(0).code, outcome::DENIED);
    assert_eq!(ro.set_opp_range(0, 0, 1).code, outcome::DENIED);
    assert_eq!(ro.set_headroom(50).code, outcome::DENIED);
    assert_eq!(ro.set_rate_limit(1000).code, outcome::DENIED);
    assert_eq!(ro.set_idle_depth(0).code, outcome::DENIED);
    assert_eq!(ro.state(0).code, outcome::UNSUPPORTED, "READ reads");
    assert_eq!(ro.stats(0).code, outcome::UNSUPPORTED, "READ reads");
    let mut rw = server(tid, CapPerms::RW);
    assert_eq!(rw.set_governor(0).code, outcome::UNSUPPORTED);
    assert_eq!(rw.set_opp_range(0, 0, 1).code, outcome::UNSUPPORTED);
    assert_eq!(rw.set_headroom(50).code, outcome::UNSUPPORTED);
    assert_eq!(rw.set_rate_limit(1000).code, outcome::UNSUPPORTED);
    assert_eq!(rw.set_idle_depth(0).code, outcome::UNSUPPORTED);
    // An opp range is checked for its fields before it is applied.
    assert_eq!(rw.set_opp_range(300, 0, 1).code, outcome::BAD_ARGUMENT);
}

/// `cpu_online`: the right (`WRITE`) is checked first like every setter; then
/// the direction (`on` is 0 or 1), then the build (Kconfig `CPU_HOTPLUG`: off,
/// a holder is answered `UNSUPPORTED`, never served; on, the call reaches the
/// scheduler, which refuses it here because the host has no CPU 1 to move);
/// the scheduler's own refusals are its host suite's
/// (`sched-policy-tests/src/cpu_power.rs`).
///
/// **Canary** (run). Let `allows` answer `true`: the no-right and read-only
/// rows fail.
#[test]
fn cpu_online_checks_the_right_then_the_direction_then_the_build() {
    let _g = serial();
    let tid = setup();
    let mut none = server(tid, CapPerms::NONE);
    assert_eq!(none.cpu_online(1, 0).code, outcome::DENIED);
    assert_eq!(ENDPOINT_RECORDS.load(Ordering::SeqCst), 1);
    let mut ro = server(tid, CapPerms::READ);
    assert_eq!(ro.cpu_online(1, 0).code, outcome::DENIED, "READ reads, it does not stop a CPU");
    let mut rw = server(tid, CapPerms::RW);
    assert_eq!(rw.cpu_online(1, 2).code, outcome::BAD_ARGUMENT);
    let built = if azos_limits::CPU_HOTPLUG { outcome::REFUSED } else { outcome::UNSUPPORTED };
    assert_eq!(rw.cpu_online(1, 0).code, built);
    assert_eq!(rw.cpu_online(1, 1).code, built);
}
