// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the service registry's authority (owner decision
// 2026-09-27, round 7), against the REAL `crates/core/service` source and the
// real `sys_service_*` handlers.
//
// Before: `SYS_SERVICE_REGISTER` registered whatever TID a1 named, so a task
// could publish a name that resolved to another task; `SYS_SERVICE_STOP` and
// `SYS_SERVICE_HEARTBEAT` acted on any name. Each test below names the input
// at which the pre-fix handler gives a different answer.
//
// The registry is process-global and has no reset, so every test uses its
// own service name.

use super::harness::serial;
use super::{
    set_service_refused_recorder, sys_service_discover, sys_service_heartbeat,
    sys_service_register, sys_service_stop_handler, SERVICE_OP_HEARTBEAT,
    SERVICE_OP_REGISTER, SERVICE_OP_STOP,
};
use std::sync::Mutex;

/// The handlers' `E_PERM` (`crates/core/syscall/src/handlers.rs`, -99).
const E_PERM: i64 = -99;

static SEEN: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());
fn recorder(op: u8, detail: u32) { SEEN.lock().unwrap().push((op, detail)); }

fn setup(tid: u32) {
    SEEN.lock().unwrap().clear();
    set_service_refused_recorder(recorder);
    azos_sched::set_current_task_tid(tid);
}

fn p(name: &[u8]) -> u64 { name.as_ptr() as u64 }

fn state_of(name: &[u8]) -> Option<azos_service::ServiceState> {
    let want = &name[..name.len() - 1];
    let mut out = None;
    azos_service::service_list(|e| {
        let n = e.name.iter().position(|&b| b == 0).unwrap_or(e.name.len());
        if &e.name[..n] == want { out = Some(e.state); }
    });
    out
}

#[test]
fn register_under_another_tid_is_refused_and_recorded() {
    let _g = serial();
    setup(7);
    let name = b"svc.auth.spoof\0";
    assert_eq!(sys_service_register(p(name), 9, 0), E_PERM);
    assert_eq!(*SEEN.lock().unwrap(), vec![(SERVICE_OP_REGISTER, 9)]);
    // Pre-fix: the name existed and resolved to TID 9.
    assert_eq!(sys_service_discover(p(name)), -1);
}

#[test]
fn register_binds_the_caller_whatever_a1_says_when_zero_or_self() {
    let _g = serial();
    setup(11);
    assert_eq!(sys_service_register(p(b"svc.auth.zero\0"), 0, 0), 0);
    // Pre-fix: TID 0 was registered, and discover answered 0.
    assert_eq!(sys_service_discover(p(b"svc.auth.zero\0")), 11);
    assert_eq!(sys_service_register(p(b"svc.auth.self\0"), 11, 0), 0);
    assert_eq!(sys_service_discover(p(b"svc.auth.self\0")), 11);
    assert!(SEEN.lock().unwrap().is_empty());
}

#[test]
fn only_the_owner_may_stop() {
    let _g = serial();
    setup(21);
    let name = b"svc.auth.stop\0";
    assert_eq!(sys_service_register(p(name), 0, 0), 0);
    azos_sched::set_current_task_tid(22);
    assert_eq!(sys_service_stop_handler(p(name)), E_PERM);
    assert_eq!(*SEEN.lock().unwrap(), vec![(SERVICE_OP_STOP, 21)]);
    // Pre-fix: Stopped.
    assert!(state_of(name) == Some(azos_service::ServiceState::Running));
    azos_sched::set_current_task_tid(21);
    assert_eq!(sys_service_stop_handler(p(name)), 0);
    assert!(state_of(name) == Some(azos_service::ServiceState::Stopped));
    assert_eq!(sys_service_stop_handler(p(b"svc.auth.none\0")), -1);
}

#[test]
fn only_the_owner_may_heartbeat() {
    let _g = serial();
    setup(31);
    let name = b"svc.auth.beat\0";
    assert_eq!(sys_service_register(p(name), 0, 0), 0);
    azos_sched::set_current_task_tid(32);
    assert_eq!(sys_service_heartbeat(p(name)), E_PERM);
    assert_eq!(*SEEN.lock().unwrap(), vec![(SERVICE_OP_HEARTBEAT, 31)]);
    azos_sched::set_current_task_tid(31);
    assert_eq!(sys_service_heartbeat(p(name)), 0);
    let mut beats = 0;
    azos_service::service_list(|e| if e.tid == 31 { beats = e.heartbeat });
    // Pre-fix: 2 — the stranger's claim counted.
    assert_eq!(beats, 1);
}

#[test]
fn a_dead_owners_names_are_released() {
    let _g = serial();
    setup(51);
    let name = b"svc.auth.dies\0";
    assert_eq!(sys_service_register(p(name), 0, 0), 0);
    assert_eq!(sys_service_register(p(b"svc.auth.dies2\0"), 0, 0), 0);
    // The kernel's task-exit hook.
    assert_eq!(azos_service::service_release_all(51), 2);
    // Pre-fix: still 51, forever.
    assert_eq!(sys_service_discover(p(name)), -1);
    // And the name is free for the next task.
    azos_sched::set_current_task_tid(52);
    assert_eq!(sys_service_register(p(name), 0, 0), 0);
    assert_eq!(sys_service_discover(p(name)), 52);
    assert_eq!(azos_service::service_release_all(51), 0);
}
