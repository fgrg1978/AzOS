// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Conformance of an extension's [`Manifest`] to the extension contract
//! (`azos_ext_api`), over the shipped provider table (`providers.rs`) and the
//! shipped latch sequence (`estop::latch_and_stop`).
//!
//! Each `check_*` takes any manifest whose providers record through [`note`]
//! and holds one clause of the contract:
//!
//! * installing a manifest twice registers each provider once;
//! * a manifest of another contract level is refused and registers nothing;
//! * when the latch arms, every `on_latch` runs, then every `stop`, both
//!   after the latch store, each in provider order;
//! * the panic-path stop takes no lock the ordinary stop may take.
//!
//! The robot's own manifest links the whole robot stack and cannot be built on
//! the host; [`ROBOT_SHAPED`] has its shape (one provider with all four hooks)
//! and [`MIXED`] covers a bare provider and a provider with no latch work.
//! The robot's manifest meets the same clauses through the table, and the
//! kernel's ktest holds that the table carries its providers.

use crate::{estop, providers};
use azos_ext_api::{Manifest, Provider, API_LEVEL};
use std::sync::{Mutex, TryLockError};

#[derive(Debug, PartialEq, Clone, Copy)]
enum Ev {
    OnLatch(&'static str, bool),
    Stop(&'static str, bool),
    PanicStop(&'static str),
    /// The stop found the lock a concurrent holder has.
    Blocked(&'static str),
}

static EVENTS: Mutex<Vec<Ev>> = Mutex::new(Vec::new());
/// The lock a provider's ordinary stop may take.
static STOP_LOCK: Mutex<()> = Mutex::new(());
static SERIAL: Mutex<()> = Mutex::new(());

fn note(e: Ev) {
    EVENTS.lock().unwrap().push(e);
}

fn take() -> Vec<Ev> {
    std::mem::take(&mut *EVENTS.lock().unwrap())
}

macro_rules! provider {
    ($name:literal, latch: $latch:expr, ready: $ready:expr) => {
        Provider {
            name: $name,
            stop: {
                fn stop() {
                    match STOP_LOCK.try_lock() {
                        Ok(_) => note(Ev::Stop($name, estop::estop_is_active())),
                        Err(TryLockError::WouldBlock) => note(Ev::Blocked($name)),
                        Err(TryLockError::Poisoned(_)) => unreachable!(),
                    }
                }
                stop
            },
            panic_stop: {
                fn panic_stop() {
                    note(Ev::PanicStop($name));
                }
                panic_stop
            },
            on_latch: if $latch {
                Some({
                    fn on_latch() {
                        note(Ev::OnLatch($name, estop::estop_is_active()));
                    }
                    on_latch
                })
            } else {
                None
            },
            ready: $ready,
        }
    };
}

fn yes() -> bool {
    true
}

fn no() -> bool {
    false
}

static ROBOT_SHAPED: Manifest = Manifest {
    name: "robot-shaped",
    api_level: API_LEVEL,
    providers: &[provider!("actuators", latch: true, ready: Some(yes))],
};

static MIXED: Manifest = Manifest {
    name: "mixed",
    api_level: API_LEVEL,
    providers: &[
        provider!("bare", latch: false, ready: None),
        provider!("latching", latch: true, ready: None),
        provider!("gated", latch: false, ready: Some(yes)),
    ],
};

fn fresh() -> std::sync::MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    providers::clear_for_tests();
    estop::estop_release(estop::ReleaseAuthority::for_test());
    take();
    g
}

fn check_installs_each_provider_once(m: &'static Manifest) {
    let _g = fresh();
    providers::install(m);
    providers::install(m);
    assert_eq!(providers::count(), m.providers.len(), "`{}`: a repeated install took a second slot", m.name);
}

fn check_other_level_is_refused(m: &'static Manifest) {
    let _g = fresh();
    let other: &'static Manifest =
        Box::leak(Box::new(Manifest { name: m.name, api_level: m.api_level + 1, providers: m.providers }));
    let refused = std::panic::catch_unwind(|| providers::install(other)).is_err();
    assert!(refused, "`{}`: a manifest of contract level {} was installed", m.name, other.api_level);
    assert_eq!(providers::count(), 0, "`{}`: a refused manifest left providers behind", m.name);
}

fn check_latch_runs_the_providers_after_the_latch_store(m: &'static Manifest) {
    let _g = fresh();
    providers::install(m);
    assert!(!estop::estop_is_active());
    estop::latch_and_stop();
    let mut want: Vec<Ev> = Vec::new();
    want.extend(m.providers.iter().filter(|p| p.on_latch.is_some()).map(|p| Ev::OnLatch(p.name, true)));
    want.extend(m.providers.iter().map(|p| Ev::Stop(p.name, true)));
    assert_eq!(take(), want, "`{}`: latch work and stops, in order, each after the latch store", m.name);
}

fn check_panic_stop_takes_no_stop_lock(m: &'static Manifest) {
    let _g = fresh();
    providers::install(m);
    let _held = STOP_LOCK.lock().unwrap();
    providers::panic_stop_all();
    let want: Vec<Ev> = m.providers.iter().map(|p| Ev::PanicStop(p.name)).collect();
    assert_eq!(take(), want, "`{}`: the panic stop waited for, or ran, a stop that takes a lock", m.name);
}

macro_rules! conformance {
    ($($check:ident),* $(,)?) => {
        mod robot_shaped { $(#[test] fn $check() { super::$check(&super::ROBOT_SHAPED); })* }
        mod mixed { $(#[test] fn $check() { super::$check(&super::MIXED); })* }
    };
}

conformance!(
    check_installs_each_provider_once,
    check_other_level_is_refused,
    check_latch_runs_the_providers_after_the_latch_store,
    check_panic_stop_takes_no_stop_lock,
);

/// The table's ordering and gate, over a manifest built by hand.
#[test]
fn providers_run_in_installation_order_and_a_provider_not_ready_closes_the_gate() {
    static NO: Manifest = Manifest {
        name: "not-ready",
        api_level: API_LEVEL,
        providers: &[provider!("closed", latch: false, ready: Some(no))],
    };
    let _g = fresh();
    providers::install(&MIXED);
    assert!(providers::all_ready());
    providers::install(&NO);
    assert!(!providers::all_ready(), "a provider whose gate is not in place left the gate open");
    providers::stop_all();
    assert_eq!(
        take(),
        [Ev::Stop("bare", false), Ev::Stop("latching", false), Ev::Stop("gated", false), Ev::Stop("closed", false)]
    );
}
