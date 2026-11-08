// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Conformance of an extension's [`Manifest`] to the extension contract
//! (`azos_ext_api`), over the shipped provider table (`providers.rs`) and the
//! shipped latch sequence (`estop::latch_and_stop`).
//!
//! Each `check_*` takes any manifest whose providers record through [`note`]
//! and holds one clause of the contract:
//!
//! * installing a manifest twice registers each provider and each hook once;
//! * a manifest of another contract level is refused and registers nothing;
//! * each boot hook runs at its own phase only, in manifest order, and the
//!   task phase hands it the kernel's line enable;
//! * the task phase hands each effect loop the manifest registers to the
//!   kernel's spawn, once, in hook order with the task hooks;
//! * the table serves exactly the effect kinds its providers own;
//! * when the latch arms, every `on_latch` runs, then every `stop`, both
//!   after the latch store, each in provider order;
//! * the panic-path stop takes no lock the ordinary stop may take.
//!
//! The robot's own manifest links the whole robot stack and cannot be built on
//! the host; [`ROBOT_SHAPED`] has its shape (one provider with all four hooks,
//! owning the motor kind, an effects hook and a devices hook) and [`MIXED`] covers a bare
//! provider, a provider with no latch work and a hook at every phase.
//! The robot's manifest meets the same clauses through the table, and the
//! kernel's ktest holds that the table carries its providers.

use crate::{estop, providers};
use azos_ext_api::{BootHook, EffectLoop, Enforcer, Manifest, Provider, API_LEVEL};
use std::sync::{Mutex, TryLockError};

#[derive(Debug, PartialEq, Clone, Copy)]
enum Ev {
    OnLatch(&'static str, bool),
    Stop(&'static str, bool),
    PanicStop(&'static str),
    /// The stop found the lock a concurrent holder has.
    Blocked(&'static str),
    /// A boot hook ran.
    Hook(&'static str),
    /// A task hook enabled an interrupt line through the kernel's enable.
    Enable(u32),
    /// The kernel was asked to create an effect loop.
    Spawn(&'static str, u32),
}

static EVENTS: Mutex<Vec<Ev>> = Mutex::new(Vec::new());
/// The lock a provider's ordinary stop may take.
static STOP_LOCK: Mutex<()> = Mutex::new(());
static SERIAL: Mutex<()> = Mutex::new(());

fn note(e: Ev) {
    EVENTS.lock().unwrap_or_else(|e| e.into_inner()).push(e);
}

fn take() -> Vec<Ev> {
    std::mem::take(&mut *EVENTS.lock().unwrap_or_else(|e| e.into_inner()))
}

macro_rules! provider {
    ($name:literal, kinds: $kinds:expr, latch: $latch:expr, ready: $ready:expr) => {
        Provider {
            name: $name,
            kinds: $kinds,
            stop: {
                fn stop() {
                    match STOP_LOCK.try_lock() {
                        Ok(_) | Err(TryLockError::Poisoned(_)) => note(Ev::Stop($name, estop::estop_is_active())),
                        Err(TryLockError::WouldBlock) => note(Ev::Blocked($name)),
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

macro_rules! hook {
    (ConfigLoaded, $name:literal) => {
        BootHook::ConfigLoaded({
            fn run() {
                note(Ev::Hook($name));
            }
            run
        })
    };
    (Effects, $name:literal) => {
        BootHook::Effects({
            fn run() {
                note(Ev::Hook($name));
            }
            run
        })
    };
    (Devices, $name:literal) => {
        BootHook::Devices({
            fn run() {
                note(Ev::Hook($name));
            }
            run
        })
    };
    (Tasks, $name:literal, line: $line:literal) => {
        BootHook::Tasks({
            fn run(enable_line: azos_ext_api::EnableLine) {
                note(Ev::Hook($name));
                assert!(enable_line($line));
            }
            run
        })
    };
}

/// The kernel's line enable, as the task phase hands it over.
fn enable_line(line: u32) -> bool {
    note(Ev::Enable(line));
    true
}

/// The kernel's creation of an effect loop, as the task phase hands it over.
fn spawn(l: &'static EffectLoop) {
    note(Ev::Spawn(l.name, l.priority));
}

fn never_runs(_: usize) {
    unreachable!("the test spawns no task");
}

static DRIVE: EffectLoop = EffectLoop { name: "drive-loop", body: never_runs, priority: 8 };
static ROTOR: EffectLoop = EffectLoop { name: "rotor-loop", body: never_runs, priority: 9 };

fn enforce_tick(_now: u64) {
    note(Ev::Hook("enforcer tick"));
}

static LINK: Enforcer = Enforcer { name: "link-loss", period_ms: 100, tick: enforce_tick };
static FENCE: Enforcer = Enforcer { name: "fence", period_ms: 50, tick: enforce_tick };

const KIND_MOTOR: u8 = crate::kind::KIND_MOTOR;

fn yes() -> bool {
    true
}

fn no() -> bool {
    false
}

static ROBOT_SHAPED: Manifest = Manifest {
    name: "robot-shaped",
    api_level: API_LEVEL,
    providers: &[provider!("actuators", kinds: &[KIND_MOTOR], latch: true, ready: Some(yes))],
    hooks: &[
        hook!(Devices, "robot-shaped devices"),
        hook!(Effects, "robot-shaped effects"),
        BootHook::EffectLoop(&DRIVE),
        BootHook::EffectLoop(&ROTOR),
    ],
};

static MIXED: Manifest = Manifest {
    name: "mixed",
    api_level: API_LEVEL,
    providers: &[
        provider!("bare", kinds: &[], latch: false, ready: None),
        provider!("latching", kinds: &[KIND_MOTOR], latch: true, ready: None),
        provider!("gated", kinds: &[], latch: false, ready: Some(yes)),
    ],
    hooks: &[
        hook!(Tasks, "mixed tasks", line: 7),
        BootHook::EffectLoop(&ROTOR),
        BootHook::Enforcer(&LINK),
        hook!(ConfigLoaded, "mixed config"),
        BootHook::Enforcer(&FENCE),
        hook!(Effects, "mixed effects"),
        hook!(ConfigLoaded, "mixed config again"),
        hook!(Devices, "mixed devices"),
    ],
};

/// What the hooks of `m` at one phase note when run by hand, in manifest
/// order.
fn hooks_at(m: &Manifest, phase: fn(&BootHook) -> bool) -> Vec<Ev> {
    take();
    for h in m.hooks.iter().filter(|h| phase(h)) {
        match *h {
            BootHook::ConfigLoaded(f) | BootHook::Effects(f) | BootHook::Devices(f) => f(),
            BootHook::Tasks(f) => f(enable_line),
            BootHook::EffectLoop(l) => spawn(l),
            BootHook::Enforcer(_) => {}
        }
    }
    take()
}

/// The provider table and the latch as a fresh boot has them, under the lock
/// every test of the table holds.
pub(crate) fn fresh() -> std::sync::MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    providers::clear_for_tests();
    estop::estop_release(estop::ReleaseAuthority::for_test());
    take();
    g
}

/// Install `m`, which a fresh table must take.
pub(crate) fn install(m: &'static Manifest) {
    assert_eq!(providers::install(m), Ok(()), "`{}` was refused", m.name);
}

fn check_a_manifest_after_the_effects_phase_is_refused(m: &'static Manifest) {
    let _g = fresh();
    providers::effects();
    take();
    assert_eq!(providers::install(m), Err(providers::Refused::PhasePassed),
               "`{}`: installed after its effect wiring had run", m.name);
    assert_eq!((providers::count(), providers::manifests()), (0, 0), "`{}`: a refused manifest left something", m.name);
    for kind in 0..=u8::MAX {
        assert!(!providers::serves(kind), "`{}`: a refused manifest serves kind {}", m.name, kind);
    }
    providers::config_loaded();
    providers::devices();
    providers::start_tasks(enable_line, spawn);
    assert!(take().is_empty(), "`{}`: a hook of a refused manifest ran", m.name);
}

fn check_installs_each_provider_once(m: &'static Manifest) {
    let _g = fresh();
    install(m);
    install(m);
    assert_eq!(providers::count(), m.providers.len(), "`{}`: a repeated install took a second slot", m.name);
}

fn check_other_level_is_refused(m: &'static Manifest) {
    let _g = fresh();
    let other: &'static Manifest =
        Box::leak(Box::new(Manifest { name: m.name, api_level: m.api_level + 1, providers: m.providers, hooks: m.hooks }));
    assert_eq!(providers::install(other), Err(providers::Refused::OtherLevel(other.api_level)),
               "`{}`: a manifest of contract level {} was installed", m.name, other.api_level);
    assert_eq!(providers::count(), 0, "`{}`: a refused manifest left providers behind", m.name);
    assert_eq!(providers::manifests(), 0, "`{}`: a refused manifest left its hooks behind", m.name);
}

fn check_hooks_run_once_at_their_phase(m: &'static Manifest) {
    let _g = fresh();
    let want_config = hooks_at(m, |h| matches!(h, BootHook::ConfigLoaded(_)));
    let want_effects = hooks_at(m, |h| matches!(h, BootHook::Effects(_)));
    let want_devices = hooks_at(m, |h| matches!(h, BootHook::Devices(_)));
    let want_tasks = hooks_at(m, |h| matches!(h, BootHook::Tasks(_) | BootHook::EffectLoop(_)));
    install(m);
    install(m);
    assert_eq!(providers::manifests(), 1, "`{}`: a repeated install kept the manifest twice", m.name);
    assert!(take().is_empty(), "`{}`: a hook ran at install", m.name);
    providers::effects();
    assert_eq!(take(), want_effects, "`{}`: the effects phase ran other hooks, or these out of order", m.name);
    providers::config_loaded();
    assert_eq!(take(), want_config, "`{}`: the config phase ran other hooks, or these out of order", m.name);
    providers::devices();
    assert_eq!(take(), want_devices, "`{}`: the devices phase ran other hooks, or these out of order", m.name);
    providers::start_tasks(enable_line, spawn);
    assert_eq!(take(), want_tasks,
               "`{}`: the task phase ran other hooks, spawned other loops, or without the line enable", m.name);
}

fn check_serves_the_kinds_its_providers_own(m: &'static Manifest) {
    let _g = fresh();
    assert!(!providers::serves(KIND_MOTOR), "an empty table served the motor kind");
    install(m);
    for kind in 0..=u8::MAX {
        let owned = m.providers.iter().any(|p| p.kinds.contains(&kind));
        assert_eq!(providers::serves(kind), owned, "`{}`: kind {} served = {}", m.name, kind, !owned);
    }
}

fn check_latch_runs_the_providers_after_the_latch_store(m: &'static Manifest) {
    let _g = fresh();
    install(m);
    assert!(!estop::estop_is_active());
    estop::latch_and_stop();
    let mut want: Vec<Ev> = Vec::new();
    want.extend(m.providers.iter().filter(|p| p.on_latch.is_some()).map(|p| Ev::OnLatch(p.name, true)));
    want.extend(m.providers.iter().map(|p| Ev::Stop(p.name, true)));
    assert_eq!(take(), want, "`{}`: latch work and stops, in order, each after the latch store", m.name);
}

fn check_panic_stop_takes_no_stop_lock(m: &'static Manifest) {
    let _g = fresh();
    install(m);
    let _held = STOP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    check_hooks_run_once_at_their_phase,
    check_serves_the_kinds_its_providers_own,
    check_a_manifest_after_the_effects_phase_is_refused,
);

/// Each phase runs once and in boot order; a later one may skip an earlier
/// one (an image that loads no configuration). **Canary.** Make `enter`
/// accept any phase: the repeated and the out-of-order runs do not panic.
#[test]
fn each_boot_phase_runs_once_and_in_order() {
    let _g = fresh();
    providers::effects();
    providers::start_tasks(enable_line, spawn);
    for (name, run) in [
        ("effects twice", (|| providers::effects()) as fn()),
        ("devices after tasks", || providers::devices()),
        ("config after tasks", || providers::config_loaded()),
        ("tasks twice", || providers::start_tasks(enable_line, spawn)),
    ] {
        assert!(std::panic::catch_unwind(run).is_err(), "{name} ran");
    }
}

/// A full table refuses the whole manifest, leaving none of it.
#[test]
fn a_manifest_the_table_has_no_room_for_is_refused_whole() {
    static BIG: Manifest = Manifest {
        name: "big",
        api_level: API_LEVEL,
        providers: &[
            provider!("p1", kinds: &[], latch: false, ready: None),
            provider!("p2", kinds: &[], latch: false, ready: None),
            provider!("p3", kinds: &[], latch: false, ready: None),
        ],
        hooks: &[],
    };
    let _g = fresh();
    install(&MIXED);
    assert_eq!(providers::install(&BIG), Err(providers::Refused::Full));
    assert_eq!((providers::count(), providers::manifests()), (MIXED.providers.len(), 1));
}

/// The table's ordering and gate, over a manifest built by hand.
#[test]
fn providers_run_in_installation_order_and_a_provider_not_ready_closes_the_gate() {
    static NO: Manifest = Manifest {
        name: "not-ready",
        api_level: API_LEVEL,
        providers: &[provider!("closed", kinds: &[], latch: false, ready: Some(no))],
        hooks: &[],
    };
    let _g = fresh();
    install(&MIXED);
    assert!(providers::all_ready());
    install(&NO);
    assert!(!providers::all_ready(), "a provider whose gate is not in place left the gate open");
    providers::stop_all();
    assert_eq!(
        take(),
        [Ev::Stop("bare", false), Ev::Stop("latching", false), Ev::Stop("gated", false), Ev::Stop("closed", false)]
    );
}

/// **The enforcement task sees every enforcer, in hook order, and no phase
/// runs one.** An enforcer of a refused manifest is not there.
///
/// **Canary.** Skip the `Enforcer` arm in `each_enforcer`: none is listed.
#[test]
fn each_enforcer_is_listed_once_in_hook_order_and_no_phase_runs_it() {
    let _g = fresh();
    let mut seen = Vec::new();
    providers::each_enforcer(|e| seen.push(e.name));
    assert!(seen.is_empty());
    install(&MIXED);
    install(&MIXED);
    providers::effects();
    providers::config_loaded();
    providers::devices();
    providers::start_tasks(enable_line, spawn);
    assert!(!take().contains(&Ev::Hook("enforcer tick")), "a boot phase ran an enforcer");
    providers::each_enforcer(|e| seen.push(e.name));
    assert_eq!(seen, vec!["link-loss", "fence"]);
}
