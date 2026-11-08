// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The effect providers the extensions install (`azos_ext_api`).
//!
//! This crate holds the actuation authority every profile shares; the stop
//! work of a particular extension's devices (the robot's wheels, ESC and
//! payload) is a [`Provider`] installed here at boot, so this crate never
//! names an extension. An image with none latches and stops nothing else.
//!
//! Lock-free on the read side: the panic path and the timer interrupt
//! (`watchdog::halt_if_panicked`) walk the table, where no lock may be taken.
//! Installation happens once per extension, at boot, before the scheduler
//! starts; an install after the boot seal (`azos_common::hook::seal`) is
//! refused, and so is one after the first boot phase. The manifests are kept too, for their boot hooks
//! ([`config_loaded`], [`devices`], [`start_tasks`], and the effects phase the gate's
//! install runs).

use core::sync::atomic::{AtomicU8, Ordering};

use azos_common::hook::{Hook, SetError};
use azos_ext_api::{BootHook, EnableLine, Manifest, Provider, SpawnLoop, API_LEVEL};

/// Room for every provider the extensions of one image install.
pub const MAX_PROVIDERS: usize = 4;
/// Room for every manifest one image installs.
pub const MAX_MANIFESTS: usize = 4;

static PROVIDERS: [Hook<&'static Provider>; MAX_PROVIDERS] = [const { Hook::new("PROVIDERS") }; MAX_PROVIDERS];
static MANIFESTS: [Hook<&'static Manifest>; MAX_MANIFESTS] = [const { Hook::new("MANIFESTS") }; MAX_MANIFESTS];

/// Why [`install`] refused a manifest. Nothing of it is installed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused {
    /// Built against another contract level (the one it names).
    OtherLevel(u16),
    /// A boot phase has already run: a hook the manifest declares for it, or
    /// the effect wiring its kinds need, would never run, so the kind would
    /// read as served with nothing behind it.
    PhasePassed,
    /// The manifest or provider table has no room.
    Full,
    /// After the boot seal (`azos_common::hook::seal`).
    Sealed,
}

/// Install `m`'s providers and hooks, in its order after those already
/// installed. Installing the same manifest twice is a no-op, so a repeated
/// install cannot run a stop or a hook twice. Refused, with nothing installed,
/// for a manifest built against another contract level, once the first boot
/// phase ([`BootHook::Effects`], run by `gate::install`) has run, for want of
/// room, and after the seal. The boot's callers stop on a refusal: a boot that
/// cannot register its stop work must not go on.
pub fn install(m: &'static Manifest) -> Result<(), Refused> {
    if m.api_level != API_LEVEL {
        return Err(Refused::OtherLevel(m.api_level));
    }
    if PHASE.load(Ordering::Acquire) != INSTALLING {
        return Err(Refused::PhasePassed);
    }
    let known = MANIFESTS.iter().any(|s| s.get().is_some_and(|k| core::ptr::eq(k, m)));
    let new = m.providers.iter().filter(|&p| !PROVIDERS.iter().any(|s| s.get().is_some_and(|q| core::ptr::eq(q, p)))).count();
    let free = PROVIDERS.iter().filter(|s| !s.is_set()).count();
    if (!known && manifests() == MAX_MANIFESTS) || new > free {
        return Err(Refused::Full);
    }
    keep(m)?;
    for p in m.providers {
        register(p)?;
    }
    Ok(())
}

fn keep(m: &'static Manifest) -> Result<(), Refused> {
    for slot in &MANIFESTS {
        match slot.try_set(m) {
            Ok(()) => return Ok(()),
            Err(SetError::AlreadySet) => continue,
            Err(SetError::Sealed) => return Err(Refused::Sealed),
        }
    }
    Err(Refused::Full)
}

fn register(p: &'static Provider) -> Result<(), Refused> {
    for slot in &PROVIDERS {
        match slot.try_set(p) {
            Ok(()) => return Ok(()),
            Err(SetError::AlreadySet) => continue,
            Err(SetError::Sealed) => return Err(Refused::Sealed),
        }
    }
    Err(Refused::Full)
}

// The boot phases, in the order the boot runs them; each runs once, and a
// later one may follow an earlier one with the ones between skipped.
const INSTALLING: u8 = 0;
const EFFECTS: u8 = 1;
const CONFIG_LOADED: u8 = 2;
const DEVICES: u8 = 3;
const TASKS: u8 = 4;
static PHASE: AtomicU8 = AtomicU8::new(INSTALLING);

/// Enter `phase`. Panics when it, or a later one, has already run: a boot-
/// order bug, after which the hooks would run twice or out of order.
fn enter(phase: u8, name: &str) {
    if PHASE.fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| (cur < phase).then_some(phase)).is_err() {
        panic!("boot phase `{}` of the extension contract ran twice or out of order", name);
    }
}

/// Every installed provider, in installation order.
fn each(mut f: impl FnMut(&'static Provider)) {
    for slot in &PROVIDERS {
        let Some(p) = slot.get() else { return };
        f(p);
    }
}

/// How many providers are installed.
pub fn count() -> usize {
    PROVIDERS.iter().filter(|s| s.is_set()).count()
}

/// How many manifests are installed.
pub fn manifests() -> usize {
    MANIFESTS.iter().filter(|s| s.is_set()).count()
}

/// Does an installed provider own effect kind `kind`?
pub fn serves(kind: u8) -> bool {
    let mut served = false;
    each(|p| served |= p.kinds.contains(&kind));
    served
}

/// Every installed manifest's hooks, in installation order.
fn each_hook(mut f: impl FnMut(&BootHook)) {
    for slot in &MANIFESTS {
        let Some(m) = slot.get() else { return };
        m.hooks.iter().for_each(&mut f);
    }
}

/// The [`BootHook::ConfigLoaded`] phase.
pub fn config_loaded() {
    enter(CONFIG_LOADED, "config loaded");
    each_hook(|h| {
        if let BootHook::ConfigLoaded(f) = h {
            f();
        }
    });
}

/// The [`BootHook::Effects`] phase (`gate::install`). From here on no
/// manifest is installed.
pub(crate) fn effects() {
    enter(EFFECTS, "effects");
    each_hook(|h| {
        if let BootHook::Effects(f) = h {
            f();
        }
    });
}

/// The [`BootHook::Devices`] phase.
pub fn devices() {
    if !cfg!(feature = "devices-phase-canary") {
        enter(DEVICES, "devices");
    }
    each_hook(|h| {
        if let BootHook::Devices(f) = h {
            f();
        }
    });
}

/// The [`BootHook::Tasks`] phase: each extension's own tasks, and each
/// [`BootHook::EffectLoop`] it registers created by `spawn`, in hook order.
pub fn start_tasks(enable_line: EnableLine, spawn: SpawnLoop) {
    enter(TASKS, "tasks");
    each_hook(|h| match h {
        BootHook::Tasks(f) => f(enable_line),
        BootHook::EffectLoop(l) => spawn(l),
        _ => {}
    });
}

/// Every provider's stop.
pub(crate) fn stop_all() {
    each(|p| (p.stop)());
}

/// Every provider's lock-free stop.
#[inline]
pub(crate) fn panic_stop_all() {
    each(|p| (p.panic_stop)());
}

/// Every provider's latch work.
pub(crate) fn on_latch_all() {
    each(|p| {
        if let Some(f) = p.on_latch {
            f();
        }
    });
}

/// Does every provider say its gate is in place?
pub(crate) fn all_ready() -> bool {
    let mut ready = true;
    each(|p| ready &= p.ready.is_none_or(|r| r()));
    ready
}

/// Forget every provider and manifest: host-test hygiene (the tables are
/// process-wide there).
#[cfg(not(target_os = "none"))]
pub fn clear_for_tests() {
    for slot in &PROVIDERS {
        slot.clear_for_tests();
    }
    for slot in &MANIFESTS {
        slot.clear_for_tests();
    }
    PHASE.store(INSTALLING, Ordering::Release);
}
