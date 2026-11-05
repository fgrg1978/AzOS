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
//! refused.

use azos_common::hook::{Hook, SetError};
use azos_ext_api::{Manifest, Provider, API_LEVEL};

/// Room for every provider the extensions of one image install.
pub const MAX_PROVIDERS: usize = 4;

static PROVIDERS: [Hook<&'static Provider>; MAX_PROVIDERS] = [const { Hook::new("PROVIDERS") }; MAX_PROVIDERS];

/// Install `m`'s providers, in its order after those already installed.
/// Installing the same provider twice is a no-op, so a repeated install cannot
/// run a stop twice. Panics for a manifest built against another contract
/// level, a full table or an install after the seal: a boot that cannot
/// register its stop work must not go on.
pub fn install(m: &'static Manifest) {
    assert!(
        m.api_level == API_LEVEL,
        "extension `{}` is built against contract level {}, this kernel serves {}",
        m.name, m.api_level, API_LEVEL
    );
    for p in m.providers {
        register(p);
    }
}

fn register(p: &'static Provider) {
    for slot in &PROVIDERS {
        match slot.try_set(p) {
            Ok(()) => return,
            Err(SetError::AlreadySet) => continue,
            Err(SetError::Sealed) => panic!("effect provider `{}` installed after the boot seal", p.name),
        }
    }
    panic!("effect provider table full ({} providers): `{}`", MAX_PROVIDERS, p.name);
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

/// Forget every provider: host-test hygiene (the table is process-wide there).
#[cfg(not(target_os = "none"))]
pub fn clear_for_tests() {
    for slot in &PROVIDERS {
        slot.clear_for_tests();
    }
}
