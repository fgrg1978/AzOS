// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Fixed-size tables of `fn()` hooks a domain registers at boot.
//!
//! This crate holds the actuation authority every domain shares; the work a
//! particular domain must add to it (stop the robot's wheels, replace the
//! brain's cached action) is registered here instead of being called by name,
//! so this crate never depends on a domain crate.
//!
//! Lock-free on the read side: [`HookTable::run`] is called from the panic
//! path and the timer interrupt (`watchdog::halt_if_panicked`), where no lock
//! may be taken. Registration happens once per hook, at boot, before the
//! scheduler starts.

use azos_common::hook::{AtomicFn, Install};

/// Room for every hook a domain registers per table. The robot domain
/// registers one per table today.
pub const MAX_HOOKS: usize = 4;

/// A table of up to [`MAX_HOOKS`] hooks, run in registration order.
pub struct HookTable {
    slots: [AtomicFn<fn()>; MAX_HOOKS],
}

impl HookTable {
    pub const fn new() -> Self {
        HookTable { slots: [const { AtomicFn::new() }; MAX_HOOKS] }
    }

    /// Append `hook`. Registering the same function twice is a no-op, so a
    /// repeated install cannot run a stop twice. Panics when the table is
    /// full: a boot that cannot register its stop work must not go on.
    pub fn register(&self, hook: fn()) {
        for slot in &self.slots {
            match slot.install(hook) {
                Install::Stored | Install::Same => return,
                Install::Taken => continue,
            }
        }
        panic!("actuation: hook table full ({} hooks)", MAX_HOOKS);
    }

    /// How many hooks are registered.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_set()).count()
    }

    /// Run every registered hook, in registration order.
    #[inline]
    pub fn run(&self) {
        for slot in &self.slots {
            let Some(f) = slot.get() else { return };
            f();
        }
    }
}

/// Run every hook in `table`. A free function so call sites read as a verb.
#[inline]
pub fn run(table: &HookTable) {
    table.run();
}
