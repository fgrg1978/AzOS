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

use core::sync::atomic::{AtomicPtr, Ordering};

/// Room for every hook a domain registers per table. The robot domain
/// registers one per table today.
pub const MAX_HOOKS: usize = 4;

/// A table of up to [`MAX_HOOKS`] hooks, run in registration order.
pub struct HookTable {
    slots: [AtomicPtr<()>; MAX_HOOKS],
}

impl HookTable {
    pub const fn new() -> Self {
        HookTable { slots: [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_HOOKS] }
    }

    /// Append `hook`. Registering the same function twice is a no-op, so a
    /// repeated install cannot run a stop twice. Panics when the table is
    /// full: a boot that cannot register its stop work must not go on.
    pub fn register(&self, hook: fn()) {
        let p = hook as *mut ();
        for slot in &self.slots {
            match slot.compare_exchange(core::ptr::null_mut(), p, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return,
                Err(cur) if cur == p => return,
                Err(_) => continue,
            }
        }
        panic!("actuation: hook table full ({} hooks)", MAX_HOOKS);
    }

    /// How many hooks are registered.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| !s.load(Ordering::Acquire).is_null()).count()
    }

    /// Run every registered hook, in registration order.
    #[inline]
    pub fn run(&self) {
        for slot in &self.slots {
            let p = slot.load(Ordering::Acquire);
            if p.is_null() {
                return;
            }
            // SAFETY: every non-null slot was stored by `register` from a
            // `fn()`, and function pointers round-trip through `*mut ()` on
            // every target this kernel builds for.
            let f: fn() = unsafe { core::mem::transmute::<*mut (), fn()>(p) };
            f();
        }
    }
}

/// Run every hook in `table`. A free function so call sites read as a verb.
#[inline]
pub fn run(table: &HookTable) {
    table.run();
}
