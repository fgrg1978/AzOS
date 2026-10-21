// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-process pointer-authentication keys (aarch64, Kconfig
//! `A64_PAUTH_PROC_KEYS`): who gets which keys, and when they reach the
//! hardware. The mechanism (the key table, the register writes, the swap at
//! the EL0 boundary) is `azos_arch::cpu::cfi` and `trap_entry.S`; this module
//! is its only caller.
//!
//! | event                          | call                                    |
//! |--------------------------------|-----------------------------------------|
//! | `spawn`                        | [`draw`] (`spawn_prepare`)              |
//! | `exec`                         | [`draw`] (`set_current_user_info`)      |
//! | `fork`, thread creation        | [`inherit_from_current`]                |
//! | a task slot is created         | [`clear`]                               |
//! | a task is switched in          | [`switch_in`] (`asid::prepare_switch`)  |
//! | first entry / exec hand-off    | [`install_current`]                     |
//!
//! A fork child must have its parent's keys: the stack it copied holds return
//! addresses the parent signed, and every `autiasp` of the child's returns
//! would fail under fresh keys. A thread shares its process's address space
//! and so its keys. Only `spawn` and `exec` start an image from nothing.
//!
//! The first entry of a spawned child, a fork child or a thread, and the
//! return of an `exec`, do not pass through a switch-in after their keys are
//! final (the child runs `fork_child_entry` parked from its creation), so the
//! hand-off consumers call [`install_current`] on the hart that will `eret`.
//! A preemption between that call and the `eret` is harmless: the task is
//! switched in again, and [`switch_in`] installs the same keys on the hart it
//! lands on.
//!
//! On the other ISAs there are no such keys and every call is empty.

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
mod imp {
    use crate::task::MAX_TASKS;
    use azos_arch::cpu::cfi::{self, KeyTable, KEY_BYTES};
    use azos_arch::Interrupts;

    /// Every task slot's keys.
    static TABLE: KeyTable<MAX_TASKS> = KeyTable::new();

    #[inline(always)]
    fn active() -> bool {
        azos_limits::A64_PAUTH_PROC_KEYS && cfi::proc_keys_active()
    }

    /// Slot `slot` starts an image: fresh keys, from the DRBG. While the pool
    /// is still unseeded they come from `cfi::derive_user_keys` instead.
    pub fn draw(slot: usize) {
        if !active() {
            return;
        }
        let mut buf = [0u8; KEY_BYTES];
        // The pool's lock is a spin lock that does not mask interrupts: an
        // interrupt that drew from the pool while this call held it would spin
        // on this hart for good.
        let saved = azos_arch::ARCH.disable_all();
        let seeded = azos_crypto::entropy::fill(&mut buf);
        azos_arch::ARCH.restore(saved);
        let keys = cfi::fresh_user_keys(seeded.then_some(&buf), cfi::kernel_key(), cfi::counter(), slot as u64);
        TABLE.draw(slot, &keys);
        // The random bytes are the keys: do not leave them on the stack.
        for b in buf.iter_mut() {
            // SAFETY: `b` is a valid, aligned, exclusive reference.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
    }

    /// Slot `child` runs the address space of the current task (a fork's copy
    /// or a thread of it): its keys.
    pub fn inherit_from_current(child: usize) {
        if !active() {
            return;
        }
        match crate::scheduler::current_slot() {
            Some(parent) => {
                TABLE.inherit(child, parent);
            }
            None => TABLE.clear(child),
        }
    }

    /// Slot `slot` is a new task: it has no keys until an image gives it some.
    pub fn clear(slot: usize) {
        TABLE.clear(slot);
    }

    /// The current task (the one `set_current_task` just named) is about to
    /// run on this hart. Interrupts are masked.
    pub fn switch_in() {
        if !active() {
            return;
        }
        if let Some(keys) = crate::scheduler::current_slot().and_then(|s| TABLE.get(s)) {
            cfi::load_user_keys(&keys);
        }
    }

    /// The current task is about to return to EL0 for the first time with
    /// keys it did not have when it was last switched in (a new image, a new
    /// child).
    pub fn install_current() {
        if !active() {
            return;
        }
        let saved = azos_arch::ARCH.disable_all();
        switch_in();
        azos_arch::ARCH.restore(saved);
    }
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
mod imp {
    #[inline(always)]
    pub fn draw(_slot: usize) {}
    #[inline(always)]
    pub fn inherit_from_current(_child: usize) {}
    #[inline(always)]
    pub fn clear(_slot: usize) {}
    #[inline(always)]
    pub fn switch_in() {}
    #[inline(always)]
    pub fn install_current() {}
}

pub use imp::*;
