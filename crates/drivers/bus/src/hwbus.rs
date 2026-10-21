// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's hardware bus: the one [`Bus`] every enumerator fills, every
//! driver binds through and every `Device` capability names.
//!
//! The logic (device objects, the match tables, the bind policy, unbind,
//! rebind) is `azos_hwbus`, pure and host-tested. This module is the static
//! instance and the two lookups the capability layer needs, so that
//! `azos_ipc` (the `Device` capability minter) and `azos_syscall`
//! (`DOMAIN_MMIO_MAP`) reach the bus without the boot code:
//!
//! - [`resolve`]: a selector (`"dt:google,goldfish-rtc"`, `"pci:1af4:1041"`,
//!   `"virtio:2#1"`: the Nth match) to the handle of the device it names;
//! - [`user_window`]: the register window ring 3 may map for a handle, and
//!   [`claim_user_window`] / [`unclaim_user_window`], which book a mapping so
//!   no kernel driver is bound to the device afterwards.
//!
//! The enumerators and the driver registry live in `kernel/src/boot/hwbus.rs`,
//! which sees every driver crate; nothing here reaches hardware.

pub use azos_hwbus::*;

use azos_sync::SpinLock;

static BUS: SpinLock<Bus> = SpinLock::new(Bus::new());

/// Run `f` on the bus, under its lock. Do not call a function that takes the
/// bus lock again from inside, and keep `f` short: the lock is a spinlock
/// with a hold bound. What calls drivers or prints (bind, unbind, reconcile)
/// goes through [`Locked`], which takes the lock only for the state change of
/// one device.
pub fn with<R>(f: impl FnOnce(&mut Bus) -> R) -> R {
    f(&mut BUS.lock())
}

/// The kernel's bus as an [`Access`]: every step takes the bus lock for
/// itself and a driver's probe, a removal and a `[HWBUS]` line run with it
/// released (`azos_hwbus::Access` has the contract).
pub struct Locked;

impl Access for Locked {
    fn with<R>(&mut self, f: impl FnOnce(&mut Bus) -> R) -> R {
        with(f)
    }
}

/// The handle of the device a selector names: `"<selector>"` is the first
/// device it matches, `"<selector>#N"` the Nth in slot order. `None` for a
/// selector the bus cannot read, a device that is not there, or `N` past the
/// matches.
pub fn resolve(selector: &str) -> Option<u32> {
    let (text, nth) = match selector.rsplit_once('#') {
        Some((t, n)) => (t, n.parse::<usize>().ok()?),
        None => (selector, 0),
    };
    let pattern = Pattern::parse(text)?;
    with(|b| b.find(&pattern, nth)).map(|h| h.0)
}

/// The register window `(base, size)` ring 3 may map for the device `handle`
/// names; `None` for a stale or unknown handle, a device with no window, and
/// a device a kernel driver owns or may still take ([`Bus::user_window`]).
pub fn user_window(handle: u32) -> Option<(u64, u64)> {
    with(|b| b.user_window(Handle(handle)))
}

/// [`user_window`] and book the mapping about to be made ([`Bus::claim_user_window`]).
pub fn claim_user_window(handle: u32) -> Option<(u64, u64)> {
    with(|b| b.claim_user_window(Handle(handle)))
}

/// Give back a booking whose mapping failed ([`Bus::unclaim_user_window`]).
pub fn unclaim_user_window(handle: u32) {
    with(|b| b.unclaim_user_window(Handle(handle)))
}
