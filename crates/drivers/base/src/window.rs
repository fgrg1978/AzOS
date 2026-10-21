// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The register window a bound driver reads its base from.
//!
//! A driver for a controller the device tree describes does not know where the
//! controller is until the hardware bus hands it the node. The bus binds it
//! (`kernel/src/boot/hwbus.rs`), the kernel maps the node's `reg` and calls
//! the driver's `attach` with the base; the driver keeps it here and every
//! register access reads it back. Before the bind, and on a board whose tree
//! has no such node, the window is unbound: the driver is absent, and each
//! entry point says so ([`Window::base`] is `None`) instead of touching an
//! address.
//!
//! The load is one relaxed atomic read: the lock-free paths (the panic
//! handler's pin drive, the timer interrupt's watchdog kick) use it too.

use core::sync::atomic::{AtomicUsize, Ordering};

/// The window (or the slot) already holds a base, or the base offered is not
/// one: an attach is refused, nothing changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Taken;

/// One register window; 0 is "unbound" (no controller sits at address 0).
pub struct Window(AtomicUsize);

impl Window {
    /// An unbound window.
    pub const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    /// Bind the window to `base`. Refused when it is already bound or `base`
    /// is 0.
    pub fn attach(&self, base: usize) -> Result<(), Taken> {
        if base == 0 {
            return Err(Taken);
        }
        self.0.compare_exchange(0, base, Ordering::AcqRel, Ordering::Relaxed).map(|_| ()).map_err(|_| Taken)
    }

    /// The base, `None` while unbound.
    #[inline(always)]
    pub fn base(&self) -> Option<usize> {
        match self.0.load(Ordering::Acquire) {
            0 => None,
            b => Some(b),
        }
    }
}

impl Default for Window {
    fn default() -> Self {
        Self::new()
    }
}

/// `N` windows of one kind (the I2C controllers), numbered in the order they
/// are attached: the first controller the tree describes is bus 0.
pub struct Windows<const N: usize>([Window; N]);

impl<const N: usize> Windows<N> {
    /// All slots unbound.
    pub const fn new() -> Self {
        Self([const { Window::new() }; N])
    }

    /// Bind the first free slot to `base`; the slot's index. Refused when
    /// every slot is taken or `base` is already one of them.
    pub fn attach_next(&self, base: usize) -> Result<usize, Taken> {
        if base == 0 || self.0.iter().any(|w| w.base() == Some(base)) {
            return Err(Taken);
        }
        for (i, w) in self.0.iter().enumerate() {
            if w.attach(base).is_ok() {
                return Ok(i);
            }
        }
        Err(Taken)
    }

    /// The base of slot `i`, `None` while it is unbound or out of range.
    #[inline(always)]
    pub fn base(&self, i: usize) -> Option<usize> {
        self.0.get(i).and_then(Window::base)
    }
}

impl<const N: usize> Default for Windows<N> {
    fn default() -> Self {
        Self::new()
    }
}
