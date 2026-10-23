// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Set-once function-pointer hooks that live in `.data.ro_after_init`.
//!
//! The kernel wires crates that cannot depend on each other through hook
//! statics: the scheduler installs `fn` pointers into `ipc`, `mm`, `sync` and
//! the drivers at boot, and they call back through them. Those used to be
//! `AtomicUsize` words in writable `.bss`/`.data` at link-time addresses, set
//! by a plain `store` and `transmute`d back to a `fn` at every call: a single
//! kernel write anywhere turned one of them into a code-execution primitive
//! with no information leak needed (security audit 2026-10-17, finding D).
//!
//! [`Hook`] closes that in two steps.
//!
//!  * **Set once.** [`Hook::try_set`] is a compare-exchange from 0: the first
//!    installer wins, the same value again is a no-op, a different one is
//!    refused. The `transmute` is gone from every caller; the one conversion
//!    lives in [`Hook::get`].
//!  * **Read-only after boot.** [`ro_hook!`] places the static in the linker
//!    section `.data.ro_after_init` (page-aligned at both ends in every kernel
//!    linker script). Once every boot-time installer has run, the kernel calls
//!    [`seal`] and remaps that section read-only (`azos_mm::vmm::
//!    seal_ro_after_init`). From then on a store faults, and a [`Hook::set`]
//!    panics with the hook's name before it gets that far.
//!
//! A hook that is installed after boot (a driver probed at run time, a test
//! canary, a job queued for a worker) is NOT a `Hook`: it belongs in a plain
//! [`AtomicFn`], writable for the kernel's whole life, and nothing here
//! pretends otherwise. `Hook` is an `AtomicFn` with the set-once rule and the
//! section on top; the one conversion between a function and a word is the
//! `AtomicFn`'s.
//!
//! **Hosted builds** (anything that is neither `target_os = "none"` nor `"azos"`: the
//! host test suites) have no section to protect and reinstall hooks per test, so there
//! [`Hook::set`] replaces the value. [`Hook::try_set`] is strict everywhere.

use core::marker::PhantomData;
use core::mem::{size_of, transmute_copy};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Why [`Hook::try_set`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetError {
    /// A different function is already installed.
    AlreadySet,
    /// [`seal`] has run: the section is (or is about to be) read-only.
    Sealed,
}

/// Set once the boot has installed every hook ([`seal`]). Lives in the section
/// it guards, so after the remap it cannot be cleared either.
#[cfg_attr(target_os = "none", link_section = ".data.ro_after_init")]
static SEALED: AtomicBool = AtomicBool::new(false);

/// Refuse every later [`Hook::set`]. Called by the boot immediately BEFORE it
/// remaps `.data.ro_after_init` read-only (the flag is stored while the page
/// is still writable).
pub fn seal() {
    SEALED.store(true, Ordering::Release);
}

/// Has the boot sealed the hooks?
#[inline]
pub fn is_sealed() -> bool {
    SEALED.load(Ordering::Acquire)
}

/// What [`AtomicFn::install`] found in the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Install {
    /// The slot was empty and now holds the function.
    Stored,
    /// The slot already held this same function; nothing changed.
    Same,
    /// The slot holds a different function; nothing changed.
    Taken,
}

/// An atomic slot holding a plain `fn(..) -> ..` pointer, or nothing.
///
/// `F` must be a function pointer (checked by size; a function's address is
/// never 0, so 0 is the empty slot). The word only ever holds 0 or the bits of
/// an `F` stored by one of the methods below, which is what makes reading it
/// back as an `F` sound.
#[repr(transparent)]
pub struct AtomicFn<F: Copy> {
    raw: AtomicUsize,
    _f: PhantomData<F>,
}

impl<F: Copy> AtomicFn<F> {
    /// An empty slot.
    pub const fn new() -> Self {
        Self { raw: AtomicUsize::new(0), _f: PhantomData }
    }

    #[inline(always)]
    fn word(f: F) -> usize {
        const { assert!(size_of::<F>() == size_of::<usize>(), "an AtomicFn holds a fn pointer") };
        // SAFETY: `F` is pointer-sized (asserted above) and `Copy`; reading its
        // bytes as a `usize` is `f as usize`.
        unsafe { transmute_copy::<F, usize>(&f) }
    }

    #[inline(always)]
    fn func(raw: usize) -> Option<F> {
        const { assert!(size_of::<F>() == size_of::<usize>(), "an AtomicFn holds a fn pointer") };
        if raw == 0 {
            None
        } else {
            // SAFETY: `raw` was read from `self.raw`, which holds 0 or a word
            // made by `word` from a valid `F` (the type's invariant).
            Some(unsafe { transmute_copy::<usize, F>(&raw) })
        }
    }

    /// Store `f` if the slot is empty (a compare-exchange from 0).
    pub fn install(&self, f: F) -> Install {
        let w = Self::word(f);
        match self.raw.compare_exchange(0, w, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Install::Stored,
            Err(cur) if cur == w => Install::Same,
            Err(_) => Install::Taken,
        }
    }

    /// Replace the slot's content with `f` (`None` empties it).
    #[inline]
    pub fn set(&self, f: Option<F>) {
        self.raw.store(f.map_or(0, Self::word), Ordering::Release);
    }

    /// Empty the slot and return what it held.
    #[inline]
    pub fn take(&self) -> Option<F> {
        Self::func(self.raw.swap(0, Ordering::AcqRel))
    }

    /// The stored function, if any.
    #[inline]
    pub fn get(&self) -> Option<F> {
        Self::func(self.raw.load(Ordering::Acquire))
    }

    /// [`AtomicFn::get`] with a relaxed load. Sound because the pointee is
    /// code, which needs no publication; use `get` when the function reads
    /// state the installer wrote.
    #[inline]
    pub fn get_relaxed(&self) -> Option<F> {
        Self::func(self.raw.load(Ordering::Relaxed))
    }

    /// Is a function stored?
    #[inline]
    pub fn is_set(&self) -> bool {
        self.raw.load(Ordering::Acquire) != 0
    }
}

impl<F: Copy> Default for AtomicFn<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// A function pointer installed once at boot and read-only afterwards.
///
/// `F` must be a plain `fn(..) -> ..` pointer (see [`AtomicFn`]).
#[repr(C)]
pub struct Hook<F: Copy> {
    slot: AtomicFn<F>,
    name: &'static str,
}

impl<F: Copy> Hook<F> {
    /// An empty hook. `name` is what the panic record says. Use [`ro_hook!`],
    /// which also puts the static in the right section.
    pub const fn new(name: &'static str) -> Self {
        Self { slot: AtomicFn::new(), name }
    }

    /// Install `f` once. Ok for the first installer and for the same `f`
    /// again; [`SetError::AlreadySet`] for a different one,
    /// [`SetError::Sealed`] after [`seal`].
    pub fn try_set(&self, f: F) -> Result<(), SetError> {
        if is_sealed() {
            return Err(SetError::Sealed);
        }
        match self.slot.install(f) {
            Install::Stored | Install::Same => Ok(()),
            Install::Taken => Err(SetError::AlreadySet),
        }
    }

    /// Install `f`; the boot's call. Panics (the panic record names the hook)
    /// when it is refused: a second, different installer or an installer that
    /// runs after the seal is a boot-order bug, not something to carry on
    /// through with a half-wired kernel.
    ///
    /// Hosted builds replace the value instead (see the module docs).
    pub fn set(&self, f: F) {
        #[cfg(not(any(target_os = "none", target_os = "azos")))]
        if !is_sealed() {
            self.slot.set(Some(f));
            return;
        }
        match self.try_set(f) {
            Ok(()) => {}
            Err(SetError::AlreadySet) => {
                panic!("ro_after_init hook `{}` installed twice with different functions", self.name)
            }
            Err(SetError::Sealed) => {
                panic!("ro_after_init hook `{}` set after the boot seal", self.name)
            }
        }
    }

    /// The installed function, if any.
    #[inline]
    pub fn get(&self) -> Option<F> {
        self.slot.get()
    }

    /// [`Hook::get`] with a relaxed load, for the hottest readers (a per-CPU
    /// id lookup); see [`AtomicFn::get_relaxed`].
    #[inline]
    pub fn get_relaxed(&self) -> Option<F> {
        self.slot.get_relaxed()
    }

    /// Forget the installed function: host-test hygiene (hooks are
    /// process-wide there). Hosted builds only; a bare-metal hook is set once.
    #[cfg(not(any(target_os = "none", target_os = "azos")))]
    pub fn clear_for_tests(&self) {
        self.slot.set(None);
    }

    /// Is a function installed?
    #[inline]
    pub fn is_set(&self) -> bool {
        self.slot.is_set()
    }

    /// The name given at [`Hook::new`].
    pub fn name(&self) -> &'static str {
        self.name
    }
}

/// Declare a [`Hook`] static in `.data.ro_after_init`.
///
/// ```ignore
/// azos_common::ro_hook! {
///     /// Called when a task exits.
///     static EXIT_HOOK: fn(u32);
/// }
/// ```
#[macro_export]
macro_rules! ro_hook {
    ($(#[$m:meta])* $vis:vis static $name:ident: $ty:ty;) => {
        $(#[$m])*
        #[cfg_attr(target_os = "none", link_section = ".data.ro_after_init")]
        $vis static $name: $crate::hook::Hook<$ty> = $crate::hook::Hook::new(stringify!($name));
    };
}
