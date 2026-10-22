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
//! canary) is NOT a `Hook`: it belongs in a plain atomic, and nothing here
//! pretends otherwise.
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

/// A function pointer installed once at boot and read-only afterwards.
///
/// `F` must be a plain `fn(..) -> ..` pointer (checked by size; a pointer is
/// never 0, so 0 means "not installed").
#[repr(C)]
pub struct Hook<F: Copy> {
    raw: AtomicUsize,
    name: &'static str,
    _f: PhantomData<F>,
}

impl<F: Copy> Hook<F> {
    /// An empty hook. `name` is what the panic record says. Use [`ro_hook!`],
    /// which also puts the static in the right section.
    pub const fn new(name: &'static str) -> Self {
        Self { raw: AtomicUsize::new(0), name, _f: PhantomData }
    }

    #[inline(always)]
    fn addr(f: F) -> usize {
        const { assert!(size_of::<F>() == size_of::<usize>(), "a Hook holds a fn pointer") };
        // SAFETY: `F` is pointer-sized (asserted above) and `Copy`; reading its
        // bytes as a `usize` is the `f as usize` the old statics did.
        unsafe { transmute_copy::<F, usize>(&f) }
    }

    /// Install `f` once. Ok for the first installer and for the same `f`
    /// again; [`SetError::AlreadySet`] for a different one,
    /// [`SetError::Sealed`] after [`seal`].
    pub fn try_set(&self, f: F) -> Result<(), SetError> {
        if is_sealed() {
            return Err(SetError::Sealed);
        }
        let a = Self::addr(f);
        match self.raw.compare_exchange(0, a, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(()),
            Err(cur) if cur == a => Ok(()),
            Err(_) => Err(SetError::AlreadySet),
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
            self.raw.store(Self::addr(f), Ordering::Release);
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
        const { assert!(size_of::<F>() == size_of::<usize>(), "a Hook holds a fn pointer") };
        let raw = self.raw.load(Ordering::Acquire);
        if raw == 0 {
            None
        } else {
            // SAFETY: only `try_set`/`set` store here, and they store the
            // address of a valid `F` (pointer-sized, asserted above).
            Some(unsafe { transmute_copy::<usize, F>(&raw) })
        }
    }

    /// [`Hook::get`] with a relaxed load, for the hottest readers (a per-CPU
    /// id lookup). Sound because the pointee is code, which needs no
    /// publication; use `get` when the hook's function reads state the
    /// installer wrote.
    #[inline]
    pub fn get_relaxed(&self) -> Option<F> {
        const { assert!(size_of::<F>() == size_of::<usize>(), "a Hook holds a fn pointer") };
        let raw = self.raw.load(Ordering::Relaxed);
        if raw == 0 {
            None
        } else {
            // SAFETY: as in `get`.
            Some(unsafe { transmute_copy::<usize, F>(&raw) })
        }
    }

    /// Forget the installed function: host-test hygiene (hooks are
    /// process-wide there). Hosted builds only; a bare-metal hook is set once.
    #[cfg(not(any(target_os = "none", target_os = "azos")))]
    pub fn clear_for_tests(&self) {
        self.raw.store(0, Ordering::Release);
    }

    /// Is a function installed?
    #[inline]
    pub fn is_set(&self) -> bool {
        self.raw.load(Ordering::Acquire) != 0
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
