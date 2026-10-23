// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Typed pointers into the current task's memory: [`UserPtr`], [`UserSlice`]
//! and [`UserCStr`] (front uaccess-pin).
//!
//! A syscall handler names user memory through these instead of a raw
//! `usize` and a byte count: the element type fixes the length, a fault is
//! a [`Efault`] the handler must handle, and nothing but a [`Pod`] type
//! (every bit pattern valid, no padding) can be read from or written to user
//! memory, so a read cannot build an invalid value and a write cannot leak
//! padding bytes of the kernel stack. The accesses are
//! `copy_from_user`, `copy_to_user` and `copy_cstr_from_user`, the
//! implementation (each page in one access section, `azos_mm::uaccess`).
//!
//! A child file the host suites pull by path next to their own `copy_*_user`.

use core::marker::PhantomData;
use core::mem::{size_of, MaybeUninit};

/// The user address was not accessible as asked: not mapped, not user
/// memory, not writable for a write, or the range wraps. A handler answers
/// `EFAULT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Efault;

/// A type any byte pattern is a valid value of, with no padding byte: what may
/// be read from or written to user memory as a whole. A read then cannot
/// build an invalid value (a `bool`, an enum, a reference), and a write
/// cannot hand ring 3 the stale bytes of the kernel stack a padding byte holds.
/// A struct of a crate that forbids `unsafe` crosses the boundary as a byte
/// array it encodes and decodes itself (`azos_driver_server`'s requests).
///
/// # Safety
///
/// Every bit pattern of `size_of::<Self>()` bytes is a valid `Self`, and
/// `Self` has no padding byte.
pub unsafe trait Pod: Copy + 'static {}

macro_rules! pod {
    ($($t:ty),* $(,)?) => { $(
        // SAFETY: a primitive integer: every pattern a value, no padding.
        unsafe impl Pod for $t {}
    )* };
}
pod!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

// SAFETY: an array of a `Pod` type has no padding between its elements.
unsafe impl<T: Pod, const N: usize> Pod for [T; N] {}

// The ABI structs that cross the boundary whole. Each is `repr(C)`, integers
// only, and `azos_abi` asserts the size that leaves no gap; the assertions
// here restate it against the fields so a field added without its size
// fails the build here too.
const _: () = assert!(size_of::<azos_abi::ipc_msg::CapDesc>() == 4 + 1 + 1 + 2 + 8);
// SAFETY: see above.
unsafe impl Pod for azos_abi::ipc_msg::CapDesc {}
const _: () = assert!(
    size_of::<azos_abi::ipc_msg::MsgDesc>()
        == 2 + 1 + 1 + 4 + 8 + 8 * azos_abi::ipc_msg::MSG_WORDS_MAX
            + size_of::<azos_abi::ipc_msg::CapDesc>() * azos_abi::ipc_msg::MSG_CAPS_MAX + 8 + 4 + 4
);
// SAFETY: see above.
unsafe impl Pod for azos_abi::ipc_msg::MsgDesc {}
const _: () = assert!(size_of::<azos_abi::foreign::ForeignFrame>() == 34 * 8);
// SAFETY: see above.
unsafe impl Pod for azos_abi::foreign::ForeignFrame {}
const _: () = assert!(size_of::<azos_abi::ushell::Move>() == 4 * 4);
// SAFETY: see above.
unsafe impl Pod for azos_abi::ushell::Move {}
const _: () = assert!(
    size_of::<azos_abi::ushell::SpawnReq>()
        == 4 + 4 + 8 + 4 + 4 + 8 + 4 + 4 + 8 + 4 + 4 + size_of::<azos_abi::ushell::Move>() * azos_abi::ushell::SPAWN_MAX_MOVES
);
// SAFETY: see above.
unsafe impl Pod for azos_abi::ushell::SpawnReq {}

/// One `T` at a user address.
#[derive(Clone, Copy, Debug)]
pub struct UserPtr<T> {
    addr: usize,
    _t: PhantomData<*const T>,
}

impl<T: Pod> UserPtr<T> {
    /// The `T` at `addr` (a register value straight from ring 3).
    #[inline(always)]
    pub const fn new(addr: u64) -> Self {
        UserPtr { addr: addr as usize, _t: PhantomData }
    }

    /// Is it the null pointer?
    #[inline(always)]
    pub const fn is_null(self) -> bool {
        self.addr == 0
    }

    /// Read the value.
    #[inline]
    pub fn read(self) -> Result<T, Efault> {
        let mut v = MaybeUninit::<T>::uninit();
        if crate::copy_from_user(v.as_mut_ptr() as *mut u8, self.addr, size_of::<T>()) {
            // SAFETY: every byte was written, and any bit pattern is a `T`.
            Ok(unsafe { v.assume_init() })
        } else {
            Err(Efault)
        }
    }

    /// Write `v`.
    #[inline]
    pub fn write(self, v: &T) -> Result<(), Efault> {
        crate::copy_to_user(self.addr, v as *const T as *const u8, size_of::<T>()).then_some(()).ok_or(Efault)
    }
}

impl UserPtr<u32> {
    /// Compare-and-swap the 4-aligned word: `old` becomes `new` atomically
    /// against every thread of the process (a futex word). `Err(Some(v))`:
    /// the word held `v`; `Err(None)`: not a writable user word. A
    /// copy-on-write or reserved page is made writable first, so no lock may
    /// be held ([`crate::process::user_cas_u32`]).
    pub fn cas(self, old: u32, new: u32) -> Result<(), Option<u32>> {
        crate::process::user_cas_u32(self.addr, old, new)
    }

    /// [`cas`](Self::cas) that never faults a page in: a page not writable
    /// already answers `Err(None)` with nothing done, for a caller under a
    /// spinlock ([`crate::process::user_cas_u32_nofault`]).
    pub fn cas_resident(self, old: u32, new: u32) -> Result<(), Option<u32>> {
        crate::process::user_cas_u32_nofault(self.addr, old, new)
    }
}

/// `len` consecutive `T`s at a user address.
#[derive(Clone, Copy, Debug)]
pub struct UserSlice<T> {
    addr: usize,
    len: usize,
    _t: PhantomData<*const T>,
}

impl<T: Pod> UserSlice<T> {
    /// `len` elements at `addr` (register values straight from ring 3).
    #[inline(always)]
    pub const fn new(addr: u64, len: usize) -> Self {
        UserSlice { addr: addr as usize, len, _t: PhantomData }
    }

    /// The elements, in bytes; `None` when the count overflows.
    #[inline(always)]
    fn bytes(n: usize) -> Option<usize> {
        n.checked_mul(size_of::<T>())
    }

    /// Read the first `dst.len()` elements into `dst` (at most the slice's
    /// own length: a longer `dst` is a fault, not a read past the range).
    pub fn read_into(self, dst: &mut [T]) -> Result<(), Efault> {
        if dst.len() > self.len {
            return Err(Efault);
        }
        let n = Self::bytes(dst.len()).ok_or(Efault)?;
        crate::copy_from_user(dst.as_mut_ptr() as *mut u8, self.addr, n).then_some(()).ok_or(Efault)
    }

    /// [`read_into`](Self::read_into) for a buffer not initialised yet (a
    /// bounce buffer on the stack): the elements read, now initialised.
    pub fn read_uninit(self, dst: &mut [MaybeUninit<T>]) -> Result<&mut [T], Efault> {
        if dst.len() > self.len {
            return Err(Efault);
        }
        let n = Self::bytes(dst.len()).ok_or(Efault)?;
        if !crate::copy_from_user(dst.as_mut_ptr() as *mut u8, self.addr, n) {
            return Err(Efault);
        }
        // SAFETY: every byte of `dst` was written, and any bit pattern is a `T`.
        Ok(unsafe { core::slice::from_raw_parts_mut(dst.as_mut_ptr() as *mut T, dst.len()) })
    }

    /// Write `src` over the first `src.len()` elements (at most the slice's
    /// own length).
    pub fn write_from(self, src: &[T]) -> Result<(), Efault> {
        if src.len() > self.len {
            return Err(Efault);
        }
        let n = Self::bytes(src.len()).ok_or(Efault)?;
        crate::copy_to_user(self.addr, src.as_ptr() as *const u8, n).then_some(()).ok_or(Efault)
    }
}

/// A NUL-terminated string at a user address.
#[derive(Clone, Copy, Debug)]
pub struct UserCStr {
    addr: usize,
}

impl UserCStr {
    #[inline(always)]
    pub const fn new(addr: u64) -> Self {
        UserCStr { addr: addr as usize }
    }

    /// Copy the string, its NUL included, into `dst`: the length without the
    /// NUL. A fault, or no NUL within `dst.len()` bytes, is [`Efault`].
    pub fn read_into(self, dst: &mut [u8]) -> Result<usize, Efault> {
        crate::copy_cstr_from_user(dst, self.addr).ok_or(Efault)
    }
}
