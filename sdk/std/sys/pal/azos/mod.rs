// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The platform layer of `*-unknown-azos`: what `std` needs of the OS, as
//! calls into `azos_stdrt` (crates/core/stdrt), which speaks the native ABI.
//! There is no errno here: a native result is a negative code, and
//! [`map_native_error`] gives it an `io::ErrorKind`.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod futex;
pub mod os;

use crate::io;

// SAFETY: must be called only once during runtime initialization. The entry
// (`_azos_entry` in azos_stdrt) has already read the startup block.
pub unsafe fn init(_argc: isize, _argv: *const *const u8, _sigpipe: u8) {}

// SAFETY: must be called only once during runtime cleanup.
pub unsafe fn cleanup() {}

pub fn unsupported<T>() -> io::Result<T> {
    Err(unsupported_err())
}

pub fn unsupported_err() -> io::Error {
    io::Error::UNSUPPORTED_PLATFORM
}

pub fn abort_internal() -> ! {
    core::intrinsics::abort();
}

/// The `io::ErrorKind` of a negative native result.
pub(crate) fn map_native_error(code: isize) -> io::Error {
    use io::ErrorKind::*;
    io::Error::from(match code {
        -4 => Interrupted,
        -9 => InvalidInput,
        -11 => WouldBlock,
        -12 => OutOfMemory,
        -13 | -1 => PermissionDenied,
        -22 => InvalidInput,
        -32 => BrokenPipe,
        -110 => TimedOut,
        _ => Uncategorized,
    })
}
