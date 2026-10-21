// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The arguments of the startup block (`SYS_SPAWN_EX`'s argv).

pub use super::common::Args;
use crate::ffi::OsString;

pub fn args() -> Args {
    let mut v = Vec::new();
    let mut i = 0;
    while let Some(a) = azos_stdrt::start::arg(i) {
        // SAFETY: arguments are bytes; the encoding of an OsString here is bytes.
        v.push(unsafe { OsString::from_encoded_bytes_unchecked(a.to_vec()) });
        i += 1;
    }
    Args::new(v)
}
