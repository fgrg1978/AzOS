// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The terminal of this program's job: the call capability its shell lent it
//! as fd 0 (`azos_stdrt::terminal`), answered only while the job has the
//! focus. Raw mode, echo and the size; the input is `std::io::stdin`. The
//! terminal server puts the shell's mode back when the job loses the focus,
//! so a program that ends without restoring it leaves nothing behind.

use crate::io;
use azos_stdrt::{console, sys, terminal};

fn lent() -> io::Result<u32> {
    console::terminal()
        .ok_or(io::const_error!(io::ErrorKind::Unsupported, "this program was lent no terminal of its own"))
}

fn refused() -> io::Error {
    io::const_error!(io::ErrorKind::PermissionDenied, "the terminal refused: the job does not have the focus")
}

/// Raw (`true`: bytes as typed, no editing) or cooked (lines) input.
pub fn set_raw(raw: bool) -> io::Result<()> {
    let h = lent()?;
    terminal::set_mode(&mut |m| sys::ipc_call(h, m), raw).then_some(()).ok_or_else(refused)
}

/// Echo typed input, or not.
pub fn set_echo(on: bool) -> io::Result<()> {
    let h = lent()?;
    terminal::set_echo(&mut |m| sys::ipc_call(h, m), on).then_some(()).ok_or_else(refused)
}

/// The window size, `(columns, rows)`.
pub fn size() -> io::Result<(u16, u16)> {
    let h = lent()?;
    terminal::size(&mut |m| sys::ipc_call(h, m)).ok_or_else(refused)
}
