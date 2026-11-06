// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel side over libsys: a server on a port ([`Port`]) or on its calls
//! alone ([`Calls`]). Each source and each kind of server is a file of its
//! own (`port.rs`, `calls.rs`, `doorbell.rs`), so a server's syscall
//! profile, derived from the files its image lists
//! (`tests/host/seccomp-tests`), names only what it uses.

use super::MsgDesc;
use azos_libsys as sys;

mod calls;
mod doorbell;
mod port;

pub use calls::Calls;
pub use port::{Port, ServedError};

const E_AGAIN: isize = azos_abi::error::Errno::EAGAIN.to_syscall_ret() as isize;

/// `r` as a result: the value, or the negative code.
fn ok(r: isize) -> Result<(), isize> {
    if r < 0 { Err(r) } else { Ok(()) }
}

/// The poll accept.
fn accept_poll(req: &mut MsgDesc) -> Result<Option<u64>, isize> {
    match sys::ipc_accept_poll(req) {
        h if h >= 0 => Ok(Some(h as u64)),
        E_AGAIN => Ok(None),
        e => Err(e),
    }
}

/// The accept that sleeps; -1 is a wake with nothing.
fn accept_blocking(req: &mut MsgDesc) -> Result<Option<u64>, isize> {
    match sys::ipc_accept_v2(req) {
        h if h >= 0 => Ok(Some(h as u64)),
        -1 => Ok(None),
        e => Err(e),
    }
}

fn reply(handle: u64, rep: &MsgDesc) -> isize {
    sys::ipc_reply_v2(handle, rep)
}
