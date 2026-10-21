// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Names` object: how a task obtains the endpoint of a service it was
//! wired to, without a global name space.
//!
//! **A name is never authority; the handle is.** Nothing here lets a task
//! reach a service because it knows a string. The signed topology says which
//! rows may ask for which names (`imports = [...]` in a `[task.NAME]` row,
//! CAPS.TOML format 5) and which row holds the endpoint behind each name; the
//! kernel hands an importing row one capability, the call right on
//! `endpoint.names`, stamped with the row's identity (the badge). The name
//! server (`userspace/services/namesd`) holds, from ITS row, the endpoint
//! capabilities it may lend, and answers:
//!
//! * [`Names::lookup`]: for a name the caller's row imports, a **derived,
//!   attenuated** capability (`Lent`): a child of the server's own in the
//!   warrant tree, with the call right only (not `DUP`, so the borrower cannot
//!   pass it on), revoked with the server's. For any other name, nothing is
//!   lent and the refusal is recorded by the server.
//! * [`Names::who_serves`]: for a name the caller's row imports, the name of
//!   the task serving it (its image's row), packed like a name; all zero when
//!   nobody serves it yet. The image hash is not here: it is a kernel fact
//!   (`IMAGE_HASHES`), and a ring-3 server has no authority over it.
//!
//! **A lent capability is a lease.** The server stamps the entry it lends with
//! a deadline (`CapDesc::expiry_ns`, `now + NAMES_LEND_TTL_MS`; none when that
//! is 0) and the kernel derives the borrower's copy with the earlier of that
//! and the server's own. When it passes, a call through the copy is refused
//! and the borrower asks again: [`Renewing`] is the transport that does so,
//! once per failed call, and closes the lapsed handle.
//!
//! A name crosses the wire as three words (the 24 bytes of
//! `ENDPOINT_NAME_MAX`), packed by [`pack_name`]; the lint of the IDL refuses
//! text, and a name is a key into the server's table, not a path.
#![no_std]

pub use azos_idl::{Cap, IdlError, Lent, MsgDesc, Transport};
use azos_idl::azos_interface;
use core::cell::Cell;

/// The interface id (ASCII "NAME").
pub const NAMES_ID: u32 = 0x4E41_4D45;
/// Longest name, in bytes: `ENDPOINT_NAME_MAX`.
pub const NAME_MAX: usize = 24;
/// Words of a packed name.
pub const NAME_WORDS: usize = NAME_MAX / 8;
/// A packed name.
pub type PackedName = [u64; NAME_WORDS];

/// What a lent capability names: an endpoint the caller may call.
pub struct Endpoint;

#[azos_interface(id = 0x4E41_4D45, level = 1)]
pub trait Names {
    /// The endpoint called `name`, lent to the caller with the call right
    /// only, or nothing lent (the name is not one the caller's row imports,
    /// the server does not hold it, or the caller is unidentified).
    fn lookup(&mut self, name: PackedName) -> Lent<Endpoint>;

    /// The task serving the endpoint called `name`, packed like a name; all
    /// zero when it is unserved or the caller may not ask.
    #[idempotent]
    fn who_serves(&mut self, name: PackedName) -> PackedName;
}

/// How a borrower makes its calls on lent handles: the v2 call and the close
/// of a handle (`libsys::ipc_call_v2`, `libsys::close_typed`).
pub trait Call {
    /// Call `handle` with `msg`: 0 when served (the reply is in `msg`), else
    /// the kernel's negative code.
    fn call(&self, handle: u32, msg: &mut MsgDesc) -> isize;
    /// Release a handle that will not be used again.
    fn close(&self, handle: u32);
}

/// A call that failed the way a lapsed lease fails. The v2 call reports an
/// endpoint it cannot resolve (stale, expired, revoked, unserved) with one
/// code, `-EPERM`, on purpose: which of them it was would report on a
/// capability the caller does not hold. A stale generation read elsewhere is
/// `-ECAPSTALE`. Either may be cured by a fresh lease; a genuine permission
/// refusal costs one more lookup and is refused again.
pub const fn lease_lapsed(rc: isize) -> bool {
    rc == azos_abi::error::Errno::EPERM.to_syscall_ret() as isize
        || rc == azos_abi::error::Errno::ECAPSTALE.to_syscall_ret() as isize
}

/// The transport of a client of a lent endpoint: calls `handle`, and when the
/// lease has lapsed asks the name server for `name` again and retries the
/// call once on the new handle.
pub struct Renewing<C: Call> {
    call: C,
    names: u32,
    name: PackedName,
    handle: Cell<u32>,
}

/// The name server's transport: the same [`Call`], on the `endpoint.names`
/// handle.
struct Dial<'a, C: Call> {
    call: &'a C,
    names: u32,
}

impl<C: Call> Transport for Dial<'_, C> {
    fn call(&self, msg: &mut MsgDesc) -> Result<(), IdlError> {
        match self.call.call(self.names, msg) {
            0 => Ok(()),
            rc => Err(IdlError::Transport(rc)),
        }
    }
}

impl<C: Call> Renewing<C> {
    /// A client of the endpoint `name` the name server lent as `handle` (0:
    /// not lent yet; the first call asks). `names` is this task's handle on
    /// `endpoint.names`.
    pub const fn new(call: C, names: u32, name: PackedName, handle: u32) -> Self {
        Renewing { call, names, name, handle: Cell::new(handle) }
    }

    /// The handle in use now.
    pub fn handle(&self) -> u32 {
        self.handle.get()
    }

    /// Ask the name server for the endpoint again: `true` when it lent one.
    /// The lapsed handle is closed, the new one replaces it.
    pub fn renew(&self) -> bool {
        let lent = NamesClient::new(Dial { call: &self.call, names: self.names }).lookup(self.name);
        match lent.ok().and_then(|l| l.get()) {
            Some(c) => {
                let old = self.handle.replace(c.raw());
                if old != 0 {
                    self.call.close(old);
                }
                true
            }
            None => false,
        }
    }
}

impl<C: Call> Transport for Renewing<C> {
    fn call(&self, msg: &mut MsgDesc) -> Result<(), IdlError> {
        let h = self.handle.get();
        let rc = if h == 0 { azos_abi::error::Errno::EPERM.to_syscall_ret() as isize } else { self.call.call(h, msg) };
        if rc == 0 {
            return Ok(());
        }
        if !lease_lapsed(rc) || !self.renew() {
            return Err(IdlError::Transport(rc));
        }
        match self.call.call(self.handle.get(), msg) {
            0 => Ok(()),
            rc => Err(IdlError::Transport(rc)),
        }
    }
}

/// Pack `name` (1..=[`NAME_MAX`] bytes) into words, little-endian, zero-padded.
/// `None` for an empty or over-long name: refused, never truncated.
pub fn pack_name(name: &[u8]) -> Option<PackedName> {
    if name.is_empty() || name.len() > NAME_MAX {
        return None;
    }
    let mut b = [0u8; NAME_MAX];
    b[..name.len()].copy_from_slice(name);
    Some(core::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]))))
}

/// The bytes of a packed name: `out` and the length (up to the first zero).
pub fn unpack_name(w: &PackedName, out: &mut [u8; NAME_MAX]) -> usize {
    for (i, x) in w.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&x.to_le_bytes());
    }
    out.iter().position(|&c| c == 0).unwrap_or(NAME_MAX)
}
