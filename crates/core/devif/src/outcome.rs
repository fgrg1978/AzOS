// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What an op of a device or service interface answers: an outcome code and,
//! for a read, the value.
//!
//! The codes are the interface layer's own vocabulary, not an `errno`; a
//! kernel-hosted op or a ring-3 driver maps its internal failure to the
//! nearest one. 0 is served.

use azos_idl::{Reader, Wire, Writer};

/// Served.
pub const OK: u32 = 0;
/// The capability's rights do not cover the op (or the system is contained
/// and the op acts).
pub const DENIED: u32 = 1;
/// An argument is outside what the resource accepts.
pub const BAD_ARGUMENT: u32 = 2;
/// The resource cannot answer yet (an unseeded pool, a sensor with no sample,
/// a driver that has not registered).
pub const NOT_READY: u32 = 3;
/// The device or its driver failed the op.
pub const FAULT: u32 = 4;
/// The build, board or driver does not provide the op.
pub const UNSUPPORTED: u32 = 5;
/// The resource is held by something else (a pin a motor owns, a bus in use).
pub const BUSY: u32 = 6;
/// The badge names no resource of this interface.
pub const NO_RESOURCE: u32 = 7;
/// The op was refused by a safety rule (the e-stop latch, a limit).
pub const REFUSED: u32 = 8;
/// Client side only, never on the wire: the call itself did not reach a
/// server (a capability that does not resolve, an endpoint nobody serves, a
/// reply that was not the interface's).
pub const NO_SERVER: u32 = 9;

/// An op's answer: the outcome code and the value that goes with a served
/// read (zero otherwise). One word for the code and the value's words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Out<T> {
    pub code: u32,
    pub value: T,
}

impl<T> Out<T> {
    pub const fn new(code: u32, value: T) -> Self {
        Out { code, value }
    }
    /// Served, with `value`.
    pub const fn ok(value: T) -> Self {
        Out { code: OK, value }
    }
    /// Served.
    pub const fn is_ok(&self) -> bool {
        self.code == OK
    }
}

impl<T: Default> Out<T> {
    /// Refused or failed with `code`, no value.
    pub fn err(code: u32) -> Self {
        Out { code, value: T::default() }
    }
}

impl<T: Wire> Wire for Out<T> {
    const WORDS: usize = 1 + T::WORDS;
    const CAPS: usize = T::CAPS;
    fn put(&self, w: &mut Writer<'_>) {
        w.word(self.code as u64);
        self.value.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let code = match u32::try_from(r.word()) {
            Ok(c) => c,
            Err(_) => {
                r.fail();
                0
            }
        };
        Out { code, value: T::get(r) }
    }
}
