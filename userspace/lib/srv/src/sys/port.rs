// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A server's event port: the calls and timers bound to it, the one wait.

use super::{accept_blocking, accept_poll, ok, reply};
use crate::{Event, Kernel, MsgDesc};
use azos_libsys as sys;

/// Why [`Port::bind_served`] did not bind every endpoint this task serves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ServedError {
    /// The task serves no endpoint.
    NoEndpoint,
    /// The endpoint behind `handle` would not bind (`code`, a negative errno:
    /// another live port has its calls, the port is full).
    Refused { handle: u32, code: isize },
}

/// How long a server backs off after a refused wait, ms.
const PAUSE_MS: u64 = 10;

/// A server's event port.
#[derive(Clone, Copy)]
pub struct Port {
    pub cap: u32,
}

impl Port {
    /// A new port of this task's.
    pub fn create() -> Result<Port, isize> {
        let cap = sys::port_create_typed();
        if cap <= 0 { Err(cap.min(-1)) } else { Ok(Port { cap: cap as u32 }) }
    }

    /// Report the calls queued on the endpoint `ep` this task serves.
    pub fn bind_calls(&self, ep: u32, key: u64) -> Result<(), isize> {
        ok(sys::port_bind_calls(self.cap, ep, key))
    }

    /// Report the calls of every endpoint this task serves: each endpoint
    /// capability it holds with `READ` and no badge. One the kernel answers
    /// `-EPERM` is not this task's to serve (an interface it calls) and is
    /// skipped; any other refusal fails the whole bind, so a served endpoint
    /// is never left unbound and silent. How many were bound.
    pub fn bind_served(&self, key: u64) -> Result<u32, ServedError> {
        let read = azos_abi::cap::CapPerms::READ.bits();
        let eperm = azos_abi::error::Errno::EPERM.to_syscall_ret() as isize;
        let mut n = 0;
        for i in 0..azos_limits::IPC_ENDPOINTS as u32 {
            let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), i);
            if h <= 0 || !sys::cap_info(h as u32).is_ok_and(|c| c.rights & read != 0 && c.badge == 0) {
                continue;
            }
            match self.bind_calls(h as u32, key) {
                Ok(()) => n += 1,
                Err(code) if code == eperm => {}
                Err(code) => return Err(ServedError::Refused { handle: h as u32, code }),
            }
        }
        if n == 0 { Err(ServedError::NoEndpoint) } else { Ok(n) }
    }

    /// Arm (or re-arm) the one-shot timer `key` for `deadline_ns`.
    pub fn arm(&self, key: u64, deadline_ns: u64) -> Result<(), isize> {
        ok(sys::port_bind_timer(self.cap, deadline_ns, key))
    }
}

impl Kernel for Port {
    fn wait(&mut self, deadline_ns: u64) -> Result<Option<Event>, isize> {
        let mut b = [0u8; sys::PORT_EVENT_BYTES];
        match sys::port_wait_until_typed(self.cap, &mut b, deadline_ns) {
            0 => Ok(None),
            n if n < 0 => Err(n),
            _ => Ok(Some(azos_abi::syscall_nr::port_event_decode(&b))),
        }
    }

    fn accept(&mut self, req: &mut MsgDesc) -> Result<Option<u64>, isize> {
        accept_poll(req)
    }

    fn accept_blocking(&mut self, req: &mut MsgDesc) -> Result<Option<u64>, isize> {
        accept_blocking(req)
    }

    fn reply(&mut self, handle: u64, rep: &MsgDesc) -> isize {
        reply(handle, rep)
    }

    fn pause(&mut self) {
        sys::sleep(PAUSE_MS);
    }
}
