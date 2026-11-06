// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel side over libsys: the port, the calls on it, its timers. The
//! sources only some servers bind are in files of their own (`doorbell.rs`,
//! `irq.rs`), so a server's syscall profile, derived from the files its image
//! lists (`tests/host/seccomp-tests`), names only what it binds.

use super::{Event, Kernel, MsgDesc};
use azos_libsys as sys;

mod doorbell;
mod irq;

/// How long a server backs off after a refused wait, ms.
const PAUSE_MS: u64 = 10;

const E_AGAIN: isize = azos_abi::error::Errno::EAGAIN.to_syscall_ret() as isize;

/// A server's event port.
#[derive(Clone, Copy)]
pub struct Port {
    pub cap: u32,
}

/// `r` as a result: the value, or the negative code.
fn ok(r: isize) -> Result<(), isize> {
    if r < 0 { Err(r) } else { Ok(()) }
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
    /// capability it holds with `READ` and no badge (the serving half; a
    /// kernel-hosted interface it calls is refused by the kernel and
    /// skipped). How many were bound, or `-ENOENT` for none.
    pub fn bind_served(&self, key: u64) -> Result<u32, isize> {
        let read = azos_abi::cap::CapPerms::READ.bits();
        let mut n = 0;
        for i in 0..azos_limits::IPC_ENDPOINTS as u32 {
            let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), i);
            if h <= 0 {
                continue;
            }
            let serving = sys::cap_info(h as u32).is_ok_and(|c| c.rights & read != 0 && c.badge == 0);
            if serving && self.bind_calls(h as u32, key).is_ok() {
                n += 1;
            }
        }
        if n == 0 { Err(azos_abi::error::Errno::ENOENT.to_syscall_ret() as isize) } else { Ok(n) }
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
        match sys::ipc_accept_poll(req) {
            h if h >= 0 => Ok(Some(h as u64)),
            E_AGAIN => Ok(None),
            e => Err(e),
        }
    }

    fn reply(&mut self, handle: u64, rep: &MsgDesc) -> isize {
        sys::ipc_reply_v2(handle, rep)
    }

    fn pause(&mut self) {
        sys::sleep(PAUSE_MS);
    }
}
