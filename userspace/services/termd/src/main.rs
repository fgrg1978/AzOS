// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `TERMD.ELF`: the AzOS terminal server.
//!
//! A ring-3 program with no hardware authority beyond the console's input,
//! which it claims at start (it is the console program, `CONSOLE_PATH`). It
//! serves the `Terminal` object (`userspace/lib/term`) to ONE client, the
//! shell, over the `endpoint.term` endpoint the topology grants: this row
//! holds `READ` (it serves), the shell's row `WRITE` (it calls). The line
//! discipline (`disc.rs`, over the editor `edit.rs`) and the interface's
//! implementation (`service.rs`) are pure and tested on the host
//! (`tests/host/term-tests`); this file is the loop around them.
//!
//! Request-driven: the ABI's accept blocks, so the loop is accept, dispatch,
//! reply. `read_event` runs `LOG_CONSOLE_WAIT` itself inside the call; see
//! `service.rs` for why that is enough for one client.
//!
//! The Linux runtime's terminal (`/dev/ptmx`, termios) is NOT mapped here.
//! A foreground Linux job reads the console through the kernel's own line
//! discipline while the console's owner lends it input (`SPAWN_F_CONSOLE_IN`,
//! which needs the spawner to be the owner); that mapping is a front of its
//! own.

#![no_std]
#![no_main]

mod disc;
// The editor's cursor and history-size accessors are for the host tests.
#[allow(dead_code)]
mod edit;
mod service;

use azos_libsys as sys;
use azos_term::{MsgDesc, TerminalIdl};
use service::{Console, Service};

/// The console as the kernel gives it to its input owner.
struct Uart;

impl Console for Uart {
    fn read(&mut self, buf: &mut [u8], timeout_ns: Option<u64>) -> isize {
        sys::console_wait(buf, timeout_ns.unwrap_or(sys::CONSOLE_WAIT_FOREVER))
    }

    fn write(&mut self, b: &[u8]) {
        let _ = sys::console_write(sys::STDOUT, b);
    }
}

struct ServiceCell(core::cell::UnsafeCell<Service<Uart>>);
// SAFETY: one thread.
unsafe impl Sync for ServiceCell {}

static SERVICE: ServiceCell = ServiceCell(core::cell::UnsafeCell::new(Service::new(Uart)));

/// `-EBUSY`: another task owns console input.
const E_BUSY: isize = -16;

#[sys::main(panic_exit = 70)]
fn main() -> ! {
    // SAFETY: the one reference, for the life of the program.
    let svc = unsafe { &mut *SERVICE.0.get() };

    // Claim console input now, not at the first read: a zero-timeout wait
    // claims it (the claim is inside any wait with a buffer) and returns at
    // once. A byte that was already typed is kept, not lost.
    let mut one = [0u8; 1];
    let n = sys::console_wait(&mut one, 0);
    if n == E_BUSY {
        let _ = sys::console_write(sys::STDOUT, b"termd: console input belongs to another task\n");
        sys::exit(1);
    }
    if n > 0 {
        svc.d.push(&one[..n as usize]);
    }
    let _ = sys::console_write(sys::STDOUT, b"[termd] AzOS terminal server (Terminal on endpoint.term)\n");

    loop {
        let mut req = MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            // Nothing arrived (a spurious wake): wait again.
            sys::yield_now();
            continue;
        }
        let mut rep = MsgDesc::default();
        let _ = TerminalIdl::dispatch(svc, &req, &mut rep);
        let _ = sys::ipc_reply_v2(call as u64, &rep);
        if let Some(status) = svc.hung_up {
            // The client is done: end the session with its status. The exit
            // releases console input; 0 gives the console back to the
            // kernel's recovery shell, anything else is a failed session the
            // supervisor restarts.
            sys::exit(status);
        }
    }
}
