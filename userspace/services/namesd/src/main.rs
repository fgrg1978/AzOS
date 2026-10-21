// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `NAMESD.ELF`: the AzOS name server.
//!
//! A ring-3 program whose whole authority is its row: `READ` on
//! `endpoint.names` (it serves it) and, for each name it may lend, a
//! `WRITE` + `transfer` grant on that endpoint (it can call it, and DUP a
//! derived copy of it to a borrower). It reads `/proc/names`, which only the
//! holder of `READ` on `endpoint.names` gets anything from. The decision and
//! the refusal record are `service.rs`, pure and tested on the host
//! (`tests/host/names-tests`); this file is the loop around them.
//!
//! Request-driven, like the terminal server: accept, dispatch, reply. The
//! caller is identified by the badge on its call, which the kernel stamped
//! from its signed row and the caller cannot change.

#![no_std]
#![no_main]

mod service;

use azos_libsys as sys;
use azos_names::{MsgDesc, NamesIdl};
use service::{Host, Service, VIEW_MAX};

/// The kernel's view of the topology and this task's own table.
struct Kernel;

impl Host for Kernel {
    fn view(&mut self, buf: &mut [u8]) -> usize {
        let h = sys::open_root(b"/proc/names\0", 0);
        if h < 0 {
            return 0;
        }
        let h = h as u32;
        let mut got = 0;
        // The VFS hands a file out in pieces of at most one page.
        while got < buf.len().min(VIEW_MAX) {
            let n = sys::file_read_typed(h, &mut buf[got..]);
            if n <= 0 {
                break;
            }
            got += n as usize;
        }
        let _ = sys::close_typed(h);
        got
    }

    fn handle(&mut self, index: u32) -> Option<u32> {
        let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), index);
        (h > 0).then_some(h as u32)
    }

    fn log(&mut self, line: &[u8]) {
        let _ = sys::console_write(sys::STDOUT, line);
    }

    fn now_ns(&mut self) -> u64 {
        sys::vdso_now_ns()
    }
}

struct ServiceCell(core::cell::UnsafeCell<Service<Kernel>>);
// SAFETY: one thread.
unsafe impl Sync for ServiceCell {}

static SERVICE: ServiceCell = ServiceCell(core::cell::UnsafeCell::new(Service::new(Kernel, azos_limits::NAMES_LEND_TTL_MS as u64 * 1_000_000)));

#[sys::main(panic_exit = 70)]
fn main() -> ! {
    // SAFETY: the one reference, for the life of the program.
    let svc = unsafe { &mut *SERVICE.0.get() };
    let _ = sys::console_write(sys::STDOUT, b"[namesd] AzOS name server (Names on endpoint.names)\n");
    loop {
        let mut req = MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            // Nothing arrived (a spurious wake): wait again.
            sys::yield_now();
            continue;
        }
        // The badge of the capability the call came through, 0 when the call
        // was not badged: an unidentified caller, whom the service refuses.
        svc.caller = if req.flags & azos_abi::ipc_msg::MSG_BADGED != 0 { req.badge as u32 } else { 0 };
        let mut rep = MsgDesc::default();
        let _ = NamesIdl::dispatch(svc, &req, &mut rep);
        let _ = sys::ipc_reply_v2(call as u64, &rep);
    }
}
