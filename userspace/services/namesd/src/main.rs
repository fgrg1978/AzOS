// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `NAMESD.ELF`: the AzOS name server.
//!
//! A ring-3 program whose whole authority is its row: `READ` on
//! `endpoint.names` (it serves it) and, for each name it may lend, a
//! `WRITE` + `transfer` grant on that endpoint (it can call it, and DUP a
//! derived copy of it to a borrower), and `MemObj inspect.names`: the
//! kernel's view of the signed topology for the name server, where it reads
//! the rows' imports and the named endpoints its row holds (`imports/`,
//! `endpoints/`); which of those it may lend is what its own table holds. The
//! decision and
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
use azos_inspect_lib::{Inspector, Value};
use azos_names::{MsgDesc, NamesIdl, NAME_MAX};
use service::{Host, Service};

/// The kernel's view of the topology (the view region its row grants,
/// `MemObj inspect.names`, mapped once) and this task's own table.
struct Kernel {
    view: Option<Inspector<'static>>,
}

impl Kernel {
    /// The string at `path`, `None` when there is none (or no tree).
    fn str_at(&mut self, path: &str) -> Option<azos_inspect_lib::Str> {
        match self.view.as_mut()?.read(path).ok()?? {
            (_, Value::Str(s)) => Some(s),
            _ => None,
        }
    }
}

/// `<dir>/<name>[/<leaf>]`, or `None` when it does not fit.
fn path<'b>(buf: &'b mut [u8; 96], dir: &str, name: &[u8], leaf: &str) -> Option<&'b str> {
    let parts: [&[u8]; 3] = [dir.as_bytes(), b"/", name];
    let mut n = 0;
    for p in parts.into_iter().chain([if leaf.is_empty() { &b""[..] } else { b"/" }, leaf.as_bytes()]) {
        buf.get_mut(n..n + p.len())?.copy_from_slice(p);
        n += p.len();
    }
    core::str::from_utf8(&buf[..n]).ok()
}

impl Host for Kernel {
    fn imports(&mut self, badge: u32, name: &[u8]) -> bool {
        let mut d = [0u8; 10];
        let mut i = d.len();
        let mut v = badge;
        loop {
            i -= 1;
            d[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        let mut buf = [0u8; 96];
        let Some(p) = path(&mut buf, "imports", &d[i..], "") else { return false };
        self.str_at(p).is_some_and(|l| l.as_bytes().split(|&c| c == b',').any(|n| n == name))
    }

    fn export(&mut self, name: &[u8], server: &mut [u8; NAME_MAX]) -> Option<(u32, usize)> {
        let mut buf = [0u8; 96];
        let index = {
            let p = path(&mut buf, "endpoints", name, "index")?;
            self.view.as_mut()?.read_u64(p).ok()??
        };
        let index = u32::try_from(index).ok()?;
        self.handle(index)?;
        let p = path(&mut buf, "endpoints", name, "server")?;
        let s = self.str_at(p)?;
        let n = s.as_bytes().len().min(NAME_MAX);
        server[..n].copy_from_slice(&s.as_bytes()[..n]);
        Some((index, n))
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

static SERVICE: ServiceCell =
    ServiceCell(core::cell::UnsafeCell::new(Service::new(Kernel { view: None }, azos_limits::NAMES_LEND_TTL_MS as u64 * 1_000_000)));

#[sys::main(panic_exit = 70)]
fn main() -> ! {
    // SAFETY: the one reference, for the life of the program.
    let svc = unsafe { &mut *SERVICE.0.get() };
    let _ = sys::console_write(sys::STDOUT, b"[namesd] AzOS name server (Names on endpoint.names)\n");
    // The view, mapped once. The kernel writes an endpoint's pool index and
    // server where they change, so those this task's spawn created are in it
    // already.
    // SAFETY: the mapping lives as long as the task, read-only, and the
    // kernel writes it only with aligned 64-bit stores.
    svc.host.view = sys::inspect_map(azos_abi::cap::SHM_INSPECT_NAMES)
        .ok()
        .and_then(|m| unsafe { Inspector::from_mapped(m, None) }.ok());
    if svc.host.view.is_none() {
        let _ = sys::console_write(sys::STDOUT, b"[namesd] no introspection tree: every lookup is refused\n");
    }
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
