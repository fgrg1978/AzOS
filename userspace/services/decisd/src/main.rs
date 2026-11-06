// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `DECISD.ELF`: the AzOS decision server.
//!
//! A ring-3 program whose topology row is its whole authority: `READ` on
//! `endpoint.decisions` (it serves it). It answers the `Decisions` object
//! (`userspace/lib/decisions`) to whoever holds a call capability on that
//! endpoint (`WHY.ELF`, and any row the topology gives `WRITE`), from the
//! decisions the kernel keeps and publishes as binary records in its
//! introspection tree's admin region (`decisions/records/<n>`: the ring when
//! `DECISION_RECORDS_DEV` is on, the journal of durable decisions with
//! `DECISION_REFUSALS_DURABLE`; with both, the durable ones keep half the
//! records). A record's subject may be a task, hence the
//! admin region, and the task view its row holds to be granted it.
//!
//! Request-driven, like `termd`: a calls-only server on `azos_srv` (it sleeps
//! in the accept), which reads the records again for each call, dispatches and
//! replies. The records, their filter and the reply words are the library's;
//! `bin.rs` is the decoder and is tested on the host
//! (`tests/host/decisions-tests`).

#![no_std]
#![no_main]

mod bin;

use azos_decisions::{DecisionsIdl, MsgDesc, Service};
use azos_inspect_lib::{Inspector, Source, Value};
use azos_libsys as sys;
use azos_srv::sys::Calls;
use azos_srv::{Answer, Handler, Server};
use bin::BinSource;

/// The records read at once: the table's worth.
const FILE_MAX: usize = bin::MAX * azos_decisions::PROVENANCE_SIZE;

static SERVICE: sys::Lock<Service<BinSource>> = sys::Lock::new(Service(BinSource::new()));

/// The admin region's records back to back into `buf`, in slot order (the
/// decoder sorts them by id; an empty slot is skipped); the bytes written (0 when the tree is not there: the kernel was built without
/// decision records, or the row holds no admin region).
fn read_records(tree: &mut Inspector<'static>, buf: &mut [u8]) -> usize {
    const SIZE: usize = azos_decisions::PROVENANCE_SIZE;
    tree.with(Source::Admin, |r| {
        let mut at = 0;
        let Some(dir) = r.lookup("decisions/records")? else { return Ok(0) };
        r.children(dir, &mut |_, v| {
            if let Value::Bytes(b) = v {
                if b.as_bytes().len() == SIZE && at + SIZE <= buf.len() {
                    buf[at..at + SIZE].copy_from_slice(b.as_bytes());
                    at += SIZE;
                }
            }
        })?;
        Ok(at)
    })
    .unwrap_or(0)
}

/// The server: the records are read again for every call (the kernel writes
/// a record into the region where it is recorded, so a call sees every
/// decision made before it, with no wait).
struct Decisions<'a> {
    svc: &'a mut Service<BinSource>,
    tree: Option<Inspector<'static>>,
    file: &'a mut [u8],
}

impl Handler<Calls> for Decisions<'_> {
    fn call(&mut self, _k: &mut Calls, _handle: u64, req: &MsgDesc, rep: &mut MsgDesc) -> Answer {
        let n = self.tree.as_mut().map_or(0, |t| read_records(t, self.file));
        self.svc.0.load(&self.file[..n]);
        let _ = DecisionsIdl::dispatch(self.svc, req, rep);
        Answer::Reply
    }
}

#[sys::main(panic_exit = 70)]
fn main() -> ! {
    // The one reference, for the life of the program.
    let svc = SERVICE.lock().leak();
    let _ = sys::console_write(sys::STDOUT, b"[decisd] AzOS decision server (Decisions on endpoint.decisions)\n");
    let mut file = [0u8; FILE_MAX];
    let public = sys::inspect_map(azos_abi::cap::SHM_INSPECT_PUBLIC).ok();
    let admin = sys::inspect_map(azos_abi::cap::SHM_INSPECT_ADMIN).ok();
    // SAFETY: the mappings live as long as the task, read-only, and the kernel
    // writes them only with aligned 64-bit stores.
    let tree = public.and_then(|p| unsafe { Inspector::from_mapped(p, admin) }.ok()).filter(|t| t.has_admin());
    if tree.is_none() {
        let _ = sys::console_write(sys::STDOUT, b"[decisd] no admin introspection region: it answers as if the kernel held no decision\n");
    }
    Server::calls_only(Calls).run(&mut Decisions { svc, tree, file: &mut file })
}
