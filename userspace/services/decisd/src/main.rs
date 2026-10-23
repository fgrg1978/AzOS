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
//! `DECISION_REFUSALS_DURABLE`). A record's subject may be a task, hence the
//! admin region, and the task view its row holds to be granted it.
//!
//! Request-driven, like `termd`: accept, read the records again (the kernel
//! writes a record into the region where it is recorded, so a request sees
//! every decision made before it, with no wait), dispatch, reply. The records,
//! their filter and the reply words are the library's; `bin.rs` is the
//! decoder and is tested on the host (`tests/host/decisions-tests`).

#![no_std]
#![no_main]

mod bin;

use azos_decisions::{DecisionsIdl, MsgDesc, Service};
use azos_inspect_lib::{Inspector, Source, Value};
use azos_libsys as sys;
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
    let mut tree = public.and_then(|p| unsafe { Inspector::from_mapped(p, admin) }.ok()).filter(|t| t.has_admin());
    if tree.is_none() {
        let _ = sys::console_write(sys::STDOUT, b"[decisd] no admin introspection region: it answers as if the kernel held no decision\n");
    }

    loop {
        let mut req = MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            // Nothing arrived (a spurious wake): wait again.
            sys::yield_now();
            continue;
        }
        let n = tree.as_mut().map_or(0, |t| read_records(t, &mut file));
        svc.0.load(&file[..n]);
        let mut rep = MsgDesc::default();
        let _ = DecisionsIdl::dispatch(svc, &req, &mut rep);
        let _ = sys::ipc_reply_v2(call as u64, &rep);
    }
}
