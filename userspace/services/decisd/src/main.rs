// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `DECISD.ELF`: the AzOS decision server.
//!
//! A ring-3 program whose topology row is its whole authority: `READ` on
//! `endpoint.decisions` (it serves it). It answers the `Decisions` object
//! (`userspace/lib/decisions`) to whoever holds a call capability on that
//! endpoint (`WHY.ELF`, and any row the topology gives `WRITE`), from the
//! decisions the kernel keeps and exports as binary records in
//! `/proc/decisions.bin` (the ring when `DECISION_RECORDS_DEV` is on, the
//! journal of durable decisions with `DECISION_REFUSALS_DURABLE`).
//!
//! Request-driven, like `termd`: accept, read the file again (a request sees
//! the decisions of the moment it is made), dispatch, reply. The records,
//! their filter and the reply words are the library's; `bin.rs` is the
//! decoder and is tested on the host (`tests/host/decisions-tests`).

#![no_std]
#![no_main]

mod bin;

use azos_decisions::{DecisionsIdl, MsgDesc, Service};
use azos_libsys as sys;
use bin::BinSource;

/// Where the kernel exports the records. NUL-terminated, as `open_root` takes
/// a name: without the NUL the open is refused and the server answers as if
/// the kernel held no decision.
const PATH: &[u8] = b"/proc/decisions.bin\0";
/// A procfs file is at most this (`azos_fs::procfs::PROCFS_MAX_FILE`).
const FILE_MAX: usize = 2048;

struct Cell(core::cell::UnsafeCell<Service<BinSource>>);
// SAFETY: one thread.
unsafe impl Sync for Cell {}

static SERVICE: Cell = Cell(core::cell::UnsafeCell::new(Service(BinSource::new())));

/// Read the file whole into `buf`; the bytes read (0 when it cannot be opened:
/// the kernel was built without decision records).
fn read_file(buf: &mut [u8]) -> usize {
    let fd = sys::open_root(PATH, 0);
    if fd < 0 {
        return 0;
    }
    let mut got = 0;
    while got < buf.len() {
        let n = sys::read(fd as u64, &mut buf[got..]);
        if n <= 0 {
            break;
        }
        got += n as usize;
    }
    let _ = sys::close(fd as u64);
    got
}

#[sys::main(panic_exit = 70)]
fn main() -> ! {
    // SAFETY: the one reference, for the life of the program.
    let svc = unsafe { &mut *SERVICE.0.get() };
    let _ = sys::console_write(sys::STDOUT, b"[decisd] AzOS decision server (Decisions on endpoint.decisions)\n");
    let mut file = [0u8; FILE_MAX];

    loop {
        let mut req = MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            // Nothing arrived (a spurious wake): wait again.
            sys::yield_now();
            continue;
        }
        let n = read_file(&mut file);
        svc.0.load(&file[..n]);
        let mut rep = MsgDesc::default();
        let _ = DecisionsIdl::dispatch(svc, &req, &mut rep);
        let _ = sys::ipc_reply_v2(call as u64, &rep);
    }
}
