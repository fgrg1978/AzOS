// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `MLSRV.ELF` (the image keeps its name until the topology row is renamed):
//! the ring-3 inference service.
//!
//! It serves the `Infer` interface on its endpoint (`endpoint.infer`, `READ`:
//! serving), with the receipts as a `Decisions` object and the verdict log
//! lease beside it; a client sees its own receipts and its own log, never
//! another context's. Models are the signed `.MBL` bundles of `/fat`. The
//! kernel's behavior task is one client of it, like any other: it calls
//! `Infer` with its own badge (`kernel/src/behavior_ml.rs`).
//!
//! # What it does, in order
//!
//! 1. The GGUF self-test of `selftest::prepare`.
//! 2. Picks the backend: `cpu-ggml` always, `rvv` when the vDSO capability
//!    word says the hart has V and the vector dot product agrees with the
//!    sequential one.
//! 3. Makes the platform; a context's verdict log is made on its first `log`
//!    call, not here.
//! 4. Loads every `*.MBL` of `/fat` into the blob arena, a volatile memory
//!    object: the system may take it back between calls, and a call that
//!    finds it gone loads the bundles again (`Service::resume_blobs`). The
//!    Domain's memory-pressure port is read where a call ends: a level that
//!    rose gives the arena back at once.
//! 5. Serves, on the main thread: one task, one place it blocks.

#![no_std]
#![no_main]

mod bundles;
mod out;
mod selftest;
mod sysplat;
mod volume;

use infsrv::broker::{Broker, Limits};
use infsrv::config::BLOB_BYTES;
use infsrv::exec::{Exec, RvvVerdict};
use infsrv::load::Arena;
use infsrv::service::{Platform, Service};
use infsrv::verdict::Publisher;
use azos_idl::MsgDesc;
use azos_libsys as sys;
use out::Line;
use sysplat::SysPlatform;

type Svc = Service<'static, SysPlatform>;

/// The service: built by `_start`, then used by the one thread that serves it.
/// A `static`, not a local, so the broker's tables are not on the stack.
static mut SERVICE: Option<Svc> = None;

/// Accept, serve, reply: for ever. An accept parks until a call arrives (a task
/// whose row serves no endpoint parks for good); it comes back empty only when
/// a wake was spurious, and then waits again.
fn serve_endpoint(svc: &mut Svc) -> ! {
    loop {
        let mut req = MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            sys::yield_now();
            continue;
        }
        let mut rep = MsgDesc::default();
        svc.handle(&req, &mut rep);
        let _ = sys::ipc_reply_v2(call as u64, &rep);
    }
}

/// Everything before the first call: the start-up checks, the backend, the
/// platform, the models, the service in its `static`. Its own function, so its
/// frame (the service is built here before it is moved) is gone when the
/// serving loop, the deepest chain of the program, runs.
#[inline(never)]
fn init() {
    sys::println(b"[infsrv] starting");
    selftest::prepare();

    // The backend.
    let hart_has_v = cfg!(target_arch = "riscv64") && sys::vdso_hwcap() & sys::hwcap::HWCAP_RV_V != 0;
    let (exec, rvv) = Exec::probe(hart_has_v);
    let mut l = Line::new(b"[infsrv] backends: cpu-ggml");
    match rvv {
        RvvVerdict::On => l.push(b" + rvv"),
        RvvVerdict::NotThisIsa => l.push(b" (rvv: not this ISA)"),
        RvvVerdict::NoHardware => l.push(b" (rvv: the hart has no V)"),
        RvvVerdict::Mismatch => l.push(b" (rvv: the vector dot product disagrees with the sequential one, NOT USED)"),
    };
    l.print();

    let mut plat = sysplat::platform();
    plat.watch_pressure();

    // The models, in an arena the system may take back between calls.
    let mut arena = Arena::new(&mut []);
    let mut broker = Broker::new(Limits::from_config());
    match plat.make_blobs() {
        Some(blobs) => arena.reset(blobs),
        None => sys::println(b"[infsrv] blob arena: no memory object: no model can be held"),
    }
    bundles::load_all(&mut broker, &mut arena);
    Line::new(b"[infsrv] blob arena: ").num((BLOB_BYTES - arena.free()) as u64).push(b" of ").num(BLOB_BYTES as u64)
        .push(b" bytes used").print();
    // SAFETY: this program has one thread; `SERVICE` is touched here and by
    // `serve_endpoint`, which `_start` calls after this returns.
    let svc = unsafe { (*core::ptr::addr_of_mut!(SERVICE)).insert(Service::new(broker, arena, exec, plat, Some(Publisher::new()))) };
    // Until the first call the arena may be taken back.
    svc.plat.blobs_park(false);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    init();
    sys::println(b"[infsrv] serving the Infer interface on endpoint.infer");
    // SAFETY: as in `init`: one thread, and `SERVICE` is set.
    match unsafe { (*core::ptr::addr_of_mut!(SERVICE)).as_mut() } {
        Some(svc) => serve_endpoint(svc),
        None => sys::exit(2),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(2);
}
