// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `endpoint.bench` server — the `ipc-roundtrip` peer.
//!
//! RFC-0040 gap 2 stage 4. This image exists because the lane's peer used to
//! be a `fork()`ed child of `vsbench`, and a forked child can never be
//! addressed by capability: it inherits no capability table
//! (`sched::process::sys_fork_impl` touches none), and an endpoint's owner is
//! fixed when the capability is SEEDED, by image name. Retiring
//! `SYS_IPC_FAST_CALL` (108) therefore required the peer to become an image.
//!
//! **The loop itself is not written here.** It is
//! `userspace/bench/vsbench/src/serve.rs`, pulled in below, so the client and the
//! server cannot drift into measuring different protocols — which RFC-0045
//! records happening to this lane once already.
//!
//! The bound is the client's own `N_IPC_TOTAL`. It is a backstop: the client
//! ends with an `IPC_SENTINEL` request, and that is what normally stops this.

#![no_std]
#![no_main]

use azos_libsys as sys;

#[path = "../../vsbench/src/ipc_proto.rs"]
mod ipc_proto;
#[path = "../../vsbench/src/serve.rs"]
mod serve;

/// Matches `bench_core::N_IPC_TOTAL`. Not shared through `#[path]` because
/// pulling `bench_core` here would drag the whole harness in; it is a
/// backstop, and the sentinel is the real terminator.
const BOUND: u64 = u64::MAX;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    sys::println(b"[vssrv] endpoint.bench server running");
    serve::serve_loop(BOUND)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::println(b"[vssrv] PANIC");
    sys::exit(101);
}
