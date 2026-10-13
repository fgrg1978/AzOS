// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The capability and IPC cases both kernels must answer alike.
//!
//! This file is compiled twice from this one source: into `captest` (the main
//! kernel's ring-3 test, `main.rs`) and into the micro kernel's `CAPTEST.ELF`
//! task (`micro/src/tasks/captest.rs`, `#[path]`). It names no kernel, no
//! library and no word width: a case is an operation of the frozen ABI
//! (`azos_abi`) issued through [`Env`] with word-sized arguments, and an
//! expectation the ABI fixes. A kernel that answers differently is the bug, on
//! whichever side it lives.
//!
//! Every case needs only what any task holds: nothing is granted by a row. The
//! cases that need a particular grant (a sensor, an endpoint to call) stay
//! with the kernel that declares it.

use azos_abi::cap::{ty, CapHandle, CapPerms};
use azos_abi::error::Errno;

/// What a kernel's ring-3 test provides: the ABI operations the cases use,
/// each returning the result register, and the report of a result.
pub trait Env {
    /// `SYS_CAP_CLOSE(handle)`.
    fn close_typed(&mut self, handle: usize) -> isize;
    /// `SYS_CAP_INFO(kind, resource)`.
    fn cap_lookup(&mut self, kind: usize, resource: usize) -> isize;
    /// `SYS_IPC_FAST_CALL_EP(endpoint, words)`: reply word 0, or the error.
    fn fast_call(&mut self, endpoint: usize, words: [usize; 4]) -> isize;
    /// `SYS_IPC_FAST_REPLY(handle, words)`.
    fn fast_reply(&mut self, handle: usize, words: [usize; 4]) -> isize;
    /// `DOMAIN_UPTIME`: the timebase counter, in a word.
    fn uptime(&mut self) -> usize;
    /// Record one result: `ok` is whether the answer matched.
    fn report(&mut self, name: &[u8], ok: bool, rc: isize);
}

fn errno(e: Errno) -> isize {
    -(e as isize)
}

/// A nonzero handle no table granted: a plausible kind, rights and slot with
/// a generation no slot has reached (generations start at 1 and a forged
/// 8000 is far past any a boot-time grant gave).
fn forged() -> usize {
    CapHandle::pack(ty::ENDPOINT, CapPerms::RW_DUP, 8000, 5).as_raw() as usize
}

/// Run every case; each is reported through `env`.
pub fn run(env: &mut impl Env) {
    // Handles: a handle that names no live slot is stale, whatever else it
    // says; closing is itself checked.
    let rc = env.close_typed(0);
    env.report(b"abi: close_typed(CAP_NULL) -> -ECAPSTALE", rc == errno(Errno::ECAPSTALE), rc);
    let rc = env.close_typed(forged());
    env.report(b"abi: close_typed(forged handle) -> -ECAPSTALE", rc == errno(Errno::ECAPSTALE), rc);

    // Lookup: the caller's own table only, so a kind it was never granted
    // finds nothing, and a kind number the ABI does not define is invalid.
    let rc = env.cap_lookup(ty::TRACE.raw() as usize, 0x0DEA_D000);
    env.report(b"abi: cap_lookup(never granted) -> -ENOENT", rc == errno(Errno::ENOENT), rc);
    let rc = env.cap_lookup(250, 0);
    env.report(b"abi: cap_lookup(undefined kind) -> -EINVAL", rc == errno(Errno::EINVAL), rc);

    // IPC: a call through a capability that does not resolve reaches no one,
    // and the answer does not say why (one code for every reason).
    let rc = env.fast_call(forged(), [1, 2, 3, 4]);
    env.report(b"abi: fast call through a forged endpoint -> -1", rc == -1, rc);
    let rc = env.fast_call(0, [1, 2, 3, 4]);
    env.report(b"abi: fast call through CAP_NULL -> -1", rc == -1, rc);
    // A reply to an exchange that never existed is stale (-2) or refused
    // (-1), never delivered: 0 would mean it reached a caller.
    let rc = env.fast_reply(0x7f00, [1, 2, 3, 4]);
    env.report(b"abi: reply to no exchange is refused", rc == -1 || rc == -2, rc);

    // The clock does not run backwards (the word may wrap on 32 bits, the
    // difference does not).
    let t0 = env.uptime();
    let t1 = env.uptime();
    let dt = t1.wrapping_sub(t0);
    env.report(b"abi: uptime does not run backwards", dt <= usize::MAX / 2, dt as isize);
}
