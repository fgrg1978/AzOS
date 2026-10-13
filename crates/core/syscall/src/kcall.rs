// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel as a caller of an endpoint a task serves (Phase 4 elasticity).
//!
//! A kernel component that needs a driver which may run in ring 3 calls it
//! with the same generated stub a ring-3 client uses: `<Name>Client` over
//! [`KernelEndpoint`], the [`azos_idl::Transport`] of a kernel task. The call
//! is `SYS_IPC_CALL_V2`'s own body (`crate::ipc_v2::call_v2`) on a request in
//! kernel memory, so the capability check, the deadline refusal, the call
//! queue, the priority donation and the wait are the syscall's, not a second
//! path. When the driver is placed in the kernel the caller holds the direct
//! stub instead and no message exists; `<Name>Placed` is the value that is
//! either.
//!
//! # The rule: never under a spinlock
//!
//! The call blocks until the server answers, for as long as the server takes.
//! A spinlock held across it holds every other CPU that wants the lock for
//! that long, which is the bound `azos_sync::preempt`'s critical sections
//! exist to keep short. `cap_store::with_table` runs its closure under the
//! task's capability-table lock, so a call from inside that closure would
//! hold the table for a ring-3 round trip. [`call`] therefore refuses, without
//! queueing anything, whenever the running context may not block
//! (`azos_sync::preempt::may_block`: a spinlock held, interrupts masked) and
//! counts the refusal ([`atomic_refusals`]). The refusal is `-EBUSY`, which the
//! stub reports as a transport failure; nothing was sent.
//!
//! # Authority
//!
//! The calling task needs a `WRITE` capability on the endpoint in its own
//! table, as any caller does. [`endpoint_handle`] gives the running kernel task
//! one, minted by the kernel from the endpoint's name (the endpoint is
//! declared by the signed topology row that serves it); a kernel component's
//! authority to call a driver it is compiled to use is not something a row can
//! grant, but the capability is still the only way in, so containment
//! (RFC-0036) refuses the acting call here as it does for ring 3.

use core::sync::atomic::{AtomicU32, Ordering};

use azos_abi::cap::{ty, CapPerms};
use azos_abi::error::Errno;
use azos_abi::ipc_msg::MsgDesc;
use azos_idl::{IdlError, Result as IdlResult, Transport};

/// Calls refused because the caller could not block.
static ATOMIC_REFUSED: AtomicU32 = AtomicU32::new(0);

/// How many calls [`call`] has refused for want of a context that may block.
pub fn atomic_refusals() -> u32 {
    ATOMIC_REFUSED.load(Ordering::Relaxed)
}

/// May the running context call? Gate canary `kcall-atomic-canary` (never in
/// a real build): always, so a call from inside `with_table` goes through and
/// the ktest `kernel_endpoint_call_is_refused_under_a_spinlock` goes red.
#[inline]
fn may_call() -> bool {
    cfg!(feature = "kcall-atomic-canary") || azos_sync::preempt::may_block()
}

/// Call through the endpoint capability `ep` (a handle in the running task's
/// table) with the request in `*msg`; the answer replaces it. `Err` is the
/// call's negative code (`-EBUSY` when the context may not block, else
/// `SYS_IPC_CALL_V2`'s).
pub fn call(ep: u32, msg: &mut MsgDesc) -> Result<(), i64> {
    if !may_call() {
        ATOMIC_REFUSED.fetch_add(1, Ordering::Relaxed);
        return Err(Errno::EBUSY.to_syscall_ret());
    }
    let req = *msg;
    match crate::ipc_v2::call_v2(ep as u64, &req, msg) {
        0 => Ok(()),
        e => Err(e),
    }
}

/// The transport of a kernel task's capability on a task-served endpoint:
/// `BuzzerClient::new(KernelEndpoint(h))`, as `BuzzerClient::new(Ep(h))` in
/// ring 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelEndpoint(pub u32);

impl Transport for KernelEndpoint {
    fn call(&self, msg: &mut MsgDesc) -> IdlResult {
        call(self.0, msg).map_err(|e| IdlError::Transport(e as isize))
    }
}

/// The running task's handle on the endpoint called `name` with `WRITE`:
/// the one it holds, else a new one the kernel mints (the endpoint is created
/// unclaimed if no server has started yet, and a call then fails until one
/// claims it). `None` when the name does not fit or a table is full. Must not
/// be called with a cap-table lock held.
pub fn endpoint_handle(name: &[u8]) -> Option<u32> {
    let tid = azos_sched::current_task_tid();
    if let Some(r) = azos_ipc::endpoint::endpoint_ref_by_name(name) {
        let held = azos_ipc::cap_store::read_table(tid, |t| {
            t.lookup_where(ty::ENDPOINT, |res, _, perms| res == r && perms.contains(CapPerms::WRITE))
        })
        .flatten();
        if let Some(h) = held {
            return Some(h.0);
        }
    }
    azos_ipc::endpoint::endpoint_named_cap(tid, CapPerms::WRITE, name).map(|c| c.raw().0)
}
