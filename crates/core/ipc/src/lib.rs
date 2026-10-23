// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

pub mod cap;
pub mod authority_policy;
// The packed (index, generation) resource layout. Declared
// inside `cap.rs`; re-exported so it is also `azos_ipc::objref`.
pub use cap::objref;
pub mod cap_store;
pub mod kpipe;
pub mod io_ring;
pub mod port;
// The link a bound io_ring keeps to its port (wave 11, PORTWAIT).
pub mod port_link;
pub mod trace;
pub mod irq_bind;
pub mod memobj;
// Kconfig INSPECT: how a task obtains the introspection regions.
pub mod inspect_region;
pub mod kregion;
pub mod ep_queue;
pub mod fastcall;
pub mod endpoint;
// `zerocopy.rs` deleted (U04-7, owner-directed 2026-09-26): 628 lines, a
// 2 MiB `static mut BUF_POOL`, no caller anywhere in the tree
// (`pipeline_acquire`/`_submit`/`_receive` matched only this module's own
// re-export) and a double-free class the shm holder-count fix (`memobj.rs`)
// already closed for the primitive that IS used. The MemObj path (shared
// regions, MOVE/SHARE through an endpoint) is the tree's zero-copy primitive.

// W5 batch 5 — typed hardware caps. Live here (not in
// crates/drivers/*) because `drivers → ipc` would create a Cargo
// cycle; `ipc → drivers` already exists.
pub mod drvreg_cap;
pub mod mmio_cap;
// `Cap<Device>` over a range of I/O ports (x86_64's port space).
pub mod ioport_cap;
// Wave 10: `Cap<File>` naming a directory tree, the authority for the calls
// that change the tree (mkdir, unlink, rmdir, rename, truncate).
pub mod file_cap;
// Wave 11: `Cap<Launch>`, the right to start one image with
// `SYS_SPAWN_EX`, seeded from the topology word `"launch"`.
pub mod launch_cap;

// P1 — topology → cap_store bridge (migration). See its
// module doc for the ordering contract and why it lives here rather than in
// `crates/core/topology` or `kernel/src/`.
pub mod cap_seed;

pub use io_ring::{
    IoRing, IoRingState, IoRingOps, SqEntry, CqEntry,
    io_ring_create, io_ring_destroy, io_ring_owner,
    io_ring_submit, io_ring_register_ops, IO_ERR_PERM,
    io_ring_release_all,
    MAX_IO_RINGS, RING_SQ_SIZE, RING_CQ_SIZE, RING_DATA_BUF_SIZE,
    OP_NOP, OP_READ_SENSOR, OP_WRITE_GPIO, OP_READ_GPIO,
    OP_I2C_READ, OP_I2C_WRITE, OP_PWM_SET, OP_MOTOR_SPEED,
    OP_NET_SEND, OP_NET_RECV,
    IO_OK, IO_ERR_INVALID_OP, IO_ERR_INVALID_PARAM, IO_ERR_NO_OPS,
};

pub use port::{
    Port, PortSource, PortSourceKind, PortEvent,
    port_create, port_destroy, port_bind, port_poll, port_has_events,
    port_queue_event, port_owner, port_release_all,
    MAX_PORTS, PORT_MAX_SOURCES,
};

pub use trace::{
    trace_event, trace_dump, trace_total,
    TRACE_IRQ, TRACE_SCHED, TRACE_SYSCALL, TRACE_FAULT, TRACE_SIGNAL,
};

pub use irq_bind::{
    IrqBinding,
    irq_bind_port, irq_unbind, irq_unbind_all, irq_dispatch, irq_msi_dispatch,
    MAX_IRQ_BINDINGS,
};

pub use memobj::{
    MemObj, MemPerms, MemHolder,
    memobj_create, memobj_release, memobj_info,
    memobj_owner, memobj_has_mapping, memobj_take_mapping,
    memobj_release_all,
    MAX_MEMOBJS, MAX_MEMOBJ_PAGES, MAX_MEMOBJ_HOLDERS,
};

pub use fastcall::{FastIpcReply, FastIpcWait};

// ---------------------------------------------------------------------------
// Task-exit resource reclamation (W3-F7)
// ---------------------------------------------------------------------------

/// Release **every** per-task resource `tid` holds. This is the function the
/// scheduler's task-exit hook must call.
///
/// **WHY it exists (W3-F7):** the exit hook registered in `kernel/src/boot/sched.rs`
/// was `handle_revoke_all`, which cleans only the *legacy* global handle
/// table. Two other per-task resource classes were never reclaimed:
///
///  * **Typed caps.** `cap_store`'s own module doc claimed `task_exit` calls
///    `cap_store::reset`; it had zero callers anywhere in the tree. That was
///    harmless only while `CAP_TABLES` was TID-indexed and TIDs were monotone
///    (nothing could ever collide). W3-F4 makes those tables *pool-slot*
///    indexed, and pool slots are recycled — so from that change on, an
///    un-reset table is a live inheritance path from a dead task to the next
///    occupant of its slot. F4 and F7 are one fix, not two.
///  * **Shared-memory references.** W3-F1 books shm references per task, so a
///    task that dies holding one pins the region — and its physical pages —
///    for the life of the board unless the exit path gives them back.
///
/// Ordering: the hook fires from `scheduler::task_exit` *before* the task is
/// marked `Zombie` and long before `do_schedule` frees its pool slot, so
/// `idx_for_tid(tid)` still resolves and `cap_store::reset` lands on the
/// right slot. See `cap_store::reset` for what breaks if that ever changes.
pub fn task_release_all(tid: u32) {
    release_all(tid, false)
}

/// [`task_release_all`] for a task the M4 supervisor is restarting:
/// identical, in the same order, except that the named endpoints
/// it served survive it, unclaimed, for its successor to re-claim
/// ([`endpoint::endpoint_orphan_all`]). Every other resource — capabilities
/// included — is released: the successor is a new task and gets its own
/// grants from the topology, as the first one did.
pub fn task_release_all_supervised(tid: u32) {
    release_all(tid, true)
}

fn release_all(tid: u32, keep_named_endpoints: bool) {
    // ── The order below is load-bearing. Read this before changing it. ──
    //
    // 1. Silence anything that can still *deliver into* this task's resources
    //    before those resources are recycled.
    // 2. Revoke authority.
    // 3. Give the resources back, waking anyone left blocked on them.
    //
    // IRQ bindings go first for a concrete reason: `irq_dispatch` calls
    // `port_queue_event` from IRQ context, and `port_release_all` below makes
    // the freed port ids immediately reusable. Freeing the ports while a
    // binding still points at them means an interrupt belonging to a dead task
    // gets delivered into the port of a live one — the same class of bug as
    // IPC-3 itself, only harder to see because it needs a device to fire.
    irq_bind::irq_unbind_all(tid);

    // Typed Cap<T> table for this task's pool slot.
    cap_store::reset(tid);
    // Shared-memory references booked against this task.
    memobj::memobj_release_all(tid);
    // Event ports owned by this task (safe now that its IRQ bindings are gone).
    port::port_release_all(tid);
    // IO rings owned by this task. A ring caught mid-pass (a submit on another
    // hart) is marked orphaned rather than freed, and its page is handed back at the
    // end of that pass — see `io_ring::io_ring_release_all`.
    io_ring::io_ring_release_all(tid);
    // Fast-IPC slots this task owns as caller or as server (IPC-3).
    //
    // **WHY it is safe for this to re-enter the scheduler.** It wakes tasks
    // left blocked on a resource whose other end just died — without that, an
    // orphaned fast-IPC client sleeps for the life of the board. That only works because
    // `scheduler::task_exit` invokes this hook *before* it takes `PoolGuard`
    // and the runqueue lock. Reorder that block and the exit path deadlocks
    // against itself, with no warning and no test to catch it.
    //
    // **WHY the leak mattered more than it looks.** A client left blocked on
    // a call whose server died sleeps forever, and a server's endpoint that
    // is not released keeps its pool slot, so the *optimized* path this kernel
    // exists to provide degrades silently without a single test failing.
    fastcall::release_all(tid);
    // Fast-IPC endpoints this task served. The pool is 32
    // machine-wide, so a service that exits without this keeps its slots until
    // reboot — a slow exhaustion, and a silent one.
    //
    // It wakes nobody, so its place in this order is free: a `Cap<Endpoint>`
    // another task still holds is not walked here. It goes stale on its own,
    // because the generation packed into that reference no longer matches the
    // freed slot. Walking every table instead would need a cap-table lock
    // while `ENDPOINTS` is held, which is the lock-order question this avoids.
    if keep_named_endpoints {
        let _ = endpoint::endpoint_orphan_all(tid);
    } else {
        endpoint::endpoint_release_all(tid);
    }
}

// ---------------------------------------------------------------------------
// Fork-time bootstrap capability grant
// ---------------------------------------------------------------------------

/// Grant `child_tid` a capability to every endpoint `parent_tid` itself owns
/// — the single relation the owner's fork-inheritance design mints. See
/// [`endpoint::endpoint_inherit_at_fork`] for the relation itself (not
/// capability CLASS, `owner_tid == parent_tid`) and why the scan is over the
/// fixed `ENDPOINTS` pool rather than the parent's cap table.
///
/// This is `crates/core/sched`'s `TASK_FORK_HOOK` callback — the fork-time mirror
/// of [`task_release_all`]'s `TASK_EXIT_HOOK`, registered the same way and
/// for the same reason: `crates/core/ipc` depends on `crates/core/sched`, so `sched`
/// cannot call into `ipc` directly. `kernel/src/boot/sched.rs`'s
/// `install_sched_hooks` registers this alongside `set_task_exit_hook`.
///
/// Called from `sys_fork_impl`, still running as the PARENT (no context
/// switch has happened), so `parent_tid` is exactly `current_task_tid()` at
/// the call site and needs no lookup. Fires before `set_task_fork_ctx`
/// publishes the child's entry point, so the grant is visible in the
/// child's own cap table before the child ever runs a single user
/// instruction — no window in which the child could observe its own empty
/// table and miss the inheritance.
///
/// Only ever adds capabilities, into free slots, after the fork's own setup
/// of the child (wave 13: a native child's inherited descriptors at the
/// parent's handles and its row's capabilities, `azos_syscall::natfork`;
/// a Linux child's row) into a table that started the fork with none
/// (`try_task_create_affinity` allocates a fresh pool slot, and a fresh or
/// reused slot's `CapTable` is wiped — see `cap_store`'s module doc on slot
/// reuse), so there is nothing here to revoke on a normal path. Clearing on
/// exit is [`task_release_all`]'s existing `cap_store::reset(tid)` call —
/// unchanged by this addition, and what makes a re-let slot safe: a new
/// occupant's table is wiped before this function, or anything else, can
/// grant into it again.
pub fn task_fork_grant(parent_tid: u32, child_tid: u32) {
    endpoint::endpoint_inherit_at_fork(parent_tid, child_tid);
}
