// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! IPC syscall handlers: the `Cap<Port>`, `Cap<Shm>` and
//! `Cap<IoRing>` typed calls. The untyped channel, shared-memory, port and
//! io_ring calls by index are retired (RFC-0040 gap 1).
//!
//! Moved out of `handlers.rs`, so that work on the IPC ABI and work on hardware
//! authority edit different files. `dispatch.rs` and the host tests import this
//! module directly. Helpers shared with the other handlers stay in
//! `handlers.rs`.

use azos_abi::cap::{ty, CapType};
use crate::handlers::note_typed_denial;

// ── Cap<Port> typed handlers — RFC-0003 W5 ────────────────────────────────

pub(crate) fn errno_for_port_err(e: azos_ipc::port::PortCapError) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::CapError;
    use azos_ipc::port::PortCapError;
    // Every typed refusal in this file reaches the recorder here — the one
    // choke point all twelve of these functions share. `Contained` is filtered
    // inside `note_typed_denial`, not here.
    if let PortCapError::Cap(c) = e {
        note_typed_denial(azos_abi::cap::ty::PORT, c);
    }
    match e {
        PortCapError::Cap(CapError::Stale | CapError::Revoked) => Errno::ECAPSTALE.to_syscall_ret(),
        PortCapError::Cap(CapError::WrongKind) => Errno::ECAPKIND.to_syscall_ret(),
        PortCapError::Cap(CapError::MissingPerms) => Errno::ECAPPERMS.to_syscall_ret(),
        PortCapError::Cap(CapError::Contained) => Errno::EAGAIN.to_syscall_ret(),
        PortCapError::Cap(CapError::NoSpace) => Errno::EMFILE.to_syscall_ret(),
        PortCapError::Full => Errno::EMFILE.to_syscall_ret(),
        PortCapError::Empty => Errno::EAGAIN.to_syscall_ret(),
        PortCapError::Closed => Errno::EBADF.to_syscall_ret(),
        PortCapError::Refused => Errno::EBUSY.to_syscall_ret(),
    }
}

/// `DOMAIN_CREATE_PORT`: no args. Allocates a port + grants
/// a `Cap<Port>` into the calling task's cap-table. Returns the raw
/// cap handle as `i64` (always > 0) on success, or `-Errno`.
pub fn sys_port_create_typed() -> i64 {
    use azos_abi::error::Errno;
    // Wave 15 (plan 4a): booked to the process, not the creating thread,
    // so it outlives the thread (`port_release_all` at the process's exit).
    let tid = if cfg!(feature = "thread-objects-canary") {
        azos_sched::current_task_tid()
    } else {
        azos_sched::current_proc_tid()
    };
    match azos_ipc::port::port_create_cap(tid) {
        Some(cap) => cap.raw().as_raw() as i64,
        None => Errno::EMFILE.to_syscall_ret(),
    }
}

/// `DOMAIN_CREATE_ENDPOINT`: no arguments.
///
/// Creates an endpoint owned by the caller and mints its `Cap<Endpoint>` into
/// the caller's own table with `RW` — `READ` is what lets it accept, `WRITE`
/// what lets it (or whoever it moves the capability to) call.
///
/// Returns the handle, or `-EMFILE`. The endpoint pool is machine-wide and
/// bounded; `endpoint_create_cap` destroys the endpoint if the grant fails, so
/// a full capability table cannot leak a pool slot.
pub fn sys_endpoint_create_typed() -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::CapPerms;
    let tid = azos_sched::current_task_tid();
    match azos_ipc::endpoint::endpoint_create_cap(tid, CapPerms::RW) {
        Some(cap) => cap.raw().as_raw() as i64,
        None => Errno::EMFILE.to_syscall_ret(),
    }
}

/// `PORT_POLL`: a0=cap_handle, a1=out_ptr. Copies a
/// 16-byte `PortEvent` (key, source_type, source_id + padding) to
/// `out_ptr` on success. Returns 16 on success, -EAGAIN if empty, or
/// -Errno on cap / arg failure.
pub fn sys_port_poll_typed(cap_raw: u64, out_ptr: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Port, Cap};

    if out_ptr == 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    // U07-2: validated BEFORE `port_poll_cap`, which DEQUEUES the event on
    // success — the same order `sys_port_wait_typed` (577) already uses.
    // Without this, a bad `out_ptr` discovered only after the dequeue loses
    // the event: the caller gets `-EFAULT` and the port never re-delivers it.
    if azos_sched::current_user_pt() != 0
        && !azos_sched::user_range_prepare_write(out_ptr as usize, PORT_EVENT_OUT_BYTES)
    {
        return Errno::EFAULT.to_syscall_ret();
    }
    let cap: Cap<Port> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let now_ns = port_now_ns();
    let result = azos_ipc::cap_store::with_table(tid, |table| {
        azos_ipc::port::port_poll_cap_at(table, cap, now_ns)
    });
    match result {
        Some(Ok(event)) => copy_port_event_out(out_ptr, &event),
        Some(Err(e)) => errno_for_port_err(e),
        None => Errno::EINVAL.to_syscall_ret(),
    }
}

/// Width of the `PortEvent` blob `PORT_POLL` and
/// `SYS_PORT_WAIT` write.
const PORT_EVENT_OUT_BYTES: usize = 16;

/// Write `event` through `out_ptr` in the 16-byte ABI-stable encoding (key:u64,
/// source_type:u8, _pad:u8, code:u16, source_id:u32, little-endian) and return 16, or
/// `-EFAULT`. Shared by 531 and 577.
fn copy_port_event_out(out_ptr: u64, event: &azos_ipc::port::PortEvent) -> i64 {
    use azos_abi::error::Errno;
    let mut buf = [0u8; PORT_EVENT_OUT_BYTES];
    buf[..8].copy_from_slice(&event.key.to_le_bytes());
    buf[8] = event.source_type;
    let c = azos_abi::syscall_nr::PORT_EVENT_CODE_OFFSET;
    buf[c..c + 2].copy_from_slice(&event.code.to_le_bytes());
    buf[12..16].copy_from_slice(&event.source_id.to_le_bytes());
    if azos_sched::current_user_pt() != 0 {
        if !azos_sched::copy_to_user(out_ptr as usize, buf.as_ptr(), PORT_EVENT_OUT_BYTES) {
            return Errno::EFAULT.to_syscall_ret();
        }
    } else {
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), out_ptr as *mut u8, PORT_EVENT_OUT_BYTES);
        }
    }
    PORT_EVENT_OUT_BYTES as i64
}

/// `PORT_DESTROY`: a0=cap_handle. Frees the port slot
/// **and revokes the cap** (W3-F5) — see `port::port_destroy_cap` for why
/// leaving it live was a confused-deputy path onto the next task that gets
/// the recycled port id.
pub fn sys_port_destroy_typed(cap_raw: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Port, Cap};

    let cap: Cap<Port> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let result = azos_ipc::cap_store::with_table(tid, |table| {
        azos_ipc::port::port_destroy_cap(table, cap)
    });
    match result {
        Some(Ok(())) => 0,
        Some(Err(e)) => errno_for_port_err(e),
        None => Errno::EINVAL.to_syscall_ret(),
    }
}

/// Port source types in `SYS_PORT_BIND`'s (512) encoding, which 575 keeps.
use azos_abi::syscall_nr::{PORT_SRC_ENDPOINT, PORT_SRC_RING, PORT_SRC_TIMER};

/// The time counter in nanoseconds: the clock a port's timer sources and
/// 604's deadline are read against (`SYS_SLEEP_UNTIL`'s unit).
fn port_now_ns() -> u64 {
    azos_abi::time::ticks_to_ns(
        azos_drv_sys::timebase::now(),
        azos_drv_sys::timebase::TIMER_FREQ,
    )
}

/// The reason a port waiter blocks on: `Port(r)` with no deadline,
/// `Timer(ticks)` until `until_ns` otherwise (rounded up to a tick, so it is
/// never reached early). The registration made the same choice
/// (`port::PortWaitStart::Registered::until`), so the wake matches it.
fn port_block_reason(r: u32, until_ns: Option<u64>) -> azos_sched::WaitReason {
    match until_ns {
        None => azos_sched::WaitReason::Port(r),
        Some(ns) => azos_sched::WaitReason::Timer(azos_abi::time::ns_to_ticks_ceil(
            ns,
            azos_drv_sys::timebase::TIMER_FREQ,
        )),
    }
}

/// A source capability's refusal, recorded under its own kind.
fn errno_for_source_cap(kind: azos_abi::cap::CapType, e: azos_ipc::cap::CapError) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::CapError;
    note_typed_denial(kind, e);
    match e {
        CapError::Stale | CapError::Revoked => Errno::ECAPSTALE.to_syscall_ret(),
        CapError::WrongKind => Errno::ECAPKIND.to_syscall_ret(),
        CapError::MissingPerms => Errno::ECAPPERMS.to_syscall_ret(),
        CapError::Contained => Errno::EAGAIN.to_syscall_ret(),
        CapError::NoSpace => Errno::EMFILE.to_syscall_ret(),
    }
}

/// Bind an io_ring or endpoint (`kind`) to port `r`: the port's slot first
/// (`port_bind_object`), then the object's link (`set_link`, the object's own
/// lock). A link to another port is replaced only when that port no longer
/// answers to it (`port_link_valid`); a live one answers `-EBUSY`. On any
/// refusal after the slot was added the slot is freed again. When the object
/// already had something to report under the hold that stored the link, the
/// port is signalled once here, so a message sent before the bind is not
/// missed.
///
/// **Tied to the capability (wave 11, LEASE3).** The source records the
/// binder's cap-table slot, so revoking the capability (or the binder's exit)
/// removes it and moving it carries it along (`port::port_cap_event`). The
/// capability was resolved in an earlier hold, so `still_held` re-reads it
/// after the source is stored: a revoke or move in between found no source to
/// act on, and the bind is undone with `-ECAPSTALE`.
fn bind_object(
    r: u32,
    kind: azos_ipc::port::PortSourceKind,
    handle: u32,
    key: u64,
    binder: Option<usize>,
    still_held: impl Fn() -> bool,
    set_link: impl Fn(azos_ipc::port::PortLink, azos_ipc::port::PortLink)
        -> Result<azos_ipc::port_link::LinkSet, i64>,
) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::port::{self, PortLink};
    use azos_ipc::port_link::LinkSet;
    let (link, added) = match port::port_bind_object_as(r, kind, handle, key, binder) {
        Ok(v) => v,
        Err(e) => return errno_for_port_err(e),
    };
    if !still_held() {
        if added {
            port::port_unbind_link(link, kind);
        }
        return Errno::ECAPSTALE.to_syscall_ret();
    }
    let mut replace = PortLink::NONE;
    for _ in 0..2 {
        match set_link(link, replace) {
            Ok(LinkSet::Stored { ready }) => {
                if ready {
                    let _ = port::port_signal(link, kind);
                }
                return 0;
            }
            Ok(LinkSet::Busy(cur)) => {
                if port::port_link_valid(cur, kind) {
                    break;
                }
                replace = cur;
            }
            Err(errno) => {
                if added {
                    port::port_unbind_link(link, kind);
                }
                return errno;
            }
        }
    }
    if added {
        port::port_unbind_link(link, kind);
    }
    Errno::EBUSY.to_syscall_ret()
}

/// `PORT_BIND`: a0=port cap (`Cap<Port>`), a1=source type
/// (0 channel, 1 ring, 2 IRQ, 3 timer, 4 endpoint) or-ed with `PORT_BIND_F_REMOVE`,
/// a2=source, a3=key. Binds (or removes) a source and returns 0, or `-Errno`.
///
/// The typed form of `SYS_PORT_BIND`. The port capability needs `WRITE`
/// and resolves with `get`, so while containment is armed a bind answers
/// `-EAGAIN` (a bind adds a source; the destroy, a release, stays live). The
/// source, by type, with the capability the caller must hold for it, resolved
/// in the same hold of the caller's table as the port's:
/// - 1: a `Cap<IoRing>` with `READ` (`bind_object`, `io_ring_set_link`);
/// - 2: a timer, `a2` its absolute deadline in nanoseconds on the time
///   counter; no capability (`port_arm_timer`; a known key re-arms);
/// - 3: an endpoint's notices: a `Cap<Endpoint>` with `READ`, and the caller
///   must serve it (`bind_object`, `endpoint_set_link`, `-EPERM` otherwise);
///   reports no-senders (wave 15 N5b).
///
/// An interrupt line is bound to a port from the line's side
/// (`DEVICE_IRQ_BIND`), not from the port's.
///
/// With `PORT_BIND_F_REMOVE`, the ring or timer sources of that type bound
/// with key `a3` are removed (`port_unbind_key`) and each ring's link cleared;
/// `-ENOENT` when none was bound.
///
/// In order:
/// - `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS` / `-EAGAIN` for the port
///   capability, recorded under `Port`;
/// - `-EINVAL` for a source type above 3 or 0, or an unknown flag bit;
/// - `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS` for the source capability,
///   recorded under its own kind;
/// - `-ECAPSTALE` when the port (or the ring) was destroyed before the
///   binding was stored;
/// - `-EMFILE` when the port's source table is full;
/// - `-EPERM` when the caller does not serve the endpoint;
/// - `-EBUSY` when the ring or endpoint already reports to another live port.
pub fn sys_port_bind_typed(port_raw: u64, source_type: u64, source: u64, key: u64) -> i64 {
    use azos_abi::cap::{CapHandle, CapPerms};
    use azos_abi::error::Errno;
    use azos_abi::syscall_nr::PORT_BIND_F_REMOVE;
    use azos_ipc::cap::{targets::{Endpoint, IoRing, Port}, Cap, CapError};
    use azos_ipc::port::{self, PortCapError, PortSourceKind};

    enum Refusal {
        Port(CapError),
        Source(CapType, CapError),
        Errno(Errno),
    }
    enum Source {
        Ring(u32),
        Endpoint(u32),
        Timer(u64),
        Remove(u8),
    }
    let flags = source_type & !0xFF;
    let ty = source_type & 0xFF;
    let port: Cap<Port> = Cap::from_raw(CapHandle::from_raw(port_raw as u32));
    let handle = CapHandle::from_raw(source as u32);
    let tid = azos_sched::current_task_tid();
    let resolved = azos_ipc::cap_store::with_table(tid, |table| {
        let r = table.get(port, CapPerms::WRITE).map_err(Refusal::Port)?;
        // Kconfig IPC_PORT_NOTICES off: no count is kept, so an endpoint
        // source would report "no senders" falsely; it is not a source then.
        let top = if azos_limits::IPC_PORT_NOTICES { PORT_SRC_ENDPOINT } else { PORT_SRC_TIMER };
        // Type 0 was the channel; no source has it now.
        if ty == 0 || ty > top || flags & !PORT_BIND_F_REMOVE != 0 {
            return Err(Refusal::Errno(Errno::EINVAL));
        }
        if flags != 0 {
            let ev = match ty {
                PORT_SRC_RING => port::PORT_EVENT_RING,
                PORT_SRC_TIMER => port::PORT_EVENT_TIMER,
                PORT_SRC_ENDPOINT => port::PORT_EVENT_NO_SENDERS,
                _ => return Err(Refusal::Errno(Errno::EINVAL)),
            };
            return Ok((r, Source::Remove(ev)));
        }
        let src = match ty {
            PORT_SRC_RING => {
                let c: Cap<IoRing> = Cap::from_raw(handle);
                Source::Ring(table.get(c, CapPerms::READ).map_err(|e| Refusal::Source(ty::IORING, e))?)
            }
            PORT_SRC_ENDPOINT => {
                let c: Cap<Endpoint> = Cap::from_raw(handle);
                Source::Endpoint(table.get(c, CapPerms::READ).map_err(|e| Refusal::Source(ty::ENDPOINT, e))?)
            }
            _ => Source::Timer(source),
        };
        Ok((r, src))
    });
    let binder = azos_ipc::cap_store::table_slot(tid);
    let (r, src) = match resolved {
        Some(Ok(v)) => v,
        Some(Err(Refusal::Port(e))) => return errno_for_port_err(PortCapError::Cap(e)),
        Some(Err(Refusal::Source(kind, e))) => return errno_for_source_cap(kind, e),
        Some(Err(Refusal::Errno(e))) => return e.to_syscall_ret(),
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    match src {
        // The gate canary: the bind answers 0 and no timer is armed.
        #[cfg(feature = "portwait-timer-canary")]
        Source::Timer(deadline_ns) => {
            let _ = deadline_ns;
            0
        }
        #[cfg(not(feature = "portwait-timer-canary"))]
        Source::Timer(deadline_ns) => match port::port_arm_timer(r, key, deadline_ns) {
            Ok(()) => 0,
            Err(e) => errno_for_port_err(e),
        },
        Source::Ring(g) => {
            let held = || azos_ipc::cap_store::with_table(tid, |t| {
                t.get(Cap::<IoRing>::from_raw(handle), CapPerms::READ) == Ok(g)
            }) == Some(true);
            bind_object(r, PortSourceKind::Ring(g), source as u32, key, binder, held, |link, replace| {
                azos_ipc::io_ring::io_ring_set_link(g, link, replace).map_err(errno_for_ioring_err)
            })
        }
        Source::Endpoint(e) => {
            let held = || azos_ipc::cap_store::with_table(tid, |t| {
                t.get(Cap::<Endpoint>::from_raw(handle), CapPerms::READ) == Ok(e)
            }) == Some(true);
            bind_object(r, PortSourceKind::Endpoint(e), source as u32, key, binder, held, |link, replace| {
                azos_ipc::endpoint::endpoint_set_link(e, tid, link, replace).map_err(|err| match err {
                    azos_ipc::endpoint::EndpointCapError::NotOwner => Errno::EPERM.to_syscall_ret(),
                    _ => Errno::ECAPSTALE.to_syscall_ret(),
                })
            })
        }
        Source::Remove(ev) => {
            let gone = match port::port_unbind_key(r, ev, key) {
                Ok(g) => g,
                Err(e) => return errno_for_port_err(e),
            };
            for &(kind, link) in &gone.items[..gone.n] {
                match kind {
                    PortSourceKind::Ring(g) => azos_ipc::io_ring::io_ring_clear_link(g, link),
                    PortSourceKind::Endpoint(e) => azos_ipc::endpoint::endpoint_clear_link(e, link),
                    _ => {}
                }
            }
            if gone.n == 0 { Errno::ENOENT.to_syscall_ret() } else { 0 }
        }
    }
}

/// `SYS_PORT_WAIT`: a0=cap (`Cap<Port>`), a1=out_ptr,
/// a2=deadline (absolute nanoseconds on the time counter; `u64::MAX` none; a
/// passed instant polls). The multi-source wait with a deadline (RFC-0052
/// §6.3): returns 16 with the event written, 0 when the
/// deadline passed with nothing ready (nothing written), or `-Errno`.
///
/// The checks and their order are: the buffer, the capability, the buffer's mapping. The wait is
/// `port::port_wait_until_ref`: take an event or register in one `PORTS` hold,
/// then block — on `WaitReason::Port(reference)` with no deadline and no armed
/// timer source, on `WaitReason::Timer` until the earlier of the two otherwise
/// — and take an event in the hold that deregisters. Turns are not counted:
/// the deadline bounds them. A block the scheduler refuses (K-C29) that
/// brings nothing answers `-EBUSY` at once, as `DOMAIN_NOTIFY_WAIT` does, instead
/// of spinning to the deadline.
pub fn sys_port_wait(cap_raw: u64, out_ptr: u64, deadline_ns: u64) -> i64 {
    use azos_abi::cap::{CapHandle, CapPerms};
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Port, Cap};
    use azos_ipc::port::PortCapError;
    use azos_sched::{task_block_killable, BlockOutcome};

    if out_ptr == 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let cap: Cap<Port> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let r = match azos_ipc::cap_store::with_table(tid, |table| table.get(cap, CapPerms::READ)) {
        Some(Ok(r)) => r,
        Some(Err(e)) => return errno_for_port_err(PortCapError::Cap(e)),
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    if azos_sched::current_user_pt() != 0
        && !azos_sched::user_range_prepare_write(out_ptr as usize, PORT_EVENT_OUT_BYTES)
    {
        return Errno::EFAULT.to_syscall_ret();
    }
    let waited = azos_ipc::port::port_wait_until_ref(r, tid, deadline_ns, port_now_ns, |until| {
        task_block_killable(port_block_reason(r, until)) == BlockOutcome::Refused
    });
    match waited {
        Ok(Some(event)) => copy_port_event_out(out_ptr, &event),
        Ok(None) => 0,
        Err(e) => errno_for_port_err(e),
    }
}

// ── Cap<Shm> typed handlers — RFC-0003 W5 batch 2 ─────────────────────────

/// `shm_acquire_typed` out-blob layout: 8 bytes total.
/// `[0..4] page_count u32 LE, [4] perms u8 (0=RO,1=RW), [5..8] pad`.
const SHM_ACQUIRE_OUT_BYTES: usize = 8;

pub(crate) fn errno_for_memobj_err(e: azos_ipc::memobj::MemObjError) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::CapError;
    use azos_ipc::memobj::MemObjError;
    // Every typed refusal in this file reaches the recorder here — the one
    // choke point all twelve of these functions share. `Contained` is filtered
    // inside `note_typed_denial`, not here.
    if let MemObjError::Cap(c) = e {
        note_typed_denial(azos_abi::cap::ty::SHM, c);
    }
    match e {
        MemObjError::Cap(CapError::Stale | CapError::Revoked) => Errno::ECAPSTALE.to_syscall_ret(),
        MemObjError::Cap(CapError::WrongKind) => Errno::ECAPKIND.to_syscall_ret(),
        MemObjError::Cap(CapError::MissingPerms) => Errno::ECAPPERMS.to_syscall_ret(),
        MemObjError::Cap(CapError::Contained) => Errno::EAGAIN.to_syscall_ret(),
        MemObjError::Cap(CapError::NoSpace) => Errno::EMFILE.to_syscall_ret(),
        MemObjError::NoMem => Errno::ENOMEM.to_syscall_ret(),
        MemObjError::BadArg => Errno::EINVAL.to_syscall_ret(),
        MemObjError::Closed => Errno::EBADF.to_syscall_ret(),
        MemObjError::Full => Errno::EMFILE.to_syscall_ret(),
        MemObjError::Busy => Errno::EBUSY.to_syscall_ret(),
    }
}

/// The creation word of `SYS_MO_CREATE` (`azos_abi::syscall_nr`), decoded.
struct ShmCreate {
    spec: azos_ipc::memobj::MemSpec,
    /// `Some(handle)`: snapshot the object that capability names.
    clone_of: Option<u32>,
}

/// `None` for a reserved or unknown field: a kind other than Anon (ring 3
/// creates Anon; Contig and Phys are the kernel's, Paged is reserved), an
/// attribute the kernel does not know or [`SHM_ATTR_VOLATILE`], a source
/// capability without the clone bit, or any other bit.
fn decode_shm_create(raw: u64) -> Option<ShmCreate> {
    use azos_abi::syscall_nr::*;
    use azos_ipc::memobj::{MemPerms, MemSpec, ATTR_NO_KERNEL_MAP, ATTR_SWAPPABLE};
    let perms = match raw & 0x3 {
        0 => MemPerms::ReadOnly,
        1 => MemPerms::ReadWrite,
        _ => return None,
    };
    let kind = (raw >> SHM_CREATE_KIND_SHIFT) & 0xFF;
    let attrs = (raw >> SHM_CREATE_ATTR_SHIFT) & 0xFF;
    let clone = raw & SHM_CREATE_CLONE != 0;
    let src = (raw >> SHM_CREATE_SRC_SHIFT) as u32;
    let known = 0x3 | (0xFF << SHM_CREATE_KIND_SHIFT) | (0xFF << SHM_CREATE_ATTR_SHIFT) | SHM_CREATE_CLONE
        | (u64::from(u32::MAX) << SHM_CREATE_SRC_SHIFT);
    if raw & !known != 0 || kind != SHM_KIND_ANON || attrs & !(SHM_ATTR_SWAPPABLE | SHM_ATTR_NO_KERNEL_MAP) != 0 {
        return None;
    }
    if clone != (src != 0) {
        return None;
    }
    let mut a = 0u8;
    if attrs & SHM_ATTR_SWAPPABLE != 0 {
        a |= ATTR_SWAPPABLE;
    }
    if attrs & SHM_ATTR_NO_KERNEL_MAP != 0 {
        a |= ATTR_NO_KERNEL_MAP;
    }
    Some(ShmCreate { spec: MemSpec::anon(perms).with_attrs(a), clone_of: clone.then_some(src) })
}

/// `SYS_MO_CREATE`: a0=page_count, a1=the creation word
/// (`azos_abi::syscall_nr::SYS_MO_CREATE`: access mode, kind,
/// attributes, clone). Allocates a MemObj, charges its frames to the caller's
/// Domain, and grants a `Cap<Shm>` into the caller's cap-table. Returns the raw
/// cap handle as `i64` (always > 0) on success, or `-Errno`.
pub fn sys_shm_create_typed(page_count: u64, creation: u64) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Shm, Cap};
    let Some(c) = decode_shm_create(creation) else {
        return Errno::EINVAL.to_syscall_ret();
    };
    // Wave 15 (plan 4a): the process owns and holds it, not the thread.
    let tid = azos_sched::current_proc_tid();
    let made = match c.clone_of {
        None => azos_ipc::memobj::memobj_create_cap(tid, page_count as usize, &c.spec),
        Some(src) => {
            let cap: Cap<Shm> = Cap::from_raw(azos_abi::cap::CapHandle::from_raw(src));
            // The size is the source's: 0 asks for it, anything else must agree.
            match azos_ipc::memobj::memobj_clone_cap(tid, cap, c.spec.perms, page_count as usize) {
                Err(e) => return errno_for_memobj_err(e),
                Ok(cap) => Ok(cap),
            }
        }
    };
    match made {
        Ok(cap) => cap.raw().as_raw() as i64,
        Err(e) => errno_for_memobj_err(e),
    }
}

/// `MEMOBJ_ACQUIRE`: a0=cap_handle, a1=out_ptr. Bumps
/// the region refcount and writes an 8-byte blob (page_count u32 LE,
/// perms u8, 3-byte pad) to `out_ptr`. Returns `SHM_ACQUIRE_OUT_BYTES`
/// on success or `-Errno`. The reference is booked to the caller and given
/// back, with the caller's others, by `SYS_MO_UNMAP`.
pub fn sys_shm_acquire_typed(cap_raw: u64, out_ptr: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Shm, Cap};
    use azos_ipc::memobj::MemPerms;

    if out_ptr == 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    // U07-2 (the "plus" site): validated BEFORE `memobj_acquire_cap`, which
    // books a live reference on success. Unlike the queue-based sites above,
    // this one is not lost data on a bad pointer — it is a reference that
    // stays booked forever after the caller is told `-EFAULT`, since nothing
    // downstream of the failed copy releases it. Validating first means the
    // destination is already known-good by the time `memobj_acquire_cap` runs.
    if azos_sched::current_user_pt() != 0
        && !azos_sched::user_range_prepare_write(out_ptr as usize, SHM_ACQUIRE_OUT_BYTES)
    {
        return Errno::EFAULT.to_syscall_ret();
    }
    let cap: Cap<Shm> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    // Wave 15 (plan 4a): the process owns and holds it, not the thread.
    let tid = azos_sched::current_proc_tid();
    let result = azos_ipc::cap_store::with_table(tid, |table| {
        azos_ipc::memobj::memobj_acquire_cap(tid, table, cap)
    });
    match result {
        Some(Ok((page_count, perms))) => {
            let mut buf = [0u8; SHM_ACQUIRE_OUT_BYTES];
            buf[..4].copy_from_slice(&(page_count as u32).to_le_bytes());
            buf[4] = match perms {
                MemPerms::ReadOnly => 0,
                MemPerms::ReadWrite => 1,
            };
            if azos_sched::current_user_pt() != 0 {
                if !azos_sched::copy_to_user(
                    out_ptr as usize,
                    buf.as_ptr(),
                    SHM_ACQUIRE_OUT_BYTES,
                ) {
                    return Errno::EFAULT.to_syscall_ret();
                }
            } else {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buf.as_ptr(),
                        out_ptr as *mut u8,
                        SHM_ACQUIRE_OUT_BYTES,
                    );
                }
            }
            SHM_ACQUIRE_OUT_BYTES as i64
        }
        Some(Err(e)) => errno_for_memobj_err(e),
        None => Errno::EINVAL.to_syscall_ret(),
    }
}

/// `SYS_MO_MAP`: a0=cap (`Cap<Shm>`), a1=0 to map (or the protect
/// form, below). Maps the region into the
/// caller's address space and returns the base address, or `-Errno`.
///
/// The typed form of `SYS_IPC_MAP`, on the packed reference the
/// capability stores: the same sequence, and the mapping is recorded the same
/// way (one per task and region), so `SYS_MO_UNMAP` finds and removes
/// it. Mints nothing. Requires `READ`; a writable region also requires `WRITE`,
/// resolved with `get`, so while containment is armed a writable region answers
/// `-EAGAIN` and a read-only one maps. The region is mapped with its own access
/// mode, as 115 maps it; `memobj_create_cap` mints `WRITE` exactly for a writable
/// region.
///
/// In order:
/// - `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS` / `-EAGAIN` for the capability;
/// - `-EINVAL` for a kernel caller, which has no user address space;
/// - `-EBUSY` when the caller already maps the region;
/// - `-EBADF` when the region has no room for another holder;
/// - `-ENOMEM` when the pages could not be mapped or the mapping recorded. The
///   reference is kept then, as 115 keeps it, and pinned (`memobj_pin_ref`): a
///   partial mapping is not reported page by page, and releasing it could free
///   frames under live PTEs. `SYS_MO_UNMAP` gives back every other
///   reference the task holds and leaves this one to the task's exit.
///
/// The map's reference is booked to the caller with the others it holds on the
/// region (the creation reference, `MEMOBJ_ACQUIRE`'s), and the one
/// release gives them back together.
pub fn sys_shm_map_typed(cap_raw: u64, op: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_abi::syscall_nr::{SHM_MAP_OP_PROTECT, SHM_MAP_PROT_WRITE};
    use azos_ipc::cap::{targets::Shm, Cap};

    let cap: Cap<Shm> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    // Wave 15 (plan 4a): the process owns and holds it, not the thread.
    let tid = azos_sched::current_proc_tid();
    if op != 0 {
        // The protect form: the caller's mapping of the object the capability
        // names becomes read-only, or writable again within what the map was
        // allowed.
        if op & !(SHM_MAP_OP_PROTECT | SHM_MAP_PROT_WRITE) != 0 || op & SHM_MAP_OP_PROTECT == 0 {
            return Errno::EINVAL.to_syscall_ret();
        }
        let write = op & SHM_MAP_PROT_WRITE != 0;
        return match azos_ipc::cap_store::with_table(tid, |table| {
            let r = table.get(cap, azos_ipc::cap::CapPerms::READ)?;
            azos_ipc::memobj::memobj_protect_ref(tid, r, write)
        }) {
            Some(Ok(())) => 0,
            Some(Err(e)) => errno_for_memobj_err(e),
            None => Errno::EINVAL.to_syscall_ret(),
        };
    }
    // `READ` to map at all; the mapping is writable when the object is and the
    // capability holds `WRITE` — an attenuated capability maps read-only
    // (`memobj_resolve_map`). Containment still answers `-EAGAIN` for a
    // writable object, as before.
    match azos_ipc::cap_store::with_table(tid, |table| azos_ipc::memobj::memobj_resolve_map(table, cap)) {
        Some(Ok(g)) => map_region_ref(tid, g.r, g.writable, g.writable),
        Some(Err(e)) => errno_for_memobj_err(e),
        None => Errno::EINVAL.to_syscall_ret(),
    }
}

/// Give back the window addresses of the calling task's mappings a MOVE
/// removed (`memobj_moved`): the PTEs went with the transfer, the addresses are
/// the task's to release. Called after a transfer that may have moved a
/// MemObj capability and before the next map; free when nothing is waiting.
pub(crate) fn reap_moved_windows() {
    if !azos_ipc::memobj::memobj_moved_windows_pending() {
        return;
    }
    let tid = azos_sched::current_proc_tid();
    let mut w = [(0usize, 0usize); 8];
    loop {
        let n = azos_ipc::memobj::memobj_take_moved_windows(tid, &mut w);
        for &(va, pages) in &w[..n] {
            let _ = azos_sched::process::release_user_window(va, pages);
        }
        if n < w.len() {
            return;
        }
    }
}

/// The mapping half of [`sys_shm_map_typed`], once an authority has resolved
/// region `r` for `tid` (a `Cap<Shm>` there; a `Cap<Trace>` for the tracer's
/// region, `crate::trace_ctl`): map it into the caller, book the mapping,
/// and answer its base address or the errno 574 documents. `max_write` is the
/// most a later `SYS_MPROTECT` of the mapping may give back (what the
/// authority allowed), `writable` what it is mapped with now.
pub(crate) fn map_region_ref(tid: u32, r: u32, writable: bool, max_write: bool) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::memobj::{self, MapAccess, MAX_MEMOBJ_PAGES};
    if azos_sched::current_user_pt() == 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    reap_moved_windows();
    match memobj::memobj_has_mapping_ref(tid, r) {
        Ok(false) => {}
        Ok(true) => return Errno::EBUSY.to_syscall_ret(),
        Err(e) => return errno_for_memobj_err(e),
    }
    let page_count = match memobj::memobj_acquire_ref(tid, r) {
        Ok((n, _)) => n,
        Err(e) => return errno_for_memobj_err(e),
    };
    let desc = match memobj::memobj_describe_ref(r) {
        Ok(d) => d,
        Err(e) => {
            let _ = memobj::memobj_release_ref(tid, r);
            return errno_for_memobj_err(e);
        }
    };
    // A clone's shared frames are read-only to every mapper: a write mapping
    // gives the object frames of its own first.
    if writable && desc.cow_shared != 0 {
        if let Err(e) = memobj::memobj_cow_break_all(r) {
            let _ = memobj::memobj_release_ref(tid, r);
            return errno_for_memobj_err(e);
        }
    }
    let mut pages = [0usize; MAX_MEMOBJ_PAGES];
    for (i, page) in pages.iter_mut().enumerate().take(page_count) {
        match memobj::memobj_page_phys_ref(r, i) {
            Ok(Some(p)) => *page = p,
            // Not reachable while this task holds its reference. Nothing is
            // mapped yet, so the reference goes back.
            _ => {
                let _ = memobj::memobj_release_ref(tid, r);
                return Errno::EBADF.to_syscall_ret();
            }
        }
    }
    // Wave 11 (LEASE3): the lessor of an in-flight sealed lease on this
    // region maps it read-only — for good: this mapping is not the seal's.
    let writable = writable && !azos_ipc::lease::lease_sealed_by(tid, r);
    let mapped = match azos_sched::process::shm_map_user(&pages[..page_count], writable) {
        Some(va) => matches!(
            memobj::memobj_note_mapping_ref(tid, r, azos_sched::current_user_pt(), va, page_count,
                MapAccess { write: writable, max_write: max_write && writable }),
            Ok(true)
        )
        .then_some(va),
        None => None,
    };
    match mapped {
        Some(va) => va as i64,
        // PTEs this record does not name may remain: the reference taken above
        // must outlive the task's typed release. The task holds it, so the
        // region is live and the pin finds its holder.
        None => {
            let _ = memobj::memobj_pin_ref(tid, r);
            Errno::ENOMEM.to_syscall_ret()
        }
    }
}

/// Unmap `pages` pages from `va` in the caller's page table, the teardown
/// `SYS_IPC_UNSHARE` applied to a recorded shm mapping: nothing for a
/// kernel caller, and stop rather than touch a VA at or above `USER_VA_TOP`.
/// User and kernel page tables share their upper levels, so unmapping such a VA
/// edits the kernel's table; a recorded VA there can only be stale (a record
/// that survived an `exec`). Saturating arithmetic clamps the range to
/// `USER_VA_TOP` instead of overflowing, which `overflow-checks = true` would
/// turn into a board reset.
///
/// Batched like `munmap`: the PTEs are cleared up to
/// `vmm::UNMAP_BATCH_PAGES` at a time with ONE TLB shootdown per batch, not
/// one per page (a 64-page region paid 64 shootdowns). The skip window is the
/// range itself, so no frame is released here: shm frames belong to the
/// region (dropped by the reference release that follows), a ring page to its
/// ring.
pub(crate) fn unmap_user_pages(va: usize, pages: usize) {
    let _mm = azos_sched::group::mm_lock();
    let user_pt = azos_sched::current_user_pt();
    if user_pt == 0 || va >= crate::handlers::USER_VA_TOP {
        return;
    }
    let len = pages.saturating_mul(azos_arch::PAGE_SIZE);
    let end = va.saturating_add(len).min(crate::handlers::USER_VA_TOP);
    let _ = azos_mm::vmm::unmap_user_range_and_free(user_pt, va, end, va, end);
}

/// `SYS_MO_UNMAP`: a0=cap_handle. Tears down **this task's**
/// mapping of the region, then gives back **every** reference this task holds
/// on it (`memobj_release_holder_ref`: the creation reference, 534's and 574's);
/// frees pages when no task holds one, and revokes the cap (W3-F5). References
/// are booked per task (W3-F1), so a task can only give back references it
/// actually took, and another task's keep the region and its capabilities
/// live. All of them, not one: the capability is the task's only name for its
/// references and the call revokes it, so a reference left behind could not be
/// named again before the task's exit. The one exception is a reference a
/// failed 574 pinned, which may guard a partial mapping: it stays until exit.
/// A task that holds no reference answers `-EBADF`, and loses the capability.
///
/// **The mapping goes first**, the order `SYS_IPC_UNSHARE` enforces: a
/// reference is never dropped while the dropper still has PTEs into the region.
/// Before RFC-0040 gap 1 this call unmapped nothing, so a task that had mapped
/// the region (`SYS_MO_MAP`) was refused with `-EBADF` and lost its
/// capability anyway. The record is taken in one hold of the caller's table
/// (the capability resolved with `READ`, the record cleared under the region
/// lock inside it), the pages are unmapped after that hold and their window
/// addresses given back to the task, and the release
/// resolves the capability again. The task keeps its reference until the
/// release, so no frame is freed under the PTEs being removed. A forged or stale
/// capability unmaps nothing and is answered, and recorded, once, by the
/// release.
pub fn sys_shm_release_typed(cap_raw: u64) -> i64 {
    use azos_abi::cap::{CapHandle, CapPerms};
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Shm, Cap};

    let cap: Cap<Shm> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    // Wave 15 (plan 4a): the process owns and holds it, not the thread.
    let tid = azos_sched::current_proc_tid();
    let mapping = azos_ipc::cap_store::with_table(tid, |table| {
        let r = table.get(cap, CapPerms::READ).ok()?;
        azos_ipc::memobj::memobj_take_mapping_ref(tid, r).ok().flatten()
    })
    .flatten();
    if let Some((va, pages)) = mapping {
        // Wave 11 (LEASE3): a seal naming this mapping is forgotten before
        // its PTEs go and its window can be reused, so a later end of the
        // lease cannot widen whatever is mapped at `va` next.
        // Matched by this address space: the seal may be a sibling thread's.
        azos_ipc::lease::lease_forget_seal(azos_sched::current_task_tid(),
                                           azos_sched::current_user_pt(), va);
        unmap_user_pages(va, pages);
        // With its PTEs gone, the addresses go back to the task's window.
        let _ = azos_sched::process::release_user_window(va, pages);
    }
    let result = azos_ipc::cap_store::with_table(tid, |table| {
        azos_ipc::memobj::memobj_release_cap(tid, table, cap)
    });
    match result {
        Some(Ok(())) => 0,
        Some(Err(e)) => errno_for_memobj_err(e),
        None => Errno::EINVAL.to_syscall_ret(),
    }
}

// ── Cap<IoRing> typed handlers — RFC-0003 W5 batch 3 ──────────────────────

/// Width in bytes of the phys-addr out-blob for SYS_RING_SETUP.
const IORING_PHYS_OUT_BYTES: usize = 8;

pub(crate) fn errno_for_ioring_err(e: azos_ipc::io_ring::IoRingCapError) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::CapError;
    use azos_ipc::io_ring::IoRingCapError;
    // Every typed refusal in this file reaches the recorder here — the one
    // choke point all twelve of these functions share. `Contained` is filtered
    // inside `note_typed_denial`, not here.
    if let IoRingCapError::Cap(c) = e {
        note_typed_denial(azos_abi::cap::ty::IORING, c);
    }
    match e {
        IoRingCapError::Cap(CapError::Stale | CapError::Revoked) => Errno::ECAPSTALE.to_syscall_ret(),
        IoRingCapError::Cap(CapError::WrongKind) => Errno::ECAPKIND.to_syscall_ret(),
        IoRingCapError::Cap(CapError::MissingPerms) => Errno::ECAPPERMS.to_syscall_ret(),
        IoRingCapError::Cap(CapError::Contained) => Errno::EAGAIN.to_syscall_ret(),
        IoRingCapError::Cap(CapError::NoSpace) => Errno::EMFILE.to_syscall_ret(),
        IoRingCapError::NoMem => Errno::ENOMEM.to_syscall_ret(),
        IoRingCapError::Closed => Errno::EBADF.to_syscall_ret(),
        IoRingCapError::Full => Errno::EMFILE.to_syscall_ret(),
        // SubmitError reuses EIO (the underlying integer status is
        // not surfaced through errno; userspace polls the CQ for
        // per-op results in the same way as legacy io_ring_submit).
        IoRingCapError::SubmitError(_) => Errno::EIO.to_syscall_ret(),
        // Nothing ran: drain the CQ and submit again.
        IoRingCapError::CqFull => Errno::EBUSY.to_syscall_ret(),
    }
}

/// The unmap `io_ring_destroy_mapped_ref` runs for a ring page that
/// `SYS_RING_SETUP` mapped: the PTE, then the window address it was
/// reserved at. Runs in the owner's context, the only one the destroy lets
/// through for a mapped ring.
fn unmap_ring_page(va: usize) {
    unmap_user_pages(va, 1);
    let _ = azos_sched::process::release_user_window(va, 1);
}

/// Undo a ring-3 create that could not complete: the ring, its mapping if one
/// was recorded, and the capability. The caller hands back `code`.
fn ioring_create_rollback(
    tid: u32,
    cap: azos_ipc::cap::Cap<azos_ipc::cap::targets::IoRing>,
    r: u32,
    code: i64,
) -> i64 {
    let _ = azos_ipc::io_ring::io_ring_destroy_mapped_ref(r, tid, unmap_ring_page);
    let _ = azos_ipc::cap_store::with_table(tid, |t| t.revoke(cap));
    code
}

/// `SYS_RING_SETUP`: a0=out_ptr. Allocates a ring, grants a
/// `Cap<IoRing>` into the caller's cap-table and writes one `u64 LE` to
/// `out_ptr`. Returns the raw cap handle (`i64` > 0) on success, or `-Errno`.
///
/// **Ring 3 receives the user virtual address of the ring page**, mapped into
/// its own address space user RW and never executable, from the same per-task
/// window `SYS_MO_MAP` maps into (`process::shm_map_user`). The layout
/// at that address is `io_ring::IoRing`, pinned by its offset assertions. The
/// mapping goes with the ring: `SYS_IORING_DESTROY_TYPED` unmaps it and gives
/// the address back before the page is freed, and a task that exits with the
/// ring gets its page freed by the exit hook while its address space, whose
/// teardown spares that window, is discarded. `fork` leaves the window out of
/// the child (`vmm::fork_cow`), so a child never shares the page. `-ENOMEM`
/// when the page cannot be mapped, `-EFAULT` when the address cannot be
/// written; either way the ring and its capability are undone.
///
/// A kernel caller receives the physical address, as before.
///
/// **Why ring 3 never receives the physical address (W3-F6):** it hands an
/// attacker a known-valid physical frame to feed to any syscall that takes
/// one, and leaks the PMM layout. Until the page was mapped ring 3 received
/// zero here.
pub fn sys_ioring_create_typed(out_ptr: u64) -> i64 {
    use azos_abi::error::Errno;
    if out_ptr == 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    // Wave 15 (plan 4a): the process owns and holds it, not the thread.
    let tid = azos_sched::current_proc_tid();
    let (cap, r, phys_addr) = match azos_ipc::io_ring::io_ring_create_cap_ref(tid) {
        Ok(v) => v,
        Err(e) => return errno_for_ioring_err(e),
    };
    if azos_sched::current_user_pt() == 0 {
        let buf = phys_addr.to_le_bytes();
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), out_ptr as *mut u8, IORING_PHYS_OUT_BYTES);
        }
        return cap.raw().as_raw() as i64;
    }
    let Some(va) = azos_sched::process::shm_map_user(&[phys_addr as usize], true) else {
        return ioring_create_rollback(tid, cap, r, Errno::ENOMEM.to_syscall_ret());
    };
    if azos_ipc::io_ring::io_ring_record_user_va(r, tid, va).is_err() {
        // Unreachable for a ring this call created: nothing else can destroy
        // it or record a mapping for it. The PTE is removed here because the
        // rollback's destroy does not know of an unrecorded one.
        unmap_ring_page(va);
        return ioring_create_rollback(tid, cap, r, Errno::ENOMEM.to_syscall_ret());
    }
    let buf = (va as u64).to_le_bytes();
    if !azos_sched::copy_to_user(out_ptr as usize, buf.as_ptr(), IORING_PHYS_OUT_BYTES) {
        return ioring_create_rollback(tid, cap, r, Errno::EFAULT.to_syscall_ret());
    }
    cap.raw().as_raw() as i64
}

/// `SYS_RING_ENTER`: a0=cap_handle. Executes the pending SQEs
/// through the kernel's op table (RFC-0041 §E) and returns how many completed
/// (≥ 0), `-EBUSY` when an entry was pending and the CQ had no room for its
/// completion (nothing ran), or `-Errno` for the capability. A refused entry
/// completes: its CQE carries `io_ring::CQE_F_REFUSED` and the errno, and the
/// submit still counts it.
///
/// **The capability is resolved without the containment step; containment is
/// per entry.** Resolving through `get` refused the whole submit with `-EAGAIN`
/// while contained, so a batch of sensor reads stopped with the writes. Each
/// write entry is refused in `io_ring::dispatch_sqe` instead, with the typed
/// call's code in its completion, and reads keep running (RFC-0041 §E rule 3).
/// Deciding per entry, as the entry is copied off the page, leaves no gap
/// between a batch inspected and a batch executed for ring 3 to rewrite.
///
/// **The pass runs after the table hold, never inside it.** Each entry's
/// capability check reads the owner's table through `cap_store::with_table`,
/// which USED TO be this task's table unconditionally — sound only while a
/// capability could never leave the task that minted it. RFC-0040 gap 2 stage
/// 4 (decision 38) allows a capability MOVE, so `tid` here and the ring's
/// recorded owner can now differ; `io_ring_submit_ref` takes `tid` explicitly
/// and refuses before dispatch when they do (RFC-0040 gap 3, see its doc) —
/// otherwise a moved `Cap<IoRing>` would run this task's batch authorized
/// against a DIFFERENT task's capabilities. A pass inside this hold would
/// also take the same lock again and never return, and would run every
/// driver call of the batch with preemption off, which the GPIO handlers
/// above keep out of the hold for the same reason. So the reference is
/// resolved in one hold, and `io_ring_submit_ref` — which compares its
/// generation under the ring table's lock — runs with none.
pub fn sys_ioring_submit_typed(cap_raw: u64) -> i64 {
    use azos_abi::cap::{CapHandle, CapPerms};
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::IoRing, Cap};
    use azos_ipc::io_ring::IoRingCapError;

    let cap: Cap<IoRing> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    // Wave 15 (plan 4a): the process owns and holds it, not the thread.
    let tid = azos_sched::current_proc_tid();
    let r = match azos_ipc::cap_store::with_table(tid, |table| {
        table.get_uncontained(cap, CapPerms::WRITE)
    }) {
        Some(Ok(r)) => r,
        Some(Err(e)) => return errno_for_ioring_err(IoRingCapError::Cap(e)),
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    // `tid` — the task that actually resolved `cap` through its OWN table
    // above, not the ring's creator — closes RFC-0040 gap 3: a `Cap<IoRing>`
    // reaching here by a capability MOVE (decision 38) would otherwise let
    // `io_ring_submit_ref` authorize every device op in the batch against the
    // ring's original owner's capabilities instead of this caller's. See that
    // function's doc.
    match azos_ipc::io_ring::io_ring_submit_ref(tid, r) {
        Ok(n) => n as i64,
        Err(e) => errno_for_ioring_err(e),
    }
}

/// `SYS_IORING_DESTROY_TYPED`: a0=cap_handle. Unmaps the ring page from
/// the caller, frees the ring + its backing page **and revokes the cap**
/// (W3-F5) — see `io_ring::io_ring_destroy_cap` for why leaving it live let a
/// stale cap drive the next task that received the recycled ring id. Returns
/// `EBADF` if a submit pass is in flight on the ring (retry), or if the page is
/// mapped and the caller is not the ring's owner.
///
/// Resolved without containment, as a release (owner decision 2026-09-13).
/// Shaped like `SYS_MO_UNMAP`: the capability is resolved in one hold
/// of the caller's table, the page is unmapped and freed outside it
/// (`io_ring_destroy_mapped_ref`: unmap first, free after), and the capability
/// is revoked in a second hold. Between the two holds only this task writes
/// its table, and `revoke` compares the slot generation, so it cannot revoke
/// a different capability.
pub fn sys_ioring_destroy_typed(cap_raw: u64) -> i64 {
    use azos_abi::cap::{CapHandle, CapPerms};
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::IoRing, Cap};
    use azos_ipc::io_ring::IoRingCapError;

    let cap: Cap<IoRing> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    // Wave 15 (plan 4a): the process owns and holds it, not the thread.
    let tid = azos_sched::current_proc_tid();
    let r = match azos_ipc::cap_store::with_table(tid, |table| {
        table.get_uncontained(cap, CapPerms::WRITE)
    }) {
        Some(Ok(r)) => r,
        Some(Err(e)) => return errno_for_ioring_err(IoRingCapError::Cap(e)),
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    if let Err(e) = azos_ipc::io_ring::io_ring_destroy_mapped_ref(r, tid, unmap_ring_page) {
        return errno_for_ioring_err(e);
    }
    let _ = azos_ipc::cap_store::with_table(tid, |table| table.revoke(cap));
    0
}
