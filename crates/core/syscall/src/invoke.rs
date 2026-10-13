// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SYS_INVOKE` (D6): the one call for every operation on an object the
//! caller holds a handle to. The wire format, the register and descriptor
//! forms and the self handles are in `azos_abi::invoke`.
//!
//! This file is the entry: it decodes the op word, gathers the op's words
//! (from `a2..a5`, or from a `MsgDesc` in the caller's memory), reads the type
//! of the handle and gives the op to the family that owns that type. The
//! families are the typed handlers that existed as calls of their own; an op
//! here is the same body behind a handle, so its capability check, its limits
//! and its records are the ones the call had.
//!
//! Replies. The register form returns up to four words in `a1..a4`
//! ([`SyscallOut`]); a call that replies nothing leaves those registers as the
//! caller passed them. The descriptor form writes the reply words back into
//! the descriptor and sets its `n_words`.

use azos_abi::cap::{ty, CapHandle, CapPerms, CapType};
use azos_abi::error::Errno;
use azos_abi::invoke::{
    DOMAIN_MEMINFO, DOMAIN_MKDIR, DOMAIN_NET_GETIP, DOMAIN_OPEN, DOMAIN_READDIR, DOMAIN_RENAME, DOMAIN_RMDIR,
    DOMAIN_SOCKET, DOMAIN_STAT, DOMAIN_STATFS, DOMAIN_TASKINFO, DOMAIN_TRUNCATE, DOMAIN_UNLINK,
    NODE_BIND, NODE_CONNECT, NODE_FSYNC, NODE_MCAST_JOIN, NODE_MCAST_LEAVE, NODE_READ, NODE_RECV, NODE_RECVFROM, NODE_SEND,
    NODE_SENDTO, NODE_WRITE,
    DOMAIN_BRK, DOMAIN_MMIO_MAP, DOMAIN_DRIVER_FETCH, DOMAIN_DRIVER_REPLY, DOMAIN_DRIVER_REPLY_FETCH, DOMAIN_DRIVER_REPLY_WAIT,
    DOMAIN_NOTIFY_ROBUST, DOMAIN_NOTIFY_WAIT, DOMAIN_NOTIFY_WAKE, DOMAIN_DRIVER_REGISTER, DOMAIN_DRIVER_UNREGISTER,
    DEVICE_IRQ_ACK, DEVICE_IRQ_BIND,
    DOMAIN_UPTIME, DOMAIN_VDSO_MAP, DOMAIN_WAIT,
    DOMAIN_LEASE_ACCEPT, DOMAIN_LEASE_ACCEPT_MAP, DOMAIN_LEASE_FREE, DOMAIN_LEASE_RETURN, MEMOBJ_ACQUIRE, MEMOBJ_LEASE_GRANT,
    MEMOBJ_LEASE_WAIT,
    PORT_BIND, PORT_DESTROY, PORT_POLL,
    DOMAIN_CREATE_ENDPOINT, DOMAIN_CREATE_PIPE, DOMAIN_CREATE_PORT, DOMAIN_EXIT_STATS, DOMAIN_SERVICE_HEARTBEAT,
    DOMAIN_SERVICE_REGISTER, DOMAIN_SET_FILTER, DOMAIN_SUBREAPER,
    is_domain_self, op_class, op_kind, op_of, LOG_CONSOLE_WAIT, LOG_CONSOLE_WRITE, INVOKE_FLAGS_KNOWN, INVOKE_OP_MASK, INVOKE_REGS, INVOKE_REG_WORDS,
};
#[cfg(feature = "lx-loader")]
use azos_abi::invoke::{DOMAIN_MODULE_MAP_X, DOMAIN_MODULE_VERIFY};
use azos_abi::ipc_msg::{MsgDesc, MSG_WORDS_MAX, MSG_VERSION};
use azos_ipc::cap::{targets, Cap, CapError};

use crate::dispatch::SyscallOut;

/// What an op is given and what it answers.
pub(crate) struct Call {
    /// The calling task.
    pub tid: u32,
    /// The handle, as the caller passed it.
    pub handle: u32,
    /// The op.
    pub op: u16,
    /// The op's words: `a2..a5` in the register form, `MsgDesc.words` in the
    /// descriptor form (zeros past what the caller sent).
    pub w: [u64; MSG_WORDS_MAX],
    /// Reply words, set with [`Call::reply`].
    pub rep: [u64; MSG_WORDS_MAX],
    /// How many reply words the op set.
    pub nrep: usize,
}

/// The errno a refused capability check answers with.
pub(crate) fn errno_cap(e: CapError) -> i64 {
    match e {
        CapError::Stale | CapError::Revoked => Errno::ECAPSTALE.to_syscall_ret(),
        CapError::WrongKind => Errno::ECAPKIND.to_syscall_ret(),
        CapError::MissingPerms => Errno::ECAPPERMS.to_syscall_ret(),
        CapError::Contained => crate::handlers::E_CONTAINED,
        CapError::NoSpace => Errno::EMFILE.to_syscall_ret(),
    }
}

const DESC_BYTES: usize = core::mem::size_of::<MsgDesc>();

/// `SYS_INVOKE`: `a0` handle, `a1` op word, `a2..a5` words or a descriptor.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sys_invoke(
    handle: u64, opw: u64, a2: u64, a3: u64, a4: u64, a5: u64,
    out: &mut SyscallOut,
) -> i64 {
    if handle > u32::MAX as u64 || opw & !(INVOKE_OP_MASK | INVOKE_FLAGS_KNOWN) != 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let regs = opw & INVOKE_REGS != 0;
    let mut c = Call {
        tid: azos_sched::current_task_tid(),
        handle: handle as u32,
        op: op_of(opw),
        w: [0; MSG_WORDS_MAX],
        rep: [0; MSG_WORDS_MAX],
        nrep: 0,
    };
    let mut desc = MsgDesc::default();
    if regs {
        c.w[..INVOKE_REG_WORDS].copy_from_slice(&[a2, a3, a4, a5]);
    } else {
        if a3 != 0 || a4 != 0 || a5 != 0 {
            return Errno::EINVAL.to_syscall_ret();
        }
        if !azos_sched::copy_from_user(&mut desc as *mut MsgDesc as *mut u8, a2 as usize, DESC_BYTES) {
            return Errno::EFAULT.to_syscall_ret();
        }
        // The descriptor carries words only: an op takes no capabilities in
        // it (a transfer is an IPC call).
        if !desc.well_formed() || desc.n_caps != 0 {
            return Errno::EINVAL.to_syscall_ret();
        }
        c.w[..desc.n_words as usize].copy_from_slice(&desc.words[..desc.n_words as usize]);
    }
    let rc = dispatch(&mut c);
    if c.nrep != 0 {
        if regs {
            let r = &c.rep;
            out.set_no_cap([r[0], r[1], r[2], r[3], 0]);
        } else {
            desc.version = MSG_VERSION;
            desc.n_words = c.nrep as u8;
            desc.words[..c.nrep].copy_from_slice(&c.rep[..c.nrep]);
            if !azos_sched::copy_to_user(a2 as usize, &desc as *const MsgDesc as *const u8, DESC_BYTES) {
                return Errno::EFAULT.to_syscall_ret();
            }
        }
    }
    rc
}

/// The type of what `handle` names, before the table is consulted: a self
/// handle, or the type bits of the packed handle.
fn type_of(handle: u32) -> Option<CapType> {
    if is_domain_self(handle) {
        return Some(CapType::new(azos_abi::cap::CapKind::Domain, 1));
    }
    CapType::from_raw(CapHandle::from_raw(handle).kind())
}

/// Give the op to the family that owns the handle's type, once the op belongs
/// to the handle's kind and the image's profile lists its class.
fn dispatch(c: &mut Call) -> i64 {
    let Some(t) = type_of(c.handle) else { return Errno::ECAPKIND.to_syscall_ret() };
    let kind = t.kind() as u8;
    if op_kind(c.op) != kind {
        return Errno::EINVAL.to_syscall_ret();
    }
    // The image's op classes (`ImageProfile::ops`): unlisted is refused like an
    // unlisted syscall number, with the task killed (audit mode records it).
    match azos_sched::scheduler::current_op_verdict(kind, op_class(c.op)) {
        azos_sched::filter::FilterVerdict::Deny | azos_sched::filter::FilterVerdict::Linux => {
            crate::handlers::seccomp_deny_op_kill(c.op)
        }
        azos_sched::filter::FilterVerdict::Audit => {
            crate::handlers::record_seccomp_audit(azos_abi::syscall_nr::SYS_INVOKE as u16)
        }
        azos_sched::filter::FilterVerdict::Allow => {}
    }
    match t {
        t if t == ty::CONSOLE => console_op(c),
        t if t == CapType::new(azos_abi::cap::CapKind::Domain, 1) => domain_self_op(c),
        t if t == ty::PORT => port_op(c),
        t if t == ty::IRQ => irq_op(c),
        t if t == ty::FILE || t == ty::PIPE || t == ty::SOCKET => node_op(c),
        t if t == ty::SHM || t == ty::LEASE => memobj_op(c),
        t if t == ty::TRACE => crate::trace_ctl::trace_op(c.handle as u64, c.op, c.w[0]),
        _ => Errno::ECAPKIND.to_syscall_ret(),
    }
}

/// Ops on the console.
fn console_op(c: &mut Call) -> i64 {
    let (need, contained_ok) = match c.op {
        LOG_CONSOLE_WRITE => (CapPerms::WRITE, true),
        LOG_CONSOLE_WAIT => (CapPerms::READ, false),
        _ => return Errno::EINVAL.to_syscall_ret(),
    };
    let cap: Cap<targets::Console> = Cap::from_raw(CapHandle::from_raw(c.handle));
    // The console is where a contained program still reports: `WRITE` skips the
    // containment step every other write goes through.
    let r = azos_ipc::cap_store::read_table(c.tid, |t| {
        if contained_ok { t.get_uncontained(cap, need) } else { t.get(cap, need) }
    });
    if let Err(e) = r.unwrap_or(Err(CapError::Stale)) {
        crate::handlers::note_typed_denial_for(c.tid, ty::CONSOLE, e);
        return errno_cap(e);
    }
    match c.op {
        LOG_CONSOLE_WRITE => crate::handlers::console_write_user(c.w[0], c.w[1]),
        _ => crate::ushell::sys_console_wait(c.w[0], c.w[1], c.w[2], c.w[3]),
    }
}

/// Ops on the caller's own domain. A self handle names no one else's.
fn domain_self_op(c: &mut Call) -> i64 {
    use azos_abi::syscall_nr::{SUBREAPER_CLEAR, SUBREAPER_GET, SUBREAPER_SET};
    if !is_domain_self(c.handle) {
        return Errno::ECAPKIND.to_syscall_ret();
    }
    let w = c.w;
    match c.op {
        DOMAIN_EXIT_STATS => crate::handlers::sys_exit_stats(w[0]),
        DOMAIN_SERVICE_REGISTER => crate::handlers::sys_service_register(w[0], w[1], w[2]),
        DOMAIN_SERVICE_HEARTBEAT => crate::handlers::sys_service_heartbeat(w[0]),
        DOMAIN_CREATE_PORT => crate::ipc_handlers::sys_port_create_typed(),
        DOMAIN_CREATE_ENDPOINT => crate::ipc_handlers::sys_endpoint_create_typed(),
        DOMAIN_CREATE_PIPE => crate::ushell::sys_pipe_typed(w[0], w[1]),
        DOMAIN_SUBREAPER => match w[0] {
            SUBREAPER_GET => azos_sched::scheduler::task_subreaper(None) as i64,
            SUBREAPER_SET => azos_sched::scheduler::task_subreaper(Some(true)) as i64,
            SUBREAPER_CLEAR => azos_sched::scheduler::task_subreaper(Some(false)) as i64,
            _ => Errno::EINVAL.to_syscall_ret(),
        },
        DOMAIN_SET_FILTER => azos_sched::seccomp::activate_profile(w[0]),
        DOMAIN_STAT => crate::handlers::sys_stat(w[0], w[1]),
        DOMAIN_READDIR => crate::handlers::sys_readdir(w[0], w[1], w[2], w[3], w[4], w[5]),
        DOMAIN_STATFS => crate::handlers::sys_statfs(w[0], w[1], w[2]),
        DOMAIN_MEMINFO => crate::handlers::sys_meminfo(),
        DOMAIN_TASKINFO => crate::handlers::sys_taskinfo(w[0], w[1]),
        DOMAIN_NET_GETIP => crate::handlers::sys_net_getip(),
        DOMAIN_OPEN => crate::handlers::sys_file_open_typed(w[0], w[1]),
        DOMAIN_MKDIR => crate::handlers::sys_mkdir(w[0]),
        DOMAIN_UNLINK => crate::handlers::sys_unlink(w[0]),
        DOMAIN_RMDIR => crate::handlers::sys_rmdir(w[0]),
        DOMAIN_RENAME => crate::handlers::sys_rename(w[0], w[1]),
        DOMAIN_TRUNCATE => crate::handlers::sys_truncate(w[0], w[1]),
        DOMAIN_SOCKET => crate::handlers::sys_socket_typed(w[0], w[1], w[2]),
        DOMAIN_UPTIME => crate::handlers::sys_uptime(),
        DOMAIN_WAIT if w[0] == 0 => crate::handlers::sys_wait_status(w[1]),
        DOMAIN_WAIT => crate::handlers::sys_waitpid(w[0], w[1]),
        DOMAIN_BRK => crate::handlers::sys_brk(w[0]),
        DOMAIN_VDSO_MAP => crate::vdso_notify::sys_vdso_task_map(),
        #[cfg(feature = "lx-loader")]
        DOMAIN_MODULE_VERIFY => crate::module_ops::sys_module_verify(w[0], w[1], w[2], w[3]),
        #[cfg(feature = "lx-loader")]
        DOMAIN_MODULE_MAP_X => crate::module_ops::sys_module_map_x(w[0], w[1], w[2]),
        DOMAIN_DRIVER_REGISTER => crate::handlers::sys_driver_register_typed(w[0], w[1], w[2], w[3]),
        DOMAIN_DRIVER_UNREGISTER => crate::handlers::sys_driver_unregister_typed(w[0]),
        DOMAIN_MMIO_MAP => crate::mmio::sys_mmio_map(w[0], w[1]),
        DOMAIN_NOTIFY_WAIT => crate::vdso_notify::sys_notify_wait(w[0], w[1], w[2]),
        DOMAIN_NOTIFY_WAKE => crate::vdso_notify::sys_notify_wake(w[0], w[1]),
        DOMAIN_NOTIFY_ROBUST => crate::vdso_notify::sys_notify_robust(w[0], w[1]),
        DOMAIN_DRIVER_FETCH => crate::handlers::sys_driver_fetch_request(w[0], w[1]),
        DOMAIN_DRIVER_REPLY => crate::handlers::sys_driver_reply(w[0], w[1]),
        DOMAIN_DRIVER_REPLY_FETCH => crate::handlers::sys_driver_reply_fetch(w[0], w[1], w[2]),
        DOMAIN_DRIVER_REPLY_WAIT => crate::handlers::sys_driver_reply_wait(w[0], w[1], w[2], w[3]),
        DOMAIN_LEASE_ACCEPT => crate::handlers::sys_ipc_lease_accept(w[0]),
        DOMAIN_LEASE_ACCEPT_MAP => crate::handlers::sys_ipc_lease_accept_map(w[0], w[1]),
        DOMAIN_LEASE_RETURN => crate::handlers::sys_ipc_lease_return(w[0]),
        DOMAIN_LEASE_FREE => crate::handlers::sys_ipc_lease_free(w[0]),
        _ => Errno::EINVAL.to_syscall_ret(),
    }
}

/// Ops on an event port. Each checks its own right on the handle.
fn port_op(c: &mut Call) -> i64 {
    let h = c.handle as u64;
    match c.op {
        PORT_POLL => crate::ipc_handlers::sys_port_poll_typed(h, c.w[0]),
        PORT_BIND => crate::ipc_handlers::sys_port_bind_typed(h, c.w[0], c.w[1], c.w[2]),
        PORT_DESTROY => crate::ipc_handlers::sys_port_destroy_typed(h),
        _ => Errno::EINVAL.to_syscall_ret(),
    }
}

/// Ops on an interrupt line the caller holds (`ty::IRQ`): the handle names the
/// line, so no op carries a line number. A bind also resolves the port it
/// reports to; each handle is checked for the right its op needs, in one hold
/// of the caller's table.
fn irq_op(c: &mut Call) -> i64 {
    use azos_ipc::port::PortCapError;
    if c.op != DEVICE_IRQ_BIND && c.op != DEVICE_IRQ_ACK {
        return Errno::EINVAL.to_syscall_ret();
    }
    enum Refusal {
        Line(CapError),
        Port(CapError),
    }
    let w = c.w;
    let line: Cap<targets::Irq> = Cap::from_raw(CapHandle::from_raw(c.handle));
    let op = c.op;
    let resolved = azos_ipc::cap_store::with_table(c.tid, |t| {
        // An ACK and a bind are not writes to anything outside: a contained
        // program keeps its drivers' lines.
        let irq = t.get_uncontained(line, CapPerms::READ).map_err(Refusal::Line)?;
        if op == DEVICE_IRQ_ACK {
            return Ok((irq, 0));
        }
        if w[0] > u32::MAX as u64 {
            return Err(Refusal::Port(CapError::Stale));
        }
        let port: Cap<targets::Port> = Cap::from_raw(CapHandle::from_raw(w[0] as u32));
        let r = t.get(port, CapPerms::WRITE).map_err(Refusal::Port)?;
        Ok((irq, r))
    });
    match resolved {
        None => Errno::ECAPSTALE.to_syscall_ret(),
        Some(Err(Refusal::Line(e))) => {
            crate::handlers::note_typed_denial_for(c.tid, ty::IRQ, e);
            errno_cap(e)
        }
        Some(Err(Refusal::Port(e))) => crate::ipc_handlers::errno_for_port_err(PortCapError::Cap(e)),
        Some(Ok((irq, port))) if op == DEVICE_IRQ_BIND => {
            let mut msg = None;
            let rc = crate::handlers::sys_irq_bind(c.tid, irq, port, w[1], w[2], &mut msg);
            // A message-signalled slot answers the message its device writes:
            // address, data, and the vector it lands on.
            if let (true, Some(m)) = (rc >= 0, msg) {
                c.rep[..3].copy_from_slice(&[m.address, m.data as u64, m.id as u64]);
                c.nrep = 3;
            }
            rc
        }
        Some(Ok((irq, _))) => crate::handlers::sys_irq_ack(c.tid, irq),
    }
}

/// Ops on a memory object or a lease on one. Each checks its own right.
fn memobj_op(c: &mut Call) -> i64 {
    let h = c.handle as u64;
    match c.op {
        MEMOBJ_ACQUIRE => crate::ipc_handlers::sys_shm_acquire_typed(h, c.w[0]),
        MEMOBJ_LEASE_GRANT => crate::handlers::sys_ipc_lease_grant_typed(h, c.w[0], c.w[1]),
        MEMOBJ_LEASE_WAIT => crate::handlers::sys_ipc_lease_wait(h),
        _ => Errno::EINVAL.to_syscall_ret(),
    }
}

/// Ops on a file, a pipe end or a socket the caller holds. A pipe end takes the
/// pipe arms of `read` and `write`; each op checks its own right on the handle.
fn node_op(c: &mut Call) -> i64 {
    use crate::handlers as h;
    let hd = c.handle as u64;
    let w = c.w;
    let pipe = crate::ushell::is_pipe_handle(hd);
    match c.op {
        NODE_READ if pipe => crate::ushell::sys_pipe_read(hd, w[0], w[1]),
        NODE_READ => h::sys_file_read_typed(hd, w[0], w[1]),
        NODE_WRITE if pipe => crate::ushell::sys_pipe_write(hd, w[0], w[1]),
        NODE_WRITE => h::sys_file_write_typed(hd, w[0], w[1]),
        NODE_FSYNC => h::sys_fsync_typed(hd),
        NODE_BIND => h::sys_bind_typed(hd, w[0]),
        NODE_CONNECT => h::sys_connect_typed(hd, w[0], w[1]),
        NODE_SEND => h::sys_send_typed(hd, w[0], w[1]),
        NODE_RECV => h::sys_recv_typed(hd, w[0], w[1]),
        NODE_SENDTO => h::sys_sendto_typed(hd, w[0], w[1], w[2]),
        NODE_RECVFROM => h::sys_recvfrom_typed(hd, w[0], w[1], w[2]),
        NODE_MCAST_JOIN => h::sys_mcast_join_typed(hd, w[0]),
        NODE_MCAST_LEAVE => h::sys_mcast_leave_typed(hd, w[0]),
        _ => Errno::EINVAL.to_syscall_ret(),
    }
}
