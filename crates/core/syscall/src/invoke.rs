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
    DOMAIN_MEMINFO, DOMAIN_MKDIR, DOMAIN_NET_GETIP, DOMAIN_READDIR, DOMAIN_RENAME, DOMAIN_RMDIR,
    DOMAIN_SOCKET, DOMAIN_STAT, DOMAIN_STATFS, DOMAIN_TASKINFO, DOMAIN_TRUNCATE, DOMAIN_UNLINK,
    NODE_ACCEPT, NODE_BIND, NODE_CONNECT, NODE_FSYNC, NODE_LISTEN, NODE_MCAST_JOIN, NODE_MCAST_LEAVE, NODE_READ, NODE_RECV, NODE_RECVFROM, NODE_SEND,
    NODE_MMAP, NODE_OPENAT, NODE_SENDTO, NODE_WRITE,
    DOMAIN_MMIO_MAP, DOMAIN_DRIVER_FETCH, DOMAIN_DRIVER_REPLY, DOMAIN_DRIVER_REPLY_FETCH, DOMAIN_DRIVER_REPLY_WAIT,
    DOMAIN_DRIVER_REGISTER, DOMAIN_DRIVER_UNREGISTER,
    DEVICE_IRQ_ACK, DEVICE_IRQ_BIND, ENDPOINT_DERIVE, EndpointDerive,
    DOMAIN_UPTIME, DOMAIN_VDSO_MAP, DOMAIN_WAIT,
    MEMOBJ_ACQUIRE, MEMOBJ_END_DROP,
    PORT_BIND, PORT_DESTROY, PORT_POLL,
    DOMAIN_CREATE_ENDPOINT, DOMAIN_CREATE_PORT, DOMAIN_EXIT_STATS, DOMAIN_PLEDGE, DOMAIN_SET_FILTER,
    DOMAIN_SUBREAPER,
    is_domain_self, op, op_class, op_kind, op_of, CLASS_CTL, LOG_CONSOLE_WAIT, LOG_CONSOLE_WRITE, INVOKE_FLAGS_KNOWN, INVOKE_OP_MASK, INVOKE_REGS, INVOKE_REG_WORDS,
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

/// The op a resolve names when the call it serves is not an op of
/// `SYS_INVOKE`: the class-only op (index 0, which no real op has) of `class`
/// on a handle of type `t`. A capability's `OP_MASK` is a mask of classes
/// (`op_class`), so this discharges it exactly as the op of that class would.
/// A numbered syscall, a ring entry or a second handle an op resolves
/// (the port an interrupt line reports to) is a use of its class; releasing a
/// handle (close, destroy, release) is `CLASS_CTL`, "makes or ends an object".
#[inline(always)]
pub(crate) const fn class_op(t: CapType, class: u8) -> u16 {
    op(t.kind(), class, 0)
}

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
        desc = match azos_sched::UserPtr::<MsgDesc>::new(a2).read() {
            Ok(d) => d,
            Err(_) => return Errno::EFAULT.to_syscall_ret(),
        };
        // The descriptor carries words only: an op takes no capabilities in
        // it (a transfer is an IPC call).
        // With Kconfig IPC_LABELS off nothing enforces a label, so one is
        // refused here as on the IPC calls (`ipc_v2::xfers`).
        if !desc.well_formed() || desc.n_caps != 0 || (desc.label != 0 && !azos_ipc::endpoint::label::ENABLED) {
            return Errno::EINVAL.to_syscall_ret();
        }
        c.w[..desc.n_words as usize].copy_from_slice(&desc.words[..desc.n_words as usize]);
    }
    // A label the caller writes into the descriptor is data it forwards (innovation
    // B4): the op, and any effect it causes, works in that scope.
    let _scope = (desc.label != 0)
        .then(|| azos_ipc::endpoint::label::scope(c.tid, azos_ipc::endpoint::label::outgoing(c.tid, desc.label)));
    let rc = dispatch(&mut c);
    if c.nrep != 0 {
        if regs {
            let r = &c.rep;
            out.set_no_cap([r[0], r[1], r[2], r[3], 0]);
        } else {
            desc.version = MSG_VERSION;
            desc.n_words = c.nrep as u8;
            desc.words[..c.nrep].copy_from_slice(&c.rep[..c.nrep]);
            if azos_sched::UserPtr::<MsgDesc>::new(a2).write(&desc).is_err() {
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
        t if t == ty::IOPORT => crate::ioport::ioport_op(c),
        t if t == ty::ENDPOINT => endpoint_op(c),
        t if t == ty::FILE || t == ty::SOCKET => node_op(c),
        t if t == ty::SHM => memobj_op(c),
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
        if contained_ok { t.get_op_uncontained(cap, need, c.op) } else { t.get_op(cap, need, c.op) }
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
        DOMAIN_CREATE_PORT => crate::ipc_handlers::sys_port_create_typed(),
        DOMAIN_CREATE_ENDPOINT => crate::ipc_handlers::sys_endpoint_create_typed(),
        DOMAIN_SUBREAPER => match w[0] {
            SUBREAPER_GET => azos_sched::scheduler::task_subreaper(None) as i64,
            SUBREAPER_SET => azos_sched::scheduler::task_subreaper(Some(true)) as i64,
            SUBREAPER_CLEAR => azos_sched::scheduler::task_subreaper(Some(false)) as i64,
            _ => Errno::EINVAL.to_syscall_ret(),
        },
        DOMAIN_SET_FILTER => azos_sched::seccomp::activate_profile(w[0]),
        DOMAIN_PLEDGE => domain_pledge(c.tid, w[0]),
        DOMAIN_STAT => crate::handlers::sys_stat(w[0], w[1]),
        DOMAIN_READDIR => crate::handlers::sys_readdir(w[0], w[1], w[2], w[3], w[4], w[5]),
        DOMAIN_STATFS => crate::handlers::sys_statfs(w[0], w[1], w[2]),
        DOMAIN_MEMINFO => crate::handlers::sys_meminfo(),
        DOMAIN_TASKINFO => crate::handlers::sys_taskinfo(w[0], w[1]),
        DOMAIN_NET_GETIP => crate::handlers::sys_net_getip(),
        DOMAIN_MKDIR => crate::handlers::sys_mkdir(w[0]),
        DOMAIN_UNLINK => crate::handlers::sys_unlink(w[0]),
        DOMAIN_RMDIR => crate::handlers::sys_rmdir(w[0]),
        DOMAIN_RENAME => crate::handlers::sys_rename(w[0], w[1]),
        DOMAIN_TRUNCATE => crate::handlers::sys_truncate(w[0], w[1]),
        DOMAIN_SOCKET => crate::handlers::sys_socket_typed(w[0], w[1], w[2]),
        DOMAIN_UPTIME => crate::handlers::sys_uptime(),
        DOMAIN_WAIT if w[0] == 0 => crate::handlers::sys_wait_status(w[1]),
        DOMAIN_WAIT => crate::handlers::sys_waitpid(w[0], w[1]),
        DOMAIN_VDSO_MAP => crate::vdso_notify::sys_vdso_task_map(),
        #[cfg(feature = "lx-loader")]
        DOMAIN_MODULE_VERIFY => crate::module_ops::sys_module_verify(w[0], w[1], w[2], w[3]),
        #[cfg(feature = "lx-loader")]
        DOMAIN_MODULE_MAP_X => crate::module_ops::sys_module_map_x(w[0], w[1], w[2]),
        DOMAIN_DRIVER_REGISTER => crate::handlers::sys_driver_register_typed(w[0], w[1], w[2], w[3]),
        DOMAIN_DRIVER_UNREGISTER => crate::handlers::sys_driver_unregister_typed(w[0]),
        DOMAIN_MMIO_MAP => crate::mmio::sys_mmio_map(w[0], w[1]),
        DOMAIN_DRIVER_FETCH => crate::handlers::sys_driver_fetch_request(w[0], w[1]),
        DOMAIN_DRIVER_REPLY => crate::handlers::sys_driver_reply(w[0], w[1]),
        DOMAIN_DRIVER_REPLY_FETCH => crate::handlers::sys_driver_reply_fetch(w[0], w[1], w[2]),
        DOMAIN_DRIVER_REPLY_WAIT => crate::handlers::sys_driver_reply_wait(w[0], w[1], w[2], w[3]),
        _ => Errno::EINVAL.to_syscall_ret(),
    }
}

/// [`DOMAIN_PLEDGE`]: narrow the pledge mask of the caller's Domain to `req`
/// (`azos_sched::domain::pledge_narrow`). The mask is the Domain's, so it binds
/// every thread of it and every Domain it creates afterwards.
fn domain_pledge(tid: u32, req: u64) -> i64 {
    use azos_sched::domain::{self, PledgeError};
    let key = azos_sched::idx_for_tid(tid).map_or(domain::NONE, azos_sched::task_domain);
    let Ok(req) = u32::try_from(req) else { return Errno::EINVAL.to_syscall_ret() };
    match domain::pledge_narrow(key, req) {
        Ok(mask) => i64::from(mask),
        Err(PledgeError::NoDomain | PledgeError::Unknown) => Errno::EINVAL.to_syscall_ret(),
        Err(PledgeError::Widen) => Errno::EACCES.to_syscall_ret(),
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
        let irq = t.get_op_uncontained(line, CapPerms::READ, op).map_err(Refusal::Line)?;
        if op == DEVICE_IRQ_ACK {
            return Ok((irq, 0));
        }
        if w[0] > u32::MAX as u64 {
            return Err(Refusal::Port(CapError::Stale));
        }
        let port: Cap<targets::Port> = Cap::from_raw(CapHandle::from_raw(w[0] as u32));
        let r = t.get_op(port, CapPerms::WRITE, class_op(ty::PORT, CLASS_CTL)).map_err(Refusal::Port)?;
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

/// Ops on an endpoint the caller holds.
fn endpoint_op(c: &mut Call) -> i64 {
    match c.op {
        ENDPOINT_DERIVE => endpoint_derive(c),
        _ => Errno::EINVAL.to_syscall_ret(),
    }
}

/// [`ENDPOINT_DERIVE`]: the words are decoded and checked whole before
/// anything is minted. The copy's deadline is the rule of `SYS_CAP_DERIVE`
/// (`crate::caps::sys_cap_derive`): a copy born expired is refused first.
fn endpoint_derive(c: &mut Call) -> i64 {
    use azos_ipc::cap::{Caveat, Caveats};
    let Some(d) = EndpointDerive::decode(&c.w) else { return Errno::EINVAL.to_syscall_ret() };
    if u64::from(d.rights) & !(CapPerms::ALL.bits() as u64) != 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let mut caveats = Caveats::NONE;
    // A declassification warrant is not a restriction and does not go through
    // the caveat list: it is stamped by the issuer's own rule (a user
    // principal, `endpoint::mint_badged_issued`) and names label bits, at
    // least one and no unknown kind.
    let mut declassify = 0u32;
    for i in 0..d.n {
        if d.kinds[i] == azos_ipc::cap::caveat::DECLASSIFY {
            let bits = d.args[i];
            if declassify != 0 || bits == 0 || bits & !u64::from(azos_abi::ipc_msg::LABEL_KNOWN) != 0 {
                return Errno::EINVAL.to_syscall_ret();
            }
            declassify = bits as u32;
            continue;
        }
        match caveats.with(Caveat::new(d.kinds[i], d.args[i])) {
            Ok(next) => caveats = next,
            Err(e) => return errno_cap(e),
        }
    }
    let now = azos_abi::time::ticks_to_ns(azos_drv_sys::timebase::now(), azos_drv_sys::timebase::TIMER_FREQ);
    if d.expiry_ns != 0 && d.expiry_ns <= now {
        azos_decision::record(
            azos_decision::Rule::DeadlineExpired,
            azos_decision::Verdict::Refuse,
            c.tid,
            [d.expiry_ns, now, c.handle as u64],
        );
        return Errno::EDEADLINE.to_syscall_ret();
    }
    match azos_ipc::endpoint::mint_badged_issued(
        c.tid, CapHandle::from_raw(c.handle), d.badge, CapPerms::from_bits_truncate(d.rights), d.expiry_ns, &caveats,
        declassify,
    ) {
        Ok(h) => h.0 as i64,
        Err(e) => {
            crate::handlers::note_typed_denial_for(c.tid, ty::ENDPOINT, e);
            errno_cap(e)
        }
    }
}

/// Ops on a memory object. Each checks its own right.
fn memobj_op(c: &mut Call) -> i64 {
    let h = c.handle as u64;
    match c.op {
        MEMOBJ_ACQUIRE => crate::ipc_handlers::sys_shm_acquire_typed(h, c.w[0]),
        MEMOBJ_END_DROP => crate::ipc_handlers::sys_shm_end_drop_typed(h, c.w[0]),
        _ => Errno::EINVAL.to_syscall_ret(),
    }
}

/// Ops on a file or a socket the caller holds; each op checks its own right on
/// the handle.
fn node_op(c: &mut Call) -> i64 {
    use crate::handlers as h;
    let hd = c.handle as u64;
    let w = c.w;
    match c.op {
        NODE_READ => h::sys_file_read_typed(hd, w[0], w[1]),
        NODE_WRITE => h::sys_file_write_typed(hd, w[0], w[1]),
        NODE_FSYNC => h::sys_fsync_typed(hd),
        NODE_BIND => h::sys_bind_typed(hd, w[0], w[1]),
        NODE_CONNECT => h::sys_connect_typed(hd, w[0], w[1]),
        NODE_SEND => h::sys_send_typed(hd, w[0], w[1]),
        NODE_RECV => h::sys_recv_typed(hd, w[0], w[1]),
        NODE_SENDTO => h::sys_sendto_typed(hd, w[0], w[1], w[2]),
        NODE_RECVFROM => h::sys_recvfrom_typed(hd, w[0], w[1], w[2]),
        NODE_MCAST_JOIN => h::sys_mcast_join_typed(hd, w[0]),
        NODE_MCAST_LEAVE => h::sys_mcast_leave_typed(hd, w[0]),
        NODE_LISTEN => h::sys_listen_typed(hd),
        NODE_ACCEPT => h::sys_accept_typed(hd),
        NODE_OPENAT => h::sys_file_openat_typed(hd, w[0], w[1]),
        NODE_MMAP => crate::file_map::sys_file_mmap(hd, w[0], w[1], w[2], w[3]),
        _ => Errno::EINVAL.to_syscall_ret(),
    }
}
