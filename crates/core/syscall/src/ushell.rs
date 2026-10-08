// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The user shell's syscalls (RFC-0055, wave 11): `SYS_PIPE_TYPED` (607),
//! `SYS_SPAWN_EX` (608), `SYS_CONSOLE_WAIT` (609), `SYS_TASK_KILL` (611), and
//! the `Cap<Pipe>` arms of the file calls 564/565/566.
//!
//! The pure parts live elsewhere and are host-tested there: the request and
//! startup blocks in `azos_abi::ushell`, the pipe ring in
//! `azos_ipc::pipe`, the console input owner in
//! `azos_drv_sys::console_rx`, the ancestor relation in
//! `azos_sched::scheduler::stop_policy`. What is here is the glue that
//! needs user memory, the capability tables and the scheduler.
//!
//! # Waiting
//!
//! Every wait here is a `Timer` wait with a short ceiling, woken early by a
//! TID wake (the UART's RX interrupt, a pipe peer, a child's exit notice, a
//! stop request), and re-tests its condition after each wake. A wake that
//! lands before the block is stamped and the block returns at once, so the
//! re-test never misses one; the ceiling bounds any wake that is lost.

use azos_abi::cap::{CapHandle, CapKind, CapPerms};
use azos_abi::error::Errno;
use azos_abi::ushell::{
    layout_startup, count_cstrs, SpawnReq, StartupFd, CONSOLE_WAIT_FOREVER, FD_CONSOLE, FD_HANDLE,
    KILL_FORCE, KILL_REQUEST, KILL_SIGNO_MAX, KILL_SUBTREE, MOVE_CONSOLE, PIPE_NONBLOCK,
    SPAWN_ARGV_MAX, SPAWN_CWD_MAX, SPAWN_ENV_MAX, SPAWN_F_CONSOLE_IN, SPAWN_F_DIE_WITH_PARENT, SPAWN_MAX_MOVES,
    SPAWN_REQ_SIZE, STARTUP_FDS,
};
use azos_drv_sys::timebase::{now, TIMER_FREQ};
use azos_ipc::cap::{targets, Cap, CapError};
use azos_ipc::pipe::{PipeCreateError, PipeIo};
use azos_sched::WaitReason;

/// `SAFETY_EXEC_REFUSED` action code for a `SYS_SPAWN_EX` refused because the
/// caller holds no `Cap<Launch>` for the image. 4 is "no topology row"
/// (`crate::spawn::SPAWN_REFUSED_ACTION_NO_ROW`).
pub const SPAWN_REFUSED_ACTION_NO_LAUNCH: u8 = 5;

/// Bytes moved per pipe or console call, at most (the file calls' clamp).
const IO_MAX: usize = 4096;
/// `StartupFd::kind` of a closed descriptor.
const FD_CLOSED_KIND: u32 = azos_abi::ushell::FD_CLOSED;
/// Console bytes one `SYS_CONSOLE_WAIT` returns at most: the RX ring's size.
const CONSOLE_CHUNK: usize = 256;

fn err(e: Errno) -> i64 {
    e.to_syscall_ret()
}

pub(crate) fn ms_ticks(ms: u64) -> u64 {
    (TIMER_FREQ / 1000).max(1).saturating_mul(ms)
}

/// Block until a TID wake or `deadline` (ticks), whichever first.
pub(crate) fn park_until(deadline: u64) {
    azos_sched::task_block(WaitReason::Timer(deadline));
}

fn wake(tid: u32) {
    if tid != 0 {
        azos_sched::scheduler::wake_task_by_tid(tid, &|r| matches!(r, WaitReason::Timer(_)));
    }
}

/// Should an interruptible wait end with `-EINTR` now? A stop request
/// (`SYS_TASK_KILL`), or, for a Linux task, a signal its mask does not block
/// (wave 13: it is delivered at this call's return to user mode).
pub(crate) fn stop_requested() -> bool {
    azos_sched::scheduler::current_stop_request().is_some()
        || (azos_limits::LINUX_ABI && azos_sched::scheduler::signal::current_deliverable())
}

/// Is `[ptr, ptr+len)` writable user memory? Checked by writing zeros, before
/// anything is consumed that a failed copy-out would lose.
fn user_writable(ptr: u64, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let zero = [0u8; 256];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(zero.len());
        if !azos_sched::copy_to_user(ptr as usize + done, zero.as_ptr(), n) {
            return false;
        }
        done += n;
    }
    true
}

fn errno_for_cap(e: CapError) -> i64 {
    match e {
        CapError::Stale => err(Errno::ECAPSTALE),
        CapError::WrongKind => err(Errno::ECAPKIND),
        CapError::MissingPerms => err(Errno::ECAPPERMS),
        CapError::Contained => err(Errno::EAGAIN),
        CapError::NoSpace => err(Errno::EMFILE),
    }
}

// ── SYS_CONSOLE_WAIT (609) ──────────────────────────────────────────────────

/// `SYS_CONSOLE_WAIT`: see `azos_abi::syscall_nr::SYS_CONSOLE_WAIT`.
pub fn sys_console_wait(buf: u64, len: u64, timeout_ns: u64, a3: u64) -> i64 {
    use azos_drv_sys::console_rx::Claim;
    use azos_drv_sys::uart;
    if a3 != 0 {
        return err(Errno::EINVAL);
    }
    let me = azos_sched::current_task_tid();
    let mut want = (len as usize).min(CONSOLE_CHUNK);
    if want > 0 {
        if !user_writable(buf, want) {
            return err(Errno::EFAULT);
        }
        if let Claim::Busy(_) = uart::CONSOLE_RX.claim(me) {
            return err(Errno::EBUSY);
        }
    }
    // Wave 13: input lent to the foreground Linux job is its own; the owner
    // reads none of it (one reader of the ring at a time) and waits only for
    // exit notices and stop requests until the lend ends with that job.
    if uart::CONSOLE_RX.lendee() != 0 {
        want = 0;
    }
    let deadline = if timeout_ns == CONSOLE_WAIT_FOREVER {
        u64::MAX
    } else {
        now().saturating_add(azos_abi::time::ns_to_ticks_ceil(timeout_ns, TIMER_FREQ))
    };
    azos_sched::scheduler::set_current_waits_child(true);
    let rc = loop {
        if stop_requested() || azos_sched::scheduler::has_exit_note(me) {
            break err(Errno::EINTR);
        }
        if want > 0 && uart::can_read() {
            let mut k = [0u8; CONSOLE_CHUNK];
            let n = uart::rx_read(&mut k[..want]);
            if n > 0 {
                break if azos_sched::copy_to_user(buf as usize, k.as_ptr(), n) {
                    n as i64
                } else {
                    err(Errno::EFAULT)
                };
            }
        }
        let t = now();
        if t >= deadline {
            break 0;
        }
        // Parked on the RX interrupt when it is wired (a 1 s ceiling bounds a
        // lost wake), else polled every 20 ms, as the kernel's `readline` is.
        let wired = want > 0 && uart::rx_wake_wired();
        let step = if want == 0 || wired { ms_ticks(1000) } else { ms_ticks(20) };
        if wired {
            uart::rx_waiter_arm(me);
            if uart::can_read() {
                uart::rx_waiter_disarm();
                continue;
            }
        }
        park_until(deadline.min(t.saturating_add(step)));
        if wired {
            uart::rx_waiter_disarm();
        }
    };
    azos_sched::scheduler::set_current_waits_child(false);
    rc
}

// ── SYS_PIPE_TYPED (607) and the pipe arms of 564/565/566 ───────────────────

/// Pipes created with `PIPE_NONBLOCK`, by resource. A small set: it only has
/// to remember the flag for the pipes alive at once.
static NONBLOCK: azos_sync::SpinLock<[u32; 16]> = azos_sync::SpinLock::new([0; 16]);

fn nonblock_set(resource: u32, on: bool) {
    let mut t = NONBLOCK.lock();
    if on {
        if let Some(e) = t.iter_mut().find(|e| **e == 0 || **e == resource) {
            *e = resource;
        }
    } else if let Some(e) = t.iter_mut().find(|e| **e == resource) {
        *e = 0;
    }
}

fn nonblock(resource: u32) -> bool {
    resource != 0 && NONBLOCK.lock().contains(&resource)
}

/// `SYS_PIPE_TYPED`: see `azos_abi::syscall_nr::SYS_PIPE_TYPED`.
pub fn sys_pipe_typed(out_ptr: u64, flags: u64) -> i64 {
    if flags & !PIPE_NONBLOCK != 0 {
        return err(Errno::EINVAL);
    }
    if out_ptr == 0 || !user_writable(out_ptr, 8) {
        return err(Errno::EFAULT);
    }
    let me = azos_sched::current_task_tid();
    let resource = match azos_ipc::pipe::pipe_create_typed(me) {
        Ok(r) => r,
        Err(PipeCreateError::NoSpace) => return err(Errno::ENOSPC),
        Err(PipeCreateError::Quota) => return err(Errno::EQUOTA),
    };
    // Both handles or neither: a table with room for one would leave a pipe
    // with an end nobody can ever close.
    let minted = azos_ipc::cap_store::with_table(me, |t| {
        let rd = t.grant::<targets::Pipe>(CapPerms::READ.union(CapPerms::DUP), resource)?;
        match t.grant::<targets::Pipe>(CapPerms::WRITE.union(CapPerms::DUP), resource) {
            Some(wr) => Some((rd, wr)),
            None => {
                t.revoke(rd);
                None
            }
        }
    })
    .flatten();
    let Some((rd, wr)) = minted else {
        azos_ipc::pipe::pipe_typed_abandon(resource);
        return err(Errno::EMFILE);
    };
    if flags & PIPE_NONBLOCK != 0 {
        nonblock_set(resource, true);
    }
    let h = [rd.raw().as_raw(), wr.raw().as_raw()];
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&h[0].to_le_bytes());
    bytes[4..].copy_from_slice(&h[1].to_le_bytes());
    if !azos_sched::copy_to_user(out_ptr as usize, bytes.as_ptr(), 8) {
        let _ = azos_ipc::cap_store::with_table(me, |t| {
            t.revoke(rd);
            t.revoke(wr);
        });
        azos_ipc::pipe::pipe_typed_abandon(resource);
        nonblock_set(resource, false);
        return err(Errno::EFAULT);
    }
    0
}

/// Is `cap_raw` a `Cap<Pipe>` handle (by its kind bits)? What 564/565/566
/// dispatch on before taking the file path.
#[inline]
pub fn is_pipe_handle(cap_raw: u64) -> bool {
    u32::try_from(cap_raw).is_ok_and(|r| CapHandle::from_raw(r).kind() == CapKind::Pipe as u8)
}

fn pipe_resource(cap_raw: u64, need: CapPerms) -> Result<u32, i64> {
    let me = azos_sched::current_task_tid();
    let cap: Cap<targets::Pipe> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    match azos_ipc::cap_store::with_table(me, |t| t.get(cap, need)) {
        Some(Ok(r)) => Ok(r),
        Some(Err(e)) => Err(errno_for_cap(e)),
        None => Err(err(Errno::EINVAL)),
    }
}

/// `SYS_FILE_READ_TYPED` on a `Cap<Pipe>` read end.
pub fn sys_pipe_read(cap_raw: u64, buf: u64, count: u64) -> i64 {
    let res = match pipe_resource(cap_raw, CapPerms::READ) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let n = (count as usize).min(IO_MAX);
    if n == 0 {
        return 0;
    }
    if !user_writable(buf, n) {
        return err(Errno::EFAULT);
    }
    let me = azos_sched::current_task_tid();
    let mut k = core::mem::MaybeUninit::<[u8; IO_MAX]>::uninit();
    let k = crate::handlers::bounce_zeroed(&mut k, n);
    loop {
        let (io, w) = azos_ipc::pipe::pipe_typed_read(res, k, me);
        wake(w);
        match io {
            PipeIo::Done(got) => {
                return if azos_sched::copy_to_user(buf as usize, k.as_ptr(), got) {
                    got as i64
                } else {
                    err(Errno::EFAULT)
                };
            }
            PipeIo::Eof => return 0,
            PipeIo::Stale => return err(Errno::ECAPSTALE),
            PipeIo::Broken => return err(Errno::EPIPE),
            PipeIo::WouldBlock => {
                if nonblock(res) || stop_requested() {
                    azos_ipc::pipe::pipe_typed_unwait(res, me);
                    return err(if nonblock(res) { Errno::EAGAIN } else { Errno::EINTR });
                }
                park_until(now().saturating_add(ms_ticks(100)));
            }
        }
    }
}

/// `SYS_FILE_WRITE_TYPED` on a `Cap<Pipe>` write end.
pub fn sys_pipe_write(cap_raw: u64, buf: u64, count: u64) -> i64 {
    let res = match pipe_resource(cap_raw, CapPerms::WRITE) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let n = (count as usize).min(IO_MAX);
    if n == 0 {
        return 0;
    }
    let mut k = core::mem::MaybeUninit::<[u8; IO_MAX]>::uninit();
    let Some(k) = crate::handlers::bounce_from_user(&mut k, buf, n) else {
        return err(Errno::EFAULT);
    };
    let me = azos_sched::current_task_tid();
    loop {
        let (io, w) = azos_ipc::pipe::pipe_typed_write(res, k, me);
        wake(w);
        match io {
            PipeIo::Done(put) => return put as i64,
            PipeIo::Broken => return err(Errno::EPIPE),
            PipeIo::Stale => return err(Errno::ECAPSTALE),
            PipeIo::Eof => return err(Errno::EPIPE),
            PipeIo::WouldBlock => {
                if nonblock(res) || stop_requested() {
                    azos_ipc::pipe::pipe_typed_unwait(res, me);
                    return err(if nonblock(res) { Errno::EAGAIN } else { Errno::EINTR });
                }
                park_until(now().saturating_add(ms_ticks(100)));
            }
        }
    }
}

/// `SYS_CLOSE_TYPED` on a `Cap<Pipe>`: revoke the handle, drop its end.
pub fn sys_pipe_close(cap_raw: u64) -> i64 {
    let me = azos_sched::current_task_tid();
    let cap: Cap<targets::Pipe> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let got = azos_ipc::cap_store::with_table(me, |t| {
        let raw = cap.raw();
        let (_, perms, resource) = t.peek_raw(raw).ok_or(CapError::Stale)?;
        if !t.revoke_raw(raw) {
            return Err(CapError::Stale);
        }
        Ok((perms, resource))
    });
    match got {
        Some(Ok((perms, resource))) => {
            let w = azos_ipc::pipe::pipe_typed_drop_end(resource, perms.contains(CapPerms::WRITE));
            if azos_ipc::pipe::pipe_typed_state(resource).is_none() {
                nonblock_set(resource, false);
            }
            wake(w);
            0
        }
        Some(Err(e)) => errno_for_cap(e),
        None => err(Errno::EINVAL),
    }
}

// ── SYS_SPAWN_EX (608) ──────────────────────────────────────────────────────

/// One distinct handle of a move list, validated.
#[derive(Clone, Copy)]
struct Moving {
    handle: u32,
    kind: CapKind,
    /// Rights the child gets.
    rights: CapPerms,
    /// The descriptor, for a `Cap<File>`.
    resource: u32,
    /// The handle it takes in the child's table, once moved.
    moved: u32,
}

/// `SYS_SPAWN_EX`: see `azos_abi::syscall_nr::SYS_SPAWN_EX`.
pub fn sys_spawn_ex(path_ptr: u64, req_ptr: u64) -> i64 {
    if path_ptr == 0 {
        return err(Errno::EFAULT);
    }
    let mut path_buf = [0u8; 256];
    if azos_sched::copy_cstr_from_user(&mut path_buf, path_ptr as usize).is_none() {
        return err(Errno::EFAULT);
    }
    let path_len = path_buf.iter().position(|&b| b == 0).unwrap_or(0);
    if path_len == 0 {
        return err(Errno::EINVAL);
    }

    // The request block and everything it points at, copied in first.
    let mut req = SpawnReq { version: azos_abi::ushell::SPAWN_REQ_VERSION, ..SpawnReq::default() };
    if req_ptr != 0 {
        let mut raw = [0u8; SPAWN_REQ_SIZE];
        if !azos_sched::copy_from_user(raw.as_mut_ptr(), req_ptr as usize, SPAWN_REQ_SIZE) {
            return err(Errno::EFAULT);
        }
        // SAFETY: `SpawnReq` is `repr(C)`, every bit pattern of its integer
        // fields is a value, and its size is asserted to be `SPAWN_REQ_SIZE`.
        req = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const SpawnReq) };
    }
    if req.check_shape().is_err() {
        return err(Errno::EINVAL);
    }
    let mut argv = [0u8; SPAWN_ARGV_MAX];
    let mut env = [0u8; SPAWN_ENV_MAX];
    let (al, el) = (req.argv_bytes as usize, req.env_bytes as usize);
    if (al > 0 && !azos_sched::copy_from_user(argv.as_mut_ptr(), req.argv_ptr as usize, al))
        || (el > 0 && !azos_sched::copy_from_user(env.as_mut_ptr(), req.env_ptr as usize, el))
    {
        return err(Errno::EFAULT);
    }
    if count_cstrs(&argv[..al]) != Some(req.argc as usize) || count_cstrs(&env[..el]) != Some(req.envc as usize) {
        return err(Errno::EINVAL);
    }
    let mut cwd = [0u8; SPAWN_CWD_MAX + 2];
    let mut cl = 0;
    if req.cwd_ptr != 0 {
        if azos_sched::copy_cstr_from_user(&mut cwd, req.cwd_ptr as usize).is_none() {
            return err(Errno::EFAULT);
        }
        cl = cwd.iter().position(|&b| b == 0).unwrap_or(cwd.len());
        if cl > SPAWN_CWD_MAX {
            return err(Errno::EINVAL);
        }
    }

    // The move list, validated whole before anything moves: each distinct
    // handle once, a File descriptor or a Pipe end, rights kept or lowered.
    let me = azos_sched::current_task_tid();
    let mut moving = [Moving { handle: 0, kind: CapKind::Null, rights: CapPerms::NONE, resource: 0, moved: 0 };
        SPAWN_MAX_MOVES];
    let mut nmoving = 0usize;
    let mut fds = [StartupFd::default(); STARTUP_FDS];
    let mut fd_slot = [usize::MAX; STARTUP_FDS];
    for m in &req.moves[..req.nmoves as usize] {
        let fd = m.child_fd as usize;
        if m.handle == MOVE_CONSOLE {
            fds[fd] = StartupFd { kind: FD_CONSOLE, handle: 0 };
            continue;
        }
        if let Some(i) = moving[..nmoving].iter().position(|x| x.handle == m.handle) {
            // `> f 2>&1`: one handle, two child fds. Moved once; the rights
            // asked for must agree.
            let want = if m.perms == 0 {
                moving[i].rights
            } else {
                CapPerms::from_bits_truncate(m.perms as u8).union(CapPerms::DUP)
            };
            if want != moving[i].rights {
                return err(Errno::EINVAL);
            }
            fd_slot[fd] = i;
            continue;
        }
        let peek = azos_ipc::cap_store::with_table(me, |t| t.peek_raw(CapHandle::from_raw(m.handle))).flatten();
        let Some((kind, held, resource)) = peek else { return err(Errno::ECAPSTALE) };
        match kind {
            CapKind::Pipe => {}
            CapKind::File if !azos_ipc::file_cap::is_tree_resource(resource) => {}
            _ => return err(Errno::ECAPKIND),
        }
        let want = if m.perms == 0 {
            held
        } else {
            CapPerms::from_bits_truncate(m.perms as u8).union(CapPerms::DUP)
        };
        if !held.contains(CapPerms::DUP) || !held.contains(want) {
            return err(Errno::ECAPPERMS);
        }
        moving[nmoving] = Moving { handle: m.handle, kind, rights: want, resource, moved: 0 };
        fd_slot[fd] = nmoving;
        nmoving += 1;
    }

    let flags = req.flags;
    let refusal = core::cell::Cell::new(0i64);
    let rc = crate::spawn::spawn_path_ex(
        &path_buf[..path_len],
        &mut |image: &str| {
            // The launch grant is checked against the image the BYTES are,
            // not the path typed.
            let ok = azos_ipc::launch_cap::launch_resource_of(image.as_bytes()).is_some_and(|r| {
                azos_ipc::cap_store::with_table(me, |t| {
                    t.holds_kind_resource_uncontained(CapKind::Launch, r, CapPerms::EXEC)
                })
                .unwrap_or(false)
            });
            if !ok {
                // Recorded as every typed refusal is (RFC-0055 S5: under the
                // console lockdown this is how a privileged tool is refused).
                let recorded = crate::handlers::note_typed_denial_recorded(
                    me, CapKind::Launch, azos_ipc::cap::CapError::MissingPerms,
                );
                azos_drv_sys::kwarn!(
                    "[SPAWN] REFUSED: tid={} holds no launch grant for {}{}", me, image,
                    if recorded { " (recorded)" } else { "" },
                );
                refusal.set(err(Errno::EACCES));
            }
            ok
        },
        &mut |child| {
            let ctid = child.tid();
            // Moves, in list order. A failure moves back what already moved.
            for i in 0..nmoving {
                let mv = moving[i];
                let res = azos_ipc::cap_store::move_cap(me, ctid, CapHandle::from_raw(mv.handle), Some(mv.rights));
                let ok = match res {
                    Ok(h) => {
                        moving[i].moved = h.as_raw();
                        mv.kind != CapKind::File
                            || crate::file_ops::file_ops()
                                .is_some_and(|o| o.set_owner(mv.resource as i32, me, ctid) == 0)
                    }
                    Err(_) => false,
                };
                if !ok {
                    if res.is_ok() {
                        let _ = azos_ipc::cap_store::move_cap(
                            ctid, me, CapHandle::from_raw(moving[i].moved), None);
                    }
                    for back in moving[..i].iter().rev() {
                        if back.kind == CapKind::File {
                            if let Some(o) = crate::file_ops::file_ops() {
                                let _ = o.set_owner(back.resource as i32, ctid, me);
                            }
                        }
                        let _ = azos_ipc::cap_store::move_cap(
                            ctid, me, CapHandle::from_raw(back.moved), None);
                    }
                    refusal.set(err(Errno::EMFILE));
                    return false;
                }
            }
            for fd in 0..STARTUP_FDS {
                if fd_slot[fd] != usize::MAX {
                    fds[fd] = StartupFd { kind: FD_HANDLE, handle: moving[fd_slot[fd]].moved };
                }
            }
            // RFC-0047: a Linux child gets the initial stack a Linux binary
            // reads, and its descriptors and working directory go to the
            // personality's table instead of a startup block.
            // Wave 13: a Linux child the console is lent to reads it on
            // descriptor 0 when the request left that closed (no pipe, no
            // redirection: a terminal's foreground job).
            if child.is_linux() && flags & SPAWN_F_CONSOLE_IN != 0 && fds[0].kind == FD_CLOSED_KIND {
                fds[0] = StartupFd { kind: FD_CONSOLE, handle: 0 };
            }
            let wrote = if child.is_linux() {
                crate::linux::proc_set_startup(ctid, &fds, &cwd[..cl])
                    && child.write_linux_stack(
                        &argv[..al], req.argc as usize, &env[..el], req.envc as usize,
                        &crate::linux::random16(),
                    )
            } else {
                child.write_startup(azos_abi::ushell::STARTUP_BLOCK_SIZE + al + el + cl + 32, &mut |base, out| {
                    layout_startup(out, base, &argv[..al], req.argc, &env[..el], req.envc, &cwd[..cl], flags, &fds)
                })
            };
            if !wrote {
                refusal.set(err(Errno::ENOMEM));
                return false;
            }
            if flags & SPAWN_F_DIE_WITH_PARENT != 0 {
                azos_sched::scheduler::set_die_with_parent(ctid);
            }
            // Wave 13: the foreground Linux job reads the console the caller
            // owns, for its life (a native child has no console read).
            if flags & SPAWN_F_CONSOLE_IN != 0 && child.is_linux() {
                let _ = azos_drv_sys::uart::CONSOLE_RX.lend(me, ctid);
            }
            true
        },
    );
    match rc {
        crate::spawn::SpawnEx::Started(tid) => tid as i64,
        crate::spawn::SpawnEx::Refused => {
            crate::handlers::record_exec_refused(SPAWN_REFUSED_ACTION_NO_LAUNCH, 0);
            refusal.get()
        }
        crate::spawn::SpawnEx::Aborted => refusal.get(),
        crate::spawn::SpawnEx::Failed(e) => e,
    }
}

// ── The console program, started by the kernel ─────────────────────────────

/// Start the console program at `path` from a kernel task (the boot loader,
/// the supervisor's restart) as [`crate::spawn::spawn_path_hooked`] does:
/// the same digest binding, seccomp profile, row and supervision hook
/// (`before_release`). What a terminal's program also needs:
///
/// * a Linux row (`abi = "linux"`, e.g. BusyBox `sh`): the initial stack
///   with `args` (space-separated, argv[0] first; empty = the image name),
///   descriptors 0-2 on the console, and console input claimed for it and
///   lent to it (its reads go through the line discipline, `^C` is SIGINT
///   to it and its children), as `SYS_SPAWN_EX` with `SPAWN_F_CONSOLE_IN`
///   gives a shell's foreground Linux job. Its exit releases input (the
///   task-exit hook), which is what tells the console mode it is gone;
/// * a native row: it claims input itself (`SYS_CONSOLE_WAIT`, the native
///   shell). With `args`, it also gets a startup block with them and
///   descriptors 0-2 on the console.
pub fn spawn_console(path: &[u8], args: &[u8], before_release: &mut dyn FnMut(u32)) -> i64 {
    let mut argv = [0u8; SPAWN_ARGV_MAX];
    let (mut al, mut argc) = (0usize, 0usize);
    let name = path.rsplit(|&b| b == b'/').next().unwrap_or(path);
    let mut words = args.split(|&b| b == b' ').filter(|w| !w.is_empty()).peekable();
    let only_name = [name];
    let list: &mut dyn Iterator<Item = &[u8]> =
        if words.peek().is_some() { &mut words } else { &mut only_name.into_iter() };
    for w in list {
        if al + w.len() + 1 <= argv.len() {
            argv[al..al + w.len()].copy_from_slice(w);
            al += w.len() + 1;
            argc += 1;
        }
    }
    let mut fds = [StartupFd::default(); STARTUP_FDS];
    for f in fds.iter_mut().take(3) {
        *f = StartupFd { kind: FD_CONSOLE, handle: 0 };
    }
    const CWD: &[u8] = b"/fat";
    let rc = crate::spawn::spawn_path_ex(path, &mut |_| true, &mut |child| {
        let tid = child.tid();
        let wrote = if child.is_linux() {
            crate::linux::proc_set_startup(tid, &fds, CWD)
                && child.write_linux_stack(&argv[..al], argc, &[], 0, &crate::linux::random16())
        } else if !args.is_empty() {
            child.write_startup(azos_abi::ushell::STARTUP_BLOCK_SIZE + al + CWD.len() + 32, &mut |base, out| {
                layout_startup(out, base, &argv[..al], argc as u32, &[], 0, CWD, 0, &fds)
            })
        } else {
            true
        };
        if !wrote {
            return false;
        }
        before_release(tid);
        if child.is_linux() {
            let _ = azos_drv_sys::uart::CONSOLE_RX.claim(tid);
            let _ = azos_drv_sys::uart::CONSOLE_RX.lend(tid, tid);
        }
        true
    });
    match rc {
        crate::spawn::SpawnEx::Started(tid) => tid as i64,
        crate::spawn::SpawnEx::Failed(e) => e,
        crate::spawn::SpawnEx::Refused | crate::spawn::SpawnEx::Aborted => -1,
    }
}

// ── SYS_TASK_KILL (611) ─────────────────────────────────────────────────────

/// `SYS_TASK_KILL`: see `azos_abi::syscall_nr::SYS_TASK_KILL`.
pub fn sys_task_kill(tid: u64, how: u64, signo: u64, flags: u64) -> i64 {
    if (how != KILL_REQUEST && how != KILL_FORCE) || signo == 0 || signo > KILL_SIGNO_MAX
        || flags & !KILL_SUBTREE != 0
    {
        return err(Errno::EINVAL);
    }
    let Ok(target) = u32::try_from(tid) else { return err(Errno::ESRCH) };
    let me = azos_sched::current_task_tid();
    if target == me {
        return err(Errno::EINVAL);
    }
    // Absent and not-a-descendant answer alike: a task cannot probe TIDs.
    if !azos_sched::scheduler::task_is_ancestor(me, target) {
        return err(Errno::ESRCH);
    }
    let force = how == KILL_FORCE;
    let mut n = 0i64;
    if flags & KILL_SUBTREE != 0 {
        let mut below = [0u32; 32];
        let found = azos_sched::scheduler::descendants_of(target, &mut below);
        for &t in &below[..found.min(below.len())] {
            if azos_sched::scheduler::task_stop(t, force, signo as u8) {
                n += 1;
            }
        }
    }
    if azos_sched::scheduler::task_stop(target, force, signo as u8) {
        n += 1;
    }
    if n == 0 { err(Errno::ESRCH) } else { n }
}
