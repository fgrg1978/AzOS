// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The user shell's syscalls: `SYS_SPAWN_EX`,
//! `LOG_CONSOLE_WAIT` and `SYS_ALERT`.
//!
//! The pure parts live elsewhere and are host-tested there: the request and
//! startup blocks in `azos_abi::ushell`, the pipe ring in
//! `azos_bytepipe`, the console input owner in
//! `azos_drv_sys::console_rx`, the ancestor relation in
//! `azos_sched::scheduler::stop_policy`. What is here is the glue that
//! needs user memory, the capability tables and the scheduler.
//!
//! # Waiting
//!
//! Every wait here is a `Timer` wait with a short ceiling, woken early by a
//! TID wake (the UART's RX interrupt, a child's exit notice, a
//! stop request), and re-tests its condition after each wake. A wake that
//! lands before the block is stamped and the block returns at once, so the
//! re-test never misses one; the ceiling bounds any wake that is lost.

use azos_abi::cap::ty;
use azos_abi::cap::{CapHandle, CapPerms, CapType};
use azos_abi::error::Errno;
use azos_abi::ushell::{
    layout_startup, count_cstrs, SpawnReq, StartupFd, CONSOLE_WAIT_FOREVER, FD_CONSOLE, FD_HANDLE,
    KILL_FORCE, KILL_REQUEST, KILL_SIGNO_MAX, KILL_SUBTREE, MOVE_CONSOLE,
    SPAWN_ARGV_MAX, SPAWN_CWD_MAX, SPAWN_ENV_MAX, SPAWN_F_CONSOLE_IN, SPAWN_F_DIE_WITH_PARENT, SPAWN_MAX_MOVES,
    SPAWN_F_USER, STARTUP_FDS,
};
use azos_drv_sys::timebase::{now, TIMER_FREQ};
use azos_sched::WaitReason;

/// `SAFETY_EXEC_REFUSED` action code for a `SYS_SPAWN_EX` refused because the
/// caller holds no `Cap<Launch>` for the image. 4 is "no topology row"
/// (`crate::spawn::SPAWN_REFUSED_ACTION_NO_ROW`).
pub const SPAWN_REFUSED_ACTION_NO_LAUNCH: u8 = 5;

/// `StartupFd::kind` of a closed descriptor.
const FD_CLOSED_KIND: u32 = azos_abi::ushell::FD_CLOSED;
/// Console bytes one `LOG_CONSOLE_WAIT` returns at most: the RX ring's size.
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

/// Should an interruptible wait end with `-EINTR` now? A stop request
/// (`SYS_ALERT`), or, for a Linux task, a signal its mask does not block
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
        if azos_sched::UserSlice::<u8>::new(ptr + done as u64, n).write_from(&zero[..n]).is_err() {
            return false;
        }
        done += n;
    }
    true
}

// ── LOG_CONSOLE_WAIT ──────────────────────────────────────────────────

/// `LOG_CONSOLE_WAIT`: see `azos_abi::syscall_nr::LOG_CONSOLE_WAIT`.
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
        match uart::CONSOLE_RX.claim(me) {
            Claim::Busy(_) => return err(Errno::EBUSY),
            // A nudge left for the owner before this one is not for it.
            Claim::Got => {
                uart::rx_nudge_take();
            }
            Claim::Already => {}
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
                break if azos_sched::UserSlice::<u8>::new(buf, n).write_from(&k[..n]).is_ok() {
                    n as i64
                } else {
                    err(Errno::EFAULT)
                };
            }
        }
        // The input event ring has something for the reader (it announced it
        // sleeps there too): return with no bytes, the caller looks at it.
        if uart::rx_nudge_take() {
            break 0;
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
            if uart::can_read() || uart::rx_nudged() {
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

// ── SYS_SPAWN_EX ──────────────────────────────────────────────────────

/// One distinct handle of a move list, validated.
#[derive(Clone, Copy)]
struct Moving {
    handle: u32,
    kind: CapType,
    /// Rights the child gets.
    rights: CapPerms,
    /// The descriptor, for a `Cap<File>`.
    resource: u32,
    /// The handle it takes in the child's table, once moved.
    moved: u32,
    /// For a pipe's region: the ends the child holds, by the fds it takes it
    /// at (fd 0 reads, any other fd writes; `azos_bytepipe`'s rule, the one
    /// `libsys` adopts the region by).
    ends: u8,
}

/// The end of a pipe region a child's `fd` names.
fn pipe_end_of_fd(fd: usize) -> u8 {
    if fd == 0 { azos_ipc::memobj::PIPE_END_READ } else { azos_ipc::memobj::PIPE_END_WRITE }
}

azos_common::ro_hook! {
    /// Called after every `SYS_SPAWN_EX` that started a task, with the path as
    /// typed and the new TID (installed by the kernel at boot; `crates/core/syscall`
    /// cannot name `console_mode`, hence a hook).
    static SPAWN_EX_HOOK: fn(&[u8], u32);
}

/// Install the `SYS_SPAWN_EX` start hook. Called once at boot.
pub fn set_spawn_ex_hook(f: fn(&[u8], u32)) {
    SPAWN_EX_HOOK.set(f);
}

/// Asked before every `SYS_SPAWN_EX` with the path as typed and the caller's
/// TID: `Some(args)` when the spawn starts the console program for the
/// component manager, and what its arguments are (see [`sys_spawn_ex`]).
/// Installed by the kernel at boot (`console_mode::console_start`).
static CONSOLE_START_HOOK: azos_sync::SpinLock<Option<fn(&[u8], u32) -> Option<&'static [u8]>>> =
    azos_sync::SpinLock::new(None);

/// Install the console-program hook. Called once at boot.
pub fn set_console_start_hook(f: fn(&[u8], u32) -> Option<&'static [u8]>) {
    *CONSOLE_START_HOOK.lock() = Some(f);
}

/// The working directory of a console program the kernel starts.
const CONSOLE_CWD: &[u8] = b"/fat";

/// `SYS_SPAWN_EX`: see `azos_abi::syscall_nr::SYS_SPAWN_EX`.
///
/// **The console program.** When the kernel's hook says the caller (the
/// component manager) is starting the console program, the child gets what a
/// terminal's program needs, whatever the request says: a Linux row (`abi =
/// "linux"`, e.g. BusyBox `sh`) gets the initial stack with the hook's
/// arguments, descriptors 0-2 on the console and working directory `/fat`,
/// and console input claimed for it and lent to it (its reads go through the
/// line discipline, `^C` is SIGINT to it and its children; its exit releases
/// input, which is what tells the console mode it is gone); a native row
/// claims input itself (`LOG_CONSOLE_WAIT`), and with arguments also gets
/// the startup block carrying them and descriptors 0-2 on the console.
pub fn sys_spawn_ex(path_ptr: u64, req_ptr: u64) -> i64 {
    if path_ptr == 0 {
        return err(Errno::EFAULT);
    }
    let mut path_buf = [0u8; 256];
    if azos_sched::UserCStr::new(path_ptr).read_into(&mut path_buf).is_err() {
        return err(Errno::EFAULT);
    }
    let path_len = path_buf.iter().position(|&b| b == 0).unwrap_or(0);
    if path_len == 0 {
        return err(Errno::EINVAL);
    }

    // The request block and everything it points at, copied in first.
    let mut req = SpawnReq { version: azos_abi::ushell::SPAWN_REQ_VERSION, ..SpawnReq::default() };
    if req_ptr != 0 {
        // `SpawnReq` is `Pod` (`azos_sched::uptr`): integers, no padding.
        req = match azos_sched::UserPtr::<SpawnReq>::new(req_ptr).read() {
            Ok(r) => r,
            Err(_) => return err(Errno::EFAULT),
        };
    }
    if req.check_shape().is_err() {
        return err(Errno::EINVAL);
    }
    let mut argv = [0u8; SPAWN_ARGV_MAX];
    let mut env = [0u8; SPAWN_ENV_MAX];
    let (al, el) = (req.argv_bytes as usize, req.env_bytes as usize);
    if (al > 0 && azos_sched::UserSlice::<u8>::new(req.argv_ptr, al).read_into(&mut argv[..al]).is_err())
        || (el > 0 && azos_sched::UserSlice::<u8>::new(req.env_ptr, el).read_into(&mut env[..el]).is_err())
    {
        return err(Errno::EFAULT);
    }
    if count_cstrs(&argv[..al]) != Some(req.argc as usize) || count_cstrs(&env[..el]) != Some(req.envc as usize) {
        return err(Errno::EINVAL);
    }
    let mut cwd = [0u8; SPAWN_CWD_MAX + 2];
    let mut cl = 0;
    if req.cwd_ptr != 0 {
        if azos_sched::UserCStr::new(req.cwd_ptr).read_into(&mut cwd).is_err() {
            return err(Errno::EFAULT);
        }
        cl = cwd.iter().position(|&b| b == 0).unwrap_or(cwd.len());
        if cl > SPAWN_CWD_MAX {
            return err(Errno::EINVAL);
        }
    }

    // The move list, validated whole before anything moves: each distinct
    // handle once, a File descriptor, a Pipe end or a pipe's region (shared,
    // not moved), rights kept or lowered.
    let me = azos_sched::current_task_tid();
    let console_args = {
        let hook = *CONSOLE_START_HOOK.lock();
        hook.and_then(|f| f(&path_buf[..path_len], me))
    };
    let console_block = console_args.map(|a| azos_abi::ushell::console_argv(&path_buf[..path_len], a));
    let mut moving = [Moving { handle: 0, kind: CapType::NULL, rights: CapPerms::NONE, resource: 0, moved: 0, ends: 0 };
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
                CapPerms::from_bits_truncate(m.perms as u8).union(CapPerms::DELEGATE)
            };
            if want != moving[i].rights {
                return err(Errno::EINVAL);
            }
            fd_slot[fd] = i;
            moving[i].ends |= pipe_end_of_fd(fd);
            continue;
        }
        let peek = azos_ipc::cap_store::with_table(me, |t| t.peek_raw(CapHandle::from_raw(m.handle))).flatten();
        let Some((kind, held, resource)) = peek else { return err(Errno::ECAPSTALE) };
        match kind {
            // A POSIX pipe's region (`azos_bytepipe`): shared with the child,
            // not moved. The caller keeps its capability and its mapping.
            ty::SHM => {}
            ty::FILE if !azos_ipc::file_cap::is_tree_resource(resource) => {}
            _ => return err(Errno::ECAPKIND),
        }
        let want = if m.perms == 0 {
            held
        } else {
            CapPerms::from_bits_truncate(m.perms as u8).union(CapPerms::DELEGATE)
        };
        // A File moves (`TRANSFER`); a pipe's region is shared as a DUP entry
        // (`DUP` and `TRANSFER`): either way the caller must hold the right to
        // hand it over, and the child gets what it asked for within what the
        // caller holds.
        let needs = if kind == ty::SHM { CapPerms::DELEGATE } else { CapPerms::TRANSFER };
        if !held.contains(needs) || !held.contains(want) {
            return err(Errno::ECAPPERMS);
        }
        moving[nmoving] = Moving { handle: m.handle, kind, rights: want, resource, moved: 0, ends: pipe_end_of_fd(fd) };
        fd_slot[fd] = nmoving;
        nmoving += 1;
    }

    let flags = req.flags;
    // Console login: a session spawn spends the one-shot grant the `keys`
    // interface's `login` op armed for the caller's Domain, before anything is
    // loaded. A spawn that fails later has still spent it: a credential starts
    // at most one attempt at a session.
    let session_root = if flags & SPAWN_F_USER != 0 {
        match crate::keys::take_login_grant(me) {
            Some(root) => Some(root),
            None => {
                azos_drv_sys::kwarn!("[SPAWN] REFUSED: tid={} asked for a user session and holds no login grant", me);
                return err(Errno::EACCES);
            }
        }
    } else {
        None
    };
    let refusal = core::cell::Cell::new(0i64);
    let rc = crate::spawn::spawn_path_ex(
        &path_buf[..path_len],
        &mut |image: &str| {
            // The launch grant is checked against the image the BYTES are,
            // not the path typed.
            let ok = azos_ipc::launch_cap::launch_resource_of(image.as_bytes()).is_some_and(|r| {
                azos_ipc::cap_store::with_table(me, |t| {
                    t.holds_kind_resource_uncontained(ty::LAUNCH, r, CapPerms::EXEC)
                })
                .unwrap_or(false)
            });
            if !ok {
                // Recorded as every typed refusal is (under the
                // console lockdown this is how a privileged tool is refused).
                let recorded = crate::handlers::note_typed_denial_recorded(
                    me, ty::LAUNCH, azos_ipc::cap::CapError::MissingPerms,
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
            // The session's Domain is the user's before it runs one
            // instruction; every Domain beneath it inherits the root.
            if let Some(root) = session_root {
                let dom = azos_sched::idx_for_tid(ctid).map_or(azos_sched::domain::NONE, azos_sched::task_domain);
                if !azos_sched::domain::set_owner_root(dom, root) {
                    refusal.set(err(Errno::EACCES));
                    return false;
                }
            }
            // Moves, in list order. A failure moves back what already moved.
            for i in 0..nmoving {
                let mv = moving[i];
                let res = if mv.kind == ty::SHM {
                    // Shared: the child gets a derived copy and the caller
                    // keeps its handle and its mapping.
                    let mut out = [CapHandle::from_raw(0); 1];
                    let mut x = azos_ipc::cap_store::CapXfer::new(CapHandle::from_raw(mv.handle), true);
                    x.rights = Some(mv.rights);
                    // The caller closes its own ends once the stages exist:
                    // that deletes its slot and leaves the stage's copy (and
                    // the stage's pipe mapping) alone, as every delete does.
                    azos_ipc::cap_store::move_caps(me, ctid, &[x], false, &mut out).map(|_| out[0])
                } else {
                    azos_ipc::cap_store::move_cap(me, ctid, CapHandle::from_raw(mv.handle), Some(mv.rights))
                };
                let ok = match res {
                    Ok(h) => {
                        moving[i].moved = h.as_raw();
                        match mv.kind {
                            ty::FILE => crate::file_ops::file_ops()
                                .is_some_and(|o| o.set_owner(mv.resource as i32, me, ctid) == 0),
                            // The child holds a reference to the region from
                            // now on: the caller may release its own the
                            // moment this returns, before the child has run
                            // to map it, and the region must outlive that.
                            // And, if the region is a pipe, the ends its fds
                            // name, counted here, in the same step: nothing
                            // the child does or suffers can leave them
                            // uncounted or counted twice.
                            ty::SHM => {
                                azos_ipc::memobj::memobj_acquire_ref(ctid, mv.resource).is_ok()
                                    && azos_ipc::memobj::memobj_pipe_hold(ctid, mv.resource, mv.ends).is_ok()
                            }
                            _ => true,
                        }
                    }
                    Err(_) => false,
                };
                if !ok {
                    // A moved handle goes back; a shared copy is revoked in
                    // the child's table (the caller never lost its own).
                    let undo = |m: &Moving| {
                        let h = CapHandle::from_raw(m.moved);
                        if m.kind == ty::SHM {
                            let _ = azos_ipc::cap_store::with_table(ctid, |t| t.delete_raw(h));
                            azos_ipc::memobj::memobj_pipe_drop_all_ref(ctid, m.resource);
                            let _ = azos_ipc::memobj::memobj_release_ref(ctid, m.resource);
                        } else {
                            let _ = azos_ipc::cap_store::move_cap(ctid, me, h, None);
                        }
                    };
                    if res.is_ok() {
                        undo(&moving[i]);
                    }
                    for back in moving[..i].iter().rev() {
                        if back.kind == ty::FILE {
                            if let Some(o) = crate::file_ops::file_ops() {
                                let _ = o.set_owner(back.resource as i32, ctid, me);
                            }
                        }
                        undo(back);
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
            // The console program (see above): a Linux or hosted child, or a
            // native one with arguments.
            let console = console_block
                .as_ref()
                .filter(|_| child.is_linux() || child.is_hosted() || console_args.is_some_and(|a| !a.is_empty()));
            let (argv, al, argc, cwd): (&[u8], usize, usize, &[u8]) = match console {
                Some((b, l, c)) => {
                    for f in fds.iter_mut().take(3) {
                        *f = StartupFd { kind: FD_CONSOLE, handle: 0 };
                    }
                    (&b[..], *l, *c, CONSOLE_CWD)
                }
                None => (&argv[..], al, req.argc as usize, &cwd[..cl]),
            };
            // Wave 13: a Linux child the console is lent to reads it on
            // descriptor 0 when the request left that closed (no pipe, no
            // redirection: a terminal's foreground job).
            if child.is_linux() && flags & SPAWN_F_CONSOLE_IN != 0 && fds[0].kind == FD_CLOSED_KIND {
                fds[0] = StartupFd { kind: FD_CONSOLE, handle: 0 };
            }
            // Three kinds of child. One hosted by the ring-3 runtime gets the
            // startup block a native child gets (its descriptors and working
            // directory, the runtime keeps them) below the initial stack a
            // Linux binary reads. One under the in-kernel personality has its
            // descriptors and working directory put in the personality's
            // table. A native one gets the startup block alone.
            let wrote = if child.is_hosted() {
                write_hosted(
                    child, &argv[..al], argc, &env[..el], req.envc as usize, cwd, flags, &fds,
                )
            } else if child.is_linux() {
                crate::linux::proc_set_startup(ctid, &fds, cwd)
                    && child.write_linux_stack(
                        &argv[..al], argc, &env[..el], req.envc as usize,
                        &crate::linux::random16(),
                    )
            } else {
                child.write_startup(azos_abi::ushell::STARTUP_BLOCK_SIZE + al + el + cwd.len() + 32, &mut |base, out| {
                    layout_startup(out, base, &argv[..al], argc as u32, &env[..el], req.envc, cwd, flags, &fds)
                })
            };
            if !wrote {
                refusal.set(err(Errno::ENOMEM));
                return false;
            }
            if flags & SPAWN_F_DIE_WITH_PARENT != 0 {
                azos_sched::scheduler::set_die_with_parent(ctid);
            }
            // The console program, Linux: it reads the console, so console
            // input is claimed for it and lent to it before it runs.
            if console.is_some() && child.is_linux() {
                let _ = azos_drv_sys::uart::CONSOLE_RX.claim(ctid);
                let _ = azos_drv_sys::uart::CONSOLE_RX.lend(ctid, ctid);
            }
            // Wave 13: the foreground Linux job reads the console the caller
            // owns, for its life (a native child has no console read).
            if flags & SPAWN_F_CONSOLE_IN != 0 && child.is_linux() {
                if let Some(owner) = console_lender(me) {
                    let _ = azos_drv_sys::uart::CONSOLE_RX.lend(owner, ctid);
                }
            }
            true
        },
    );
    match rc {
        crate::spawn::SpawnEx::Started(tid) => {
            if let Some(f) = SPAWN_EX_HOOK.get() {
                f(&path_buf[..path_len], tid as u32);
            }
            tid as i64
        }
        crate::spawn::SpawnEx::Refused => {
            crate::handlers::record_exec_refused(SPAWN_REFUSED_ACTION_NO_LAUNCH, 0);
            refusal.get()
        }
        crate::spawn::SpawnEx::Aborted => refusal.get(),
        crate::spawn::SpawnEx::Failed(e) => e,
    }
}

/// A child hosted by the ring-3 runtime (Kconfig LINUX_RUNTIME,
/// `crate::foreign`): the startup block of a native child, with the
/// descriptors and the working directory and no strings, then the Linux
/// initial stack below it. `a1` carries the block's address at the runtime's
/// first instruction, where the runtime builds its descriptor table from it
/// (`azos_linux_rt::Runtime::init`); the Linux program never sees it.
#[allow(clippy::too_many_arguments)]
fn write_hosted(
    child: &mut azos_sched::spawn::SpawnPrepared,
    argv: &[u8],
    argc: usize,
    env: &[u8],
    envc: usize,
    cwd: &[u8],
    flags: u32,
    fds: &[StartupFd; STARTUP_FDS],
) -> bool {
    // `hosted-startup-canary`: no block, the runtime starts on its defaults.
    (cfg!(feature = "hosted-startup-canary")
        || child.write_startup(azos_abi::ushell::STARTUP_BLOCK_SIZE + cwd.len() + 8, &mut |base, out| {
            layout_startup(out, base, &[], 0, &[], 0, cwd, flags, fds)
        }))
        && child.write_linux_stack(argv, argc, env, envc, &crate::linux::random16())
}

/// Who may lend console input on `me`'s behalf: the input owner itself, or a
/// CLIENT of the owner, a task that holds a call capability (`WRITE`) on an
/// endpoint the owner serves. The Terminal object's shape: the terminal
/// server owns input, and the shell, its one client through `endpoint.term`,
/// starts the foreground Linux job that the server's input is lent to. The
/// authority is the capability (the `endpoint.term` call right the name
/// server lent it, from the shell's signed `imports`), not a
/// task id; the lend itself is still the owner's, one at a time
/// ([`azos_drv_sys::console_rx::RxOwner::lend`]), and it ends with the job.
/// Returns the OWNER's id (what `lend` checks), `None` if `me` is neither.
fn console_lender(me: u32) -> Option<u32> {
    let owner = azos_drv_sys::uart::CONSOLE_RX.owner();
    if owner == azos_drv_sys::console_rx::RX_OWNER_NONE || owner == azos_drv_sys::console_rx::RX_OWNER_KERNEL {
        return None;
    }
    if owner == me {
        return Some(owner);
    }
    (0..azos_ipc::endpoint::MAX_ENDPOINTS as u32).find_map(|i| {
        let h = azos_ipc::cap_store::with_table(me, |t| t.lookup(ty::ENDPOINT, i)).flatten()?;
        (azos_ipc::endpoint::endpoint_dest_for(me, h.as_raw()) == Ok(owner)).then_some(owner)
    })
}

// ── SYS_ALERT ─────────────────────────────────────────────────────

/// `SYS_ALERT`: see `azos_abi::syscall_nr::SYS_ALERT`.
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
