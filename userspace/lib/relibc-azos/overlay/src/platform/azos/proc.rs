// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Processes and threads: `posix_spawn` over `SYS_SPAWN_EX`, `waitpid` over
//! `DOMAIN_WAIT`, pthreads over `SYS_THREAD_CREATE`, futexes over
//! `SYS_FUTEX_WAIT`/`SYS_FUTEX_WAKE`.
//!
//! There is no `fork` and no `exec` on the native ABI: a program is created by
//! spawning an image, which `SpawnReq` describes completely (arguments,
//! environment, working directory and the descriptors the child starts with).

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::AtomicU32;

use azos_abi::{
    ushell::{
        Move, SpawnReq, MOVE_CONSOLE, SPAWN_ARGC_MAX, SPAWN_ARGV_MAX, SPAWN_CWD_MAX, SPAWN_ENVC_MAX,
        SPAWN_ENV_MAX, SPAWN_MAX_MOVES, SPAWN_REQ_VERSION, STARTUP_FDS,
    },
};

use super::{
    check, errno_of,
    fdtab::{self, Kind, OpenFile},
    fs, pure,
    time::now_ns,
};
use crate::{
    c_str::CStr,
    error::{Errno, Result},
    header::{
        errno::{E2BIG, EBADF, ECHILD, EINVAL, EMFILE, ENAMETOOLONG, ETIMEDOUT},
        fcntl::AT_FDCWD,
        spawn::{posix_spawn_file_actions_t, posix_spawnattr_t, Action},
        sys_wait::WNOHANG,
        time::timespec,
    },
    iter::NulTerminated,
    pthread::OsTid,
    platform::{
        environ_iter,
        types::{c_char, c_int, pid_t},
    },
};

// ── futex ────────────────────────────────────────────────────────────────────

pub(crate) unsafe fn futex_wait(addr: *mut u32, val: u32, deadline: Option<&timespec>) -> Result<()> {
    // The word is the futex's: only atomic accesses race on it.
    let word = unsafe { &*addr.cast::<AtomicU32>() };
    let timeout = match deadline {
        None => 0,
        Some(d) => {
            let at = (d.tv_sec as u64).saturating_mul(azos_abi::time::NS_PER_SEC).saturating_add(d.tv_nsec as u64);
            pure::futex_timeout(at, now_ns()).ok_or(Errno(ETIMEDOUT))?
        }
    };
    check(azos_libsys::futex_wait(word, val, timeout)).map(|_| ())
}

pub(crate) unsafe fn futex_wake(addr: *mut u32, num: u32) -> Result<u32> {
    let word = unsafe { &*addr.cast::<AtomicU32>() };
    check(azos_libsys::futex_wake(word, num)).map(|n| n as u32)
}

// ── threads ──────────────────────────────────────────────────────────────────

/// What `pthread::create` leaves on the new thread's stack, lowest address first
/// (its `push` order, reversed): the shim, the start routine and its argument,
/// the TCB and the synchronisation mutex.
const SHIM: usize = 0;

type Shim = unsafe extern "C" fn(usize, usize, usize, usize) -> !;

/// The thread's entry (`SYS_THREAD_CREATE` calls it with `(0, stack, arg)`): it
/// reads the shim and its four arguments from the words `rlct_clone` was given.
extern "C" fn thread_entry(_zero: u64, _sp: u64, words: u64) -> ! {
    let w = words as *const usize;
    // SAFETY: `words` is the stack `pthread::create` built, which outlives the thread.
    unsafe {
        let shim: Shim = core::mem::transmute(*w.add(SHIM));
        shim(*w.add(1), *w.add(2), *w.add(3), *w.add(4))
    }
}

/// The key relibc files a live thread under (\`OsTid\`): the address of its TCB.
/// The native \`SYS_GETPID\` names the process, also from a thread, and a thread
/// cannot learn its own task id; the TCB is unique per live thread and both the
/// creator (here) and the thread (\`current_os_tid\`) know it.
pub(crate) fn os_tid_of(tcb: usize) -> OsTid {
    OsTid { thread_id: tcb }
}

pub(crate) unsafe fn rlct_clone(stack: *mut usize) -> Result<OsTid> {
    // The thread's own frames grow down from the 16-byte aligned address at or
    // below the words, which stay above them.
    let sp = stack as usize & !15;
    let tls = unsafe { thread_pointer_for(stack) };
    check(azos_libsys::thread_create_with_tls(thread_entry, sp, stack as u64, core::ptr::null_mut(), tls))?;
    // words[3] is the new thread's TCB.
    Ok(os_tid_of(unsafe { *stack.add(3) }))
}

/// The thread pointer the kernel installs before the thread's first instruction.
/// On x86_64 ring 3 cannot set its own FS base, so the TCB's TLS end (its first
/// field) goes with the create call; on the other ISAs the thread's shim sets
/// `tp` / `TPIDR_EL0` itself (0 here: the thread starts with 0 until then).
unsafe fn thread_pointer_for(stack: *mut usize) -> u64 {
    if cfg!(target_arch = "x86_64") {
        // words[3] is the new TCB; `Tcb` is `repr(C)` with `tls_end` first.
        unsafe { *(*stack.add(3) as *const usize) as u64 }
    } else {
        0
    }
}

// ── wait ─────────────────────────────────────────────────────────────────────

pub(crate) fn waitpid(pid: pid_t, stat_loc: Option<crate::out::Out<c_int>>, options: c_int) -> Result<pid_t> {
    let mut stat_loc = stat_loc;
    loop {
        let mut code = 0i32;
        let r = if pid > 0 {
            azos_libsys::waitpid(pid as u32, &mut code)
        } else if pid == -1 {
            azos_libsys::wait_status(&mut code)
        } else {
            // A process group is not a native object.
            return Err(Errno(ECHILD));
        };
        match r {
            // "-1": no child has finished yet (the call polls).
            -1 if options & WNOHANG != 0 => return Ok(0),
            -1 => azos_libsys::sleep(1),
            r if r < 0 => return Err(errno_of(r)),
            tid => {
                if let Some(s) = stat_loc.as_mut() {
                    s.write(pure::wait_status(code));
                }
                return Ok(tid as pid_t);
            }
        }
    }
}

// ── spawn ────────────────────────────────────────────────────────────────────

fn blob<'a>(items: impl Iterator<Item = &'a [u8]>, max_n: usize, max_bytes: usize) -> Result<(Vec<u8>, u32)> {
    pure::cstr_blob(items, max_n, max_bytes).map_err(|_| Errno(E2BIG))
}

pub(crate) unsafe fn spawn(
    program: CStr,
    fac: Option<&posix_spawn_file_actions_t>,
    _fat: Option<&posix_spawnattr_t>,
    argv: NulTerminated<*mut c_char>,
    envp: Option<NulTerminated<*mut c_char>>,
) -> Result<pid_t> {
    let image = fs::resolve_cwd(program.to_bytes())?;

    let args: Vec<&[u8]> = argv.map(|a| unsafe { CStr::from_ptr(*a) }.to_bytes()).collect();
    let envs: Vec<&[u8]> = match envp {
        Some(e) => e.map(|v| unsafe { CStr::from_ptr(*v) }.to_bytes()).collect(),
        // No environment given: the child gets the caller's.
        None => environ_iter().map(|v| unsafe { CStr::from_ptr(v) }.to_bytes()).collect(),
    };
    let (argv_blob, argc) = blob(args.into_iter(), SPAWN_ARGC_MAX, SPAWN_ARGV_MAX)?;
    let (env_blob, envc) = blob(envs.into_iter(), SPAWN_ENVC_MAX, SPAWN_ENV_MAX)?;

    // The descriptors the child starts with: what the caller has on 0..8 and did
    // not mark close-on-exec, then the file actions, in order.
    let mut child: Vec<Option<Arc<OpenFile>>> = fdtab::inheritable();
    let mut cwd = fs::cwd_abs();
    if let Some(fac) = fac {
        for action in fac {
            match action {
                Action::Open { fd, path, flag, mode } => {
                    let slot = child_slot(fd)?;
                    let opened = fs::openat(AT_FDCWD, CStr::borrow(&path), flag, mode)?;
                    let file = fdtab::get(opened);
                    let _ = fdtab::close(opened);
                    child[slot] = Some(file?);
                }
                Action::Close(fd) => child[child_slot(fd)?] = None,
                Action::Dup2(from, to) => {
                    let to = child_slot(to)?;
                    // A small fd names what the child would have by now; a larger
                    // one is the caller's (the child inherits those too, but
                    // only 0..=7 can be handed over).
                    let file = match usize::try_from(from) {
                        Ok(f) if f < STARTUP_FDS => child[f].clone().ok_or(Errno(EBADF))?,
                        _ => fdtab::get(from)?,
                    };
                    child[to] = Some(file);
                }
                Action::Chdir(path) => cwd = fs::resolve_cwd(path.as_bytes())?,
                // Refused: a directory descriptor holds no directory (see `fs`).
                Action::FChdir(fd) => fs::fchdir(fd)?,
            }
        }
    }
    // The path, NUL included, must fit the request's working directory.
    if cwd.len() > SPAWN_CWD_MAX + 1 {
        return Err(Errno(ENAMETOOLONG));
    }

    let mut req = SpawnReq {
        version: SPAWN_REQ_VERSION,
        argv_ptr: if argv_blob.is_empty() { 0 } else { argv_blob.as_ptr() as u64 },
        argv_bytes: argv_blob.len() as u32,
        argc,
        env_ptr: if env_blob.is_empty() { 0 } else { env_blob.as_ptr() as u64 },
        env_bytes: env_blob.len() as u32,
        envc,
        cwd_ptr: cwd.as_ptr() as u64,
        ..SpawnReq::default()
    };
    let mut moved: Vec<Arc<OpenFile>> = Vec::new();
    // The pipe ends the child gets, with the region capability the move list
    // names (the kernel counts the ends for the child in the spawn).
    let mut pipes: Vec<(Arc<OpenFile>, u32)> = Vec::new();
    for (fd, f) in child.iter().enumerate() {
        let Some(f) = f else { continue };
        let handle = match f.kind {
            Kind::Console => MOVE_CONSOLE,
            Kind::File => f.handle,
            // A pipe end is shared, not moved: the region's capability goes in
            // the list (the kernel derives a copy) and this process keeps its
            // own end. The child's position names the end it gets, so a read
            // end may only go to fd 0 and a write end to the others.
            Kind::Pipe => {
                use azos_libsys::pipe::End;
                match (azos_libsys::pipe::end_of(f.handle), fd) {
                    (Some(End::Read), 0) | (Some(End::Write), 1..) => {}
                    (Some(_), _) => return Err(Errno(EINVAL)),
                    (None, _) => return Err(Errno(EBADF)),
                }
                match pipes.iter().find(|(p, _)| Arc::ptr_eq(p, f)) {
                    Some((_, cap)) => *cap,
                    None => match azos_libsys::pipe::region_of(f.handle) {
                        Ok((cap, _)) => {
                            pipes.push((f.clone(), cap));
                            cap
                        }
                        Err(e) => return Err(Errno((-e) as c_int)),
                    },
                }
            }
            // A directory is a path here, not a handle a child can be given.
            Kind::Dir => continue,
        };
        if req.nmoves as usize == SPAWN_MAX_MOVES {
            return Err(Errno(EMFILE));
        }
        req.moves[req.nmoves as usize] = Move { child_fd: fd as u32, handle, perms: 0, _pad: 0 };
        req.nmoves += 1;
        if handle != MOVE_CONSOLE && f.kind == Kind::File && !moved.iter().any(|m| Arc::ptr_eq(m, f)) {
            moved.push(f.clone());
        }
    }

    let tid = check(azos_libsys::spawn_ex(&image, Some(&req)))?;
    // The files' handles were moved: they are the child's now. A pipe end was
    // shared and stays this process's.
    for f in moved {
        f.mark_gone();
    }
    Ok(tid as pid_t)
}

/// The child fd a file action names: only 0..=7 reach a child.
fn child_slot(fd: c_int) -> Result<usize> {
    usize::try_from(fd).ok().filter(|&f| f < STARTUP_FDS).ok_or(Errno(EMFILE))
}
