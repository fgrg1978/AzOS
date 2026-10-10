// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Linux personality (RFC-0047, owner decisions P1-P6): in-kernel
//! translation of Linux syscalls for the tasks whose signed topology row says
//! `abi = "linux"`, behind Kconfig `LINUX_ABI`.
//!
//! # Where it sits
//!
//! `scheduler::current_syscall_verdict` answers `FilterVerdict::Linux` for a
//! Linux task (one bit of the per-CPU filter word, set at the context switch
//! from `Task::abi`), and `syscall_dispatch_out` hands the trap here instead
//! of to the native table. A native task never reaches this file, and with
//! `LINUX_ABI` off the bit is never set and the branch folds away.
//!
//! # What is preserved
//!
//! - **Authority.** Every call that touches a kernel object goes through the
//!   native handler that does it for a native task, with the task's own
//!   capability table: a file is opened by the same tree gate and minted as
//!   the same `Cap<File>`, a pipe is the same `Cap<Pipe>`. A Linux row holds
//!   no hardware capability (the topology refuses one), so a Linux image has
//!   exactly the authority its row gives it and nothing the translation adds.
//! - **Seccomp after translation (P5).** Before each native call this asks
//!   the task's filter about the NATIVE number ([`reach`]), and a refusal
//!   kills the task as it would a native one. The profile of a Linux image
//!   lists the native numbers `azos_linux_abi::TABLE` says its calls
//!   reach; `tests/host/seccomp-tests` derives it from the source.
//!
//! # What the personality keeps
//!
//! Per Linux task, in a small pool keyed by TID ([`PROCS`]): the descriptor
//! table (small integers onto console / `Cap<File>` / `Cap<Pipe>` handles /
//! open directories), the working directory, the signal actions and mask
//! (state only: no delivery yet, RFC-0047 P3 is a later stage), and the
//! umask. The pool entry is written at spawn ([`proc_init`],
//! [`proc_set_startup`]) and dropped at `exit_group`; an entry whose task is
//! gone is reused.
//!
//! `clone` in the fork and vfork shapes ([`sys_clone`]: the child is seeded
//! from its row and shares the parent's open descriptions) and `execve` of
//! an image of the caller's own row ([`sys_execve`]) are answered. Since
//! wave 13 `clone` also makes threads ([`clone_thread`]), with `futex`,
//! `set_tid_address`, `exit` (the thread) and `exit_group` (the process):
//! the personality entry is the process's, keyed by its id (the group
//! leader's TID), and every thread reaches it.
//!
//! # Not answered yet
//!
//! `posix_spawn`'s `CLONE_VM | CLONE_VFORK` child with a stack, requeue and
//! priority-inheritance futexes, and everything outside
//! `azos_linux_abi::TABLE`, which answers `-ENOSYS` and is reported.
//! (`mprotect`, signal delivery and console input are answered since wave 13.)

use azos_linux_abi as lx;
use azos_linux_abi::errno as le;
use azos_linux_abi::nr;
use azos_sched::filter::FilterVerdict;
use azos_sync::SpinLock;

use crate::file_ops::file_ops;
use azos_abi::syscall_nr as k;
use azos_linux_abi::signal as sig;
use azos_sched::scheduler::signal as sigst;

/// Linux tasks alive at once.
const PROCS: usize = 8;
/// Descriptors per Linux task (0..FDS).
const FDS: usize = 16;
/// Open directories per Linux task.
const DIRS: usize = 4;
/// Longest directory path kept for an open directory.
const DIR_PATH_MAX: usize = 96;
/// Longest working directory.
const CWD_MAX: usize = 64;
/// Longest path an open/stat call resolves.
const PATH_MAX: usize = 256;
/// Bytes one read, write, readv or writev moves at most (at most the native
/// clamp, 4096). Kconfig `LINUX_IO_MAX`.
const IO_MAX: usize = azos_limits::LINUX_IO_MAX;
/// Signals with an action slot (1..=64).
const NSIG: usize = 64;
/// Longest image path `/proc/self/exe` resolves to.
const EXE_MAX: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Closed,
    Console,
    Handle,
    Dir,
}

#[derive(Clone, Copy, Debug)]
struct FdEnt {
    kind: Kind,
    /// The `Cap<File>`/`Cap<Pipe>` handle, for `Handle`.
    handle: u32,
    /// The directory slot, for `Dir`.
    dir: u8,
    cloexec: bool,
    nonblock: bool,
    /// The Linux access mode it was opened with (0, 1, 2).
    accmode: u8,
}

const FD_CLOSED: FdEnt = FdEnt { kind: Kind::Closed, handle: 0, dir: 0, cloexec: false, nonblock: false, accmode: 0 };
const FD_CONSOLE: FdEnt = FdEnt { kind: Kind::Console, handle: 0, dir: 0, cloexec: false, nonblock: false, accmode: 2 };

#[derive(Clone, Copy)]
struct DirEnt {
    used: bool,
    len: u8,
    /// The index the next `getdents64` reads.
    next: u32,
    path: [u8; DIR_PATH_MAX],
}

const DIR_FREE: DirEnt = DirEnt { used: false, len: 0, next: 0, path: [0; DIR_PATH_MAX] };

struct Proc {
    /// 0: free.
    tid: u32,
    fds: [FdEnt; FDS],
    dirs: [DirEnt; DIRS],
    cwd: [u8; CWD_MAX],
    cwd_len: u8,
    act: [lx::KSigaction; NSIG],
    /// `rt_sigsuspend`'s caller's own mask, put back when the handler that
    /// ended the wait returns (it is the mask its frame saves).
    suspend_saved: Option<u64>,
    umask: u32,
    /// The topology row (image name) the task runs under: what a forked
    /// child is reseeded from, and the only row `execve` may enter.
    row: [u8; 16],
    row_len: u8,
    /// The image's path, what `/proc/self/exe` names (BusyBox's applets
    /// re-execute it).
    exe: [u8; EXE_MAX],
    exe_len: u8,
    /// Unanswered calls reported so far (bounded: a loop over an unanswered
    /// call must not flood the console).
    reported: u8,
}

const KSA_DFL: lx::KSigaction = lx::KSigaction { handler: 0, flags: 0, restorer: 0, mask: 0 };

const PROC_FREE: Proc = Proc {
    tid: 0,
    fds: [FD_CLOSED; FDS],
    dirs: [DIR_FREE; DIRS],
    cwd: [0; CWD_MAX],
    cwd_len: 0,
    act: [KSA_DFL; NSIG],
    suspend_saved: None,
    umask: 0o022,
    row: [0; 16],
    row_len: 0,
    exe: [0; EXE_MAX],
    exe_len: 0,
    reported: 0,
};

static TABLE: SpinLock<[Proc; PROCS]> = SpinLock::new([PROC_FREE; PROCS]);

fn arch() -> lx::Arch {
    lx::Arch::native()
}

/// Run `f` on the current task's entry. `None` when it has none (a Linux
/// task always has one: a spawn that cannot give it one is refused).
fn with_me<R>(f: impl FnOnce(&mut Proc) -> R) -> Option<R> {
    // Wave 13: one entry per process; every thread of it reaches it.
    let me = azos_sched::current_proc_tid();
    let mut t = TABLE.lock();
    t.iter_mut().find(|p| p.tid == me && me != 0).map(f)
}

/// RFC-0047: give Linux child `tid` of row `row` its personality entry: the
/// console on descriptors 0, 1 and 2, working directory `/`. `false` when the
/// pool is full of live Linux tasks; the spawn is then refused.
pub fn proc_init(tid: u32, row: &str, exe: &[u8]) -> bool {
    if row.len() > 16 || exe.len() > EXE_MAX {
        return false;
    }
    let mut t = TABLE.lock();
    let slot = t.iter().position(|p| p.tid == tid).or_else(|| {
        t.iter().position(|p| p.tid == 0 || azos_sched::idx_for_tid(p.tid).is_none())
    });
    let Some(i) = slot else { return false };
    let p = &mut t[i];
    *p = PROC_FREE;
    p.tid = tid;
    p.fds[0] = FD_CONSOLE;
    p.fds[1] = FD_CONSOLE;
    p.fds[2] = FD_CONSOLE;
    p.cwd[0] = b'/';
    p.cwd_len = 1;
    p.row[..row.len()].copy_from_slice(row.as_bytes());
    p.row_len = row.len() as u8;
    p.exe[..exe.len()].copy_from_slice(exe);
    p.exe_len = exe.len() as u8;
    // Wave 13: its signal words, every disposition the default.
    sigst::attach(tid, 0, ignored_of(&p.act));
    true
}

/// RFC-0055 meets RFC-0047: the descriptors a `SYS_SPAWN_EX` move list gave
/// Linux child `tid` (console or a moved handle per fd 0..=7), and its
/// working directory. `false` when it has no entry.
pub fn proc_set_startup(
    tid: u32,
    fds: &[azos_abi::ushell::StartupFd; azos_abi::ushell::STARTUP_FDS],
    cwd: &[u8],
) -> bool {
    use azos_abi::ushell::{FD_CONSOLE as SFD_CONSOLE, FD_HANDLE as SFD_HANDLE};
    let mut t = TABLE.lock();
    let Some(p) = t.iter_mut().find(|p| p.tid == tid && tid != 0) else { return false };
    for (i, f) in fds.iter().enumerate() {
        p.fds[i] = match f.kind {
            SFD_CONSOLE => FD_CONSOLE,
            SFD_HANDLE => FdEnt { kind: Kind::Handle, handle: f.handle, accmode: 2, ..FD_CLOSED },
            _ => FD_CLOSED,
        };
    }
    if !cwd.is_empty() && cwd[0] == b'/' && cwd.len() <= CWD_MAX {
        p.cwd[..cwd.len()].copy_from_slice(cwd);
        p.cwd_len = cwd.len() as u8;
    }
    true
}

/// Does the topology row named `image` say `abi = "linux"`? What exec checks
/// (through `handlers::set_exec_linux_row`) to refuse a Linux image: one
/// starts only by spawn, which tags it before it runs.
pub fn row_is_linux(image: &str) -> bool {
    azos_topology::get()
        .is_some_and(|t| t.abi_of(image.as_bytes()) == azos_topology::TaskAbi::Linux)
}

/// 16 bytes for `AT_RANDOM`: from the kernel entropy pool when it is
/// seeded. Before that, a mix of the timebase and the TID: `AT_RANDOM`
/// seeds a stack-protector canary and hash seeds, and an unseeded pool must
/// not stop a spawn, but those bytes are not secret.
pub fn random16() -> [u8; 16] {
    let mut b = [0u8; 16];
    if crate::entropy::fill_kernel(&mut b) {
        return b;
    }
    let mut x = azos_drv_sys::timebase::now() ^ ((azos_sched::current_task_tid() as u64) << 32);
    for chunk in b.chunks_mut(8) {
        // splitmix64
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
    }
    b
}

// ── Seccomp after translation ───────────────────────────────────────────────

/// Ask the task's filter about native call `num` before the translation
/// makes it. Refused, the task is killed exactly as a native task would be.
fn reach(num: u64) {
    match azos_sched::scheduler::current_native_verdict(num) {
        FilterVerdict::Allow => {}
        FilterVerdict::Audit => crate::handlers::record_seccomp_audit(num as u16),
        FilterVerdict::Deny | FilterVerdict::Linux => crate::handlers::seccomp_deny_kill(num),
    }
}

// ── Small helpers ───────────────────────────────────────────────────────────

fn neg(e: i64) -> i64 {
    -e
}

fn put_user(ptr: u64, bytes: &[u8]) -> bool {
    ptr != 0 && azos_sched::copy_to_user(ptr as usize, bytes.as_ptr(), bytes.len())
}

fn get_user(ptr: u64, bytes: &mut [u8]) -> bool {
    ptr != 0 && azos_sched::copy_from_user(bytes.as_mut_ptr(), ptr as usize, bytes.len())
}

fn get_u64(ptr: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    get_user(ptr, &mut b).then(|| u64::from_le_bytes(b))
}

/// Copy a NUL-terminated user path into `buf`; its length, or a Linux errno.
fn user_path(ptr: u64, buf: &mut [u8; PATH_MAX]) -> Result<usize, i64> {
    if ptr == 0 {
        return Err(neg(le::EFAULT));
    }
    if azos_sched::copy_cstr_from_user(&mut buf[..], ptr as usize).is_none() {
        return Err(neg(le::EFAULT));
    }
    match buf.iter().position(|&b| b == 0) {
        Some(0) => Err(neg(le::ENOENT)),
        Some(n) => Ok(n),
        None => Err(neg(le::ENAMETOOLONG)),
    }
}

fn fd_get(fd: u64) -> Result<FdEnt, i64> {
    if fd >= FDS as u64 {
        return Err(neg(le::EBADF));
    }
    match with_me(|p| p.fds[fd as usize]) {
        Some(e) if e.kind != Kind::Closed => Ok(e),
        _ => Err(neg(le::EBADF)),
    }
}

/// The lowest closed descriptor at or above `min`, claimed with `ent`.
fn fd_alloc(min: usize, ent: FdEnt) -> Result<usize, i64> {
    with_me(|p| {
        let i = (min..FDS).find(|&i| p.fds[i].kind == Kind::Closed)?;
        p.fds[i] = ent;
        Some(i)
    })
    .flatten()
    .ok_or(neg(le::EMFILE))
}

/// Resolve `path` against `dirfd` (`AT_FDCWD` or an open directory) into
/// `out`; the absolute path's length.
fn resolve(dirfd: u64, path: &[u8], out: &mut [u8; PATH_MAX]) -> Result<usize, i64> {
    // `/proc` is not mounted for a Linux task; its one name a static
    // program relies on is its own image.
    if path == b"/proc/self/exe" {
        let (e, n) = with_me(|p| (p.exe, p.exe_len as usize)).ok_or(neg(le::EBADF))?;
        if n == 0 {
            return Err(neg(le::ENOENT));
        }
        out[..n].copy_from_slice(&e[..n]);
        return Ok(n);
    }
    let mut base = [0u8; DIR_PATH_MAX];
    let base_len;
    if path.first() == Some(&b'/') || dirfd == lx::AT_FDCWD {
        let (c, n) = with_me(|p| (p.cwd, p.cwd_len as usize)).ok_or(neg(le::EBADF))?;
        base[..n].copy_from_slice(&c[..n]);
        base_len = n;
    } else {
        let e = fd_get(dirfd)?;
        if e.kind != Kind::Dir {
            return Err(neg(le::ENOTDIR));
        }
        let d = with_me(|p| p.dirs[e.dir as usize]).ok_or(neg(le::EBADF))?;
        base[..d.len as usize].copy_from_slice(&d.path[..d.len as usize]);
        base_len = d.len as usize;
    }
    lx::join_path(&base[..base_len], path, out).ok_or(neg(le::ENAMETOOLONG))
}

/// Is `path` a directory? `stat` first; a mount point the VFS cannot stat
/// counts as one when it lists.
fn is_dir(path: &[u8]) -> Result<bool, i64> {
    let ops = file_ops().ok_or(neg(le::EIO))?;
    reach(k::SYS_STAT);
    match ops.stat(path) {
        Ok(st) => Ok(st.mode & lx::mode::S_IFMT == lx::mode::S_IFDIR),
        Err(e) => {
            reach(k::SYS_READDIR);
            if ops.readdir(path, 0).is_some() {
                Ok(true)
            } else {
                Err(lx::errno_from_native(e, le::ENOENT))
            }
        }
    }
}

// ── The dispatcher ──────────────────────────────────────────────────────────

/// RFC-0047: where a call whose filter word is 0 arrives. A Linux task's
/// calls go to [`dispatch`]; anything else (no task current, a native slot
/// whose word was not published) gets the native verdict and handler.
#[allow(clippy::too_many_arguments)]
pub fn entry(
    num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
    sepc: u64, user_sp: u64, regs: &azos_sched::UserRegs,
    out: &mut crate::SyscallOut,
) -> i64 {
    match azos_sched::scheduler::zero_word_native_verdict(num) {
        None => dispatch(num, a0, a1, a2, a3, a4, a5, sepc, user_sp, regs, out),
        Some(v) => {
            match v {
                FilterVerdict::Allow => {}
                FilterVerdict::Audit => crate::handlers::record_seccomp_audit(num as u16),
                FilterVerdict::Deny | FilterVerdict::Linux => crate::handlers::seccomp_deny_kill(num),
            }
            crate::dispatch::dispatch_native_checked(num, a0, a1, a2, a3, a4, a5, sepc, user_sp, regs, out)
        }
    }
}

/// Answer Linux call `num` for the current (Linux) task.
///
/// The identity calls are answered here, before [`dispatch_slow`], for the
/// reason `syscall_dispatch_out` has its own fast path: the big `match`
/// inlines every arm's locals into one frame, and the cheapest call should
/// not pay its prologue.
#[allow(clippy::too_many_arguments)]
pub fn dispatch(
    num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
    sepc: u64, user_sp: u64, regs: &azos_sched::UserRegs,
    out: &mut crate::SyscallOut,
) -> i64 {
    let _ = out;
    match num {
        // Wave 13: a process is a thread group; its id is its leader's TID.
        nr::GETPID => azos_sched::current_proc_tid() as i64,
        nr::GETTID => azos_sched::current_task_tid() as i64,
        // The word this thread's exit clears and wakes (musl points it at its
        // thread-list lock right before a thread exits).
        nr::SET_TID_ADDRESS => {
            azos_sched::group::set_current_clear_tid(a0);
            azos_sched::current_task_tid() as i64
        }
        nr::FUTEX => sys_futex(a0, a1, a2, a3, a4, a5),
        // No users on this kernel (POSIX subset rule 3): everyone is 0.
        nr::GETUID | nr::GETEUID | nr::GETGID | nr::GETEGID => 0,
        nr::CLONE => sys_clone(a0, a1, a2, a3, a4, sepc, user_sp, regs),
        nr::RT_SIGRETURN => sys_rt_sigreturn(user_sp),
        // Wave 13: out of the big `match`, for the reason the identity calls
        // are (a mask change is the cheapest signal call, and the most made).
        nr::RT_SIGPROCMASK => sys_rt_sigprocmask(a0, a1, a2, a3),
        _ => {
            let r = dispatch_slow(num, a0, a1, a2, a3, a4);
            // Wave 13: a restartable call a signal interrupted remembers its
            // first argument; the delivery at this same return decides
            // between `-EINTR` and running the call again (`SA_RESTART`).
            if r == -le::EINTR && matches!(num, nr::READ | nr::READV | nr::WRITE | nr::WRITEV | nr::WAIT4)
                && sigst::current_deliverable()
            {
                sigst::set_current_restart(a0);
            }
            r
        }
    }
}

/// Everything but the identity calls. `#[inline(never)]` is structural: see
/// [`dispatch`].
#[inline(never)]
fn dispatch_slow(num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    match num {
        nr::WRITE => sys_write(a0, a1, a2),
        nr::READ => sys_read(a0, a1, a2),
        nr::WRITEV => sys_rwv(a0, a1, a2, true),
        nr::READV => sys_rwv(a0, a1, a2, false),
        nr::OPENAT => sys_openat(a0, a1, a2),
        nr::CLOSE => sys_close(a0),
        nr::FSTAT => sys_fstat(a0, a1),
        nr::NEWFSTATAT => sys_newfstatat(a0, a1, a2, a3),
        nr::LSEEK => sys_lseek(a0, a1, a2),
        nr::GETDENTS64 => sys_getdents64(a0, a1, a2),
        nr::PIPE2 => sys_pipe2(a0, a1),
        nr::DUP => sys_dup3(a0, u64::MAX, 0),
        nr::DUP3 => sys_dup3(a0, a1, a2),
        nr::FCNTL => sys_fcntl(a0, a1, a2),
        nr::IOCTL => sys_ioctl(a0, a1, a2),
        nr::GETCWD => sys_getcwd(a0, a1),
        nr::CHDIR => sys_chdir(a0),
        nr::EXIT => sys_exit_thread(a0),
        nr::EXIT_GROUP => sys_exit_group(a0),
        nr::WAIT4 => sys_wait4(a0, a1, a2, a3),
        nr::EXECVE => sys_execve(a0, a1, a2),
        nr::BRK => {
            reach(k::SYS_BRK);
            crate::handlers::sys_brk(a0)
        }
        nr::MMAP => sys_mmap(a0, a1, a2, a3, a4),
        nr::MPROTECT => {
            // Wave 13 (security): exactly PROT_READ/PROT_WRITE; PROT_EXEC refused.
            reach(k::SYS_MMAP);
            lx::errno_from_native(crate::handlers::sys_mprotect(a0, a1, a2), le::ENOMEM)
        }
        nr::MUNMAP => {
            reach(k::SYS_MUNMAP);
            lx::errno_from_native(crate::handlers::sys_munmap(a0, a1), le::EINVAL)
        }
        nr::CLOCK_GETTIME => sys_clock_gettime(a0, a1),
        nr::NANOSLEEP => sys_nanosleep(a0, a1),
        nr::SCHED_YIELD => {
            reach(k::SYS_YIELD);
            azos_sched::task_yield();
            0
        }
        nr::RT_SIGACTION => sys_rt_sigaction(a0, a1, a2, a3),
        nr::RT_SIGPENDING => sys_rt_sigpending(a0, a1),
        nr::RT_SIGSUSPEND => sys_rt_sigsuspend(a0, a1),
        nr::SIGALTSTACK => sys_sigaltstack(a0, a1),
        nr::KILL => sys_kill(a0 as i64, a1),
        nr::TKILL => sys_tkill(0, a0 as i64, a1),
        nr::TGKILL => {
            if (a0 as i64) <= 0 {
                return neg(le::EINVAL);
            }
            sys_tkill(a0 as i64, a1 as i64, a2)
        }
        nr::UNAME => {
            let u = lx::utsname_bytes(arch(), b"azos");
            if put_user(a0, &u) { 0 } else { neg(le::EFAULT) }
        }
        nr::UMASK => with_me(|p| {
            let old = p.umask;
            p.umask = (a0 & 0o777) as u32;
            old as i64
        })
        .unwrap_or(0o022),
        nr::GETPPID => azos_sched::scheduler::current_task_parent_tid() as i64,
        // Wave 15: the head of this thread's robust futex list, walked at its
        // exit (`scheduler::robust_list_exit`). Linux's only length, else
        // `-EINVAL`; the address is checked when it is walked.
        nr::SET_ROBUST_LIST => {
            if a1 != lx::robust::HEAD_LEN {
                return neg(le::EINVAL);
            }
            azos_sched::group::set_current_robust_list(a0);
            0
        }
        nr::SCHED_GETAFFINITY => {
            // `sched_getaffinity(pid, size, mask)`: one CPU set; the kernel
            // answers the bytes written (a `long`).
            if a1 < 8 {
                return neg(le::EINVAL);
            }
            if put_user(a2, &1u64.to_le_bytes()) { 8 } else { neg(le::EFAULT) }
        }
        nr::PRCTL => match a0 {
            // PR_SET_NAME, PR_GET_NAME: the task's name is its image's.
            15 => 0,
            16 => if put_user(a1, &[0u8; 16]) { 0 } else { neg(le::EFAULT) },
            // PR_SET_CHILD_SUBREAPER, PR_GET_CHILD_SUBREAPER (wave 13): the
            // same mark as the native `SYS_TASK_SUBREAPER`.
            36 => {
                azos_sched::scheduler::task_subreaper(Some(a1 != 0));
                0
            }
            37 => {
                let on = azos_sched::scheduler::task_subreaper(None) as i32;
                if put_user(a1, &on.to_le_bytes()) { 0 } else { neg(le::EFAULT) }
            }
            _ => neg(le::EINVAL),
        },
        _ => unanswered(num),
    }
}

/// A Linux call the personality does not answer: `-ENOSYS`, reported on the
/// console the first few times per task, never passed to a native handler.
fn unanswered(num: u64) -> i64 {
    let first = with_me(|p| {
        let f = p.reported < 16;
        p.reported = p.reported.saturating_add(1);
        f
    })
    .unwrap_or(false);
    if first {
        azos_drv_sys::kprintln!(
            "[LINUX] tid={} syscall {} not answered by the personality: -ENOSYS",
            azos_sched::current_task_tid(), num,
        );
    }
    neg(le::ENOSYS)
}

// ── I/O ─────────────────────────────────────────────────────────────────────

fn sys_write(fd: u64, buf: u64, count: u64) -> i64 {
    let e = match fd_get(fd) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let n = count.min(IO_MAX as u64);
    match e.kind {
        Kind::Console => {
            reach(k::SYS_WRITE);
            lx::errno_from_native(crate::handlers::sys_write(1, buf, n), le::EFAULT)
        }
        Kind::Handle => {
            reach(k::SYS_FILE_WRITE_TYPED);
            let pipe = crate::ushell::is_pipe_handle(e.handle as u64);
            let r = if pipe {
                crate::ushell::sys_pipe_write(e.handle as u64, buf, n)
            } else {
                crate::handlers::sys_file_write_typed(e.handle as u64, buf, n)
            };
            let r = lx::errno_from_native(r, le::EIO);
            // Wave 13: a write to a pipe nobody reads raises SIGPIPE (its
            // default ends the writer, 128 + 13) and still answers -EPIPE.
            if pipe && r == -le::EPIPE && !cfg!(feature = "linux-sigpipe-canary") {
                let me = azos_sched::current_task_tid();
                let _ = sigst::post(me, lx::sig::SIGPIPE as u32, 0);
            }
            r
        }
        Kind::Dir => neg(le::EISDIR),
        Kind::Closed => neg(le::EBADF),
    }
}

fn sys_read(fd: u64, buf: u64, count: u64) -> i64 {
    let e = match fd_get(fd) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let n = count.min(IO_MAX as u64);
    match e.kind {
        // Console input belongs to `SH.ELF` (RFC-0055: one owner); wave 13:
        // the shell lends it to its foreground Linux job, which reads it
        // through the line discipline. Anyone else sees end of file.
        Kind::Console => console_read(buf, n),
        Kind::Handle => {
            reach(k::SYS_FILE_READ_TYPED);
            let r = if crate::ushell::is_pipe_handle(e.handle as u64) {
                crate::ushell::sys_pipe_read(e.handle as u64, buf, n)
            } else {
                crate::handlers::sys_file_read_typed(e.handle as u64, buf, n)
            };
            lx::errno_from_native(r, le::EIO)
        }
        Kind::Dir => neg(le::EISDIR),
        Kind::Closed => neg(le::EBADF),
    }
}

/// The console's line discipline (one console). `seen` is the console
/// interrupt count the line was edited under: a `^C` since then drops it.
struct Console {
    ld: sig::LineDisc,
    seen: u32,
}

static CONSOLE: SpinLock<Console> = SpinLock::new(Console { ld: sig::LineDisc::new(), seen: 0 });

/// May the current task read the console? Input is lent to it or to one of
/// its ancestors (the shell's foreground job and what that job runs).
fn console_lent_to_me() -> bool {
    let lendee = azos_drv_sys::uart::CONSOLE_RX.lendee();
    let me = azos_sched::current_task_tid();
    lendee != 0 && (lendee == me || azos_sched::scheduler::task_is_ancestor(lendee, me))
}

/// Wave 13: `read` on a console descriptor. Without the lend, end of file
/// (as before). With it: complete lines from the canonical line discipline,
/// typed bytes echoed; blocks on the RX interrupt (a clock ceiling bounds a
/// lost wake) and ends with `-EINTR` when a signal is to be delivered.
fn console_read(buf: u64, n: u64) -> i64 {
    let mut out = [0u8; sig::LINE_MAX];
    let want = (n as usize).min(sig::LINE_MAX);
    let r = console_read_k(&mut out[..want]);
    if r > 0 && !put_user(buf, &out[..r as usize]) {
        return neg(le::EFAULT);
    }
    r
}

/// [`console_read`] into a kernel buffer (at most a line): its count, 0 for
/// end of file, or a negative errno. `readv`'s source too (K2).
fn console_read_k(out: &mut [u8]) -> i64 {
    if out.is_empty() || cfg!(feature = "linux-console-eof-canary") || !console_lent_to_me() {
        return 0;
    }
    reach(k::SYS_CONSOLE_WAIT);
    use azos_drv_sys::uart;
    let me = azos_sched::current_task_tid();
    let want = out.len().min(sig::LINE_MAX);
    loop {
        // At most 16 input bytes per hold of the lock, their echo (at most
        // 4 bytes each) kept here and written after the lock is dropped: the
        // console write may wait for the TX ring, never under this lock.
        let mut echo = [0u8; 64];
        let mut ne = 0usize;
        let mut more = false;
        let got = {
            let mut c = CONSOLE.lock();
            let seq = uart::intr_seq();
            if seq != c.seen {
                c.seen = seq;
                c.ld.flush_all();
            }
            let mut raised = 0u64;
            let mut fed = 0;
            while uart::can_read() {
                if fed == 16 {
                    more = true;
                    break;
                }
                let mut b = [0u8; 1];
                if uart::rx_read(&mut b) == 0 {
                    break;
                }
                fed += 1;
                let mut put = |e: &[u8]| {
                    let k = e.len().min(echo.len() - ne);
                    echo[ne..ne + k].copy_from_slice(&e[..k]);
                    ne += k;
                };
                if let sig::Feed::Signal(s) = c.ld.feed(b[0], &mut put) {
                    raised = s;
                }
            }
            if raised != 0 {
                // `^C`/`^\\` read here (the RX interrupt was not the one to
                // see it): the same signal, to the same tasks.
                drop(c);
                console_signal(raised as u32);
                None
            } else {
                c.ld.take(&mut out[..want])
            }
        };
        if ne > 0 {
            uart::console_write(&echo[..ne]);
        }
        if more && got.is_none() {
            continue;
        }
        if let Some(k) = got {
            return k as i64;
        }
        if crate::ushell::stop_requested() {
            return neg(le::EINTR);
        }
        if !console_lent_to_me() {
            return 0;
        }
        let t = azos_drv_sys::timebase::now();
        if uart::rx_wake_wired() {
            uart::rx_waiter_arm(me);
            if uart::can_read() {
                uart::rx_waiter_disarm();
                continue;
            }
            crate::ushell::park_until(t.saturating_add(crate::ushell::ms_ticks(1000)));
            uart::rx_waiter_disarm();
        } else {
            crate::ushell::park_until(t.saturating_add(crate::ushell::ms_ticks(20)));
        }
    }
}

/// Signal `s` to the task console input is lent to and its descendants (the
/// foreground job, as a terminal's process group). From the console's RX
/// interrupt (`^C`), or from a reader that found the character itself.
/// Lock-free: the posts are atomics and TID wakes.
pub fn console_signal(s: u32) {
    let lendee = azos_drv_sys::uart::CONSOLE_RX.lendee();
    if lendee == 0 {
        return;
    }
    let _ = sigst::post(lendee, s, 0);
    let mut below = [0u32; 32];
    let found = azos_sched::scheduler::descendants_of(lendee, &mut below).min(below.len());
    // Processes only: a thread is reached through its process.
    for &t in &below[..found] {
        if azos_sched::group::proc_tid(t) == t {
            let _ = sigst::post(t, s, 0);
        }
    }
}

/// The calling thread's memory, for the iovec walk.
struct UserIov;

impl lx::iov::IovMem for UserIov {
    fn word(&mut self, addr: u64) -> Option<u64> {
        get_u64(addr)
    }
    fn copy_in(&mut self, dst: &mut [u8], base: u64) -> bool {
        get_user(base, dst)
    }
    fn copy_out(&mut self, base: u64, src: &[u8]) -> bool {
        put_user(base, src)
    }
    fn writable(&mut self, base: u64, len: usize) -> bool {
        base != 0 && azos_sched::user_range_prepare_write(base as usize, len)
    }
}

/// `readv`/`writev` (K2): ONE transfer per call, as Linux. `writev` gathers
/// the segments into one bounce of [`IO_MAX`] bytes and makes one typed
/// write: one console line under the ring-3 writers' lock, one pipe write
/// (whole or waiting whole up to `PIPE_BUF`), one file write under the
/// description's position lock. So no other writer of the same description
/// lands between two segments. `readv` makes one read and scatters it.
/// The walk itself, and its checks, are `azos_linux_abi::iov`.
fn sys_rwv(fd: u64, iov: u64, cnt: u64, write: bool) -> i64 {
    let e = match fd_get(fd) {
        Ok(e) => e,
        Err(r) => return r,
    };
    match e.kind {
        Kind::Dir => return neg(le::EISDIR),
        Kind::Closed => return neg(le::EBADF),
        Kind::Console | Kind::Handle => {}
    }
    let mut k = core::mem::MaybeUninit::<[u8; IO_MAX]>::uninit();
    let buf = crate::handlers::bounce_zeroed(&mut k, IO_MAX);
    if write {
        lx::iov::writev(&mut UserIov, iov, cnt, buf, |b| write_kbuf(&e, b))
    } else {
        lx::iov::readv(&mut UserIov, iov, cnt, buf, |b| read_kbuf(&e, b))
    }
}

/// One typed write of kernel bytes to the descriptor `e` (Console or Handle).
fn write_kbuf(e: &FdEnt, b: &[u8]) -> i64 {
    match e.kind {
        Kind::Console => {
            reach(k::SYS_WRITE);
            azos_drv_sys::uart::console_write_ring3(b);
            b.len() as i64
        }
        Kind::Handle => {
            reach(k::SYS_FILE_WRITE_TYPED);
            let pipe = crate::ushell::is_pipe_handle(e.handle as u64);
            let r = if pipe {
                crate::ushell::pipe_write_kbuf(e.handle as u64, b)
            } else {
                crate::handlers::file_write_typed_kbuf(e.handle as u64, b)
            };
            let r = lx::errno_from_native(r, le::EIO);
            // As `sys_write`: a pipe nobody reads raises SIGPIPE.
            if pipe && r == -le::EPIPE && !cfg!(feature = "linux-sigpipe-canary") {
                let me = azos_sched::current_task_tid();
                let _ = sigst::post(me, lx::sig::SIGPIPE as u32, 0);
            }
            r
        }
        Kind::Dir => neg(le::EISDIR),
        Kind::Closed => neg(le::EBADF),
    }
}

/// One typed read into a kernel buffer from the descriptor `e`.
fn read_kbuf(e: &FdEnt, b: &mut [u8]) -> i64 {
    match e.kind {
        Kind::Console => console_read_k(b),
        Kind::Handle => {
            reach(k::SYS_FILE_READ_TYPED);
            let r = if crate::ushell::is_pipe_handle(e.handle as u64) {
                crate::ushell::pipe_read_kbuf(e.handle as u64, b)
            } else {
                crate::handlers::file_read_typed_kbuf(e.handle as u64, b)
            };
            lx::errno_from_native(r, le::EIO)
        }
        Kind::Dir => neg(le::EISDIR),
        Kind::Closed => neg(le::EBADF),
    }
}

fn sys_openat(dirfd: u64, path_ptr: u64, flags: u64) -> i64 {
    let mut raw = [0u8; PATH_MAX];
    let n = match user_path(path_ptr, &mut raw) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let mut path = [0u8; PATH_MAX];
    let plen = match resolve(dirfd, &raw[..n], &mut path) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let path = &path[..plen];
    let Some(req) = lx::open_flags(flags, arch()) else { return neg(le::EINVAL) };
    let accmode = (req.native & 3) as u8;
    let cloexec = flags & lx::oflag::O_CLOEXEC != 0;

    // A directory is the personality's own descriptor, read later through
    // `readdir`; a create never names one.
    if req.native & lx::oflag::O_CREAT == 0 {
        match is_dir(path) {
            Ok(true) => {
                if accmode != 0 {
                    return neg(le::EISDIR);
                }
                return open_dir(path, cloexec);
            }
            Ok(false) if req.directory => return neg(le::ENOTDIR),
            Ok(false) => {}
            Err(e) => return e,
        }
    } else if req.directory {
        return neg(le::EINVAL);
    }

    reach(k::SYS_FILE_OPEN_TYPED);
    let h = crate::handlers::file_open_typed_kpath(path, req.native);
    if h < 0 {
        // A refusal by the capability check (the tree gate) has already been
        // recorded by it; say so, so the refusal is visible where it happened.
        if h == azos_abi::error::Errno::EACCES.to_syscall_ret() {
            let me = azos_sched::current_task_tid();
            let recorded = crate::handlers::take_denial_recorded_for(me);
            azos_drv_sys::kwarn!(
                "[LINUX] tid={} openat refused by the capability check: -EACCES{}",
                me, if recorded { " (recorded)" } else { " (not recorded: recorder bound or absent)" },
            );
        }
        return lx::errno_from_native(h, le::ENOENT);
    }
    let ent = FdEnt { kind: Kind::Handle, handle: h as u32, dir: 0, cloexec, nonblock: req.nonblock, accmode };
    match fd_alloc(0, ent) {
        Ok(fd) => fd as i64,
        Err(e) => {
            reach(k::SYS_CLOSE_TYPED);
            let _ = crate::handlers::sys_close_typed(h as u64);
            e
        }
    }
}

fn open_dir(path: &[u8], cloexec: bool) -> i64 {
    if path.len() > DIR_PATH_MAX {
        return neg(le::ENAMETOOLONG);
    }
    let r = with_me(|p| {
        let d = p.dirs.iter().position(|d| !d.used)?;
        let fd = (0..FDS).find(|&i| p.fds[i].kind == Kind::Closed)?;
        p.dirs[d] = DirEnt { used: true, len: path.len() as u8, next: 0, path: [0; DIR_PATH_MAX] };
        p.dirs[d].path[..path.len()].copy_from_slice(path);
        p.fds[fd] = FdEnt { kind: Kind::Dir, dir: d as u8, cloexec, ..FD_CLOSED };
        Some(fd)
    })
    .flatten();
    match r {
        Some(fd) => fd as i64,
        None => neg(le::EMFILE),
    }
}

fn sys_close(fd: u64) -> i64 {
    let e = match fd_get(fd) {
        Ok(e) => e,
        Err(r) => return r,
    };
    // Mark it closed first, then release the handle if no other descriptor
    // names it (`dup3` aliases share one handle).
    let still_named = with_me(|p| {
        p.fds[fd as usize] = FD_CLOSED;
        if e.kind == Kind::Dir {
            p.dirs[e.dir as usize] = DIR_FREE;
        }
        e.kind == Kind::Handle && p.fds.iter().any(|f| f.kind == Kind::Handle && f.handle == e.handle)
    })
    .unwrap_or(true);
    if e.kind == Kind::Handle && !still_named {
        reach(k::SYS_CLOSE_TYPED);
        let r = if crate::ushell::is_pipe_handle(e.handle as u64) {
            crate::ushell::sys_pipe_close(e.handle as u64)
        } else {
            crate::handlers::sys_close_typed(e.handle as u64)
        };
        if r < 0 {
            return lx::errno_from_native(r, le::EIO);
        }
    }
    0
}

/// Fill `st` for an open descriptor.
fn stat_fd(e: FdEnt) -> Result<lx::Stat, i64> {
    let mut st = lx::Stat { nlink: 1, blksize: 512, ..lx::Stat::default() };
    match e.kind {
        Kind::Console => {
            st.mode = lx::mode::S_IFCHR | 0o620;
            // A tty major (4) in the old encoding: what `isatty` checks
            // through TCGETS anyway.
            st.rdev = 4 << 8;
        }
        Kind::Handle if crate::ushell::is_pipe_handle(e.handle as u64) => {
            st.mode = lx::mode::S_IFIFO | 0o600;
            st.blksize = 4096;
        }
        Kind::Handle => {
            let fd = crate::handlers::file_desc_of(e.handle as u64).map_err(|r| lx::errno_from_native(r, le::EBADF))?;
            let ops = file_ops().ok_or(neg(le::EIO))?;
            // The size is where the end is; the offset is put back.
            let cur = ops.lseek(fd as i32, 0, 1);
            let end = ops.lseek(fd as i32, 0, 2);
            if cur < 0 || end < 0 {
                return Err(neg(le::EIO));
            }
            let _ = ops.lseek(fd as i32, cur, 0);
            st.mode = lx::mode::S_IFREG | 0o644;
            st.size = end;
            st.ino = fd + 1;
        }
        Kind::Dir => {
            let d = with_me(|p| p.dirs[e.dir as usize]).ok_or(neg(le::EBADF))?;
            return stat_path(&d.path[..d.len as usize]);
        }
        Kind::Closed => return Err(neg(le::EBADF)),
    }
    st.blocks = (st.size + 511) / 512;
    Ok(st)
}

fn stat_path(path: &[u8]) -> Result<lx::Stat, i64> {
    let ops = file_ops().ok_or(neg(le::EIO))?;
    reach(k::SYS_STAT);
    let s = match ops.stat(path) {
        Ok(s) => s,
        // A mount point the VFS cannot stat but can list is a directory.
        Err(e) => {
            reach(k::SYS_READDIR);
            if ops.readdir(path, 0).is_some() {
                crate::file_ops::StatOut { mode: lx::mode::S_IFDIR | 0o755, nlink: 1, ..Default::default() }
            } else {
                return Err(lx::errno_from_native(e, le::ENOENT));
            }
        }
    };
    // An inode number the path names stably, so `ls -i` and `find -inum`
    // see one number per file within a boot.
    let ino = path.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| (h ^ b as u64).wrapping_mul(0x100_0000_01b3));
    Ok(lx::Stat {
        dev: 1,
        ino,
        mode: s.mode,
        nlink: s.nlink.max(1),
        size: s.size as i64,
        blksize: 512,
        blocks: (s.size as i64 + 511) / 512,
        atime: s.atime as i64,
        mtime: s.mtime as i64,
        ctime: s.ctime as i64,
        rdev: 0,
    })
}

fn sys_fstat(fd: u64, buf: u64) -> i64 {
    let e = match fd_get(fd) {
        Ok(e) => e,
        Err(r) => return r,
    };
    match stat_fd(e) {
        Ok(st) => if put_user(buf, &st.to_bytes()) { 0 } else { neg(le::EFAULT) },
        Err(r) => r,
    }
}

fn sys_newfstatat(dirfd: u64, path_ptr: u64, buf: u64, flags: u64) -> i64 {
    let mut raw = [0u8; PATH_MAX];
    let st = if flags & lx::AT_EMPTY_PATH != 0 && path_ptr != 0 && {
        let mut first = [0u8; 1];
        get_user(path_ptr, &mut first) && first[0] == 0
    } {
        match fd_get(dirfd).and_then(stat_fd) {
            Ok(s) => s,
            Err(r) => return r,
        }
    } else {
        let n = match user_path(path_ptr, &mut raw) {
            Ok(n) => n,
            Err(e) => return e,
        };
        let mut path = [0u8; PATH_MAX];
        let plen = match resolve(dirfd, &raw[..n], &mut path) {
            Ok(l) => l,
            Err(e) => return e,
        };
        match stat_path(&path[..plen]) {
            Ok(s) => s,
            Err(r) => return r,
        }
    };
    if put_user(buf, &st.to_bytes()) { 0 } else { neg(le::EFAULT) }
}

fn sys_lseek(fd: u64, off: u64, whence: u64) -> i64 {
    let e = match fd_get(fd) {
        Ok(e) => e,
        Err(r) => return r,
    };
    if whence > 2 {
        return neg(le::EINVAL);
    }
    match e.kind {
        Kind::Handle if !crate::ushell::is_pipe_handle(e.handle as u64) => {
            let d = match crate::handlers::file_desc_of(e.handle as u64) {
                Ok(d) => d,
                Err(r) => return lx::errno_from_native(r, le::EBADF),
            };
            let Some(ops) = file_ops() else { return neg(le::EIO) };
            lx::errno_from_native(ops.lseek(d as i32, off as i64, whence as i32), le::EINVAL)
        }
        // A directory rewinds (what `rewinddir` asks).
        Kind::Dir if off == 0 && whence == 0 => {
            with_me(|p| p.dirs[e.dir as usize].next = 0);
            0
        }
        Kind::Dir => neg(le::EINVAL),
        _ => neg(le::ESPIPE),
    }
}

fn sys_getdents64(fd: u64, buf: u64, count: u64) -> i64 {
    let e = match fd_get(fd) {
        Ok(e) => e,
        Err(r) => return r,
    };
    if e.kind != Kind::Dir {
        return neg(le::ENOTDIR);
    }
    let Some(d) = with_me(|p| p.dirs[e.dir as usize]) else { return neg(le::EBADF) };
    let Some(ops) = file_ops() else { return neg(le::EIO) };
    reach(k::SYS_READDIR);
    let mut out = [0u8; 2048];
    let cap = (count as usize).min(out.len());
    let mut used = 0usize;
    let mut idx = d.next;
    let path = &d.path[..d.len as usize];
    while let Some((name, _size, is_dir)) = ops.readdir(path, idx) {
        let nlen = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        let ino = (idx as u64) + 2;
        let dt = if is_dir { lx::DT_DIR } else { lx::DT_REG };
        match lx::encode_dirent64(&mut out[used..cap], ino, idx as i64 + 1, dt, &name[..nlen]) {
            Some(n) => used += n,
            None => break,
        }
        idx += 1;
    }
    if used == 0 && ops.readdir(path, idx).is_some() {
        // The next entry does not fit the caller's buffer at all.
        return neg(le::EINVAL);
    }
    if !put_user(buf, &out[..used]) && used > 0 {
        return neg(le::EFAULT);
    }
    with_me(|p| p.dirs[e.dir as usize].next = idx);
    used as i64
}

fn sys_pipe2(fds_ptr: u64, flags: u64) -> i64 {
    if flags & !(lx::oflag::O_CLOEXEC | lx::oflag::O_NONBLOCK) != 0 {
        return neg(le::EINVAL);
    }
    reach(k::SYS_PIPE_TYPED);
    let native_flags = if flags & lx::oflag::O_NONBLOCK != 0 { azos_abi::ushell::PIPE_NONBLOCK } else { 0 };
    // `int fds[2]` is 8 bytes, which is what the native call writes its two
    // handles into; they are read back and replaced by descriptors.
    let r = crate::ushell::sys_pipe_typed(fds_ptr, native_flags);
    if r < 0 {
        return lx::errno_from_native(r, le::EMFILE);
    }
    let mut b = [0u8; 8];
    if !get_user(fds_ptr, &mut b) {
        return neg(le::EFAULT);
    }
    let rd = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let wr = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
    let cloexec = flags & lx::oflag::O_CLOEXEC != 0;
    let nonblock = flags & lx::oflag::O_NONBLOCK != 0;
    let fr = fd_alloc(0, FdEnt { kind: Kind::Handle, handle: rd, cloexec, nonblock, accmode: 0, dir: 0 });
    let fw = fr.and_then(|_| fd_alloc(0, FdEnt { kind: Kind::Handle, handle: wr, cloexec, nonblock, accmode: 1, dir: 0 }));
    match (fr, fw) {
        (Ok(a), Ok(c)) => {
            let mut o = [0u8; 8];
            o[..4].copy_from_slice(&(a as u32).to_le_bytes());
            o[4..].copy_from_slice(&(c as u32).to_le_bytes());
            if put_user(fds_ptr, &o) { 0 } else { neg(le::EFAULT) }
        }
        (r1, _) => {
            if let Ok(a) = r1 {
                with_me(|p| p.fds[a] = FD_CLOSED);
            }
            reach(k::SYS_CLOSE_TYPED);
            let _ = crate::ushell::sys_pipe_close(rd as u64);
            let _ = crate::ushell::sys_pipe_close(wr as u64);
            neg(le::EMFILE)
        }
    }
}

/// `dup3(old, new, flags)`; `new == u64::MAX` is `dup(old)` (lowest free).
fn sys_dup3(old: u64, new: u64, flags: u64) -> i64 {
    let e = match fd_get(old) {
        Ok(e) => e,
        Err(r) => return r,
    };
    if flags & !lx::oflag::O_CLOEXEC != 0 {
        return neg(le::EINVAL);
    }
    if e.kind == Kind::Dir {
        // One directory cursor per descriptor; sharing it is not modelled.
        return neg(le::EINVAL);
    }
    let ent = FdEnt { cloexec: flags & lx::oflag::O_CLOEXEC != 0, ..e };
    if new == u64::MAX {
        return match fd_alloc(0, FdEnt { cloexec: false, ..e }) {
            Ok(fd) => fd as i64,
            Err(r) => r,
        };
    }
    if new == old {
        return neg(le::EINVAL);
    }
    if new >= FDS as u64 {
        return neg(le::EBADF);
    }
    if fd_get(new).is_ok() {
        let r = sys_close(new);
        if r < 0 {
            return r;
        }
    }
    with_me(|p| p.fds[new as usize] = ent);
    new as i64
}

fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> i64 {
    use lx::fcntl::*;
    let e = match fd_get(fd) {
        Ok(e) => e,
        Err(r) => return r,
    };
    match cmd {
        F_GETFD => e.cloexec as i64,
        F_SETFD => {
            with_me(|p| p.fds[fd as usize].cloexec = arg & FD_CLOEXEC != 0);
            0
        }
        F_GETFL => (e.accmode as u64 | if e.nonblock { lx::oflag::O_NONBLOCK } else { 0 }) as i64,
        F_SETFL => {
            with_me(|p| p.fds[fd as usize].nonblock = arg & lx::oflag::O_NONBLOCK != 0);
            0
        }
        F_DUPFD | F_DUPFD_CLOEXEC => {
            if e.kind == Kind::Dir {
                return neg(le::EINVAL);
            }
            if arg >= FDS as u64 {
                return neg(le::EINVAL);
            }
            match fd_alloc(arg as usize, FdEnt { cloexec: cmd == F_DUPFD_CLOEXEC, ..e }) {
                Ok(n) => n as i64,
                Err(r) => r,
            }
        }
        _ => neg(le::EINVAL),
    }
}

fn sys_ioctl(fd: u64, req: u64, arg: u64) -> i64 {
    use lx::ioctl::*;
    let e = match fd_get(fd) {
        Ok(e) => e,
        Err(r) => return r,
    };
    if e.kind != Kind::Console {
        return neg(le::ENOTTY);
    }
    let ok = |b: bool| if b { 0 } else { neg(le::EFAULT) };
    match req {
        // The console has no size probe (RFC-0055): 24 x 80.
        TIOCGWINSZ => ok(put_user(arg, &lx::winsize_bytes(24, 80))),
        TCGETS => ok(put_user(arg, &lx::termios_bytes())),
        // Accepted, without effect: the native shell owns the line
        // discipline (RFC-0055 5.4).
        TCSETS | TCSETSW | TCSETSF | TIOCSWINSZ => 0,
        TIOCGPGRP => ok(put_user(arg, &(azos_sched::current_task_tid() as i32).to_le_bytes())),
        TIOCSPGRP => 0,
        _ => neg(le::EINVAL),
    }
}

fn sys_getcwd(buf: u64, size: u64) -> i64 {
    let Some((c, n)) = with_me(|p| (p.cwd, p.cwd_len as usize)) else { return neg(le::EFAULT) };
    if (size as usize) < n + 1 {
        return neg(le::ERANGE);
    }
    let mut out = [0u8; CWD_MAX + 1];
    out[..n].copy_from_slice(&c[..n]);
    if put_user(buf, &out[..n + 1]) { (n + 1) as i64 } else { neg(le::EFAULT) }
}

fn sys_chdir(path_ptr: u64) -> i64 {
    let mut raw = [0u8; PATH_MAX];
    let n = match user_path(path_ptr, &mut raw) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let mut path = [0u8; PATH_MAX];
    let plen = match resolve(lx::AT_FDCWD, &raw[..n], &mut path) {
        Ok(l) => l,
        Err(e) => return e,
    };
    match is_dir(&path[..plen]) {
        Ok(true) => {}
        Ok(false) => return neg(le::ENOTDIR),
        Err(e) => return e,
    }
    if plen > CWD_MAX {
        return neg(le::ENAMETOOLONG);
    }
    with_me(|p| {
        p.cwd[..plen].copy_from_slice(&path[..plen]);
        p.cwd_len = plen as u8;
    });
    0
}

// ── Process ─────────────────────────────────────────────────────────────────

fn sys_exit_group(code: u64) -> i64 {
    // The entry goes first: the native exit closes the task's descriptors and
    // never returns here. Not while other threads of the process still run
    // (wave 13): they are being stopped, and an entry whose process is gone is
    // reclaimed by the next `proc_init` anyway.
    let me = azos_sched::current_proc_tid();
    if azos_sched::group::live_members(me) <= 1 {
        let mut t = TABLE.lock();
        if let Some(p) = t.iter_mut().find(|p| p.tid == me && me != 0) {
            p.tid = 0;
        }
    }
    reach(k::SYS_EXIT);
    crate::handlers::sys_exit(code & 0xff)
}

/// `exit(code)` (wave 13): ends only the calling thread while its process
/// has others; the process's last thread ends the process.
fn sys_exit_thread(code: u64) -> i64 {
    if azos_sched::group::live_members(azos_sched::current_proc_tid()) > 1 {
        reach(k::SYS_EXIT);
        azos_sched::scheduler::thread_exit((code & 0xff) as i32)
    }
    sys_exit_group(code)
}

// The PI futex word and errnos (crates/core/sync/src/pi_futex.rs) are
// Linux's and the native robust ABI's, bit for bit.
const _: () = {
    use azos_sync::pi_futex as pf;
    assert!(pf::FUTEX_TID_MASK == lx::robust::FUTEX_TID_MASK && pf::FUTEX_TID_MASK == k::ROBUST_TID_MASK);
    assert!(pf::FUTEX_OWNER_DIED == lx::robust::FUTEX_OWNER_DIED && pf::FUTEX_OWNER_DIED == k::ROBUST_OWNER_DIED);
    assert!(pf::FUTEX_WAITERS == lx::robust::FUTEX_WAITERS && pf::FUTEX_WAITERS == k::ROBUST_WAITERS);
    assert!(pf::EPERM as i64 == le::EPERM && pf::ESRCH as i64 == le::ESRCH && pf::EINTR as i64 == le::EINTR);
    assert!(pf::EAGAIN as i64 == le::EAGAIN && pf::ENOMEM as i64 == le::ENOMEM && pf::EFAULT as i64 == le::EFAULT);
    assert!(pf::EINVAL as i64 == le::EINVAL && pf::EDEADLK as i64 == le::EDEADLK);
    assert!(pf::ENOSYS as i64 == le::ENOSYS && pf::ETIMEDOUT as i64 == le::ETIMEDOUT);
};

/// `futex(uaddr, op, val, timeout, uaddr2, val3)` (wave 13; wave 15 N9):
/// `FUTEX_WAIT`, `FUTEX_WAKE` and their `_BITSET` forms with the full mask,
/// `FUTEX_REQUEUE` and `FUTEX_CMP_REQUEUE` (Kconfig `FUTEX_REQUEUE`).
/// With `FUTEX_PRIVATE_FLAG` the key is the process's; without it, a word of
/// a shm region the caller maps is keyed by the region (Kconfig
/// `FUTEX_SHARED`, the notify calls' key) and any other word is the
/// process's, as Linux keys a shared futex on private memory by its mm.
/// `FUTEX_WAIT`'s timeout is relative, `FUTEX_WAIT_BITSET`'s absolute on
/// the monotonic clock. With Kconfig `FUTEX_PI` (wave 15 N10),
/// `FUTEX_LOCK_PI`, `FUTEX_LOCK_PI2`, `FUTEX_TRYLOCK_PI` and
/// `FUTEX_UNLOCK_PI` too, through `azos_sync::pi_futex`. Requeue-PI and
/// wake-op forms are not answered.
fn sys_futex(uaddr: u64, op: u64, val: u64, timeout: u64, uaddr2: u64, val3: u64) -> i64 {
    use lx::futex::*;
    let cmd = op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    let private = op & FUTEX_PRIVATE_FLAG != 0;
    let bitset = cmd == FUTEX_WAIT_BITSET || cmd == FUTEX_WAKE_BITSET;
    if bitset && val3 & 0xffff_ffff != FUTEX_BITSET_MATCH_ANY {
        return unanswered(nr::FUTEX);
    }
    match cmd {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            let deadline = if timeout == 0 {
                None
            } else {
                let mut b = [0u8; 16];
                if !get_user(timeout, &mut b) {
                    return neg(le::EFAULT);
                }
                let Some(ns) = lx::timespec_ns(&b) else { return neg(le::EINVAL) };
                let freq = azos_drv_sys::timebase::TIMER_FREQ;
                let ticks = azos_abi::time::ns_to_ticks_ceil(ns, freq);
                Some(if cmd == FUTEX_WAIT {
                    azos_drv_sys::timebase::now().saturating_add(ticks)
                } else {
                    ticks
                })
            };
            let (key, kva) = match futex_word(uaddr, private) {
                Ok(w) => w,
                Err(e) => return e,
            };
            reach(k::SYS_FUTEX_WAIT);
            azos_sched::futex::wait_key(key, val as u32, deadline, &|| futex_read(uaddr, kva))
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            let (key, _) = match futex_word(uaddr, private) {
                Ok(w) => w,
                Err(e) => return e,
            };
            reach(k::SYS_FUTEX_WAKE);
            azos_sched::futex::wake_key(key, val.min(u32::MAX as u64) as u32)
        }
        FUTEX_REQUEUE | FUTEX_CMP_REQUEUE if azos_sched::futex_table::REQUEUE => {
            // `timeout` carries `val2` (nr_requeue) for these ops.
            let (nr_wake, nr_requeue) = (val as u32 as i32, timeout as u32 as i32);
            if nr_wake < 0 || nr_requeue < 0 {
                return neg(le::EINVAL);
            }
            let (from, kva) = match futex_word(uaddr, private) {
                Ok(w) => w,
                Err(e) => return e,
            };
            let (to, _) = match futex_word(uaddr2, private) {
                Ok(w) => w,
                Err(e) => return e,
            };
            // A requeue is a wake that moves the rest: the wake's authority.
            reach(k::SYS_FUTEX_WAKE);
            let cmp = (cmd == FUTEX_CMP_REQUEUE).then_some(val3 as u32);
            match azos_sched::futex::requeue(from, to, nr_wake as u32, nr_requeue as u32, cmp, &|| futex_read(uaddr, kva)) {
                // Linux answers woken + requeued for both ops.
                Ok((woken, moved)) => (woken + moved) as i64,
                Err(e) => e,
            }
        }
        // Wave 15 N10, Kconfig FUTEX_PI: n answers ENOSYS (below) as before.
        // The requeue-PI pair is not answered yet.
        FUTEX_LOCK_PI | FUTEX_LOCK_PI2 | FUTEX_TRYLOCK_PI | FUTEX_UNLOCK_PI if azos_sync::pi_futex::ENABLED => {
            use azos_sync::pi_futex::{sys_futex_pi, PiCmd};
            if uaddr & 3 != 0 {
                return neg(le::EINVAL);
            }
            let pcmd = match cmd {
                FUTEX_TRYLOCK_PI => PiCmd::TryLock,
                FUTEX_UNLOCK_PI => PiCmd::Unlock,
                // Absolute on either clock: REALTIME counts from boot here
                // (see `clock_gettime`), so both are the timer's ticks.
                _ if timeout == 0 => PiCmd::Lock { deadline: None },
                _ => {
                    let mut b = [0u8; 16];
                    if !get_user(timeout, &mut b) {
                        return neg(le::EFAULT);
                    }
                    let Some(ns) = lx::timespec_ns(&b) else { return neg(le::EINVAL) };
                    let freq = azos_drv_sys::timebase::TIMER_FREQ;
                    PiCmd::Lock { deadline: Some(azos_abi::time::ns_to_ticks_ceil(ns, freq)) }
                }
            };
            sys_futex_pi(uaddr, pcmd)
        }
        _ => unanswered(nr::FUTEX),
    }
}

/// The futex-table key of the word at `uaddr`, and the kernel address of a
/// shared word (0 for a private one, read through `copy_from_user`).
fn futex_word(uaddr: u64, private: bool) -> Result<(azos_sched::futex::Key, usize), i64> {
    if uaddr & 3 != 0 {
        return Err(neg(le::EINVAL));
    }
    if !private && azos_sched::futex_table::SHARED {
        // The mapping is the process's, whichever thread asks (as notify).
        let tid = azos_sched::current_proc_tid();
        if let Some((region, off, phys)) = azos_ipc::shm::shm_resolve_mapped(tid, uaddr as usize) {
            let key = azos_sched::futex::Key::Shared { obj: region, offset: off as u32 };
            return Ok((key, azos_mm::addr::phys_to_virt(phys)));
        }
    }
    azos_sched::futex::private_key(uaddr).map(|key| (key, 0)).ok_or(neg(le::EFAULT))
}

/// Read the futex word: through its region's page for a shared word (the
/// caller's mapping holds the region for the call), else from user memory.
fn futex_read(uaddr: u64, kva: usize) -> Option<u32> {
    if kva == 0 {
        return crate::threads::read_u32(uaddr);
    }
    // SAFETY: `kva` is a 4-byte-aligned word of a region the caller maps
    // (`futex_word`), which holds the page for the call.
    Some(unsafe { &*(kva as *const core::sync::atomic::AtomicU32) }.load(core::sync::atomic::Ordering::Acquire))
}

/// `wait4(pid, wstatus, options, rusage)`: pid > 0 or -1; `WNOHANG` (1);
/// `WUNTRACED`/`WCONTINUED` accepted (no task is ever stopped here). Blocks
/// on a clock deadline, never by counting yields, and ends with `-EINTR` when
/// the task is asked to stop. `rusage` is zeroed (no accounting is offered).
fn sys_wait4(pid: u64, status_ptr: u64, options: u64, rusage: u64) -> i64 {
    const WNOHANG: u64 = 1;
    const KNOWN: u64 = 1 | 2 | 8 | 0x4000_0000 | 0x8000_0000;
    if options & !KNOWN != 0 {
        return neg(le::EINVAL);
    }
    if rusage != 0 && !put_user(rusage, &[0u8; 144]) {
        return neg(le::EFAULT);
    }
    let pid = pid as i64;
    if pid == 0 || pid < -1 {
        // Process groups do not exist here.
        return neg(le::EINVAL);
    }
    // Wave 13: the children are the process's, whichever thread waits.
    let me = azos_sched::current_proc_tid();
    loop {
        let (got, code) = if pid > 0 {
            reach(k::SYS_WAITPID);
            match azos_sched::take_exit_note_for(me, pid as u32) {
                Ok((t, c)) => (t as i64, c),
                Err(azos_sched::WaitpidMiss::NotYet) => (0, 0),
                Err(azos_sched::WaitpidMiss::NotOurs) => return neg(le::ECHILD),
            }
        } else {
            reach(k::SYS_WAIT_STATUS);
            match azos_sched::take_exit_note(me) {
                Some((t, c)) => (t as i64, c),
                None if !azos_sched::scheduler::has_reapable_child(me) => return neg(le::ECHILD),
                None => (0, 0),
            }
        };
        if got > 0 {
            // Wave 13: a child a signal ended is reported killed by it
            // (`WIFSIGNALED`), as Linux does; its native code stays 128 + n
            // for native waiters.
            let killed = if cfg!(feature = "linux-wait-exited-canary") { None } else { sigst::take_killed(got as u32) };
            let st = match killed {
                Some(sig) => lx::wait_status_signalled(sig),
                None => lx::wait_status(code),
            };
            if status_ptr != 0 && !put_user(status_ptr, &st.to_le_bytes()) {
                return neg(le::EFAULT);
            }
            return got;
        }
        if options & WNOHANG != 0 {
            return 0;
        }
        if crate::ushell::stop_requested() {
            return neg(le::EINTR);
        }
        azos_sched::scheduler::set_current_waits_child(true);
        crate::ushell::park_until(azos_drv_sys::timebase::now().saturating_add(crate::ushell::ms_ticks(10)));
        azos_sched::scheduler::set_current_waits_child(false);
    }
}

// ── Memory ──────────────────────────────────────────────────────────────────

fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64) -> i64 {
    use lx::mman::*;
    // Anonymous private memory only: file mappings and shared mappings are
    // not answered, and an executable mapping is refused (W^X).
    if flags & MAP_ANONYMOUS == 0 || flags & MAP_SHARED != 0 || flags & MAP_PRIVATE == 0 {
        return neg(le::ENOSYS);
    }
    // Linux ignores `fd` for an anonymous mapping, and so does this.
    let _ = fd;
    if flags & MAP_FIXED != 0 || prot & PROT_EXEC != 0 || len == 0 {
        return neg(le::EINVAL);
    }
    reach(k::SYS_MMAP);
    // Wave 14: the pre-commit bits travel (same values in both ABIs).
    let r = crate::handlers::sys_mmap(addr, len, prot, flags & (MAP_POPULATE | MAP_LOCKED), u64::MAX, 0);
    lx::errno_from_native(r, le::ENOMEM)
}

// ── Time ────────────────────────────────────────────────────────────────────

fn now_ns() -> u64 {
    azos_abi::time::ticks_to_ns(azos_drv_sys::timebase::now(), azos_drv_sys::timebase::TIMER_FREQ)
}

fn sys_clock_gettime(id: u64, ts: u64) -> i64 {
    use lx::clock::*;
    match id {
        // REALTIME counts from boot: no wall clock is offered to a Linux task
        // yet (the NTP offset is a native call of its own).
        REALTIME | MONOTONIC | MONOTONIC_RAW | REALTIME_COARSE | MONOTONIC_COARSE | BOOTTIME => {
            if put_user(ts, &lx::timespec_bytes(now_ns())) { 0 } else { neg(le::EFAULT) }
        }
        _ => neg(le::EINVAL),
    }
}

fn sys_nanosleep(req: u64, rem: u64) -> i64 {
    let mut b = [0u8; 16];
    if !get_user(req, &mut b) {
        return neg(le::EFAULT);
    }
    let Some(ns) = lx::timespec_ns(&b) else { return neg(le::EINVAL) };
    reach(k::SYS_SLEEP_UNTIL);
    let deadline = now_ns().saturating_add(ns);
    let tick_deadline = azos_abi::time::ns_to_ticks_ceil(deadline, azos_drv_sys::timebase::TIMER_FREQ);
    while azos_drv_sys::timebase::now() < tick_deadline {
        if crate::ushell::stop_requested() {
            let left = deadline.saturating_sub(now_ns());
            if rem != 0 {
                let _ = put_user(rem, &lx::timespec_bytes(left));
            }
            return neg(le::EINTR);
        }
        // Wake at least every 10 ms to look at the stop request.
        let step = azos_drv_sys::timebase::now().saturating_add(crate::ushell::ms_ticks(10));
        crate::ushell::park_until(step.min(tick_deadline));
    }
    0
}

// ── Signals (wave 13, RFC-0047 P3) ──────────────────────────────────────────
//
// The words (pending, mask, discarded set) live in the scheduler
// (`azos_sched::scheduler::signal`), lock-free, so a signal can be posted
// from another task, an exit or the console interrupt. The dispositions live
// here, and a signal is acted on only by its target, at its own return to
// user mode ([`on_return_to_user`], called by the trap paths when the
// scheduler's one-load check says there is work).
//
// Authority (who may signal whom): `SYS_TASK_KILL`'s, unchanged. A task
// signals itself freely; another task only if it is that task's ANCESTOR
// (`stop_policy::is_ancestor`, at most 8 steps), and only if its row's
// profile lists `SYS_TASK_KILL` (the native number `kill` reaches). Anything
// else, absent included, is `-ESRCH`, so a task cannot probe TIDs. No
// capability widens this today. A native target has no handlers (the native
// ABI is signal-free): it gets the native stop request, forced for `SIGKILL`.

/// The signals a disposition table discards on arrival: `SIG_IGN`, and
/// `SIG_DFL` where the default is not to end the task.
fn ignored_of(act: &[lx::KSigaction; NSIG]) -> u64 {
    let mut m = 0u64;
    for (i, a) in act.iter().enumerate() {
        let s = i as u64 + 1;
        let ign = match a.handler {
            lx::sig::SIG_IGN => true,
            lx::sig::SIG_DFL => sig::default_action(s) != sig::DefaultAction::Terminate,
            _ => false,
        };
        if ign {
            m |= sig::bit(s);
        }
    }
    m & !sig::bit(lx::sig::SIGKILL)
}

fn sys_rt_sigaction(s: u64, act: u64, oact: u64, setsize: u64) -> i64 {
    use lx::sig::*;
    if setsize != 8 || s == 0 || s > NSIG_MAX {
        return neg(le::EINVAL);
    }
    let a = arch();
    let size = lx::KSigaction::size(a);
    let mut new = None;
    if act != 0 {
        if s == SIGKILL || s == SIGSTOP {
            return neg(le::EINVAL);
        }
        let mut b = [0u8; 32];
        if !get_user(act, &mut b[..size]) {
            return neg(le::EFAULT);
        }
        new = lx::KSigaction::from_bytes(&b[..size], a);
    }
    let Some(old) = with_me(|p| {
        let old = p.act[s as usize - 1];
        if let Some(n) = new {
            p.act[s as usize - 1] = n;
            sigst::set_current_ignored(ignored_of(&p.act));
        }
        old
    }) else {
        return neg(le::EFAULT);
    };
    if oact != 0 && !put_user(oact, &old.to_bytes(a)[..size]) {
        return neg(le::EFAULT);
    }
    0
}

/// The kernel address of the aligned user word at `ptr`, through the
/// current task's page table (`write`: a store is allowed there, after any
/// copy-on-write break). An aligned word never spans two pages, so one
/// translation serves it: what `copy_*_user` does for a run of bytes, without
/// the run.
fn user_word(ptr: u64, write: bool) -> Option<*mut u64> {
    if ptr == 0 || ptr & 7 != 0 {
        return None;
    }
    let pt = azos_sched::current_user_pt();
    if pt == 0 {
        return None;
    }
    let pa = azos_mm::vmm::translate_user(pt, ptr as usize, write)?;
    Some(azos_mm::addr::phys_to_virt(pa) as *mut u64)
}

#[inline(never)]
fn sys_rt_sigprocmask(how: u64, set: u64, oset: u64, setsize: u64) -> i64 {
    use lx::sig::*;
    if setsize != 8 {
        return neg(le::EINVAL);
    }
    let new = if set != 0 {
        // SAFETY: a translated, aligned user word, read once.
        match user_word(set, false).map(|p| unsafe { core::ptr::read_volatile(p) }).or_else(|| get_u64(set)) {
            Some(v) => Some(v),
            None => return neg(le::EFAULT),
        }
    } else {
        None
    };
    if new.is_some() && how > SIG_SETMASK {
        return neg(le::EINVAL);
    }
    let Some(old) = sigst::current_blocked() else { return neg(le::EFAULT) };
    if let Some(v) = new {
        // SIGKILL and SIGSTOP cannot be blocked (the scheduler drops them).
        sigst::set_current_blocked(match how {
            SIG_BLOCK => old | v,
            SIG_UNBLOCK => old & !v,
            _ => v,
        });
    }
    if oset != 0 {
        match user_word(oset, true) {
            // SAFETY: a translated, aligned, writable user word.
            Some(p) => unsafe { core::ptr::write_volatile(p, old) },
            None if put_user(oset, &old.to_le_bytes()) => {}
            None => return neg(le::EFAULT),
        }
    }
    0
}

/// `rt_sigpending(set, size)`: the pending signals the mask holds back.
fn sys_rt_sigpending(set: u64, size: u64) -> i64 {
    if size != 8 {
        return neg(le::EINVAL);
    }
    let blocked = sigst::current_blocked().unwrap_or(0);
    if put_user(set, &(sigst::current_pending() & blocked).to_le_bytes()) { 0 } else { neg(le::EFAULT) }
}

/// `rt_sigsuspend(mask, size)`: wait under `mask` until a signal is
/// delivered; always `-EINTR`, never restarted. The caller's own mask is
/// what the handler's frame saves, so it comes back when the handler returns.
fn sys_rt_sigsuspend(mask_ptr: u64, size: u64) -> i64 {
    if size != 8 {
        return neg(le::EINVAL);
    }
    let Some(mask) = get_u64(mask_ptr) else { return neg(le::EFAULT) };
    reach(k::SYS_SLEEP_UNTIL);
    let Some(old) = sigst::current_blocked() else { return neg(le::EFAULT) };
    with_me(|p| p.suspend_saved = Some(old));
    sigst::set_current_blocked(mask);
    while !crate::ushell::stop_requested() {
        // A clock ceiling bounds a lost wake; a post wakes the wait at once.
        crate::ushell::park_until(azos_drv_sys::timebase::now().saturating_add(crate::ushell::ms_ticks(100)));
    }
    neg(le::EINTR)
}

/// `sigaltstack(ss, old_ss)`: no alternate stack is offered. The old one
/// reads back as disabled; asking to disable it is accepted, installing
/// one is `-EINVAL`.
fn sys_sigaltstack(ss: u64, old_ss: u64) -> i64 {
    if old_ss != 0 {
        let mut b = [0u8; 24];
        b[8..12].copy_from_slice(&sig::SS_DISABLE.to_le_bytes());
        if !put_user(old_ss, &b) {
            return neg(le::EFAULT);
        }
    }
    if ss != 0 {
        let mut b = [0u8; 24];
        if !get_user(ss, &mut b) {
            return neg(le::EFAULT);
        }
        if u32::from_le_bytes([b[8], b[9], b[10], b[11]]) & sig::SS_DISABLE == 0 {
            return neg(le::EINVAL);
        }
    }
    0
}

/// May the current process (`me`, its thread `me_thread`) signal process
/// `p`? Itself, or a descendant (the stop policy's ancestry, at most 8 steps;
/// a child forked by any of its threads is its child).
fn may_signal(me: u32, me_thread: u32, p: u32) -> bool {
    p == me
        || azos_sched::scheduler::task_is_ancestor(me, p)
        || azos_sched::scheduler::task_is_ancestor(me_thread, p)
}

/// Post `s` to process `p` (thread `thread`: to exactly that thread) on
/// behalf of process `me`; a native target gets its stop request instead.
fn signal_one(me: u32, p: u32, thread: Option<u32>, s: u64) {
    let r = match thread {
        // Gate canary only: a thread-directed signal is taken as the process's.
        Some(_) if cfg!(feature = "linux-tkill-process-canary") => sigst::post(p, s as u32, me),
        Some(t) => sigst::post_thread(t, s as u32, me),
        None => sigst::post(p, s as u32, me),
    };
    if r == sigst::Posted::NotLinux && s as u32 <= azos_sched::scheduler::stop_policy::SIGNO_MAX {
        // A native task: the stop request its ABI has (forced for SIGKILL),
        // exit code 128 + signo if it ends.
        let _ = azos_sched::scheduler::task_stop(thread.unwrap_or(p), s == lx::sig::SIGKILL, s as u8);
    }
    if p != me {
        azos_drv_sys::kprintln!("[SIGNAL] tid={} -> tid={} sig={} ({:?})", me, thread.unwrap_or(p), s, r);
    }
}

/// `tkill(tid, sig)` / `tgkill(tgid, tid, sig)` (`tgid` 0: not checked):
/// thread `tid`, which must be a thread of the caller's process or of a
/// descendant process (`tgkill` also: of process `tgid`). It takes the signal
/// itself: if it blocks it, it stays pending on that thread.
fn sys_tkill(tgid: i64, tid: i64, s: u64) -> i64 {
    if s > lx::sig::NSIG_MAX || tid <= 0 || tgid < 0 {
        return neg(le::EINVAL);
    }
    let me = azos_sched::current_proc_tid();
    let me_thread = azos_sched::current_task_tid();
    let t = tid as u32;
    let p = azos_sched::group::proc_tid(t);
    if azos_sched::idx_for_tid(t).is_none() || (tgid != 0 && p != tgid as u32) || !may_signal(me, me_thread, p) {
        return neg(le::ESRCH);
    }
    if s == 0 {
        return 0;
    }
    if p != me {
        reach(k::SYS_TASK_KILL);
    }
    signal_one(me, p, Some(t), s);
    0
}

/// `kill(pid, sig)`: a process (any of its threads that does not block the
/// signal takes it). `pid > 0` one process; `0` the caller's process and its
/// descendants; `-1` its descendants; `< -1` process `-pid` and its
/// descendants (the nearest thing to a process group here: there are none).
/// `sig == 0` only checks.
fn sys_kill(pid: i64, s: u64) -> i64 {
    if s > lx::sig::NSIG_MAX {
        return neg(le::EINVAL);
    }
    let me = azos_sched::current_proc_tid();
    let me_thread = azos_sched::current_task_tid();
    // To itself: no authority to check, nothing to look up.
    if pid == me as i64 {
        if s != 0 {
            let _ = sigst::post(me, s as u32, me);
        }
        return 0;
    }
    let mut list = [0u32; 33];
    let mut n = 0usize;
    let root = match pid {
        p if p > 0 => {
            // A thread's TID names its process, as on Linux.
            list[0] = azos_sched::group::proc_tid(p as u32);
            n = 1;
            0
        }
        0 => {
            list[0] = me;
            n = 1;
            me
        }
        -1 => me,
        p => {
            let r = azos_sched::group::proc_tid(p.unsigned_abs() as u32);
            list[0] = r;
            n = 1;
            r
        }
    };
    if root != 0 {
        let mut below = [0u32; 32];
        let found = azos_sched::scheduler::descendants_of(root, &mut below).min(below.len());
        // Processes only: a thread is reached through its process.
        for &t in &below[..found] {
            if n < list.len() && azos_sched::group::proc_tid(t) == t {
                list[n] = t;
                n += 1;
            }
        }
    }
    let mut hit = 0u32;
    let mut reached = false;
    for &p in &list[..n] {
        if p == 0 || !may_signal(me, me_thread, p) || azos_sched::idx_for_tid(p).is_none() {
            continue;
        }
        hit += 1;
        if s == 0 {
            continue;
        }
        if p != me && !reached {
            reach(k::SYS_TASK_KILL);
            reached = true;
        }
        signal_one(me, p, None, s);
    }
    if hit == 0 { neg(le::ESRCH) } else { 0 }
}

/// The frame being built or read back, as words. One at a time: a frame is
/// built or read at a return to user mode, short and free of waits.
static FRAME_BUF: SpinLock<[u64; sig::FRAME_WORDS_MAX]> = SpinLock::new([0; sig::FRAME_WORDS_MAX]);

fn put_user_words(ptr: u64, w: &[u64]) -> bool {
    ptr != 0 && azos_sched::copy_to_user(ptr as usize, w.as_ptr() as *const u8, w.len() * 8)
}

fn get_user_words(ptr: u64, w: &mut [u64]) -> bool {
    ptr != 0 && azos_sched::copy_from_user(w.as_mut_ptr() as *mut u8, ptr as usize, w.len() * 8)
}

/// End the current task's PROCESS as signal `s`'s default action does: the
/// whole thread group goes (`exit_group`: the exit path stops every other
/// member), exit code `128 + s`, and a Linux parent's `wait4` sees the
/// child killed by `s`. At a return to user mode (a safe point: no lock is
/// held).
fn die_by_signal(s: u32) -> ! {
    let me = azos_sched::current_task_tid();
    let proc_id = azos_sched::current_proc_tid();
    azos_ipc::trace::trace_event(azos_ipc::trace::TRACE_SIGNAL, me, s, 0, 2);
    azos_drv_sys::kprintln!("[SIGNAL] tid={} ended by signal {} (exit {})", me, s, 128 + s);
    // The entry is the process's: dropped by its last thread only, as
    // `exit_group` drops it.
    if azos_sched::group::live_members(proc_id) <= 1 {
        let mut t = TABLE.lock();
        if let Some(p) = t.iter_mut().find(|p| p.tid == proc_id && proc_id != 0) {
            p.tid = 0;
        }
    }
    azos_sched::scheduler::task_exit_by_signal(128 + s as i32)
}

/// `rt_sigreturn()`: the frame at the user stack pointer (where the handler
/// was entered with it, its own frame popped) is read back and applied at
/// this call's return to user mode ([`on_return_to_user`]), where the
/// registers are; a frame that cannot be read ends the task as `SIGSEGV`
/// would.
fn sys_rt_sigreturn(user_sp: u64) -> i64 {
    sigst::set_current_restore(user_sp);
    0
}

/// Wave 13: the current task returns to user mode with signal work counted
/// (the scheduler's one-load check). `ctx` is its user context as the trap
/// path holds it; `from_syscall` says it returns from a call (`a0`/`x0` is
/// that call's result). Applies a pending `rt_sigreturn`, then delivers the
/// first pending signal its mask lets through: discards it, ends the task,
/// or builds its handler's frame on the user stack and points `ctx` at the
/// handler. Returns whether `ctx` changed (the caller writes it back).
///
/// The caller supplies the FP file: `fp_save` reads the live one for a frame,
/// `fp_load` installs one a sigreturn read back.
pub fn on_return_to_user(
    ctx: &mut sig::Context,
    from_syscall: bool,
    fp_save: &mut dyn FnMut(&mut [u64]) -> bool,
    fp_load: &mut dyn FnMut(&[u64]),
) -> bool {
    if !azos_sched::scheduler::current_is_linux() {
        return false;
    }
    let a = arch();
    let (a0, spi) = match a {
        lx::Arch::Riscv64 => (10usize, 2usize),
        lx::Arch::Aarch64 => (0usize, 31usize),
    };
    let mut changed = false;
    let mut restart = sigst::take_current_restart().filter(|_| from_syscall);
    if let Some(sp) = sigst::take_current_restore() {
        let n = sig::head_words(a);
        let restored = {
            let mut buf = FRAME_BUF.lock();
            match get_user_words(sp, &mut buf[..n]).then(|| sig::read_frame(a, &buf[..n])).flatten() {
                Some((r, mask, true)) => {
                    let f = sig::fp_words(a);
                    get_user_words(sp + 8 * f.start as u64, &mut buf[f.clone()]).then(|| {
                        fp_load(&buf[f]);
                        (r, mask)
                    })
                }
                Some((r, mask, false)) => Some((r, mask)),
                None => None,
            }
        };
        let Some((r, mask)) = restored else { die_by_signal(11) };
        *ctx = r;
        sigst::set_current_blocked(mask);
        changed = true;
        // The interrupted call's result is the restored a0; nothing to
        // restart.
        restart = None;
    }
    if cfg!(feature = "linux-signal-canary") {
        // Gate canary only: nothing is ever delivered.
        return changed;
    }
    // Wave 15: a task a forced stop is ending (`SIGKILL`, an `exit_group` or
    // exec of a sibling) runs no handler, as Linux's `fatal_signal_pending`:
    // its signals stay pending, so a process-directed one goes back to the
    // process at its exit (`signal_state::detach`) instead of being taken
    // into a frame whose handler is cut off by the stop.
    if azos_sched::scheduler::current_forced_exit().is_some() {
        return changed;
    }
    let me = azos_sched::current_task_tid();
    while let Some((s, sender)) = sigst::take_current() {
        // The action and, for a handler, the mask its frame saves
        // (`rt_sigsuspend`'s caller's own), in one look at the table.
        let (act, suspended) = with_me(|p| {
            let act = p.act[s as usize - 1];
            let sus = if act.handler > lx::sig::SIG_IGN { p.suspend_saved.take() } else { None };
            (act, sus)
        })
        .unwrap_or((KSA_DFL, None));
        match act.handler {
            lx::sig::SIG_IGN => {
                azos_ipc::trace::trace_event(azos_ipc::trace::TRACE_SIGNAL, me, s, sender, 0);
                continue;
            }
            lx::sig::SIG_DFL => match sig::default_action(s as u64) {
                sig::DefaultAction::Terminate => die_by_signal(s),
                _ => {
                    azos_ipc::trace::trace_event(azos_ipc::trace::TRACE_SIGNAL, me, s, sender, 0);
                    continue;
                }
            },
            handler => {
                // The interrupted call: run again with `SA_RESTART`, else
                // `-EINTR`.
                if let Some(arg) = restart.take() {
                    if ctx.gpr[a0] as i64 == -le::EINTR && act.flags & sig::sa::RESTART != 0 {
                        ctx.gpr[a0] = arg;
                        ctx.pc = ctx.pc.wrapping_sub(4);
                    }
                }
                let ret = match a {
                    lx::Arch::Riscv64 => {
                        let t = azos_mm::vdso::sigtramp_phys();
                        (t != 0).then_some(azos_mm::vdso::SIGTRAMP_USER_VA as u64)
                    }
                    lx::Arch::Aarch64 => {
                        (act.flags & sig::sa::RESTORER != 0 && act.restorer != 0).then_some(act.restorer)
                    }
                };
                // No way back from the handler: end as the default would.
                let Some(ret) = ret else { die_by_signal(s) };
                let saved = suspended.unwrap_or_else(|| sigst::current_blocked().unwrap_or(0));
                let info = sig::Info {
                    signo: s,
                    code: if sender == 0 { sig::si::KERNEL } else { sig::si::USER },
                    pid: sender,
                    status: 0,
                };
                let base = sig::frame_base(a, ctx.gpr[spi]);
                let ok = {
                    let mut buf = FRAME_BUF.lock();
                    let fp = fp_save(&mut buf[sig::fp_words(a)]);
                    match sig::write_frame(a, &mut buf[..], ctx, saved, &info, fp) {
                        Some(n) => put_user_words(base, &buf[..n]),
                        None => false,
                    }
                } && (a != lx::Arch::Aarch64
                    // The frame record {fp, lr} after the ucontext.
                    || put_user_words(base + 8 * sig::a64_frame_record_word() as u64, &[ctx.gpr[29], ctx.gpr[30]]));
                if !ok {
                    // The stack cannot take the frame: SIGSEGV's default.
                    die_by_signal(11);
                }
                ctx.pc = handler;
                ctx.gpr[a0] = s as u64;
                ctx.gpr[a0 + 1] = base;
                ctx.gpr[a0 + 2] = base + sig::SIGINFO_SIZE as u64;
                ctx.gpr[spi] = base;
                match a {
                    lx::Arch::Riscv64 => ctx.gpr[1] = ret,
                    lx::Arch::Aarch64 => {
                        ctx.gpr[30] = ret;
                        ctx.gpr[29] = base + (sig::SIGINFO_SIZE + sig::A64_UC_SIZE) as u64;
                    }
                }
                let mut blocked = sigst::current_blocked().unwrap_or(0) | act.mask;
                if act.flags & sig::sa::NODEFER == 0 {
                    blocked |= sig::bit(s as u64);
                }
                sigst::set_current_blocked(blocked);
                if act.flags & sig::sa::RESETHAND != 0 {
                    with_me(|p| {
                        p.act[s as usize - 1] = KSA_DFL;
                        sigst::set_current_ignored(ignored_of(&p.act));
                    });
                }
                azos_ipc::trace::trace_event(azos_ipc::trace::TRACE_SIGNAL, me, s, sender, 1);
                return true;
            }
        }
    }
    // Only discarded signals interrupted the call: it runs again.
    if let Some(arg) = restart {
        if ctx.gpr[a0] as i64 == -le::EINTR {
            ctx.gpr[a0] = arg;
            ctx.pc = ctx.pc.wrapping_sub(4);
            changed = true;
        }
    }
    // `rt_sigsuspend` ended with no handler run: its caller's mask is back.
    if let Some(m) = with_me(|p| p.suspend_saved.take()).flatten() {
        sigst::set_current_blocked(m);
    }
    changed
}

// ── Stage 3: clone (fork shape) and execve ──────────────────────────────────

/// `clone(flags, newsp, ptid, tls, ctid)` in the shape `fork` and `vfork`
/// take: an exit signal in the low byte, optionally `CLONE_VM | CLONE_VFORK`
/// with no new stack (served as a fork: the child gets a copy-on-write copy,
/// which a vfork child may not tell apart); or a thread (wave 13,
/// [`clone_thread`]). `posix_spawn`'s shared-memory child (`CLONE_VM |
/// CLONE_VFORK` with a stack) is not answered.
///
/// The child is reseeded from the parent's row, never from the parent's
/// table (owner decision, round 47): it holds what the row declares and the
/// descriptors it inherits, nothing the parent acquired otherwise.
#[allow(clippy::too_many_arguments)]
fn sys_clone(
    flags: u64, newsp: u64, ptid: u64, tls: u64, ctid: u64,
    sepc: u64, user_sp: u64, regs: &azos_sched::UserRegs,
) -> i64 {
    use lx::clone::*;
    let rest = flags & !CSIGNAL;
    let vfork = CLONE_VM | CLONE_VFORK;
    // Wave 13: a thread.
    let thread = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
    let optional = CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID
        | CLONE_DETACHED | CLONE_CHILD_SETTID;
    if flags & thread == thread && flags & !(thread | optional) == 0 && newsp != 0 {
        return clone_thread(flags, newsp, ptid, tls, ctid, sepc, regs);
    }
    if !(rest == 0 || (rest == vfork && newsp == 0)) {
        return unanswered(nr::CLONE);
    }
    reach(k::SYS_FORK);
    // Wave 13: a fork from a thread is the process's; its descriptors are
    // the process's to duplicate.
    let _mm = azos_sched::group::mm_lock();
    let parent = azos_sched::current_proc_tid();
    let r = azos_sched::process::sys_fork_impl_hooked(sepc, user_sp, regs, &mut |child| {
        crate::handlers::fork_regions_to_child(child) && fork_child_setup(parent, child)
    });
    if r < 0 { neg(le::EAGAIN) } else { r }
}

/// A thread of the caller's process (wave 13): it resumes after the `clone`
/// with a 0 return on stack `newsp`, its thread pointer `tls`
/// (`CLONE_SETTLS`), its TID stored at `ptid` (`CLONE_PARENT_SETTID`) and at
/// `ctid` (`CLONE_CHILD_SETTID`) before it runs, and `ctid` cleared and woken
/// at its exit (`CLONE_CHILD_CLEARTID`). It shares the personality entry
/// (descriptors, working directory, signal state) with every thread of the
/// process.
#[allow(clippy::too_many_arguments)]
fn clone_thread(
    flags: u64, newsp: u64, ptid: u64, tls: u64, ctid: u64,
    sepc: u64, regs: &azos_sched::UserRegs,
) -> i64 {
    use lx::clone::*;
    if newsp & 15 != 0 {
        return neg(le::EINVAL);
    }
    reach(k::SYS_THREAD_CREATE);
    let clear = if flags & CLONE_CHILD_CLEARTID != 0 { ctid } else { 0 };
    let tls = (flags & CLONE_SETTLS != 0).then_some(tls);
    let r = azos_sched::process::thread_create_impl(
        azos_sched::process::resume_pc_after(sepc), newsp, tls, clear, regs, None,
        &mut |child| {
            let id = (child as i32).to_le_bytes();
            // Its signal words: the creating thread's mask, the process's
            // dispositions, nothing pending (Linux's thread clone).
            let ign = with_me(|p| ignored_of(&p.act)).unwrap_or(0);
            sigst::attach(child, sigst::current_blocked().unwrap_or(0), ign);
            (flags & CLONE_PARENT_SETTID == 0 || ptid == 0 || put_user(ptid, &id))
                && (flags & CLONE_CHILD_SETTID == 0 || ctid == 0 || put_user(ctid, &id))
        },
    );
    if r < 0 { neg(le::EAGAIN) } else { r }
}

/// The parent's descriptors as the child sees them, its row's capabilities,
/// and a copy of the parent's personality state. In the parent's context,
/// before the child can run.
///
/// Wave 13 (DEBTS): only the descriptor slots (192 B), the row and the image
/// path are read onto the stack. The rest of the parent's entry — 64 signal
/// actions (2 KiB), the open directories, the working directory — is copied
/// entry to entry under `TABLE` at the end. The old body took the whole
/// entry by value as a tuple and then destructured it, which made this
/// closure the largest frame in the fleet image (5776 B).
fn fork_child_setup(parent: u32, child: u32) -> bool {
    let Some((fds, row, row_len, exe, exe_len)) = with_me(|p| (p.fds, p.row, p.row_len, p.exe, p.exe_len)) else {
        return false;
    };
    // The child inherits the mask and the dispositions, never a pending
    // signal (Linux's fork).
    let mask = sigst::current_blocked().unwrap_or(0);
    let Ok(row_str) = core::str::from_utf8(&row[..row_len as usize]) else { return false };
    if !proc_init(child, row_str, &exe[..exe_len as usize]) {
        return false;
    }
    match crate::spawn::seed_caps(child, row_str) {
        crate::spawn::Seeded::Caps { .. } => {}
        _ => return false,
    }
    #[cfg(feature = "linux-abi-fork-canary")]
    {
        // Gate canary only: the child gets a grant its row does not declare.
        let _ = azos_ipc::cap_seed::seed_one_cap_outcome(
            child, azos_abi::cap::CapKind::File, azos_abi::cap::CapPerms::RW, "/fat",
        );
    }
    // Each distinct handle once; aliases (`dup3`) keep sharing it. Outside
    // `TABLE`: `dup_handle_into` takes the capability and file locks.
    let mut map = [(0u32, 0u32); FDS];
    let mut nmap = 0usize;
    let mut child_fds = fds;
    for e in child_fds.iter_mut() {
        if e.kind != Kind::Handle {
            continue;
        }
        let new = match map[..nmap].iter().find(|m| m.0 == e.handle) {
            Some(m) => m.1,
            None => match dup_handle_into(parent, child, e.handle) {
                Some(h) => {
                    map[nmap] = (e.handle, h);
                    nmap += 1;
                    h
                }
                None => return false,
            },
        };
        e.handle = new;
    }
    let mut t = TABLE.lock();
    let Some(pi) = t.iter().position(|p| p.tid == parent && parent != 0) else { return false };
    let Some(ci) = t.iter().position(|p| p.tid == child) else { return false };
    if pi == ci {
        return false;
    }
    // Two disjoint entries, so each field is copied entry to entry.
    let (src, dst) = if pi < ci {
        let (a, b) = t.split_at_mut(ci);
        (&a[pi], &mut b[0])
    } else {
        let (a, b) = t.split_at_mut(pi);
        (&b[0], &mut a[ci])
    };
    dst.fds = child_fds;
    dst.dirs = src.dirs;
    dst.cwd = src.cwd;
    dst.cwd_len = src.cwd_len;
    dst.act = src.act;
    dst.umask = src.umask;
    let ign = ignored_of(&dst.act);
    drop(t);
    sigst::attach(child, mask, ign);
    true
}

/// Give `child` its own handle on what `parent`'s `handle` names: another
/// handle on the same pipe end (one more reader or writer on it), or a
/// duplicate descriptor of the same file. The duplicate shares the parent's
/// open file description, so the two share one offset as on Linux; each
/// descriptor keeps its own owner (`set_owner`). `None` if it cannot.
fn dup_handle_into(parent: u32, child: u32, handle: u32) -> Option<u32> {
    use azos_abi::cap::{CapHandle, CapKind, CapPerms};
    use azos_ipc::cap::targets::{File, Pipe};
    let (kind, perms, res) =
        azos_ipc::cap_store::with_table(parent, |t| t.peek_raw(CapHandle::from_raw(handle))).flatten()?;
    match kind {
        CapKind::Pipe => {
            let w = perms.contains(CapPerms::WRITE);
            if !azos_ipc::pipe::pipe_typed_add_end(res, w) {
                return None;
            }
            match azos_ipc::cap_store::grant::<Pipe>(child, perms, res) {
                Some(c) => Some(c.raw().as_raw()),
                None => {
                    let _ = azos_ipc::pipe::pipe_typed_drop_end(res, w);
                    None
                }
            }
        }
        CapKind::File if !azos_ipc::file_cap::is_tree_resource(res) => {
            let ops = file_ops()?;
            let nfd = ops.dup(res as i32);
            if nfd < 0 {
                return None;
            }
            if ops.set_owner(nfd as i32, parent, child) != 0 {
                let _ = ops.close(nfd as i32);
                return None;
            }
            match azos_ipc::cap_store::grant::<File>(child, perms, nfd as u32) {
                Some(c) => Some(c.raw().as_raw()),
                // The child owns it now; its exit closes it.
                None => None,
            }
        }
        _ => None,
    }
}

/// Most argv and environment bytes an `execve` passes on.
const EXEC_STRINGS_MAX: usize = 2048;

/// Copy a NULL-terminated array of user string pointers into `out` as
/// NUL-terminated strings; `(bytes, count)`.
fn user_strv(ptr: u64, out: &mut [u8]) -> Result<(usize, usize), i64> {
    let mut used = 0usize;
    let mut n = 0usize;
    if ptr == 0 {
        return Ok((0, 0));
    }
    loop {
        let Some(sp) = get_u64(ptr + 8 * n as u64) else { return Err(neg(le::EFAULT)) };
        if sp == 0 {
            return Ok((used, n));
        }
        if n >= lx::STACK_STRINGS_MAX {
            return Err(-7); // E2BIG
        }
        let mut tmp = [0u8; 256];
        if azos_sched::copy_cstr_from_user(&mut tmp, sp as usize).is_none() {
            return Err(neg(le::EFAULT));
        }
        let l = tmp.iter().position(|&b| b == 0).ok_or(-7i64)?;
        if used + l + 1 > out.len() {
            return Err(-7);
        }
        out[used..used + l].copy_from_slice(&tmp[..l]);
        out[used + l] = 0;
        used += l + 1;
        n += 1;
    }
}

/// `execve(path, argv, envp)`: replace the image with a Linux image (its
/// digest bound to a row's profile), keeping the descriptors that are not
/// close-on-exec, the working directory, the mask and the ignored signals,
/// as Linux does.
///
/// Wave 13: the image may be another Linux row's. It then runs with THAT
/// row's authority, never the caller's: the caller must hold a launch grant
/// (`Cap<Launch>` `EXEC`) for it, as `SYS_SPAWN_EX` requires, and the new
/// image's capability table is the target row's seed plus only the handles
/// its inherited descriptors stand on; its filter is the target row's
/// profile. Refused without the grant (recorded, `-EACCES`); entered, it is
/// said on the console.
fn sys_execve(path_ptr: u64, argv_ptr: u64, envp_ptr: u64) -> i64 {
    let mut raw = [0u8; PATH_MAX];
    let n = match user_path(path_ptr, &mut raw) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let mut path = [0u8; PATH_MAX];
    let plen = match resolve(lx::AT_FDCWD, &raw[..n], &mut path) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let mut strs = [0u8; EXEC_STRINGS_MAX];
    let (al, argc) = match user_strv(argv_ptr, &mut strs) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (el, envc) = match user_strv(envp_ptr, &mut strs[al..]) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(ops) = file_ops() else { return neg(le::EIO) };
    let Some((row, row_len)) = with_me(|p| (p.row, p.row_len)) else { return neg(le::EFAULT) };
    reach(k::SYS_EXECPATH);
    let random = random16();
    let mut buf = crate::handlers::EXEC_BOUNCE.lock();
    let img = match crate::spawn::read_image(ops, &path[..plen], &mut buf[..]) {
        Ok(i) => i,
        Err(e) => return lx::errno_from_native(e, le::ENOENT),
    };
    let Some(profile) = azos_sched::seccomp::image_for_digest(&img.digest) else {
        let _ = crate::handlers::exec_image_is_bound_by_digest(&img.digest);
        return neg(le::EACCES);
    };
    let me = azos_sched::current_task_tid();
    let own = core::str::from_utf8(&row[..row_len as usize]).unwrap_or("?");
    let cross = profile.image.as_bytes() != &row[..row_len as usize];
    if !row_is_linux(profile.image) {
        azos_drv_sys::kwarn!(
            "[LINUX] tid={} execve REFUSED: {} is not a Linux row (from row {})", me, profile.image, own,
        );
        let head = u32::from_be_bytes([img.digest[0], img.digest[1], img.digest[2], img.digest[3]]);
        crate::handlers::record_exec_refused(crate::ushell::SPAWN_REFUSED_ACTION_NO_LAUNCH, head);
        return neg(le::EACCES);
    }
    if cross && !cfg!(feature = "linux-exec-row-canary") {
        use azos_abi::cap::{CapKind, CapPerms};
        let granted = azos_ipc::launch_cap::launch_resource_of(profile.image.as_bytes()).is_some_and(|r| {
            azos_ipc::cap_store::with_table(me, |t| {
                t.holds_kind_resource_uncontained(CapKind::Launch, r, CapPerms::EXEC)
            })
            .unwrap_or(false)
        });
        if !granted {
            let recorded = crate::handlers::note_typed_denial_recorded(
                me, CapKind::Launch, azos_ipc::cap::CapError::MissingPerms,
            );
            let head = u32::from_be_bytes([img.digest[0], img.digest[1], img.digest[2], img.digest[3]]);
            crate::handlers::record_exec_refused(crate::ushell::SPAWN_REFUSED_ACTION_NO_LAUNCH, head);
            azos_drv_sys::kwarn!(
                "[LINUX] tid={} execve REFUSED: row {} holds no launch grant for {}{}",
                me, own, profile.image, if recorded { " (recorded)" } else { "" },
            );
            return neg(le::EACCES);
        }
    }
    let mem = if cross { Some(crate::topo_sched::resolve_mem(profile.image, None).0) } else { None };
    let (argv, env) = strs[..al + el].split_at(al);
    let prepared = crate::spawn::with_elf(ops, &img, &path[..plen], &mut buf[..], &mut |elf| {
        azos_sched::process::exec_prepare_image(elf, mem, &mut |user_pt, aux| {
            azos_sched::spawn::write_linux_stack_into(user_pt, aux, argv, argc, env, envc, &random)
        })
    });
    drop(buf);
    let Some(prepared) = prepared else { return neg(le::ENOMEM) };
    // Wave 15 (plan 4a): every check has passed and the new image is built;
    // only now do the other threads end (`handlers::exec_end_other_threads`:
    // a refused execve leaves them running; before, they ran on across it).
    // A thread that was not the leader holds the process's TID after it.
    if crate::handlers::exec_end_other_threads().is_err() {
        azos_sched::process::exec_abort(prepared);
        return neg(le::EINTR);
    }
    let _ = azos_sched::process::exec_commit(prepared);
    // The robust list named the old image's memory (Linux drops it at exec).
    azos_sched::group::set_current_robust_list(0);
    let me = azos_sched::current_task_tid();
    if cross {
        enter_row(me, profile, own);
    }
    // The new image starts without FP state (riscv64; aarch64 resets it on
    // the exec hand-off).
    azos_sched::fp::exec_reset();
    // The new image: close-on-exec descriptors closed, caught signals back to
    // their default (ignored ones stay ignored).
    let mut closing = [usize::MAX; FDS];
    with_me(|p| {
        if plen <= EXE_MAX {
            p.exe[..plen].copy_from_slice(&path[..plen]);
            p.exe_len = plen as u8;
        }
        for (i, f) in p.fds.iter().enumerate() {
            if f.cloexec && f.kind != Kind::Closed {
                closing[i] = i;
            }
        }
        for a in p.act.iter_mut() {
            if a.handler != lx::sig::SIG_IGN {
                *a = KSA_DFL;
            }
        }
        sigst::set_current_ignored(ignored_of(&p.act));
    });
    for &i in closing.iter().filter(|&&i| i != usize::MAX) {
        let _ = sys_close(i as u64);
    }
    0
}

/// Wave 13: the current task (`me`, a Linux task that has just exec'd an
/// image of row `profile.image`) takes that row's authority instead of its
/// own row's (`own`): every capability goes but the pipe ends and open files
/// its inherited descriptors stand on, the row's grants are seeded, its
/// profile becomes the task's filter, and the row is what a fork reseeds
/// from and what `execve` is measured against from now on.
fn enter_row(me: u32, profile: &'static azos_sched::seccomp::ImageProfile, own: &str) {
    use azos_abi::cap::CapKind;
    let dropped = azos_ipc::cap_store::with_table(me, |t| {
        t.revoke_where(|kind, res| {
            !(kind == CapKind::Pipe || (kind == CapKind::File && !azos_ipc::file_cap::is_tree_resource(res)))
        })
    })
    .unwrap_or(0);
    let seeded = crate::spawn::seed_caps(me, profile.image);
    azos_sched::set_current_syscall_filter(azos_sched::seccomp::image_filter(profile));
    with_me(|p| {
        let n = profile.image.len().min(p.row.len());
        p.row = [0; 16];
        p.row[..n].copy_from_slice(&profile.image.as_bytes()[..n]);
        p.row_len = n as u8;
    });
    azos_drv_sys::kprintln!(
        "[LINUX] tid={} execve into row {} (from row {}): {} capabilities dropped, {:?}",
        me, profile.image, own, dropped, seeded,
    );
}
