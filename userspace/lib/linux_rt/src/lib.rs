// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Linux personality as a ring-3 runtime ("Linux ABI without a
//! kernel map"; moved out of the kernel).
//!
//! The kernel knows no Linux system-call number. A Linux process runs in an
//! address space that also holds this runtime, mapped at spawn
//! (`azos_sched::foreign`). Each Linux trap is reflected to [`Runtime::dispatch`]
//! with the thread's registers in a [`ForeignFrame`] (`azos_abi::foreign`); the
//! runtime answers what it owns itself and maps the rest onto native calls
//! through the [`Native`] trait, writes the result into the frame, and the
//! image that wraps it (`userspace/services/lxrt`) resumes the program.
//!
//! # What the runtime keeps
//!
//! The state of the Linux process, in this address space and nowhere else:
//! the descriptor table (small integers onto the console, `Cap<File>` handles,
//! pipe ends and open directories; a pipe end is a byte ring in a shared
//! region the image maps, `azos_bytepipe`), the working directory, the
//! umask, the signal actions and mask (state only: nothing is delivered), and
//! the image's path. A fork copies it with the address space. A spawn hands
//! the first three over: the descriptors and working directory the spawn
//! request asked for arrive in the startup block a native child gets
//! (`azos_abi::ushell::StartupBlock`), and [`Runtime::init`] builds the
//! table from it.
//!
//! # What it asks of the kernel
//!
//! Nothing it did not already offer a native process. Every [`Native`] call is
//! an ordinary system call, filtered by the row's image profile and checked
//! against the task's capability tables. A Linux image has exactly the
//! authority its row gives it; this crate adds none, and a program that
//! jumps into it gets no more than the image has.
//!
//! # What it does not answer yet
//!
//! Anything that needs a native primitive the ABI does not have until the ABI
//! cut (D6): `lseek` (a `Cap<File>` has no seek), `mprotect`, signal delivery
//! and `kill` (no upcall into the process), `clone` as a thread (the native
//! thread's start and clear-on-exit are not a Linux thread's), `execve` (the
//! native exec refuses a Linux image and carries no argument vector),
//! requeue and priority-inheritance futexes, and console input. Each answers
//! `-ENOSYS` (or end of file, for the console) and is reported once per call
//! number, never silently.
//!
//! `clone` in the fork and vfork shapes and `wait4` are answered over the
//! foreign-ABI family's `SYS_FOREIGN_FORK` and the domain's `wait` op: the
//! fork already gives the child the parent's open files at the same handles,
//! sharing their offsets, and the regions of its pipes as shared mappings (the
//! kernel counts the child's pipe ends in the fork), so the descriptor table
//! that is copied with the address space is the child's as it stands.

#![no_std]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use azos_abi::foreign::{ForeignFrame, REG_NUMBER, REG_RESULT};
use azos_abi::time::{ClockError, ClockId};
use azos_abi::ushell::{StartupFd, FD_CONSOLE as SFD_CONSOLE, FD_HANDLE as SFD_HANDLE, STARTUP_FDS};
use azos_abi::syscall_nr::{STAT_BYTES, STAT_OFF_ATIME, STAT_OFF_CTIME, STAT_OFF_MODE, STAT_OFF_MTIME, STAT_OFF_NLINK, STAT_OFF_SIZE, STAT_S_IFDIR, STAT_S_IFMT};
use azos_linux_abi as lx;
use azos_linux_abi::errno as le;
use azos_linux_abi::nr;

/// The native calls the runtime makes for itself, whatever the Linux program
/// asks: it registers its trap entry and resumes the program, copies the
/// process for a `fork`, learns its own thread id, finds its console capability, and reads the clock when the vDSO has no counter. A Linux
/// image's seccomp profile lists these beside the native numbers its Linux
/// calls reach (`azos_linux_abi::native_reach`).
pub const RUNTIME_NATIVE: &[u16] = &[
    azos_abi::syscall_nr::SYS_FOREIGN_ENTRY as u16,
    azos_abi::syscall_nr::SYS_FOREIGN_RESUME as u16,
    azos_abi::syscall_nr::SYS_FOREIGN_FORK as u16,
    azos_abi::syscall_nr::SYS_GETPID as u16,
    azos_abi::syscall_nr::SYS_INVOKE as u16,
    // The console capability: `azos_libsys::console_cap` looks it up
    // (`CAP_INFO_LOOKUP`) before the runtime's first write to the console.
    azos_abi::syscall_nr::SYS_CAP_INFO as u16,
];

/// The `SYS_INVOKE` ops the runtime issues for the program's Linux calls (its
/// `Native` implementation, `userspace/services/lxrt`): the console write, the
/// file ops, `stat`/`readdir`, the clock, `wait4`, and the memory-object ops
/// a pipe's ends use. The runtime shares the program's address space, so the
/// program can issue every one of them whatever it asks: a Linux image's
/// seccomp profile lists their classes beside [`RUNTIME_NATIVE`] (checked by
/// `tests/host/seccomp-tests`, which also scans the runtime's source).
pub const RUNTIME_OPS: &[u16] = &[
    azos_abi::invoke::LOG_CONSOLE_WRITE,
    azos_abi::invoke::NODE_OPENAT,
    azos_abi::invoke::NODE_READ,
    azos_abi::invoke::NODE_WRITE,
    azos_abi::invoke::DOMAIN_STAT,
    azos_abi::invoke::DOMAIN_READDIR,
    azos_abi::invoke::DOMAIN_UPTIME,
    azos_abi::invoke::DOMAIN_WAIT,
    azos_abi::invoke::MEMOBJ_ACQUIRE,
    azos_abi::invoke::MEMOBJ_END_DROP,
];

/// Descriptors per process (0..FDS).
pub const FDS: usize = 16;
/// Open directories per process.
pub const DIRS: usize = 4;
/// Longest path kept for an open directory or an open file.
pub const KEEP_PATH_MAX: usize = 96;
/// Longest working directory.
pub const CWD_MAX: usize = 64;
/// Longest path an open/stat call resolves.
pub const PATH_MAX: usize = 256;
/// Bytes one read, write, readv or writev moves at most (Kconfig
/// `LINUX_IO_MAX`).
pub const IO_MAX: usize = azos_limits::LINUX_IO_MAX;
/// Signals with an action slot (1..=64).
pub const NSIG: usize = 64;
/// Longest image path `/proc/self/exe` resolves to.
pub const EXE_MAX: usize = 64;
/// Size of the native directory-entry name buffer.
pub const NAME_BYTES: usize = azos_abi::syscall_nr::READDIR_NAME_BYTES;

/// The native calls the runtime makes. The runtime image implements them
/// with `azos_libsys`; the host tests implement them with a model. Every
/// error is the native negative code (`azos_linux_abi::errno_from_native` maps
/// it to a Linux errno).
pub trait Native {
    /// The calling thread's id (`SYS_GETPID`).
    fn getpid(&self) -> i64;
    /// Monotonic nanoseconds (the vDSO, no system call).
    fn now_ns(&self) -> u64;
    /// Now on a native clock (`libsys::clock_now`: the vDSO, no system call).
    fn clock_ns(&self, id: ClockId) -> Result<u64, ClockError>;
    /// Write to the console (the console handle's `WRITE` op): bytes written.
    fn console_write(&self, buf: &[u8]) -> i64;
    /// Open `path` (NUL-terminated, absolute) with the native flags, beneath
    /// the task's root `Cap<Dir>` (`NODE_OPENAT`): a `Cap<File>` handle.
    fn file_open(&self, path: &[u8], flags: u64) -> i64;
    /// Read through a `Cap<File>` handle or a pipe end.
    fn handle_read(&self, h: u32, buf: &mut [u8]) -> i64;
    /// Write through a `Cap<File>` handle or a pipe end (`-EPIPE` when no
    /// reader is left).
    fn handle_write(&self, h: u32, buf: &[u8]) -> i64;
    /// Close a handle of either kind (`SYS_CAP_CLOSE`).
    fn handle_close(&self, h: u32) -> i64;
    /// Make a pipe: read and write end handles (an end may be a token of the
    /// image's own byte pipes, see [`Native::handle_is_pipe`]).
    fn pipe(&self, ends: &mut [u32; 2], nonblock: bool) -> i64;
    /// Is the handle `h` a pipe end? (Reads, writes and closes go the same way
    /// for a file and a pipe end; a write to a pipe end with no reader left
    /// raises `SIGPIPE`, and `fcntl(F_SETFL)` reaches the end's description.)
    fn handle_is_pipe(&self, h: u32) -> bool;
    /// `O_NONBLOCK` of the pipe end `h` changed (`fcntl(F_SETFL)`): a flag of
    /// the open file description, which the image keeps with the end.
    fn handle_set_nonblock(&self, _h: u32, _on: bool) {}
    /// `DOMAIN_STAT`: the record `azos_abi::syscall_nr::STAT_BYTES` documents.
    fn stat(&self, path: &[u8], out: &mut [u8; STAT_BYTES]) -> i64;
    /// `DOMAIN_READDIR`: entry `idx` of the directory `dir` (NUL-terminated).
    fn readdir(&self, dir: &[u8], idx: u64, name: &mut [u8; NAME_BYTES], size: &mut u32, is_dir: &mut u32) -> i64;
    /// The granule `SYS_MO_MAP` rounds a length up to (the build's page size).
    fn page_size(&self) -> u64;
    /// Anonymous private memory (`SYS_MO_MAP`); `flags` are Linux's
    /// `MAP_POPULATE | MAP_LOCKED` bits only.
    fn mmap(&self, addr: u64, len: u64, prot: u64, flags: u64) -> i64;
    /// `SYS_MO_UNMAP`.
    fn munmap(&self, addr: u64, len: u64) -> i64;
    /// Sleep until the monotonic clock reads `deadline_ns` (`SYS_SLEEP_UNTIL`).
    fn sleep_until_ns(&self, deadline_ns: u64);
    /// `SYS_YIELD`.
    fn yield_now(&self);
    /// `SYS_FOREIGN_FORK`: 0 in the child, the child's id in the parent. The
    /// child has the parent's open descriptions at the same handles (the
    /// kernel duplicates them, sharing offsets) and the parent's address
    /// space, this runtime's state with it.
    fn fork(&self) -> i64;
    /// The domain's `wait` op: the child `tid`'s exit code in `code` and `tid` when it
    /// has ended; a negative code while it has not (`-1`), or `-ECHILD`-like
    /// (any other negative) when it is nobody's child.
    fn waitpid(&self, tid: u32, code: &mut i32) -> i64;
    /// `SYS_EXIT`.
    fn exit(&self, code: i32) -> !;
}

// ── A lock for the process's state ──────────────────────────────────────────

/// A spin lock. The state is small and never held across a native call that
/// can block; a thread that fails to take it yields.
pub struct Lock<T> {
    held: AtomicBool,
    v: UnsafeCell<T>,
}

// SAFETY: the flag serialises every access to the cell.
unsafe impl<T: Send> Sync for Lock<T> {}

impl<T> Lock<T> {
    /// A lock around `v`.
    pub const fn new(v: T) -> Self {
        Self { held: AtomicBool::new(false), v: UnsafeCell::new(v) }
    }

    /// Run `f` on the protected value.
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        while self.held.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        // SAFETY: the flag is held.
        let r = f(unsafe { &mut *self.v.get() });
        self.held.store(false, Ordering::Release);
        r
    }
}

// ── The spawn's hand-over ───────────────────────────────────────────────────

/// What a spawn hands the process: the descriptors 0..=7 and the working
/// directory of the request (`azos_abi::ushell::StartupBlock`, read by the
/// image from the address the kernel passes in the second argument register).
pub struct Startup<'a> {
    /// Child descriptors 0..=7: closed, the console, or a handle moved into
    /// this process's capability table.
    pub fds: &'a [StartupFd; STARTUP_FDS],
    /// The working directory, absolute; empty (or too long for the
    /// runtime's `CWD_MAX`) keeps `/`.
    pub cwd: &'a [u8],
}

// ── State ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Closed,
    Console,
    /// A `Cap<File>`.
    File,
    /// A pipe end (see [`Native::handle_is_pipe`]).
    Pipe,
    Dir,
}

#[derive(Clone, Copy, Debug)]
struct FdEnt {
    kind: Kind,
    /// The native handle, for `File` and `Pipe`.
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
    path: [u8; KEEP_PATH_MAX],
}

const DIR_FREE: DirEnt = DirEnt { used: false, len: 0, next: 0, path: [0; KEEP_PATH_MAX] };

/// A path kept for an open file, so `fstat` can ask the native `stat`.
#[derive(Clone, Copy)]
struct KeptPath {
    len: u8,
    path: [u8; KEEP_PATH_MAX],
}

const NO_PATH: KeptPath = KeptPath { len: 0, path: [0; KEEP_PATH_MAX] };

const KSA_DFL: lx::KSigaction = lx::KSigaction { handler: 0, flags: 0, restorer: 0, mask: 0 };

struct State {
    fds: [FdEnt; FDS],
    paths: [KeptPath; FDS],
    dirs: [DirEnt; DIRS],
    cwd: [u8; CWD_MAX],
    cwd_len: u8,
    act: [lx::KSigaction; NSIG],
    mask: u64,
    umask: u32,
    exe: [u8; EXE_MAX],
    exe_len: u8,
    /// Unanswered calls reported so far (bounded).
    reported: u8,
    /// The thread-id word `set_tid_address` was given.
    tid_addr: u64,
    /// Children forked and not yet reaped (0: free).
    children: [u32; CHILDREN],
    /// The program break (0 until the program first asks): what `brk` answers.
    brk_cur: u64,
    /// The end of the pages mapped for the break (`brk_cur` rounded up).
    brk_end: u64,
}

/// Children one process may have unreaped at once.
pub const CHILDREN: usize = 16;

const STATE_INIT: State = State {
    fds: [FD_CLOSED; FDS],
    paths: [NO_PATH; FDS],
    dirs: [DIR_FREE; DIRS],
    cwd: [0; CWD_MAX],
    cwd_len: 0,
    act: [KSA_DFL; NSIG],
    mask: 0,
    umask: 0o022,
    exe: [0; EXE_MAX],
    exe_len: 0,
    reported: 0,
    tid_addr: 0,
    children: [0; CHILDREN],
    brk_cur: 0,
    brk_end: 0,
};

fn arch() -> lx::Arch {
    lx::Arch::native()
}

fn neg(e: i64) -> i64 {
    -e
}

// ── The runtime ─────────────────────────────────────────────────────────────

/// The Linux personality of one process.
pub struct Runtime<N: Native> {
    native: N,
    st: Lock<State>,
    /// The process's id (its first thread's), asked of the kernel once at
    /// [`Runtime::init`]: `getpid` and `gettid` are answered from it with no
    /// native call.
    pid: AtomicI64,
    /// The id of the process that forked this one, or 1 for one the shell
    /// started (the native ABI does not say who started a process).
    ppid: AtomicI64,
}

impl<N: Native> Runtime<N> {
    /// A runtime with the process's initial state: the console on
    /// descriptors 0, 1 and 2, working directory `/`.
    pub const fn new(native: N) -> Self {
        Self { native, st: Lock::new(STATE_INIT), pid: AtomicI64::new(0), ppid: AtomicI64::new(1) }
    }

    /// The native calls, for the image that wraps the runtime.
    pub fn native(&self) -> &N {
        &self.native
    }

    /// Set the process up: its descriptors and working directory from the
    /// startup block the spawn gave it (`startup`), or, for a spawn that
    /// gave none (`SYS_SPAWN_EX` without a request), the console on 0..=2 and `/`;
    /// and the image's path (what `/proc/self/exe` names).
    pub fn init(&self, exe: &[u8], startup: Option<&Startup>) {
        self.pid.store(self.native.getpid(), Ordering::Relaxed);
        self.st.with(|s| {
            *s = STATE_INIT;
            s.cwd[0] = b'/';
            s.cwd_len = 1;
            match startup {
                None => {
                    s.fds[0] = FD_CONSOLE;
                    s.fds[1] = FD_CONSOLE;
                    s.fds[2] = FD_CONSOLE;
                }
                Some(st) => {
                    for (fd, f) in st.fds.iter().enumerate() {
                        s.fds[fd] = match f.kind {
                            SFD_CONSOLE => FD_CONSOLE,
                            // The kind is in the handle's own bits: the
                            // native read, write and close calls serve both.
                            SFD_HANDLE => FdEnt {
                                kind: if self.native.handle_is_pipe(f.handle) {
                                    Kind::Pipe
                                } else {
                                    Kind::File
                                },
                                handle: f.handle,
                                accmode: 2,
                                ..FD_CLOSED
                            },
                            _ => FD_CLOSED,
                        };
                    }
                    if st.cwd.first() == Some(&b'/') && st.cwd.len() <= CWD_MAX {
                        s.cwd[..st.cwd.len()].copy_from_slice(st.cwd);
                        s.cwd_len = st.cwd.len() as u8;
                    }
                }
            }
            let n = exe.len().min(EXE_MAX);
            s.exe[..n].copy_from_slice(&exe[..n]);
            s.exe_len = n as u8;
        });
    }

    /// Answer the Linux call in `f` and write the result into it. The
    /// number is in the ISA's number register, the arguments in its first six
    /// argument registers (`azos_abi::foreign`).
    pub fn dispatch(&self, f: &mut ForeignFrame) {
        let num = f.gpr[REG_NUMBER];
        let a = |i: usize| f.gpr[REG_RESULT + i];
        let r = self.call(num, a(0), a(1), a(2), a(3), a(4), a(5));
        f.gpr[REG_RESULT] = r as u64;
    }

    /// Answer the x86-64 Linux call in `f` and write the result into it:
    /// [`Self::dispatch`] for the one ISA whose ABI is not the asm-generic
    /// one. The number is in `rax` and the arguments in `rdi rsi rdx r10 r8
    /// r9`; `azos_linux_abi::x86_64::translate` turns the call into the one
    /// the runtime answers, and the layouts that differ (`struct stat`,
    /// `struct utsname`, `struct sigaction`) are written in x86-64's.
    /// A call the runtime does not answer is `-ENOSYS`, reported under its
    /// x86-64 number.
    pub fn dispatch_x86_64(&self, f: &mut ForeignFrame) {
        use lx::x86_64::{self as x86, Post};
        let num = f.gpr[x86::REG_NUMBER];
        let args = x86::REG_ARGS.map(|r| f.gpr[r]);
        let r = match x86::translate(num, args) {
            None => self.unanswered(num),
            Some(c) => {
                let a = c.args;
                match c.post {
                    Post::None => self.call(c.num, a[0], a[1], a[2], a[3], a[4], a[5]),
                    Post::Sigaction => self.sys_rt_sigaction(lx::Arch::Aarch64, a[0], a[1], a[2], a[3]),
                    Post::Uname(buf) => put_user(buf, &x86::utsname_bytes(b"azos")),
                    Post::DupSame(fd) => {
                        let r = self.call(c.num, a[0], a[1], a[2], a[3], a[4], a[5]);
                        if r < 0 { r } else { fd as i64 }
                    }
                    Post::Stat(buf) => {
                        let r = self.call(c.num, a[0], a[1], a[2], a[3], a[4], a[5]);
                        if r < 0 {
                            r
                        } else {
                            // The call wrote the generic layout there.
                            let mut g = [0u8; lx::STAT_SIZE];
                            if get_user(buf, &mut g) != 0 {
                                neg(le::EFAULT)
                            } else {
                                put_user(buf, &x86::stat_from_generic(&g))
                            }
                        }
                    }
                }
            }
        };
        f.gpr[x86::REG_RESULT] = r as u64;
    }

    #[allow(clippy::too_many_arguments)]
    fn call(&self, num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
        let _ = a5;
        match num {
            // A process is a thread group of one here; its id is the thread's.
            nr::GETPID | nr::GETTID => self.pid.load(Ordering::Relaxed),
            nr::SET_TID_ADDRESS => {
                self.st.with(|s| s.tid_addr = a0);
                self.pid.load(Ordering::Relaxed)
            }
            // No users on this kernel (POSIX subset rule 3): everyone is 0.
            nr::GETUID | nr::GETEUID | nr::GETGID | nr::GETEGID => 0,
            nr::WRITE => self.sys_write(a0, a1, a2),
            nr::READ => self.sys_read(a0, a1, a2),
            nr::WRITEV => self.sys_rwv(a0, a1, a2, true),
            nr::READV => self.sys_rwv(a0, a1, a2, false),
            nr::OPENAT => self.sys_openat(a0, a1, a2),
            nr::CLOSE => self.sys_close(a0),
            nr::FSTAT => self.sys_fstat(a0, a1),
            nr::NEWFSTATAT => self.sys_newfstatat(a0, a1, a2, a3),
            nr::GETDENTS64 => self.sys_getdents64(a0, a1, a2),
            nr::PIPE2 => self.sys_pipe2(a0, a1),
            nr::DUP => self.sys_dup3(a0, u64::MAX, 0),
            nr::DUP3 => self.sys_dup3(a0, a1, a2),
            nr::FCNTL => self.sys_fcntl(a0, a1, a2),
            nr::IOCTL => self.sys_ioctl(a0, a1, a2),
            nr::GETCWD => self.sys_getcwd(a0, a1),
            nr::CHDIR => self.sys_chdir(a0),
            nr::EXIT | nr::EXIT_GROUP => self.native.exit((a0 & 0xff) as i32),
            nr::CLONE => self.sys_clone(a0, a1),
            nr::WAIT4 => self.sys_wait4(a0, a1, a2, a3),
            nr::GETPPID => self.ppid.load(Ordering::Relaxed),
            nr::BRK => self.sys_brk(a0),
            nr::MMAP => self.sys_mmap(a0, a1, a2, a3, a4),
            nr::MUNMAP => lx::errno_from_native(self.native.munmap(a0, a1), le::EINVAL),
            nr::CLOCK_GETTIME => self.sys_clock_gettime(a0, a1),
            nr::NANOSLEEP => self.sys_nanosleep(a0),
            nr::SCHED_YIELD => {
                self.native.yield_now();
                0
            }
            nr::RT_SIGACTION => self.sys_rt_sigaction(arch(), a0, a1, a2, a3),
            nr::RT_SIGPROCMASK => self.sys_rt_sigprocmask(a0, a1, a2, a3),
            nr::RT_SIGPENDING => self.sys_rt_sigpending(a0, a1),
            nr::SIGALTSTACK => self.sys_sigaltstack(a0, a1),
            nr::UNAME => {
                let u = lx::utsname_bytes(arch(), b"azos");
                put_user(a0, &u)
            }
            nr::UMASK => self.st.with(|s| {
                let old = s.umask;
                s.umask = (a0 & 0o777) as u32;
                old as i64
            }),
            nr::SCHED_GETAFFINITY => {
                if a1 < 8 {
                    return neg(le::EINVAL);
                }
                if put_user(a2, &1u64.to_le_bytes()) == 0 { 8 } else { neg(le::EFAULT) }
            }
            nr::PRCTL => match a0 {
                // PR_SET_NAME, PR_GET_NAME: the task's name is its image's.
                15 => 0,
                16 => put_user(a1, &[0u8; 16]),
                _ => neg(le::EINVAL),
            },
            _ => self.unanswered(num),
        }
    }

    /// A Linux call the runtime does not answer: `-ENOSYS`, reported on the
    /// console the first few times.
    fn unanswered(&self, num: u64) -> i64 {
        let first = self.st.with(|s| {
            let f = s.reported < 16;
            s.reported = s.reported.saturating_add(1);
            f
        });
        if first {
            let mut line = [0u8; 96];
            let mut n = 0;
            for part in [&b"[LINUX] tid="[..], &dec(self.pid.load(Ordering::Relaxed) as u64), &b" syscall "[..], &dec(num),
                &b" not answered by the personality: -ENOSYS\n"[..]]
            {
                let take = part.len().min(line.len() - n);
                line[n..n + take].copy_from_slice(&part[..take]);
                n += take;
            }
            let _ = self.native.console_write(&line[..n]);
        }
        neg(le::ENOSYS)
    }

    // ── processes ───────────────────────────────────────────────────────────

    /// `clone(flags, newsp, ...)` in the shape `fork` and `vfork` take: an
    /// exit signal in the low byte, optionally `CLONE_VM | CLONE_VFORK` with
    /// no new stack (served as a fork: the child gets a copy-on-write copy,
    /// which a vfork child may not tell apart). A thread, or `posix_spawn`'s
    /// shared-memory child, is not answered.
    ///
    /// The native fork gives the child this process's open descriptions at the
    /// same handles, so the descriptor table copied with the address space is
    /// the child's as it stands: the child needs only its own ids.
    fn sys_clone(&self, flags: u64, newsp: u64) -> i64 {
        use lx::clone::*;
        let rest = flags & !CSIGNAL;
        if !(rest == 0 || (rest == (CLONE_VM | CLONE_VFORK) && newsp == 0)) {
            return self.unanswered(nr::CLONE);
        }
        let parent = self.pid.load(Ordering::Relaxed);
        let r = self.native.fork();
        if r < 0 {
            return neg(le::EAGAIN);
        }
        if r == 0 {
            // The child: its own id, its parent's id, nobody's child yet.
            self.pid.store(self.native.getpid(), Ordering::Relaxed);
            self.ppid.store(parent, Ordering::Relaxed);
            self.st.with(|s| s.children = [0; CHILDREN]);
            return 0;
        }
        let kept = self.st.with(|s| match s.children.iter().position(|&c| c == 0) {
            Some(i) => {
                s.children[i] = r as u32;
                true
            }
            None => false,
        });
        // Past the table the child still runs; it is just not waitable by
        // `wait4(-1)` (a native waiter can still take it by id).
        let _ = kept;
        r
    }

    /// `wait4(pid, wstatus, options, rusage)`: `pid > 0` or `-1`; `WNOHANG`
    /// (1); `WUNTRACED`/`WCONTINUED` accepted (no task is ever stopped
    /// here). Blocks on the clock, never by counting yields. `rusage` is
    /// zeroed (no accounting is offered).
    fn sys_wait4(&self, pid: u64, status_ptr: u64, options: u64, rusage: u64) -> i64 {
        const WNOHANG: u64 = 1;
        const KNOWN: u64 = 1 | 2 | 8 | 0x4000_0000 | 0x8000_0000;
        if options & !KNOWN != 0 {
            return neg(le::EINVAL);
        }
        if rusage != 0 && put_user(rusage, &[0u8; 144]) != 0 {
            return neg(le::EFAULT);
        }
        let pid = pid as i64;
        if pid == 0 || pid < -1 {
            // Process groups do not exist here.
            return neg(le::EINVAL);
        }
        loop {
            // The children this process has not reaped.
            let kids = self.st.with(|s| s.children);
            let mut found: Option<(u32, i32)> = None;
            let mut any = false;
            for &k in kids.iter().filter(|&&k| k != 0) {
                if pid > 0 && k as i64 != pid {
                    continue;
                }
                let mut code = 0i32;
                match self.native.waitpid(k, &mut code) {
                    r if r > 0 => {
                        any = true;
                        found = Some((k, code));
                        break;
                    }
                    // Still running.
                    -1 => any = true,
                    // Nobody's child any more (taken by another waiter):
                    // forget it, it will never answer.
                    _ => self.st.with(|s| {
                        if let Some(c) = s.children.iter_mut().find(|c| **c == k) {
                            *c = 0;
                        }
                    }),
                }
            }
            if let Some((tid, code)) = found {
                self.st.with(|s| {
                    if let Some(c) = s.children.iter_mut().find(|c| **c == tid) {
                        *c = 0;
                    }
                });
                if status_ptr != 0 && put_user(status_ptr, &lx::wait_status(code).to_le_bytes()) != 0 {
                    return neg(le::EFAULT);
                }
                return tid as i64;
            }
            if !any {
                return neg(le::ECHILD);
            }
            if options & WNOHANG != 0 {
                return 0;
            }
            self.native.sleep_until_ns(self.native.now_ns().saturating_add(10_000_000));
        }
    }

    // ── descriptors ─────────────────────────────────────────────────────────

    fn fd_get(&self, fd: u64) -> Result<FdEnt, i64> {
        if fd >= FDS as u64 {
            return Err(neg(le::EBADF));
        }
        let e = self.st.with(|s| s.fds[fd as usize]);
        if e.kind == Kind::Closed { Err(neg(le::EBADF)) } else { Ok(e) }
    }

    /// The lowest closed descriptor at or above `min`, claimed with `ent`
    /// (and `path` kept for a file).
    fn fd_alloc(&self, min: usize, ent: FdEnt, path: Option<&[u8]>) -> Result<usize, i64> {
        self.st
            .with(|s| {
                let i = (min..FDS).find(|&i| s.fds[i].kind == Kind::Closed)?;
                s.fds[i] = ent;
                s.paths[i] = NO_PATH;
                if let Some(p) = path {
                    let n = p.len().min(KEEP_PATH_MAX);
                    s.paths[i].path[..n].copy_from_slice(&p[..n]);
                    s.paths[i].len = n as u8;
                }
                Some(i)
            })
            .ok_or(neg(le::EMFILE))
    }

    /// Resolve `path` against `dirfd` (`AT_FDCWD` or an open directory) into
    /// `out`; the absolute path's length.
    fn resolve(&self, dirfd: u64, path: &[u8], out: &mut [u8; PATH_MAX]) -> Result<usize, i64> {
        // `/proc` is not mounted for a Linux task; its one name a static
        // program relies on is its own image.
        if path == b"/proc/self/exe" {
            let (e, n) = self.st.with(|s| (s.exe, s.exe_len as usize));
            if n == 0 {
                return Err(neg(le::ENOENT));
            }
            out[..n].copy_from_slice(&e[..n]);
            return Ok(n);
        }
        let mut base = [0u8; KEEP_PATH_MAX];
        let base_len;
        if path.first() == Some(&b'/') || dirfd == lx::AT_FDCWD {
            let (c, n) = self.st.with(|s| (s.cwd, s.cwd_len as usize));
            base[..n].copy_from_slice(&c[..n]);
            base_len = n;
        } else {
            let e = self.fd_get(dirfd)?;
            if e.kind != Kind::Dir {
                return Err(neg(le::ENOTDIR));
            }
            let d = self.st.with(|s| s.dirs[e.dir as usize]);
            base[..d.len as usize].copy_from_slice(&d.path[..d.len as usize]);
            base_len = d.len as usize;
        }
        lx::join_path(&base[..base_len], path, out).ok_or(neg(le::ENAMETOOLONG))
    }

    /// Is `path` a directory? `stat` first; a mount point the VFS cannot stat
    /// counts as one when it lists.
    fn is_dir(&self, path: &[u8]) -> Result<bool, i64> {
        let mut z = [0u8; PATH_MAX + 1];
        let zp = nul_terminated(path, &mut z)?;
        let mut st = [0u8; STAT_BYTES];
        match self.native.stat(zp, &mut st) {
            r if r >= 0 => Ok(rd32(&st, STAT_OFF_MODE) & STAT_S_IFMT == STAT_S_IFDIR),
            e => {
                let (mut name, mut size, mut isd) = ([0u8; NAME_BYTES], 0u32, 0u32);
                if self.native.readdir(zp, 0, &mut name, &mut size, &mut isd) == 0 {
                    Ok(true)
                } else {
                    Err(lx::errno_from_native(e, le::ENOENT))
                }
            }
        }
    }

    // ── I/O ─────────────────────────────────────────────────────────────────

    fn sys_write(&self, fd: u64, buf: u64, count: u64) -> i64 {
        let e = match self.fd_get(fd) {
            Ok(e) => e,
            Err(r) => return r,
        };
        let n = count.min(IO_MAX as u64) as usize;
        match e.kind {
            Kind::Console | Kind::File | Kind::Pipe => {
                // SAFETY: the program's own memory; a bad pointer faults the
                // process, as it would the program.
                let src = unsafe { user_slice(buf, n) };
                self.write_bytes(&e, src)
            }
            Kind::Dir => neg(le::EISDIR),
            Kind::Closed => neg(le::EBADF),
        }
    }

    fn write_bytes(&self, e: &FdEnt, b: &[u8]) -> i64 {
        match e.kind {
            Kind::Console => lx::errno_from_native(self.native.console_write(b), le::EFAULT),
            Kind::File => lx::errno_from_native(self.native.handle_write(e.handle, b), le::EIO),
            Kind::Pipe => {
                let r = lx::errno_from_native(self.native.handle_write(e.handle, b), le::EIO);
                if r == neg(le::EPIPE) {
                    self.sigpipe();
                }
                r
            }
            Kind::Dir => neg(le::EISDIR),
            Kind::Closed => neg(le::EBADF),
        }
    }

    /// A write to a pipe nobody reads: `SIGPIPE`. Nothing is delivered to a
    /// handler (no upcall into the program), so the default action is the
    /// only one taken, as the kernel's own personality took it: the writer
    /// ends with status 128 + 13. Ignored or blocked, the write only fails
    /// with `EPIPE`.
    fn sigpipe(&self) {
        use lx::sig::SIGPIPE;
        let (handler, masked) = self.st.with(|s| (s.act[SIGPIPE as usize - 1].handler, s.mask & (1 << (SIGPIPE - 1)) != 0));
        if handler == 0 && !masked {
            self.native.exit(128 + SIGPIPE as i32);
        }
    }

    fn sys_read(&self, fd: u64, buf: u64, count: u64) -> i64 {
        let e = match self.fd_get(fd) {
            Ok(e) => e,
            Err(r) => return r,
        };
        let n = count.min(IO_MAX as u64) as usize;
        match e.kind {
            // Console input is not offered to a hosted task yet: end of file.
            Kind::Console => 0,
            Kind::File | Kind::Pipe => {
                // SAFETY: as `sys_write`.
                let dst = unsafe { user_slice_mut(buf, n) };
                lx::errno_from_native(self.native.handle_read(e.handle, dst), le::EIO)
            }
            Kind::Dir => neg(le::EISDIR),
            Kind::Closed => neg(le::EBADF),
        }
    }

    /// `readv`/`writev`: ONE transfer per call, as Linux (the walk and its
    /// checks are `azos_linux_abi::iov`).
    fn sys_rwv(&self, fd: u64, iov: u64, cnt: u64, write: bool) -> i64 {
        let e = match self.fd_get(fd) {
            Ok(e) => e,
            Err(r) => return r,
        };
        match e.kind {
            Kind::Dir => return neg(le::EISDIR),
            Kind::Closed => return neg(le::EBADF),
            Kind::Console | Kind::File | Kind::Pipe => {}
        }
        let mut bounce = [0u8; IO_MAX];
        if write {
            lx::iov::writev(&mut UserIov, iov, cnt, &mut bounce, |b| self.write_bytes(&e, b))
        } else {
            lx::iov::readv(&mut UserIov, iov, cnt, &mut bounce, |b| match e.kind {
                Kind::Console => 0,
                _ => lx::errno_from_native(self.native.handle_read(e.handle, b), le::EIO),
            })
        }
    }

    fn sys_openat(&self, dirfd: u64, path_ptr: u64, flags: u64) -> i64 {
        let mut raw = [0u8; PATH_MAX];
        let n = match user_path(path_ptr, &mut raw) {
            Ok(n) => n,
            Err(e) => return e,
        };
        let mut path = [0u8; PATH_MAX];
        let plen = match self.resolve(dirfd, &raw[..n], &mut path) {
            Ok(l) => l,
            Err(e) => return e,
        };
        let path = &path[..plen];
        let Some(req) = lx::open_flags(flags, arch()) else { return neg(le::EINVAL) };
        let accmode = (req.native & 3) as u8;
        let cloexec = flags & lx::oflag::O_CLOEXEC != 0;

        // A directory is the runtime's own descriptor, read later through
        // `readdir`; a create never names one.
        if req.native & lx::oflag::O_CREAT == 0 {
            match self.is_dir(path) {
                Ok(true) => {
                    if accmode != 0 {
                        return neg(le::EISDIR);
                    }
                    return self.open_dir(path, cloexec);
                }
                Ok(false) if req.directory => return neg(le::ENOTDIR),
                Ok(false) => {}
                Err(e) => return e,
            }
        } else if req.directory {
            return neg(le::EINVAL);
        }

        let mut z = [0u8; PATH_MAX + 1];
        let zp = match nul_terminated(path, &mut z) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let h = self.native.file_open(zp, req.native);
        if h < 0 {
            return lx::errno_from_native(h, le::ENOENT);
        }
        let ent = FdEnt { kind: Kind::File, handle: h as u32, dir: 0, cloexec, nonblock: req.nonblock, accmode };
        match self.fd_alloc(0, ent, Some(path)) {
            Ok(fd) => fd as i64,
            Err(e) => {
                let _ = self.native.handle_close(h as u32);
                e
            }
        }
    }

    fn open_dir(&self, path: &[u8], cloexec: bool) -> i64 {
        if path.len() > KEEP_PATH_MAX {
            return neg(le::ENAMETOOLONG);
        }
        let r = self.st.with(|s| {
            let d = s.dirs.iter().position(|d| !d.used)?;
            let fd = (0..FDS).find(|&i| s.fds[i].kind == Kind::Closed)?;
            s.dirs[d] = DirEnt { used: true, len: path.len() as u8, next: 0, path: [0; KEEP_PATH_MAX] };
            s.dirs[d].path[..path.len()].copy_from_slice(path);
            s.fds[fd] = FdEnt { kind: Kind::Dir, dir: d as u8, cloexec, ..FD_CLOSED };
            s.paths[fd] = NO_PATH;
            Some(fd)
        });
        match r {
            Some(fd) => fd as i64,
            None => neg(le::EMFILE),
        }
    }

    fn sys_close(&self, fd: u64) -> i64 {
        let e = match self.fd_get(fd) {
            Ok(e) => e,
            Err(r) => return r,
        };
        // Mark it closed first, then release the handle if no other
        // descriptor names it (`dup3` aliases share one handle).
        let still_named = self.st.with(|s| {
            s.fds[fd as usize] = FD_CLOSED;
            s.paths[fd as usize] = NO_PATH;
            if e.kind == Kind::Dir {
                s.dirs[e.dir as usize] = DIR_FREE;
            }
            matches!(e.kind, Kind::File | Kind::Pipe)
                && s.fds.iter().any(|f| matches!(f.kind, Kind::File | Kind::Pipe) && f.handle == e.handle)
        });
        if matches!(e.kind, Kind::File | Kind::Pipe) && !still_named {
            let r = self.native.handle_close(e.handle);
            if r < 0 {
                return lx::errno_from_native(r, le::EIO);
            }
        }
        0
    }

    // ── stat ────────────────────────────────────────────────────────────────

    fn stat_path(&self, path: &[u8]) -> Result<lx::Stat, i64> {
        let mut z = [0u8; PATH_MAX + 1];
        let zp = nul_terminated(path, &mut z)?;
        let mut raw = [0u8; STAT_BYTES];
        let (size, mode, nlink, atime, mtime, ctime);
        match self.native.stat(zp, &mut raw) {
            r if r >= 0 => {
                size = rd64(&raw, STAT_OFF_SIZE);
                mode = rd32(&raw, STAT_OFF_MODE);
                nlink = rd32(&raw, STAT_OFF_NLINK);
                atime = rd64(&raw, STAT_OFF_ATIME);
                mtime = rd64(&raw, STAT_OFF_MTIME);
                ctime = rd64(&raw, STAT_OFF_CTIME);
            }
            e => {
                // A mount point the VFS cannot stat but can list is a directory.
                let (mut name, mut sz, mut isd) = ([0u8; NAME_BYTES], 0u32, 0u32);
                if self.native.readdir(zp, 0, &mut name, &mut sz, &mut isd) == 0 {
                    (size, mode, nlink, atime, mtime, ctime) = (0, lx::mode::S_IFDIR | 0o755, 1, 0, 0, 0);
                } else {
                    return Err(lx::errno_from_native(e, le::ENOENT));
                }
            }
        }
        // An inode number the path names stably, so `ls -i` and `find -inum`
        // see one number per file within a boot.
        let ino = path.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| (h ^ b as u64).wrapping_mul(0x100_0000_01b3));
        Ok(lx::Stat {
            dev: 1,
            ino,
            mode,
            nlink: nlink.max(1),
            size: size as i64,
            blksize: 512,
            blocks: (size as i64 + 511) / 512,
            atime: atime as i64,
            mtime: mtime as i64,
            ctime: ctime as i64,
            rdev: 0,
        })
    }

    fn stat_fd(&self, fd: u64, e: FdEnt) -> Result<lx::Stat, i64> {
        let mut st = lx::Stat { nlink: 1, blksize: 512, ..lx::Stat::default() };
        match e.kind {
            Kind::Console => {
                st.mode = lx::mode::S_IFCHR | 0o620;
                // A tty major (4) in the old encoding: what `isatty` checks
                // through TCGETS anyway.
                st.rdev = 4 << 8;
            }
            Kind::Pipe => {
                st.mode = lx::mode::S_IFIFO | 0o600;
                st.blksize = 4096;
            }
            Kind::File => {
                let (p, n) = self.st.with(|s| (s.paths[fd as usize].path, s.paths[fd as usize].len as usize));
                if n == 0 {
                    // A file the spawn handed over (`> f`): no path to ask
                    // the native `stat` about, so the size is unknown.
                    st.mode = lx::mode::S_IFREG | 0o644;
                } else {
                    return self.stat_path(&p[..n]);
                }
            }
            Kind::Dir => {
                let d = self.st.with(|s| s.dirs[e.dir as usize]);
                return self.stat_path(&d.path[..d.len as usize]);
            }
            Kind::Closed => return Err(neg(le::EBADF)),
        }
        st.blocks = (st.size + 511) / 512;
        Ok(st)
    }

    fn sys_fstat(&self, fd: u64, buf: u64) -> i64 {
        let e = match self.fd_get(fd) {
            Ok(e) => e,
            Err(r) => return r,
        };
        match self.stat_fd(fd, e) {
            Ok(st) => put_user(buf, &st.to_bytes()),
            Err(r) => r,
        }
    }

    fn sys_newfstatat(&self, dirfd: u64, path_ptr: u64, buf: u64, flags: u64) -> i64 {
        let mut raw = [0u8; PATH_MAX];
        let st = if flags & lx::AT_EMPTY_PATH != 0 && path_ptr != 0 && {
            // SAFETY: one byte of the program's own string.
            unsafe { *(path_ptr as *const u8) == 0 }
        } {
            match self.fd_get(dirfd).and_then(|e| self.stat_fd(dirfd, e)) {
                Ok(s) => s,
                Err(r) => return r,
            }
        } else {
            let n = match user_path(path_ptr, &mut raw) {
                Ok(n) => n,
                Err(e) => return e,
            };
            let mut path = [0u8; PATH_MAX];
            let plen = match self.resolve(dirfd, &raw[..n], &mut path) {
                Ok(l) => l,
                Err(e) => return e,
            };
            match self.stat_path(&path[..plen]) {
                Ok(s) => s,
                Err(r) => return r,
            }
        };
        put_user(buf, &st.to_bytes())
    }

    fn sys_getdents64(&self, fd: u64, buf: u64, count: u64) -> i64 {
        let e = match self.fd_get(fd) {
            Ok(e) => e,
            Err(r) => return r,
        };
        if e.kind != Kind::Dir {
            return neg(le::ENOTDIR);
        }
        let d = self.st.with(|s| s.dirs[e.dir as usize]);
        let mut z = [0u8; KEEP_PATH_MAX + 1];
        z[..d.len as usize].copy_from_slice(&d.path[..d.len as usize]);
        let zp = &z[..d.len as usize + 1];
        let mut out = [0u8; 2048];
        let cap = (count as usize).min(out.len());
        let mut used = 0usize;
        let mut idx = d.next;
        loop {
            let (mut name, mut size, mut isd) = ([0u8; NAME_BYTES], 0u32, 0u32);
            if self.native.readdir(zp, idx as u64, &mut name, &mut size, &mut isd) != 0 {
                break;
            }
            let nlen = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            let ino = (idx as u64) + 2;
            let dt = if isd != 0 { lx::DT_DIR } else { lx::DT_REG };
            match lx::encode_dirent64(&mut out[used..cap], ino, idx as i64 + 1, dt, &name[..nlen]) {
                Some(n) => used += n,
                None => break,
            }
            idx += 1;
        }
        if used == 0 {
            let (mut name, mut size, mut isd) = ([0u8; NAME_BYTES], 0u32, 0u32);
            if self.native.readdir(zp, idx as u64, &mut name, &mut size, &mut isd) == 0 {
                // The next entry does not fit the caller's buffer at all.
                return neg(le::EINVAL);
            }
        }
        if used > 0 && put_user(buf, &out[..used]) != 0 {
            return neg(le::EFAULT);
        }
        self.st.with(|s| s.dirs[e.dir as usize].next = idx);
        used as i64
    }

    // ── pipes, duplicates, fcntl, ioctl ─────────────────────────────────────

    fn sys_pipe2(&self, fds_ptr: u64, flags: u64) -> i64 {
        if flags & !(lx::oflag::O_CLOEXEC | lx::oflag::O_NONBLOCK) != 0 {
            return neg(le::EINVAL);
        }
        let cloexec = flags & lx::oflag::O_CLOEXEC != 0;
        let nonblock = flags & lx::oflag::O_NONBLOCK != 0;
        let mut ends = [0u32; 2];
        let r = self.native.pipe(&mut ends, nonblock);
        if r < 0 {
            return lx::errno_from_native(r, le::EMFILE);
        }
        let fr = self.fd_alloc(0, FdEnt { kind: Kind::Pipe, handle: ends[0], cloexec, nonblock, accmode: 0, dir: 0 }, None);
        let fw = fr.and_then(|_| {
            self.fd_alloc(0, FdEnt { kind: Kind::Pipe, handle: ends[1], cloexec, nonblock, accmode: 1, dir: 0 }, None)
        });
        match (fr, fw) {
            (Ok(a), Ok(c)) => {
                let mut o = [0u8; 8];
                o[..4].copy_from_slice(&(a as u32).to_le_bytes());
                o[4..].copy_from_slice(&(c as u32).to_le_bytes());
                if put_user(fds_ptr, &o) == 0 { 0 } else { neg(le::EFAULT) }
            }
            (r1, _) => {
                if let Ok(a) = r1 {
                    self.st.with(|s| s.fds[a] = FD_CLOSED);
                }
                let _ = self.native.handle_close(ends[0]);
                let _ = self.native.handle_close(ends[1]);
                neg(le::EMFILE)
            }
        }
    }

    /// `dup3(old, new, flags)`; `new == u64::MAX` is `dup(old)` (lowest free).
    fn sys_dup3(&self, old: u64, new: u64, flags: u64) -> i64 {
        let e = match self.fd_get(old) {
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
        let kept = self.st.with(|s| s.paths[old as usize]);
        let kp = &kept.path[..kept.len as usize];
        if new == u64::MAX {
            return match self.fd_alloc(0, FdEnt { cloexec: false, ..e }, Some(kp)) {
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
        if self.fd_get(new).is_ok() {
            let r = self.sys_close(new);
            if r < 0 {
                return r;
            }
        }
        self.st.with(|s| {
            s.fds[new as usize] = FdEnt { cloexec: flags & lx::oflag::O_CLOEXEC != 0, ..e };
            s.paths[new as usize] = kept;
        });
        new as i64
    }

    fn sys_fcntl(&self, fd: u64, cmd: u64, arg: u64) -> i64 {
        use lx::fcntl::*;
        let e = match self.fd_get(fd) {
            Ok(e) => e,
            Err(r) => return r,
        };
        match cmd {
            F_GETFD => e.cloexec as i64,
            F_SETFD => {
                self.st.with(|s| s.fds[fd as usize].cloexec = arg & FD_CLOEXEC != 0);
                0
            }
            F_GETFL => (e.accmode as u64 | if e.nonblock { lx::oflag::O_NONBLOCK } else { 0 }) as i64,
            F_SETFL => {
                let on = arg & lx::oflag::O_NONBLOCK != 0;
                self.st.with(|s| s.fds[fd as usize].nonblock = on);
                if e.kind == Kind::Pipe {
                    self.native.handle_set_nonblock(e.handle, on);
                }
                0
            }
            F_DUPFD | F_DUPFD_CLOEXEC => {
                if e.kind == Kind::Dir || arg >= FDS as u64 {
                    return neg(le::EINVAL);
                }
                let kept = self.st.with(|s| s.paths[fd as usize]);
                match self.fd_alloc(arg as usize, FdEnt { cloexec: cmd == F_DUPFD_CLOEXEC, ..e }, Some(&kept.path[..kept.len as usize])) {
                    Ok(n) => n as i64,
                    Err(r) => r,
                }
            }
            _ => neg(le::EINVAL),
        }
    }

    fn sys_ioctl(&self, fd: u64, req: u64, arg: u64) -> i64 {
        use lx::ioctl::*;
        let e = match self.fd_get(fd) {
            Ok(e) => e,
            Err(r) => return r,
        };
        if e.kind != Kind::Console {
            return neg(le::ENOTTY);
        }
        match req {
            // The console has no size probe: 24 x 80.
            TIOCGWINSZ => put_user(arg, &lx::winsize_bytes(24, 80)),
            TCGETS => put_user(arg, &lx::termios_bytes()),
            // Accepted, without effect: the native shell owns the line
            // discipline.
            TCSETS | TCSETSW | TCSETSF | TIOCSWINSZ => 0,
            TIOCGPGRP => put_user(arg, &(self.pid.load(Ordering::Relaxed) as i32).to_le_bytes()),
            TIOCSPGRP => 0,
            _ => neg(le::EINVAL),
        }
    }

    // ── working directory ───────────────────────────────────────────────────

    fn sys_getcwd(&self, buf: u64, size: u64) -> i64 {
        let (c, n) = self.st.with(|s| (s.cwd, s.cwd_len as usize));
        if (size as usize) < n + 1 {
            return neg(le::ERANGE);
        }
        let mut out = [0u8; CWD_MAX + 1];
        out[..n].copy_from_slice(&c[..n]);
        if put_user(buf, &out[..n + 1]) == 0 { (n + 1) as i64 } else { neg(le::EFAULT) }
    }

    fn sys_chdir(&self, path_ptr: u64) -> i64 {
        let mut raw = [0u8; PATH_MAX];
        let n = match user_path(path_ptr, &mut raw) {
            Ok(n) => n,
            Err(e) => return e,
        };
        let mut path = [0u8; PATH_MAX];
        let plen = match self.resolve(lx::AT_FDCWD, &raw[..n], &mut path) {
            Ok(l) => l,
            Err(e) => return e,
        };
        match self.is_dir(&path[..plen]) {
            Ok(true) => {}
            Ok(false) => return neg(le::ENOTDIR),
            Err(e) => return e,
        }
        if plen > CWD_MAX {
            return neg(le::ENAMETOOLONG);
        }
        self.st.with(|s| {
            s.cwd[..plen].copy_from_slice(&path[..plen]);
            s.cwd_len = plen as u8;
        });
        0
    }

    // ── memory and time ─────────────────────────────────────────────────────

    /// The program break, built over the native memory call: the native ABI
    /// has no break (a native program maps memory), a Linux program expects
    /// one. The break lives in a run of anonymous pages mapped one after the
    /// other: the first page when the program first asks, and a growth maps
    /// what is missing at the run's end. The kernel places anonymous mappings
    /// one after the other, so a run that a mapping of the program's own
    /// interrupted cannot grow; the answer is then the unchanged break, which
    /// is how Linux refuses, and the program (malloc) falls back to `mmap`.
    /// Shrinking is not done: a request below the break answers the break.
    fn sys_brk(&self, addr: u64) -> i64 {
        use lx::mman::*;
        let page = self.native.page_size();
        self.st.with(|s| {
            if s.brk_end == 0 {
                let first = self.native.mmap(0, page, PROT_READ | PROT_WRITE, 0);
                if first <= 0 {
                    return 0;
                }
                s.brk_cur = first as u64;
                s.brk_end = s.brk_cur + page;
            }
            if addr <= s.brk_cur {
                return s.brk_cur as i64;
            }
            // The end the request needs, rounded up to a granule; a request
            // that wraps the address space is refused like any other that
            // cannot be mapped.
            let Some(want) = addr.checked_add(page - 1).map(|a| a & !(page - 1)) else {
                return s.brk_cur as i64;
            };
            if want > s.brk_end {
                let more = want - s.brk_end;
                let at = self.native.mmap(0, more, PROT_READ | PROT_WRITE, 0);
                if at != s.brk_end as i64 {
                    // Not next to the run (or refused): give back what was mapped.
                    if at > 0 {
                        let _ = self.native.munmap(at as u64, more);
                    }
                    return s.brk_cur as i64;
                }
                s.brk_end = want;
            }
            s.brk_cur = addr;
            addr as i64
        })
    }

    fn sys_mmap(&self, addr: u64, len: u64, prot: u64, flags: u64, fd: u64) -> i64 {
        use lx::mman::*;
        // Anonymous private memory only: file mappings and shared mappings
        // are not answered, and an executable mapping is refused (W^X).
        if flags & MAP_ANONYMOUS == 0 || flags & MAP_SHARED != 0 || flags & MAP_PRIVATE == 0 {
            return neg(le::ENOSYS);
        }
        let _ = fd;
        if flags & MAP_FIXED != 0 || prot & PROT_EXEC != 0 || len == 0 {
            return neg(le::EINVAL);
        }
        // The pre-commit bits travel (same values in both ABIs).
        let r = self.native.mmap(addr, len, prot, flags & (MAP_POPULATE | MAP_LOCKED));
        lx::errno_from_native(r, le::ENOMEM)
    }

    fn sys_clock_gettime(&self, id: u64, ts: u64) -> i64 {
        // Every clock a Linux task can name is a native one
        // (`ClockId::from_posix`); REALTIME and TAI read as time since boot
        // until a time source sets them.
        let Some(clock) = ClockId::from_posix(id) else { return neg(le::EINVAL) };
        match self.native.clock_ns(clock) {
            Ok(ns) => put_user(ts, &lx::timespec_bytes(ns)),
            Err(_) => neg(le::EINVAL),
        }
    }

    fn sys_nanosleep(&self, req: u64) -> i64 {
        let mut b = [0u8; 16];
        if get_user(req, &mut b) != 0 {
            return neg(le::EFAULT);
        }
        let Some(ns) = lx::timespec_ns(&b) else { return neg(le::EINVAL) };
        self.native.sleep_until_ns(self.native.now_ns().saturating_add(ns));
        0
    }

    // ── signals (state only) ────────────────────────────────────────────────

    /// `rt_sigaction`, with the kernel `struct sigaction` of `a`'s layout.
    fn sys_rt_sigaction(&self, a: lx::Arch, s: u64, act: u64, oact: u64, setsize: u64) -> i64 {
        use lx::sig::*;
        if setsize != 8 || s == 0 || s > NSIG_MAX {
            return neg(le::EINVAL);
        }
        let size = lx::KSigaction::size(a);
        let mut new = None;
        if act != 0 {
            if s == SIGKILL || s == SIGSTOP {
                return neg(le::EINVAL);
            }
            let mut b = [0u8; 32];
            if get_user(act, &mut b[..size]) != 0 {
                return neg(le::EFAULT);
            }
            new = lx::KSigaction::from_bytes(&b[..size], a);
        }
        let old = self.st.with(|st| {
            let old = st.act[s as usize - 1];
            if let Some(n) = new {
                st.act[s as usize - 1] = n;
            }
            old
        });
        if oact != 0 && put_user(oact, &old.to_bytes(a)[..size]) != 0 {
            return neg(le::EFAULT);
        }
        0
    }

    fn sys_rt_sigprocmask(&self, how: u64, set: u64, oset: u64, setsize: u64) -> i64 {
        use lx::sig::*;
        if setsize != 8 {
            return neg(le::EINVAL);
        }
        let new = if set != 0 {
            let mut b = [0u8; 8];
            if get_user(set, &mut b) != 0 {
                return neg(le::EFAULT);
            }
            Some(u64::from_le_bytes(b))
        } else {
            None
        };
        if new.is_some() && how > SIG_SETMASK {
            return neg(le::EINVAL);
        }
        let unblockable = (1u64 << (SIGKILL - 1)) | (1u64 << (SIGSTOP - 1));
        let old = self.st.with(|s| {
            let old = s.mask;
            if let Some(v) = new {
                s.mask = match how {
                    SIG_BLOCK => old | v,
                    SIG_UNBLOCK => old & !v,
                    _ => v,
                } & !unblockable;
            }
            old
        });
        if oset != 0 && put_user(oset, &old.to_le_bytes()) != 0 {
            return neg(le::EFAULT);
        }
        0
    }

    /// Nothing is ever pending: no signal is delivered to a hosted process yet.
    fn sys_rt_sigpending(&self, set: u64, size: u64) -> i64 {
        if size != 8 {
            return neg(le::EINVAL);
        }
        put_user(set, &0u64.to_le_bytes())
    }

    /// `sigaltstack`: no alternate stack is offered. The old one reads back
    /// as disabled; asking to disable it is accepted, installing one is
    /// `-EINVAL`.
    fn sys_sigaltstack(&self, ss: u64, old_ss: u64) -> i64 {
        if old_ss != 0 {
            let mut b = [0u8; 24];
            b[8..12].copy_from_slice(&lx::signal::SS_DISABLE.to_le_bytes());
            if put_user(old_ss, &b) != 0 {
                return neg(le::EFAULT);
            }
        }
        if ss != 0 {
            let mut b = [0u8; 24];
            if get_user(ss, &mut b) != 0 {
                return neg(le::EFAULT);
            }
            if u32::from_le_bytes([b[8], b[9], b[10], b[11]]) & lx::signal::SS_DISABLE == 0 {
                return neg(le::EINVAL);
            }
        }
        0
    }
}

// ── The program's memory ────────────────────────────────────────────────────
//
// The runtime shares the program's address space, so a user pointer is a
// pointer. A bad one faults the process (the kernel ends it as it ends any
// task that faults) where the in-kernel table answered `-EFAULT`; pointers
// the runtime only passes on to a native call keep their `-EFAULT`.

/// `n` bytes at user address `ptr`.
///
/// # Safety
/// `[ptr, ptr + n)` must be readable by the process (a fault otherwise).
unsafe fn user_slice<'a>(ptr: u64, n: usize) -> &'a [u8] {
    if n == 0 {
        return &[];
    }
    unsafe { core::slice::from_raw_parts(ptr as *const u8, n) }
}

/// `n` bytes at user address `ptr`, writable.
///
/// # Safety
/// As [`user_slice`], writable.
unsafe fn user_slice_mut<'a>(ptr: u64, n: usize) -> &'a mut [u8] {
    if n == 0 {
        return &mut [];
    }
    unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, n) }
}

/// Copy `bytes` to user address `ptr`: 0, or `-EFAULT` for a null pointer.
fn put_user(ptr: u64, bytes: &[u8]) -> i64 {
    if ptr == 0 {
        return neg(le::EFAULT);
    }
    // SAFETY: the program's own memory.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len()) };
    0
}

/// Copy user bytes at `ptr` into `bytes`: 0, or `-EFAULT` for a null pointer.
fn get_user(ptr: u64, bytes: &mut [u8]) -> i64 {
    if ptr == 0 {
        return neg(le::EFAULT);
    }
    // SAFETY: the program's own memory.
    unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, bytes.as_mut_ptr(), bytes.len()) };
    0
}

/// Copy a NUL-terminated user path into `buf`; its length, or a Linux errno.
fn user_path(ptr: u64, buf: &mut [u8; PATH_MAX]) -> Result<usize, i64> {
    if ptr == 0 {
        return Err(neg(le::EFAULT));
    }
    for i in 0..PATH_MAX {
        // SAFETY: byte by byte up to the terminator, the program's own string.
        let b = unsafe { *((ptr + i as u64) as *const u8) };
        if b == 0 {
            return if i == 0 { Err(neg(le::ENOENT)) } else { Ok(i) };
        }
        buf[i] = b;
    }
    Err(neg(le::ENAMETOOLONG))
}

/// `path` followed by a NUL, in `z`.
fn nul_terminated<'a>(path: &[u8], z: &'a mut [u8; PATH_MAX + 1]) -> Result<&'a [u8], i64> {
    if path.len() > PATH_MAX {
        return Err(neg(le::ENAMETOOLONG));
    }
    z[..path.len()].copy_from_slice(path);
    z[path.len()] = 0;
    Ok(&z[..path.len() + 1])
}

fn rd32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn rd64(b: &[u8], at: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(w)
}

/// The calling process's memory, for the iovec walk.
struct UserIov;

impl lx::iov::IovMem for UserIov {
    fn word(&mut self, addr: u64) -> Option<u64> {
        if addr == 0 {
            return None;
        }
        // SAFETY: an iovec word of the program's own array.
        Some(unsafe { core::ptr::read_unaligned(addr as *const u64) })
    }
    fn copy_in(&mut self, dst: &mut [u8], base: u64) -> bool {
        base != 0 && get_user(base, dst) == 0
    }
    fn copy_out(&mut self, base: u64, src: &[u8]) -> bool {
        base != 0 && put_user(base, src) == 0
    }
    fn writable(&mut self, base: u64, _len: usize) -> bool {
        base != 0
    }
}

/// `v` in decimal.
fn dec(v: u64) -> DecBuf {
    DecBuf::new(v)
}

/// A decimal number as bytes (`Deref` to the digits).
struct DecBuf {
    b: [u8; 20],
    from: usize,
}

impl DecBuf {
    fn new(mut v: u64) -> Self {
        let mut b = [0u8; 20];
        let mut i = 20;
        loop {
            i -= 1;
            b[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        Self { b, from: i }
    }
}

impl core::ops::Deref for DecBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.b[self.from..]
    }
}
