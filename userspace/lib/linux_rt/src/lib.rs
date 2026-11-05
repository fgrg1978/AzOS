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
//! umask, the signal actions, mask and pending set, and
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
//! # Signals
//!
//! A signal the process sends itself (`kill` of its own id, `tkill`, `tgkill`,
//! `raise`) is posted to the pending set and delivered before the call returns:
//! ignored, ended with `128 + signo` (the default action), or run in the
//! program's handler on a frame this runtime writes on the program's stack
//! (`azos_linux_abi::signal`; the program's `rt_sigreturn` comes back here and
//! restores the frame). The F/D/V state is not saved in the frame. A signal to
//! a child goes over `SYS_ALERT`, which ends the target with `128 + signo`:
//! the sender cannot see the target's handlers, so a signal whose default
//! action ends a process ends it, and SIGKILL is exact. A handler in another
//! process is not run, and a signal arriving from outside the process is not
//! delivered: there is no upcall into a running program yet. x86-64 has no
//! frame layout here, so a handler there is `-ENOSYS`.
//!
//! # What it does not answer yet
//!
//! requeue futexes, `set_robust_list`, and console input. Each answers
//! `-ENOSYS` (or end of file, for the console) and is reported once per call
//! number, never silently. `lseek`, `mprotect`, `futex` wait and wake and the
//! priority-inheritance futexes are answered over `NODE_SEEK`,
//! `DOMAIN_MPROTECT` and `SYS_FUTEX_WAIT/WAKE` (the PI ones through its
//! `FUTEX_OP_PI_*` operations, the same word protocol).
//!
//! # Threads and `execve`
//!
//! `clone` with `CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
//! CLONE_THREAD` is `SYS_THREAD_CREATE`: the new thread starts in the image's
//! trampoline, which stores its id at `ptid`/`ctid` (`CLONE_PARENT_SETTID`,
//! `CLONE_CHILD_SETTID`) and resumes a copy of the creator's registers with a
//! 0 result on the new stack; `CLONE_CHILD_CLEARTID` is the native `ctid`
//! (cleared and woken when the thread ends) and `set_tid_address` is
//! `DOMAIN_SET_CLEAR_TID`. `exit` ends the calling thread (`SYS_THREAD_EXIT`)
//! unless it is the last, `exit_group` the process. The runtime's state is
//! the process's and shared by every thread; the signal mask and the pending
//! set are the process's too, so a signal a thread sends to another thread of
//! its process runs its handler on the sender.
//!
//! `execve` has no in-place native exec to ask for, so it starts the image
//! with `SYS_SPAWN_EX` (arguments, environment, working directory and the
//! descriptors that are not close-on-exec, 0..=7), closes what it held, waits
//! for it and exits with its code. The process id the caller's parent waits on
//! stays; the image has its own, and its parent is the caller.
//!
//! `clone` in the fork and vfork shapes and `wait4` are answered over the
//! foreign-ABI family's `SYS_FOREIGN_FORK` and the domain's `wait` op: the
//! fork already gives the child the parent's open files at the same handles,
//! sharing their offsets, and the regions of its pipes as shared mappings (the
//! kernel counts the child's pipe ends in the fork), so the descriptor table
//! that is copied with the address space is the child's as it stands.

#![no_std]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};

use azos_abi::foreign::{ForeignFrame, REG_NUMBER, REG_RESULT, REG_SP};
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
    azos_abi::invoke::NODE_SEEK,
    azos_abi::invoke::DOMAIN_MPROTECT,
    azos_abi::invoke::DOMAIN_SET_CLEAR_TID,
];

/// A descriptor as `execve` hands it to the image it starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecFd {
    Closed,
    Console,
    /// A `Cap<File>` handle (moved).
    File(u32),
    /// A pipe end (shared).
    Pipe(u32),
}

/// What `execve` asks `SYS_SPAWN_EX` for.
pub struct SpawnImage<'a> {
    /// The image's absolute path, NUL-terminated.
    pub path: &'a [u8],
    /// NUL-separated argument strings and their count.
    pub argv: &'a [u8],
    pub argc: u32,
    /// NUL-separated `KEY=VALUE` strings and their count.
    pub env: &'a [u8],
    pub envc: u32,
    /// The working directory, NUL-terminated.
    pub cwd: &'a [u8],
    /// The image's descriptors 0..=7.
    pub fds: [ExecFd; 8],
}

/// Most NUL-separated bytes of argument strings and of environment strings,
/// and strings of each, that `SYS_SPAWN_EX` carries.
pub const EXEC_STRINGS: usize = azos_abi::ushell::SPAWN_ARGV_MAX;
pub const EXEC_ARGC: usize = azos_abi::ushell::SPAWN_ARGC_MAX;

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

/// The state of a pipe end, as `poll` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PipeReady {
    /// Which end: a write end is ready when it has room, a read end when it
    /// holds bytes.
    pub write_end: bool,
    pub ready: bool,
    /// The other end is gone.
    pub hup: bool,
}

/// How long a `poll` that found nothing sleeps before it looks again. A pipe
/// end has no event a sleeping `poll` could be woken by without holding its
/// futex word, so the wait is a bounded sleep; it is the latency of a `poll`
/// on a pipe a peer fills later.
pub const POLL_TICK_NS: u64 = 1_000_000;

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
    /// What a call on the pipe end `h` would find now, for `poll`; `None`
    /// when `h` names no open end.
    fn pipe_ready(&self, h: u32) -> Option<PipeReady>;
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
    /// The domain's `wait` op, sleeping: as [`waitpid`](Self::waitpid) (`tid`
    /// 0: any child), until a child ends, `-ECHILD` when none can, `-EINTR`.
    fn wait_block(&self, tid: u32, code: &mut i32) -> i64;
    /// `SYS_EXIT`.
    fn exit(&self, code: i32) -> !;
    /// `NODE_SEEK` on a `Cap<File>` handle: the new offset.
    fn handle_seek(&self, h: u32, offset: i64, whence: u32) -> i64;
    /// `DOMAIN_MPROTECT`: read and write bits only; `PROT_EXEC` is refused.
    fn mprotect(&self, addr: u64, len: u64, prot: u64) -> i64;
    /// `SYS_FUTEX_WAIT` on the word at `addr` (`timeout_ns` relative, 0: none):
    /// 0 woken, `-EAGAIN` the word differs, `-ETIMEDOUT` (110), `-EINTR`.
    fn futex_wait(&self, addr: u64, expected: u32, timeout_ns: u64) -> i64;
    /// `SYS_FUTEX_WAKE`: how many waiters were woken.
    fn futex_wake(&self, addr: u64, n: u32) -> i64;
    /// The native PI word operations (`FUTEX_OP_PI_*`): take (`timeout_ns`
    /// relative, 0: none; `try_only`: do not block) and release the word at `addr`.
    fn futex_lock_pi(&self, addr: u64, timeout_ns: u64, try_only: bool) -> i64;
    fn futex_unlock_pi(&self, addr: u64) -> i64;
    /// `SYS_THREAD_CREATE` for a Linux thread: it resumes `start` (the
    /// creator's registers, result 0, stack pointer `newsp`) with the thread
    /// pointer `tls`, after storing its own id at every non-zero address in
    /// `settid`; `clear_tid` is the word its end clears and wakes (0: none).
    /// The thread's id, or a negative native code.
    fn thread_create(&self, start: &ForeignFrame, newsp: u64, clear_tid: u64, tls: u64, settid: [u64; 2]) -> i64;
    /// `SYS_THREAD_EXIT`: end the calling thread only.
    fn thread_exit(&self, code: i32) -> !;
    /// `DOMAIN_SET_CLEAR_TID`: the word the calling thread's end clears and wakes.
    fn set_clear_tid(&self, addr: u64) -> i64;
    /// The calling thread's thread pointer (0 where ring 3 cannot read it).
    fn thread_pointer(&self) -> u64;
    /// `SYS_SPAWN_EX` for `execve`: the child's id or a negative native code.
    fn spawn_image(&self, img: &SpawnImage) -> i64;
    /// `SYS_ALERT` on the descendant `tid`: it ends with `128 + signo`.
    fn alert(&self, tid: u32, signo: u32) -> i64;
    /// The address of code that issues `rt_sigreturn` (a handler's return
    /// address when the program gave no `SA_RESTORER`).
    fn sigreturn_code(&self) -> u64;
    /// Resume the program at `frame` with thread pointer `tp` (x86-64
    /// `arch_prctl(ARCH_SET_FS)`): ring 3 cannot write its FS base, and the
    /// kernel writes one only at a thread's first entry, so a new thread of
    /// the process started with `tp` (`SYS_THREAD_CREATE`) resumes the frame
    /// and the calling thread never returns to user mode. Comes back only
    /// when no thread could be made: the native negative code.
    fn resume_with_thread_pointer(&self, frame: &ForeignFrame, tp: u64) -> i64;
}

// ── A lock for the process's state ──────────────────────────────────────────

/// A lock whose waiters yield. The state is small and never held across a
/// native call that can block; a thread that fails to take it calls the
/// `yield_now` the caller passes to [`Lock::with`] (the native `SYS_YIELD`),
/// so under strict priority the holder runs instead of being spun against.
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

    /// Run `f` on the protected value, calling `wait` between attempts while
    /// another thread holds the lock.
    pub fn with<R>(&self, wait: impl Fn(), f: impl FnOnce(&mut T) -> R) -> R {
        while self.held.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            wait();
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
    /// Signals posted to this process and not yet delivered.
    pending: u64,
    umask: u32,
    exe: [u8; EXE_MAX],
    exe_len: u8,
    /// Unanswered calls reported so far (bounded).
    reported: u8,
    /// The thread-id word `set_tid_address` was given.
    tid_addr: u64,
    /// The ids of the threads `clone` made and that still run (0: free).
    threads: [u32; THREADS],
    /// Children forked and not yet reaped (0: free).
    children: [u32; CHILDREN],
    /// The program break (0 until the program first asks): what `brk` answers.
    brk_cur: u64,
    /// The end of the pages mapped for the break (`brk_cur` rounded up).
    brk_end: u64,
    /// The FS base `arch_prctl(ARCH_SET_FS)` installed (x86-64; 0 at start).
    fs_base: u64,
}

/// Threads one process may have besides its first (the native limit is 16 per group).
pub const THREADS: usize = 16;

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
    pending: 0,
    umask: 0o022,
    exe: [0; EXE_MAX],
    exe_len: 0,
    reported: 0,
    tid_addr: 0,
    threads: [0; THREADS],
    children: [0; CHILDREN],
    brk_cur: 0,
    brk_end: 0,
    fs_base: 0,
};

/// The layouts of the asm-generic calls the runtime answers. x86_64 has none
/// of its own (`None`): its face (`lx::x86_64`) hands the runtime asm-generic
/// calls, whose flag values are riscv64's, and writes the layouts that differ
/// itself.
fn arch() -> lx::Arch {
    lx::Arch::native().unwrap_or(lx::Arch::Riscv64)
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
    /// Threads of the process still running, the first included.
    live: AtomicU32,
    /// A `clone` made a thread: `gettid` is then the calling thread's id.
    threaded: AtomicBool,
}

impl<N: Native> Runtime<N> {
    /// A runtime with the process's initial state: the console on
    /// descriptors 0, 1 and 2, working directory `/`.
    pub const fn new(native: N) -> Self {
        Self { native, st: Lock::new(STATE_INIT), pid: AtomicI64::new(0), ppid: AtomicI64::new(1), live: AtomicU32::new(1), threaded: AtomicBool::new(false) }
    }

    /// Run `f` on the process's state, yielding through the native call while
    /// another thread holds it.
    fn locked<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        self.st.with(|| self.native.yield_now(), f)
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
        self.live.store(1, Ordering::Relaxed);
        self.threaded.store(false, Ordering::Relaxed);
        self.locked(|s| {
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
        if num == nr::RT_SIGRETURN {
            self.sigreturn(f);
            self.deliver(f);
            return;
        }
        let a = |i: usize| f.gpr[REG_RESULT + i];
        let r = if num == nr::CLONE && is_thread_clone(a(0), a(1)) {
            self.sys_clone_thread(f, (REG_RESULT, REG_SP), a(0), a(1), a(2), a(3), a(4))
        } else {
            self.call(num, a(0), a(1), a(2), a(3), a(4), a(5))
        };
        f.gpr[REG_RESULT] = r as u64;
        self.deliver(f);
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
                    Post::None if c.num == nr::CLONE && is_thread_clone(a[0], a[1]) => {
                        self.sys_clone_thread(f, (x86::REG_RESULT, X86_RSP), a[0], a[1], a[2], a[3], a[4])
                    }
                    Post::None => self.call(c.num, a[0], a[1], a[2], a[3], a[4], a[5]),
                    Post::PollMs(ms) => {
                        let wait = if (ms as i32) < 0 {
                            None
                        } else {
                            Some(self.native.now_ns().saturating_add(u64::from(ms) * 1_000_000))
                        };
                        self.poll(a[0], a[1], wait)
                    }
                    Post::Sigaction => self.sys_rt_sigaction(lx::Arch::Aarch64, a[0], a[1], a[2], a[3]),
                    Post::Uname(buf) => put_user(buf, &x86::utsname_bytes(b"azos")),
                    Post::ArchPrctl => self.sys_arch_prctl(f, a[0], a[1]),
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

    /// `arch_prctl(code, addr)` (x86-64): the FS base, musl's thread pointer.
    /// `ARCH_SET_FS` writes the result into the frame first and resumes the
    /// program on a thread started with the base ([`Native::resume_with_thread_pointer`]):
    /// it returns only when that failed, with the base not installed.
    /// `ARCH_GET_FS` stores the base last installed. A non-canonical base is
    /// `-EPERM`, any other code `-EINVAL`, as Linux answers them.
    fn sys_arch_prctl(&self, f: &mut ForeignFrame, code: u64, addr: u64) -> i64 {
        use lx::x86_64::arch_prctl::{FS_LIMIT, GET_FS, SET_FS};
        match code {
            SET_FS if addr >= FS_LIMIT => neg(le::EPERM),
            SET_FS => {
                let old = self.locked(|s| core::mem::replace(&mut s.fs_base, addr));
                f.gpr[lx::x86_64::REG_RESULT] = 0;
                let r = self.native.resume_with_thread_pointer(f, addr);
                self.locked(|s| s.fs_base = old);
                lx::errno_from_native(r, le::ENOMEM)
            }
            GET_FS => put_user(addr, &self.locked(|s| s.fs_base).to_le_bytes()),
            _ => neg(le::EINVAL),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn call(&self, num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
        match num {
            // A process is a thread group of one here; its id is the thread's.
            nr::GETPID => self.pid.load(Ordering::Relaxed),
            nr::GETTID => self.tid(),
            nr::SET_TID_ADDRESS if !cfg!(feature = "canary-no-threads") => {
                self.locked(|s| s.tid_addr = a0);
                let r = self.native.set_clear_tid(a0);
                if r < 0 { lx::errno_from_native(r, le::EINVAL) } else { self.tid() }
            }
            nr::SET_TID_ADDRESS => {
                self.locked(|s| s.tid_addr = a0);
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
            nr::EXIT if !cfg!(feature = "canary-no-threads") => self.sys_exit(a0),
            nr::EXIT | nr::EXIT_GROUP => self.native.exit((a0 & 0xff) as i32),
            nr::EXECVE if !cfg!(feature = "canary-no-execve") => self.sys_execve(a0, a1, a2),
            nr::CLONE => self.sys_clone(a0, a1),
            nr::WAIT4 => self.sys_wait4(a0, a1, a2, a3),
            nr::GETPPID => self.ppid.load(Ordering::Relaxed),
            nr::BRK => self.sys_brk(a0),
            nr::MMAP => self.sys_mmap(a0, a1, a2, a3, a4),
            nr::MUNMAP => lx::errno_from_native(self.native.munmap(a0, a1), le::EINVAL),
            nr::CLOCK_GETTIME => self.sys_clock_gettime(a0, a1),
            nr::NANOSLEEP => self.sys_nanosleep(a0),
            nr::PPOLL => self.sys_ppoll(a0, a1, a2),
            nr::SCHED_YIELD => {
                self.native.yield_now();
                0
            }
            nr::LSEEK if !cfg!(feature = "canary-no-lseek") => self.sys_lseek(a0, a1, a2),
            nr::MPROTECT if !cfg!(feature = "canary-no-mprotect") => self.sys_mprotect(a0, a1, a2),
            nr::FUTEX if !cfg!(feature = "canary-no-futex") => self.sys_futex(a0, a1, a2, a3, a5),
            nr::KILL if !cfg!(feature = "canary-no-kill") => self.sys_kill(a0 as i64, a1),
            nr::TKILL if !cfg!(feature = "canary-no-kill") => self.sys_tgkill(a0, a0, a1),
            nr::TGKILL if !cfg!(feature = "canary-no-kill") => self.sys_tgkill(a0, a1, a2),
            nr::RT_SIGACTION => self.sys_rt_sigaction(arch(), a0, a1, a2, a3),
            nr::RT_SIGPROCMASK => self.sys_rt_sigprocmask(a0, a1, a2, a3),
            nr::RT_SIGPENDING => self.sys_rt_sigpending(a0, a1),
            nr::SIGALTSTACK => self.sys_sigaltstack(a0, a1),
            nr::UNAME => {
                let u = lx::utsname_bytes(arch(), b"azos");
                put_user(a0, &u)
            }
            nr::UMASK => self.locked(|s| {
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
        let first = self.locked(|s| {
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
            self.live.store(1, Ordering::Relaxed);
            self.threaded.store(false, Ordering::Relaxed);
            self.locked(|s| {
                s.children = [0; CHILDREN];
                s.threads = [0; THREADS];
            });
            return 0;
        }
        let kept = self.locked(|s| match s.children.iter().position(|&c| c == 0) {
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

    /// The calling thread's id: the process's until a `clone` made a thread.
    fn tid(&self) -> i64 {
        if self.threaded.load(Ordering::Relaxed) {
            self.native.getpid()
        } else {
            self.pid.load(Ordering::Relaxed)
        }
    }

    /// `exit`: the calling thread only. The last thread ends the process
    /// with its code.
    fn sys_exit(&self, code: u64) -> i64 {
        let code = (code & 0xff) as i32;
        if self.live.fetch_sub(1, Ordering::AcqRel) > 1 {
            let me = self.native.getpid() as u32;
            self.locked(|s| {
                if let Some(t) = s.threads.iter_mut().find(|t| **t == me) {
                    *t = 0;
                }
            });
            self.native.thread_exit(code)
        }
        self.native.exit(code)
    }

    /// `clone` as a thread ([`is_thread_clone`]): `SYS_THREAD_CREATE` with the
    /// creator's registers as the new thread's, result 0, on `newsp`.
    fn sys_clone_thread(&self, f: &ForeignFrame, regs: (usize, usize), flags: u64, newsp: u64, ptid: u64, tls: u64, ctid: u64) -> i64 {
        use lx::clone::*;
        if cfg!(feature = "canary-no-threads") {
            return self.unanswered(nr::CLONE);
        }
        if newsp & 15 != 0 {
            return neg(le::EINVAL);
        }
        let mut start = *f;
        start.gpr[regs.0] = 0;
        start.gpr[regs.1] = newsp;
        let clear = if flags & CLONE_CHILD_CLEARTID != 0 { ctid } else { 0 };
        let tp = if flags & CLONE_SETTLS != 0 {
            tls
        } else {
            // The thread keeps its creator's thread pointer.
            match self.native.thread_pointer() {
                0 => self.locked(|s| s.fs_base),
                t => t,
            }
        };
        let settid = [
            if flags & CLONE_PARENT_SETTID != 0 { ptid } else { 0 },
            if flags & CLONE_CHILD_SETTID != 0 { ctid } else { 0 },
        ];
        self.threaded.store(true, Ordering::Relaxed);
        self.live.fetch_add(1, Ordering::AcqRel);
        let r = self.native.thread_create(&start, newsp, clear, tp, settid);
        if r < 0 {
            self.live.fetch_sub(1, Ordering::AcqRel);
            return neg(le::EAGAIN);
        }
        self.locked(|s| {
            if let Some(t) = s.threads.iter_mut().find(|t| **t == 0) {
                *t = r as u32;
            }
        });
        r
    }

    /// `execve(path, argv, envp)`: the image is started over `SYS_SPAWN_EX`
    /// with the strings, the working directory and the descriptors 0..=7 that
    /// are not close-on-exec; this process closes what it held, waits for the
    /// image and exits with its code. Descriptors at 8 and above that stay
    /// open across an exec are `-EMFILE` (the request carries eight). `-E2BIG`
    /// past the request's limits, `-ENOENT` when the image cannot be read,
    /// `-EACCES` when the row may not start it.
    fn sys_execve(&self, path_ptr: u64, argv_ptr: u64, envp_ptr: u64) -> i64 {
        let mut raw = [0u8; PATH_MAX];
        let n = match user_path(path_ptr, &mut raw) {
            Ok(n) => n,
            Err(e) => return e,
        };
        let mut abs = [0u8; PATH_MAX];
        let alen = match self.resolve(lx::AT_FDCWD, &raw[..n], &mut abs) {
            Ok(l) => l,
            Err(e) => return e,
        };
        let mut z = [0u8; PATH_MAX + 1];
        let path = match nul_terminated(&abs[..alen], &mut z) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut argv = [0u8; EXEC_STRINGS];
        let mut env = [0u8; EXEC_STRINGS];
        let (al, argc) = match user_strv(argv_ptr, &mut argv) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (el, envc) = match user_strv(envp_ptr, &mut env) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (fds, cwd, cwd_len) = self.locked(|s| (s.fds, s.cwd, s.cwd_len as usize));
        let mut zc = [0u8; CWD_MAX + 1];
        zc[..cwd_len].copy_from_slice(&cwd[..cwd_len]);
        let mut carry = [ExecFd::Closed; 8];
        for (i, e) in fds.iter().enumerate() {
            let c = match e.kind {
                Kind::Closed | Kind::Dir => ExecFd::Closed,
                _ if e.cloexec => ExecFd::Closed,
                Kind::Console => ExecFd::Console,
                Kind::File => ExecFd::File(e.handle),
                Kind::Pipe => ExecFd::Pipe(e.handle),
            };
            if i < 8 {
                carry[i] = c;
            } else if c != ExecFd::Closed {
                return neg(le::EMFILE);
            }
        }
        let img = SpawnImage {
            path,
            argv: &argv[..al],
            argc,
            env: &env[..el],
            envc,
            cwd: &zc[..cwd_len + 1],
            fds: carry,
        };
        let child = self.native.spawn_image(&img);
        if child < 0 {
            return match child {
                -13 => neg(le::EACCES),
                -24 => neg(le::EMFILE),
                -22 => neg(le::EINVAL),
                -11 => neg(le::EAGAIN),
                _ => neg(le::ENOENT),
            };
        }
        // What the image does not inherit goes: the file handles were moved,
        // the pipe ends were shared and are still this process's.
        for e in fds.iter() {
            match e.kind {
                Kind::Pipe => {
                    let _ = self.native.handle_close(e.handle);
                }
                Kind::File if e.cloexec => {
                    let _ = self.native.handle_close(e.handle);
                }
                _ => {}
            }
        }
        // The child's exit wakes this sleep (`DOMAIN_WAIT` with no time limit).
        loop {
            let mut code = 0i32;
            if self.native.wait_block(child as u32, &mut code) > 0 {
                self.native.exit(code & 0xff);
            }
        }
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
            let kids = self.locked(|s| s.children);
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
                    _ => self.locked(|s| {
                        if let Some(c) = s.children.iter_mut().find(|c| **c == k) {
                            *c = 0;
                        }
                    }),
                }
            }
            if let Some((tid, code)) = found {
                self.locked(|s| {
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
            // Sleep until the named child (or any child) ends, then take it
            // in the scan above, which also forgets what the kernel reaped.
            let mut code = 0i32;
            let target = if pid > 0 { pid as u32 } else { 0 };
            let r = self.native.wait_block(target, &mut code);
            if r > 0 {
                self.locked(|s| {
                    if let Some(c) = s.children.iter_mut().find(|c| **c == r as u32) {
                        *c = 0;
                    }
                });
                if status_ptr != 0 && put_user(status_ptr, &lx::wait_status(code).to_le_bytes()) != 0 {
                    return neg(le::EFAULT);
                }
                return r;
            }
            if r == -4 {
                return neg(le::EINTR);
            }
        }
    }

    // ── descriptors ─────────────────────────────────────────────────────────

    fn fd_get(&self, fd: u64) -> Result<FdEnt, i64> {
        if fd >= FDS as u64 {
            return Err(neg(le::EBADF));
        }
        let e = self.locked(|s| s.fds[fd as usize]);
        if e.kind == Kind::Closed { Err(neg(le::EBADF)) } else { Ok(e) }
    }

    /// The lowest closed descriptor at or above `min`, claimed with `ent`
    /// (and `path` kept for a file).
    fn fd_alloc(&self, min: usize, ent: FdEnt, path: Option<&[u8]>) -> Result<usize, i64> {
        self.locked(|s| {
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
            let (e, n) = self.locked(|s| (s.exe, s.exe_len as usize));
            if n == 0 {
                return Err(neg(le::ENOENT));
            }
            out[..n].copy_from_slice(&e[..n]);
            return Ok(n);
        }
        let mut base = [0u8; KEEP_PATH_MAX];
        let base_len;
        if path.first() == Some(&b'/') || dirfd == lx::AT_FDCWD {
            let (c, n) = self.locked(|s| (s.cwd, s.cwd_len as usize));
            base[..n].copy_from_slice(&c[..n]);
            base_len = n;
        } else {
            let e = self.fd_get(dirfd)?;
            if e.kind != Kind::Dir {
                return Err(neg(le::ENOTDIR));
            }
            let d = self.locked(|s| s.dirs[e.dir as usize]);
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
        let (handler, masked) = self.locked(|s| (s.act[SIGPIPE as usize - 1].handler, s.mask & (1 << (SIGPIPE - 1)) != 0));
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
        let r = self.locked(|s| {
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
        let still_named = self.locked(|s| {
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
                let (p, n) = self.locked(|s| (s.paths[fd as usize].path, s.paths[fd as usize].len as usize));
                if n == 0 {
                    // A file the spawn handed over (`> f`): no path to ask
                    // the native `stat` about, so the size is unknown.
                    st.mode = lx::mode::S_IFREG | 0o644;
                } else {
                    return self.stat_path(&p[..n]);
                }
            }
            Kind::Dir => {
                let d = self.locked(|s| s.dirs[e.dir as usize]);
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
        let d = self.locked(|s| s.dirs[e.dir as usize]);
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
        self.locked(|s| s.dirs[e.dir as usize].next = idx);
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
                    self.locked(|s| s.fds[a] = FD_CLOSED);
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
        let kept = self.locked(|s| s.paths[old as usize]);
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
        self.locked(|s| {
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
                self.locked(|s| s.fds[fd as usize].cloexec = arg & FD_CLOEXEC != 0);
                0
            }
            F_GETFL => (e.accmode as u64 | if e.nonblock { lx::oflag::O_NONBLOCK } else { 0 }) as i64,
            F_SETFL => {
                let on = arg & lx::oflag::O_NONBLOCK != 0;
                self.locked(|s| s.fds[fd as usize].nonblock = on);
                if e.kind == Kind::Pipe {
                    self.native.handle_set_nonblock(e.handle, on);
                }
                0
            }
            F_DUPFD | F_DUPFD_CLOEXEC => {
                if e.kind == Kind::Dir || arg >= FDS as u64 {
                    return neg(le::EINVAL);
                }
                let kept = self.locked(|s| s.paths[fd as usize]);
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
        let (c, n) = self.locked(|s| (s.cwd, s.cwd_len as usize));
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
        self.locked(|s| {
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
        self.locked(|s| {
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
        let flags = match anon_map_flags(len, prot, flags) {
            Ok(f) => f,
            Err(e) => return e,
        };
        // The hint, `MAP_FIXED_NOREPLACE` and the pre-commit bits travel (same
        // values in both ABIs); the kernel places the mapping.
        let r = self.native.mmap(addr, len, prot, flags);
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

    // ── poll ────────────────────────────────────────────────────────────────

    /// `ppoll(fds, nfds, timeout, ...)`: the signal mask argument is not
    /// applied (no signal is delivered here).
    fn sys_ppoll(&self, fds: u64, nfds: u64, tmo: u64) -> i64 {
        let wait = if tmo == 0 {
            None
        } else {
            let mut b = [0u8; 16];
            if get_user(tmo, &mut b) != 0 {
                return neg(le::EFAULT);
            }
            let Some(ns) = lx::timespec_ns(&b) else { return neg(le::EINVAL) };
            Some(self.native.now_ns().saturating_add(ns))
        };
        self.poll(fds, nfds, wait)
    }

    /// Report each descriptor's readiness in its `revents`; with none ready
    /// wait until `deadline` (`None`: without bound), looking again every
    /// [`POLL_TICK_NS`]. The count of descriptors with a nonzero `revents`.
    fn poll(&self, fds: u64, nfds: u64, deadline: Option<u64>) -> i64 {
        use lx::poll::{parse, NFDS_MAX, POLLFD_BYTES};
        if nfds > NFDS_MAX {
            return neg(le::EINVAL);
        }
        loop {
            let mut ready = 0i64;
            for i in 0..nfds {
                let at = fds.wrapping_add(i * POLLFD_BYTES as u64);
                let mut rec = [0u8; POLLFD_BYTES];
                if get_user(at, &mut rec) != 0 {
                    return neg(le::EFAULT);
                }
                let (fd, events) = parse(&rec);
                let revents = if fd < 0 { 0 } else { self.revents(fd as u64, events) };
                if put_user(at.wrapping_add(6), &revents.to_le_bytes()) != 0 {
                    return neg(le::EFAULT);
                }
                ready += i64::from(revents != 0);
            }
            if ready > 0 {
                return ready;
            }
            let now = self.native.now_ns();
            let next = match deadline {
                Some(d) if now >= d => return 0,
                Some(d) => d.min(now.saturating_add(POLL_TICK_NS)),
                None => now.saturating_add(POLL_TICK_NS),
            };
            self.native.sleep_until_ns(next);
        }
    }

    /// The events descriptor `fd` reports for the `events` asked.
    fn revents(&self, fd: u64, events: u16) -> u16 {
        use lx::poll::*;
        let Ok(e) = self.fd_get(fd) else { return POLLNVAL };
        let raw = match e.kind {
            // Reads of the console answer end of file at once, and a write
            // never waits.
            Kind::Console | Kind::File | Kind::Dir => POLLIN | POLLOUT,
            Kind::Pipe => match self.native.pipe_ready(e.handle) {
                None => POLLNVAL,
                Some(p) if p.write_end => {
                    if p.hup {
                        POLLERR
                    } else if p.ready {
                        POLLOUT
                    } else {
                        0
                    }
                }
                Some(p) => (if p.ready { POLLIN } else { 0 }) | (if p.hup { POLLHUP } else { 0 }),
            },
            Kind::Closed => POLLNVAL,
        };
        raw & (events | POLLERR | POLLHUP | POLLNVAL)
    }

    // ── signals ─────────────────────────────────────────────────────────────

    /// `lseek`: a file's offset lives in its open description, which the
    /// native handle names (every duplicate shares it). A directory rewinds;
    /// the console and pipe ends cannot seek.
    fn sys_lseek(&self, fd: u64, off: u64, whence: u64) -> i64 {
        let e = match self.fd_get(fd) {
            Ok(e) => e,
            Err(r) => return r,
        };
        if whence > 2 {
            return neg(le::EINVAL);
        }
        match e.kind {
            Kind::File => lx::errno_from_native(self.native.handle_seek(e.handle, off as i64, whence as u32), le::EINVAL),
            Kind::Dir if off == 0 && whence == 0 => {
                self.locked(|s| s.dirs[e.dir as usize].next = 0);
                0
            }
            Kind::Dir => neg(le::EINVAL),
            _ => neg(le::ESPIPE),
        }
    }

    /// `mprotect`: the native call refuses `PROT_EXEC`, so W^X holds here as
    /// it did in the kernel's table. An empty range is success when aligned.
    fn sys_mprotect(&self, addr: u64, len: u64, prot: u64) -> i64 {
        if len == 0 {
            return if addr & (self.native.page_size() - 1) == 0 { 0 } else { neg(le::EINVAL) };
        }
        lx::errno_from_native(self.native.mprotect(addr, len, prot), le::ENOMEM)
    }

    /// `futex` wait and wake on the plain or `_BITSET(MATCH_ANY)` form, and the
    /// priority-inheritance lock, trylock and unlock on the native PI word
    /// operations (same word protocol). The kernel keys the word by the
    /// process, so `FUTEX_PRIVATE_FLAG` changes nothing. Requeue is not
    /// answered.
    fn sys_futex(&self, uaddr: u64, op: u64, val: u64, timeout: u64, val3: u64) -> i64 {
        use lx::futex::*;
        let cmd = op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
        let bitset = cmd == FUTEX_WAIT_BITSET || cmd == FUTEX_WAKE_BITSET;
        if bitset && val3 & 0xffff_ffff != FUTEX_BITSET_MATCH_ANY {
            return self.unanswered(nr::FUTEX);
        }
        match cmd {
            FUTEX_WAIT | FUTEX_WAIT_BITSET => {
                if uaddr == 0 {
                    return neg(le::EFAULT);
                }
                if uaddr & 3 != 0 {
                    return neg(le::EINVAL);
                }
                let rel = if timeout == 0 {
                    0
                } else {
                    let mut b = [0u8; 16];
                    if get_user(timeout, &mut b) != 0 {
                        return neg(le::EFAULT);
                    }
                    let Some(ns) = lx::timespec_ns(&b) else { return neg(le::EINVAL) };
                    if cmd == FUTEX_WAIT {
                        // Natively 0 is "no timeout"; a zero timespec is "now".
                        ns.max(1)
                    } else {
                        let clock = if op & FUTEX_CLOCK_REALTIME != 0 { ClockId::REAL } else { ClockId::MONO };
                        let Ok(now) = self.native.clock_ns(clock) else { return neg(le::EINVAL) };
                        match ns.checked_sub(now) {
                            Some(d) if d > 0 => d,
                            _ => return neg(le::ETIMEDOUT),
                        }
                    }
                };
                match self.native.futex_wait(uaddr, val as u32, rel) {
                    -110 => neg(le::ETIMEDOUT),
                    r => lx::errno_from_native(r, le::EINVAL),
                }
            }
            FUTEX_WAKE | FUTEX_WAKE_BITSET => {
                if uaddr == 0 {
                    return neg(le::EFAULT);
                }
                if uaddr & 3 != 0 || (val as i32) < 0 {
                    return neg(le::EINVAL);
                }
                lx::errno_from_native(self.native.futex_wake(uaddr, val as u32), le::EINVAL)
            }
            FUTEX_LOCK_PI | FUTEX_LOCK_PI2 | FUTEX_TRYLOCK_PI => {
                if uaddr == 0 {
                    return neg(le::EFAULT);
                }
                if uaddr & 3 != 0 {
                    return neg(le::EINVAL);
                }
                // Absolute: on CLOCK_REALTIME for FUTEX_LOCK_PI, and for
                // FUTEX_LOCK_PI2 when the flag says so; else the monotonic one.
                let rel = if cmd == FUTEX_TRYLOCK_PI || timeout == 0 {
                    0
                } else {
                    let mut b = [0u8; 16];
                    if get_user(timeout, &mut b) != 0 {
                        return neg(le::EFAULT);
                    }
                    let Some(ns) = lx::timespec_ns(&b) else { return neg(le::EINVAL) };
                    let realtime = cmd == FUTEX_LOCK_PI || op & FUTEX_CLOCK_REALTIME != 0;
                    let clock = if realtime { ClockId::REAL } else { ClockId::MONO };
                    let Ok(now) = self.native.clock_ns(clock) else { return neg(le::EINVAL) };
                    match ns.checked_sub(now) {
                        Some(d) if d > 0 => d,
                        _ => return neg(le::ETIMEDOUT),
                    }
                };
                match self.native.futex_lock_pi(uaddr, rel, cmd == FUTEX_TRYLOCK_PI) {
                    -110 => neg(le::ETIMEDOUT),
                    r => lx::errno_from_native(r, le::EINVAL),
                }
            }
            FUTEX_UNLOCK_PI => {
                if uaddr == 0 {
                    return neg(le::EFAULT);
                }
                if uaddr & 3 != 0 {
                    return neg(le::EINVAL);
                }
                lx::errno_from_native(self.native.futex_unlock_pi(uaddr), le::EINVAL)
            }
            _ => self.unanswered(nr::FUTEX),
        }
    }

    /// `kill(pid, sig)`. Process groups do not exist here.
    fn sys_kill(&self, pid: i64, sig: u64) -> i64 {
        if sig > lx::sig::NSIG_MAX {
            return neg(le::EINVAL);
        }
        if pid == 0 || pid == self.pid.load(Ordering::Relaxed) {
            return self.post_self(sig);
        }
        if pid < 0 {
            return neg(le::ESRCH);
        }
        self.signal_child(pid as u32, sig)
    }

    /// `tgkill(tgid, tid, sig)`: a process is a thread group of one, so the
    /// thread is the process.
    fn sys_tgkill(&self, tgid: u64, tid: u64, sig: u64) -> i64 {
        if sig > lx::sig::NSIG_MAX {
            return neg(le::EINVAL);
        }
        let own_thread = tgid as i64 == self.pid.load(Ordering::Relaxed)
            && tid != 0
            && self.locked(|s| s.threads.contains(&(tid as u32)));
        if tgid != tid && !own_thread {
            return neg(le::ESRCH);
        }
        if own_thread || tid as i64 == self.pid.load(Ordering::Relaxed) {
            self.post_self(sig)
        } else {
            self.signal_child(tid as u32, sig)
        }
    }

    fn post_self(&self, sig: u64) -> i64 {
        if sig == 0 {
            return 0;
        }
        let handled = self.locked(|s| s.act[sig as usize - 1].handler > lx::sig::SIG_IGN);
        if handled && lx::Arch::native().is_none() {
            return self.unanswered(nr::KILL);
        }
        self.locked(|s| s.pending |= lx::signal::bit(sig));
        0
    }

    /// A signal to a child over `SYS_ALERT`, which ends it as the default
    /// action does. A signal whose default action discards it, and signal 0,
    /// only check that the child exists.
    fn signal_child(&self, pid: u32, sig: u64) -> i64 {
        let child = self.locked(|s| s.children.contains(&pid));
        if sig == 0 || lx::signal::default_action(sig) != lx::signal::DefaultAction::Terminate {
            return if child { 0 } else { neg(le::ESRCH) };
        }
        if sig > 31 {
            return self.unanswered(nr::KILL);
        }
        match self.native.alert(pid, sig as u32) {
            r if r > 0 => 0,
            r => lx::errno_from_native(r, le::ESRCH),
        }
    }

    /// The first pending signal the mask lets through, taken off the pending
    /// set: its action and the mask the interrupted code had.
    fn take_signal(&self) -> Option<(u64, lx::KSigaction, u64)> {
        self.locked(|s| {
            let ready = s.pending & !s.mask;
            if ready == 0 {
                return None;
            }
            let sig = u64::from(ready.trailing_zeros()) + 1;
            s.pending &= !lx::signal::bit(sig);
            let act = s.act[sig as usize - 1];
            let old = s.mask;
            if act.handler > lx::sig::SIG_IGN {
                s.mask |= act.mask;
                if act.flags & lx::signal::sa::NODEFER == 0 {
                    s.mask |= lx::signal::bit(sig);
                }
                if act.flags & lx::signal::sa::RESETHAND != 0 {
                    s.act[sig as usize - 1] = KSA_DFL;
                }
            }
            Some((sig, act, old))
        })
    }

    /// Deliver what is pending at the return of the call in `f`: ignore it,
    /// end the process, or enter the handler on a frame below the program's
    /// stack pointer.
    fn deliver(&self, f: &mut ForeignFrame) {
        use lx::signal::{self as sg, DefaultAction};
        while let Some((sig, act, old_mask)) = self.take_signal() {
            match act.handler {
                lx::sig::SIG_IGN => continue,
                lx::sig::SIG_DFL => match sg::default_action(sig) {
                    DefaultAction::Terminate => self.native.exit(128 + sig as i32),
                    _ => continue,
                },
                handler => {
                    let Some(arch) = lx::Arch::native() else { self.native.exit(128 + 11) };
                    let base = sg::frame_base(arch, f.gpr[REG_SP]);
                    let ctx = sg::Context { gpr: f.gpr, pc: f.pc, pstate: f.flags };
                    let info = sg::Info { signo: sig as u32, code: sg::si::USER, pid: self.pid.load(Ordering::Relaxed) as u32, status: 0 };
                    let mut w = [0u64; sg::FRAME_WORDS_MAX];
                    let Some(n) = sg::write_frame(arch, &mut w, &ctx, old_mask, &info, false) else {
                        self.native.exit(128 + 11)
                    };
                    let mut bytes = [0u8; sg::FRAME_WORDS_MAX * 8];
                    for (i, v) in w[..n].iter().enumerate() {
                        bytes[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
                    }
                    put_user(base, &bytes[..n * 8]);
                    let restorer = if act.flags & sg::sa::RESTORER != 0 && act.restorer != 0 {
                        act.restorer
                    } else {
                        self.native.sigreturn_code()
                    };
                    f.gpr[REG_RESULT] = sig;
                    f.gpr[REG_RESULT + 1] = base;
                    f.gpr[REG_RESULT + 2] = base + sg::SIGINFO_SIZE as u64;
                    f.gpr[REG_SP] = base;
                    match arch {
                        lx::Arch::Riscv64 => f.gpr[1] = restorer,
                        lx::Arch::Aarch64 => {
                            // The frame record {fp, lr} after the ucontext.
                            let rec = base + 8 * sg::a64_frame_record_word() as u64;
                            let mut r = [0u8; 16];
                            r[..8].copy_from_slice(&ctx.gpr[29].to_le_bytes());
                            r[8..].copy_from_slice(&ctx.gpr[30].to_le_bytes());
                            put_user(rec, &r);
                            f.gpr[29] = rec;
                            f.gpr[30] = restorer;
                        }
                    }
                    f.pc = handler;
                    return;
                }
            }
        }
    }

    /// `rt_sigreturn`: restore the registers and mask from the frame at the
    /// stack pointer the handler returned with. A frame that cannot be read
    /// ends the process as `SIGSEGV` would.
    fn sigreturn(&self, f: &mut ForeignFrame) {
        use lx::signal as sg;
        let Some(arch) = lx::Arch::native() else { self.native.exit(128 + 11) };
        let n = sg::head_words(arch);
        let sp = f.gpr[REG_SP];
        if sp == 0 || sp & 15 != 0 {
            self.native.exit(128 + 11);
        }
        let mut bytes = [0u8; sg::FRAME_WORDS_MAX * 8];
        get_user(sp, &mut bytes[..n * 8]);
        let mut w = [0u64; sg::FRAME_WORDS_MAX];
        for (i, v) in w[..n].iter_mut().enumerate() {
            *v = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]));
        }
        let Some((ctx, mask, _fp)) = sg::read_frame(arch, &w[..n]) else { self.native.exit(128 + 11) };
        f.gpr = ctx.gpr;
        f.pc = ctx.pc;
        f.flags = ctx.pstate & azos_abi::foreign::FLAGS_USER_MASK;
        self.locked(|s| s.mask = mask);
    }

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
        let old = self.locked(|st| {
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
        let old = self.locked(|s| {
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

    /// The signals posted to this process that its mask holds back.
    fn sys_rt_sigpending(&self, set: u64, size: u64) -> i64 {
        if size != 8 {
            return neg(le::EINVAL);
        }
        let held = self.locked(|s| s.pending & s.mask);
        put_user(set, &held.to_le_bytes())
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
/// `rsp` in the frame's x86-64 register order (the hardware encoding, `azos_abi::foreign`).
const X86_RSP: usize = 4;

/// Is this `clone` a thread: `CLONE_VM | CLONE_FS | CLONE_FILES |
/// CLONE_SIGHAND | CLONE_THREAD`, the optional flags a C library adds, and a
/// stack of its own.
fn is_thread_clone(flags: u64, newsp: u64) -> bool {
    use lx::clone::*;
    let thread = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
    let optional = CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_DETACHED
        | CLONE_CHILD_SETTID;
    flags & thread == thread && flags & !(thread | optional) == 0 && newsp != 0
}

/// The NUL-terminated strings of the pointer vector at `ptr` (null: none),
/// NUL-separated into `out`: their bytes and count. `-E2BIG` past `out` or
/// `EXEC_ARGC` strings.
fn user_strv(ptr: u64, out: &mut [u8]) -> Result<(usize, u32), i64> {
    const E2BIG: i64 = 7;
    if ptr == 0 {
        return Ok((0, 0));
    }
    let (mut used, mut n) = (0usize, 0u32);
    loop {
        // SAFETY: the program's own vector, read up to its null terminator.
        let sp = unsafe { *((ptr + 8 * u64::from(n)) as *const u64) };
        if sp == 0 {
            return Ok((used, n));
        }
        if n as usize >= EXEC_ARGC {
            return Err(neg(E2BIG));
        }
        let mut i = 0usize;
        loop {
            // SAFETY: the program's own string, up to its terminator.
            let b = unsafe { *((sp + i as u64) as *const u8) };
            if used + i >= out.len() {
                return Err(neg(E2BIG));
            }
            out[used + i] = b;
            i += 1;
            if b == 0 {
                break;
            }
        }
        used += i;
        n += 1;
    }
}

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
