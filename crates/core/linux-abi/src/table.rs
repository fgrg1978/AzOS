// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The one source of the Linux calls the personality answers: number, name,
//! the native calls its translation may reach, a class and a note. The
//! `nr` constants, [`TABLE`] (what `linux.rs` and the ring-3 runtime answer,
//! and what every Linux image's seccomp profile is derived from) and the
//! table in `Documentation/linux-syscalls.md` all come from the one list
//! below; `tests/host/linux-abi-tests` fails when the document, the handlers'
//! `reach(..)` calls or the runtime's numbers drift from it.
//!
//! A number that is not here answers `-ENOSYS` and is tallied
//! ([`crate::tally`]): no call is added without the evidence the tally gives.

use azos_abi::syscall_nr as k;

/// Why a Linux call is, or is not, in the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Answered in full for what the measured binaries (musl programs,
    /// BusyBox) ask of it.
    Needed,
    /// Answered in a reduced shape (a subset of its requests, or by one of the
    /// two hosts only); the rest waits for the tally of unanswered calls to
    /// show a binary that needs it.
    Deferred,
    /// Refused by design, whatever a binary asks: the personality never
    /// answers it, so it stays out of [`TABLE`] and appears only here.
    Never,
}

impl Class {
    pub const fn name(self) -> &'static str {
        match self {
            Class::Needed => "needed",
            Class::Deferred => "deferred",
            Class::Never => "never",
        }
    }
}

/// One Linux call the personality answers.
#[derive(Clone, Copy, Debug)]
pub struct Syscall {
    pub nr: u64,
    pub name: &'static str,
    /// The native numbers its translation may reach (empty: answered from the
    /// personality's own state, or from a capability the task already holds).
    pub native: &'static [u16],
    /// The same numbers by name, for the documents and the scan of `linux.rs`.
    pub native_names: &'static [&'static str],
    pub class: Class,
    /// Where `linux.rs` makes the `reach(..)` calls for it: a function, or
    /// `arm:NAME` for the arm of `dispatch_slow` that answers `nr::NAME`.
    pub handlers: &'static [&'static str],
    pub note: &'static str,
}

macro_rules! syscalls {
    ($( $konst:ident = $num:literal, $name:literal, $class:ident,
        [$($nat:ident),*], [$($h:literal),*], $note:literal; )*) => {
        /// Linux syscall numbers (asm-generic; riscv64 and aarch64 alike).
        pub mod nr {
            $( pub const $konst: u64 = $num; )*
        }

        /// Every Linux number the personality answers. Anything not listed
        /// answers `-ENOSYS` and is tallied.
        pub const TABLE: &[Syscall] = &[
            $( Syscall {
                nr: $num,
                name: $name,
                native: &[$(k::$nat as u16),*],
                native_names: &[$(stringify!($nat)),*],
                class: Class::$class,
                handlers: &[$($h),*],
                note: $note,
            }, )*
        ];
    };
}

syscalls! {
    GETCWD = 17, "getcwd", Needed, [], [], "From the personality's own state: the working directory it keeps per process.";
    DUP = 23, "dup", Needed, [], [], "A descriptor alias in the personality's table; no native call.";
    DUP3 = 24, "dup3", Needed, [SYS_CAP_CLOSE], ["sys_close"], "`dup3` onto an open descriptor closes it first.";
    FCNTL = 25, "fcntl", Deferred, [], [], "Descriptor flags and `F_DUPFD` over the personality's table.";
    IOCTL = 29, "ioctl", Deferred, [], [], "The console's terminal requests only.";
    CHDIR = 49, "chdir", Needed, [SYS_INVOKE], ["is_dir"], "A directory is recognised with `stat`, or by listing for a mount point the VFS cannot stat.";
    OPENAT = 56, "openat", Needed, [SYS_INVOKE, SYS_CAP_CLOSE], ["sys_openat"], "A file is opened through `Cap<File>` and closed again when no descriptor is left for it; a directory is read later with `readdir`.";
    CLOSE = 57, "close", Needed, [SYS_CAP_CLOSE], ["sys_close", "pipe_release"], "Releases the handle when no descriptor is left for it.";
    PIPE2 = 59, "pipe2", Needed, [SYS_MO_CREATE, SYS_CAP_CLOSE], ["sys_pipe2"], "The pipe is a memory object with a byte ring in it, closed again when no descriptor is left for it.";
    GETDENTS64 = 61, "getdents64", Needed, [SYS_INVOKE], ["sys_getdents64"], "Asks the covering tree again on every call.";
    LSEEK = 62, "lseek", Needed, [SYS_INVOKE], ["sys_lseek"], "The offset of the open file description, over a held `Cap<File>`; the file is reached through `SYS_INVOKE`.";
    READ = 63, "read", Needed, [SYS_INVOKE], ["sys_read", "console_read_k", "read_kbuf"], "The console reads through the input the shell lent its foreground job.";
    WRITE = 64, "write", Needed, [SYS_INVOKE], ["sys_write", "write_kbuf"], "";
    READV = 65, "readv", Needed, [SYS_INVOKE], ["read_kbuf"], "";
    WRITEV = 66, "writev", Needed, [SYS_INVOKE], ["write_kbuf"], "";
    PPOLL = 73, "ppoll", Deferred, [SYS_SLEEP_UNTIL], [], "Answered only by the ring-3 runtime; the in-kernel table answers `-ENOSYS` and tallies it.";
    NEWFSTATAT = 79, "newfstatat", Needed, [SYS_INVOKE], ["stat_path"], "";
    FSTAT = 80, "fstat", Needed, [SYS_INVOKE], ["stat_fd", "stat_path"], "A file's size is read through its held `Cap<File>`; a directory descriptor is stat'ed by its path.";
    EXIT = 93, "exit", Needed, [SYS_EXIT, SYS_THREAD_EXIT], ["sys_exit_thread"], "A thread's exit; the last thread ends the process.";
    EXIT_GROUP = 94, "exit_group", Needed, [SYS_EXIT], ["sys_exit_group"], "";
    SET_TID_ADDRESS = 96, "set_tid_address", Needed, [], [], "The word the calling thread's exit clears and wakes.";
    FUTEX = 98, "futex", Deferred, [SYS_FUTEX_WAIT, SYS_FUTEX_WAKE], ["sys_futex"], "`FUTEX_WAIT`/`FUTEX_WAKE` and their `_BITSET` forms with a full mask, private to the process; requeue reaches the wake.";
    SET_ROBUST_LIST = 99, "set_robust_list", Needed, [], [], "The robust futex list walked at the thread's exit.";
    NANOSLEEP = 101, "nanosleep", Needed, [SYS_SLEEP_UNTIL], ["sys_nanosleep"], "";
    CLOCK_GETTIME = 113, "clock_gettime", Deferred, [], [], "Read from the vDSO clock; no native call.";
    SCHED_GETAFFINITY = 123, "sched_getaffinity", Deferred, [], [], "One CPU, the one the task runs on; another task's is answered only when the caller may signal it.";
    SCHED_YIELD = 124, "sched_yield", Needed, [SYS_YIELD], ["arm:SCHED_YIELD"], "";
    KILL = 129, "kill", Needed, [SYS_ALERT], ["sys_kill"], "A signal to another task is the native stop call's authority (the caller's ancestry); a signal to itself reaches nothing.";
    TKILL = 130, "tkill", Needed, [SYS_ALERT], ["sys_tkill"], "";
    TGKILL = 131, "tgkill", Needed, [SYS_ALERT], ["sys_tkill"], "";
    SIGALTSTACK = 132, "sigaltstack", Deferred, [], [], "Only `SS_DISABLE` is answered: no alternate stack.";
    RT_SIGSUSPEND = 133, "rt_sigsuspend", Needed, [SYS_SLEEP_UNTIL], ["sys_rt_sigsuspend"], "Waits as `nanosleep` does, until a signal is delivered.";
    RT_SIGACTION = 134, "rt_sigaction", Needed, [], [], "";
    RT_SIGPROCMASK = 135, "rt_sigprocmask", Needed, [], [], "";
    RT_SIGPENDING = 136, "rt_sigpending", Needed, [], [], "";
    RT_SIGRETURN = 139, "rt_sigreturn", Needed, [], [], "";
    UNAME = 160, "uname", Needed, [], [], "";
    UMASK = 166, "umask", Needed, [], [], "";
    PRCTL = 167, "prctl", Deferred, [SYS_INVOKE], ["arm:PRCTL"], "`PR_SET_NAME`/`PR_GET_NAME` and the child-subreaper pair (`DOMAIN_SUBREAPER`); every other option `-EINVAL`.";
    GETPID = 172, "getpid", Needed, [], [], "";
    GETPPID = 173, "getppid", Needed, [], [], "";
    GETUID = 174, "getuid", Needed, [], [], "";
    GETEUID = 175, "geteuid", Needed, [], [], "";
    GETGID = 176, "getgid", Needed, [], [], "";
    GETEGID = 177, "getegid", Needed, [], [], "";
    GETTID = 178, "gettid", Needed, [], [], "";
    BRK = 214, "brk", Needed, [SYS_INVOKE], ["arm:BRK"], "Personality-only: no native entry point moves the break; the native handler is reached through `SYS_INVOKE`.";
    MUNMAP = 215, "munmap", Needed, [SYS_MO_UNMAP], ["arm:MUNMAP"], "";
    CLONE = 220, "clone", Deferred, [SYS_FOREIGN_FORK, SYS_CAP_CLOSE, SYS_THREAD_CREATE], ["sys_clone", "clone_thread"], "Fork shape: a copy-on-write child reseeded from its row, counted against the row's `instances`; or a thread sharing the process's space, capabilities and descriptors.";
    EXECVE = 221, "execve", Deferred, [SYS_INVOKE, SYS_CAP_CLOSE, SYS_SPAWN_EX], ["exec_image"], "Into the caller's own row, or another Linux row the caller holds a launch grant for; the target row's scheduling applies.";
    MMAP = 222, "mmap", Deferred, [SYS_MO_MAP, SYS_INVOKE], ["sys_mmap", "sys_mmap_file"], "Anonymous private maps through the memory-object calls; a file map through `SYS_INVOKE`. Never executable, never `MAP_FIXED`.";
    MPROTECT = 226, "mprotect", Needed, [SYS_INVOKE], ["arm:MPROTECT"], "The pages' read and write permissions, exactly, through `SYS_INVOKE`/`DOMAIN_MPROTECT`; never execute.";
    WAIT4 = 260, "wait4", Needed, [SYS_INVOKE], ["sys_wait4"], "Reaps a child of the process.";
}

/// The native numbers Linux call `n` may reach, or `None` if the personality
/// does not answer `n` (it gets `-ENOSYS`).
pub fn native_reach(n: u64) -> Option<&'static [u16]> {
    TABLE.iter().find(|e| e.nr == n).map(|e| e.native)
}

/// The Linux number of the call named `name` (`"openat"`), for the
/// derivation in `tests/host/seccomp-tests`.
pub fn number_of(name: &str) -> Option<u64> {
    TABLE.iter().find(|e| e.name == name).map(|e| e.nr)
}
