// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Linux personality's pure half (RFC-0047, owner decisions P1-P6).
//!
//! A task whose signed topology row says `abi = "linux"` traps with Linux
//! syscall numbers in `a7`/`x8`. The kernel side
//! (`crates/core/syscall/src/linux.rs`) translates each call onto the native
//! handlers; this crate holds everything about that which needs no kernel
//! state, so `tests/host/linux-abi-tests` can check it on the host:
//!
//! - [`nr`]: the Linux numbers. riscv64 and aarch64 both use the asm-generic
//!   table, so one table serves both ISAs. Numbers and layouts are taken from
//!   musl (MIT: `arch/generic/bits/syscall.h.in`, `arch/*/bits/*.h`), not from
//!   Linux's uapi headers (RFC-0047 §0 point 3).
//! - [`native_reach`]: the NATIVE numbers a Linux call may reach once
//!   translated. Seccomp runs after translation (P5), so a Linux image's
//!   profile lists these; `tests/host/seccomp-tests` derives the profile of a
//!   Linux image from its source through this table.
//! - [`errno_from_native`], the open-flag map, and the wire layouts the
//!   translation writes: `struct stat`, `linux_dirent64`, `struct winsize`,
//!   the kernel `struct termios`, `struct utsname`, and the initial stack
//!   (argc, argv, envp, auxv) a static binary's `_start` reads.
#![no_std]

use azos_abi::syscall_nr as k;

/// The ISA a layout is for. The asm-generic syscall table is shared, but a
/// few layouts and flag values are not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    Riscv64,
    Aarch64,
}

impl Arch {
    /// The ISA this crate is compiled for (riscv64 on the host, where the
    /// host tests pass the ISA explicitly anyway).
    pub const fn native() -> Self {
        if cfg!(target_arch = "aarch64") && cfg!(target_os = "none") {
            Arch::Aarch64
        } else {
            Arch::Riscv64
        }
    }
}

/// Linux syscall numbers (asm-generic; riscv64 and aarch64 alike).
pub mod nr {
    pub const GETCWD: u64 = 17;
    pub const DUP: u64 = 23;
    pub const DUP3: u64 = 24;
    pub const FCNTL: u64 = 25;
    pub const IOCTL: u64 = 29;
    pub const CHDIR: u64 = 49;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const PIPE2: u64 = 59;
    pub const GETDENTS64: u64 = 61;
    pub const LSEEK: u64 = 62;
    pub const READ: u64 = 63;
    pub const WRITE: u64 = 64;
    pub const READV: u64 = 65;
    pub const WRITEV: u64 = 66;
    pub const NEWFSTATAT: u64 = 79;
    pub const FSTAT: u64 = 80;
    pub const EXIT: u64 = 93;
    pub const EXIT_GROUP: u64 = 94;
    pub const SET_TID_ADDRESS: u64 = 96;
    pub const FUTEX: u64 = 98;
    pub const SET_ROBUST_LIST: u64 = 99;
    pub const NANOSLEEP: u64 = 101;
    pub const CLOCK_GETTIME: u64 = 113;
    pub const SCHED_GETAFFINITY: u64 = 123;
    pub const SCHED_YIELD: u64 = 124;
    pub const KILL: u64 = 129;
    pub const TKILL: u64 = 130;
    pub const TGKILL: u64 = 131;
    pub const SIGALTSTACK: u64 = 132;
    pub const RT_SIGSUSPEND: u64 = 133;
    pub const RT_SIGACTION: u64 = 134;
    pub const RT_SIGPROCMASK: u64 = 135;
    pub const RT_SIGPENDING: u64 = 136;
    pub const RT_SIGRETURN: u64 = 139;
    pub const UNAME: u64 = 160;
    pub const UMASK: u64 = 166;
    pub const PRCTL: u64 = 167;
    pub const GETPID: u64 = 172;
    pub const GETPPID: u64 = 173;
    pub const GETUID: u64 = 174;
    pub const GETEUID: u64 = 175;
    pub const GETGID: u64 = 176;
    pub const GETEGID: u64 = 177;
    pub const GETTID: u64 = 178;
    pub const BRK: u64 = 214;
    pub const MUNMAP: u64 = 215;
    pub const CLONE: u64 = 220;
    pub const EXECVE: u64 = 221;
    pub const MMAP: u64 = 222;
    pub const MPROTECT: u64 = 226;
    pub const WAIT4: u64 = 260;
}

/// Every Linux number the personality answers, with the native numbers its
/// translation may reach (empty: answered from the personality's own state
/// or from a capability the task already holds, with no native entry point).
///
/// Anything not listed answers `-ENOSYS` and is recorded.
pub const TABLE: &[(u64, &str, &[u16])] = &[
    (nr::GETCWD, "getcwd", &[]),
    // `dup3` onto an open descriptor closes it first.
    (nr::DUP, "dup", &[]),
    (nr::DUP3, "dup3", &[k::SYS_CLOSE_TYPED as u16]),
    (nr::FCNTL, "fcntl", &[]),
    (nr::IOCTL, "ioctl", &[]),
    // A directory is recognised with `stat` (250), or by listing (251) for a
    // mount point the VFS cannot stat.
    (nr::CHDIR, "chdir", &[k::SYS_STAT as u16, k::SYS_READDIR as u16]),
    // A file is opened through `Cap<File>` (563) and closed again (566) when
    // no descriptor is left for it; a directory is recognised as `chdir`
    // does and read later with `readdir`.
    (nr::OPENAT, "openat", &[
        k::SYS_FILE_OPEN_TYPED as u16, k::SYS_STAT as u16, k::SYS_READDIR as u16,
        k::SYS_CLOSE_TYPED as u16,
    ]),
    (nr::CLOSE, "close", &[k::SYS_CLOSE_TYPED as u16]),
    // Both ends are closed again when no descriptor is left for one.
    (nr::PIPE2, "pipe2", &[k::SYS_PIPE_TYPED as u16, k::SYS_CLOSE_TYPED as u16]),
    (nr::GETDENTS64, "getdents64", &[k::SYS_READDIR as u16]),
    // Bookkeeping over a held `Cap<File>`: the offset of its open file description.
    (nr::LSEEK, "lseek", &[]),
    // The console reads through the input the shell lent its foreground job
    // (`SYS_CONSOLE_WAIT`'s authority, wave 13).
    (nr::READ, "read", &[k::SYS_FILE_READ_TYPED as u16, k::SYS_CONSOLE_WAIT as u16]),
    (nr::WRITE, "write", &[k::SYS_WRITE as u16, k::SYS_FILE_WRITE_TYPED as u16]),
    (nr::READV, "readv", &[k::SYS_FILE_READ_TYPED as u16, k::SYS_CONSOLE_WAIT as u16]),
    (nr::WRITEV, "writev", &[k::SYS_WRITE as u16, k::SYS_FILE_WRITE_TYPED as u16]),
    (nr::NEWFSTATAT, "newfstatat", &[k::SYS_STAT as u16, k::SYS_READDIR as u16]),
    // A file's size is read through its held `Cap<File>`; a directory
    // descriptor is stat'ed by its path.
    (nr::FSTAT, "fstat", &[k::SYS_STAT as u16, k::SYS_READDIR as u16]),
    (nr::EXIT, "exit", &[k::SYS_EXIT as u16]),
    (nr::EXIT_GROUP, "exit_group", &[k::SYS_EXIT as u16]),
    // The word the calling thread's exit clears and wakes (wave 13).
    (nr::SET_TID_ADDRESS, "set_tid_address", &[]),
    // Wave 13: `FUTEX_WAIT`/`FUTEX_WAKE` (and their `_BITSET` forms with a
    // full mask), private to the process.
    // Wave 15 N9: FUTEX_REQUEUE / CMP_REQUEUE reach SYS_FUTEX_WAKE (a wake
    // that moves the rest), so a profile that allows the wake allows them.
    (nr::FUTEX, "futex", &[k::SYS_FUTEX_WAIT as u16, k::SYS_FUTEX_WAKE as u16]),
    // Wave 15: the robust futex list walked at the thread's exit.
    (nr::SET_ROBUST_LIST, "set_robust_list", &[]),
    (nr::NANOSLEEP, "nanosleep", &[k::SYS_SLEEP_UNTIL as u16]),
    (nr::CLOCK_GETTIME, "clock_gettime", &[]),
    (nr::SCHED_YIELD, "sched_yield", &[k::SYS_YIELD as u16]),
    // One CPU, the one the task runs on (a single-threaded task's view).
    (nr::SCHED_GETAFFINITY, "sched_getaffinity", &[]),
    // `PR_SET_NAME`/`PR_GET_NAME` and `PR_{SET,GET}_CHILD_SUBREAPER` (wave
    // 13) accepted; every other option `-EINVAL`.
    (nr::PRCTL, "prctl", &[]),
    (nr::RT_SIGACTION, "rt_sigaction", &[]),
    (nr::RT_SIGPROCMASK, "rt_sigprocmask", &[]),
    (nr::RT_SIGPENDING, "rt_sigpending", &[]),
    // Waits as `nanosleep` does, until a signal is delivered.
    (nr::RT_SIGSUSPEND, "rt_sigsuspend", &[k::SYS_SLEEP_UNTIL as u16]),
    // Only `SS_DISABLE` is answered: no alternate stack.
    (nr::SIGALTSTACK, "sigaltstack", &[]),
    (nr::RT_SIGRETURN, "rt_sigreturn", &[]),
    // Wave 13: a signal to another task is the native stop call's authority
    // (`SYS_TASK_KILL`, 611): the caller's ancestry, by its profile. A
    // signal to itself reaches nothing.
    (nr::KILL, "kill", &[k::SYS_TASK_KILL as u16]),
    (nr::TKILL, "tkill", &[k::SYS_TASK_KILL as u16]),
    (nr::TGKILL, "tgkill", &[k::SYS_TASK_KILL as u16]),
    (nr::UNAME, "uname", &[]),
    (nr::UMASK, "umask", &[]),
    (nr::GETPID, "getpid", &[]),
    (nr::GETPPID, "getppid", &[]),
    (nr::GETUID, "getuid", &[]),
    (nr::GETEUID, "geteuid", &[]),
    (nr::GETGID, "getgid", &[]),
    (nr::GETEGID, "getegid", &[]),
    (nr::GETTID, "gettid", &[]),
    (nr::BRK, "brk", &[k::SYS_BRK as u16]),
    (nr::MUNMAP, "munmap", &[k::SYS_MUNMAP as u16]),
    (nr::MMAP, "mmap", &[k::SYS_MMAP as u16]),
    // Wave 13: the pages' read and write permissions, exactly; never execute.
    (nr::MPROTECT, "mprotect", &[k::SYS_MMAP as u16]),
    (nr::WAIT4, "wait4", &[k::SYS_WAITPID as u16, k::SYS_WAIT_STATUS as u16]),
    // Fork shape only (stage 3): a copy-on-write child of the same image,
    // reseeded from its row; its inherited descriptors are dup'ed (a file)
    // or given another handle on the same end (a pipe), closed again if the
    // child cannot be set up.
    //
    // Wave 13: or a thread (`CLONE_VM | CLONE_FS | CLONE_FILES |
    // CLONE_SIGHAND | CLONE_THREAD` with a stack), sharing the process's
    // address space, capabilities and descriptors.
    (nr::CLONE, "clone", &[k::SYS_FORK as u16, k::SYS_CLOSE_TYPED as u16, k::SYS_THREAD_CREATE as u16]),
    // Within the caller's own row only (stage 3); its close-on-exec
    // descriptors are closed.
    (nr::EXECVE, "execve", &[k::SYS_EXECPATH as u16, k::SYS_CLOSE_TYPED as u16]),
];

/// The native numbers Linux call `n` may reach, or `None` if the personality
/// does not answer `n` (it gets `-ENOSYS`).
pub fn native_reach(n: u64) -> Option<&'static [u16]> {
    TABLE.iter().find(|e| e.0 == n).map(|e| e.2)
}

/// The Linux number of the call named `name` (`"openat"`), for the
/// derivation in `tests/host/seccomp-tests`.
pub fn number_of(name: &str) -> Option<u64> {
    TABLE.iter().find(|e| e.1 == name).map(|e| e.0)
}

/// Linux errno values (the generic table).
pub mod errno {
    pub const EPERM: i64 = 1;
    pub const ENOENT: i64 = 2;
    pub const ESRCH: i64 = 3;
    pub const EINTR: i64 = 4;
    pub const EIO: i64 = 5;
    pub const EBADF: i64 = 9;
    pub const ECHILD: i64 = 10;
    pub const EAGAIN: i64 = 11;
    pub const ENOMEM: i64 = 12;
    pub const EACCES: i64 = 13;
    pub const EFAULT: i64 = 14;
    pub const EBUSY: i64 = 16;
    pub const EEXIST: i64 = 17;
    pub const ENOTDIR: i64 = 20;
    pub const EISDIR: i64 = 21;
    pub const EINVAL: i64 = 22;
    pub const EMFILE: i64 = 24;
    pub const ENOTTY: i64 = 25;
    pub const ENOSPC: i64 = 28;
    pub const ESPIPE: i64 = 29;
    pub const EROFS: i64 = 30;
    pub const EPIPE: i64 = 32;
    pub const ERANGE: i64 = 34;
    pub const ENAMETOOLONG: i64 = 36;
    pub const ENOSYS: i64 = 38;
    pub const ENOTEMPTY: i64 = 39;
    pub const ETIMEDOUT: i64 = 110;
}

/// A native return value as a Linux one. Non-negative values pass through.
/// The native POSIX-aligned errnos (1..=98) are Linux's own numbers. Native
/// `-1`, the generic failure, becomes `-generic` (the caller picks what the
/// failing call means: `ENOENT` for an open, `EIO` for a read). The
/// capability errnos become what a Linux program can act on: a stale or
/// wrong-kind handle is a bad descriptor, a missing right or a topology
/// refusal is `EACCES`, a safety refusal is `EPERM`.
pub fn errno_from_native(ret: i64, generic: i64) -> i64 {
    use azos_abi::error::Errno as N;
    if ret >= 0 {
        return ret;
    }
    if ret == -1 {
        return -generic;
    }
    let e = -ret;
    if (2..=98).contains(&e) {
        return ret;
    }
    let linux = match e {
        x if x == N::ENOTOWNER as i64 => errno::EPERM,
        x if x == N::ECAPKIND as i64 || x == N::ECAPSTALE as i64 => errno::EBADF,
        x if x == N::ECAPPERMS as i64 || x == N::ETOPOLOGY as i64 => errno::EACCES,
        x if x == N::ESAFETY as i64 => errno::EPERM,
        _ => errno::EIO,
    };
    -linux
}

/// Open flags (`openat`'s `flags`).
pub mod oflag {
    pub const O_ACCMODE: u64 = 0o3;
    pub const O_CREAT: u64 = 0o100;
    pub const O_EXCL: u64 = 0o200;
    pub const O_NOCTTY: u64 = 0o400;
    pub const O_TRUNC: u64 = 0o1000;
    pub const O_APPEND: u64 = 0o2000;
    pub const O_NONBLOCK: u64 = 0o4000;
    pub const O_CLOEXEC: u64 = 0o2000000;
    /// `O_DIRECTORY` differs: 0o200000 on asm-generic (riscv64), 0o40000 on
    /// aarch64 (musl `arch/aarch64/bits/fcntl.h`).
    pub const fn o_directory(arch: super::Arch) -> u64 {
        match arch {
            super::Arch::Riscv64 => 0o200000,
            super::Arch::Aarch64 => 0o40000,
        }
    }
    /// `O_LARGEFILE`: implied on a 64-bit kernel, accepted and ignored.
    pub const fn o_largefile(arch: super::Arch) -> u64 {
        match arch {
            super::Arch::Riscv64 => 0o100000,
            super::Arch::Aarch64 => 0o400000,
        }
    }
    /// `O_NOFOLLOW`: FAT32 has no symbolic links, so it is always honoured.
    pub const fn o_nofollow(arch: super::Arch) -> u64 {
        match arch {
            super::Arch::Riscv64 => 0o400000,
            super::Arch::Aarch64 => 0o100000,
        }
    }
}

/// What an `openat` asks for, in the native vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenReq {
    /// `crates/fs/fs/src/vfs.rs` flags: access mode, `O_CREAT` 0x40,
    /// `O_TRUNC` 0x200, `O_APPEND` 0x400 (the same values as Linux).
    pub native: u64,
    /// `O_DIRECTORY`: only a directory may be opened.
    pub directory: bool,
    /// `O_NONBLOCK` (kept on the descriptor; only pipes honour it).
    pub nonblock: bool,
}

/// Map Linux open flags onto the native ones. `None` for a flag the native
/// open cannot honour (`O_EXCL`, which it would silently ignore, and access
/// mode 3); `-EINVAL` is the caller's answer.
pub fn open_flags(flags: u64, arch: Arch) -> Option<OpenReq> {
    use oflag::*;
    let known = O_ACCMODE | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_APPEND | O_NONBLOCK
        | O_CLOEXEC | o_directory(arch) | o_largefile(arch) | o_nofollow(arch);
    if flags & !known != 0 || flags & O_ACCMODE == 3 || flags & O_EXCL != 0 {
        return None;
    }
    Some(OpenReq {
        native: flags & (O_ACCMODE | O_CREAT | O_TRUNC | O_APPEND),
        directory: flags & o_directory(arch) != 0,
        nonblock: flags & O_NONBLOCK != 0,
    })
}

/// File type bits of `st_mode`.
pub mod mode {
    pub const S_IFIFO: u32 = 0o010000;
    pub const S_IFCHR: u32 = 0o020000;
    pub const S_IFDIR: u32 = 0o040000;
    pub const S_IFREG: u32 = 0o100000;
    pub const S_IFMT: u32 = 0o170000;
}

/// `linux_dirent64::d_type`.
pub const DT_DIR: u8 = 4;
/// `linux_dirent64::d_type`.
pub const DT_REG: u8 = 8;

/// The fields of `struct stat` the personality fills.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub size: i64,
    pub blksize: i32,
    pub blocks: i64,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub rdev: u64,
}

/// `sizeof(struct stat)` on riscv64 and aarch64 (asm-generic layout).
pub const STAT_SIZE: usize = 128;

impl Stat {
    /// The asm-generic `struct stat` (musl `arch/{riscv64,aarch64}/bits/stat.h`):
    /// dev@0 ino@8 mode@16 nlink@20 uid@24 gid@28 rdev@32 size@48 blksize@56
    /// blocks@64 atime@72 mtime@88 ctime@104, nanoseconds after each time.
    pub fn to_bytes(&self) -> [u8; STAT_SIZE] {
        let mut b = [0u8; STAT_SIZE];
        b[0..8].copy_from_slice(&self.dev.to_le_bytes());
        b[8..16].copy_from_slice(&self.ino.to_le_bytes());
        b[16..20].copy_from_slice(&self.mode.to_le_bytes());
        b[20..24].copy_from_slice(&self.nlink.to_le_bytes());
        // uid, gid: 0 (no users on this kernel, POSIX subset rule 3).
        b[32..40].copy_from_slice(&self.rdev.to_le_bytes());
        b[48..56].copy_from_slice(&self.size.to_le_bytes());
        b[56..60].copy_from_slice(&self.blksize.to_le_bytes());
        b[64..72].copy_from_slice(&self.blocks.to_le_bytes());
        b[72..80].copy_from_slice(&self.atime.to_le_bytes());
        b[88..96].copy_from_slice(&self.mtime.to_le_bytes());
        b[104..112].copy_from_slice(&self.ctime.to_le_bytes());
        b
    }
}

/// Write one `linux_dirent64` at the start of `out`: d_ino u64, d_off i64,
/// d_reclen u16, d_type u8, the name and its NUL, padded to 8 bytes. Returns
/// the record length, or `None` if it does not fit.
pub fn encode_dirent64(out: &mut [u8], ino: u64, off: i64, d_type: u8, name: &[u8]) -> Option<usize> {
    let reclen = (19 + name.len() + 1 + 7) & !7;
    if reclen > out.len() || reclen > u16::MAX as usize {
        return None;
    }
    out[..reclen].fill(0);
    out[0..8].copy_from_slice(&ino.to_le_bytes());
    out[8..16].copy_from_slice(&off.to_le_bytes());
    out[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
    out[18] = d_type;
    out[19..19 + name.len()].copy_from_slice(name);
    Some(reclen)
}

/// ioctl requests (asm-generic `ioctls.h`, as musl spells them).
pub mod ioctl {
    pub const TCGETS: u64 = 0x5401;
    pub const TCSETS: u64 = 0x5402;
    pub const TCSETSW: u64 = 0x5403;
    pub const TCSETSF: u64 = 0x5404;
    pub const TIOCGPGRP: u64 = 0x540F;
    pub const TIOCSPGRP: u64 = 0x5410;
    pub const TIOCGWINSZ: u64 = 0x5413;
    pub const TIOCSWINSZ: u64 = 0x5414;
}

/// `struct winsize` for the console: rows, cols, 0, 0. The console has no
/// size probe (RFC-0055: COLUMNS/LINES are 80/24), so this is that answer.
pub fn winsize_bytes(rows: u16, cols: u16) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0..2].copy_from_slice(&rows.to_le_bytes());
    b[2..4].copy_from_slice(&cols.to_le_bytes());
    b
}

/// Size of the kernel `struct termios` `TCGETS` writes (four flag words,
/// `c_line`, `c_cc[19]`). musl's own `struct termios` is larger; the kernel
/// writes only this prefix.
pub const TERMIOS_SIZE: usize = 36;

/// The console's termios as the personality reports it: a cooked terminal
/// in the sense a program can act on (`ICANON | ECHO | ISIG`, `ICRNL`,
/// `OPOST | ONLCR`, `B115200 | CS8 | CREAD`) with the usual control
/// characters. `TCSETS*` is accepted and does not change the console: the
/// native shell owns the line discipline (RFC-0055 5.4).
pub fn termios_bytes() -> [u8; TERMIOS_SIZE] {
    const ICRNL: u32 = 0o400;
    const OPOST: u32 = 0o1;
    const ONLCR: u32 = 0o4;
    const B115200: u32 = 0o010002;
    const CS8: u32 = 0o60;
    const CREAD: u32 = 0o200;
    const ISIG: u32 = 0o1;
    const ICANON: u32 = 0o2;
    const ECHO: u32 = 0o10;
    let mut b = [0u8; TERMIOS_SIZE];
    b[0..4].copy_from_slice(&ICRNL.to_le_bytes());
    b[4..8].copy_from_slice(&(OPOST | ONLCR).to_le_bytes());
    b[8..12].copy_from_slice(&(B115200 | CS8 | CREAD).to_le_bytes());
    b[12..16].copy_from_slice(&(ISIG | ICANON | ECHO).to_le_bytes());
    // c_line = 0; c_cc: VINTR ^C, VQUIT ^\, VERASE DEL, VKILL ^U, VEOF ^D,
    // VTIME 0, VMIN 1.
    let cc = &mut b[17..36];
    cc[0] = 3;
    cc[1] = 0x1c;
    cc[2] = 0x7f;
    cc[3] = 0x15;
    cc[4] = 4;
    cc[5] = 0;
    cc[6] = 1;
    b
}

/// `sizeof(struct utsname)`: six 65-byte fields.
pub const UTSNAME_SIZE: usize = 390;

/// `struct utsname`: sysname, nodename, release, version, machine,
/// domainname. `release` is a Linux-shaped version string because musl and
/// BusyBox parse it; it names this personality, not a Linux kernel.
pub fn utsname_bytes(arch: Arch, nodename: &[u8]) -> [u8; UTSNAME_SIZE] {
    let mut b = [0u8; UTSNAME_SIZE];
    let mut put = |field: usize, s: &[u8]| {
        let n = s.len().min(64);
        b[field * 65..field * 65 + n].copy_from_slice(&s[..n]);
    };
    put(0, b"Linux");
    put(1, nodename);
    put(2, b"6.1.0-azos-personality");
    put(3, b"#1 AzOS RFC-0047");
    put(4, match arch {
        Arch::Riscv64 => b"riscv64".as_slice(),
        Arch::Aarch64 => b"aarch64".as_slice(),
    });
    put(5, b"(none)");
    b
}

/// Signal delivery's frames, default actions and the console line
/// discipline (wave 13).
pub mod signal;

/// The robust futex list walked at a thread's exit (wave 15).
pub mod robust;

/// `readv`/`writev` as one transfer each: the iovec walk (wave 15, K2).
pub mod iov;

/// Signal numbers and `rt_sigprocmask` operations (RFC-0047 P3: signals
/// live inside the Linux compartment).
pub mod sig {
    pub const SIGINT: u64 = 2;
    pub const SIGKILL: u64 = 9;
    pub const SIGPIPE: u64 = 13;
    pub const SIGTERM: u64 = 15;
    pub const SIGCHLD: u64 = 17;
    pub const SIGSTOP: u64 = 19;
    /// Highest signal number (`_NSIG - 1`).
    pub const NSIG_MAX: u64 = 64;
    pub const SIG_BLOCK: u64 = 0;
    pub const SIG_UNBLOCK: u64 = 1;
    pub const SIG_SETMASK: u64 = 2;
    /// `SIG_DFL` / `SIG_IGN` as handler values.
    pub const SIG_DFL: u64 = 0;
    pub const SIG_IGN: u64 = 1;
}

/// The kernel `struct sigaction` `rt_sigaction` reads and writes: handler,
/// flags, (restorer on aarch64, which defines `SA_RESTORER`; riscv64 does
/// not), and a 64-bit mask.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KSigaction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

impl KSigaction {
    /// Bytes of the structure on `arch`.
    pub const fn size(arch: Arch) -> usize {
        match arch {
            Arch::Riscv64 => 24,
            Arch::Aarch64 => 32,
        }
    }

    pub fn to_bytes(&self, arch: Arch) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&self.handler.to_le_bytes());
        b[8..16].copy_from_slice(&self.flags.to_le_bytes());
        match arch {
            Arch::Riscv64 => b[16..24].copy_from_slice(&self.mask.to_le_bytes()),
            Arch::Aarch64 => {
                b[16..24].copy_from_slice(&self.restorer.to_le_bytes());
                b[24..32].copy_from_slice(&self.mask.to_le_bytes());
            }
        }
        b
    }

    pub fn from_bytes(b: &[u8], arch: Arch) -> Option<Self> {
        if b.len() < Self::size(arch) {
            return None;
        }
        let u = |at: usize| {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[at..at + 8]);
            u64::from_le_bytes(w)
        };
        Some(match arch {
            Arch::Riscv64 => Self { handler: u(0), flags: u(8), restorer: 0, mask: u(16) },
            Arch::Aarch64 => Self { handler: u(0), flags: u(8), restorer: u(16), mask: u(24) },
        })
    }
}

/// The Linux wait status of a child that ended with native exit code `code`:
/// a normal exit with the low 8 bits (`WIFEXITED`, `WEXITSTATUS`). A child a
/// signal ended is reported by [`wait_status_signalled`] instead (wave 13).
pub const fn wait_status(code: i32) -> i32 {
    (code & 0xff) << 8
}

/// The Linux wait status of a child killed by signal `sig` (wave 13):
/// `WIFSIGNALED`, `WTERMSIG` = `sig`, no core dump.
pub const fn wait_status_signalled(sig: u32) -> i32 {
    (sig & 0x7f) as i32
}

/// Clock ids `clock_gettime` answers.
pub mod clock {
    pub const REALTIME: u64 = 0;
    pub const MONOTONIC: u64 = 1;
    pub const MONOTONIC_RAW: u64 = 4;
    pub const REALTIME_COARSE: u64 = 5;
    pub const MONOTONIC_COARSE: u64 = 6;
    pub const BOOTTIME: u64 = 7;
}

/// `struct timespec` as 16 bytes.
pub fn timespec_bytes(ns: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&((ns / 1_000_000_000) as i64).to_le_bytes());
    b[8..16].copy_from_slice(&((ns % 1_000_000_000) as i64).to_le_bytes());
    b
}

/// A `struct timespec` read back as nanoseconds; `None` if `tv_nsec` is out
/// of range or a field is negative (`-EINVAL`).
pub fn timespec_ns(b: &[u8; 16]) -> Option<u64> {
    let mut s = [0u8; 8];
    s.copy_from_slice(&b[0..8]);
    let sec = i64::from_le_bytes(s);
    s.copy_from_slice(&b[8..16]);
    let nsec = i64::from_le_bytes(s);
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return None;
    }
    Some((sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64))
}

/// Auxiliary-vector keys the initial stack carries.
pub mod at {
    pub const NULL: u64 = 0;
    pub const PHDR: u64 = 3;
    pub const PHENT: u64 = 4;
    pub const PHNUM: u64 = 5;
    pub const PAGESZ: u64 = 6;
    pub const BASE: u64 = 7;
    pub const FLAGS: u64 = 8;
    pub const ENTRY: u64 = 9;
    pub const UID: u64 = 11;
    pub const EUID: u64 = 12;
    pub const GID: u64 = 13;
    pub const EGID: u64 = 14;
    pub const HWCAP: u64 = 16;
    pub const CLKTCK: u64 = 17;
    pub const SECURE: u64 = 23;
    pub const RANDOM: u64 = 25;
    pub const EXECFN: u64 = 31;
}

/// What the image loader learned that the auxiliary vector reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImageAux {
    /// User address of the program headers, or 0 when no `PT_LOAD` maps them
    /// (then `AT_PHDR` is left out rather than pointing at unmapped memory).
    pub phdr: u64,
    pub phent: u64,
    pub phnum: u64,
    pub entry: u64,
    pub pagesz: u64,
}

/// Find where the program headers of `elf` land in the image: the address
/// inside the first `PT_LOAD` whose file range holds them, or 0 if none does. Also returns `e_phentsize`, `e_phnum` and
/// `e_entry`. `None` for a malformed header.
pub fn image_aux(elf: &[u8], pagesz: u64) -> Option<ImageAux> {
    if elf.len() < 64 || &elf[0..4] != b"\x7fELF" || elf[4] != 2 || elf[5] != 1 {
        return None;
    }
    let r16 = |at: usize| u16::from_le_bytes([elf[at], elf[at + 1]]) as u64;
    let r32 = |at: usize| u32::from_le_bytes([elf[at], elf[at + 1], elf[at + 2], elf[at + 3]]) as u64;
    let r64 = |at: usize| r32(at) | (r32(at + 4) << 32);
    let entry = r64(24);
    let phoff = r64(32);
    let phent = r16(54);
    let phnum = r16(56);
    if phent < 56 || phnum == 0 {
        return None;
    }
    let table_end = phoff.checked_add(phent.checked_mul(phnum)?)?;
    if table_end > elf.len() as u64 {
        return None;
    }
    let mut from_load = 0u64;
    for i in 0..phnum {
        let at = (phoff + i * phent) as usize;
        let p_type = r32(at);
        let p_offset = r64(at + 8);
        let p_vaddr = r64(at + 16);
        let p_filesz = r64(at + 32);
        const PT_LOAD: u64 = 1;
        if p_type == PT_LOAD
            && from_load == 0
            && p_offset <= phoff
            && table_end <= p_offset.saturating_add(p_filesz)
        {
            from_load = p_vaddr + (phoff - p_offset);
        }
    }
    // Taken from the covering `PT_LOAD`, not from `PT_PHDR`: a `PT_PHDR` no
    // `PT_LOAD` covers would name unmapped memory, and when one does cover
    // it the two addresses are the same.
    Some(ImageAux { phdr: from_load, phent, phnum, entry, pagesz })
}

/// Most argv and environment strings the initial stack carries (the
/// `SYS_SPAWN_EX` limits).
pub const STACK_STRINGS_MAX: usize = 32;

/// Lay out the initial stack a static Linux binary's `_start` reads, in
/// `out`, which is mapped at user addresses `[base, base + out.len())`; the
/// stack grows down from `base + out.len()`.
///
/// From the top: the argv strings, the environment strings, 16 random bytes
/// (`AT_RANDOM`), then, 16-byte aligned, `argc`, the argv pointers and a
/// NULL, the envp pointers and a NULL, and the auxiliary vector ending in
/// `AT_NULL`. Returns the stack pointer (the address of `argc`), or `None`
/// if it does not fit, a blob is not `argc`/`envc` NUL-terminated strings,
/// or `base` is not 16-byte aligned.
#[allow(clippy::too_many_arguments)]
pub fn layout_initial_stack(
    out: &mut [u8],
    base: u64,
    argv: &[u8],
    argc: usize,
    env: &[u8],
    envc: usize,
    random: &[u8; 16],
    aux: &ImageAux,
) -> Option<u64> {
    if base % 16 != 0 || argc > STACK_STRINGS_MAX || envc > STACK_STRINGS_MAX {
        return None;
    }
    let count = |blob: &[u8]| -> Option<usize> {
        if blob.is_empty() {
            return Some(0);
        }
        if *blob.last()? != 0 {
            return None;
        }
        Some(blob.iter().filter(|&&b| b == 0).count())
    };
    if count(argv)? != argc || count(env)? != envc {
        return None;
    }
    let top = out.len();
    // Strings, then the random bytes, at the top.
    let argv_at = top.checked_sub(argv.len() + env.len())?;
    let env_at = argv_at + argv.len();
    let random_at = (argv_at.checked_sub(16)?) & !15;
    // The pointer block: argc, argv[], NULL, envp[], NULL, auxv pairs.
    let mut auxv: [(u64, u64); 18] = [(0, 0); 18];
    let mut na = 0usize;
    let mut push = |k: u64, v: u64| {
        auxv[na] = (k, v);
        na += 1;
    };
    if aux.phdr != 0 {
        push(at::PHDR, aux.phdr);
    }
    push(at::PHENT, aux.phent);
    push(at::PHNUM, aux.phnum);
    push(at::PAGESZ, aux.pagesz);
    push(at::BASE, 0);
    push(at::FLAGS, 0);
    push(at::ENTRY, aux.entry);
    push(at::UID, 0);
    push(at::EUID, 0);
    push(at::GID, 0);
    push(at::EGID, 0);
    push(at::HWCAP, 0);
    push(at::CLKTCK, 100);
    push(at::SECURE, 0);
    push(at::RANDOM, base + random_at as u64);
    if argc > 0 {
        push(at::EXECFN, base + argv_at as u64);
    }
    push(at::NULL, 0);
    let words = 1 + argc + 1 + envc + 1 + 2 * na;
    let block = words * 8;
    let sp_at = (random_at.checked_sub(block)?) & !15;

    out.fill(0);
    out[argv_at..argv_at + argv.len()].copy_from_slice(argv);
    out[env_at..env_at + env.len()].copy_from_slice(env);
    out[random_at..random_at + 16].copy_from_slice(random);
    let mut w = sp_at;
    let mut put = |out: &mut [u8], v: u64| {
        out[w..w + 8].copy_from_slice(&v.to_le_bytes());
        w += 8;
    };
    put(out, argc as u64);
    let mut s = argv_at;
    for _ in 0..argc {
        put(out, base + s as u64);
        s += out[s..].iter().position(|&b| b == 0)? + 1;
    }
    put(out, 0);
    let mut s = env_at;
    for _ in 0..envc {
        put(out, base + s as u64);
        s += out[s..].iter().position(|&b| b == 0)? + 1;
    }
    put(out, 0);
    for &(k, v) in &auxv[..na] {
        put(out, k);
        put(out, v);
    }
    Some(base + sp_at as u64)
}

/// `clone` flags the personality looks at.
pub mod clone {
    /// The exit signal in the low byte.
    pub const CSIGNAL: u64 = 0xff;
    pub const CLONE_VM: u64 = 0x100;
    pub const CLONE_FS: u64 = 0x200;
    pub const CLONE_FILES: u64 = 0x400;
    pub const CLONE_SIGHAND: u64 = 0x800;
    pub const CLONE_VFORK: u64 = 0x4000;
    pub const CLONE_THREAD: u64 = 0x10000;
    pub const CLONE_SYSVSEM: u64 = 0x40000;
    pub const CLONE_SETTLS: u64 = 0x80000;
    pub const CLONE_PARENT_SETTID: u64 = 0x100000;
    pub const CLONE_CHILD_CLEARTID: u64 = 0x200000;
    pub const CLONE_DETACHED: u64 = 0x400000;
    pub const CLONE_CHILD_SETTID: u64 = 0x1000000;
}

/// `futex` operations (wave 13).
pub mod futex {
    pub const FUTEX_WAIT: u64 = 0;
    pub const FUTEX_WAKE: u64 = 1;
    pub const FUTEX_REQUEUE: u64 = 3;
    pub const FUTEX_CMP_REQUEUE: u64 = 4;
    pub const FUTEX_WAIT_BITSET: u64 = 9;
    pub const FUTEX_WAKE_BITSET: u64 = 10;
    pub const FUTEX_PRIVATE_FLAG: u64 = 128;
    pub const FUTEX_CLOCK_REALTIME: u64 = 256;
    pub const FUTEX_BITSET_MATCH_ANY: u64 = 0xffff_ffff;
}

/// `fcntl` commands.
pub mod fcntl {
    pub const F_DUPFD: u64 = 0;
    pub const F_GETFD: u64 = 1;
    pub const F_SETFD: u64 = 2;
    pub const F_GETFL: u64 = 3;
    pub const F_SETFL: u64 = 4;
    pub const F_DUPFD_CLOEXEC: u64 = 1030;
    pub const FD_CLOEXEC: u64 = 1;
}

/// `AT_FDCWD` as the 64-bit register value.
pub const AT_FDCWD: u64 = (-100i64) as u64;
/// `newfstatat` flag: operate on `dirfd` itself when the path is empty.
pub const AT_EMPTY_PATH: u64 = 0x1000;
/// `newfstatat` flag: do not follow a final symbolic link (always true here).
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;

/// mmap constants.
pub mod mman {
    pub const PROT_READ: u64 = 1;
    pub const PROT_WRITE: u64 = 2;
    pub const PROT_EXEC: u64 = 4;
    pub const MAP_SHARED: u64 = 1;
    pub const MAP_PRIVATE: u64 = 2;
    pub const MAP_FIXED: u64 = 0x10;
    pub const MAP_ANONYMOUS: u64 = 0x20;
    pub const MAP_LOCKED: u64 = 0x2000;
    pub const MAP_POPULATE: u64 = 0x8000;
}

/// Join `path` onto the working directory `cwd` (absolute, no trailing `/`
/// except for `/` itself) into `out`, resolving `.` and `..` lexically.
/// FAT32 has no symbolic links, so lexical resolution is exact. Returns the
/// length, or `None` if the result does not fit or `path` is empty.
pub fn join_path(cwd: &[u8], path: &[u8], out: &mut [u8]) -> Option<usize> {
    if path.is_empty() {
        return None;
    }
    let mut n = 0usize;
    let push_comp = |out: &mut [u8], n: &mut usize, comp: &[u8]| -> Option<()> {
        if comp.is_empty() || comp == b"." {
            return Some(());
        }
        if comp == b".." {
            while *n > 0 && out[*n - 1] != b'/' {
                *n -= 1;
            }
            if *n > 0 {
                *n -= 1;
            }
            return Some(());
        }
        if *n + 1 + comp.len() > out.len() {
            return None;
        }
        out[*n] = b'/';
        out[*n + 1..*n + 1 + comp.len()].copy_from_slice(comp);
        *n += 1 + comp.len();
        Some(())
    };
    if path[0] != b'/' {
        for comp in cwd.split(|&b| b == b'/') {
            push_comp(out, &mut n, comp)?;
        }
    }
    for comp in path.split(|&b| b == b'/') {
        push_comp(out, &mut n, comp)?;
    }
    if n == 0 {
        if out.is_empty() {
            return None;
        }
        out[0] = b'/';
        n = 1;
    }
    Some(n)
}
