// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Linux personality's pure half.
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
//!   Linux's uapi headers.
//! - [`x86_64`]: the ring-3 runtime's x86-64 face: Linux's x86-64 call
//!   numbers and argument registers, translated to the asm-generic calls the
//!   runtime answers, and the result layouts that differ.
//! - [`native_reach`]: the NATIVE numbers a Linux call may reach once
//!   translated. Seccomp runs after translation (P5), so a Linux image's
//!   profile lists these; `tests/host/seccomp-tests` derives the profile of a
//!   Linux image from its source through this table.
//! - [`errno_from_native`], the open-flag map, and the wire layouts the
//!   translation writes: `struct stat`, `linux_dirent64`, `struct winsize`,
//!   the kernel `struct termios` and `struct utsname`. The initial stack a
//!   static binary's `_start` reads is `azos_image`'s, re-exported here.
#![no_std]
#![forbid(unsafe_code)]


/// The ISA a layout is for. The asm-generic syscall table is shared, but a
/// few layouts and flag values are not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    Riscv64,
    Aarch64,
}

impl Arch {
    /// The asm-generic layouts of the ISA this crate is compiled for: `None`
    /// on x86_64, whose Linux ABI is not the asm-generic one (only the ring-3
    /// runtime's [`x86_64`] face speaks it), so the in-kernel table cannot
    /// translate for it. riscv64 on the host, where the host tests pass the
    /// ISA explicitly anyway.
    pub const fn native() -> Option<Self> {
        Self::of_target(
            cfg!(any(target_os = "none", target_os = "azos")),
            cfg!(target_arch = "riscv64"),
            cfg!(target_arch = "aarch64"),
        )
    }

    /// [`Self::native`] for a target described by its cfgs: `bare_metal`
    /// (`target_os = "none"` for the kernel, `"azos"` for a ring-3 image), and
    /// whether it is riscv64 or aarch64.
    pub const fn of_target(bare_metal: bool, riscv64: bool, aarch64: bool) -> Option<Self> {
        if !bare_metal {
            Some(Arch::Riscv64)
        } else if aarch64 {
            Some(Arch::Aarch64)
        } else if riscv64 || cfg!(feature = "x86-in-kernel-table-canary") {
            Some(Arch::Riscv64)
        } else {
            None
        }
    }
}

/// Whether this kernel can run a Linux task: it has the personality (Kconfig
/// `LINUX_ABI`), and the task is hosted by the ring-3 runtime (`runtime`,
/// Kconfig `LINUX_RUNTIME`) or translated by the in-kernel table, which needs
/// the ISA's asm-generic layouts (`native`, [`Arch::native`]). A spawn of a
/// Linux row is refused otherwise, never translated with another ISA's.
pub const fn linux_task_runs(abi: bool, runtime: bool, native: Option<Arch>) -> bool {
    abi && (runtime || native.is_some())
}

mod table;
pub use table::{native_reach, nr, number_of, Class, Syscall, TABLE};
pub mod tally;

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
    pub const EDEADLK: i64 = 35;
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
    /// `crates/fs/src/vfs.rs` flags: access mode, `O_CREAT` 0x40,
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

/// A size a filesystem answered, as `st_size`: saturating, so a ring-3
/// filesystem server's huge value cannot overflow the arithmetic after it.
///
/// Canary `stat-size-wrap-canary`: the plain cast and the unchecked sum.
pub fn size_word(size: u64) -> i64 {
    if cfg!(feature = "stat-size-wrap-canary") {
        return size as i64;
    }
    i64::try_from(size).unwrap_or(i64::MAX)
}

/// `st_blocks`: the 512-byte blocks of `size`, rounded up; never negative and
/// never an overflow.
pub fn blocks_512(size: i64) -> i64 {
    if cfg!(feature = "stat-size-wrap-canary") {
        return (size + 511) / 512;
    }
    size.max(0).saturating_add(511) / 512
}

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
/// size probe (the shell takes COLUMNS/LINES as 80/24), so this is that answer.
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
/// native shell owns the line discipline.
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

/// A thread's CPU set as `sched_getaffinity` writes it, bit `n` of word
/// `n / 64` = CPU `n`: its pin (`-1` = none), or every CPU the scheduler
/// places work on (`online` is the prefix it walks). Bits past the mask
/// (`WORDS * 64`) are dropped.
pub fn cpu_set<const WORDS: usize>(pin: i8, online: usize) -> [u64; WORDS] {
    let mut set = [0u64; WORDS];
    let cpus = match usize::try_from(pin) {
        Ok(p) => p..p + 1,
        Err(_) => 0..online,
    };
    for c in cpus.filter(|&c| c < WORDS * 64) {
        set[c / 64] |= 1 << (c % 64);
    }
    set
}

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
    put(3, b"#1 AzOS");
    put(4, match arch {
        Arch::Riscv64 => b"riscv64".as_slice(),
        Arch::Aarch64 => b"aarch64".as_slice(),
    });
    put(5, b"(none)");
    b
}

/// Signal delivery's frames, default actions and the console line
/// discipline.
pub mod signal;

/// The robust futex list walked at a thread's exit.
pub mod robust;

/// `readv`/`writev` as one transfer each: the iovec walk.
pub mod iov;

/// The x86-64 face of the ring-3 runtime: its call numbers, argument
/// registers and the result layouts that differ from the asm-generic ones.
pub mod x86_64;

/// Signal numbers and `rt_sigprocmask` operations (signals
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
/// signal ended is reported by [`wait_status_signalled`] instead.
pub const fn wait_status(code: i32) -> i32 {
    (code & 0xff) << 8
}

/// The Linux wait status of a child killed by signal `sig`:
/// `WIFSIGNALED`, `WTERMSIG` = `sig`, no core dump.
pub const fn wait_status_signalled(sig: u32) -> i32 {
    (sig & 0x7f) as i32
}

/// Clock ids `clock_gettime` answers (`CLOCK_REALTIME` 0, `CLOCK_MONOTONIC` 1,
/// `CLOCK_MONOTONIC_RAW` 4, the two `_COARSE` ones, `CLOCK_BOOTTIME` 7 and
/// `CLOCK_TAI` 11). They are the POSIX numbers the C library shares, so the
/// table lives in the native ABI, with the native clock each one is read on:
/// `azos_abi::time::ClockId::from_posix`.
pub use azos_abi::time::posix_clock as clock;

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

/// `poll` / `ppoll`: `struct pollfd` and the event bits (asm-generic and
/// x86-64 alike).
pub mod poll {
    pub const POLLIN: u16 = 0x001;
    pub const POLLOUT: u16 = 0x004;
    pub const POLLERR: u16 = 0x008;
    pub const POLLHUP: u16 = 0x010;
    pub const POLLNVAL: u16 = 0x020;
    /// Bytes of one `struct pollfd`: `int fd; short events; short revents`.
    pub const POLLFD_BYTES: usize = 8;
    /// The most descriptors one call may name (Linux's `RLIMIT_NOFILE` bound,
    /// here a fixed one).
    pub const NFDS_MAX: u64 = 1024;
    /// `(fd, events)` of the record `b`.
    pub fn parse(b: &[u8; POLLFD_BYTES]) -> (i32, u16) {
        (i32::from_le_bytes([b[0], b[1], b[2], b[3]]), u16::from_le_bytes([b[4], b[5]]))
    }
}

// The image facts and the initial stack are the loader's, for every image:
// they live in `azos_image`, re-exported here for the personality's callers.
pub use azos_image::{at, image_aux, layout_initial_stack, ImageAux, STACK_STRINGS_MAX};

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

/// `futex` operations.
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
    /// Priority-inheritance operations (Kconfig `FUTEX_PI`).
    pub const FUTEX_LOCK_PI: u64 = 6;
    pub const FUTEX_UNLOCK_PI: u64 = 7;
    pub const FUTEX_TRYLOCK_PI: u64 = 8;
    pub const FUTEX_WAIT_REQUEUE_PI: u64 = 11;
    pub const FUTEX_CMP_REQUEUE_PI: u64 = 12;
    /// As `FUTEX_LOCK_PI`, its timeout on `CLOCK_MONOTONIC` unless
    /// `FUTEX_CLOCK_REALTIME` is given.
    pub const FUTEX_LOCK_PI2: u64 = 13;
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
    pub const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;

    /// The `flags` an anonymous private `mmap` passes to the native call, or
    /// `-EINVAL` for what the personality refuses before asking: plain
    /// `MAP_FIXED`, an executable mapping (W^X) and an empty one. The hint
    /// travels in its own argument; of the flags, the pre-commit bits and
    /// `MAP_FIXED_NOREPLACE` (the native bit has Linux's value) do.
    ///
    /// `MAP_FIXED` replaces whatever the range holds. Answering it would let a
    /// stray or hostile address unmap the program's own stack, its heap, the
    /// vDSO or the runtime's pages without a word, and nothing a Linux program
    /// of this tree needs asks for it: refused, loudly. `MAP_FIXED_NOREPLACE`
    /// (alone or with `MAP_FIXED`, which it then overrides, as on Linux) is the
    /// exact placement that cannot clobber: the address or `-EEXIST`.
    pub fn anon_map_flags(len: u64, prot: u64, flags: u64) -> Result<u64, i64> {
        let fixed = flags & MAP_FIXED != 0 && flags & MAP_FIXED_NOREPLACE == 0;
        if fixed || prot & PROT_EXEC != 0 || len == 0 {
            return Err(-crate::errno::EINVAL);
        }
        Ok(flags & (MAP_POPULATE | MAP_LOCKED | MAP_FIXED_NOREPLACE))
    }

    /// The `flags` a file-backed `mmap` passes to the kernel's `NODE_MMAP`, or
    /// `-EINVAL` for what the personality refuses before asking: `MAP_FIXED`
    /// and `MAP_FIXED_NOREPLACE` (the kernel places a file mapping), an
    /// executable mapping (W^X) and an empty one. Only `MAP_SHARED` and
    /// `MAP_PRIVATE` travel; the kernel requires exactly one of them.
    pub fn file_map_flags(len: u64, prot: u64, flags: u64) -> Result<u64, i64> {
        if flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0 || prot & PROT_EXEC != 0 || len == 0 {
            return Err(-crate::errno::EINVAL);
        }
        Ok(flags & (MAP_SHARED | MAP_PRIVATE))
    }
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
