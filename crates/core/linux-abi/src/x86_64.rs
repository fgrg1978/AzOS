// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The x86-64 face of the Linux personality, for the ring-3 runtime
//! (`userspace/lib/linux_rt`, hosted by `userspace/services/lxrt`).
//!
//! Linux's x86-64 ABI is not the asm-generic one the rest of this crate
//! holds: its own call numbers (and the older calls the generic table dropped:
//! `open`, `stat`, `pipe`, `dup2`, `fork`, `vfork`), its own argument
//! registers (`rdi rsi rdx r10 r8 r9`, the number and the result in `rax`),
//! `clone`'s last two arguments swapped, a 144-byte `struct stat` with other
//! field offsets, and its own `uname` machine name. The runtime answers one
//! set of calls whatever the ISA, in the asm-generic numbering of [`crate::nr`];
//! this module is the translation from a trapped x86-64 call to that
//! numbering, with the few result layouts that differ. It is pure (no kernel
//! state, no memory access), so `tests/host/linux-abi-tests` checks it on the
//! host.
//!
//! Only the calls the runtime answers are translated. Anything else (`lseek`,
//! `mprotect`, ...) is [`translate`]'s `None`, and the runtime answers it
//! `-ENOSYS` under its x86-64 number, reported once. `arch_prctl` has no
//! asm-generic counterpart: it is translated to itself ([`Post::ArchPrctl`])
//! and answered by the runtime, which installs a new FS base the one way ring
//! 3 can have one (a thread started with it, `SYS_THREAD_CREATE`'s tls). The
//! runtime keeps no signal frame: `rt_sigaction` is state only, as on the
//! other ISAs.
//!
//! Numbers and layouts are taken from musl (MIT: `arch/x86_64/bits/syscall.h.in`,
//! `arch/x86_64/bits/stat.h`), not from Linux's uapi headers.

use crate::{Arch, STAT_SIZE, UTSNAME_SIZE};

/// The x86-64 Linux call numbers the runtime answers, and the ones its
/// translation needs to name.
pub mod nr {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const OPEN: u64 = 2;
    pub const CLOSE: u64 = 3;
    pub const STAT: u64 = 4;
    pub const FSTAT: u64 = 5;
    pub const LSTAT: u64 = 6;
    pub const POLL: u64 = 7;
    pub const MMAP: u64 = 9;
    pub const MUNMAP: u64 = 11;
    pub const BRK: u64 = 12;
    pub const RT_SIGACTION: u64 = 13;
    pub const RT_SIGPROCMASK: u64 = 14;
    pub const IOCTL: u64 = 16;
    pub const READV: u64 = 19;
    pub const WRITEV: u64 = 20;
    pub const PIPE: u64 = 22;
    pub const SCHED_YIELD: u64 = 24;
    pub const DUP: u64 = 32;
    pub const DUP2: u64 = 33;
    pub const NANOSLEEP: u64 = 35;
    pub const GETPID: u64 = 39;
    pub const CLONE: u64 = 56;
    pub const FORK: u64 = 57;
    pub const VFORK: u64 = 58;
    pub const EXIT: u64 = 60;
    pub const WAIT4: u64 = 61;
    pub const UNAME: u64 = 63;
    pub const FCNTL: u64 = 72;
    pub const GETCWD: u64 = 79;
    pub const CHDIR: u64 = 80;
    pub const UMASK: u64 = 95;
    pub const GETUID: u64 = 102;
    pub const GETGID: u64 = 104;
    pub const GETEUID: u64 = 107;
    pub const GETEGID: u64 = 108;
    pub const GETPPID: u64 = 110;
    pub const RT_SIGPENDING: u64 = 127;
    pub const SIGALTSTACK: u64 = 131;
    pub const PRCTL: u64 = 157;
    pub const GETTID: u64 = 186;
    pub const SCHED_GETAFFINITY: u64 = 204;
    pub const GETDENTS64: u64 = 217;
    pub const SET_TID_ADDRESS: u64 = 218;
    pub const CLOCK_GETTIME: u64 = 228;
    pub const EXIT_GROUP: u64 = 231;
    pub const OPENAT: u64 = 257;
    pub const NEWFSTATAT: u64 = 262;
    pub const PPOLL: u64 = 271;
    pub const DUP3: u64 = 292;
    pub const PIPE2: u64 = 293;
    /// Not answered (the runtime has no seek): named so the test can say so.
    pub const LSEEK: u64 = 8;
    /// The thread pointer (the FS base): [`super::arch_prctl`].
    pub const ARCH_PRCTL: u64 = 158;
}

/// `arch_prctl`'s codes (Linux `arch/x86/include/uapi/asm/prctl.h`):
/// the two the runtime answers. musl's static start sets its TLS with
/// [`SET_FS`] before anything else, so without it no musl program runs.
pub mod arch_prctl {
    /// Set the FS base (the thread pointer) to the second argument.
    pub const SET_FS: u64 = 0x1002;
    /// Store the FS base at the address in the second argument.
    pub const GET_FS: u64 = 0x1003;
    /// The first FS base `SET_FS` refuses (`-EPERM`): the canonical lower
    /// half under 4-level paging, which a `wrmsr` of `IA32_FS_BASE` accepts
    /// in the kernel (`azos_arch`'s `is_user_tls_base`).
    pub const FS_LIMIT: u64 = 1 << 47;
}

/// Index in `azos_abi::foreign::ForeignFrame::gpr` of the register that
/// carries the call number and takes the result: `rax`.
pub const REG_NUMBER: usize = 0;
/// Index of the result register (`rax`).
pub const REG_RESULT: usize = 0;
/// Indices of the six argument registers, in order: `rdi rsi rdx r10 r8 r9`
/// (the hardware encoding order `azos_abi::foreign` documents for x86_64:
/// `rax rcx rdx rbx rsp rbp rsi rdi r8..r15`).
pub const REG_ARGS: [usize; 6] = [7, 6, 2, 10, 8, 9];

// The numbers above are the ones `azos_abi::foreign` names for x86_64.
const _: () = {
    if cfg!(target_arch = "x86_64") {
        assert!(azos_abi::foreign::REG_NUMBER == REG_NUMBER);
        assert!(azos_abi::foreign::REG_RESULT == REG_RESULT);
        assert!(azos_abi::foreign::REG_FIRST_ARG == REG_ARGS[0]);
    }
};

/// What the runtime must do besides running the translated call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Post {
    /// Nothing: the result is the call's.
    None,
    /// The call wrote an asm-generic 128-byte `struct stat` at this address
    /// (on success): rewrite it as [`STAT_SIZE_X86_64`] bytes of x86-64 layout.
    Stat(u64),
    /// `dup2(fd, fd)`: no copy, the answer is `fd` if it is open (the call
    /// checks that with `fcntl(F_GETFD)`), else the call's error.
    DupSame(u64),
    /// `uname`: the buffer at this address gets the x86-64 machine name.
    Uname(u64),
    /// `rt_sigaction`: the kernel `struct sigaction` is `{handler, flags,
    /// restorer, mask}`, the layout `Arch::Aarch64` has.
    Sigaction,
    /// `poll(fds, nfds, timeout)`, which `ppoll` replaced in the generic table:
    /// the call is a `ppoll` with no timeout argument, and this is the
    /// timeout in milliseconds, an `int` (negative: wait without bound).
    PollMs(u32),
    /// `arch_prctl(code, addr)`, which has no asm-generic number: the
    /// runtime answers it itself ([`arch_prctl`]).
    ArchPrctl,
}

/// A trapped x86-64 call, in the runtime's asm-generic terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Call {
    /// The asm-generic number ([`crate::nr`]) the runtime dispatches on.
    pub num: u64,
    /// Its arguments, in the asm-generic order.
    pub args: [u64; 6],
    pub post: Post,
}

/// `F_GETFD` of `fcntl`.
const F_GETFD: u64 = 1;
/// The signal a `fork` child's exit sends its parent.
const SIGCHLD: u64 = crate::sig::SIGCHLD;

/// Translate x86-64 call `num` with arguments `a` (in [`REG_ARGS`] order) to
/// the asm-generic call the runtime answers, or `None` for a call it does not
/// answer.
pub fn translate(num: u64, a: [u64; 6]) -> Option<Call> {
    use crate::nr as g;
    let c = |num: u64, args: [u64; 6], post: Post| Some(Call { num, args, post });
    let same = |num: u64| Some(Call { num, args: a, post: Post::None });
    match num {
        nr::READ => same(g::READ),
        nr::WRITE => same(g::WRITE),
        nr::READV => same(g::READV),
        nr::WRITEV => same(g::WRITEV),
        nr::CLOSE => same(g::CLOSE),
        nr::MMAP => same(g::MMAP),
        nr::MUNMAP => same(g::MUNMAP),
        nr::BRK => same(g::BRK),
        nr::RT_SIGPROCMASK => same(g::RT_SIGPROCMASK),
        nr::RT_SIGPENDING => same(g::RT_SIGPENDING),
        nr::SIGALTSTACK => same(g::SIGALTSTACK),
        nr::IOCTL => same(g::IOCTL),
        nr::SCHED_YIELD => same(g::SCHED_YIELD),
        nr::DUP => same(g::DUP),
        nr::DUP3 => same(g::DUP3),
        nr::NANOSLEEP => same(g::NANOSLEEP),
        nr::GETPID => same(g::GETPID),
        nr::GETTID => same(g::GETTID),
        nr::GETPPID => same(g::GETPPID),
        nr::GETUID => same(g::GETUID),
        nr::GETEUID => same(g::GETEUID),
        nr::GETGID => same(g::GETGID),
        nr::GETEGID => same(g::GETEGID),
        nr::SET_TID_ADDRESS => same(g::SET_TID_ADDRESS),
        nr::EXIT => same(g::EXIT),
        nr::EXIT_GROUP => same(g::EXIT_GROUP),
        nr::WAIT4 => same(g::WAIT4),
        nr::FCNTL => same(g::FCNTL),
        nr::GETCWD => same(g::GETCWD),
        nr::CHDIR => same(g::CHDIR),
        nr::UMASK => same(g::UMASK),
        nr::PRCTL => same(g::PRCTL),
        nr::SCHED_GETAFFINITY => same(g::SCHED_GETAFFINITY),
        nr::GETDENTS64 => same(g::GETDENTS64),
        nr::CLOCK_GETTIME => same(g::CLOCK_GETTIME),
        nr::OPENAT => same(g::OPENAT),
        nr::PIPE2 => same(g::PIPE2),
        nr::PPOLL => same(g::PPOLL),
        // `clone(flags, stack, ptid, ctid, tls)` here, `(flags, stack, ptid,
        // tls, ctid)` in the generic table.
        nr::CLONE => c(g::CLONE, [a[0], a[1], a[2], a[4], a[3], a[5]], Post::None),
        // The calls the generic table dropped, in the generic call's terms.
        nr::OPEN => c(g::OPENAT, [crate::AT_FDCWD, a[0], a[1], a[2], 0, 0], Post::None),
        nr::PIPE => c(g::PIPE2, [a[0], 0, 0, 0, 0, 0], Post::None),
        nr::POLL => c(g::PPOLL, [a[0], a[1], 0, 0, 0, 0], Post::PollMs(a[2] as u32)),
        nr::DUP2 if a[0] == a[1] => c(g::FCNTL, [a[0], F_GETFD, 0, 0, 0, 0], Post::DupSame(a[1])),
        nr::DUP2 => c(g::DUP3, [a[0], a[1], 0, 0, 0, 0], Post::None),
        nr::FORK => c(g::CLONE, [SIGCHLD, 0, 0, 0, 0, 0], Post::None),
        nr::VFORK => c(
            g::CLONE,
            [crate::clone::CLONE_VM | crate::clone::CLONE_VFORK | SIGCHLD, 0, 0, 0, 0, 0],
            Post::None,
        ),
        // The stat family: the generic call, then the layout.
        nr::STAT => c(g::NEWFSTATAT, [crate::AT_FDCWD, a[0], a[1], 0, 0, 0], Post::Stat(a[1])),
        nr::LSTAT => c(g::NEWFSTATAT, [crate::AT_FDCWD, a[0], a[1], crate::AT_SYMLINK_NOFOLLOW, 0, 0], Post::Stat(a[1])),
        nr::FSTAT => c(g::FSTAT, a, Post::Stat(a[1])),
        nr::NEWFSTATAT => c(g::NEWFSTATAT, a, Post::Stat(a[2])),
        // Layouts only the x86-64 side knows.
        nr::UNAME => c(g::UNAME, a, Post::Uname(a[0])),
        nr::RT_SIGACTION => c(g::RT_SIGACTION, a, Post::Sigaction),
        nr::ARCH_PRCTL => c(nr::ARCH_PRCTL, a, Post::ArchPrctl),
        _ => None,
    }
}

/// `sizeof(struct stat)` on x86-64 (musl `arch/x86_64/bits/stat.h`).
pub const STAT_SIZE_X86_64: usize = 144;

/// Rewrite an asm-generic `struct stat` (`Stat::to_bytes`: dev@0 ino@8
/// mode@16 nlink@20 uid@24 gid@28 rdev@32 size@48 blksize@56 blocks@64
/// atime@72 mtime@88 ctime@104) as the x86-64 one: dev@0 ino@8 nlink@16 (64
/// bits) mode@24 uid@28 gid@32 rdev@40 size@48 blksize@56 (64 bits) blocks@64
/// atime@72 mtime@88 ctime@104, three unused words after.
pub fn stat_from_generic(g: &[u8; STAT_SIZE]) -> [u8; STAT_SIZE_X86_64] {
    let mut x = [0u8; STAT_SIZE_X86_64];
    x[0..16].copy_from_slice(&g[0..16]); // st_dev, st_ino
    x[16..20].copy_from_slice(&g[20..24]); // st_nlink: a u32 widened to 64 bits
    x[24..28].copy_from_slice(&g[16..20]); // st_mode
    x[28..32].copy_from_slice(&g[24..28]); // st_uid
    x[32..36].copy_from_slice(&g[28..32]); // st_gid
    x[40..48].copy_from_slice(&g[32..40]); // st_rdev
    x[48..56].copy_from_slice(&g[48..56]); // st_size
    let blksize = i32::from_le_bytes([g[56], g[57], g[58], g[59]]) as i64;
    x[56..64].copy_from_slice(&blksize.to_le_bytes()); // st_blksize: widened
    x[64..72].copy_from_slice(&g[64..72]); // st_blocks
    x[72..120].copy_from_slice(&g[72..120]); // atim, mtim, ctim
    x
}

/// `struct utsname` for x86-64: the shared one, with the machine this ISA
/// names.
pub fn utsname_bytes(nodename: &[u8]) -> [u8; UTSNAME_SIZE] {
    let mut b = crate::utsname_bytes(Arch::Riscv64, nodename);
    // Field 4 is `machine`, 65 bytes wide.
    b[4 * 65..5 * 65].fill(0);
    b[4 * 65..4 * 65 + 6].copy_from_slice(b"x86_64");
    b
}
