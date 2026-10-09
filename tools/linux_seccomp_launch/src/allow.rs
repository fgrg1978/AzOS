// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Linux/riscv64 syscalls the Linux+seccomp column of vsbench allows.
//!
//! **This is the one list.** The launcher's BPF program is generated from it
//! (`bpf.rs`), the vsbench docs point here instead of restating it, and
//! `host-tests` fails if it drifts from what `userspace/bench/vsbench` issues when
//! built with `--features linux`.
//!
//! Numbers are the RISC-V generic ABI (`asm-generic/unistd.h`), the same ones
//! `userspace/bench/vsbench/src/abi_linux.rs` spells out; names are that file's
//! constant names, so the host test can match entry by entry.
//!
//! ## How the set was derived, 2026-09-14 (re-derived 2026-09-27)
//!
//! 1. **Source.** With `--features linux`, `main.rs` compiles `bench_core.rs`
//!    (no `ecall`, only `rdtime`) and `abi_linux.rs`, whose seven
//!    `syscallN` helpers are the only `ecall` sites. Every helper call names a
//!    `SYS_*` constant; the constants below are exactly those names. Since
//!    2026-09-27 the Linux build also links `azos_libsys` for its pure
//!    ring core (`SpscRing` and friends) and calls none of its wrappers.
//! 2. **Binary.** Re-checked 2026-09-27, after the wave-6 counterparts
//!    (`futex`, `clock_nanosleep`, `io_uring_*`, `close`): the built ELF has
//!    225 `ecall` instructions; each is preceded in its block by
//!    `li a7,<n>`, and the `<n>` are exactly the twenty-five vsbench numbers
//!    below — no AzOS number from the linked `azos_libsys`. (First
//!    derivation, 2026-09-14: 147 `ecall`s, twenty numbers.)
//! 3. **vDSO.** vsbench calls two vDSO functions. In the 6.4.0-rc4 reference
//!    kernel's vDSO, `__vdso_clock_gettime` falls back to ecall 113 and
//!    `__vdso_getcpu` is `li a7,168; ecall`; both are listed.
//! 4. **Runtime.** No libc, no allocator, a naked `_start`, a `loop {}` panic
//!    handler and `exit` (93) at the end: nothing runs before or after `main`
//!    that issues a syscall. No signal handler is installed, so there is no
//!    `rt_sigreturn` (139), and no `restart_syscall` (128) either: the calls
//!    that DO block since 2026-09-27 (`futex` wait, `clock_nanosleep`,
//!    `io_uring_enter` waiting for completions) are only restarted that way
//!    after a signal handler or a stop, and there is neither. The process
//!    exits with `exit`, not `exit_group` (94).
//!
//! **What this filter does not see: io_uring operations.** An SQE's
//! `IORING_OP_READ`/`WRITE`/`TIMEOUT` is executed by the ring, not issued as
//! a syscall, so seccomp filters `io_uring_setup`/`io_uring_enter` and
//! nothing the ring then does. The Linux+seccomp column's `ioring-*` numbers
//! are therefore NOT filtered per operation — a property of Linux, stated
//! here so the column is not read as "same filter, every path".
//!
//! The launcher's own call after the install is `execve`: the filter is
//! installed before it, so it has to pass the filter. Since wave 12
//! vsbench issues `execve` too (its `spawn+wait` lane starts itself with
//! `--exit`), so the entry is listed as vsbench's and is reachable after the
//! launch as well.

/// Who issues the call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum By {
    /// `userspace/bench/vsbench` built with `--features linux`.
    Vsbench,
    /// The launcher, after the filter is installed, for a call vsbench does
    /// not make. None today: its one call (`execve`) is vsbench's too.
    #[allow(dead_code)]
    Launcher,
}

#[derive(Clone, Copy, Debug)]
pub struct Syscall {
    pub nr: u32,
    pub name: &'static str,
    pub by: By,
}

const fn v(nr: u32, name: &'static str) -> Syscall {
    Syscall { nr, name, by: By::Vsbench }
}

/// Ascending by number. The BPF program compares in this order, which is the
/// same linear, ascending shape as the AzOS image profile scan
/// (`SyscallFilter::is_allowed` in `crates/core/sched/src/filter.rs`).
pub const ALLOWED: [Syscall; 33] = [
    v(23, "SYS_DUP"),
    // N0 (wave 15): `cap-lookup`'s Linux twin, `fcntl(fd, F_GETFD)`.
    v(25, "SYS_FCNTL"),
    v(29, "SYS_IOCTL"),
    // Wave 15 `disk` lanes: mount the vfat disk at /mnt, then fsync.
    v(34, "SYS_MKDIRAT"),
    v(40, "SYS_MOUNT"),
    v(56, "SYS_OPENAT"),
    v(57, "SYS_CLOSE"),
    v(59, "SYS_PIPE2"),
    v(63, "SYS_READ"),
    v(64, "SYS_WRITE"),
    v(82, "SYS_FSYNC"),
    v(93, "SYS_EXIT"),
    v(98, "SYS_FUTEX"),
    v(113, "SYS_CLOCK_GETTIME"),
    v(115, "SYS_CLOCK_NANOSLEEP"),
    v(124, "SYS_SCHED_YIELD"),
    v(165, "SYS_GETRUSAGE"),
    v(168, "SYS_GETCPU"),
    v(172, "SYS_GETPID"),
    v(198, "SYS_SOCKET"),
    v(200, "SYS_BIND"),
    v(203, "SYS_CONNECT"),
    v(206, "SYS_SENDTO"),
    v(207, "SYS_RECVFROM"),
    // Wave 15 `nic-egress`: SO_BROADCAST / SO_BINDTODEVICE.
    v(208, "SYS_SETSOCKOPT"),
    v(214, "SYS_BRK"),
    v(215, "SYS_MUNMAP"),
    v(220, "SYS_CLONE"),
    // The launcher's one call after the install, and since wave 12 also
    // vsbench's (`spawn+wait`: `posix_spawn` of itself).
    v(221, "SYS_EXECVE"),
    v(222, "SYS_MMAP"),
    v(260, "SYS_WAIT4"),
    v(425, "SYS_IO_URING_SETUP"),
    v(426, "SYS_IO_URING_ENTER"),
];

/// The vDSO functions vsbench calls and the syscall each falls back to, read
/// off the reference kernel's vDSO disassembly (see the module header).
pub const VDSO_FALLBACKS: [(&str, u32); 2] = [
    ("__vdso_clock_gettime", 113),
    ("__vdso_getcpu", 168),
];
