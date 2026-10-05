// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The seccomp-bpf program, built at compile time from `allow::ALLOWED`.
//!
//! ```text
//!   0      ld  [4]                      seccomp_data.arch
//!   1      jeq #AUDIT_ARCH_RISCV64  jt 0  jf KILL
//!   2      ld  [0]                      seccomp_data.nr
//!   3..3+n jeq #ALLOWED[j].nr       jt ALLOW  jf 0     (ascending)
//!   3+n    ret #SECCOMP_RET_KILL_PROCESS
//!   4+n    ret #SECCOMP_RET_ALLOW
//! ```
//!
//! `n + 5` instructions: 31 for the 26 entries.
//!
//! **Arch first.** A syscall number means nothing without its ABI: on a
//! kernel that also runs 32-bit RISC-V binaries the same number names a
//! different call. Anything that is not `AUDIT_ARCH_RISCV64` is killed.
//!
//! **Linear, ascending, and not a binary search.** The AzOS side checks its
//! image profile with a linear scan of the listed numbers
//! (`SyscallFilter::is_allowed`), so a linear compare chain in ascending order
//! is the same algorithm. A decision tree would give the Linux column a
//! cheaper filter than the one it is compared against.
//!
//! **Why the chain length may not matter on Linux.** The program never loads
//! an argument, so every listed number is a constant ALLOW. Kernels with the
//! seccomp action cache (5.11+, where the architecture defines
//! `SECCOMP_ARCH_NATIVE`) evaluate that once when the filter is attached and
//! skip the program for those numbers afterwards; the reference kernel has no
//! BPF JIT, so without the cache the program runs in the interpreter on every
//! syscall. Which of the two applies to 6.4.0-rc4 on riscv64 is not verified:
//! `CONFIG_SECCOMP_CACHE_DEBUG`, the only way to read the cache, is off in its
//! config. `host-tests` asserts the program stays cacheable.
//!
//! **Default `SECCOMP_RET_KILL_PROCESS`, not `RET_ERRNO`.** Several lanes
//! ignore return values on purpose (`getpid`, `sched_yield`, the report's
//! `write`). An errno would turn a missing entry into a lane that times the
//! filter's rejection and prints a number for it. A kill prints no number.

use crate::allow::ALLOWED;

/// `struct sock_filter`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// `struct sock_fprog`.
#[repr(C)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

// Classic BPF opcodes, `linux/bpf_common.h`.
pub const BPF_LD_W_ABS: u16 = 0x00 | 0x00 | 0x20; // BPF_LD | BPF_W | BPF_ABS
pub const BPF_JMP_JEQ_K: u16 = 0x05 | 0x10 | 0x00; // BPF_JMP | BPF_JEQ | BPF_K
pub const BPF_RET_K: u16 = 0x06 | 0x00; // BPF_RET | BPF_K

/// Offsets into `struct seccomp_data`.
pub const SECCOMP_DATA_NR: u32 = 0;
pub const SECCOMP_DATA_ARCH: u32 = 4;

/// `EM_RISCV (243) | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`.
pub const AUDIT_ARCH_RISCV64: u32 = 0xC000_00F3;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

pub const LEN: usize = ALLOWED.len() + 5;

const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter { code, jt: 0, jf: 0, k }
}

const fn jeq(k: u32, jt: usize, jf: usize) -> SockFilter {
    // Classic BPF jump offsets are one byte.
    assert!(jt <= 255 && jf <= 255);
    SockFilter { code: BPF_JMP_JEQ_K, jt: jt as u8, jf: jf as u8, k }
}

pub const fn program() -> [SockFilter; LEN] {
    let n = ALLOWED.len();
    let mut p = [stmt(0, 0); LEN];
    p[0] = stmt(BPF_LD_W_ABS, SECCOMP_DATA_ARCH);
    // Offsets count from the next instruction: KILL is at 3+n.
    p[1] = jeq(AUDIT_ARCH_RISCV64, 0, n + 1);
    p[2] = stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR);
    let mut j = 0;
    while j < n {
        // Strictly ascending: a duplicate or out-of-order entry is a list
        // edit gone wrong, and it fails the build.
        assert!(j == 0 || ALLOWED[j - 1].nr < ALLOWED[j].nr);
        // ALLOW is at 4+n.
        p[3 + j] = jeq(ALLOWED[j].nr, n - j, 0);
        j += 1;
    }
    p[3 + n] = stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS);
    p[4 + n] = stmt(BPF_RET_K, SECCOMP_RET_ALLOW);
    p
}
