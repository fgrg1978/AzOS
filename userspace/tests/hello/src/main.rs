// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 and x86_64 counterpart of `hello.S`.
//!
//! Same two syscalls as the RISC-V original, in the same order: write the
//! banner to fd 1, then exit(0). Issued with raw `svc #0` — no `libsys` —
//! matching `hello.S`'s own character: a hand-written, no-library syscall
//! test, not a program that exercises the wrapper crate.
//!
//! ABI (`crates/core/abi/src/syscall_nr.rs`, "Register convention"):
//!   aarch64: x8 = syscall number, x0..x5 = arguments, svc #0, x0 = return value;
//!   x86_64: rax = syscall number, rdi rsi rdx r10 r8 r9 = arguments, syscall.
//!
//! SYS_WRITE = 23  (x0=fd, x1=buf_ptr, x2=len)
//! SYS_EXIT  = 3   (x0 = exit code)
//!
//! **No aarch64 kernel exists to exec this yet.** Built and linked so the
//! toolchain path (`rust-lld`, page-aligned segments, `x8`/`svc #0`) is
//! proven out alongside the other 12 userspace programs, same as `hello.elf`
//! proves out the RISC-V path.

#![no_std]
#![no_main]

// Each syscall below selects its trap instruction per ISA; on
// an ISA with no branch the build stops here instead of losing the trap.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("hello: no syscall instruction for this ISA (aarch64, x86_64; riscv64 has hello.S)");

use azos_abi::syscall_nr::{SYS_WRITE, SYS_EXIT};


const MSG: &[u8] = b"Hello from user-space!\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_WRITE,
            in("x0") 1u64,
            in("x1") MSG.as_ptr() as u64,
            in("x2") MSG.len() as u64,
            lateout("x0") _,
            options(nostack),
        );
        // x86_64: rax = number, rdi rsi rdx = arguments; `syscall` writes
        // rcx and r11.
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_WRITE => _,
            in("rdi") 1u64,
            in("rsi") MSG.as_ptr() as u64,
            in("rdx") MSG.len() as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    exit(0)
}

fn exit(code: u64) -> ! {
    unsafe {
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_EXIT,
            in("x0") code,
            options(nostack, noreturn),
        );
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "syscall",
            in("rax") SYS_EXIT,
            in("rdi") code,
            options(nostack, noreturn),
        );
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    exit(1)
}
