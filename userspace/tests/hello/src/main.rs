// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 counterpart of `hello.S` (phase 6 prep, aarch64 parity).
//!
//! Same two syscalls as the RISC-V original, in the same order: write the
//! banner to fd 1, then exit(0). Issued with raw `svc #0` — no `libsys` —
//! matching `hello.S`'s own character: a hand-written, no-library syscall
//! test, not a program that exercises the wrapper crate.
//!
//! ABI (`crates/core/abi/src/syscall_nr.rs`, "Register convention"):
//!   x8 = syscall number, x0..x5 = arguments, svc #0, x0 = return value.
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

use azos_abi::syscall_nr::{SYS_WRITE, SYS_EXIT};


const MSG: &[u8] = b"Hello from user-space!\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_WRITE,
            in("x0") 1u64,
            in("x1") MSG.as_ptr() as u64,
            in("x2") MSG.len() as u64,
            lateout("x0") _,
            options(nostack),
        );
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_EXIT,
            in("x0") 0u64,
            options(nostack, noreturn),
        );
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_EXIT,
            in("x0") 1u64,
            options(nostack, noreturn),
        );
    }
}
