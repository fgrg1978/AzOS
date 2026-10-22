// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 and x86_64 counterpart of `hello.S`.
//!
//! The same calls as the RISC-V original, in the same order: find the console
//! handle, write the banner on it, then exit(0). Issued with raw `svc #0` — no `libsys` —
//! matching `hello.S`'s own character: a hand-written, no-library syscall
//! test, not a program that exercises the wrapper crate.
//!
//! ABI (`crates/core/abi/src/syscall_nr.rs`, "Register convention"):
//!   aarch64: x8 = syscall number, x0..x5 = arguments, svc #0, x0 = return value;
//!   x86_64: rax = syscall number, rdi rsi rdx r10 r8 r9 = arguments, syscall.
//!
//! SYS_CAP_INFO    (x0 = 0, x1 = CAP_INFO_LOOKUP, x2 = the console's type, x3 = 0) -> the console handle
//! SYS_INVOKE      (x0 = handle, x1 = the console WRITE op word, x2 = buf, x3 = len)
//! SYS_EXIT        (x0 = exit code)
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

// The process entry, `_azos_entry`: the entry the target spec names for every
// native image (sdk/targets, `-e`); this crate links no libsys, so it defines
// its own, as libsys does. aarch64: a jump to `_start`. x86_64 (System V): the
// kernel starts an image with rsp 16-byte aligned, and a function expects
// rsp + 8 aligned (a `call` pushed its return address): realign, call `_start`
// with the kernel's rdi/rsi untouched, never return.
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".globl _azos_entry",
    ".type _azos_entry, %function",
    "_azos_entry:",
    "    b _start",
    ".size _azos_entry, . - _azos_entry",
);
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl _azos_entry",
    ".type _azos_entry, @function",
    "_azos_entry:",
    "    xor ebp, ebp",
    "    and rsp, -16",
    "    call _start",
    "    ud2",
    ".size _azos_entry, . - _azos_entry",
);

use azos_abi::cap::ty;
use azos_abi::invoke::{INVOKE_REGS, LOG_CONSOLE_WRITE};
use azos_abi::syscall_nr::{CAP_INFO_LOOKUP, SYS_CAP_INFO, SYS_EXIT, SYS_INVOKE};


const MSG: &[u8] = b"Hello from user-space!\n";

/// One raw syscall with four arguments; its result.
fn sc(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    unsafe {
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        // x86_64: rax = number, rdi rsi rdx r10 = arguments; `syscall` writes
        // rcx and r11.
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let console_h = sc(SYS_CAP_INFO, 0, CAP_INFO_LOOKUP, ty::CONSOLE.raw() as u64, 0);
    sc(SYS_INVOKE, console_h, INVOKE_REGS | LOG_CONSOLE_WRITE as u64, MSG.as_ptr() as u64, MSG.len() as u64);
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
