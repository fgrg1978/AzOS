// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 counterpart of `test.S` (phase 6 prep, aarch64 parity).
//!
//! Same five checks as the RISC-V original, in the same order: `SYS_GETPID`,
//! `SYS_WRITE` (banner), `SYS_BRK` (get), `SYS_BRK` (extend by 4096),
//! `SYS_WRITE` (pattern written to the newly allocated page). Raw `svc #0` —
//! no `libsys` — matching `test.S`'s own character.
//!
//! ABI (`crates/core/abi/src/syscall_nr.rs`, "Register convention"):
//!   x8 = syscall number, x0..x5 = arguments, svc #0, x0 = return value.
//!
//! **No aarch64 kernel exists to exec this yet** — see `userspace/tests/hello`'s
//! module doc for why this crate exists at all (no aarch64 GNU
//! cross-assembler on this host) and what it proves (the toolchain path),
//! not what it measures (nothing does, yet).

#![no_std]
#![no_main]

use azos_abi::syscall_nr::{SYS_GETPID, SYS_WRITE, SYS_BRK, SYS_EXIT};


const MSG_BANNER: &[u8; 30] = b"[SYSCALL_TEST] Starting...\n\0\0\0";
const MSG_PASS: &[u8; 32] = b"[SYSCALL_TEST] ALL PASSED!\n\0\0\0\0\0";
const MSG_FAIL: &[u8; 26] = b"[SYSCALL_TEST] FAILED!\n\0\0\0";

#[inline(always)]
unsafe fn syscall0(nr: u64) -> i64 {
    let ret: i64;
    unsafe { core::arch::asm!("svc #0", in("x8") nr, lateout("x0") ret, options(nostack)) };
    ret
}

#[inline(always)]
unsafe fn syscall1(nr: u64, x0: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0", in("x8") nr, inlateout("x0") x0 as i64 => ret, options(nostack),
        )
    };
    ret
}

#[inline(always)]
unsafe fn syscall3(nr: u64, x0: u64, x1: u64, x2: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0", in("x8") nr, inlateout("x0") x0 as i64 => ret,
            in("x1") x1, in("x2") x2, options(nostack),
        )
    };
    ret
}

fn fail() -> ! {
    unsafe {
        syscall3(SYS_WRITE, 1, MSG_FAIL.as_ptr() as u64, MSG_FAIL.len() as u64);
        syscall1(SYS_EXIT, 1);
    }
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        // Test 1: SYS_GETPID.
        let _tid = syscall0(SYS_GETPID);

        // Test 2: SYS_WRITE (banner). Must write exactly 30 bytes.
        let n = syscall3(SYS_WRITE, 1, MSG_BANNER.as_ptr() as u64, MSG_BANNER.len() as u64);
        if n != MSG_BANNER.len() as i64 {
            fail();
        }

        // Test 3: SYS_BRK(0) — current brk. Must not be 0.
        let brk0 = syscall1(SYS_BRK, 0);
        if brk0 == 0 {
            fail();
        }

        // Test 4: SYS_BRK(brk0 + 4096) — extend. New brk must be >= brk0 + 4096.
        let want = brk0 + 4096;
        let brk1 = syscall1(SYS_BRK, want as u64);
        if brk1 < want {
            fail();
        }

        // Test 5: write/read a byte through the newly allocated page.
        let p = brk0 as *mut u8;
        core::ptr::write_volatile(p, 0x42);
        let back = core::ptr::read_volatile(p);
        if back != 0x42 {
            fail();
        }

        // All passed.
        syscall3(SYS_WRITE, 1, MSG_PASS.as_ptr() as u64, MSG_PASS.len() as u64);
        syscall1(SYS_EXIT, 0);
    }
    loop {}
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    fail();
}
