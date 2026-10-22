// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 counterpart of `test.S` (phase 6 prep, aarch64 parity).
//!
//! Same checks as the RISC-V original, in the same order: `SYS_GETPID`,
//! the console `WRITE` (banner), `SYS_MO_MAP` (one anonymous page), a store
//! and a load through that page, the console `WRITE` (verdict). Raw `svc #0` —
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

use azos_abi::cap::ty;
use azos_abi::invoke::{INVOKE_REGS, LOG_CONSOLE_WRITE};
use azos_abi::syscall_nr::{CAP_INFO_LOOKUP, SYS_CAP_INFO, SYS_EXIT, SYS_GETPID, SYS_INVOKE, SYS_MO_MAP};


const MSG_BANNER: &[u8; 30] = b"[SYSCALL_TEST] Starting...\n\0\0\0";
const MSG_PASS: &[u8; 32] = b"[SYSCALL_TEST] ALL PASSED!\n\0\0\0\0\0";
const MSG_FAIL: &[u8; 26] = b"[SYSCALL_TEST] FAILED!\n\0\0\0";

#[inline(always)]
unsafe fn syscall0(nr: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0", in("x8") nr, lateout("x0") ret,
            // The native syscall contract's clobbers (crates/core/abi/src/
            // syscall_nr.rs, "Register contract"): x7-x17 and x30.
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        )
    };
    ret
}

#[inline(always)]
unsafe fn syscall1(nr: u64, x0: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0", in("x8") nr, inlateout("x0") x0 as i64 => ret,
            // The native syscall contract's clobbers (crates/core/abi/src/
            // syscall_nr.rs, "Register contract"): x7-x17 and x30.
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        )
    };
    ret
}

/// Write `msg` on the console: find the handle, then the `WRITE` op on it.
/// The bytes taken, or a negative errno.
unsafe fn console_write(msg: &[u8]) -> i64 {
    unsafe {
        let h = syscall4(SYS_CAP_INFO, 0, CAP_INFO_LOOKUP, ty::CONSOLE.raw() as u64, 0);
        if h < 0 {
            return h;
        }
        syscall4(SYS_INVOKE, h as u64, INVOKE_REGS | LOG_CONSOLE_WRITE as u64, msg.as_ptr() as u64, msg.len() as u64)
    }
}

#[inline(always)]
unsafe fn syscall4(nr: u64, x0: u64, x1: u64, x2: u64, x3: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0", in("x8") nr, inlateout("x0") x0 as i64 => ret,
            in("x1") x1, in("x2") x2, in("x3") x3,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        )
    };
    ret
}

/// One page of anonymous read-write memory (`SYS_MO_MAP`, `a0` 0): its
/// address, or `-1`.
unsafe fn map_page() -> i64 {
    const PROT_RW: u64 = 3;
    unsafe { syscall4(SYS_MO_MAP, 0, 0, 4096, PROT_RW) }
}

fn fail() -> ! {
    unsafe {
        console_write(MSG_FAIL);
        syscall1(SYS_EXIT, 1);
    }
    loop {}
}

/// The process entry the target spec names (`-e _azos_entry`, sdk/targets).
#[unsafe(no_mangle)]
pub extern "C" fn _azos_entry() -> ! {
    unsafe {
        // Test 1: SYS_GETPID.
        let _tid = syscall0(SYS_GETPID);

        // Test 2: the console WRITE (banner). Must write exactly 30 bytes.
        let n = console_write(MSG_BANNER);
        if n != MSG_BANNER.len() as i64 {
            fail();
        }

        // Test 3: SYS_MO_MAP — one anonymous page. A real address, not -1.
        let page = map_page();
        if page <= 0 {
            fail();
        }

        // Test 4: write/read a byte through the newly mapped page.
        let p = page as *mut u8;
        core::ptr::write_volatile(p, 0x42);
        let back = core::ptr::read_volatile(p);
        if back != 0x42 {
            fail();
        }

        // All passed.
        console_write(MSG_PASS);
        syscall1(SYS_EXIT, 0);
    }
    loop {}
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    fail();
}
