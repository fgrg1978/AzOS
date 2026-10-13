// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The trap: one call with six argument words and `invoke`.
//!
//! The register discipline is `azos_libsys`'s (its `syscall6` and `invoke`;
//! the `sysabi` gate rows hold it): the kernel preserves the callee-saved
//! registers and the argument registers it does not reply in, and clobbers
//! the rest, which the `asm!` blocks declare. This is the std side's own copy
//! because `azos_libsys` cannot be part of the std build graph (it depends on
//! a proc-macro crate through `azos_idl`); the two are kept equal by
//! `tests/host/stdrt-tests` (the same text-level check as the libsys one).

use core::arch::asm;

pub use azos_abi::ipc_msg::MsgDesc;
use azos_abi::syscall_nr::{SYS_INVOKE, SYS_IPC_CALL_V2};

/// A trap with up to six argument words (`a0..a5`; the unused ones are 0).
/// Returns the first reply register as the signed result.
#[inline(always)]
pub unsafe fn syscall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> isize {
    let ret: isize;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 as isize => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            in("a5") a5,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 as isize => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            in("x4") a4,
            in("x5") a5,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        #[cfg(target_arch = "x86_64")]
        asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8") a4,
            in("r9") a5,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Invoke op `op` on `handle` in the register form (`azos_abi::invoke`): the
/// words go in `a2..a5`, the value comes back in `a0` and four reply words
/// in `a1..a4`. The replies land in argument registers, so they are declared
/// written (a helper that declared `a1..a6` as plain inputs would let rustc
/// assume them intact across the trap).
#[inline(always)]
pub fn invoke(handle: u32, op: u16, w: [u64; 4]) -> (isize, [u64; 4]) {
    let opw = op as u64 | azos_abi::invoke::INVOKE_REGS;
    let ret: isize;
    let (r1, r2, r3, r4): (u64, u64, u64, u64);
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!(
            "ecall",
            in("a7") SYS_INVOKE,
            inlateout("a0") handle as u64 => ret,
            inlateout("a1") opw => r1,
            inlateout("a2") w[0] => r2,
            inlateout("a3") w[1] => r3,
            inlateout("a4") w[2] => r4,
            inlateout("a5") w[3] => _,
            lateout("a6") _,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") SYS_INVOKE,
            inlateout("x0") handle as u64 => ret,
            inlateout("x1") opw => r1,
            inlateout("x2") w[0] => r2,
            inlateout("x3") w[1] => r3,
            inlateout("x4") w[2] => r4,
            inlateout("x5") w[3] => _,
            lateout("x6") _,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        // x86_64: arguments in rdi rsi rdx r10 r8 r9 (a0..a5); a1..a6 come
        // back in rdx rsi rdi r8 r9 r10 (the kernel's `SYSCALL_OUT` order).
        #[cfg(target_arch = "x86_64")]
        asm!(
            "syscall",
            inlateout("rax") SYS_INVOKE as isize => ret,
            inlateout("rdi") handle as u64 => r3,
            inlateout("rsi") opw => r2,
            inlateout("rdx") w[0] => r1,
            inlateout("r10") w[1] => _,
            inlateout("r8") w[2] => r4,
            inlateout("r9") w[3] => _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (ret, [r1, r2, r3, r4])
}

/// The v2 endpoint call (`SYS_IPC_CALL_V2`): the request in `*msg`, the reply
/// written over it. 0 when answered, else a negative code.
pub fn ipc_call(ep: u32, msg: &mut MsgDesc) -> isize {
    unsafe { syscall6(SYS_IPC_CALL_V2, ep as u64, msg as *mut MsgDesc as u64, 0, 0, 0, 0) }
}

/// A trap instruction: the kernel ends the task with a fault status.
#[inline(always)]
pub fn trap() -> ! {
    // SAFETY: a trap instruction; the kernel ends the task.
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!("ebreak", options(noreturn));
        #[cfg(target_arch = "aarch64")]
        asm!("brk #0", options(noreturn));
        #[cfg(target_arch = "x86_64")]
        asm!("ud2", options(noreturn));
    }
}
