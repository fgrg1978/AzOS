// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The M-mode entry: reset vector, trap vector, and the Rust handler they
//! call.
//!
//! `mscratch` holds the address of the running task's [`Frame`] while the
//! task runs. A trap swaps it with `t6`, saves the other 30 registers into
//! the frame, runs [`micro_trap`] on the kernel stack and restores from the
//! frame it returns, which is the same task's or another's. Tasks run in
//! U-mode, so a trap from M-mode is a kernel fault and stops the machine.

use core::arch::{asm, global_asm};

use crate::hw::{self, Machine};
use crate::kernel::{Frame, Kernel};
use crate::config::*;

global_asm!(r#"
    .section .text.init
    .globl _start
_start:
    csrr t0, mhartid
    bnez t0, 9f
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, __kstack_top
    la t0, __bss_start
    la t1, __bss_end
1:  bgeu t0, t1, 2f
    sw zero, 0(t0)
    addi t0, t0, 4
    j 1b
2:  csrw mscratch, zero
    la t0, trap_entry
    csrw mtvec, t0
    call micro_main
9:  wfi
    j 9b

    .section .text
    .balign 4
    .globl trap_entry
trap_entry:
    csrrw t6, mscratch, t6
    # mscratch is the running task's frame while a task runs and 0 while the
    # kernel does: a trap with 0 in it came from the kernel itself.
    beqz t6, kernel_trap
    sw x1, 4(t6)
    sw x2, 8(t6)
    sw x3, 12(t6)
    sw x4, 16(t6)
    sw x5, 20(t6)
    sw x6, 24(t6)
    sw x7, 28(t6)
    sw x8, 32(t6)
    sw x9, 36(t6)
    sw x10, 40(t6)
    sw x11, 44(t6)
    sw x12, 48(t6)
    sw x13, 52(t6)
    sw x14, 56(t6)
    sw x15, 60(t6)
    sw x16, 64(t6)
    sw x17, 68(t6)
    sw x18, 72(t6)
    sw x19, 76(t6)
    sw x20, 80(t6)
    sw x21, 84(t6)
    sw x22, 88(t6)
    sw x23, 92(t6)
    sw x24, 96(t6)
    sw x25, 100(t6)
    sw x26, 104(t6)
    sw x27, 108(t6)
    sw x28, 112(t6)
    sw x29, 116(t6)
    sw x30, 120(t6)
    csrr t5, mscratch
    sw t5, 124(t6)
    csrw mscratch, zero
    csrr t5, mepc
    sw t5, 128(t6)
    # gp is a register a task may set to anything: the kernel's own
    # gp-relative accesses need it back before any Rust runs.
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, __kstack_top
    mv a0, t6
    csrr a1, mcause
    csrr a2, mtval
    call micro_trap
    mv t6, a0
    j restore

kernel_trap:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, __kstack_top
    csrr a0, mcause
    csrr a1, mepc
    csrr a2, mtval
    call micro_kernel_trap
9:  wfi
    j 9b

    .globl restore
restore:
    lw t5, 128(t6)
    csrw mepc, t5
    csrw mscratch, t6
    lw x1, 4(t6)
    lw x2, 8(t6)
    lw x3, 12(t6)
    lw x4, 16(t6)
    lw x5, 20(t6)
    lw x6, 24(t6)
    lw x7, 28(t6)
    lw x8, 32(t6)
    lw x9, 36(t6)
    lw x10, 40(t6)
    lw x11, 44(t6)
    lw x12, 48(t6)
    lw x13, 52(t6)
    lw x14, 56(t6)
    lw x15, 60(t6)
    lw x16, 64(t6)
    lw x17, 68(t6)
    lw x18, 72(t6)
    lw x19, 76(t6)
    lw x20, 80(t6)
    lw x21, 84(t6)
    lw x22, 88(t6)
    lw x23, 92(t6)
    lw x24, 96(t6)
    lw x25, 100(t6)
    lw x26, 104(t6)
    lw x27, 108(t6)
    lw x28, 112(t6)
    lw x29, 116(t6)
    lw x30, 120(t6)
    lw t6, 124(t6)
    mret
"#);

static mut KERNEL: Kernel<'static> = Kernel::new();

/// The kernel. Never aliased: one hart, and the trap handler is the only
/// caller once the first task runs.
///
/// # Safety
/// Not re-entrant: a caller must not hold the reference across a trap.
pub unsafe fn kernel() -> &'static mut Kernel<'static> {
    &mut *core::ptr::addr_of_mut!(KERNEL)
}

/// Run the first task: the entry that never returns.
///
/// # Safety
/// The kernel is booted, and the machine is in M-mode with interrupts off.
pub unsafe fn enter() -> ! {
    let k = kernel();
    let mut hwm = Machine;
    k.schedule(&mut hwm);
    let frame = k.frame(k.current()) as *mut Frame;
    // MPP = U (00), MPIE = 1; the timer interrupt on.
    asm!(
        "li t0, 0x1800",
        "csrc mstatus, t0",
        "li t0, 0x80",
        "csrs mstatus, t0",
        "li t0, 0x80",
        "csrs mie, t0",
        out("t0") _,
    );
    hw::arm_timer(hw::mtime() + TICK_PERIOD);
    asm!("mv t6, {0}", "j restore", in(reg) frame, options(noreturn));
}

/// The trap handler, called by `trap_entry` with the saved frame.
///
/// # Safety
/// Only `trap_entry` calls it.
#[no_mangle]
pub unsafe extern "C" fn micro_trap(frame: *mut Frame, cause: usize, tval: usize) -> *mut Frame {
    let k = kernel();
    let mut m = Machine;
    debug_assert!(core::ptr::eq(frame, k.frame(k.current())));
    let interrupt = cause >> (usize::BITS - 1) != 0;
    match (interrupt, cause & !(1 << (usize::BITS - 1))) {
        (false, 8) => k.syscall(&mut m), // ecall from U-mode
        (true, 7) => {
            hw::arm_timer(hw::mtime() + TICK_PERIOD);
            k.on_tick(&mut m);
        }
        _ => k.fault(&mut m, cause, tval),
    }
    let next = k.schedule(&mut m);
    k.frame(next) as *mut Frame
}

/// A trap taken in M-mode: the kernel itself faulted. Print where and stop.
///
/// # Safety
/// Only `kernel_trap` calls it.
#[no_mangle]
pub unsafe extern "C" fn micro_kernel_trap(cause: usize, epc: usize, tval: usize) -> ! {
    use core::fmt::Write;
    struct Uart;
    impl Write for Uart {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            hw::uart_write(s.as_bytes());
            Ok(())
        }
    }
    let _ = writeln!(Uart, "\n[MICRO] kernel trap: cause={:#x} epc={:#x} tval={:#x}: halting", cause, epc, tval);
    loop {
        asm!("wfi");
    }
}
