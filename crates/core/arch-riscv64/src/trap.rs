// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Trap handling: TrapFrame, cause codes, and dispatch.
///
/// The assembly `trap_entry.S` saves all registers into a TrapFrame on the
/// stack, then calls `trap_handler()` (defined here). On return the assembly
/// restores registers and executes `sret`.
///
/// Ported from kernel/include/trap.h + kernel/core/trap.c

// ---- Register value type (u64 on RV64) ----

pub type RegVal = u64;

// ---- Exception codes (scause/mcause without interrupt bit) ----

pub const TRAP_INSTR_MISALIGNED: usize = 0;
pub const TRAP_INSTR_ACCESS_FAULT: usize = 1;
pub const TRAP_ILLEGAL_INSTR: usize = 2;
pub const TRAP_BREAKPOINT: usize = 3;
pub const TRAP_LOAD_MISALIGNED: usize = 4;
pub const TRAP_LOAD_ACCESS_FAULT: usize = 5;
pub const TRAP_STORE_MISALIGNED: usize = 6;
pub const TRAP_STORE_ACCESS_FAULT: usize = 7;
pub const TRAP_ECALL_FROM_U: usize = 8;
pub const TRAP_ECALL_FROM_S: usize = 9;
pub const TRAP_ECALL_FROM_M: usize = 11;
pub const TRAP_INSTR_PAGE_FAULT: usize = 12;
pub const TRAP_LOAD_PAGE_FAULT: usize = 13;
pub const TRAP_STORE_PAGE_FAULT: usize = 15;

// ---- Interrupt codes (scause with MSB set) ----

pub const INTERRUPT_BIT: usize = 1 << 63;

// S-mode interrupt codes
pub const INT_SOFTWARE_S: usize = 1;
pub const INT_TIMER_S: usize = 5;
pub const INT_EXTERNAL_S: usize = 9;

/// Trap frame layout — must match `trap_entry*.S` exactly.
///
/// RV64: 32 regs × 8 + 4 CSRs × 8 = 288 bytes
#[repr(C)]
pub struct TrapFrame {
    pub regs: [RegVal; 32], // x0-x31 (x0 always 0 but space reserved)
    pub sepc: RegVal,       // sepc
    pub sstatus: RegVal,    // sstatus
    pub scause: RegVal,     // scause
    pub stval: RegVal,      // stval
}

// Compile-time verification of struct size
const _: () = assert!(core::mem::size_of::<TrapFrame>() == 288);

// `trap_entry.S` derives TF_SP as `offset_of!(TrapFrame, regs) + 2 * 8` (x2 =
// sp) rather than hardcoding it — but that's only correct if `regs` starts
// the struct. B2-01 injects every other TrapFrame offset into the asm from
// this struct; this is the one invariant that injection does not check on
// its own, so pin it here.
const _: () = assert!(core::mem::offset_of!(TrapFrame, regs) == 0);

/// Convert a trap cause code to a human-readable string.
pub fn cause_str(cause: usize) -> &'static str {
    if cause & INTERRUPT_BIT != 0 {
        match cause & !INTERRUPT_BIT {
            1 => "Supervisor software interrupt",
            5 => "Supervisor timer interrupt",
            9 => "Supervisor external interrupt",
            _ => "Unknown interrupt",
        }
    } else {
        match cause {
            TRAP_INSTR_MISALIGNED => "Instruction address misaligned",
            TRAP_INSTR_ACCESS_FAULT => "Instruction access fault",
            TRAP_ILLEGAL_INSTR => "Illegal instruction",
            TRAP_BREAKPOINT => "Breakpoint",
            TRAP_LOAD_MISALIGNED => "Load address misaligned",
            TRAP_LOAD_ACCESS_FAULT => "Load access fault",
            TRAP_STORE_MISALIGNED => "Store/AMO address misaligned",
            TRAP_STORE_ACCESS_FAULT => "Store/AMO access fault",
            TRAP_ECALL_FROM_U => "Environment call from U-mode",
            TRAP_ECALL_FROM_S => "Environment call from S-mode",
            TRAP_ECALL_FROM_M => "Environment call from M-mode",
            TRAP_INSTR_PAGE_FAULT => "Instruction page fault",
            TRAP_LOAD_PAGE_FAULT => "Load page fault",
            TRAP_STORE_PAGE_FAULT => "Store/AMO page fault",
            _ => "Unknown exception",
        }
    }
}
