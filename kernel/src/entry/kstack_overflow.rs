// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A kernel stack overflow, caught at trap entry (riscv64, aarch64: the
//! stack bit test in `trap_entry.S`; x86_64 takes #DF on its IST stack). The
//! trap would have stored its frame in the guard below a task stack and
//! faulted again forever, so it runs on a stack of its own instead.

/// Each hart's stack for the report, `1 << OVF_SHIFT` bytes.
pub const OVF_SHIFT: u32 = 14;
const OVF: usize = 1 << OVF_SHIFT;

#[repr(C, align(16))]
pub struct OverflowStacks([[u8; OVF]; crate::MAX_HARTS]);

#[no_mangle]
pub static mut AZOS_KSTACK_OVERFLOW: OverflowStacks = OverflowStacks([[0; OVF]; crate::MAX_HARTS]);

/// The report: the trapping PC, the SP that ran off its stack, the fault
/// address. Never returns.
#[no_mangle]
pub extern "C" fn azos_kstack_overflow(pc: usize, sp: usize, addr: usize) -> ! {
    panic!("kernel stack overflow: pc {:#x}, sp {:#x} below the stack of slot {}, fault at {:#x}",
           pc, sp, azos_mm::kstack::slot_holding(sp + azos_mm::kstack::STRIDE / 2), addr);
}
