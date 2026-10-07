// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 trap entry — SKELETON: the `TrapFrame` the asm in
//! `x86_64/asm/trap_entry.S` will save, its [`TrapContext`] impl, and the
//! Rust dispatcher that asm calls. Bodies are `todo!()`; nothing here runs.

#![cfg(target_arch = "x86_64")]

use super::{TrapClass, TrapContext};

/// The register file `trap_entry.S` pushes (layout fixed by that asm).
#[repr(C)]
pub struct TrapFrame {
    /// rax..r15 in push order.
    pub regs: [u64; 15],
    /// The IDT vector number the stub pushed.
    pub vector: u64,
    /// The CPU-pushed error code (0 for vectors without one).
    pub error_code: u64,
    /// The `iretq` frame: rip, cs, rflags, rsp, ss.
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
    /// CR2 at a #PF (vector 14).
    pub cr2: u64,
}

impl TrapContext for TrapFrame {
    /// The IDT vector.
    fn cause(&self) -> usize { todo!("x86_64: cause: the IDT vector") }
    /// 0-31 exceptions (14 = #PF), the `syscall` path, >= 32 interrupts.
    fn class(&self) -> TrapClass { todo!("x86_64: class: vector 14 -> PageFault, syscall_entry -> Syscall, >= 32 -> Interrupt") }
    /// The vector minus the LAPIC base the IOAPIC routes to.
    fn irq_number(&self) -> usize { todo!("x86_64: irq_number: vector - IRQ base") }
    /// CR2.
    fn fault_addr(&self) -> usize { todo!("x86_64: fault_addr: CR2") }
    fn pc(&self) -> usize { todo!("x86_64: pc: rip") }
    fn set_pc(&mut self, _pc: usize) { todo!("x86_64: set_pc: rip") }
    fn user_sp(&self) -> usize { todo!("x86_64: user_sp: rsp") }
    /// CS.RPL == 3.
    fn came_from_user(&self) -> bool { todo!("x86_64: came_from_user: cs & 3 == 3") }
    /// rax (Linux x86_64 ABI).
    fn syscall_number(&self) -> usize { todo!("x86_64: syscall_number: rax") }
    /// rdi, rsi, rdx, r10, r8, r9.
    fn syscall_arg(&self, _n: usize) -> usize { todo!("x86_64: syscall_arg: rdi rsi rdx r10 r8 r9") }
    /// rax.
    fn set_syscall_return(&mut self, _v: usize) { todo!("x86_64: set_syscall_return: rax") }
}

/// The Rust dispatcher `trap_entry.S` calls with the saved frame: route by
/// `TrapContext::class` to `trap::interrupt` / `trap::exception`, as
/// `riscv64_trap_handler` and `aarch64_trap_entry` do.
#[unsafe(no_mangle)]
pub extern "C" fn x86_64_trap_entry(_frame: &mut TrapFrame) {
    todo!("x86_64: x86_64_trap_entry: dispatch through TrapContext")
}

/// The preemption point on the way out of a trap.
#[unsafe(no_mangle)]
pub extern "C" fn x86_64_trap_resched() {
    todo!("x86_64: x86_64_trap_resched: schedule() if a reschedule is pending")
}

/// Every CPU exception before the real trap path exists (boot.S's IDT):
/// report and stop, instead of a triple fault.
#[unsafe(no_mangle)]
pub extern "C" fn x86_64_early_exception(vector: u64, error_code: u64, rip: u64) -> ! {
    azos_drv_sys::kprintln!("[X86] CPU exception {} (error code {:#x}) at rip {:#x}: no trap path yet, stopping",
        vector, error_code, rip);
    azos_arch::Boot::shutdown(&azos_arch::ARCH)
}
