// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-arch trap entry.
//!
//! Each ISA owns its native `TrapFrame`, the trap-entry asm that saves it
//! (`<isa>/asm/trap_entry.S`, landing pads included), the decode of that
//! frame into the common view (`impl Frame` / `impl ArchFrame`, in
//! `<isa>/trap.rs`), the cause decode that classifies a trap, and the
//! interrupt controller (`<isa>/irq.rs`: claim, complete, the line ladder).
//! What the kernel *does* with a trap (the syscall flow and its prologue, the
//! page-fault and exception policy, the fatal tail, the interrupt bracket, the
//! tick and the reschedule point) is `crate::trap`, written once and generic
//! over the frame; `tools/trap_lint.py` keeps it out of this directory.

pub mod aarch64;
pub mod riscv64;
pub mod x86_64;

/// This ISA's IPC fast path resume stub (Chain E commit 9), for
/// `azos_syscall::fastpath::set_resume_stub`.
pub(crate) fn ipc_resume_stub() -> usize {
    #[cfg(target_arch = "riscv64")]
    let pc = riscv64::ipc_resume_stub();
    #[cfg(target_arch = "aarch64")]
    let pc = aarch64::trap::ipc_resume_stub();
    #[cfg(target_arch = "x86_64")]
    let pc = x86_64::trap::ipc_resume_stub();
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
    compile_error!("entry::ipc_resume_stub: no resume stub for this ISA");
    pc
}
