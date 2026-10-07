// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//
// x86_64 trap entry — SKELETON. Not assembled by any build; it lists what
// the real file must do, matched to kernel/src/entry/(riscv64, aarch64)/asm/
// trap_entry.S.
//
// Exports:
//   _vectors               the 256-entry IDT stubs (vector number pushed,
//                          a dummy error code for vectors without one)
//   syscall_entry          the `syscall` target (IA32_LSTAR), with
//                          IA32_STAR/IA32_FMASK set at boot
//   trap_return            restore a TrapFrame and iretq / sysretq
//   x86_64_ret_to_user     first entry to ring 3 (riscv64 sret_to_user,
//                          aarch64 aarch64_ret_to_user)
// Calls:
//   x86_64_trap_entry(&mut TrapFrame)     the Rust dispatcher in
//                          kernel/src/entry/x86_64.rs (riscv64_trap_handler /
//                          aarch64_trap_entry), which routes through
//                          TrapContext to trap::interrupt / trap::exception
//   x86_64_trap_resched                   preemption point on the way out
//                          (trap_resched / aarch64_trap_resched)
//
// Per entry:
//   1. From ring 3: swapgs (kernel GS = per-CPU base); RSP from the TSS
//      (interrupts) or from the per-CPU kernel stack (syscall, which does
//      not switch stacks itself).
//   2. Save the general registers into the TrapFrame layout
//      kernel/src/entry/x86_64.rs declares; CR2 for #PF (fault_addr).
//   3. The IRQ stack on hardware interrupts (AZOS_IRQ_STACK_BASE[cpu]).
//   4. call x86_64_trap_entry; on return, x86_64_trap_resched if a
//      reschedule is pending, restore, swapgs back if returning to ring 3,
//      then iretq (or sysretq on the syscall path, with the canonical-RIP
//      check Linux does before it).
//   5. Spectre/MDS hygiene on the user boundary as the mitigation Kconfig
//      symbols select (verw, IBRS/eIBRS, retpoline thunks).

    .text
    .globl _vectors
    .globl syscall_entry
    .globl trap_return
    .globl x86_64_ret_to_user
_vectors:
syscall_entry:
trap_return:
x86_64_ret_to_user:
    ud2
