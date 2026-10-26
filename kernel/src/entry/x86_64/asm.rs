// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The x86_64 entry asm (`asm/*.S`), assembled into the kernel with the
//! constants each file takes from the Rust structs and Kconfig.

use core::arch::global_asm;
use crate::*;

// x86_64: the PVH boot path (boot.S: baseline check, long mode, IDT, then
// kernel_main) and the trap / switch stubs, AT&T syntax like the other
// ISAs' files. `x86_level` is Kconfig X86_64_LEVEL, checked by CPUID before
// any code compiled for that level runs.
// arch-only: x86_64's own asm files and level; each ISA includes its own.
#[cfg(target_arch = "x86_64")]
global_asm!(
    include_str!("asm/boot.S"),
    x86_level = const X86_64_LEVEL,
    // 1 = the Limine entry (`_limine_start`) is assembled too (feature x86-limine).
    x86_limine = const cfg!(feature = "x86-limine") as u32,
    // One constant, three consumers (Rust, this asm, linker-x86_64.ld's
    // ASSERT against `_kernel_va_offset_check`), as on aarch64.
    kva = const azos_arch::mmu::KERNEL_VA_OFFSET,
    // The direct map's base (RAM, page tables), mapped by boot.S's tables too.
    dmb = const azos_arch::mmu::DIRECT_MAP_BASE,
    // Kconfig `KASLR` not `n`: the image is linked position-independent, and
    // `long_entry` picks its base and applies its relocations
    // (`x86_64_early_kaslr`, arch/x86_64/src/mmu/kaslr_boot.rs).
    kaslr = const azos_arch::mmu::kaslr::ENABLED as u8,
    options(att_syntax),
);
// The trap entry and the switch: every TrapFrame / PerCpu / TaskContext /
// Task offset read off the real structs (B2-01), as for the other ISAs.
#[cfg(target_arch = "x86_64")]
global_asm!(
    include_str!("asm/trap_entry.S"),
    tf_size        = const core::mem::size_of::<entry::x86_64::TrapFrame>(),
    tf_cr2         = const core::mem::offset_of!(entry::x86_64::TrapFrame, cr2),
    tf_gs_saved    = const core::mem::offset_of!(entry::x86_64::TrapFrame, gs_saved),
    tf_vector      = const core::mem::offset_of!(entry::x86_64::TrapFrame, vector),
    tf_rip         = const core::mem::offset_of!(entry::x86_64::TrapFrame, rip),
    tf_cs          = const core::mem::offset_of!(entry::x86_64::TrapFrame, cs),
    tf_rflags      = const core::mem::offset_of!(entry::x86_64::TrapFrame, rflags),
    tf_rsp         = const core::mem::offset_of!(entry::x86_64::TrapFrame, rsp),
    r_rax          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::RAX),
    r_rbx          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::RBX),
    r_rcx          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::RCX),
    r_rdx          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::RDX),
    r_rsi          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::RSI),
    r_rdi          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::RDI),
    r_rbp          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::RBP),
    r_r8           = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::R8),
    r_r9           = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::R9),
    r_r10          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::R10),
    r_r11          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::R11),
    r_r12          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::R12),
    r_r13          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::R13),
    r_r14          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::R14),
    r_r15          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::R15),
    pc_kernel_rsp  = const azos_arch::cpu::PERCPU_KERNEL_RSP,
    pc_user_rsp    = const azos_arch::cpu::PERCPU_USER_RSP,
    pc_fp_live     = const azos_arch::cpu::PERCPU_FP_LIVE,
    pc_tss_rsp0    = const azos_arch::cpu::PERCPU_TSS_RSP0,
    syscall_vector = const azos_arch::trap::idt::SYSCALL_VECTOR,
    first_interrupt = const azos_arch::trap::idt::FIRST_INTERRUPT,
    user_cs        = const azos_arch::trap::gdt::USER_CS,
    user_ds        = const azos_arch::trap::gdt::USER_DS,
    irq_handler_stack = const entry::x86_64::ext::cpu_init::IRQ_HANDLER_STACK,
    rflags_tf_rf   = const azos_arch::cpu::RFLAGS_TF | azos_arch::cpu::RFLAGS_RF,
    use_sysret     = const azos_limits::X86_SYSRET as u32,
    smap_clac      = const azos_arch_api::isa::x86_64::SMAP.allowed() as u32,
    mit_verw       = const (azos_arch_api::isa::x86_64::MIT_MDS_TAA.allowed()
                            || azos_arch_api::isa::x86_64::MIT_RFDS.allowed()) as u32,
    kernel_ds      = const azos_arch::trap::gdt::KERNEL_DS,
    // The swapgs fence (Kconfig MITIGATION_SPECTRE_V1_INDEX, K1 L15).
    mit_swapgs     = const azos_limits::MITIGATION_SPECTRE_V1_INDEX as u32,
    // Chain E commit 8: the native syscall path (Kconfig SYSCALL_LEAN_ENTRY)
    // and its canary.
    syscall_lean   = const azos_limits::SYSCALL_LEAN_ENTRY as u32,
    syscall_abi_canary = const cfg!(feature = "syscall-abi-canary") as u32,
    syscall_abi_canary_a1 = const azos_abi::syscall_nr::SYSCALL_ABI_CANARY_A1,
    // Chain E commit 9: the IPC fast path's resume stub reads the task's
    // `reap_on_resume` (Kconfig IPC_FASTPATH_RESUME).
    task_reap_off  = const core::mem::offset_of!(azos_sched::task::Task, reap_on_resume),
    resume_exit_call = const azos_sched::scheduler::IPC_FAST_EXIT_CALL as u32,
    // Chain E cut 7: the native path's branch for the two IPC fast calls.
    ipc_fast_entry = const IPC_FAST_ENTRY as u32,
    ipc_fast_lo    = const IPC_FAST_LO,
    options(att_syntax),
);
#[cfg(target_arch = "x86_64")]
global_asm!(
    include_str!("asm/context_switch.S"),
    ctx_ra  = const core::mem::offset_of!(azos_sched::task::TaskContext, ra),
    ctx_sp  = const core::mem::offset_of!(azos_sched::task::TaskContext, sp),
    ctx_rbx = const core::mem::offset_of!(azos_sched::task::TaskContext, rbx),
    ctx_rbp = const core::mem::offset_of!(azos_sched::task::TaskContext, rbp),
    ctx_r12 = const core::mem::offset_of!(azos_sched::task::TaskContext, r12),
    ctx_r13 = const core::mem::offset_of!(azos_sched::task::TaskContext, r13),
    ctx_r14 = const core::mem::offset_of!(azos_sched::task::TaskContext, r14),
    ctx_r15 = const core::mem::offset_of!(azos_sched::task::TaskContext, r15),
    ctx_pc  = const core::mem::offset_of!(azos_sched::task::TaskContext, pc),
    task_satp_off = const core::mem::offset_of!(azos_sched::task::Task, task_satp),
    context_saving_off = const core::mem::offset_of!(azos_sched::task::Task, context_saving),
    pc_fp_live = const azos_arch::cpu::PERCPU_FP_LIVE,
    // 1 when the kernel is built with the external indirect-branch thunk
    // (tools/build/kconfig_to_cargo.py: X86_MIT_SPECTRE_V2 = probe).
    mit_thunk = const matches!(azos_arch_api::isa::x86_64::MIT_SPECTRE_V2, azos_arch_api::isa::ExtPolicy::Probe) as u32,
    // 1 when the kernel is built with ENDBR64 pads (Kconfig X86_CET_IBT not n):
    // the resume may not be an indirect jump then.
    cet_ibt = const azos_arch_api::isa::x86_64::CET_IBT.allowed() as u32,
    options(att_syntax),
);
