// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The aarch64 entry asm (`asm/*.S`), assembled into the kernel with the
//! constants each file takes from the Rust structs and Kconfig.

use core::arch::global_asm;
use crate::*;

// ── aarch64 boot + trap asm — Item 2 Stage 5 ────────────────────────────
//
// boot.S, trap_entry.S and context_switch.S; each file's header comment
// says what it covers. `max_harts` mirrors the riscv64 injection above —
// MAX_HARTS is defined below this block, which is fine: `const` items resolve by name
// within the module regardless of textual order.
#[cfg(target_arch = "aarch64")]
global_asm!(
    include_str!("asm/boot.S"),
    max_harts = const MAX_HARTS,
    // One constant, three consumers (Rust, this asm, the linker script's
    // ASSERT against `_kernel_va_offset_check`): a drift fails to LINK.
    kernel_va_offset = const azos_arch::mmu::KERNEL_VA_OFFSET,
    // The same tie for the granule: linker-aarch64.ld ASSERTs its
    // `AZOS_PAGE_SIZE` (kernel/build.rs) against `_azos_page_size_check`.
    page_size = const azos_arch::PAGE_SIZE,
    // Kconfig `A64_PAN` not `n`: boot.S may set PSTATE.PAN (when the ID
    // register says the core has it). The canary drops that probe.
    pan_allowed = const azos_arch_api::isa::aarch64::PAN.allowed() as u8,
    pan_unprobed = const cfg!(feature = "a64-pan-unprobed-canary") as u8,
    // The SCTLR_EL1 word both entry paths write (SPAN set; boot.S clears it
    // where PAN is in use). The canary skips the write: the firmware's word.
    sctlr_lo = const entry::aarch64::SCTLR_BOOT_LO,
    sctlr_hi = const entry::aarch64::SCTLR_BOOT_HI,
    sctlr_canary = const cfg!(feature = "el0-state-canary") as u8,
    // Kconfig `KASLR` not `n`: the image is linked position-independent, and
    // boot.S picks its base and applies its relocations before the jump to the
    // upper half (`aarch64_early_kaslr`).
    kaslr = const azos_arch::mmu::kaslr::ENABLED as u8,
    // The bootstrap map's DRAM gigabyte: boot.S rounds the image's address
    // down to it ("Where RAM is").
    boot_window_shift = const azos_arch::mmu::BOOT_WINDOW.trailing_zeros(),
);

// TrapFrame layout + vector-number constants (B2-01 pattern): read off the
// real `entry::aarch64::TrapFrame` struct and its `VEC_*` constants via
// size_of!/offset_of! rather than hand-copied literals — see that file's
// doc comment on why the size assert alone isn't enough (the padding
// story) and trap_entry.S's own header for how these operands are used.
#[cfg(target_arch = "aarch64")]
global_asm!(
    include_str!("asm/trap_entry.S"),
    trap_frame_size = const core::mem::size_of::<entry::aarch64::TrapFrame>(),
    tf_off_elr      = const core::mem::offset_of!(entry::aarch64::TrapFrame, elr_el1),
    tf_off_spsr     = const core::mem::offset_of!(entry::aarch64::TrapFrame, spsr_el1),
    tf_off_sp_el0   = const core::mem::offset_of!(entry::aarch64::TrapFrame, sp_el0),
    tf_off_far      = const core::mem::offset_of!(entry::aarch64::TrapFrame, far_el1),
    tf_off_esr      = const core::mem::offset_of!(entry::aarch64::TrapFrame, esr_el1),
    tf_off_vector   = const core::mem::offset_of!(entry::aarch64::TrapFrame, vector),
    vec_sync_cur    = const entry::aarch64::VEC_SYNC_CURRENT_EL_SP0,
    vec_irq_cur     = const entry::aarch64::VEC_IRQ_CURRENT_EL_SP0,
    vec_sync_lo     = const entry::aarch64::VEC_SYNC_LOWER_EL,
    vec_irq_lo      = const entry::aarch64::VEC_IRQ_LOWER_EL,
    // Same constants riscv64's own trap_entry.S takes above — MAX_HARTS is
    // ISA-neutral (defined once, below, for both boot.S files already);
    // AARCH64_IRQ_STACK_SIZE mirrors riscv64's IRQ_STACK_SIZE (task 1: "IRQs
    // taken on a per-CPU IRQ stack", the same shape, not a copy of riscv64's
    // own slots — see that const's doc comment).
    max_harts       = const MAX_HARTS,
    irq_stack_size  = const IRQ_STACK_SIZE,
    // Chain E commit 8: the native `svc` path (Kconfig SYSCALL_LEAN_ENTRY),
    // the frame tag it tests, and its canary.
    syscall_lean    = const azos_limits::SYSCALL_LEAN_ENTRY as u32,
    tf_off_tag      = const core::mem::offset_of!(entry::aarch64::TrapFrame, syscall_tag),
    syscall_abi_canary = const cfg!(feature = "syscall-abi-canary") as u32,
    syscall_abi_canary_a1_lo = const azos_abi::syscall_nr::SYSCALL_ABI_CANARY_A1 & 0xffff,
    syscall_abi_canary_a1_hi = const (azos_abi::syscall_nr::SYSCALL_ABI_CANARY_A1 >> 16) & 0xffff,
    // Chain E commit 9: the IPC fast path's resume stub reads the task's
    // `reap_on_resume` (Kconfig IPC_FASTPATH_RESUME).
    task_reap_off   = const core::mem::offset_of!(azos_sched::task::Task, reap_on_resume),
    resume_exit_call = const azos_sched::scheduler::IPC_FAST_EXIT_CALL as u32,
    // Chain E cut 7: the native path's branch for the two IPC fast calls.
    ipc_fast_entry  = const IPC_FAST_ENTRY as u32,
    ipc_fast_lo     = const IPC_FAST_LO,
    // Kconfig A64_PAUTH_PROC_KEYS: the per-process key swap at the EL0 boundary.
    pac_user        = const azos_limits::A64_PAUTH_PROC_KEYS as u32,
);

// Context switch asm — Phase 3 (context switch + scheduler on aarch64).
// Same B2-01 shape as the two blocks above: every offset read off the real
// `azos_sched::task::TaskContext` / `Task` structs via `offset_of!`,
// never hand-copied. `task_satp_off`/`context_saving_off` are the SAME two
// constants riscv64's own context_switch.S takes above (same fields, same
// meaning — see that block's comment) — not a second, drifting copy.
#[cfg(target_arch = "aarch64")]
global_asm!(
    include_str!("asm/context_switch.S"),
    tlb_max_harts = const azos_arch_api::tlb_gen::HARTS,
    ctx_ra  = const core::mem::offset_of!(azos_sched::task::TaskContext, ra),
    ctx_sp  = const core::mem::offset_of!(azos_sched::task::TaskContext, sp),
    ctx_x19 = const core::mem::offset_of!(azos_sched::task::TaskContext, x19),
    ctx_x21 = const core::mem::offset_of!(azos_sched::task::TaskContext, x21),
    ctx_x23 = const core::mem::offset_of!(azos_sched::task::TaskContext, x23),
    ctx_x25 = const core::mem::offset_of!(azos_sched::task::TaskContext, x25),
    ctx_x27 = const core::mem::offset_of!(azos_sched::task::TaskContext, x27),
    ctx_x29 = const core::mem::offset_of!(azos_sched::task::TaskContext, x29),
    ctx_pc  = const core::mem::offset_of!(azos_sched::task::TaskContext, pc),
    ctx_tp  = const core::mem::offset_of!(azos_sched::task::TaskContext, tp),
    task_satp_off = const core::mem::offset_of!(azos_sched::task::Task, task_satp),
    context_saving_off = const core::mem::offset_of!(azos_sched::task::Task, context_saving),
);
