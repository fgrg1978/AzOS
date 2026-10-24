// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The riscv64 entry asm (`asm/*.S`), assembled into the kernel with the
//! constants each file takes from the Rust structs and Kconfig.

use core::arch::global_asm;
use crate::*;

// Include boot assembly
// All these .S files are RISC-V; lives in entry/riscv64/asm per Item 2
// Stage 3 batch 7 (per-arch entry organisation).  aarch64 boot/trap asm
// sits in entry/aarch64/asm — currently a stub README; will get the real
// asm in Stage 5 when the kernel boots on that ISA. (x86_64's entry/
// scaffolding was deleted 2026-09-21, B2-04.)
// `max_harts` is injected rather than duplicated: both files size per-hart
// tables (`secondary_stacks`, K-C16's trap vectors) and a hand-written `.equ`
// in each is exactly the class of constant that drifts out of sync silently —
// here the symptom would be a hart writing outside its own slot.
#[cfg(target_arch = "riscv64")]
global_asm!(
    include_str!("asm/boot.S"),
    max_harts = const MAX_HARTS,
    // Kconfig `KASLR` not `n`: the image is linked position-independent, and
    // boot.S picks its base, applies its relocations and jumps to it
    // (`riscv64_early_kaslr`, crates/core/arch-riscv64/src/mmu/kaslr_boot.rs).
    kaslr = const azos_arch::mmu::kaslr::ENABLED as u8,
);

// Include trap entry assembly.
// B2-01: the six TrapFrame layout constants (TRAP_FRAME_SIZE, TF_SEPC,
// TF_SSTATUS, TF_SCAUSE, TF_STVAL, TF_SP) used to be `.equ`-hand-written in
// trap_entry.S with a comment claiming they matched "crates/core/arch/src/
// trap.rs" — a facade that only re-exports; the struct lives in
// crates/core/arch-riscv64/src/trap.rs and had no compile-time link to that
// comment at all. Injected here the same way task_satp_off/context_saving_off
// are below: size_of!/offset_of! read the real struct, so a field added
// before `sepc` moves every one of these automatically instead of silently
// disagreeing with a hand-copied number.
#[cfg(target_arch = "riscv64")]
global_asm!(
    include_str!("asm/trap_entry.S"),
    max_harts = const MAX_HARTS,
    irq_stack_size = const IRQ_STACK_SIZE,
    trap_frame_size = const core::mem::size_of::<TrapFrame>(),
    tf_sepc = const core::mem::offset_of!(TrapFrame, sepc),
    tf_sstatus = const core::mem::offset_of!(TrapFrame, sstatus),
    tf_scause = const core::mem::offset_of!(TrapFrame, scause),
    tf_stval = const core::mem::offset_of!(TrapFrame, stval),
    // regs[2] = saved SP (x2); the asm's `TF_SP(sp)` accesses assume `regs`
    // sits at offset 0 (see the assert next to TrapFrame in trap.rs) — this
    // still reads the offset rather than hardcoding it so a reordering of
    // TrapFrame's own fields cannot silently break the SP save/restore.
    tf_sp = const core::mem::offset_of!(TrapFrame, regs) + 2 * 8,
    // Chain E commit 8: the native syscall path (Kconfig
    // SYSCALL_LEAN_ENTRY), the frame tag in the never-saved x0 slot, and
    // the canary that flips one callee-saved bit on its exit.
    syscall_lean = const azos_limits::SYSCALL_LEAN_ENTRY as u32,
    tf_tag = const core::mem::offset_of!(TrapFrame, regs),
    syscall_abi_canary = const cfg!(feature = "syscall-abi-canary") as u32,
    syscall_abi_canary_a1 = const azos_abi::syscall_nr::SYSCALL_ABI_CANARY_A1,
    // Chain E commit 9: the IPC fast path's resume stub reads the task's
    // `reap_on_resume` (Kconfig IPC_FASTPATH_RESUME).
    task_reap_off = const core::mem::offset_of!(azos_sched::task::Task, reap_on_resume),
    resume_exit_call = const azos_sched::scheduler::IPC_FAST_EXIT_CALL as u32,
    // Chain E cut 7: the native path's branch for the two IPC fast calls.
    ipc_fast_entry = const IPC_FAST_ENTRY as u32,
    ipc_fast_lo = const IPC_FAST_LO,
);

// Include context switch assembly.
// Phase 12: when rvv feature is active, use the RVV-aware variant.
// TASK_SATP_OFFSET is injected at compile time via offset_of! — if someone
// adds fields before task_satp, the offset updates automatically.
#[cfg(target_arch = "riscv64")]
#[cfg(not(feature = "rvv"))]
global_asm!(
    include_str!("asm/context_switch.S"),
    task_satp_off = const core::mem::offset_of!(azos_sched::task::Task, task_satp),
    // K-C23: context_saving is cleared straight from the asm (fence + sb) —
    // a Rust helper's Release store publishes the old task's stack as
    // reusable while still running ON that stack, so the helper must not
    // have a frame; injecting the offset keeps the asm store correct even
    // if fields move. (Passed to context_switch_rvv.S below as well, since
    // 2026-09-24: that file clears the flag with the same tail now, so the
    // two switches take the identical pair of offsets from this one site.)
    context_saving_off = const core::mem::offset_of!(azos_sched::task::Task, context_saving),
    // The TLB root table (`TLB_MAX_HARTS`) is the same Kconfig `NR_CPUS` long.
    tlb_max_harts = const MAX_HARTS,
    ipc_resume_points = const azos_syscall::fastpath::RESUME as u32,
);
#[cfg(target_arch = "riscv64")]
#[cfg(feature = "rvv")]
global_asm!(
    include_str!("asm/context_switch_rvv.S"),
    task_satp_off = const core::mem::offset_of!(azos_sched::task::Task, task_satp),
    // Passed since 2026-09-24: this file now clears `context_saving` with the
    // same K-C23 fence+sb release tail as the scalar switch, so it needs the
    // same offset. It used to take only `task_satp_off` — and the scheduler
    // paid for that with twelve `cfg` sites that compiled the K-C24
    // double-dispatch protection out of every rvv build, `k1` included.
    context_saving_off = const core::mem::offset_of!(azos_sched::task::Task, context_saving),
    // TID for rvv_ctx_save/rvv_ctx_restore's VEC_STATES[] index — read here
    // via offset_of! and loaded in the .S at each call site, replacing a
    // `task_ptr.add(120)` read inside fp.rs that was actually
    // TaskContext.tp (the hart id, CTX_TP = 120 in context_switch.S), not
    // Task.tid (offset 128). Every context switch under `rvv` was
    // saving/restoring v0-v31/vl/vtype/vstart into the wrong slot.
    task_tid_off = const core::mem::offset_of!(azos_sched::task::Task, tid),
    ipc_resume_points = const azos_syscall::fastpath::RESUME as u32,
    // The TLB root table (`TLB_MAX_HARTS`) is the same Kconfig `NR_CPUS` long.
    tlb_max_harts = const MAX_HARTS,
);
