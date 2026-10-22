# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Context Switch (RISC-V Assembly)
#
# Switches execution from one Task to another by saving/restoring
# callee-saved registers only (caller-saved are on the stack already,
# per RISC-V calling convention).
#
# fn context_switch(old: *mut Task, new: *mut Task)
#   a0 = old task pointer (NULL on first call)
#   a1 = new task pointer
#
# Task::context (TaskContext) is at offset 0 of Task (repr(C)).

.option arch, +m, +a, +c, +zicsr, +zifencei, +zaamo, +zalrsc, +zmmul

# TaskContext field offsets (8 bytes each, RV64)
# Must match crates/core/sched/src/task.rs TaskContext layout.
.equ CTX_RA,   0
.equ CTX_SP,   8
.equ CTX_S0,  16
.equ CTX_S1,  24
.equ CTX_S2,  32
.equ CTX_S3,  40
.equ CTX_S4,  48
.equ CTX_S5,  56
.equ CTX_S6,  64
.equ CTX_S7,  72
.equ CTX_S8,  80
.equ CTX_S9,  88
.equ CTX_S10, 96
.equ CTX_S11, 104
.equ CTX_PC,  112
.equ CTX_TP,  120

# Task struct offsets — auto-generated via offset_of! in main.rs
.equ TASK_SATP_OFFSET,       {task_satp_off}
# Length of `AZOS_HART_SATP` (`azos_arch::tlb::TLB_MAX_HARTS`, Kconfig
# `NR_CPUS`), injected by the `global_asm!` block in kernel/src/main.rs. It
# was a literal 8 here: past it a hart skipped publishing its root and
# `tlb::shootdown` never signalled it.
.equ TLB_MAX_HARTS,          {tlb_max_harts}
.equ TASK_CTX_SAVING_OFFSET, {context_saving_off}
# azos_syscall::fastpath::RESUME: a saved context may start at
# `riscv64_ipc_resume_stub` (see restore_new_task).
.equ IPC_RESUME_POINTS,      {ipc_resume_points}

.section .text
.align 4
.global context_switch

context_switch:
    # If old == NULL, skip saving (first context switch)
    beqz a0, restore_new_task

save_old_task:
    # Save callee-saved registers to old->context (offset 0)
    sd ra,  CTX_RA(a0)
    sd sp,  CTX_SP(a0)
    sd s0,  CTX_S0(a0)
    sd s1,  CTX_S1(a0)
    sd s2,  CTX_S2(a0)
    sd s3,  CTX_S3(a0)
    sd s4,  CTX_S4(a0)
    sd s5,  CTX_S5(a0)
    sd s6,  CTX_S6(a0)
    sd s7,  CTX_S7(a0)
    sd s8,  CTX_S8(a0)
    sd s9,  CTX_S9(a0)
    sd s10, CTX_S10(a0)
    sd s11, CTX_S11(a0)
    sd tp,  CTX_TP(a0)

    # Save PC: when old is rescheduled, execution resumes after this call.
    sd ra,  CTX_PC(a0)

    # Mark old task's context as safely saved now that every callee-saved
    # register + PC has been written to old->context. Closes the SMP race
    # where a waker on another hart could see old's new state (Blocked, or
    # Ready after preemption) and try to dispatch it before this save
    # finished.
    #
    # K-C23: this store is a RELEASE publish of "old's stack is up for
    # grabs", and it must be the LAST touch of anything old owns — the
    # moment it lands, another hart may dispatch old and start pushing
    # frames onto that stack. It used to be `call mark_context_saved`, a
    # Rust helper whose Release store had exactly that meaning while its
    # own return sequence still ran on old's stack: correct only while
    # rustc kept it a frameless leaf, and one kprintln/wcet-probe/dev-build
    # prologue away from an S-mode stack race. Inline asm has no frame by
    # construction. `fence rw, w` + plain store = Release on RV64; `sb`
    # because AtomicBool is one byte. a0 still holds the old Task pointer —
    # nothing above clobbers it — and a1 (new) no longer needs the s0
    # shuffle the call required.
    fence rw, w
    sb   zero, TASK_CTX_SAVING_OFFSET(a0)

restore_new_task:
    # Restore callee-saved registers from new->context
    ld sp,  CTX_SP(a1)
    # Chain E commit 9 (Kconfig IPC_FASTPATH_RESUME): a context the IPC fast
    # path pointed at its resume stub starts there with only sp, a1 (new)
    # and tp; the stub's exits (`trap_native_return`, `trap_return`) reload
    # ra and s0-s11 from the trap frame, and the stub's own `call` writes ra.
    # So skip the thirteen loads of what that context last saved (the
    # frames it blocked in are abandoned); the save side above is unchanged.
    # Every other switch pays the `la` and the branch.
    ld t0,  CTX_PC(a1)
.if IPC_RESUME_POINTS
    la   t3, riscv64_ipc_resume_stub
    beq  t0, t3, ctx_callee_saved_skipped
.endif
    ld ra,  CTX_RA(a1)
    ld s0,  CTX_S0(a1)
    ld s1,  CTX_S1(a1)
    ld s2,  CTX_S2(a1)
    ld s3,  CTX_S3(a1)
    ld s4,  CTX_S4(a1)
    ld s5,  CTX_S5(a1)
    ld s6,  CTX_S6(a1)
    ld s7,  CTX_S7(a1)
    ld s8,  CTX_S8(a1)
    ld s9,  CTX_S9(a1)
    ld s10, CTX_S10(a1)
    ld s11, CTX_S11(a1)
ctx_callee_saved_skipped:
    # K-A11 / K1 M2: `tp` is this hart's id, and a context switch never
    # changes hart, so the incoming task runs with the `tp` already here; it
    # is not loaded from `new->context.tp`. That word is placement
    # bookkeeping only (the CPU a task last ran on or is queued for: the
    # scheduler's wake and rebalance paths read it, the save above writes
    # it). Loading it could only match the hardware id or be wrong: a stale
    # word (an enqueue racing the previous hart's save) made this hart run as
    # another CPU, every later `PER_CPU[current_cpu_id()]` then naming the
    # wrong ready queue and `current_idx`. context_switch_rvv.S and the
    # aarch64 and x86_64 switches keep the hardware id the same way.
    #
    # K-C16 (trap_entry.S): a trap from U-mode re-establishes the kernel `tp`
    # from the per-hart trap vector before any Rust runs, so the `tp` saved
    # above is always a genuine hart id, never one ring 3 supplied.

    # Load PC
    # (t0 = CTX_PC: loaded above)

    # Switch page table only if SATP actually changes.
    # Kernel tasks share the same PT — skip the expensive sfence.vma.
    ld t1,  TASK_SATP_OFFSET(a1)
    csrr t2, satp
    # N12 (Kconfig TLB_RETAIN): `AZOS_TLB_SWITCH_FLUSH[hart]`, set by
    # `azos_sched::asid::prepare_switch` on this hart just before this call:
    # 0 = keep the TLB (ASID-tagged, same generation), 1 = flush when the
    # root changes (TLB_RETAIN off, or no ASID bits: the old behaviour),
    # 2 = flush even when it does not (a rollover or a skipped shootdown).
    li   t5, 1
    li   t3, TLB_MAX_HARTS
    bgeu tp, t3, 2f
    la   t3, AZOS_TLB_SWITCH_FLUSH
    slli t4, tp, 3
    add  t3, t3, t4
    ld   t5, 0(t3)
2:
    bne t1, t2, ctx_do_pt_switch
    li   t3, 2
    bne  t5, t3, ctx_skip_pt_switch
    sfence.vma zero, zero
    j    ctx_skip_pt_switch
ctx_do_pt_switch:
    # TLB shootdown bookkeeping (crates/core/arch-riscv64/src/tlb.rs): publish the
    # root this hart is about to translate through, BEFORE the csrw, fenced,
    # so a remote `tlb::shootdown` either sees it or this hart's walk after
    # the sfence below sees the shooter's PTE store. Indexed by `tp`, this
    # hart's id (the switch never changes it). Only this path pays (a real
    # address-space change, which already pays a full flush).
    li   t3, TLB_MAX_HARTS
    bgeu tp, t3, 1f
    la   t3, AZOS_HART_SATP
    slli t4, tp, 3
    add  t3, t3, t4
    sd   t1, 0(t3)
    fence rw, rw
1:
    csrw satp, t1
    beqz t5, ctx_skip_pt_switch
    sfence.vma zero, zero

ctx_skip_pt_switch:
    jr t0              # Jump to new task's PC

.size context_switch, . - context_switch
