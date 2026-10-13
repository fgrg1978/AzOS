// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//
// Context Switch (AArch64 Assembly) — Phase 3.
//
// Switches execution from one Task to another by saving/restoring the
// AAPCS64 callee-saved register set only (caller-saved regs are already on
// the stack of whoever called into `context_switch` — same reasoning as
// riscv64's `entry/riscv64/asm/context_switch.S`, which this file mirrors
// field-for-field where the ABI allows).
//
// fn context_switch(old: *mut Task, new: *mut Task)
//   x0 = old task pointer (NULL on first call)
//   x1 = new task pointer
//
// Task::context (TaskContext) is at offset 0 of Task (repr(C)), same
// contract as riscv64.
//
// ── What is saved, and why (owner brief: "decide on FP state") ─────────
//
// AAPCS64 callee-saved: x19-x28, x29 (frame pointer), x30 (LR), sp, and the
// LOW 64 BITS of v8-v15 (d8-d15). Only the GPR half is saved as part of the
// task context. The kernel is built for `aarch64-unknown-none-softfloat`
// ("the Linux way"), so no kernel code ever holds a value in d8-d15 across
// a call — there is nothing of the kernel's own to preserve, and
// `tools/aarch64_fp_free_check.sh` proves it on the linked ELF. The one FP
// thing this file does is the lazy-FP block at the top of `context_switch`:
// the outgoing task's USER FP state, saved into its per-task area
// (`kernel/src/entry/aarch64/fp_lazy.rs`) only if it is live on this hart.
// The `CTX_D*` offsets below are still injected (kernel/src/main.rs) but
// no longer used by any instruction.
//
// `tp` is not a literal GPR on this ISA, and — closed hazard, found during
// the aarch64 ipctest SMP-stall investigation — `CTX_TP` (`TaskContext::tp`)
// must NEVER be read into or written from `TPIDR_EL1` here. `TPIDR_EL1` is
// `current_cpu_id()`'s
// only source of truth for "which physical hart is this" (`crates/core/sched/
// src/smp.rs`); `context.tp` is pure scheduler bookkeeping — "which CPU's
// ready queue this task is logically enqueued on", written by the wake/
// placement paths in `crates/core/sched/src/scheduler.rs` and read back by
// `find_best_cpu`/`task_census` as plain memory, never as hart identity.
//
// This file used to `mrs`/`msr` `TPIDR_EL1` here on every switch, treating
// it as this ISA's `tp`-equivalent GPR — modelled on riscv64's own
// context_switch.S, which genuinely must save/restore `tp` because it is an
// ordinary GPR the compiler and the task's own code can touch. That mirror
// was the bug: riscv64 also has K-C16, which RE-ESTABLISHES `tp` from a
// known-good per-hart source at every trap entry, so a task's saved `tp` is
// never trusted for hart identity even there. This ISA had no counterpart —
// the old comment here said so and treated it as harmless ("no equivalent
// privilege-boundary hole"), which conflated "cannot be corrupted by ring 3"
// with "cannot be corrupted by the scheduler's own bookkeeping". It can: an
// unpinned task's `context.tp` records whichever CPU it was LAST placed on,
// and once any task is ever dispatched (context-switched into) on a hart
// that does not match that recording, `msr TPIDR_EL1, x9` below used to
// overwrite the PHYSICAL hart's own identity with the wrong logical CPU —
// permanently, self-perpetuating from then on: `current_cpu_id()` is wrong
// on every subsequent call this hart makes, including inside `schedule()`/
// `do_schedule()` themselves, so every task this hart ever enqueues afterward
// is enqueued under the WRONG cpu's ready queue and lock. Measured directly
// (aarch64 ipctest phase A, `-smp 2`): once triggered, every unpinned task
// placed on the victim hart's logical CPU index sits `Ready`, `queued=true`,
// correctly counted by `find_best_cpu`'s bookkeeping, and is never dequeued
// again — `cpu_dequeue_locked` on that logical index keeps running on
// whichever hart now (wrongly) claims that identity, never the physical one
// actually holding the ready-queue lock and bitmap the task sits in.
//
// `TPIDR_EL1` is instead a per-hart constant, published exactly once by
// `boot.S` (`msr TPIDR_EL1, x20`, primary and secondary paths both) before
// `kernel_main` ever runs, and never written again. `CTX_TP` stays a real
// `TaskContext` field — `crates/core/sched` still uses it as plain memory for
// placement bookkeeping — this file just no longer routes it through
// hardware.

// TaskContext field offsets — injected via `offset_of!` from
// kernel/src/main.rs's `global_asm!` block, never hand-copied (a past
// review finding on the riscv64 side: hand-written TrapFrame offsets).
.equ CTX_RA,   {ctx_ra}
.equ CTX_SP,   {ctx_sp}
.equ CTX_X19,  {ctx_x19}   // pair: x19/x20
.equ CTX_X21,  {ctx_x21}   // pair: x21/x22
.equ CTX_X23,  {ctx_x23}   // pair: x23/x24
.equ CTX_X25,  {ctx_x25}   // pair: x25/x26
.equ CTX_X27,  {ctx_x27}   // pair: x27/x28
.equ CTX_X29,  {ctx_x29}
.equ CTX_PC,   {ctx_pc}
.equ CTX_TP,   {ctx_tp}
// Length of `AZOS_TLB_SWITCH_FLUSH` (`azos_arch_api::tlb_gen::HARTS`, NR_CPUS).
.equ TLB_MAX_HARTS, {tlb_max_harts}
.equ CTX_D8,   {ctx_d8}    // pair: d8/d9
.equ CTX_D10,  {ctx_d10}   // pair: d10/d11
.equ CTX_D12,  {ctx_d12}   // pair: d12/d13
.equ CTX_D14,  {ctx_d14}   // pair: d14/d15

// Task struct offsets — same two constants riscv64's context_switch.S
// takes, same injection site (kernel/src/main.rs), same meaning.
.equ TASK_SATP_OFFSET,       {task_satp_off}
.equ TASK_CTX_SAVING_OFFSET, {context_saving_off}

// The kernel is soft-float; the lazy-FP save below names V registers on
// purpose.
.arch_extension fp
.arch_extension simd

.section .text
.align 4
.global context_switch

context_switch:
    // ── Lazy FP: the outgoing task's user FP state, if live here ────────
    //
    // `AARCH64_FP_LIVE[hart]` (kernel/src/entry/aarch64/fp_lazy.rs) is the
    // save area of the task whose user FP state is in this hart's V
    // registers with EL0 FP enabled, or 0 — always 0 for a task that has
    // not executed an FP instruction since it was switched in, which then
    // pays five instructions here and nothing else. When it is live: save
    // it, clear the entry and put CPACR_EL1.FPEN back to 0b01 (EL0 traps),
    // so the next user FP instruction on this hart — whoever runs it —
    // traps into `fp_lazy::first_use` and loads its own state. This runs
    // first, before the `context_saving` release below: that store is what
    // lets another hart reuse old's slot, and the area belongs to the slot.
    // With old == NULL (first switch, or a zombie whose slot was already
    // freed and may be re-initialised concurrently) nothing is written to
    // the area; the live state is only dropped. The hart index is
    // TPIDR_EL1, published once per hart by boot.S and range-checked there
    // against MAX_HARTS. x10-x14 are caller-saved scratch here.
    mrs  x10, TPIDR_EL1
    adrp x11, AARCH64_FP_LIVE
    add  x11, x11, :lo12:AARCH64_FP_LIVE
    add  x11, x11, x10, lsl #3
    ldr  x12, [x11]
    cbz  x12, .Lfp_not_live
    cbz  x0, .Lfp_drop
    stp  q0,  q1,  [x12, #0  * 16]
    stp  q2,  q3,  [x12, #2  * 16]
    stp  q4,  q5,  [x12, #4  * 16]
    stp  q6,  q7,  [x12, #6  * 16]
    stp  q8,  q9,  [x12, #8  * 16]
    stp  q10, q11, [x12, #10 * 16]
    stp  q12, q13, [x12, #12 * 16]
    stp  q14, q15, [x12, #14 * 16]
    stp  q16, q17, [x12, #16 * 16]
    stp  q18, q19, [x12, #18 * 16]
    stp  q20, q21, [x12, #20 * 16]
    stp  q22, q23, [x12, #22 * 16]
    stp  q24, q25, [x12, #24 * 16]
    stp  q26, q27, [x12, #26 * 16]
    stp  q28, q29, [x12, #28 * 16]
    stp  q30, q31, [x12, #30 * 16]
    mrs  x13, FPSR
    mrs  x14, FPCR
    str  w13, [x12, #512]
    str  w14, [x12, #516]
.Lfp_drop:
    str  xzr, [x11]
    mov  x13, #0x100000        // CPACR_EL1.FPEN = 0b01 (bits [21:20])
    msr  CPACR_EL1, x13
.Lfp_not_live:

    // If old == NULL, skip saving (first context switch) — mirrors
    // riscv64's `beqz a0, restore_new_task`.
    cbz x0, restore_new_task

save_old_task:
    stp x19, x20, [x0, #CTX_X19]
    stp x21, x22, [x0, #CTX_X21]
    stp x23, x24, [x0, #CTX_X23]
    stp x25, x26, [x0, #CTX_X25]
    stp x27, x28, [x0, #CTX_X27]
    str x29,      [x0, #CTX_X29]
    str x30,      [x0, #CTX_RA]

    mov x9, sp
    str x9,  [x0, #CTX_SP]

    // Save PC: when old is rescheduled, execution resumes after this call
    // (x30/LR at the point of this save IS that resume address — same
    // value as CTX_RA above, same reason riscv64 stores `ra` into both
    // CTX_RA and CTX_PC: a fresh, never-switched-out task's `pc` and `ra`
    // both start out equal to its entry point, so one restore path serves
    // both "jump here" and "return here" without a branch on which case
    // this is).
    str x30,      [x0, #CTX_PC]

    // No `TPIDR_EL1` save here — see this file's header
    // comment. `CTX_TP` is scheduler bookkeeping, not hart identity, and
    // this hart's `TPIDR_EL1` must stay exactly what `boot.S` published.

    // K-C23 equivalent: publish "old's stack is up for grabs" as the LAST
    // touch of anything old owns — mirrors riscv64's `fence rw, w` + `sb
    // zero`. `dmb ish` (inner-shareable full barrier) orders every store
    // above ahead of this one; `strb` then publishes the release. Same
    // reasoning as riscv64's own comment: this must stay inline (no `bl`),
    // because a call's own return sequence would run ON old's stack AFTER
    // the store already told another core that stack is free to reuse.
    dmb ish
    mov x9, #0
    strb w9, [x0, #TASK_CTX_SAVING_OFFSET]

restore_new_task:
    ldp x19, x20, [x1, #CTX_X19]
    ldp x21, x22, [x1, #CTX_X21]
    ldp x23, x24, [x1, #CTX_X23]
    ldp x25, x26, [x1, #CTX_X25]
    ldp x27, x28, [x1, #CTX_X27]
    ldr x29,      [x1, #CTX_X29]
    ldr x30,      [x1, #CTX_RA]

    ldr x9, [x1, #CTX_SP]
    mov sp, x9

    // Deliberately NOT restoring `TPIDR_EL1` from `CTX_TP` here
    // — see this file's header comment for the root-cause writeup. Unlike
    // riscv64's `tp` (a real GPR, restored as part of the ordinary callee-
    // saved set and then RE-ESTABLISHED from a known-good source at every
    // trap via K-C16), aarch64 has no per-task `tp` GPR to restore: the
    // physical hart's identity lives in `TPIDR_EL1` alone, is published once
    // by `boot.S`, and must never be overwritten by a task's own (possibly
    // stale, possibly wrong-hart) bookkeeping.

    // Load resume PC into a register the page-table switch below does not
    // touch, so it survives untouched to the final `br`.
    ldr x9, [x1, #CTX_PC]

    // Switch page table only if it actually changes — mirrors riscv64's
    // "kernel tasks share the same PT, skip the expensive flush", but the
    // SENTINEL MEANING OF ZERO IS DIFFERENT ON THIS ISA, and (closed
    // hazard, found during the aarch64 ipctest SMP-stall investigation)
    // "zero" must resolve to the KERNEL's own root, never to "whatever
    // TTBR0_EL1 already holds".
    //
    // riscv64's `task_satp` defaults to 0 for every task that has never had
    // a user address space (see `try_task_create_init`), and 0 there is a
    // VALID satp encoding: Sv39's MODE field clear means Bare (MMU off),
    // and riscv64's kernel is identity-mapped (VA==PA) for kernel space, so
    // running kernel code under Bare mode after that switch still resolves
    // every address correctly — weaker protection, not a crash.
    //
    // TTBR0_EL1 has no such reading. It is a physical table-base address,
    // not a mode field — writing 0 to it does not turn the MMU off (that is
    // SCTLR_EL1.M, untouched here); it means "walk page tables starting at
    // physical address 0", and this kernel deliberately leaves page 0
    // unmapped (`vmm::null_guard`, kernel_main). So this path never writes
    // a literal 0 to TTBR0_EL1 — `task_satp == 0` instead means "this task
    // wants the KERNEL's own root", resolved via `AARCH64_KERNEL_TTBR0`
    // (`entry/aarch64.rs`) below, the same compare-and-skip-if-unchanged
    // shape the nonzero (real user address space) case already had.
    //
    // **What broke before this fix, measured.** The comment this replaced
    // read task_satp == 0 as "skip the switch unconditionally — every task
    // this phase is a kernel task sharing the kernel's own TTBR0_EL1",
    // true on the milestone it was written for (Phase 3, before any user
    // task existed) and silently wrong from Phase 6 on: a hart that runs a
    // user task (task_satp = that task's own root) and is then dispatched
    // to ANY kernel task — idle most often, since it is the fallback every
    // hart lands on with nothing else ready — kept the user task's
    // TTBR0_EL1 loaded, unconditionally, forever, because `cbz x10,
    // ctx_skip_pt_switch` fired on the KERNEL task's zero `task_satp`
    // regardless of what was already loaded. Once that user task exited
    // and its page table's physical frames were freed and reused (ipctest's
    // own allocation churn), the idling hart was running under a dangling
    // root: kernel VAs that resolved a moment earlier stopped resolving,
    // most visibly right where the NEXT interrupt tried to build a trap
    // frame — a same-EL data abort (`_trap_common`'s FP/SIMD save, or
    // shortly after, depending on which kernel page the stale table still
    // happened to cover) with interrupts masked, taking the hart out of
    // GIC delivery permanently (no more ticks, no more IPIs, nothing ever
    // printed because the fault handler's own `kprintln!` needed the same
    // broken translation). This was the aarch64 ipctest ~20% `-smp 2`
    // stall: confirmed via the QEMU monitor (`gva2gpa` on the frozen CPU
    // resolved the kernel vector table's own VA as `Unmapped`, while the
    // same VA resolved fine on the surviving CPU) and via a temporary
    // idle-loop `TTBR0_EL1` publish that read back a stale user root, not
    // `AARCH64_KERNEL_TTBR0`'s value, right before the hart went dark.
    ldr x10, [x1, #TASK_SATP_OFFSET]
    cbnz x10, ctx_have_satp
    // task_satp == 0 — this task wants the kernel's own root. Read it by
    // fixed symbol name (see `AARCH64_KERNEL_TTBR0`'s doc comment) rather
    // than a Rust call: this is a plain AAPCS64 function body, so an
    // ordinary `adrp`/`ldr` pair is exactly as cheap and safe as any other
    // load in this file.
    adrp x10, AARCH64_KERNEL_TTBR0
    add  x10, x10, :lo12:AARCH64_KERNEL_TTBR0
    ldr  x10, [x10]
    // Not yet published (still early boot — `context_switch` is never
    // actually called this early, since scheduling starts well after
    // `kernel_main` publishes it, but this is a bare fallback rather than
    // a load-bearing assumption): 0 here still means "trust whatever is
    // loaded", the pre-fix behavior, never "install literal 0".
    cbz x10, ctx_skip_pt_switch
ctx_have_satp:
    // N12 (Kconfig TLB_RETAIN): `AZOS_TLB_SWITCH_FLUSH[hart]`, set by
    // `azos_sched::asid::prepare_switch` on this hart just before this call:
    // 0 = keep the TLB (user leaves are nG and the word carries the ASID),
    // 1 = flush when the root changes (the old behaviour), 2 = flush even
    // when it does not. The hart index is TPIDR_EL1 (see above).
    mrs  x12, TPIDR_EL1
    mov  x14, #1
    cmp  x12, #TLB_MAX_HARTS
    b.hs 2f
    adrp x13, AZOS_TLB_SWITCH_FLUSH
    add  x13, x13, :lo12:AZOS_TLB_SWITCH_FLUSH
    ldr  x14, [x13, x12, lsl #3]
2:
    mrs x11, TTBR0_EL1
    cmp x10, x11
    b.ne 3f
    cmp  x14, #2
    b.ne ctx_skip_pt_switch
    b    4f
3:
    msr TTBR0_EL1, x10
    isb                     // context-synchronize the TTBR0_EL1 write
    cbz  x14, ctx_skip_pt_switch
4:
    tlbi vmalle1            // stale translations under the old table
    dsb ish                 // completion of the invalidation
    isb                     // before any translation can use the new table

ctx_skip_pt_switch:
    br x9               // jump to new task's PC

.extern AARCH64_KERNEL_TTBR0
.extern AARCH64_FP_LIVE

.size context_switch, . - context_switch
