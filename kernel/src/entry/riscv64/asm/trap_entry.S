# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Trap Entry Point (Assembly)
# RISC-V trap handler entry point
#
# Entered when any trap (exception or interrupt) occurs.
# Saves all registers, calls Rust trap_handler, restores state.
#
# Stack Switching for U-mode traps:
#   sscratch holds kernel SP when in U-mode (0 when in S-mode).
#   On trap: swap SP <-> sscratch to get kernel stack.
#
# K-C16: the kernel `tp` (= hart id) is re-established from the per-hart trap
# vector on every trap taken from U-mode.  See the block comment above
# `trap_hart_vectors` for the full rationale.

.option arch, +m, +a, +c, +zicsr, +zifencei, +zaamo, +zalrsc, +zmmul

# TrapFrame layout constants (B2-01).
# NOT hand-duplicated: these six were `.equ N` literals with a comment
# claiming they matched "crates/core/arch/src/trap.rs" — that path is an 18-line
# facade, not the struct, and nothing checked the numbers against either.
# `{trap_frame_size}` / `{tf_sepc}` / `{tf_sstatus}` / `{tf_scause}` /
# `{tf_stval}` / `{tf_sp}` are substituted by the `global_asm!(...)` block in
# kernel/src/main.rs via `size_of::<TrapFrame>()` / `offset_of!(TrapFrame,
# ..)` on the real struct in crates/core/arch-riscv64/src/trap.rs — the same
# technique this file already uses for `{max_harts}` / `{irq_stack_size}`
# below and context_switch.S uses for `task_satp_off`. A field added before
# `sepc` moves these automatically instead of silently disagreeing with a
# hand-copied number.
.equ TRAP_FRAME_SIZE, {trap_frame_size}   # size_of::<TrapFrame>()
.equ TF_SEPC,         {tf_sepc}           # offset of sepc    in TrapFrame
.equ TF_SSTATUS,      {tf_sstatus}        # offset of sstatus in TrapFrame
.equ TF_SCAUSE,       {tf_scause}         # offset of scause  in TrapFrame
.equ TF_STVAL,        {tf_stval}          # offset of stval   in TrapFrame
.equ TF_SP,           {tf_sp}             # offset of regs[2] (saved SP)

# sstatus bit constants
.equ SSTATUS_SPP, (1 << 8)        # Supervisor Previous Privilege

# Number of harts with a dedicated trap-vector slot.
# NOT hand-duplicated: `{max_harts}` is substituted by the
# `global_asm!(..., max_harts = const MAX_HARTS)` block in
# kernel/src/main.rs — same technique as context_switch.S's `task_satp_off`.
# kernel/src/main.rs::MAX_HARTS is the single source; do not replace this
# with a literal.
.equ MAX_HARTS, {max_harts}

# Size of one hart's interrupt stack, from CONFIG_INTERRUPT_STACK_SIZE_KB
# through the same global_asm! substitution.  The stacks themselves are in
# the per-CPU areas, reached through `AZOS_IRQ_STACK_BASE` (kernel/src/main.rs);
# one hand-written size here and another there is the class of constant that
# drifts silently, and the symptom would be a hart running off the end of its
# stack into whatever lies below it.
.equ IRQ_STACK_SIZE, {irq_stack_size}

.section .text

# ── K-C16: per-hart trap vectors ────────────────────────────────────────────
#
# THE BUG.  In this kernel `tp` carries the hart id: `boot.S` sets `tp =
# hart_id` and `sched::smp::current_cpu_id()` is literally `mv rd, tp`, so
# every `PER_CPU[current_cpu_id()]` access depends on it.  The trap entry used
# to save the incoming `tp` into the frame and never re-establish a kernel
# value, which means that after ANY trap from U-mode the kernel ran on the
# `tp` ring 3 handed it.  A user task that writes `tp` and issues an `ecall`
# makes the kernel believe it is on another hart: wrong ready queue, wrong
# "current task", wrong scheduler state — a privilege-boundary hole reachable
# from ring 3 with no privileges at all.  It only failed to explode because no
# program in this tree happens to touch `tp` (there is no TLS here).  That is
# a convention, not a defence.
#
# WHERE THE HART ID COMES FROM.  RISC-V gives S-mode no `mhartid`, and this
# kernel already spends `sscratch` on the kernel SP (`csrrw sp, sscratch, sp`
# at the top of the entry), so the usual "sscratch points at a per-hart
# struct" trick is not available without rewriting every writer of sscratch —
# including two `csrw sscratch, sp` sites in Rust (crates/core/sched/src/process.rs
# sret_to_user / sret_to_user_forked) that belong to another lane.  Worse, any
# sscratch-based tag has a bootstrap hole: the FIRST trap after `sret_to_user`
# would see an untagged value.
#
# `stvec` has none of those problems.  It is a per-hart CSR, it is written
# exactly once per hart at boot (boot.S for secondaries, `trap_init()` in
# kernel/src/trap/interrupt.rs for the boot hart), it is not writable from U-mode, and
# it is already correct at the very first trap a task ever takes.  So each
# hart gets its OWN vector slot and the entry recovers the id from `stvec`.
#
# LAYOUT.  One 8-byte slot per hart:
#
#     slot k:  [ .word k ][ j trap_entry_common ]     <- stvec points HERE (+4)
#              ^ base+8k                ^ base+8k+4
#
# The id word sits BELOW the entry point on purpose: `.balign 8` alone then
# pins its offset at -4 from `stvec`, whatever the assembler does with the
# `j` (a compressed `c.j` would shift a trailing word to +2 and we would read
# the next slot's opcode as a hart id).  `stvec` ends up 4-byte aligned, which
# is what Direct mode and `trap_init()`'s `trap_addr & 0x3 == 0` assert want.
#
# THE BOOT HART.  `trap_init()` installs the plain `trap_vector` symbol, so
# the boot hart cannot use a slot chosen at link time (its id is only known at
# run time, and it is not necessarily 0).  `trap_vector` therefore carries the
# sentinel id -1 and the entry falls back to `boot_hart_id`, a .data word
# boot.S fills in from a0 before it ever calls into Rust.  Nothing patches
# .text — `enforce_wx()` maps .text RX later on and a store there would fault.
#
# COST: 3 instructions per U-mode trap on a secondary hart (csrr, lw, bgez),
# 3 more on the boot hart (la = auipc+addi, ld).  Zero on S-mode traps, zero
# on the context-switch path.  The load hits .text/.data, both mapped R in the
# kernel PT and shared into every user PT by copy_kernel_entries_to_user(), so
# it is safe to execute before satp is switched back.  Against the ~1879 ns
# syscall floor this is noise.
.balign 8
.global trap_hart_vectors
trap_hart_vectors:
.set hart_slot_id, 0
.rept MAX_HARTS
    .balign 8
    .word hart_slot_id                 # this slot's hart id, at stvec-4
    j     trap_entry_common
    .set  hart_slot_id, hart_slot_id + 1
.endr

.align 4
.global trap_vector
.global trap_return

#
# trap_vector - generic entry, installed by trap_init() on the boot hart.
#
# Same shape as a per-hart slot, but the id word is the sentinel -1: the hart
# id is not known at link time, so the entry reads it from `boot_hart_id`.
#
.balign 8
    .word -1                           # sentinel, at trap_vector-4
trap_vector:
    j trap_entry_common

#
# trap_entry_common - Entry point for all traps (shared body)
#
# CPU sets sepc, scause, stval, then jumps to this hart's stvec slot, which
# jumps here.
#
trap_entry_common:
    # Swap SP <-> sscratch
    csrrw sp, sscratch, sp

    # SP != 0: we came from U-mode, SP = kernel stack, sscratch = user SP.
    # (Wave 15: one taken branch instead of a not-taken `beqz` plus a `j` on
    # every trap from U-mode, every syscall included.)
    bnez sp, trap_save_context

    # SP == 0: we came from S-mode (sscratch was 0)
trap_from_smode:
    # Restore: swap back (get real kernel SP from sscratch)
    csrrw sp, sscratch, sp
    # Now SP = kernel stack, sscratch = 0 again

trap_save_context:
    # Allocate trap frame
    addi sp, sp, -TRAP_FRAME_SIZE

    # Save general-purpose registers x0-x31
    # x0 is always 0, skip but reserve space (offset 0)
    sd x1,   8(sp)    # ra
    # x2 (sp) saved below
    sd x3,  24(sp)    # gp
    sd x4,  32(sp)    # tp
    sd x5,  40(sp)    # t0
    sd x6,  48(sp)    # t1
    sd x7,  56(sp)    # t2
    sd x8,  64(sp)    # s0/fp
    sd x9,  72(sp)    # s1
    sd x10, 80(sp)    # a0
    sd x11, 88(sp)    # a1
    sd x12, 96(sp)    # a2
    sd x13, 104(sp)   # a3
    sd x14, 112(sp)   # a4
    sd x15, 120(sp)   # a5
    sd x16, 128(sp)   # a6
    sd x17, 136(sp)   # a7 (syscall number)
    sd x18, 144(sp)   # s2
    sd x19, 152(sp)   # s3
    sd x20, 160(sp)   # s4
    sd x21, 168(sp)   # s5
    sd x22, 176(sp)   # s6
    sd x23, 184(sp)   # s7
    sd x24, 192(sp)   # s8
    sd x25, 200(sp)   # s9
    sd x26, 208(sp)   # s10
    sd x27, 216(sp)   # s11
    sd x28, 224(sp)   # t3
    sd x29, 232(sp)   # t4
    sd x30, 240(sp)   # t5
    sd x31, 248(sp)   # t6

    # Save original SP: check SPP bit to determine origin
    # sstatus read once (wave 15): t5 is already in the frame, so it holds
    # the value `save_csrs` stores, and nothing on either path below writes
    # sstatus or t5.
    csrr t5, sstatus
    andi t0, t5, SSTATUS_SPP
    bnez t0, save_smode_sp

    # Came from U-mode: original SP is in sscratch
    csrr t0, sscratch
    sd t0, TF_SP(sp)            # regs[2] = user SP
    csrw sscratch, zero         # Mark: now in S-mode

    # K-C16: re-establish the kernel tp (= hart id) for the hart we are
    # ACTUALLY on, instead of trusting the tp ring 3 handed us.  The user's
    # own tp is already safe in the frame at 32(sp) and is given back
    # untouched on the way out — user code may keep whatever tp it likes, it
    # just may not impose it on the kernel.
    # x5/t0 is already saved in the frame at this point, so it is free.
    csrr t0, stvec              # per-hart CSR; U-mode cannot write it
    lw   tp, -4(t0)             # id word sits 4 bytes below every vector slot
    bgez tp, save_csrs          # >= 0: per-hart slot, id is the literal
    la   t0, boot_hart_id       # -1: generic vector => boot hart
    ld   tp, 0(t0)
    j save_csrs

save_smode_sp:
    # Came from S-mode: original SP = current SP + frame size
    addi t0, sp, TRAP_FRAME_SIZE
    sd t0, TF_SP(sp)            # regs[2] = kernel SP before frame

save_csrs:
    csrr t0, sepc
    sd t0, TF_SEPC(sp)

    sd t5, TF_SSTATUS(sp)

    csrr t0, stval
    sd t0, TF_STVAL(sp)

    # scause last: `t0` still holds it at the interrupt test below, which
    # used to read the CSR a second time.
    csrr t0, scause
    sd t0, TF_SCAUSE(sp)

    # Call Rust trap handler: a0 = pointer to TrapFrame
    # Returns SATP value in a0 (0 = no PT switch)
    #
    # B2-04: `riscv64_trap_handler` (kernel/src/entry/riscv64.rs) is the
    # entry point (it replaced the old `trap_handler` in `main.rs`) — it
    # does the identical scause-bit dispatch through `TrapContext`, then
    # forwards to `trap::interrupt::handle_interrupt`/`trap::exception::handle_exception`.
    #
    # ── Interrupts run on this hart's own stack ──────────────────────────
    #
    # WHY.  An interrupt is taken on whatever stack was running, so the cost
    # of the handler lands on top of the deepest syscall chain in the tree.
    # On 2026-09-15 that is exactly how every brain-peer boot died: a timer
    # taken during the receive path put its frame past the end of a 16 KiB
    # task stack.  Raising the task stack paid for that once; a dedicated
    # stack per hart stops the task stack having to budget for it at all.
    #
    # WHAT MOVES AND WHAT DOES NOT.  Only the HANDLER moves.  The trap frame
    # stays on the interrupted stack, because `trap_return` computes the next
    # trap's `sscratch` as frame + TRAP_FRAME_SIZE and hands it to U-mode.
    #
    # THE NESTING CHECK.  `sp - base < IRQ_STACK_SIZE` (unsigned, so a pointer
    # below the base wraps and fails the test) says this hart is already on
    # its interrupt stack -- a trap taken inside a handler.  Resetting sp to
    # the top there would drop the outer handler's frame and return into it.
    #
    # `tp` is the hart id and is valid on both paths that reach here: the
    # U-mode path re-established it from stvec at `save_csrs`, and the S-mode
    # path never left the kernel's own.
    #
    # t0-t4 are free: every general-purpose register is already in the frame.
    mv a0, sp

    bgez t0, trap_call_here          # bit 63 clear => exception, stay put

    # This CPU's interrupt stack, from its per-CPU area: one word per CPU
    # in AZOS_IRQ_STACK_BASE (kernel/src/main.rs), 0 when it has none.
    la   t1, AZOS_IRQ_STACK_BASE
    slli t3, tp, 3
    add  t1, t1, t3
    ld   t1, 0(t1)                   # base of this hart's stack
    beqz t1, trap_call_here          # none (cannot happen once armed): stay
    li   t2, IRQ_STACK_SIZE
    sub  t4, sp, t1
    bltu t4, t2, trap_call_here      # already on it: nested, keep going

    add  t1, t1, t2                  # slot top; stacks grow down
    mv   t0, sp                      # remember the frame
    mv   sp, t1
    addi sp, sp, -16
    sd   t0, 0(sp)                   # the frame address, below the handler
    call riscv64_trap_handler
    ld   sp, 0(sp)                   # back onto the frame
    mv   s2, a0                      # Save SATP in callee-saved s2

    # A timer or an IPI that wants the scheduler only RAISES A FLAG, and this
    # is where it is spent.  `schedule()` switches by saving `sp` into the
    # outgoing task's TCB, and a shared per-hart stack is not a place a task
    # can be resumed from: the next interrupt on this hart would reset sp to
    # the top and overwrite the frame the task was sleeping on.  sp is back
    # on the task stack here, which is the only place that switch is safe.
    #
    # ONLY ON THIS PATH.  Every syscall is an exception and reaches
    # `trap_call_here` instead, so it does not pay for a call, a hart-id read
    # and an atomic swap it can never need -- the syscall floor is measured
    # against Linux and is not a place to spend instructions.  A task that
    # yields inside a syscall calls the scheduler itself, as it always did.
    #
    # s2 carries the SATP across this call.  It is callee-saved, so the Rust
    # side gives it back, and interrupts stay off until the sret below.
    mv   a0, sp                      # trap_resched(frame): the frame is at sp
    call trap_resched
    j    trap_return

trap_call_here:
    call riscv64_trap_handler
    mv   s2, a0                      # Save SATP in callee-saved s2

    # Fall through to trap_return

#
# trap_return - Restore state and return from trap
#
# O3.1-nest: `sstatus` (the frame's OWN snapshot, taken at trap entry) is
# written FIRST, before `sscratch` or `sepc` are touched, for the same
# reason `process.rs`'s `sret_to_user`/`sret_to_user_forked` write `sstatus`
# before `sepc`/`sscratch` on the way IN: whichever CSR closes SIE has to go
# first, or a trap taken in the gap sees a live SIE the frame never asked
# for.
#
# THE BUG THIS CLOSES.  With IRQs enabled inside a syscall (O3.1) nothing
# clears the live SIE bit between the syscall body and here — the frame's
# TF_SSTATUS has SIE=0 (hardware always clears it on entry), but that value
# only reaches the CSR once `csrw sstatus` executes, and the old code ran
# it LAST.  In the gap after `csrw sscratch, t1` below and before that
# write, a live timer with SIE=1 takes a trap that reads the CURRENT
# (unrestored) `sscratch` — already the U-mode return value — as if it were
# a valid kernel SP, allocates ITS frame at `sscratch - TRAP_FRAME_SIZE`
# (the syscall's own, not-yet-restored frame, since `sscratch` was set to
# exactly `frame + TRAP_FRAME_SIZE`), and records `TF_SP = sscratch`
# (`save_smode_sp`'s `addi t0, sp, TRAP_FRAME_SIZE`) instead of the true
# pre-trap `sp` — off by +TRAP_FRAME_SIZE. That nested trap's own
# `trap_return` then resumes execution one frame too high: past the top of
# THIS task's `TASK_STACKS` slot and into the bottom of the next one, so
# the next register save this task makes lands on another task's kernel
# stack. Measured (see the O3.1 notes above): USER register values
# (ipctest's `FORK_CANARY`, its shm VA) turning up as return addresses on
# OTHER tasks' (`net-poll`, `flight-ctrl`) kernel stacks, always at that
# same +TRAP_FRAME_SIZE offset. A second, narrower instance of the same
# class sits between the old `csrw sepc` and `csrw sstatus`: sepc already
# holds the resume address, SIE is still live, and a trap in that gap
# clobbers sepc with kernel text (the exact hazard `sret_to_user`'s comment
# documents on the way in). Writing `sstatus` first closes both gaps in one
# move, before `sscratch` or `sepc` becomes observable. Zero added
# instructions: the write is moved, not duplicated (see the `ld` below,
# which keeps the same register live for the K-C16b check without
# re-issuing the `csrw`).
trap_return:
    # Same CSR order as before (sstatus, then sscratch, then sepc), one SPP
    # test instead of two (SYSFLOOR: the U-mode path is 9 instructions, was
    # 13): `t0` keeps the SPP bit and `t1` the resume pc across the branch,
    # so neither TF_SSTATUS nor TF_SEPC is loaded twice and the U-mode path
    # falls through with no `j`.
    ld t0, TF_SSTATUS(sp)       # Load saved sstatus
    csrw sstatus, t0            # O3.1-nest: closes SIE (if the frame says so)
                                 # before sscratch/sepc below become live traps.
    ld t1, TF_SEPC(sp)          # resume pc; a load, not yet observable
    andi t0, t0, SSTATUS_SPP    # Check SPP bit
    bnez t0, restore_to_smode

    # Returning to U-mode: set sscratch = kernel SP for next trap
    addi t0, sp, TRAP_FRAME_SIZE
    csrw sscratch, t0
    csrw sepc, t1

    # K-C16b (separate finding from K-C16, same file): restore tp ONLY when
    # returning to U-mode.
    #
    # Returning to U-mode, the frame holds the user's own tp — give it back.
    # Returning to S-mode the frame holds the tp of the hart this trap was
    # TAKEN on, which is not necessarily the hart we are returning on: a task
    # preempted by a timer IRQ can be migrated, and context_switch.S then
    # restores the correct tp for the new hart from task.context.tp (the K-A11
    # invariant).  Reloading the stale frame value here would undo exactly
    # that and drop the kernel back into the K-A11 corruption by another
    # route.  The tp the hart is currently running with is the correct one, so
    # leave it alone: `restore_to_smode` never loads it.
    ld x4, 32(sp)               # SPP=0 -> returning to U-mode: user's own tp

restore_regs:
    # Switch page table if needed (s2 = SATP from trap_handler, checked
    # BEFORE s2 is restored from the frame below)
    beqz s2, skip_pt_switch
    csrw satp, s2
    sfence.vma zero, zero

skip_pt_switch:
    # Restore general-purpose registers
    ld x1,   8(sp)    # ra
    # x2 (sp) restored last
    ld x3,  24(sp)    # gp
    # x4 (tp) restored above, U-mode returns only — see K-C16b
    ld x5,  40(sp)    # t0
    ld x6,  48(sp)    # t1
    ld x7,  56(sp)    # t2
    ld x8,  64(sp)    # s0/fp
    ld x9,  72(sp)    # s1
    ld x10, 80(sp)    # a0
    ld x11, 88(sp)    # a1
    ld x12, 96(sp)    # a2
    ld x13, 104(sp)   # a3
    ld x14, 112(sp)   # a4
    ld x15, 120(sp)   # a5
    ld x16, 128(sp)   # a6
    ld x17, 136(sp)   # a7
    ld x18, 144(sp)   # s2
    ld x19, 152(sp)   # s3
    ld x20, 160(sp)   # s4
    ld x21, 168(sp)   # s5
    ld x22, 176(sp)   # s6
    ld x23, 184(sp)   # s7
    ld x24, 192(sp)   # s8
    ld x25, 200(sp)   # s9
    ld x26, 208(sp)   # s10
    ld x27, 216(sp)   # s11
    ld x28, 224(sp)   # t3
    ld x29, 232(sp)   # t4
    ld x30, 240(sp)   # t5
    ld x31, 248(sp)   # t6

    # Restore SP last
    ld x2, TF_SP(sp)

    # Return from trap
    sret

restore_to_smode:
    # Returning to S-mode: sscratch stays 0; the kernel tp stays (K-C16b).
    csrw sscratch, zero
    csrw sepc, t1
    j restore_regs

.size trap_entry_common, . - trap_entry_common

# K-C16: boot hart id, published by boot.S (a0 from OpenSBI) before it calls
# kernel_main.  Read only by the generic `trap_vector` path above.  Lives in
# .data — .bss is zeroed by clear_bss in boot.S and .text becomes RX once
# enforce_wx() runs, so neither would do.
.section .data
.balign 8
.global boot_hart_id
boot_hart_id:
    .quad 0
