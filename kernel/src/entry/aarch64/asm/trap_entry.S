// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// AArch64 exception-vector table — Item 2 Stage 5, then Phase 2 (this
// task: trap save/restore + `eret`, GICv3, timer ticks).
//
// Installed into VBAR_EL1 by boot.S before any faultable code runs. Every
// one of the 16 vectors funnels into `_trap_common`, which builds the
// `entry::aarch64::TrapFrame` (kernel/src/entry/aarch64.rs) — GPRs +
// ELR_EL1/SPSR_EL1/SP_EL0/FAR_EL1/ESR_EL1, no FP state (see the note in
// `_trap_common`) — on the stack and calls `aarch64_trap_entry(&mut TrapFrame)`.
// That function either mutates the frame and RETURNS (an `svc #0`
// self-test, or any IRQ dispatched through the GIC — see its own doc
// comment), in which case `trap_return` below restores everything and
// `eret`s back to `ELR_EL1`; or it never returns at all (an unhandled
// trap class prints over `kprintln!` and parks on `wfi`), in which case
// nothing after the `bl`/switched-stack call below ever executes. Do NOT
// migrate the riscv64 trap path onto this — that stays a separate,
// measured step.
//
// TrapFrame layout constants (mirrors trap_entry.S's B2-01 pattern on
// riscv64): every named operand below is substituted by the `global_asm!(...)`
// block in kernel/src/main.rs via `size_of::<TrapFrame>()` /
// `offset_of!(TrapFrame, ..)` on the real struct in
// kernel/src/entry/aarch64.rs, or (MAX_HARTS / the IRQ stack size) the
// same kernel-wide constants `boot.S` already takes — never hand-
// duplicated `.equ` literals that can silently disagree with the struct.
.equ TRAP_FRAME_SIZE,  {trap_frame_size}
.equ TF_OFF_ELR,       {tf_off_elr}
.equ TF_OFF_SPSR,      {tf_off_spsr}
.equ TF_OFF_SP_EL0,    {tf_off_sp_el0}
.equ TF_OFF_FAR,       {tf_off_far}
.equ TF_OFF_ESR,       {tf_off_esr}
.equ TF_OFF_VECTOR,    {tf_off_vector}
.equ TF_OFF_FPSTATE,   {tf_off_fpstate}
.equ MAX_HARTS,        {max_harts}
.equ IRQ_STACK_SIZE,   {irq_stack_size}

// The two vector-number PAIRS `entry::aarch64::TrapFrame::class()` actually
// checks — VEC_SYNC_CURRENT_EL_SP0 / VEC_IRQ_CURRENT_EL_SP0 and
// VEC_SYNC_LOWER_EL / VEC_IRQ_LOWER_EL (kernel/src/entry/aarch64.rs) —
// injected rather than re-typed as literals, same reason as the offsets
// above. Despite the "_SP0" half of the first pair's name, this table
// wires it for the group ARM ARM §D1.10 calls "Current EL using SPx" —
// the ONLY group a self-fault (or the `svc #0` self-test) can land in,
// since boot.S drops into EL1h (SP_EL1) and this milestone never switches
// to SP_EL0. VEC_IRQ_CUR is also the ONLY interrupt group reachable this
// milestone (no EL0 task exists yet to take VEC_IRQ_LO) — the IRQ-stack
// switch below still checks both, so this table does not change the day
// a user task does exist.
.equ VEC_SYNC_CUR, {vec_sync_cur}
.equ VEC_IRQ_CUR,  {vec_irq_cur}
.equ VEC_SYNC_LO,  {vec_sync_lo}
.equ VEC_IRQ_LO,   {vec_irq_lo}

.section .text.vectors
.balign 2048
.globl _vectors
_vectors:
    // ── Group 0 — Current EL, SP0. Unreachable: EL1h never switches to
    // SP_EL0. Vector numbers offset by 0x10 so a hit here is visibly
    // "this group should be impossible", not a false match on group 1's
    // or group 2's own 0/1/4/5.
    b       _slot_sync_cur_sp0
    .balign 0x80
    b       _slot_irq_cur_sp0
    .balign 0x80
    b       _slot_fiq_cur_sp0
    .balign 0x80
    b       _slot_serr_cur_sp0
    .balign 0x80

    // ── Group 1 — Current EL, SPx. What boot.S actually drops into, so
    // this is the only group a kernel-mode fault OR the `svc #0`
    // self-test can ever take at this milestone.
    b       _slot_sync_cur_spx
    .balign 0x80
    b       _slot_irq_cur_spx
    .balign 0x80
    b       _slot_fiq_cur_spx
    .balign 0x80
    b       _slot_serr_cur_spx
    .balign 0x80

    // ── Group 2 — Lower EL, AArch64. Unreachable this milestone (no EL0
    // task exists yet), wired with the vector numbers
    // entry::aarch64.rs already names for it so this table does not
    // change the day a user task exists.
    b       _slot_sync_lower64
    .balign 0x80
    b       _slot_irq_lower64
    .balign 0x80
    b       _slot_fiq_lower64
    .balign 0x80
    b       _slot_serr_lower64
    .balign 0x80

    // ── Group 3 — Lower EL, AArch32. Never used — no 32-bit userspace.
    b       _slot_sync_lower32
    .balign 0x80
    b       _slot_irq_lower32
    .balign 0x80
    b       _slot_fiq_lower32
    .balign 0x80
    b       _slot_serr_lower32

// Sixteen tiny trampolines, one per vector slot: reserve the frame,
// stash the two registers _trap_common needs as scratch (x0 carries the
// vector number in by the time _trap_common runs; x1 is spare), and
// jump in. Kept out of the 0x80-per-slot table above so a slot is
// exactly one `b` — the table stays legible as 16 entries instead of 16
// half-visible code blobs.
.macro TRAP_SLOT name, vecnum
_slot_\name:
    sub     sp, sp, #TRAP_FRAME_SIZE
    stp     x0, x1, [sp]
    mov     x0, #\vecnum
    b       _trap_common
.endm

TRAP_SLOT sync_cur_sp0,  0x10
TRAP_SLOT irq_cur_sp0,   0x11
TRAP_SLOT fiq_cur_sp0,   0x12
TRAP_SLOT serr_cur_sp0,  0x13
TRAP_SLOT sync_cur_spx,  VEC_SYNC_CUR
TRAP_SLOT irq_cur_spx,   VEC_IRQ_CUR
TRAP_SLOT fiq_cur_spx,   0x16
TRAP_SLOT serr_cur_spx,  0x17
TRAP_SLOT sync_lower64,  VEC_SYNC_LO
TRAP_SLOT irq_lower64,   VEC_IRQ_LO
TRAP_SLOT fiq_lower64,   0x1a
TRAP_SLOT serr_lower64,  0x1b
TRAP_SLOT sync_lower32,  0x1c
TRAP_SLOT irq_lower32,   0x1d
TRAP_SLOT fiq_lower32,   0x1e
TRAP_SLOT serr_lower32,  0x1f

// Common tail. On entry: sp points at a TRAP_FRAME_SIZE-byte frame with
// x0 and x1's ORIGINAL values already saved at offsets 0/8 (by the
// TRAP_SLOT macro, before it clobbered x0 with the vector number); x0
// itself currently holds the vector number, not the trapped x0.
_trap_common:
    str     x0, [sp, #TF_OFF_VECTOR]

    stp     x2,  x3,  [sp, #16]
    stp     x4,  x5,  [sp, #32]
    stp     x6,  x7,  [sp, #48]
    stp     x8,  x9,  [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30,      [sp, #240]

    // ── No FP/SIMD save ──────────────────────────────────────────────
    //
    // The kernel is soft-float (`aarch64-unknown-none-softfloat`) and
    // `tools/aarch64_fp_free_check.sh` proves no code reached from here
    // names a V register, so the interrupted code's V0-V31/FPSR/FPCR are
    // still in the hardware when this trap returns. User FP state is saved
    // lazily, by `context_switch` and only for a task that used FP since it
    // was switched in (`kernel/src/entry/aarch64/fp_lazy.rs`). This used to
    // save and restore all 512+8 bytes on every trap.

    // x9 as scratch, not x0: x0 still holds the vector number, which the
    // dispatch below tests without reloading it from the frame.
    mrs     x9, ELR_EL1
    str     x9, [sp, #TF_OFF_ELR]
    mrs     x9, SPSR_EL1
    str     x9, [sp, #TF_OFF_SPSR]
    mrs     x9, SP_EL0
    str     x9, [sp, #TF_OFF_SP_EL0]
    mrs     x9, FAR_EL1
    str     x9, [sp, #TF_OFF_FAR]
    mrs     x9, ESR_EL1
    str     x9, [sp, #TF_OFF_ESR]

    // IRQ or not, decided from the vector number still in x0: the two IRQ
    // vectors are 1 and 5 (`VEC_IRQ_CURRENT_EL_SP0`/`VEC_IRQ_LOWER_EL`),
    // the only numbers in this table with `(v & ~4) == 1` — checked at
    // assembly time below, so a renumbering fails to build instead of
    // misrouting. The sync/syscall path falls straight through to `91:`
    // (three instructions of dispatch); the IRQ path is out of line, after
    // `trap_return`. This replaced a reload of the vector from the frame
    // and two compare-and-branch pairs.
    .if ((VEC_IRQ_CUR & ~4) != 1) || ((VEC_IRQ_LO & ~4) != 1) || ((VEC_SYNC_CUR & ~4) == 1) || ((VEC_SYNC_LO & ~4) == 1)
    .error "trap_entry.S: IRQ vector test assumes IRQ vectors 1 and 5, sync vectors neither"
    .endif
    bic     x1, x0, #4

    // aarch64_trap_entry(&mut TrapFrame) — AAPCS first argument is the
    // frame's own address, which is exactly `sp` right now (the struct's
    // `#[repr(C, align(16))]` layout starts at offset 0, and `sp` is
    // 16-byte aligned coming out of an EL1h exception). x0 carries this
    // across the IRQ-stack switch (label 90) untouched — only `sp` itself
    // moves, never the frame pointer argument.
    mov     x0, sp
    cmp     x1, #1
    b.eq    90f

91: // sync/syscall, or a nested IRQ: call on the current stack
    bl      aarch64_trap_entry
    // Stash the TTBR0_EL1 switch request the same way the IRQ path (label
    // 90) does — see that comment. On THIS path it is the real one: a
    // SYS_EXEC/autorun hand-off consumed inside `aarch64_trap_entry`'s
    // syscall arm returns the new table's PA here (0 otherwise).
    mov     x19, x0
    // Fall through to trap_return.

//
// trap_return — restore GPRs + the saved system registers and
// `eret`. Only reached when `aarch64_trap_entry` actually returns
// (`svc #0` self-test or a dispatched IRQ) — an unhandled trap parks
// inside `aarch64_trap_entry` itself and never gets here.
//
trap_return:
    // O3.1 (owner decision 2026-09-26): closes the aarch64 analogue of the
    // riscv64 O3.1-nest bug (see that file's trap_return comment) BEFORE
    // touching any of ELR_EL1/SPSR_EL1/SP_EL0/TTBR0_EL1 below. AArch64 has
    // no `sscratch`-style software SP tag — SP_EL0/SP_EL1 are banked in
    // hardware, so that half of the riscv64 bug class does not exist here
    // (verified by reading this whole file: no software SP swap anywhere
    // in it). The OTHER half does: once a syscall runs with IRQs enabled
    // (`ARCH.enable_all()`, `crates/core/arch-aarch64/src/sysregs.rs`'s
    // `msr DAIFClr,#2`), DAIF.I stays clear across this entire routine
    // unless masked again — `SPSR_EL1` is only "the PSTATE `eret` will
    // restore"; writing it does NOT affect this hart's OWN live DAIF
    // (RISC-V's single-register `sstatus` trick has no aarch64
    // equivalent; the exec/fork first entries, which used to carry their
    // own copy of this guard in `crates/core/sched/src/process.rs`, now come
    // through here too — see `aarch64_ret_to_user` below). Without this
    // line, a real IRQ landing after `msr ELR_EL1`/`msr SPSR_EL1` below and
    // before `eret` takes a nested EL1 exception that overwrites BOTH CSRs
    // with the interrupted PC/PSTATE; the nested trap's OWN `eret` resumes
    // exactly here but never restores THIS frame's `TF_OFF_ELR`/
    // `TF_OFF_SPSR` a second time (this code never re-reads them), so this
    // routine's own `eret` below would jump to kernel text with whatever
    // the nested trap last left in the CSRs — the riscv64 sepc-clobber
    // instance, ELR_EL1/SPSR_EL1 instead of sepc, ported to this ISA by a
    // different mechanism. `#0xf` masks all four DAIF classes (matching
    // `process.rs`'s own convention) rather than just `I`: `eret` restores
    // the full mask from the frame's `SPSR_EL1` the same instruction it
    // restores PC, so nothing is left masked past this trap.
    msr     DAIFSet, #0xf
trap_return_masked:

    ldr     x9, [sp, #TF_OFF_ELR]
    msr     ELR_EL1, x9
    ldr     x9, [sp, #TF_OFF_SPSR]
    msr     SPSR_EL1, x9
    ldr     x9, [sp, #TF_OFF_SP_EL0]
    msr     SP_EL0, x9

    // ── Phase 6 (userspace): install the new TTBR0_EL1, if requested ────
    //
    // `x19` (stashed right after `aarch64_trap_entry` returned, above) is
    // the exec-handoff's new page-table PA, or 0. Must run AFTER the
    // ELR_EL1/SPSR_EL1/SP_EL0 restores above (those are per-trap, unrelated
    // to the address space) and BEFORE the GPR restore below, which
    // overwrites x19 with the frame's own saved value via `ldp x18, x19`.
    // Same sequence `context_switch.S`'s per-task switch and
    // `process::sret_to_user` use: `isb` before the flush is
    // context-synchronizing the TTBR0_EL1 write itself, `tlbi vmalle1` +
    // `dsb nsh` + `isb` discard stale translations under the old table and
    // order that completion before any instruction can use the new one —
    // flush-on-switch (no ASID tagging), same choice made there.
    cbz     x19, 92f
    msr     TTBR0_EL1, x19
    isb
    tlbi    vmalle1
    dsb     nsh
    isb
92:

    ldp     x2,  x3,  [sp, #16]
    ldp     x4,  x5,  [sp, #32]
    ldp     x6,  x7,  [sp, #48]
    ldp     x8,  x9,  [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldp     x16, x17, [sp, #128]
    ldp     x18, x19, [sp, #144]
    ldp     x20, x21, [sp, #160]
    ldp     x22, x23, [sp, #176]
    ldp     x24, x25, [sp, #192]
    ldp     x26, x27, [sp, #208]
    ldp     x28, x29, [sp, #224]
    ldr     x30,      [sp, #240]
    ldp     x0,  x1,  [sp]

    add     sp, sp, #TRAP_FRAME_SIZE
    // ISB not required before `eret` per the Arm ARM (`eret` is already
    // a context-synchronizing event); none of the writes above need one
    // to be observed by the `eret` itself.
    eret

    // ── Interrupts run on this hart's own stack ─────────────────────
    //
    // Mirrors riscv64's `trap_entry.S` (see its long comment on why):
    // an interrupt is taken on whatever stack was running, so its cost
    // should not land on top of the deepest call chain in the tree.
    // Only the HANDLER's own stack frame moves — the TrapFrame built
    // above stays on the interrupted stack, `trap_return` pops it from
    // there, and `x0` (the frame pointer) is unaffected either way.
    //
    // `x9-x14` are free: every GPR is already in the frame.
90: // maybe switch to the IRQ stack
    mrs     x9, MPIDR_EL1
    and     x9, x9, #0xffffff          // Aff2:Aff1:Aff0 — see boot.S
    mov     x10, #MAX_HARTS
    cmp     x9, x10
    csel    x9, x9, xzr, lo            // out-of-range hart id -> slot 0

    mov     x13, #IRQ_STACK_SIZE
    mul     x10, x9, x13               // offset = hart * IRQ_STACK_SIZE
    adrp    x11, aarch64_irq_stacks
    add     x11, x11, :lo12:aarch64_irq_stacks
    add     x11, x11, x10              // x11 = this hart's slot base
    add     x12, x11, x13              // x12 = slot top (stacks grow down)

    // Nesting check (unsigned): `sp - base < size` means we are ALREADY
    // on this hart's IRQ stack — a trap taken inside a handler. Do not
    // reset sp in that case; that would drop the outer handler's frame.
    sub     x14, sp, x11
    cmp     x14, x13
    b.lo    91b                        // already on it: call in place

    mov     x2, sp                     // remember the interrupted sp
    mov     sp, x12
    sub     sp, sp, #16
    str     x2, [sp]
    bl      aarch64_trap_entry
    // Stash the TTBR0_EL1 switch request (0 = none) in x19 — a callee-saved
    // register `aarch64_trap_resched` below is obliged to preserve across
    // its own call (AAPCS64), so it survives to `trap_return`'s own use of
    // it below. Always 0 on this path today (`handle_irq` never requests a
    // switch), kept generic so this does not need revisiting if that
    // changes.
    mov     x19, x0
    ldr     x2, [sp]
    mov     sp, x2

    // Phase 3 (context switch + scheduler) — mirrors riscv64's own
    // `call trap_resched` at the equivalent point in its trap_entry.S,
    // including the comment there on why this is the ONLY place it is
    // safe: `sp` is back on the INTERRUPTED task's own stack (never the
    // shared per-hart IRQ stack `_trap_common` switched to), which is
    // the only stack a task can safely be PARKED on if `schedule()` decides
    // to `context_switch()` away. `aarch64_trap_resched` may not return
    // here for a long time — the interrupted task might not be rescheduled
    // for many ticks — but when it does, `sp` (and every register
    // `trap_return` below reads) is exactly as this line left it, because
    // `context_switch` restores this exact call frame like any other
    // AAPCS64 return. Only on THIS path (non-nested IRQ that took its own
    // stack): the `91:` label (nested IRQ, or sync/svc) falls
    // straight to `trap_return` and pays nothing for a reschedule check it
    // can never need — same "ONLY ON THIS PATH" restriction riscv64
    // documents at its own call site.
    mov     x0, sp                     // aarch64_trap_resched(frame): the frame is at sp
    bl      aarch64_trap_resched
    b       trap_return


//
// ── The other two ways into EL0 use the same tail ───────────────────────
//
// Every return to EL0 in this kernel goes through `trap_return` above:
// returns from a trap, and — through the two entries below — a task's
// first entry into a fresh image (`aarch64_enter_user`, reached from
// `crates/core/sched/src/process.rs`'s `sret_to_user`) and a forked child's
// first entry (`aarch64_enter_user_forked`, from `sret_to_user_forked`).
// Those used to carry their own copies of the DAIF mask, the
// ELR_EL1/SPSR_EL1/SP_EL0/TTBR0_EL1 writes and the GPR zeroing or restore;
// now the caller builds an ordinary `TrapFrame` on its kernel stack and
// the one tail restores it. What the tail does, once, for all of them:
//   * O3.1: IRQs masked before ELR_EL1/SPSR_EL1/SP_EL0/TTBR0_EL1 (masked
//     here, first, so the `sp` move below is covered too);
//   * TTBR0_EL1 switch when x19 != 0 (x19 = the `ttbr0` argument);
//   * every GPR from the frame (zeroes for a fresh image, so no kernel
//     value — x18 included — reaches EL0);
//   * lazy FP: nothing to do here by design. The FP invariant (FPEN=0b11
//     iff this hart holds the running task's live state) is kept by
//     `context_switch` and `fp_lazy::first_use`; the callers of these
//     entries drop (exec) or adopt (fork) the task's saved state first.
//   * reschedule: only the IRQ path (label 90) sets and consumes
//     NEED_RESCHED; neither a syscall return nor these first entries can
//     find it pending (see `aarch64_trap_resched`), so they do not pay
//     for the check.
// `sp` becomes the frame: the frame is at the bottom of the caller's live
// stack, everything below it is dead (these entries never return), and the
// next trap from EL0 builds its frame just under where this one ends.
//
// aarch64_ret_to_user(frame: *const TrapFrame, ttbr0: u64) -> !
.globl aarch64_ret_to_user
aarch64_ret_to_user:
    msr     DAIFSet, #0xf
    mov     sp, x0
    mov     x19, x1
    b       trap_return_masked

// aarch64_ret_to_user_tls(frame: *const TrapFrame, ttbr0: u64, tpidr_el0: u64) -> !
// Same, plus TPIDR_EL0 (a forked child's TLS pointer), written with IRQs
// masked on the hart that is about to `eret`.
.globl aarch64_ret_to_user_tls
aarch64_ret_to_user_tls:
    msr     DAIFSet, #0xf
    msr     TPIDR_EL0, x2
    mov     sp, x0
    mov     x19, x1
    b       trap_return_masked

.extern aarch64_trap_entry
.extern aarch64_irq_stacks
.extern aarch64_trap_resched
