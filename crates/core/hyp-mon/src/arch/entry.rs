// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The EL2 entry stub and vector table, in asm.
//!
//! `_azos_monitor_enter` is where the kernel's boot trampoline branches on the
//! primary PE (via `bl`, so LR is the EL1 return). It turns on EL2 stage-1
//! (an identity map baked into the image, PA-independent), claims this PE's
//! stack with an atomic now that exclusives work, saves the caller's GPRs,
//! runs `hyp_el2_init`, restores them and `eret`s the caller into EL1 — so the
//! kernel's boot registers (the FDT pointer included) survive unchanged.
//!
//! `_hyp_vectors` routes a synchronous trap from EL1 (an HVC, or once
//! `HCR_EL2.TSC` is set in F3 an SMC, or a stage-2 fault in F2) through
//! `hyp_sync_from_el1`.

use super::{MAX_PES, STACK_SIZE};

core::arch::global_asm!(
    r#"
.section .text.entry, "ax"

// Enable EL2 stage-1 with the identity table. MMU off on entry; no stack
// needed. Clobbers x10-x14. The `.if {mmu}` guard is the `hyp-mmu-off-canary`:
// with it 0 the monitor runs untranslated and `probe` never reports el2-mmu.
.macro HYP_MMU_ON
.if {mmu}
    adrp    x10, IDENTITY_L1
    add     x10, x10, :lo12:IDENTITY_L1
    movz    x11, #0xFF00                 // MAIR: attr0 Device, attr1 Normal WB
    msr     MAIR_EL2, x11
    ldr     x11, ={tcr}
    msr     TCR_EL2, x11
    msr     TTBR0_EL2, x10
    isb
    tlbi    alle2
    dsb     nsh
    isb
    mrs     x11, SCTLR_EL2
    orr     x11, x11, #(1 << 0)          // M
    orr     x11, x11, #(1 << 2)          // C
    orr     x11, x11, #(1 << 12)         // I
    msr     SCTLR_EL2, x11
    isb
.endif
.endm

.globl _azos_monitor_enter
_azos_monitor_enter:
    mov     x28, lr                      // EL1 return (callee-saved across the body)
    HYP_MMU_ON
    bl      _hyp_claim_and_stack         // x0 = slot, sp set
    // Save the caller's GPRs so the EL1 continuation sees them unchanged.
    sub     sp, sp, #256
    stp     x0, x1,   [sp, #0]
    stp     x2, x3,   [sp, #16]
    stp     x4, x5,   [sp, #32]
    stp     x6, x7,   [sp, #48]
    stp     x8, x9,   [sp, #64]
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
    bl      hyp_el2_init                 // x0 = slot, still in place
    ldp     x0, x1,   [sp, #0]
    ldp     x2, x3,   [sp, #16]
    ldp     x4, x5,   [sp, #32]
    ldp     x6, x7,   [sp, #48]
    ldp     x8, x9,   [sp, #64]
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
    add     sp, sp, #256
    mov     x10, #0x3C5                  // SPSR_EL2 = EL1h, DAIF masked
    msr     SPSR_EL2, x10
    msr     ELR_EL2, x28
    eret

// Claim this PE's EL2 stack slot (MMU is on, so exclusives work) and set SP.
// Returns the slot in x0. A slot at or above the pool parks the PE (fail
// closed). Clobbers x0, x10-x14.
_hyp_claim_and_stack:
    adrp    x10, HYP_PE_SEQ
    add     x10, x10, :lo12:HYP_PE_SEQ
1:  ldaxr   x11, [x10]
    add     x12, x11, #1
    stlxr   w13, x12, [x10]
    cbnz    w13, 1b
    cmp     x11, #{maxpes}
    b.hs    _hyp_park
    mov     x0, x11
    adrp    x12, HYP_STACKS
    add     x12, x12, :lo12:HYP_STACKS
    movz    x13, #{stack_hi}, lsl #16
    madd    x12, x11, x13, x12
    add     x12, x12, x13
    mov     sp, x12
    ret

// A PSCI-started secondary enters here (the entry the monitor substituted in
// `CPU_ON`), at EL2, MMU off, with x0 = the target index the monitor chose as
// the context. It brings EL2 up for this PE and `eret`s to the kernel's own
// requested entry with x0 = the kernel's requested context (its hart id).
.globl _hyp_secondary_entry
_hyp_secondary_entry:
    HYP_MMU_ON
    mov     x27, x0                      // the index the monitor passed
    bl      _hyp_claim_and_stack         // x0 = slot, sp set
    bl      hyp_el2_init                 // x0 = slot
    mov     x0, x27
    bl      hyp_secondary_resume         // x0 = kernel entry PC
    mov     x26, x0
    mov     x0, x27
    bl      hyp_secondary_ctx            // x0 = kernel context (its hart id)
    mov     x10, #0x3C5
    msr     SPSR_EL2, x10
    msr     ELR_EL2, x26
    eret

.globl _hyp_park
_hyp_park:
    wfe
    b       _hyp_park

// ── EL2 vector table ────────────────────────────────────────────────────
.balign 2048
.globl _hyp_vectors
_hyp_vectors:
    .balign 0x80
    b _hyp_el2_fault
    .balign 0x80
    b _hyp_el2_fault
    .balign 0x80
    b _hyp_el2_fault
    .balign 0x80
    b _hyp_el2_fault
    .balign 0x80
    b _hyp_el2_fault
    .balign 0x80
    b _hyp_el2_fault
    .balign 0x80
    b _hyp_el2_fault
    .balign 0x80
    b _hyp_el2_fault
    .balign 0x80
    b _hyp_sync_lower            // 0x400: synchronous from EL1
    .balign 0x80
    b _hyp_el2_fault
    .balign 0x80
    b _hyp_el2_fault
    .balign 0x80
    b _hyp_el2_fault
    .balign 0x80
    b _hyp_el2_fault
    .balign 0x80
    b _hyp_el2_fault
    .balign 0x80
    b _hyp_el2_fault
    .balign 0x80
    b _hyp_el2_fault

_hyp_sync_lower:
    sub     sp, sp, #256
    stp     x0, x1,   [sp, #0]
    stp     x2, x3,   [sp, #16]
    stp     x4, x5,   [sp, #32]
    stp     x6, x7,   [sp, #48]
    stp     x8, x9,   [sp, #64]
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
    mov     x0, sp
    bl      hyp_sync_from_el1
    ldp     x0, x1,   [sp, #0]
    ldp     x2, x3,   [sp, #16]
    ldp     x4, x5,   [sp, #32]
    ldp     x6, x7,   [sp, #48]
    ldp     x8, x9,   [sp, #64]
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
    add     sp, sp, #256
    eret

_hyp_el2_fault:
    wfe
    b       _hyp_el2_fault
"#,
    maxpes = const MAX_PES,
    stack_hi = const (STACK_SIZE >> 16),
    mmu = const (!cfg!(feature = "hyp-mmu-off-canary")) as u32,
    tcr = const super::mmu::TCR_EL2,
);
