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
    mov     x0, #0                       // the primary holds slot 0
    bl      _hyp_claim_and_stack         // sp set
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
    mov     x0, #0
    mov     x1, #1                       // primary
    bl      hyp_el2_init
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

// Take the stack of slot x0 for this PE (MMU is on, so exclusives work). The
// slot's key must be this PE's affinity: free (taken now, the primary's slot 0)
// or already its own (a PE back from CPU_OFF or a power-down, or one `CPU_ON`
// claimed for). Another PE's slot, or a slot past the pool, parks the PE (fail
// closed). Keeps x0 = slot. Clobbers x10-x13.
_hyp_claim_and_stack:
    cmp     x0, #{maxpes}
    b.hs    _hyp_park
    mrs     x10, MPIDR_EL1
    ldr     x11, ={aff_mask}
    and     x10, x10, x11
    orr     x10, x10, #(1 << 63)
    adrp    x12, HYP_PE_SLOTS
    add     x12, x12, :lo12:HYP_PE_SLOTS
    add     x12, x12, x0, lsl #3
1:  ldaxr   x11, [x12]
    cmp     x11, x10
    b.eq    2f
    cbnz    x11, _hyp_park
    stlxr   w13, x10, [x12]
    cbnz    w13, 1b
2:  clrex
    adrp    x12, HYP_STACKS
    add     x12, x12, :lo12:HYP_STACKS
    movz    x13, #{stack_hi}, lsl #16
    madd    x12, x0, x13, x12
    add     x12, x12, x13
    mov     sp, x12
    ret

// A PSCI-started secondary enters here (the entry the monitor substituted in
// `CPU_ON`), at EL2, MMU off, with x0 = the target index the monitor chose as
// the context (the slot of this PE). It brings EL2 up for this PE and `eret`s to the kernel's own
// requested entry with x0 = the kernel's requested context (its hart id).
.globl _hyp_secondary_entry
_hyp_secondary_entry:
    msr     SPSel, #1                    // EL2 runs on SP_EL2 whatever the entry state was
    HYP_MMU_ON
    mov     x27, x0                      // the slot the monitor passed
    bl      _hyp_claim_and_stack         // sp set, x0 = slot
    mov     x1, #0                       // not the primary's first entry
    bl      hyp_el2_init
    mov     x0, x27
    bl      hyp_secondary_resume         // x0 = kernel entry PC
    cbz     x0, _hyp_park                // never an eret to PA 0
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

// A trapped `MSR TTBR0_EL1, Xt` (every context switch when `HCR_EL2.TVM` is
// the pin) is carried out here, with two scratch registers on the stack, before
// the frame of the general path is built; anything else falls through to it.
_hyp_sync_lower:
    stp     x0, x1, [sp, #-16]!
    mrs     x0, ESR_EL2
    bic     x1, x0, #{rt_mask}
    movz    x0, #{ttbr0_lo}
    movk    x0, #{ttbr0_hi}, lsl #16
    cmp     x1, x0
    b.ne    9f
    mrs     x0, ESR_EL2
    ubfx    x0, x0, #5, #5               // Rt
    adr     x1, 1f
    add     x1, x1, x0, lsl #3           // 8 bytes an entry
    br      x1
1:  ldr     x0, [sp]
    b       2f
    ldr     x0, [sp, #8]
    b       2f
    mov     x0, x2
    b       2f
    mov     x0, x3
    b       2f
    mov     x0, x4
    b       2f
    mov     x0, x5
    b       2f
    mov     x0, x6
    b       2f
    mov     x0, x7
    b       2f
    mov     x0, x8
    b       2f
    mov     x0, x9
    b       2f
    mov     x0, x10
    b       2f
    mov     x0, x11
    b       2f
    mov     x0, x12
    b       2f
    mov     x0, x13
    b       2f
    mov     x0, x14
    b       2f
    mov     x0, x15
    b       2f
    mov     x0, x16
    b       2f
    mov     x0, x17
    b       2f
    mov     x0, x18
    b       2f
    mov     x0, x19
    b       2f
    mov     x0, x20
    b       2f
    mov     x0, x21
    b       2f
    mov     x0, x22
    b       2f
    mov     x0, x23
    b       2f
    mov     x0, x24
    b       2f
    mov     x0, x25
    b       2f
    mov     x0, x26
    b       2f
    mov     x0, x27
    b       2f
    mov     x0, x28
    b       2f
    mov     x0, x29
    b       2f
    mov     x0, x30
    b       2f
    mov     x0, xzr
2:  msr     TTBR0_EL1, x0
    mrs     x1, ELR_EL2
    add     x1, x1, #4
    msr     ELR_EL2, x1
    ldp     x0, x1, [sp], #16
    eret
9:  ldp     x0, x1, [sp], #16
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
    aff_mask = const super::ptcheck::AFF_MASK,
    stack_hi = const (STACK_SIZE >> 16),
    mmu = const (!cfg!(feature = "hyp-mmu-off-canary")) as u32,
    tcr = const super::mmu::TCR_EL2,
    rt_mask = const super::sysreg::RT_MASK,
    ttbr0_lo = const super::sysreg::TTBR0_WRITE_ESR & 0xffff,
    ttbr0_hi = const super::sysreg::TTBR0_WRITE_ESR >> 16,
);
