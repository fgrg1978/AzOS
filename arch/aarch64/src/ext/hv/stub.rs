// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The resident EL2 stub: `VBAR_EL2`'s vector table, its HVC handler and the
//! world switch that runs a guest.
//!
//! `_azos_drop_to_el1` (`mmu/boot.rs`) keeps EL2 when the image is built with
//! the hypervisor (Kconfig `HV`, the cargo feature `hv`): it installs
//! `_azos_hv_vectors` into `VBAR_EL2` before the `eret`, on the primary path
//! and on every PSCI `CPU_ON` secondary (they enter at EL2 and take the same
//! trampoline), zeroes `SP_EL2` and records in `azos_hv_state` that EL2 is
//! kept. An image without the hypervisor does not install the stub at all.
//!
//! What the stub does, with no stack (`SP_EL2` is zero while the host runs
//! and the vCPU block's address while a guest does; the secondaries only set
//! their own `sp` after the drop) and `TPIDR_EL2` as its one spill slot:
//!
//! * `HVC` from AArch64 EL1 with the probe function id: returns
//!   [`PROBE_MAGIC`](super::PROBE_MAGIC) in `x0` and the ABI version in `x1`.
//! * `HVC` with a PSCI function id (`0x8400_00xx` / `0xC400_00xx`): the same
//!   call re-issued as `SMC #0`, `x0`-`x3` through, the result back to EL1.
//!   That is what a kernel with PSCI conduit `hvc` meant, and with a real EL2
//!   above it the call used to trap to a vector table that did not exist.
//!   (A **guest's** PSCI is never this: it is emulated, `serve.rs`.)
//! * [`HVC_ENTER`](super::HVC_ENTER), `x1` = the physical address of a
//!   [`Block`](super::world::Block): the world switch. The host's EL1 state,
//!   floating point, virtual timer and `HCR_EL2` / `CPTR_EL2` / `MDCR_EL2` /
//!   `CNTHCTL_EL2` / `CNTVOFF_EL2` are saved in the block; the guest's EL1
//!   state, floating point, virtual timer, list registers and the traps of a
//!   guest ([`world::hcr`](super::world::hcr)) are loaded; `SP_EL2` becomes
//!   the block; `eret` to the guest. While it runs, the EL2 physical timer
//!   (`CNTHP`, PPI 26) holds the host's own timer deadline, so the host's tick
//!   still ends a run that never exits.
//! * Any exception the guest takes to EL2 (a trap, a physical IRQ / FIQ, an
//!   SError) saves the guest into the block, restores everything above and
//!   `eret`s to the instruction after the `HVC`, with `ESR_EL2` (or
//!   [`RAW_ARM_IRQ`](azos_arch_api::RAW_ARM_IRQ)), `FAR_EL2` and `HPFAR_EL2`
//!   in the block. A physical interrupt is not acknowledged here: it is still
//!   pending when the host's `eret` unmasks it, and the host takes it.
//! * [`HVC_FLUSH`](super::HVC_FLUSH), `x1` = a VMID: `TLBI VMALLS12E1IS` for
//!   it, then `IC IALLUIS`.
//! * [`HVC_INFO`](super::HVC_INFO): `ICH_VTR_EL2` (list registers and
//!   preemption bits of the virtual CPU interface).
//! * Any other `HVC`: `x0 = -1` (SMCCC `NOT_SUPPORTED`).
//! * Anything else (a trap this stub does not own, an exception at EL2):
//!   `ESR_EL2` and `ELR_EL2` into `azos_hv_trap`, then park on `WFE`.
//!
//! EL2 runs with the MMU off: every address is physical and every access is
//! Device memory, so the handler is exclusive-free and keeps accesses aligned,
//! and the host cleans the block to the point of coherency before the `HVC`
//! and invalidates it after (`vcpu.rs`). The vector table is in
//! `.text.azos_boot`, which both linker scripts keep.
//!
//! # What is not switched
//!
//! The GIC's physical CPU interface (the guest's `ICC_*` accesses are the
//! virtual interface's: `HCR_EL2.IMO`), the debug registers beyond `MDSCR_EL1`,
//! the PMU (every access traps and is answered as a PMU with no counters,
//! `world::pmu_trap`), SVE and SME state (their use traps), the memory-tagging
//! registers (`HCR_EL2.ATA` is clear, so the guest's use traps) and the
//! statistical-profiling and trace units (the guest has none).

use core::arch::global_asm;
use core::sync::atomic::{AtomicU8, Ordering};

use super::world::off;
use super::{Availability, Reason, ABI_VERSION, HVC_ENTER, HVC_FLUSH, HVC_INFO, HVC_PROBE, PROBE_MAGIC};

global_asm!(r#"// The kernel is built soft-float (no FP in Rust code), but the world switch moves the
// FP and SIMD registers of the host and the guest: the assembler is told they exist.
.arch_extension fp
.arch_extension simd
.macro azos_el1_save base, feat
    mrs     x4, SCTLR_EL1
    mrs     x5, TTBR0_EL1
    stp     x4, x5, [\base, #0]
    mrs     x4, TTBR1_EL1
    mrs     x5, TCR_EL1
    stp     x4, x5, [\base, #16]
    mrs     x4, MAIR_EL1
    mrs     x5, AMAIR_EL1
    stp     x4, x5, [\base, #32]
    mrs     x4, VBAR_EL1
    mrs     x5, CONTEXTIDR_EL1
    stp     x4, x5, [\base, #48]
    mrs     x4, CPACR_EL1
    mrs     x5, ESR_EL1
    stp     x4, x5, [\base, #64]
    mrs     x4, FAR_EL1
    mrs     x5, AFSR0_EL1
    stp     x4, x5, [\base, #80]
    mrs     x4, AFSR1_EL1
    mrs     x5, PAR_EL1
    stp     x4, x5, [\base, #96]
    mrs     x4, TPIDR_EL1
    mrs     x5, TPIDR_EL0
    stp     x4, x5, [\base, #112]
    mrs     x4, TPIDRRO_EL0
    mrs     x5, SP_EL0
    stp     x4, x5, [\base, #128]
    mrs     x4, SP_EL1
    mrs     x5, ELR_EL1
    stp     x4, x5, [\base, #144]
    mrs     x4, SPSR_EL1
    mrs     x5, CSSELR_EL1
    stp     x4, x5, [\base, #160]
    mrs     x4, ACTLR_EL1
    mrs     x5, CNTKCTL_EL1
    stp     x4, x5, [\base, #176]
    mrs     x4, MDSCR_EL1
    stp     x4, xzr, [\base, #192]
    tbz     \feat, #0, 1f
    mrs     x4, S3_0_C2_C1_0
    mrs     x5, S3_0_C2_C1_1
    stp     x4, x5, [\base, #208]
    mrs     x4, S3_0_C2_C1_2
    mrs     x5, S3_0_C2_C1_3
    stp     x4, x5, [\base, #224]
    mrs     x4, S3_0_C2_C2_0
    mrs     x5, S3_0_C2_C2_1
    stp     x4, x5, [\base, #240]
    mrs     x4, S3_0_C2_C2_2
    mrs     x5, S3_0_C2_C2_3
    stp     x4, x5, [\base, #256]
    mrs     x4, S3_0_C2_C3_0
    mrs     x5, S3_0_C2_C3_1
    stp     x4, x5, [\base, #272]
1:
.endm
.macro azos_el1_load base, feat
    ldp     x4, x5, [\base, #0]
    msr     SCTLR_EL1, x4
    msr     TTBR0_EL1, x5
    ldp     x4, x5, [\base, #16]
    msr     TTBR1_EL1, x4
    msr     TCR_EL1, x5
    ldp     x4, x5, [\base, #32]
    msr     MAIR_EL1, x4
    msr     AMAIR_EL1, x5
    ldp     x4, x5, [\base, #48]
    msr     VBAR_EL1, x4
    msr     CONTEXTIDR_EL1, x5
    ldp     x4, x5, [\base, #64]
    msr     CPACR_EL1, x4
    msr     ESR_EL1, x5
    ldp     x4, x5, [\base, #80]
    msr     FAR_EL1, x4
    msr     AFSR0_EL1, x5
    ldp     x4, x5, [\base, #96]
    msr     AFSR1_EL1, x4
    msr     PAR_EL1, x5
    ldp     x4, x5, [\base, #112]
    msr     TPIDR_EL1, x4
    msr     TPIDR_EL0, x5
    ldp     x4, x5, [\base, #128]
    msr     TPIDRRO_EL0, x4
    msr     SP_EL0, x5
    ldp     x4, x5, [\base, #144]
    msr     SP_EL1, x4
    msr     ELR_EL1, x5
    ldp     x4, x5, [\base, #160]
    msr     SPSR_EL1, x4
    msr     CSSELR_EL1, x5
    ldp     x4, x5, [\base, #176]
    msr     ACTLR_EL1, x4
    msr     CNTKCTL_EL1, x5
    ldp     x4, x5, [\base, #192]
    msr     MDSCR_EL1, x4
    tbz     \feat, #0, 1f
    ldp     x4, x5, [\base, #208]
    msr     S3_0_C2_C1_0, x4
    msr     S3_0_C2_C1_1, x5
    ldp     x4, x5, [\base, #224]
    msr     S3_0_C2_C1_2, x4
    msr     S3_0_C2_C1_3, x5
    ldp     x4, x5, [\base, #240]
    msr     S3_0_C2_C2_0, x4
    msr     S3_0_C2_C2_1, x5
    ldp     x4, x5, [\base, #256]
    msr     S3_0_C2_C2_2, x4
    msr     S3_0_C2_C2_3, x5
    ldp     x4, x5, [\base, #272]
    msr     S3_0_C2_C3_0, x4
    msr     S3_0_C2_C3_1, x5
1:
.endm
.macro azos_fp_save base
    stp     q0, q1, [\base, #0]
    stp     q2, q3, [\base, #32]
    stp     q4, q5, [\base, #64]
    stp     q6, q7, [\base, #96]
    stp     q8, q9, [\base, #128]
    stp     q10, q11, [\base, #160]
    stp     q12, q13, [\base, #192]
    stp     q14, q15, [\base, #224]
    stp     q16, q17, [\base, #256]
    stp     q18, q19, [\base, #288]
    stp     q20, q21, [\base, #320]
    stp     q22, q23, [\base, #352]
    stp     q24, q25, [\base, #384]
    stp     q26, q27, [\base, #416]
    stp     q28, q29, [\base, #448]
    stp     q30, q31, [\base, #480]
.endm
.macro azos_fp_load base
    ldp     q0, q1, [\base, #0]
    ldp     q2, q3, [\base, #32]
    ldp     q4, q5, [\base, #64]
    ldp     q6, q7, [\base, #96]
    ldp     q8, q9, [\base, #128]
    ldp     q10, q11, [\base, #160]
    ldp     q12, q13, [\base, #192]
    ldp     q14, q15, [\base, #224]
    ldp     q16, q17, [\base, #256]
    ldp     q18, q19, [\base, #288]
    ldp     q20, q21, [\base, #320]
    ldp     q22, q23, [\base, #352]
    ldp     q24, q25, [\base, #384]
    ldp     q26, q27, [\base, #416]
    ldp     q28, q29, [\base, #448]
    ldp     q30, q31, [\base, #480]
.endm

// One list register, if the CPU interface has it (x6 = how many it has).
.macro azos_lr_load idx, crm, op2, done
    cmp     x6, #(\idx + 1)
    b.lt    \done
    ldr     x4, [x2, #({lr} + \idx * 8)]
    msr     S3_4_C12_C\crm\()_\op2, x4
.endm
.macro azos_lr_save idx, crm, op2, done
    cmp     x6, #(\idx + 1)
    b.lt    \done
    mrs     x4, S3_4_C12_C\crm\()_\op2
    str     x4, [x2, #({lr} + \idx * 8)]
.endm
// The active-priority registers a CPU interface with PREbits (x7: the field,
// bits minus one) preemption bits has: one pair always, a second pair from
// six bits, two more from seven.
.macro azos_ap_load
    ldr     x4, [x2, #{ap0r}]
    msr     S3_4_C12_C8_0, x4
    ldr     x4, [x2, #{ap1r}]
    msr     S3_4_C12_C9_0, x4
    cmp     x7, #5
    b.lt    .Lazos_ap_load_done
    ldr     x4, [x2, #({ap0r} + 8)]
    msr     S3_4_C12_C8_1, x4
    ldr     x4, [x2, #({ap1r} + 8)]
    msr     S3_4_C12_C9_1, x4
    cmp     x7, #6
    b.lt    .Lazos_ap_load_done
    ldr     x4, [x2, #({ap0r} + 16)]
    msr     S3_4_C12_C8_2, x4
    ldr     x4, [x2, #({ap0r} + 24)]
    msr     S3_4_C12_C8_3, x4
    ldr     x4, [x2, #({ap1r} + 16)]
    msr     S3_4_C12_C9_2, x4
    ldr     x4, [x2, #({ap1r} + 24)]
    msr     S3_4_C12_C9_3, x4
.Lazos_ap_load_done:
.endm
.macro azos_ap_save
    mrs     x4, S3_4_C12_C8_0
    str     x4, [x2, #{ap0r}]
    mrs     x4, S3_4_C12_C9_0
    str     x4, [x2, #{ap1r}]
    cmp     x7, #5
    b.lt    .Lazos_ap_save_done
    mrs     x4, S3_4_C12_C8_1
    str     x4, [x2, #({ap0r} + 8)]
    mrs     x4, S3_4_C12_C9_1
    str     x4, [x2, #({ap1r} + 8)]
    cmp     x7, #6
    b.lt    .Lazos_ap_save_done
    mrs     x4, S3_4_C12_C8_2
    str     x4, [x2, #({ap0r} + 16)]
    mrs     x4, S3_4_C12_C8_3
    str     x4, [x2, #({ap0r} + 24)]
    mrs     x4, S3_4_C12_C9_2
    str     x4, [x2, #({ap1r} + 16)]
    mrs     x4, S3_4_C12_C9_3
    str     x4, [x2, #({ap1r} + 24)]
.Lazos_ap_save_done:
.endm

.macro azos_hv_vec target
    .balign 0x80
    b       \target
.endm

.section .text.azos_boot, "ax"
.balign 2048
.globl _azos_hv_vectors
_azos_hv_vectors:
    // Current EL with SP0, current EL with SPx: nothing at EL2 is expected to trap.
    azos_hv_vec _azos_hv_park
    azos_hv_vec _azos_hv_park
    azos_hv_vec _azos_hv_park
    azos_hv_vec _azos_hv_park
    azos_hv_vec _azos_hv_park
    azos_hv_vec _azos_hv_park
    azos_hv_vec _azos_hv_park
    azos_hv_vec _azos_hv_park
    // Lower EL, AArch64: synchronous (the host's HVC, or a trap of the guest),
    // IRQ and FIQ (a physical interrupt while a guest runs; HCR_EL2.IMO/FMO),
    // SError.
    azos_hv_vec _azos_hv_sync
    azos_hv_vec _azos_hv_irq
    azos_hv_vec _azos_hv_irq
    azos_hv_vec _azos_hv_serror
    // Lower EL, AArch32: EL1 is AArch64 (HCR_EL2.RW = 1), so none of these arrives.
    azos_hv_vec _azos_hv_park
    azos_hv_vec _azos_hv_park
    azos_hv_vec _azos_hv_park
    azos_hv_vec _azos_hv_park

// ── a synchronous exception from a lower EL ─────────────────────────────
// x9 is spilled to TPIDR_EL2, the stub's one scratch slot. SP_EL2 is zero
// while the host runs and the block's address while a guest does (the trampoline
// zeroes it on every PE; the entry sets it, the exit clears it), so it tells
// the host's HVC from a trap of the guest without a register to spare.
.balign 4
_azos_hv_sync:
    msr     TPIDR_EL2, x9
    mov     x9, sp
    cbnz    x9, azos_hv_gexit_sync
    mrs     x9, ESR_EL2
    lsr     x9, x9, #26             // EC
    cmp     x9, #0x16               // HVC from AArch64
    b.ne    _azos_hv_park
    // The hypervisor service (owner 6, function numbers from 0x86000000).
    movz    w9, #{azhv_hi}, lsl #16
    sub     w9, w0, w9
    cbz     w9, .Lazos_probe        // HVC_PROBE, exact
    cmp     w9, #{fn_enter}
    b.eq    azos_hv_enter
    cmp     w9, #{fn_flush}
    b.eq    .Lazos_flush
    cmp     w9, #{fn_info}
    b.eq    .Lazos_info
    // PSCI: fast call, function number 0..31 with bits 23:16 zero, owner 4
    // (standard secure service), SMC32 or SMC64 (bit 30).
    tst     w0, #0x00ffffe0
    b.ne    .Lazos_unsupported
    lsr     w9, w0, #24
    bic     w9, w9, #0x40
    cmp     w9, #0x84
    b.ne    .Lazos_unsupported
    smc     #0                      // x0-x3 through, result in x0
    b       .Lazos_return
.Lazos_probe:
    movz    x0, #{magic_hi}, lsl #16
    movk    x0, #{magic_lo}
    mov     x1, #{abi}
    b       .Lazos_return
.Lazos_flush:                       // x1 = VMID: its stage-1 and stage-2 entries, everywhere
    dsb     ish                     // the tables the host just wrote
    lsl     x1, x1, #48
    msr     VTTBR_EL2, x1
    isb
    tlbi    vmalls12e1is
    dsb     ish
    ic      ialluis                 // a frame given back is code the guest may have run
    dsb     ish
    msr     VTTBR_EL2, xzr          // the host is VMID 0
    isb
    mov     x0, #0
    b       .Lazos_return
.Lazos_info:                        // ICH_VTR_EL2: list registers, preemption bits
    mrs     x0, S3_4_C12_C11_1
    b       .Lazos_return
.Lazos_unsupported:
    mov     x0, #-1                 // SMCCC NOT_SUPPORTED
.Lazos_return:
    mrs     x9, TPIDR_EL2
    eret

// A physical interrupt or an SError: the guest's, if a guest runs; the host
// never routes either here.
.balign 4
_azos_hv_irq:
    msr     TPIDR_EL2, x9
    mov     x9, sp
    cbz     x9, _azos_hv_park
    stp     x0, x1, [sp, #0]
    mov     x0, #-1                 // RAW_ARM_IRQ
    b       azos_hv_gexit
.balign 4
_azos_hv_serror:
    msr     TPIDR_EL2, x9
    mov     x9, sp
    cbz     x9, _azos_hv_park
    stp     x0, x1, [sp, #0]
    mrs     x0, ESR_EL2
    b       azos_hv_gexit

.balign 4
_azos_hv_park:
    mrs     x9, ESR_EL2
    mrs     x10, ELR_EL2
    adrp    x11, azos_hv_trap
    add     x11, x11, :lo12:azos_hv_trap
    stp     x9, x10, [x11]
1:  wfe
    b       1b

// ── entering a guest ────────────────────────────────────────────────────
// x1 = the block's physical address. The host's x0-x18 are dead (the wrapper
// below is a call) and x19-x30 are on its stack, so every register is free.
// Used: x2 the block, x3 a region base, x4-x7 scratch, x8 the feature bits,
// x10-x12 the host's timer.
.balign 4
azos_hv_enter:
    mov     x2, x1
    ldr     x8, [x2, #{feat}]
    // The host: EL1 state, the return address, the controls this changes, its
    // timer, its floating point.
    add     x3, x2, #{host_el1}
    azos_el1_save x3, x8
    mrs     x4, ELR_EL2
    str     x4, [x2, #{host_elr}]
    mrs     x4, SPSR_EL2
    str     x4, [x2, #({host_elr} + 8)]
    mrs     x4, HCR_EL2
    str     x4, [x2, #{host_hcr}]
    mrs     x4, CPTR_EL2
    str     x4, [x2, #({host_hcr} + 8)]
    mrs     x4, MDCR_EL2
    str     x4, [x2, #{host_mdcr}]
    mrs     x12, CNTVOFF_EL2
    str     x12, [x2, #({host_mdcr} + 8)]
    mrs     x4, CNTHCTL_EL2
    str     x4, [x2, #{host_cnthctl}]
    mrs     x10, CNTV_CTL_EL0
    str     x10, [x2, #({host_cnthctl} + 8)]
    mrs     x11, CNTV_CVAL_EL0
    str     x11, [x2, #{host_cntv_cval}]
    mrs     x4, FPCR
    mrs     x5, FPSR
    add     x3, x2, #{host_fpcr}
    stp     x4, x5, [x3]
    add     x3, x2, #{host_fp}
    azos_fp_save x3
    // The host's tick must still end the run: its virtual timer is replaced by
    // the guest's, so the EL2 physical timer (PPI 26) carries the host's
    // deadline (the host's CNTV compare plus its CNTVOFF) while the guest runs.
    mov     x6, xzr
    tbz     x10, #0, .Lazos_cnthp_set       // the host's timer is off
    tbnz    x10, #1, .Lazos_cnthp_set       // or masked
    add     x5, x11, x12
    msr     CNTHP_CVAL_EL2, x5
    mov     x6, #1
.Lazos_cnthp_set:
    msr     CNTHP_CTL_EL2, x6
    // The guest's controls.
    ldr     x4, [x2, #{vtcr}]
    msr     VTCR_EL2, x4
    ldr     x4, [x2, #{vttbr}]
    msr     VTTBR_EL2, x4
    ldr     x4, [x2, #{vmpidr}]
    msr     VMPIDR_EL2, x4
    mrs     x4, MIDR_EL1
    msr     VPIDR_EL2, x4
    ldr     x4, [x2, #{cntvoff}]
    msr     CNTVOFF_EL2, x4
    ldr     x4, [x2, #{cnthctl}]
    msr     CNTHCTL_EL2, x4
    ldr     x4, [x2, #{cptr}]
    msr     CPTR_EL2, x4
    ldr     x4, [x2, #{mdcr}]
    msr     MDCR_EL2, x4
    // The guest's virtual interrupt controller and timer.
    ldr     x4, [x2, #{ich_vmcr}]
    msr     S3_4_C12_C11_7, x4              // ICH_VMCR_EL2
    ldr     x6, [x2, #{nlr}]
    ldr     x7, [x2, #{prebits}]
    azos_ap_load
    azos_lr_load 0, 12, 0, .Lazos_lr_load_done
    azos_lr_load 1, 12, 1, .Lazos_lr_load_done
    azos_lr_load 2, 12, 2, .Lazos_lr_load_done
    azos_lr_load 3, 12, 3, .Lazos_lr_load_done
    azos_lr_load 4, 12, 4, .Lazos_lr_load_done
    azos_lr_load 5, 12, 5, .Lazos_lr_load_done
    azos_lr_load 6, 12, 6, .Lazos_lr_load_done
    azos_lr_load 7, 12, 7, .Lazos_lr_load_done
    azos_lr_load 8, 13, 0, .Lazos_lr_load_done
    azos_lr_load 9, 13, 1, .Lazos_lr_load_done
    azos_lr_load 10, 13, 2, .Lazos_lr_load_done
    azos_lr_load 11, 13, 3, .Lazos_lr_load_done
    azos_lr_load 12, 13, 4, .Lazos_lr_load_done
    azos_lr_load 13, 13, 5, .Lazos_lr_load_done
    azos_lr_load 14, 13, 6, .Lazos_lr_load_done
    azos_lr_load 15, 13, 7, .Lazos_lr_load_done
.Lazos_lr_load_done:
    ldr     x4, [x2, #{ich_hcr}]
    msr     S3_4_C12_C11_0, x4              // ICH_HCR_EL2
    ldr     x4, [x2, #{cntv_ctl}]
    ldr     x5, [x2, #{cntv_cval}]
    msr     CNTV_CVAL_EL0, x5
    msr     CNTV_CTL_EL0, x4
    // The guest's floating point and EL1 state.
    add     x3, x2, #{fpcr}
    ldp     x4, x5, [x3]
    msr     FPCR, x4
    msr     FPSR, x5
    add     x3, x2, #{fp}
    azos_fp_load x3
    add     x3, x2, #{guest}
    azos_el1_load x3, x8
    // Where it resumes, with stage 2 and the traps on last.
    ldr     x4, [x2, #{pc}]
    msr     ELR_EL2, x4
    ldr     x4, [x2, #{pstate}]
    msr     SPSR_EL2, x4
    ldr     x4, [x2, #{hcr}]
    msr     HCR_EL2, x4
    // SP_EL2 = the block from here until the exit: that is what says "a guest runs".
    mov     sp, x2
    ldp     x0, x1, [sp, #0]
    ldp     x4, x5, [sp, #32]
    ldp     x6, x7, [sp, #48]
    ldp     x8, x9, [sp, #64]
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
    ldr     x30, [sp, #240]
    ldp     x2, x3, [sp, #16]
    eret

// ── the guest stops ─────────────────────────────────────────────────────
// SP_EL2 = the block; the guest's x9 is in TPIDR_EL2; x0 and x1 are saved.
.balign 4
azos_hv_gexit_sync:
    stp     x0, x1, [sp, #0]
    mrs     x0, ESR_EL2
azos_hv_gexit:                      // x0 = ESR_EL2, or -1 for a physical interrupt
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    str     x8, [sp, #64]
    mrs     x1, TPIDR_EL2
    str     x1, [sp, #72]
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
    str     x30, [sp, #240]
    mov     x2, sp
    mov     x1, xzr
    mov     sp, x1                          // no guest runs any more
    str     x0, [x2, #{esr}]
    mrs     x4, FAR_EL2
    str     x4, [x2, #{far}]
    mrs     x4, HPFAR_EL2
    str     x4, [x2, #{hpfar}]
    mrs     x4, ELR_EL2
    str     x4, [x2, #{pc}]
    mrs     x4, SPSR_EL2
    str     x4, [x2, #{pstate}]
    ldr     x8, [x2, #{feat}]
    // The guest: EL1 state, floating point, timer, interrupt controller.
    add     x3, x2, #{guest}
    azos_el1_save x3, x8
    mrs     x4, FPCR
    mrs     x5, FPSR
    add     x3, x2, #{fpcr}
    stp     x4, x5, [x3]
    add     x3, x2, #{fp}
    azos_fp_save x3
    mrs     x4, CNTV_CTL_EL0
    str     x4, [x2, #{cntv_ctl}]
    mrs     x4, CNTV_CVAL_EL0
    str     x4, [x2, #{cntv_cval}]
    ldr     x6, [x2, #{nlr}]
    ldr     x7, [x2, #{prebits}]
    azos_lr_save 0, 12, 0, .Lazos_lr_save_done
    azos_lr_save 1, 12, 1, .Lazos_lr_save_done
    azos_lr_save 2, 12, 2, .Lazos_lr_save_done
    azos_lr_save 3, 12, 3, .Lazos_lr_save_done
    azos_lr_save 4, 12, 4, .Lazos_lr_save_done
    azos_lr_save 5, 12, 5, .Lazos_lr_save_done
    azos_lr_save 6, 12, 6, .Lazos_lr_save_done
    azos_lr_save 7, 12, 7, .Lazos_lr_save_done
    azos_lr_save 8, 13, 0, .Lazos_lr_save_done
    azos_lr_save 9, 13, 1, .Lazos_lr_save_done
    azos_lr_save 10, 13, 2, .Lazos_lr_save_done
    azos_lr_save 11, 13, 3, .Lazos_lr_save_done
    azos_lr_save 12, 13, 4, .Lazos_lr_save_done
    azos_lr_save 13, 13, 5, .Lazos_lr_save_done
    azos_lr_save 14, 13, 6, .Lazos_lr_save_done
    azos_lr_save 15, 13, 7, .Lazos_lr_save_done
.Lazos_lr_save_done:
    azos_ap_save
    mrs     x4, S3_4_C12_C11_7              // ICH_VMCR_EL2
    str     x4, [x2, #{ich_vmcr}]
    msr     S3_4_C12_C11_0, xzr             // ICH_HCR_EL2: the virtual interface off
    // The host back: its timer first (the guest's is in the block), then its controls.
    msr     CNTHP_CTL_EL2, xzr
    ldr     x4, [x2, #({host_mdcr} + 8)]
    msr     CNTVOFF_EL2, x4
    ldr     x4, [x2, #{host_cntv_cval}]
    msr     CNTV_CVAL_EL0, x4
    ldr     x4, [x2, #({host_cnthctl} + 8)]
    msr     CNTV_CTL_EL0, x4
    ldr     x4, [x2, #{host_cnthctl}]
    msr     CNTHCTL_EL2, x4
    ldr     x4, [x2, #{host_mdcr}]
    msr     MDCR_EL2, x4
    ldr     x4, [x2, #({host_hcr} + 8)]
    msr     CPTR_EL2, x4
    msr     VTTBR_EL2, xzr
    mrs     x4, MPIDR_EL1                   // what the host's own MPIDR_EL1 reads is VMPIDR_EL2
    msr     VMPIDR_EL2, x4
    ldr     x4, [x2, #{host_hcr}]
    msr     HCR_EL2, x4
    add     x3, x2, #{host_fpcr}
    ldp     x4, x5, [x3]
    msr     FPCR, x4
    msr     FPSR, x5
    add     x3, x2, #{host_fp}
    azos_fp_load x3
    add     x3, x2, #{host_el1}
    azos_el1_load x3, x8
    ldr     x4, [x2, #{host_elr}]
    msr     ELR_EL2, x4
    ldr     x4, [x2, #({host_elr} + 8)]
    msr     SPSR_EL2, x4
    mov     x0, xzr
    eret

// ── the host's side of the entry (EL1) ──────────────────────────────────
// azos_hv_run_guest(x0 = the block's physical address) -> x0 = 0. A call:
// the stub clobbers every register but the stack and the ones saved here, and
// hands back the host's EL1 state and floating point as they were.
.section .text.azos_hv_run_guest, "ax"
.balign 4
.globl azos_hv_run_guest
azos_hv_run_guest:
    stp     x29, x30, [sp, #-112]!
    stp     x27, x28, [sp, #16]
    stp     x25, x26, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x21, x22, [sp, #64]
    stp     x19, x20, [sp, #80]
    str     x18, [sp, #96]
    mov     x1, x0
    movz    x0, #{enter_hi}, lsl #16
    movk    x0, #{enter_lo}
    hvc     #0
    ldr     x18, [sp, #96]
    ldp     x19, x20, [sp, #80]
    ldp     x21, x22, [sp, #64]
    ldp     x23, x24, [sp, #48]
    ldp     x25, x26, [sp, #32]
    ldp     x27, x28, [sp, #16]
    ldp     x29, x30, [sp], #112
    ret

.section .data
.balign 16
.globl azos_hv_trap
azos_hv_trap:
    .quad   0                       // ESR_EL2 of the last trap the stub parked on
    .quad   0                       // ELR_EL2
.globl azos_hv_state
azos_hv_state:
    .byte   0                       // 1 once the trampoline kept EL2 (set at MMU off)
.balign 8
.text
"#,
    azhv_hi = const (HVC_PROBE >> 16) as u16,
    fn_enter = const (HVC_ENTER - HVC_PROBE),
    fn_flush = const (HVC_FLUSH - HVC_PROBE),
    fn_info = const (HVC_INFO - HVC_PROBE),
    magic_hi = const (PROBE_MAGIC >> 16) as u16,
    magic_lo = const (PROBE_MAGIC & 0xFFFF) as u16,
    abi = const ABI_VERSION,
    enter_hi = const (HVC_ENTER >> 16) as u16,
    enter_lo = const (HVC_ENTER & 0xFFFF) as u16,
    feat = const off::FEAT,
    host_el1 = const off::HOST_EL1,
    host_elr = const off::HOST_ELR,
    host_hcr = const off::HOST_HCR,
    host_mdcr = const off::HOST_MDCR,
    host_cnthctl = const off::HOST_CNTHCTL,
    host_cntv_cval = const off::HOST_CNTV_CVAL,
    host_fpcr = const off::HOST_FPCR,
    host_fp = const off::HOST_FP,
    vtcr = const off::VTCR,
    vttbr = const off::VTTBR,
    vmpidr = const off::VMPIDR,
    cntvoff = const off::CNTVOFF,
    cnthctl = const off::CNTHCTL,
    cptr = const off::CPTR,
    mdcr = const off::MDCR,
    ich_vmcr = const off::ICH_VMCR,
    ich_hcr = const off::ICH_HCR,
    nlr = const off::NLR,
    prebits = const off::PREBITS,
    cntv_ctl = const off::CNTV_CTL,
    cntv_cval = const off::CNTV_CVAL,
    fpcr = const off::FPCR,
    fp = const off::FP,
    guest = const off::GUEST,
    pc = const off::PC,
    pstate = const off::PSTATE,
    hcr = const off::HCR,
    lr = const off::LR,
    ap0r = const off::AP0R,
    ap1r = const off::AP1R,
    esr = const off::ESR,
    far = const off::FAR,
    hpfar = const off::HPFAR,
);

#[allow(non_upper_case_globals)]
extern "C" {
    static azos_hv_state: AtomicU8;
    static azos_hv_trap: [core::sync::atomic::AtomicU64; 2];
    /// The host's side of the entry: `HVC` into the stub with `block_pa`,
    /// which saves the callee-saved registers it is about to lose. Returns
    /// when the guest stops.
    fn azos_hv_run_guest(block_pa: u64) -> u64;
}

/// Did the boot path keep EL2: the byte the trampoline sets.
pub(super) fn availability() -> Availability {
    // SAFETY: a byte in `.data`, written once with the MMU off before any Rust runs.
    if unsafe { azos_hv_state.load(Ordering::Relaxed) } == 1 {
        Availability::Resident
    } else {
        Availability::Absent(Reason::EntryEl1)
    }
}

/// `ESR_EL2` and `ELR_EL2` of the last trap the stub parked a PE on, if any.
pub(super) fn last_trap() -> Option<(u64, u64)> {
    // SAFETY: two words in `.data`, written by the parked PE.
    let (esr, elr) = unsafe {
        (azos_hv_trap[0].load(Ordering::Relaxed), azos_hv_trap[1].load(Ordering::Relaxed))
    };
    if esr == 0 && elr == 0 { None } else { Some((esr, elr)) }
}

/// `HVC #0` to the stub: `x0 = HVC_PROBE`; the ABI version it answers with.
pub(super) fn probe() -> Option<u64> {
    let mut x0 = HVC_PROBE as u64;
    let x1: u64;
    // SAFETY: the stub answers the probe at EL2 and returns; the caller checked
    // that EL2 is resident, so this is not a conduit-less HVC.
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") x0,
            lateout("x1") x1,
            lateout("x2") _,
            lateout("x3") _,
            options(nostack, preserves_flags),
        );
    }
    if x0 == PROBE_MAGIC { Some(x1) } else { None }
}

/// `ICH_VTR_EL2`, read at EL2. Only on a CPU with the GICv3 system-register
/// interface (`world::gic_v3_sysregs`): elsewhere the read is undefined.
pub(super) fn gic_info() -> u64 {
    let mut x0 = HVC_INFO as u64;
    // SAFETY: the stub reads one EL2 register and returns; EL2 is resident
    // (`HvImpl::can_enter` checks both before anything asks).
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") x0,
            lateout("x1") _,
            lateout("x2") _,
            lateout("x3") _,
            options(nostack, preserves_flags),
        );
    }
    x0
}

/// Invalidate the stage-1 and stage-2 translations of `vmid` on every CPU, and
/// the instruction caches.
pub(super) fn flush(vmid: u16) {
    let mut x0 = HVC_FLUSH as u64;
    // SAFETY: the stub does the maintenance at EL2 and returns; callers check
    // `availability()` first.
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") x0,
            inout("x1") vmid as u64 => _,
            lateout("x2") _,
            lateout("x3") _,
            options(nostack, preserves_flags),
        );
    }
    let _ = x0;
}

/// Run the guest of `block` until it stops.
///
/// # Safety
/// `block` is a [`Block`](super::world::Block) in the kernel's own memory (the
/// linear map reaches it from its physical address), which the caller cleaned
/// to the point of coherency before and invalidates after; EL2 is resident;
/// the caller runs with interrupts masked on the CPU it prepared the entry for
/// (the control registers, the redistributor).
pub(super) unsafe fn run_guest(block: *mut super::world::Block) {
    let pa = (block as u64) & !crate::mmu::KERNEL_VA_OFFSET;
    // SAFETY: the contract above; the wrapper preserves the callee-saved
    // registers, the stub the host's EL1 state and floating point. The block
    // escapes into the call as a pointer, so the compiler assumes it changes.
    let r = unsafe { azos_hv_run_guest(pa) };
    debug_assert_eq!(r, 0);
}
