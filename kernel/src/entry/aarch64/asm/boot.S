// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// AArch64 boot entry point for AzOS (Rust) kernel — Item 2 Stage 5.
//
// QEMU `-M virt`; `_start` opens with a 64-byte arm64 Linux boot-protocol
// Image header (see below) so this is loaded as an Image, not a plain ELF
// — the gate builds an ELF and `llvm-objcopy -O binary`'s it into a
// `.img`, and boots THAT. Either loader (QEMU's `-kernel`, or U-Boot
// `booti`) recognises the header's magic and places this binary at
// `_dram_base + _text_offset` = 0x4008_0000 (linker-aarch64.ld's ORIGIN,
// unchanged from the plain-ELF milestone this supersedes) — no firmware
// in front of us either way.
//
// Boot-time register state, per tests/qemu/aarch64-smoke/src/main.rs
// (measured on this machine, not assumed) and this task's own QEMU runs:
//   x0        = FDT pointer when loaded as an Image (the case this file
//               now targets) — QEMU synthesizes and places an FDT only
//               for a recognised Image load, never for a bare ELF
//               `-kernel` (x0 == 0 there; verified empirically, not
//               assumed — see this task's report for the QEMU behavior
//               this depended on).
//   CurrentEL = EL2 if `-M virt,virtualization=on` gives the guest a
//               real EL2, EL1 otherwise.
//   Everything else implementation-defined.
//
// Secondary PEs (every PE whose full MPIDR_EL1 affinity is nonzero) park
// on WFE at `_secondary_park` below until `crates/core/sched::smp::wake_hart`
// issues PSCI `CPU_ON` for them — Phase 4 (SMP): the target entry point is
// `_aarch64_secondary_entry`, further down this file, NOT `_start` (`x0`
// there is the `context_id` PSCI hands the new PE, this kernel's own
// convention for it is `hart_id`, not the FDT pointer `_start` expects).
// Its own stack table is `aarch64_secondary_stacks`
// (`kernel/src/main.rs`), sized like riscv64's `secondary_stacks` — see
// `_aarch64_secondary_entry`'s header comment for the full sequence.

.equ MAX_HARTS, {max_harts}

.section .text.boot
.globl _start
_start:
    // ── arm64 Linux boot-protocol Image header (Documentation/arch/
    // arm64/booting.rst) ────────────────────────────────────────────
    //
    // QEMU's `-kernel` loader and U-Boot `booti` both recognise a raw
    // (`objcopy -O binary`) image as this format by its magic at offset
    // 0x38, and ONLY THEN pass the FDT's physical address in x0 — a
    // bare ELF `-kernel` load (the boot method every earlier milestone
    // here used) always hands x0 == 0. `code0` is the one instruction
    // that must survive being executed first: it branches straight past
    // the other 60 header bytes to the real entry code below.
    // `_text_offset`/`_image_size` are ABSOLUTE symbols computed in
    // linker-aarch64.ld, not here — see that file's comment on why the
    // subtraction has to happen after the linker lays out `_kernel_end`.
    b       _entry_after_header      // code0: skip the header
    .long   0                        // code1: reserved
    .quad   _text_offset             // 0x08: image load offset from _dram_base
    .quad   _image_size              // 0x10: effective image size (bss/stack included)
    .quad   0x2                      // 0x18: flags — LE (bit0=0), placement=1 (bit1)
    .quad   0                        // 0x20: res2
    .quad   0                        // 0x28: res3
    .quad   0                        // 0x30: res4
    .byte   0x41, 0x52, 0x4d, 0x64   // 0x38: magic "ARM\x64" (little-endian 0x644d5241)
    .long   0                        // 0x3c: res5 (PE/COFF offset — unused, no PE header)

_entry_after_header:
    // Preserve the incoming FDT pointer across everything below in a
    // callee-saved register. `_azos_drop_to_el1` (arch-aarch64::boot)
    // is documented to clobber x10 only, but x19 makes that irrelevant —
    // correct regardless of what that trampoline does or later changes to.
    mov     x19, x0

    // ── Primary/secondary selection: the FULL MPIDR affinity ───────────
    //
    // tests/qemu/aarch64-smoke's `_start` checks `MPIDR_EL1 & 0xFF` (Aff0)
    // only. That misidentifies the primary on any topology with more
    // than one cluster: PE0 of cluster 0 and PE0 of cluster 1 both read
    // Aff0 == 0 and would both take the primary path. QEMU's `virt`
    // machine under a flat `-smp N` (no clusters=/sockets=) never
    // produces that shape, but nothing here should depend on the one
    // topology it happens to have been tested against.
    //
    // The mask keeps Aff3[39:32] and Aff2:Aff1:Aff0[23:0], dropping
    // MT[24], RES0[29:25], U[30] and RES1[31]. Built into a register
    // (0x0000_00FF_00FF_FFFF) rather than used as an AND immediate:
    // that bit pattern is two separate one-runs separated by zero gaps
    // on both sides, which is not representable as a single AArch64
    // logical-immediate encoding (those require one contiguous rotated
    // run, replicated at a power-of-two element size) — confirmed by
    // trying it: `and x11, x9, #0xff00ffffff` is rejected by the
    // assembler ("immediate out of range").
    mrs     x9, MPIDR_EL1
    movz    x10, #0xffff
    movk    x10, #0x00ff, lsl #16
    movk    x10, #0x00ff, lsl #32
    and     x11, x9, x10
    cbnz    x11, _secondary_park

    // ── hart_id, for kernel_main's first argument ───────────────────────
    //
    // Aff0 | Aff1<<8 | Aff2<<16 — the bottom 24 bits of MPIDR_EL1. This is
    // the FIRST place the id is computed, not the only one: it is published
    // into `TPIDR_EL1` below, and THAT register — not a live MPIDR decode —
    // is what `azos_arch::cpu::hart_id()` (crates/core/arch-aarch64/src/
    // cpu.rs) and `azos_sched::smp::current_cpu_id()` both read (U10-4:
    // they used to be two different sources; now they are one `mrs
    // TPIDR_EL1` each). It must still agree with whatever value ends up in
    // TPIDR_EL1, or a PE reserves boot-time resources under one id and
    // indexes `azos_sync::preempt` / any `PER_CPU`-shaped table under
    // another. On the primary PE this is always 0 (Aff0=Aff1=Aff2=0 is
    // exactly what the primary check above just required).
    and     x20, x9, #0x00ffffff

    // ── Publish hart id into TPIDR_EL1 ──────────────────────────────────
    //
    // `azos_sched::smp::current_cpu_id()` reads `TPIDR_EL1` on this ISA
    // (the aarch64 counterpart of riscv64's `tp`) — every `PER_CPU[...]`
    // access in the scheduler depends on it reading the right hart. Until
    // Phase 3 (context switch + scheduler), nothing wrote this register at
    // all: it held whatever QEMU reset it to, which happens to be 0 and so
    // happened to agree with the primary hart's id — a convention, not a
    // defence, and wrong the day a second PE runs real code. Written here,
    // right after x20 is computed and before anything Rust-side can read
    // it (the earliest point both facts are true), so it holds for
    // `kernel_main`'s very first call into `crates/core/sched`.
    //
    // TPIDR_EL1 is banked per EL and untouched by `_azos_drop_to_el1`
    // (that trampoline only writes HCR_EL2/CPTR_EL2/the EL2 timer+GICv3
    // grants/SCTLR_EL1 — see crates/core/arch-aarch64/src/boot.rs), so writing
    // it before the EL2->EL1 branch below is safe on both entry paths.
    msr     TPIDR_EL1, x20

    // ── Record entry EL, drop EL2 -> EL1 if needed ──────────────────────
    //
    // Mirrors riscv64 boot.S publishing `boot_hart_id` to a .data word
    // before anything can trap: a fact only boot.S can observe, kept so
    // Rust can print it. `_azos_drop_to_el1` sets HCR_EL2, CPTR_EL2,
    // the physical-timer and GICv3-sysreg EL1 grants, and SCTLR_EL1
    // (MMU off), then ERETs back into the caller's LR at EL1h with DAIF
    // masked — see crates/core/arch-aarch64/src/boot.rs for the full
    // sysreg-by-sysreg rationale. x19/x20 are callee-saved and survive
    // the `bl` regardless of that trampoline's own clobber list.
    mrs     x9, CurrentEL
    lsr     x9, x9, #2
    mov     w21, #0
    cmp     x9, #2
    b.ne    1f
    mov     w21, #1
    bl      _azos_drop_to_el1
1:
    adrp    x0, boot_entry_el
    add     x0, x0, :lo12:boot_entry_el
    strb    w21, [x0]

    // ── FP/SIMD access for EL1, on BOTH entry paths ─────────────────────
    //
    // CPACR_EL1.FPEN = 0b01 (bits [21:20]): EL1 may execute FP and Advanced
    // SIMD, EL0 traps (EC 0x07) — the lazy-FP resting state, see
    // kernel/src/entry/aarch64/fp_lazy.rs. `aarch64_early_mmu_init` sets it
    // again after `mmu_setup` (which writes 0b11). ZEN [17:16] and SMEN
    // [25:24] stay 0b00, so an SVE or SME instruction traps to OUR EL1
    // vector, where it is reported.
    //
    // **This was missing on the EL1 path (found 2026-09-21).** The only
    // writers of CPACR_EL1 were `_azos_drop_to_el1` — which runs only
    // when we enter at EL2 — and `mmu_setup::enable_identity_map`, which
    // this kernel does not call yet. So entered at EL1 (how QEMU `virt`
    // starts us without `virtualization=on`, and how the gate runs),
    // FP/SIMD was trapped, and the first FP instruction in Rust code took
    // an EC=0x07 exception. The minimal kernel_main happened to emit none;
    // a canary that forced 4 KiB of stack use got its buffer-fill loop
    // vectorised to NEON and trapped at once (the kernel was hard-float
    // then). The kernel is now soft-float and emits no FP itself, but EL1
    // still needs FPEN for the lazy user-FP save/restore and the boot FP
    // self-check. Written here, after the two entry paths converge and
    // before any compiled code runs, it holds for both.
    movz    x9, #0x10, lsl #16
    msr     CPACR_EL1, x9
    isb

    // ── PSTATE.PAN = 1, on BOTH entry paths (O3.2, owner decision) ───────
    //
    // Same bug class as CPACR_EL1 above, found the same way (this task's
    // own pan-probe feature, run against a scratch USER-tagged page):
    // `crates/core/arch-aarch64::boot::_azos_drop_to_el1`'s `SPSR_EL2` write
    // sets PAN too, but that trampoline runs ONLY when entered at EL2, and
    // even then only takes effect from the ERET onward — SCTLR_EL1.SPAN=0
    // (same file) only sets PAN on a LATER EL0->EL1 exception, which has
    // not happened yet this early. Entered at EL1 directly (how QEMU
    // `virt` starts us without `virtualization=on`, and how the gate
    // runs — see the CPACR_EL1 comment above), NEITHER path ever ran, and
    // PAN kept whatever its architectural reset state is (measured:
    // "protection off" — the pan-probe read a USER-tagged page from EL1
    // and did NOT fault). Written here, after the two entry paths
    // converge, holds for both from this point on.
    .arch_extension pan
    msr     PAN, #1

    // ── Install the exception vector table ──────────────────────────────
    //
    // Before anything else can fault: until VBAR_EL1 is live, a fault
    // here is implementation-defined behaviour, not a clean report. This
    // is the aarch64 counterpart of riscv64's "stvec before any
    // faultable code" in trap_init() — just earlier in boot, because
    // aarch64 has no OpenSBI underneath us already holding *some* vector
    // live the way riscv64 does until trap_init() runs.
    adrp    x0, _vectors
    add     x0, x0, :lo12:_vectors
    msr     VBAR_EL1, x0
    isb

    // ── Boot stack ───────────────────────────────────────────────────────
    //
    // linker-aarch64.ld's `.stack` section: below _kernel_end, NOLOAD,
    // with a red zone under it — same shape as every riscv64 linker
    // script's `.stack`.
    adrp    x0, _stack_end
    add     x0, x0, :lo12:_stack_end
    mov     sp, x0

    // Paint the stack + red zone with the SAME BOOT_STACK_PAINT pattern
    // riscv64 boot.S uses (0x5354414B5354414B, "STAKSTAK") so
    // `boot_stack_report` in kernel/src/boot/stacks.rs reads it back with no
    // per-ISA branch. Nothing has run on this stack yet.
    adrp    x0, _stack_redzone
    add     x0, x0, :lo12:_stack_redzone
    adrp    x1, _stack_end
    add     x1, x1, :lo12:_stack_end
    movz    x2, #0x5354, lsl #48
    movk    x2, #0x414b, lsl #32
    movk    x2, #0x5354, lsl #16
    movk    x2, #0x414b
paint_stack:
    cmp     x0, x1
    b.hs    paint_stack_done
    str     x2, [x0], #8
    b       paint_stack
paint_stack_done:

    // ── Clear .bss ───────────────────────────────────────────────────────
    //
    // `. = ALIGN(8)` right before `_bss_end` in linker-aarch64.ld
    // guarantees the last 8-byte store lands exactly on the boundary —
    // the same guarantee the stack-paint loop above relies on for
    // `_stack_end` (`.stack` is 4K-aligned) and riscv64's clear_bss
    // relies on for its own `_bss_end`.
    adrp    x0, _bss_start
    add     x0, x0, :lo12:_bss_start
    adrp    x1, _bss_end
    add     x1, x1, :lo12:_bss_end
clear_bss:
    cmp     x0, x1
    b.hs    clear_bss_done
    str     xzr, [x0], #8
    b       clear_bss
clear_bss_done:

    // ── MMU on, before the first atomic (Item 2 Stage 5, task 2) ────────
    //
    // With the MMU off, every data access is Device-nGnRnE — and an
    // exclusive/atomic access (every `AtomicBool::compare_exchange`, every
    // spinlock) to Device memory is CONSTRAINED UNPREDICTABLE per the ARM
    // ARM (QEMU tolerates it; real silicon is not obliged to). The very
    // first thing `kernel_main` does is `uart::init()` → a `kprintln!` →
    // `UartGuard`'s spinlock → a `compare_exchange`. So the MMU must be on
    // — with RAM mapped Normal cacheable — before that call, not inside
    // it. `aarch64_early_mmu_init` (kernel/src/entry/aarch64.rs) owns
    // three static page tables and calls straight into
    // `arch_aarch64::mmu_setup::enable_identity_map` — the SAME identity-
    // map code `tests/qemu/aarch64-smoke` already boots through, not a second
    // copy of the MAIR/TCR encoding. It touches only its own static
    // tables and CPU system registers: no lock, no atomic, so it is safe
    // to run before any lock exists. x19 (dtb ptr) / x20 (hart id) are
    // callee-saved across the `bl` per AAPCS64, same guarantee this file
    // already leans on for `_azos_drop_to_el1` above.
    bl      aarch64_early_mmu_init

    // ── TTBR1 alias — aarch64 parity program, "move the kernel into
    //    TTBR1" migration, first wave ──────────────────────────────────
    //
    // Primary only (no counterpart in `_aarch64_secondary_entry` below):
    // this wave's alias table is a standalone boot-time PROOF that
    // TCR_EL1's upper-half fields and TTBR1_EL1 are wired correctly (see
    // `aarch64_early_ttbr1_alias`'s own doc) — it is not yet the
    // kernel's real mapping, so every secondary booting through its own
    // MMU-on path (`aarch64_secondary_mmu_init`, below) needs none of it.
    // x19 (dtb ptr) / x20 (hart id) are callee-saved across this `bl`,
    // same AAPCS64 guarantee `aarch64_early_mmu_init`'s own call already
    // relies on.
    bl      aarch64_early_ttbr1_alias

    // ── Move the PC into the upper half (TTBR1) ─────────────────────────
    //
    // The kernel is LINKED high, so from here on every symbol reference is a
    // high VA; the identity map TTBR0 still holds is what got us this far.
    // `movz/movk` because `global_asm!` has no literal pool, and `br` on a
    // computed absolute address because a relative `b` would land back in the
    // low alias it is trying to leave.
    .globl  _kernel_va_offset_check
    .set    _kernel_va_offset_check, {kernel_va_offset}
    .globl  _azos_page_size_check
    .set    _azos_page_size_check, {page_size}
    movz    x10, #(({kernel_va_offset} >> 48) & 0xffff), lsl #48
    movk    x10, #(({kernel_va_offset} >> 32) & 0xffff), lsl #32
    adr     x9, 1f
    add     x9, x9, x10
    br      x9
1:
    // Vector base and stack still point low. Both move before anything can
    // fault or push: a fault taken with a low VBAR_EL1 once TTBR0 stops
    // mapping the kernel is unrecoverable AND silent, because the handler
    // cannot translate its own first instruction.
    mrs     x9, VBAR_EL1
    add     x9, x9, x10
    msr     VBAR_EL1, x9
    isb
    mov     x9, sp
    add     x9, x9, x10
    mov     sp, x9

    // ── Call Rust kernel_main(hart_id, dtb_ptr) ────────────────────────
    mov     x0, x20
    mov     x1, x19
    bl      kernel_main

    // kernel_main's signature is `-> !`; this exists only so a bug that
    // somehow returns halts instead of running off the end of .text.
halt:
    wfi
    b       halt

// PEs that lost the primary check above park here. Also where
// `_aarch64_secondary_entry` below sends a hart whose id is out of range —
// PSCI `CPU_ON` (Phase 4, SMP) wakes every OTHER PE at that entry point
// instead of leaving them here; a PE that never gets a `CPU_ON` (this
// kernel simply never calls `wake_hart` for it — see
// `crates/core/sched::smp::wake_harts`) stays parked on `wfe` for however long
// QEMU keeps it alive, same as before this task.
_secondary_park:
    wfe
    b       _secondary_park

.size _start, . - _start

// ── Secondary PE entry — Phase 4 (SMP) ──────────────────────────────────
//
// PSCI `CPU_ON` (`arch-aarch64::psci::cpu_on`, called from
// `crates/core/sched::smp::wake_hart`) starts the target PE HERE, not at
// `_start` — `x0` carries the `context_id` argument, and `_start` needs
// `x0` to be the FDT pointer the Image-format boot protocol hands the
// PRIMARY. This kernel's own convention (not a PSCI requirement) is
// `context_id = hart_id`: `crates/core/sched::smp::wake_hart`'s own doc explains
// why (a table lookup here, not a trusted pointer). Mirrors riscv64's own
// `_secondary_start` (`kernel/src/entry/riscv64/asm/boot.S`) — same
// contract (a small integer in, not an address), same per-hart stack table
// shape, same range check before anything is computed from it.
//
// **Every PE on QEMU `virt,virtualization=on` arrives here at EL2**, same
// as the primary — PSCI `CPU_ON` starts a target PE at the SAME exception
// level the boot protocol gave the primary (measured; `crates/aarch64-
// smoke`'s own secondary path documents this). So this path needs the SAME
// EL2->EL1 drop `_start` above takes, not a `virtualization=on`-only
// special case.
.globl _aarch64_secondary_entry
.align 2
_aarch64_secondary_entry:
    // x0 = hart_id (this kernel's own convention — see header comment).
    mov     x20, x0

    // Range-check BEFORE anything is computed from it — same ordering
    // `_secondary_start`'s own comment insists on (riscv64 boot.S): a stack
    // slot or table index derived from an out-of-range id points outside
    // the table this kernel actually sized, into whatever `.bss` sits next.
    mov     x9, #MAX_HARTS
    cmp     x20, x9
    b.hs    _secondary_park

    // ── Record entry EL, drop EL2 -> EL1 if needed ──────────────────────
    // No `boot_entry_el` store here (unlike the primary path): that byte is
    // a single global "how did boot happen" fact for kernel_main's own
    // banner, already recorded once by the primary; every secondary taking
    // the same EL2 path would just restate the identical value into a
    // location nothing re-reads afterward.
    mrs     x9, CurrentEL
    lsr     x9, x9, #2
    cmp     x9, #2
    b.ne    1f
    bl      _azos_drop_to_el1
1:
    // ── Publish hart id into TPIDR_EL1 ──────────────────────────────────
    // Same reason as the primary's own write above: every `PER_CPU[...]`
    // access in `crates/core/sched` depends on `current_cpu_id()` reading the
    // right core. Canary (b) — drop this line — must fail the
    // `CORE_HART_ID` readback marker, not silently corrupt scheduling: with
    // it missing, `TPIDR_EL1` keeps whatever PSCI `CPU_ON` reset it to
    // (`0` on QEMU), so every secondary would misidentify itself as hart 0.
    msr     TPIDR_EL1, x20

    // ── FP/SIMD access for EL1 (CPACR_EL1.FPEN = 0b01, EL0 traps) ────────
    // Same bug class the primary path's own comment documents: this PE's
    // CPACR_EL1 is its own banked reset state, untouched by anything the
    // primary did. `aarch64_early_mmu_init`/`aarch64_secondary_mmu_init`
    // (Rust, below) set it again after `mmu_setup`'s own 0b11 writes.
    movz    x9, #0x10, lsl #16
    msr     CPACR_EL1, x9
    isb

    // PAN is ALSO banked per-PE (O3.2) — same reason as CPACR_EL1 above.
    .arch_extension pan
    msr     PAN, #1

    // ── Install the exception vector table ──────────────────────────────
    // Banked per-PE, same as CPACR_EL1 above — VBAR_EL1 is not inherited
    // from the primary.
    adrp    x0, _vectors
    add     x0, x0, :lo12:_vectors
    msr     VBAR_EL1, x0
    isb

    // ── This core's own boot stack ───────────────────────────────────────
    // sp = aarch64_secondary_stacks[hart_id] + stack_size — the SAME
    // arithmetic `_secondary_start` (riscv64) does with `secondary_stacks`,
    // computed here rather than trusting a stack top handed through
    // `context_id`: `x20` (hart_id) was already range-checked above, an
    // address would not have been.
    adrp    x0, aarch64_secondary_stacks
    add     x0, x0, :lo12:aarch64_secondary_stacks
    adrp    x1, _aarch64_secondary_stack_size
    add     x1, x1, :lo12:_aarch64_secondary_stack_size
    ldr     x1, [x1]
    mul     x2, x20, x1
    add     x0, x0, x2
    add     sp, x0, x1

    // ── MMU on, against the REAL kernel page table, before the first
    //    atomic ──────────────────────────────────────────────────────────
    // Same constraint as the primary's own `bl aarch64_early_mmu_init`
    // above (Device memory + an exclusive access is CONSTRAINED
    // UNPREDICTABLE) — `aarch64_secondary_mmu_init` (kernel/src/entry/
    // aarch64.rs) reads the published table PA with a plain (non-exclusive)
    // load, which IS safe pre-MMU, and switches TTBR0_EL1 to it. `sp` is
    // live (set above) and no atomic has run yet, so this `bl` is safe.
    // Same low→high sequence as the primary, per PE. Order matters: the
    // identity map lets this core run with the MMU on while its PC is still
    // low, TTBR1 (banked per PE) makes the high half exist for it at all, and
    // only after the jump may TTBR0 move to the real kernel table.
    bl      aarch64_early_mmu_init
    bl      aarch64_secondary_ttbr1_attach

    movz    x10, #(({kernel_va_offset} >> 48) & 0xffff), lsl #48
    movk    x10, #(({kernel_va_offset} >> 32) & 0xffff), lsl #32
    adr     x9, 2f
    add     x9, x9, x10
    br      x9
2:
    mrs     x9, VBAR_EL1
    add     x9, x9, x10
    msr     VBAR_EL1, x9
    isb
    mov     x9, sp
    add     x9, x9, x10
    mov     sp, x9

    bl      aarch64_secondary_mmu_init

    // ── Call Rust aarch64_smp_secondary_start(hart_id) ───────────────────
    mov     x0, x20
    bl      aarch64_smp_secondary_start

    // `aarch64_smp_secondary_start`'s signature is `-> !`; this exists only
    // so a bug that somehow returns parks instead of running off the end.
    b       _secondary_park

.size _aarch64_secondary_entry, . - _aarch64_secondary_entry

// Entry EL, recorded before the EL2->EL1 drop so kernel_main can print
// it: 1 if this boot took the trampoline, 0 if QEMU started us at EL1
// directly (`virtualization=on` vs not, on `-M virt`).
.section .data
.align 3
.globl boot_entry_el
boot_entry_el:
    .byte 0

.extern _azos_drop_to_el1
.extern _vectors
.extern kernel_main
.extern aarch64_early_mmu_init
.extern aarch64_early_ttbr1_alias
.extern aarch64_secondary_mmu_init
.extern aarch64_smp_secondary_start
.extern aarch64_secondary_stacks
.extern _aarch64_secondary_stack_size
