# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Boot entry point for AzOS (Rust)
# RISC-V 64-bit, S-mode (OpenSBI provides M-mode)
#
# Boot parameters from OpenSBI:
#   a0 = hart_id (the hardware `mhartid`)
#   a1 = dtb_ptr (device tree blob)
#
# `tp` holds the LOGICAL CPU id, not the hardware hart id: the boot hart is
# CPU 0 whatever its `mhartid` is (a JH7110 boots on hart 1..4, hart 0 being
# the S7 monitor core), and every other hart is started with its logical id
# as the SBI `opaque` argument (`azos_percpu` maps one to the other).
#
# Secondary harts are started later via SBI HSM hart_start(),
# which jumps directly to _secondary_start.

# Enable ISA extensions for LLVM 19+ assembler (decomposed M and A extensions)
.option arch, +m, +a, +c, +zicsr, +zifencei, +zaamo, +zalrsc, +zmmul

# Number of harts with a per-hart trap-vector slot / stack slot.
# NOT hand-duplicated: `{max_harts}` is substituted by the
# `global_asm!(..., max_harts = const MAX_HARTS)` block in
# kernel/src/main.rs, so kernel/src/main.rs::MAX_HARTS is the single source.
# Do not replace it with a literal.
.equ MAX_HARTS, {max_harts}

.section .text.boot
.global _start

_start:
    mv s0, a0                      # Save hart_id
    mv s1, a1                      # Save dtb_ptr

    # Boot hart selection: atomic lock, first hart wins
    la t0, boot_lock
    li t1, 1
    amoswap.w.aq t2, t1, (t0)
    bnez t2, secondary_halt        # Others halt (SBI HSM will start them later)

    # Disable S-mode interrupts
    csrw sie, zero

    # tp = the logical CPU id (per-CPU data): the boot hart is CPU 0. Its
    # trap vector is slot 0 of `trap_hart_vectors` (trap_init), whose id word
    # is 0 too.
    li tp, 0

    # Boot stack: the linker scripts' `.stack` section, below _kernel_end.
    la sp, _stack_end

    # Paint the boot stack and the red zone under it before anything runs on
    # it, so `boot_stack_report` (kernel/src/boot/stacks.rs) can read back how deep
    # kernel_main went and whether it went past the stack. Nothing has run on
    # this stack yet: OpenSBI hands off to `_start` directly (B2-02, 2026-09-
    # 21 — the no-OpenSBI M-mode boot stub that used to reuse this same stack
    # before `_start` ran was deleted; it was never wired to a real entry).
    la t0, _stack_redzone
    la t1, _stack_end
    li t2, 0x5354414B5354414B      # BOOT_STACK_PAINT, "STAKSTAK"
paint_stack:
    bgeu t0, t1, paint_stack_done
    sd t2, 0(t0)
    addi t0, t0, 8
    j paint_stack
paint_stack_done:

    # Clear BSS
    #
    # bgeu stops the loop at or before _bss_end; it does not itself make an
    # unaligned _bss_end safe. Each `sd` writes 8 bytes, so a last write that
    # starts below _bss_end could still land up to 7 bytes past it. What
    # actually makes this safe is `. = ALIGN(8)` right before `_bss_end` in
    # all five linker scripts (kernel/linker*.ld) — _bss_end is always
    # 8-byte aligned, so the last `sd` lands exactly on it, never past. The
    # stack-paint loop above relies on the same guarantee for `_stack_end`
    # (`.stack` sections are 4K-aligned).
    la t0, _bss_start
    la t1, _bss_end
clear_bss:
    bgeu t0, t1, clear_bss_done
    sd zero, 0(t0)
    addi t0, t0, 8
    j clear_bss
clear_bss_done:

.if {kaslr}
    # ── Virtual KASLR (Kconfig KASLR not n) ─────────────────────────────────
    #
    # The image is linked position-independent at the address it is loaded at.
    # Here, with satp = 0 and the PC still at that physical address, the boot
    # hart picks a random base for it in the upper half of Sv39, applies the
    # image's R_RISCV_RELATIVE relocations (the delta is 0 when no seed was
    # found under `probe`; the walk still runs, because the linker leaves a RELA
    # target zero) and, when it slid the image, builds a boot root (low 256 GiB
    # 1:1 with gigapages + the image at its new base), records its satp and the
    # bias (run VA minus PA) in AZOS_RV64_BOOT_SATP / AZOS_RV64_IMAGE_BIAS. Every operand
    # below is a PC-relative address, so nothing here reads a pointer the
    # relocations have not fixed. s0 (hart) and s1 (dtb) are callee-saved and
    # tp is never touched by Rust. A `require` that cannot be met stops inside,
    # on the SBI console.
    mv      a0, s1                   # device tree (physical, 0 = none)
    lla     a1, _text_start          # image start
    lla     a2, _kernel_end
    lla     a3, __rela_start
    lla     a4, __rela_end
    call    riscv64_early_kaslr
    lla     t0, AZOS_RV64_IMAGE_BIAS
    ld      t1, 0(t0)
    beqz    t1, 2f                   # not slid: keep running at the physical address
    lla     t0, AZOS_RV64_BOOT_SATP
    ld      t0, 0(t0)
    lla     t2, 1f
    add     t2, t2, t1               # the slid address of 1:
    fence   rw, rw
    csrw    satp, t0                 # the boot root maps this PC 1:1 and at 1:
    sfence.vma zero, zero
    jr      t2
1:
    lla     sp, _stack_end           # the stack, now through the image window
2:
.endif

    # fence.i here does not serve I-cache/BSS coherence: .bss is data, never
    # fetched as instructions, so clearing it cannot leave a stale icache
    # line behind. No known correctness bug depends on this fence — it is
    # cheap, defensive insurance before the first far call into Rust
    # (`call kernel_main` below), not a fix for a coherence problem BSS
    # clearing could cause.
    fence.i

    # Call Rust kernel_main(boot hart's hardware id, dtb_ptr)
    mv a0, s0
    mv a1, s1
    call kernel_main

    # If kernel_main returns, halt
halt:
    wfi
    j halt

# Harts that lost the boot lock wait here until SBI HSM starts them
secondary_halt:
    wfi
    j secondary_halt

.size _start, . - _start

# Secondary CPU entry point
# Called by SBI HSM hart_start: a0 = hart_id (opaque argument)
.section .text.boot
.global _secondary_start
.align 2

_secondary_start:
    # a0 = the hart's hardware id, a1 = the `opaque` hart_start was given:
    # the logical CPU id (`azos_arch::firmware::hart_start`). The hardware id
    # is not needed past here; every table below is indexed by the logical id.
    mv s0, a1
    mv tp, a1

    csrw sie, zero

    # Range-check the CPU id BEFORE anything is computed from it. The sp
    # derived from an id >= MAX_HARTS would index past AZOS_SECONDARY_SP
    # into adjacent .data; parking used to happen only after that sp was already
    # live in the register file, so any future instruction between stack
    # setup and the park that touched the stack would have corrupted .bss.
    # Nothing before this needs more than s0 itself.
    li t1, MAX_HARTS
    bgeu s0, t1, secondary_halt     # no stack slot, no trap-vector slot,
                                    # no PER_CPU entry: park

.if {kaslr}
    # A slid image (Kconfig KASLR): this hart starts at the physical address
    # SBI was given with satp = 0. Install the boot root (AZOS_RV64_BOOT_SATP, built
    # by the boot hart; it maps this PC 1:1 and the image at its slid base) and
    # jump to the slid address of the next instruction, then go on as if
    # started there. The boot hart's write of both words is ordered before this
    # hart's start by the SBI call that started it. Not slid (AZOS_RV64_IMAGE_BIAS
    # = 0): nothing to do.
    lla     t0, AZOS_RV64_IMAGE_BIAS
    ld      t1, 0(t0)
    beqz    t1, 2f
    lla     t0, AZOS_RV64_BOOT_SATP
    ld      t0, 0(t0)
    lla     t2, 1f
    add     t2, t2, t1
    csrw    satp, t0
    sfence.vma zero, zero
    jr      t2
1:
    fence.i                          # the walk wrote data inside the image: no stale instruction view
2:
.endif

    # Stack = AZOS_SECONDARY_SP[hart_id]: the top of this CPU's boot stack
    # in its per-CPU area (kernel/src/main.rs), written by the boot hart
    # before it started us. 0 = no area (not a possible CPU): park.
    la t0, AZOS_SECONDARY_SP
    slli t2, s0, 3
    add t0, t0, t2
    ld sp, 0(t0)
    beqz sp, secondary_halt

    # Set trap vector — K-C16: this hart's OWN slot, not the generic vector.
    # Each slot carries its hart id in the word just below the entry point, so
    # the trap entry can rebuild the kernel tp after a trap from U-mode
    # instead of trusting the tp ring 3 handed it.  stvec is a per-hart CSR
    # and U-mode cannot write it, which is exactly why the id is kept there.
    la t0, trap_hart_vectors
    slli t2, s0, 3                  # slot stride = 8 bytes
    add t0, t0, t2
    addi t0, t0, 4                  # stvec points at the `j`, id word at -4
    csrw stvec, t0

    csrw sscratch, zero

    .equ SSTATUS_SPP, (1 << 8)     # Supervisor Previous Privilege = S-mode
    li t0, SSTATUS_SPP
    csrs sstatus, t0

    # A hart that left through the saved-context path (a non-retentive
    # hart_suspend, or a hotplug stop: kernel/src/entry/riscv64/resume.rs) has
    # a slot waiting; `azos_cpu_resume_check` takes it once. It goes back to
    # what it saved. A hart without one (every first start) boots below.
    mv a0, s0
    call azos_cpu_resume_check
    beqz a0, 1f
    j azos_cpu_resume_restore
1:
    # Call Rust secondary_main(hart_id), the one secondary entry every ISA
    # reaches (kernel/src/boot/smp.rs)
    mv a0, s0
    call secondary_main

    wfi
    j secondary_halt

.size _secondary_start, . - _secondary_start

.if {kaslr}
.extern riscv64_early_kaslr
.extern AZOS_RV64_IMAGE_BIAS
.extern AZOS_RV64_BOOT_SATP
.extern __rela_start
.extern __rela_end
.endif
.extern AZOS_SECONDARY_SP
.extern azos_cpu_resume_check
.extern azos_cpu_resume_restore
.extern trap_hart_vectors

# Boot lock (atomic)
.section .data
.align 2
.global boot_lock
boot_lock:
    .word 0
