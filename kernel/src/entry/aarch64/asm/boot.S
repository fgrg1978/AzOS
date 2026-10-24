// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// AArch64 boot entry point for AzOS (Rust) kernel — Item 2 Stage 5.
//
// QEMU `-M virt`; `_start` opens with a 64-byte arm64 Linux boot-protocol
// Image header (see below) so this is loaded as an Image, not a plain ELF
// — the gate builds an ELF and `llvm-objcopy -O binary`'s it into a
// `.img`, and boots THAT. Either loader (QEMU's `-kernel`, or U-Boot
// `booti`) recognises the header's magic and places this binary
// `_text_offset` above the base of its DRAM: 0x4008_0000 on QEMU `virt`
// (linker-aarch64.ld's ORIGIN, the link address). The Raspberry Pi firmware
// reads no header and puts kernel8.img at its `kernel_address` (0x8_0000 on
// a Pi 3 under QEMU, 0x20_0000 by default on a Pi 5), with RAM at 0. The
// image runs wherever it lands (KASLR's relocation walk moves it from the
// link address; see "Where RAM is").
//
// Boot-time register state (measured under QEMU, not assumed):
//   x0        = FDT pointer when loaded as an Image (the case this file
//               now targets) — QEMU synthesizes and places an FDT only
//               for a recognised Image load, never for a bare ELF
//               `-kernel` (x0 == 0 there; verified empirically, not
//               assumed — see this task's report for the QEMU behavior
//               this depended on). Measured again 2026-10-09 on QEMU
//               11.0.0 (`-S`, monitor `xp`, `-append` given): for the ELF,
//               x0 = 0 at `_start` and RAM base 0x4000_0000 reads zeros.
//               For a non-Linux image QEMU places the DTB only in the RAM
//               below the image's lowest address (here 512 KiB, up to
//               0x4008_0000), and `virt`'s DTB is 1 MiB (totalsize
//               0x100000, padded), so it is silently left out. Given a
//               packed copy (`-dtb`, 8 KiB) QEMU does put it, bootargs and
//               all, at 0x4000_0000, but x0 is still 0: only a probe of RAM
//               base would find it, and nothing here probes. An ELF boot
//               therefore has no device tree and no command line (`init=`,
//               `canary=`): boot the Image (`kernel.img`), as the gate does.
//   CurrentEL = EL2 if `-M virt,virtualization=on` gives the guest a
//               real EL2, EL1 otherwise.
//   Everything else implementation-defined.
//
// The PE that enters `_start` is the boot CPU, whatever its MPIDR_EL1
// affinity: the arm64 boot protocol (Documentation/arch/arm64/booting.rst)
// starts only the boot CPU at the image and holds the others in firmware.
// They start when `crates/core/sched::smp::wake_hart` issues PSCI `CPU_ON`
// for them — Phase 4 (SMP): the target entry point is
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
    // callee-saved register. `_azos_drop_to_el1` (arch-aarch64::mmu::boot)
    // is documented to clobber x10 only, but x19 makes that irrelevant —
    // correct regardless of what that trampoline does or later changes to.
    mov     x19, x0

    // ── Where RAM is: the gigabyte the image was loaded into ───────────
    //
    // The bootstrap identity map covers one gigabyte of DRAM (`mmu::
    // BOOT_WINDOW`), so its base is the image's physical address rounded
    // down to that size, from the PC alone, before any device tree is read:
    // 0x4000_0000 on QEMU `virt` (the image at 0x4008_0000), 0 on a
    // Raspberry Pi. The header's `text_offset` is not used: only QEMU and
    // U-Boot honour it, while the Pi firmware loads kernel8.img at its own
    // `kernel_address` (0x80000 on a Pi 3 under QEMU, 0x200000 by default on
    // a Pi 4 or 5, which minus our 0x80000 is no gigabyte at all). x23
    // (callee-saved) carries it to the early MMU, KASLR and TTBR1 calls
    // below; x22 is the image's PA.
    adrp    x22, _start
    add     x22, x22, :lo12:_start
    lsr     x23, x22, #{boot_window_shift}
    lsl     x23, x23, #{boot_window_shift}

    // ── The boot CPU: whichever PE the loader started (K1 M5) ──────────
    //
    // No MPIDR test. This used to require affinity == 0 and park every other
    // PE on `wfe`, so a SoC whose boot CPU has a nonzero affinity (a
    // cluster-1 boot, some big.LITTLE and server parts) parked the only CPU
    // the loader started, before any console existed. The boot protocol
    // already guarantees one PE here (PSCI keeps the rest off, a spin table
    // in firmware), and the kernel needs no election: no first-wins atomic
    // either, since with the MMU off data accesses are Device memory, where
    // exclusives are IMPLEMENTATION DEFINED (a part without a global
    // monitor may fail them forever) — Linux's head.S takes none either. The boot CPU's hardware id is read where it is needed:
    // `boot_hooks::firmware_table` maps `read_mpidr()` to logical CPU 0.
    //
    // ── hart_id, for kernel_main's first argument ───────────────────────
    //
    // The LOGICAL CPU id, not an affinity: the boot CPU is CPU 0
    // (`crate::boot::BOOT_CPU`), as riscv64's boot.S sets `tp`. It is
    // published into `TPIDR_EL1` below, and THAT register is what
    // `azos_arch::cpu::hart_id()` and `azos_sched::smp::current_cpu_id()`
    // both read (U10-4: one `mrs TPIDR_EL1` each). An affinity there (the
    // old `MPIDR & 0xffffff`) would index every `PER_CPU`-shaped table out
    // of range on a boot CPU with a nonzero affinity.
    mov     x20, #0

    // ── Record entry EL, drop EL2 -> EL1 if needed ──────────────────────
    //
    // `_azos_drop_to_el1` sets HCR_EL2, CPTR_EL2,
    // the physical-timer and GICv3-sysreg EL1 grants, and SCTLR_EL1
    // (MMU off), then ERETs back into the caller's LR at EL1h with DAIF
    // masked — see crates/core/arch-aarch64/src/mmu/boot.rs for the full
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

    // ── Publish hart id into TPIDR_EL1 ──────────────────────────────────
    //
    // `azos_sched::smp::current_cpu_id()` reads `TPIDR_EL1` on this ISA
    // (the aarch64 counterpart of riscv64's `tp`): every `PER_CPU[...]`
    // access in the scheduler depends on it reading the right CPU. Written
    // before anything Rust-side can read it, so it holds for `kernel_main`'s
    // very first call into `crates/core/sched`.
    //
    // At EL1, after the drop, as the secondary path does (K1 L12): at EL2 a
    // loader that entered with HCR_EL2.E2H=1 (a VHE-only core) redirects the
    // EL1 register names to EL2, and `TPIDR_EL1` would keep its UNKNOWN
    // reset value.
    msr     TPIDR_EL1, x20

    // ── FP/SIMD access for EL1, on BOTH entry paths ─────────────────────
    //
    // CPACR_EL1.FPEN = 0b01 (bits [21:20]): EL1 may execute FP and Advanced
    // SIMD, EL0 traps (EC 0x07) — the lazy-FP resting state, see
    // kernel/src/entry/aarch64/fp.rs. `aarch64_early_mmu_init` sets it
    // again after `mmu::setup` (which writes 0b11). ZEN [17:16] and SMEN
    // [25:24] stay 0b00, so an SVE or SME instruction traps to OUR EL1
    // vector, where it is reported.
    //
    // **This was missing on the EL1 path (found 2026-09-21).** The only
    // writers of CPACR_EL1 were `_azos_drop_to_el1` — which runs only
    // when we enter at EL2 — and `mmu::setup::enable_identity_map`, which
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
    // `crates/core/arch-aarch64::mmu::boot::_azos_drop_to_el1`'s `SPSR_EL2` write
    // once set PAN too, but that trampoline runs ONLY when entered at EL2
    // (it now leaves PAN and SPAN to this block) — SCTLR_EL1.SPAN=0 (below)
    // only sets PAN on a LATER EL0->EL1 exception, which has not happened
    // yet this early. Entered at EL1 directly (how QEMU
    // `virt` starts us without `virtualization=on`, and how the gate
    // runs — see the CPACR_EL1 comment above), NEITHER path ever ran, and
    // PAN kept whatever its architectural reset state is (measured:
    // "protection off" — the pan-probe read a USER-tagged page from EL1
    // and did NOT fault). Written here, after the two entry paths
    // converge, holds for both from this point on.
    //
    // FEAT_PAN is Armv8.1: on an Armv8.0 core (Cortex-A53/A72) `MSR PAN`
    // is UNDEFINED and, with VBAR_EL1 not yet set, the boot dies silently
    // here. So it runs only when Kconfig `A64_PAN` is not `n` AND
    // ID_AA64MMFR1_EL1.PAN [23:20] is non-zero, under `require` too: a
    // `require`d PAN on a core without it must reach the [ISA] refusal
    // instead of dying here. `pan_unprobed` is the canary
    // (`a64-pan-unprobed-canary`): the instruction back without the probe.
    //
    // ── SCTLR_EL1, on BOTH entry paths (el0-state-audit) ─────────────────
    //
    // The whole word (`sysregs::SCTLR_EL1_BOOT`), with SPAN cleared under the
    // same probe as PAN, so every exception from EL0 sets PSTATE.PAN. Same bug
    // class again: entered at EL1, nothing wrote SCTLR_EL1 but the MMU enable,
    // which ORs M, C and I into the firmware's word, so its EL0 controls (UMA,
    // UCT, DZE, UCI, TSCXT) and SPAN rode through. QEMU's EL1 reset has SPAN
    // 1: after the first eret to EL0 (SPSR 0) the kernel ran with PAN 0 on
    // every exception from ring 3. The canary (`el0-state-canary`) skips the
    // write, the old path.
    movz    x9, #{sctlr_lo}
    movk    x9, #{sctlr_hi}, lsl #16
.if {pan_allowed}
.if {pan_unprobed} == 0
    mrs     x10, ID_AA64MMFR1_EL1
    ubfx    x10, x10, #20, #4
    cbz     x10, 1f
.endif
    .arch_extension pan
    msr     PAN, #1
    bic     x9, x9, #(1 << 23)       // SCTLR_EL1.SPAN = 0
1:
.endif
.if {sctlr_canary} == 0
    msr     SCTLR_EL1, x9
    isb
.endif

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
    // it. `aarch64_early_mmu_init` (kernel/src/entry/aarch64/mod.rs) owns
    // three static page tables and calls straight into
    // `arch_aarch64::mmu::setup::enable_identity_map` — the SAME identity-
    // map code as every other user of the arch crate, not a second copy of
    // the MAIR/TCR encoding. It touches only its own static
    // tables and CPU system registers: no lock, no atomic, so it is safe
    // to run before any lock exists. x19 (dtb ptr) / x20 (hart id) are
    // callee-saved across the `bl` per AAPCS64, same guarantee this file
    // already leans on for `_azos_drop_to_el1` above.
    mov     x0, x23                  // DRAM base
    bl      aarch64_early_mmu_init

.if {kaslr}
    // ── Virtual KASLR (Kconfig KASLR not n) ──────────────────────────────
    //
    // The image is linked position-independent at KERNEL_VA_OFFSET + its load
    // address. Here, with the identity map live and the PC still low, the
    // boot picks a random base for it in the image half of the upper range,
    // applies the image's R_AARCH64_RELATIVE relocations (the delta is 0
    // when no seed was found under `probe`; the walk still runs, because the
    // linker leaves a RELA target zero) and records the base in
    // AZOS_IMAGE_BIAS (run VA minus PA of the image). Every operand is an
    // `adrp`/`add` physical address, so nothing here reads a pointer the
    // relocations have not fixed. x19 (dtb) and x20 (hart) are callee-saved.
    // A `require` that cannot be met stops inside, on the PL011.
    mov     x0, x19                  // device tree (physical, 0 = none)
    adrp    x1, _start
    add     x1, x1, :lo12:_start     // image start
    adrp    x2, _kernel_end
    add     x2, x2, :lo12:_kernel_end
    adrp    x3, __rela_start
    add     x3, x3, :lo12:__rela_start
    adrp    x4, __rela_end
    add     x4, x4, :lo12:__rela_end
    ldr     x5, _kernel_link_pa_word // where the image was linked to load
    mov     x6, x23                  // DRAM base
    bl      aarch64_early_kaslr
.else
    // Without KASLR the link is not position-independent: the image runs only
    // where it was linked to load. A loader that put it elsewhere (a board
    // whose RAM is not QEMU `virt`'s) is refused on the PL011, not left to
    // run into the first absolute address.
    ldr     x9, _kernel_link_pa_word
    cmp     x9, x22
    b.ne    aarch64_early_misplaced
.endif

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
    // The slid image's blocks (Kconfig KASLR) need its physical extent.
    adrp    x0, _start
    add     x0, x0, :lo12:_start
    adrp    x1, _kernel_end
    add     x1, x1, :lo12:_kernel_end
    mov     x2, x23                  // DRAM base
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
.if {kaslr}
    // The image's run VA minus its PA: KERNEL_VA_OFFSET unless the boot slid
    // it (`aarch64_early_kaslr`). The stack below is in the image, so the
    // same bias moves the PC, VBAR_EL1 and SP.
    adrp    x10, AZOS_IMAGE_BIAS
    ldr     x10, [x10, :lo12:AZOS_IMAGE_BIAS]
.else
    movz    x10, #(({kernel_va_offset} >> 48) & 0xffff), lsl #48
    movk    x10, #(({kernel_va_offset} >> 32) & 0xffff), lsl #32
.endif
    adr     x9, 1f
    add     x9, x9, x10
    br      x9
1:
    hint    #36                      // bti j: the `br` above is an indirect branch
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

    // ── Signed returns on (Kconfig A64_PAUTH; cpu/cfi.rs) ───────────────
    //
    // The last point with no signed frame on the stack: Rust ran before this
    // (the MMU bring-up) with `paciasp`/`autiasp` both no-ops, and from
    // `kernel_main` on every non-leaf function signs its return address.
    // `azos_cfi_prepare` loads the key and says whether to flip SCTLR_EL1.EnIA
    // (not on a core without PAuth, or with A64_PAUTH = n); the flip is a
    // leaf of its own because it must not return through a frame that signed.
    mov     x0, #1                   // the boot CPU
    bl      azos_spec_apply          // PSTATE.SSBS = 0 where FEAT_SSBS (A64_MIT_SSB)
    mov     x0, #1                   // the boot CPU makes the key
    bl      azos_cfi_prepare
    cbz     x0, 1f
    bl      _azos_cfi_enable
1:

    // ── Call Rust kernel_main(hart_id, dtb_ptr) ────────────────────────
    mov     x0, x20
    mov     x1, x19
    bl      kernel_main

    // kernel_main's signature is `-> !`; this exists only so a bug that
    // somehow returns halts instead of running off the end of .text.
halt:
    wfi
    b       halt

// Where `_aarch64_secondary_entry` below sends a PE it must not run: an
// out-of-range hart id, and its other refusals. PSCI `CPU_ON` (Phase 4,
// SMP) starts every other PE at that entry point; a PE that never gets a
// `CPU_ON` (this kernel never calls `wake_hart` for it — see
// `crates/core/sched::smp::wake_harts`) stays in firmware.
_secondary_park:
    wfe
    b       _secondary_park

// The physical address the image was linked to load at (linker-aarch64.ld's
// `_kernel_link_pa`, an absolute symbol, so no relocation touches the word).
// `aarch64_early_kaslr` relocates the image from there to wherever the loader
// actually put it (`_start`'s `adrp`), which is not the same place on a board
// whose RAM is not where QEMU `virt`'s is.
.balign 8
_kernel_link_pa_word:
    .quad   _kernel_link_pa

.size _start, . - _start

// ── Secondary PE entry — Phase 4 (SMP) ──────────────────────────────────
//
// PSCI `CPU_ON` (`arch-aarch64::firmware::cpu_on`, called from
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
// level the boot protocol gave the primary (measured; `tests/qemu/aarch64-
// smoke`'s own secondary path documents this). So this path needs the SAME
// EL2->EL1 drop `_start` above takes, not a `virtualization=on`-only
// special case.
.globl _aarch64_secondary_entry
.align 2
_aarch64_secondary_entry:
    // CFI landing pad (Kconfig A64_BTI): `bti jc`, HINT #38, a no-op on a core
    // without FEAT_BTI, so unconditional. PSCI CPU_ON enters here.
    hint    #38                      // bti jc
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
    // right core. Canary (b) — drop this line — must fail the boot, not
    // silently corrupt scheduling: with it missing, `TPIDR_EL1` keeps
    // whatever PSCI `CPU_ON` reset it to (`0` on QEMU), so everything this
    // secondary runs before `secondary_main` acts as hart 0. It fails the
    // per-hart TTBR0/TTBR1 and CPACR_EL1 readbacks (published from that
    // early code into hart 0's slot), NOT the `CORE_HART_ID` marker:
    // `secondary_main` (kernel/src/boot/smp.rs) rewrites `TPIDR_EL1` with
    // `set_percpu_base` before `secondary_publish_online` reads it back.
    msr     TPIDR_EL1, x20

    // ── FP/SIMD access for EL1 (CPACR_EL1.FPEN = 0b01, EL0 traps) ────────
    // Same bug class the primary path's own comment documents: this PE's
    // CPACR_EL1 is its own banked reset state, untouched by anything the
    // primary did. `aarch64_early_mmu_init`/`aarch64_secondary_mmu_init`
    // (Rust, below) set it again after `mmu::setup`'s own 0b11 writes.
    movz    x9, #0x10, lsl #16
    msr     CPACR_EL1, x9
    isb

    // PAN and SCTLR_EL1 are ALSO banked per-PE (O3.2) — same reason as
    // CPACR_EL1 above, and probed the same way as the primary's (Armv8.0 has
    // no FEAT_PAN): the boot word, SPAN cleared where PAN is in use.
    movz    x9, #{sctlr_lo}
    movk    x9, #{sctlr_hi}, lsl #16
.if {pan_allowed}
.if {pan_unprobed} == 0
    mrs     x10, ID_AA64MMFR1_EL1
    ubfx    x10, x10, #20, #4
    cbz     x10, 1f
.endif
    .arch_extension pan
    msr     PAN, #1
    bic     x9, x9, #(1 << 23)       // SCTLR_EL1.SPAN = 0
1:
.endif
.if {sctlr_canary} == 0
    msr     SCTLR_EL1, x9
    isb
.endif

    // ── Install the exception vector table ──────────────────────────────
    // Banked per-PE, same as CPACR_EL1 above — VBAR_EL1 is not inherited
    // from the primary.
    adrp    x0, _vectors
    add     x0, x0, :lo12:_vectors
    msr     VBAR_EL1, x0
    isb

    // ── This core's own boot stack ───────────────────────────────────────
    // sp = AZOS_SECONDARY_SP[hart_id]: the PHYSICAL top of this CPU's boot
    // stack in its per-CPU area (kernel/src/main.rs), written — and cleaned
    // to the point of coherency, since we read it with the MMU off — by the
    // boot CPU before it started us. 0 = no area (not a possible CPU): park.
    // `x20` (hart_id) was already range-checked above against MAX_HARTS, the
    // table's length. Read through the table rather than trusting a stack
    // address handed through `context_id`: an address could not be checked.
    adrp    x0, AZOS_SECONDARY_SP
    add     x0, x0, :lo12:AZOS_SECONDARY_SP
    ldr     x0, [x0, x20, lsl #3]
    cbz     x0, _secondary_park
    mov     sp, x0

    // ── MMU on, against the REAL kernel page table, before the first
    //    atomic ──────────────────────────────────────────────────────────
    // Same constraint as the primary's own `bl aarch64_early_mmu_init`
    // above (Device memory + an exclusive access is CONSTRAINED
    // UNPREDICTABLE) — `aarch64_secondary_mmu_init` (kernel/src/entry/
    // aarch64/mod.rs) reads the published table PA with a plain (non-exclusive)
    // load, which IS safe pre-MMU, and switches TTBR0_EL1 to it. `sp` is
    // live (set above) and no atomic has run yet, so this `bl` is safe.
    // Same low→high sequence as the primary, per PE. Order matters: the
    // identity map lets this core run with the MMU on while its PC is still
    // low, TTBR1 (banked per PE) makes the high half exist for it at all, and
    // only after the jump may TTBR0 move to the real kernel table.
    // DRAM base, the primary's own derivation (see `_start`).
    adrp    x0, _start
    add     x0, x0, :lo12:_start
    lsr     x0, x0, #{boot_window_shift}
    lsl     x0, x0, #{boot_window_shift}
    bl      aarch64_early_mmu_init
    bl      aarch64_secondary_ttbr1_attach
    cbz     x0, _secondary_park           // no TTBR1 to attach: never run on the boot alias (K1 L9)

    movz    x10, #(({kernel_va_offset} >> 48) & 0xffff), lsl #48
    movk    x10, #(({kernel_va_offset} >> 32) & 0xffff), lsl #32
.if {kaslr}
    // x10 = the linear map's offset (this PE's stack is in the linear map:
    // AZOS_SECONDARY_SP is a physical top); x11 = the image's bias (PC and
    // VBAR), read with the MMU on, so it is coherent with the boot CPU's write.
    adrp    x11, AZOS_IMAGE_BIAS
    ldr     x11, [x11, :lo12:AZOS_IMAGE_BIAS]
.else
    mov     x11, x10
.endif
    adr     x9, 2f
    add     x9, x9, x11
    br      x9
2:
    hint    #36                      // bti j: the `br` above is an indirect branch
    mrs     x9, VBAR_EL1
    add     x9, x9, x11
    msr     VBAR_EL1, x9
    isb
    mov     x9, sp
    add     x9, x9, x10
    mov     sp, x9

    bl      aarch64_secondary_mmu_init

    // ── Signed returns on, with the boot CPU's key (see `_start`) ────────
    mov     x0, #0                   // a secondary: also the firmware workaround and the refusal
    bl      azos_spec_apply
    mov     x0, #0
    bl      azos_cfi_prepare
    cbz     x0, 1f
    bl      _azos_cfi_enable
1:

    // ── A PE that left through the saved-context path ────────────────────
    // A power-down CPU_SUSPEND or a hotplug stop (kernel/src/entry/aarch64/
    // resume.rs) leaves a slot waiting; `azos_cpu_resume_check` takes it once.
    // The PE goes back to what it saved, on the stack and MMU set up above. A
    // PE without a slot (every first start) boots below.
    mov     x0, x20
    bl      azos_cpu_resume_check
    cbz     x0, 1f
    b       azos_cpu_resume_restore
1:
    // ── Call Rust secondary_main(hart_id) ────────────────────────────────
    // The one secondary entry every ISA reaches (kernel/src/boot/smp.rs).
    mov     x0, x20
    bl      secondary_main

    // `secondary_main`'s signature is `-> !`; this exists only
    // so a bug that somehow returns parks instead of running off the end.
    b       _secondary_park

.size _aarch64_secondary_entry, . - _aarch64_secondary_entry

// ── Spin-table pen ───────────────────────────────────────────────────────
//
// A CPU the firmware held in a spin table (device tree `enable-method =
// "spin-table"`, a Raspberry Pi 3) jumps here when the boot CPU writes this
// address to its `cpu-release-addr` (`azos_arch::smp::spin_table_release`,
// early in the boot): MMU off, the firmware's exception level, no argument.
// It waits for its slot of `AZOS_SPIN_GO` (crates/core/arch-aarch64/src/
// smp.rs) to hold its own affinity key with bit 63 set — the boot CPU writes
// it when it starts the CPU (`spin_table_start`) and cleans the line to the
// point of coherency, which is what these Device-type loads see — and then
// enters `_aarch64_secondary_entry` with the slot's index, its logical id, in
// x0: the same entry and contract PSCI `CPU_ON` gives.
.globl _aarch64_spin_pen
.align 2
_aarch64_spin_pen:
    hint    #38                      // bti jc: the firmware's `br`
    // x1 = this CPU's affinity key: Aff2:Aff1:Aff0 from MPIDR_EL1[23:0] and
    // Aff3 ([39:32]) at [31:24] (`azos_arch::cpu::mpidr_affinity_key`).
    mrs     x9, MPIDR_EL1
    and     x1, x9, #0xffffff
    ubfx    x9, x9, #32, #8
    orr     x1, x1, x9, lsl #24
    adrp    x2, AZOS_SPIN_GO
    add     x2, x2, :lo12:AZOS_SPIN_GO
1:
    mov     x0, #0
2:
    ldr     x3, [x2, x0, lsl #3]
    tbz     x3, #63, 3f
    cmp     w3, w1
    b.eq    _aarch64_secondary_entry
3:
    add     x0, x0, #1
    cmp     x0, #MAX_HARTS
    b.lo    2b
    wfe
    b       1b

.size _aarch64_spin_pen, . - _aarch64_spin_pen

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
.extern azos_spec_apply
.extern azos_cfi_prepare
.extern _azos_cfi_enable
.extern aarch64_early_ttbr1_alias
.if {kaslr}
.extern aarch64_early_kaslr
.else
.extern aarch64_early_misplaced
.extern AZOS_IMAGE_BIAS
.extern __rela_start
.extern __rela_end
.endif
.extern aarch64_secondary_mmu_init
.extern secondary_main
.extern AZOS_SECONDARY_SP
.extern AZOS_SPIN_GO
