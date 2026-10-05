# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# PMP M-mode boot stub for AzOS.
#
# This stub runs in M-mode before mret into S-mode.
# It configures PMP registers with the AzOS memory-protection policy,
# then transfers control to the S-mode kernel.
#
# Usage (QEMU, no OpenSBI):
#   qemu-system-riscv64 -machine virt -bios none -kernel pmp_stub.elf
#
# The stub:
#   1. Sets up 6 TOR PMP regions (firmware/kernel text/kernel data/RT heap/ML heap/MMIO)
#   2. Sets mepc to the kernel entry point (0x80200000)
#   3. Sets mstatus.MPP = S-mode (01)
#   4. Performs mret to enter S-mode
#
# NOTE: This is a reference implementation.  For production, the PMP
# configuration should be integrated into the actual M-mode firmware
# (OpenSBI or custom M-mode init).
#
# Memory layout assumptions (QEMU virt, default):
#   Firmware:    0x00000000 - 0x80200000  (R)
#   Kernel text: 0x80200000 - KERNEL_END  (RX)
#   Kernel data: KERNEL_END - HEAP_START  (RW)
#   RT heap:     HEAP_START - HEAP_MID    (RWX)
#   ML heap:     HEAP_MID   - HEAP_END    (RW)
#   MMIO:        0x00000000 - 0x20000000  (RW, no X)

.option arch, +m, +a, +c, +zicsr

.section .text.boot
.align 2
.global _start

# ── Constants ─────────────────────────────────────────────────────────
# Adjust these for your build (from linker output / kernel_end symbol).
.equ KERNEL_ENTRY,   0x80200000
.equ FIRMWARE_END,   0x80200000   # End of OpenSBI / start of kernel
.equ KERNEL_END,     0x80240000   # Approximate; adjust per build
.equ HEAP_START,     0x80280000   # After VMM page tables
.equ HEAP_SIZE,      0x00400000   # 4 MiB
.equ HEAP_MID,       0x80480000   # HEAP_START + HEAP_SIZE/2
.equ HEAP_END,       0x80680000   # HEAP_START + HEAP_SIZE
.equ MMIO_END,       0x20000000   # 512 MiB covers all peripherals

# PMP cfg byte encoding (TOR mode):
#   [7]   L (lock)
#   [4:3] A = 01 (TOR)
#   [2]   X
#   [1]   W
#   [0]   R
.equ PMP_TOR,    0x08            # A=TOR, no perms
.equ PMP_TOR_R,  0x09            # TOR + R
.equ PMP_TOR_RX, 0x0D            # TOR + R + X
.equ PMP_TOR_RW, 0x0B            # TOR + R + W
.equ PMP_TOR_RWX,0x0F            # TOR + R + W + X

_start:
    # ── 1. Program pmpaddr registers (TOR upper bounds, >> 2) ─────────

    # Region 0: Firmware (0 .. FIRMWARE_END) — R
    li   t0, (FIRMWARE_END >> 2)
    csrw pmpaddr0, t0

    # Region 1: Kernel text (FIRMWARE_END .. KERNEL_END) — RX
    li   t0, (KERNEL_END >> 2)
    csrw pmpaddr1, t0

    # Region 2: Kernel data (KERNEL_END .. HEAP_START) — RW
    li   t0, (HEAP_START >> 2)
    csrw pmpaddr2, t0

    # Region 3: RT heap (HEAP_START .. HEAP_MID) — RWX
    li   t0, (HEAP_MID >> 2)
    csrw pmpaddr3, t0

    # Region 4: ML heap (HEAP_MID .. HEAP_END) — RW (no X)
    li   t0, (HEAP_END >> 2)
    csrw pmpaddr4, t0

    # Region 5: MMIO (0 .. MMIO_END) — RW (no X)
    li   t0, (MMIO_END >> 2)
    csrw pmpaddr5, t0

    # Region 6: Catch-all deny — max address
    li   t0, -1                  # all bits set → max address >> 2
    srli t0, t0, 2
    csrw pmpaddr6, t0

    # ── 2. Program pmpcfg0 (entries 0-7 packed in one 64-bit CSR) ─────
    #
    # Byte layout (little-endian):
    #   [7:0]   entry 0 = TOR+R     = 0x09
    #   [15:8]  entry 1 = TOR+RX    = 0x0D
    #   [23:16] entry 2 = TOR+RW    = 0x0B
    #   [31:24] entry 3 = TOR+RWX   = 0x0F
    #   [39:32] entry 4 = TOR+RW    = 0x0B
    #   [47:40] entry 5 = TOR+RW    = 0x0B
    #   [55:48] entry 6 = TOR+DENY  = 0x08
    #   [63:56] entry 7 = OFF       = 0x00

    # Build the 64-bit value in two 32-bit halves.
    # Low 32 bits:  0x0F_0B_0D_09
    li   t0, 0x0F0B0D09
    # High 32 bits: 0x00_08_0B_0B
    li   t1, 0x00080B0B
    slli t1, t1, 32
    or   t0, t0, t1
    csrw pmpcfg0, t0

    # ── 3. Set up S-mode entry ────────────────────────────────────────

    # Set mepc = kernel entry point
    li   t0, KERNEL_ENTRY
    csrw mepc, t0

    # Set mstatus.MPP = 01 (S-mode)
    # MPP is bits [12:11] of mstatus
    csrr t0, mstatus
    li   t1, (3 << 11)          # clear MPP bits
    not  t1, t1
    and  t0, t0, t1
    li   t1, (1 << 11)          # set MPP = 01 (S-mode)
    or   t0, t0, t1
    csrw mstatus, t0

    # Pass hart ID (a0) and DTB pointer (a1) to kernel_main.
    # These should already be in a0/a1 from the boot ROM / QEMU.

    # ── 4. Enter S-mode ──────────────────────────────────────────────
    mret

    # Should never reach here
1:  wfi
    j    1b
