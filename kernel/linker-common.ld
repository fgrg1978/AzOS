/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Fernando Rodriguez */
/*
 * Shared boot-stack sizing for every AzOS linker script (B1-01).
 *
 * Was five copies of the same two lines (kernel/linker.ld, linker-vf2.ld,
 * linker-k1.ld, linker-fleet.ld, linker-embedded.ld) — the class of constant
 * that drifts silently: change one to grow the boot stack and the other four
 * still ship the old value. INCLUDEd, not copied.
 *
 * kernel_main peaks at 85 KiB of boot stack (measured 2026-09-15, QEMU,
 * `--features qemu`, report printed at the end of kernel_main); 256K leaves
 * room for other feature sets and growth. `boot_stack_report` (kernel/src/boot/stacks.rs)
 * fails the gate if a build ever writes into the red zone.
 */
BOOT_STACK_SIZE = 256K;
BOOT_STACK_REDZONE = 16K;
