# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Minimal RISC-V 64-bit user-space test program.
# Loaded by the kernel shell with "exec /fat/HELLO.ELF".
#
# Syscall ABI (matches azos_syscall/numbers.rs):
#   a7 = syscall number
#   a0..a5 = arguments
#   ecall
#   a0 = return value
#
# SYS_PUTCHAR = 1   (a0 = char)
# SYS_WRITE   = 23  (a0=fd, a1=buf_ptr, a2=len)
# SYS_EXIT    = 3   (a0 = exit code)

.option arch, +m, +a, +c, +zicsr, +zifencei

.section .text
.align 2
.global _start

_start:
    # --- write(1, msg, msg_len) ---
    li   a7, 23             # SYS_WRITE
    li   a0, 1              # fd = 1 (stdout / UART)
    la   a1, msg            # buf ptr
    li   a2, 23             # length of "Hello from user-space!\n"
    ecall

    # --- exit(0) ---
    li   a7, 3              # SYS_EXIT
    li   a0, 0
    ecall

    # should never reach here
1:  j 1b

.section .rodata
msg:
    .ascii "Hello from user-space!\n"
