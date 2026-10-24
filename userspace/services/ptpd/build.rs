// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The stack this image asks for: 20 KiB.
//! Its deepest static chain is 15.5 KiB on riscv64 (`_start`, `main`, the
//! NIC-queue receive path with its frame buffers on the stack), 19.4 KiB with
//! the margin: over the 16 KiB default (Kconfig `USER_STACK_SIZE_KB`).
//!
//! lld writes it as the `p_memsz` of the image's `PT_GNU_STACK` header, which
//! the loader reads (crates/core/sched/src/process.rs, `elf_bounds::stack_bytes`):
//! no file bytes, no PT_LOAD. tools/lint/user_stacks.py checks the figure against
//! the image's deepest static call chain.

fn main() {
    println!("cargo:rustc-link-arg-bins=-zstack-size={}", 20 * 1024);
}
