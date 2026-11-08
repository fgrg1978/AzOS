// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The stack this image asks for: 28 KiB.
//! Its deepest static chain is 19.6 KiB (`main`, whose frame holds the
//! applets the compiler inlined into it, `ps` holding the task table twice
//! among them, then a utility of `azos_coreutils` reporting a bad option),
//! 24.4 KiB with the 25% margin tools/lint/user_stacks.py adds.
//!
//! lld writes it as the `p_memsz` of the image's `PT_GNU_STACK` header, which
//! the loader reads (crates/core/sched/src/process.rs, `elf_bounds::stack_bytes`):
//! no file bytes, no PT_LOAD. An image without one gets Kconfig
//! `USER_STACK_SIZE_KB`. tools/lint/user_stacks.py checks the figure against the
//! image's deepest static call chain.

fn main() {
    println!("cargo:rustc-link-arg-bins=-zstack-size={}", 28 * 1024);
}
