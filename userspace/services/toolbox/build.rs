// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The stack this image asks for: 24 KiB.
//! Its deepest static chain is 16.6 KiB (`main > ps`, which holds the task
//! table twice), 20.8 KiB with the 25% margin tools/lint/user_stacks.py adds.
//!
//! lld writes it as the `p_memsz` of the image's `PT_GNU_STACK` header, which
//! the loader reads (crates/core/sched/src/process.rs, `elf_bounds::stack_bytes`):
//! no file bytes, no PT_LOAD. An image without one gets Kconfig
//! `USER_STACK_SIZE_KB`. tools/lint/user_stacks.py checks the figure against the
//! image's deepest static call chain.

fn main() {
    println!("cargo:rustc-link-arg-bins=-zstack-size={}", 24 * 1024);
}
