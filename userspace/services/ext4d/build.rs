// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The stack this image asks for: 32 KiB. A path walk nests a lookup, a
//! directory block's map and an inode read, each with a block-sized buffer;
//! tools/lint/user_stacks.py checks the figure against the deepest static chain.

fn main() {
    println!("cargo:rustc-link-arg-bins=-zstack-size={}", 32 * 1024);
}
