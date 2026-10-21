// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `crates/core/sched/src/kernel_ctx.rs`, the real file: the
//! floor a task with no user page table may name to `copy_to_user` and its
//! siblings. The crash it pins stored to user VA `0x14fb8` from task
//! `thread` (riscv64, QEMU `virt`, RAM at `0x8000_0000`).

use crate::kernel_ctx::{addr_ok, floor};

/// `process::USER_STACK_TOP` is `RAM_BASE` (the ceiling stays under the
/// kernel's identity map), or `0x8000_0000` for RAM at 0.
const QEMU_RV: (usize, usize) = (0x8000_0000, 0x8000_0000);
const QEMU_ARM: (usize, usize) = (0x4000_0000, 0x4000_0000);
const VF2: (usize, usize) = (0x4000_0000, 0x4000_0000);
const X86: (usize, usize) = (0, 0x8000_0000);
const K1: (usize, usize) = (0, 0x8000_0000);

/// The user VA the crash stored to.
const CRASH_VA: usize = 0x14fb8;

#[test]
fn the_crash_address_is_refused_on_every_board_but_k1() {
    for (name, (ram, top), riscv) in [
        ("qemu riscv64", QEMU_RV, true),
        ("qemu aarch64", QEMU_ARM, false),
        ("vf2", VF2, true),
        ("x86_64", X86, false),
    ] {
        let f = floor(ram, top, riscv);
        assert_eq!(f, top, "{name}: the floor is the user ceiling");
        assert!(!addr_ok(CRASH_VA, f), "{name}: a store to 0x14fb8 must be refused");
        assert!(!addr_ok(top - 1, f), "{name}: the last user byte is a user address");
    }
}

#[test]
fn a_kernel_address_is_kept() {
    let f = floor(QEMU_RV.0, QEMU_RV.1, true);
    assert!(addr_ok(0x8000_0000, f), "RAM, where a kernel stack lives");
    assert!(addr_ok(0x8020_0000, f), "the kernel image");
    assert!(addr_ok(usize::MAX - 7, f), "the top of the address space is not a user address");
    // aarch64 and x86_64 kernel half.
    assert!(addr_ok(0xffff_0000_0000_0000, floor(QEMU_ARM.0, QEMU_ARM.1, false)));
    assert!(addr_ok(0xffff_ffff_8000_0000, floor(X86.0, X86.1, false)));
}

#[test]
fn a_range_that_crosses_the_ceiling_is_a_user_range() {
    // The caller tests the FIRST byte: a range starting under the floor is
    // refused whatever its length, one starting at it is a kernel range.
    let f = floor(QEMU_RV.0, QEMU_RV.1, true);
    assert!(!addr_ok(f - 4, f));
    assert!(addr_ok(f, f));
}

#[test]
fn k1_keeps_the_old_behaviour_and_x86_does_not() {
    // K1: riscv64 with RAM at 0, kernel memory below any ceiling: no floor.
    assert_eq!(floor(K1.0, K1.1, true), 0);
    assert!(addr_ok(CRASH_VA, floor(K1.0, K1.1, true)));
    // x86_64 reports RAM at 0 too, and has a higher-half kernel: floor kept.
    assert_eq!(floor(X86.0, X86.1, false), 0x8000_0000);
    assert!(!addr_ok(CRASH_VA, floor(X86.0, X86.1, false)));
}
