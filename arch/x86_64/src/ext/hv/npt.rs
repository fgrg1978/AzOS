// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AMD nested page tables: the guest-physical to host-physical map, built
//! with the kernel's own x86 PTE builder (`crate::mmu`).
//!
//! An NPT is an ordinary x86_64 page table walked for the *guest physical*
//! address, so the entry format is the host's. The one difference that
//! matters: the nested walk treats every guest access as a user access, so
//! the U/S bit must be set at every level or the walk faults on the first
//! access. `mmu::make_table` sets it on a table pointer; a leaf gets it from
//! a `PagePerms` with `user: true`, which is what [`leaf_perms`] returns.
//! Global (G) is never set: an NPT entry is not a kernel mapping.
//!
//! Permission is read-always (a present page is readable), write and execute
//! as asked: no combination of "execute-only" exists on x86 paging.

use azos_arch_api::{MemType, PagePerms};

use crate::mmu::{self, TableMem, WalkError};

/// What a nested mapping lets the guest do. Read is implied.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GuestAccess {
    pub write: bool,
    pub exec: bool,
}

impl GuestAccess {
    /// Data.
    pub const RW: Self = Self { write: true, exec: false };
    /// Code.
    pub const RX: Self = Self { write: false, exec: true };
}

/// The `PagePerms` of a nested leaf: user (the walk's requirement), accessed
/// and dirty preset (the monitor does not track guest page use), write-back.
pub const fn leaf_perms(a: GuestAccess) -> PagePerms {
    PagePerms { read: true, write: a.write, exec: a.exec, user: true, mem: MemType::WB, accessed: true, dirty: true }
}

/// Map guest-physical `gpa` to host-physical `hpa` with a leaf at
/// `leaf_level`, allocating intermediate tables from `mem`. `levels` is the
/// host's paging depth (`mmu::levels()`: the nested walk follows it), `gb`
/// the 1 GiB capability. The caller invalidates the guest's TLB entries
/// (`TLB_CTL`) before the next `VMRUN` when this replaced a mapping; a new
/// mapping needs nothing.
#[allow(clippy::too_many_arguments)]
pub fn map<M: TableMem>(mem: &mut M, root: usize, levels: usize, gpa: usize, hpa: usize,
                        leaf_level: usize, a: GuestAccess, gb: bool) -> Result<(), WalkError> {
    mmu::map(mem, root, levels, gpa, hpa, leaf_level, leaf_perms(a), gb)
}
