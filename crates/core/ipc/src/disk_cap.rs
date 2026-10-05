// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `Cap<Disk>` scoped to one partition (RFC-0048 P3).
//!
//! **Resource numbering.** Resource `0` is the whole medium, as it has been
//! since the disk syscalls were first gated; nothing mints it (a kernel task
//! passes `cap_check` without one). Resource `n + 1` is partition `n` of the
//! table the kernel parsed at boot (`azos_drv_block::partition`). A
//! partition holder names sectors RELATIVE to its partition (owner decision,
//! round 23): the disk syscalls add the partition's start, so a sector outside
//! it cannot even be spelled; a run past the partition's end is refused and
//! recorded (`handlers.rs::disk_lba`).
//!
//! **The only minter is the topology** (`cap_seed`, target `"disk.part.<n>"`,
//! owner decision: one partition from a kernel-parsed MBR/GPT, minted by
//! topology). A partition the kernel did not find cannot be minted: the
//! capability would otherwise name a range that some later table might give
//! a different meaning.

use crate::cap::{targets, Cap, CapPerms};

/// The capability resource for partition `index`, or `None` past the table's
/// numbering (`u32::MAX` has no `+ 1`).
pub const fn partition_resource(index: u32) -> Option<u32> {
    index.checked_add(1)
}

/// The partition a non-zero `resource` names, or `None` for the whole-disk
/// resource 0.
pub const fn resource_partition(resource: u32) -> Option<u32> {
    if resource == 0 { None } else { Some(resource - 1) }
}

/// Mint a `Cap<Disk>` for partition `index` into `tid`.
///
/// Refused when the kernel published no such partition, or when `perms` asks
/// for anything but read and/or write.
pub fn disk_part_grant_cap(tid: u32, index: u32, perms: CapPerms) -> Option<Cap<targets::Disk>> {
    let bits = perms.bits();
    if bits == 0 || bits & !CapPerms::RW.bits() != 0 {
        return None;
    }
    azos_drv_block::partition::partition(index)?;
    let resource = partition_resource(index)?;
    crate::cap_store::grant::<targets::Disk>(tid, perms, resource)
}
