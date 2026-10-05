// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SYS_MMIO_MAP` (509), the one way ring 3 maps device registers.
//!
//! RFC-0043: the caller names an index into the board's MMIO region table,
//! not an address, and the table decides the range and whether it may be
//! written. See `crates/core/ipc/src/mmio_cap.rs` for the argument check.

use crate::handlers::*;

/// A capability refusal written at dispatch level returns -1, the value of
/// `dispatch.rs`'s `E_PERM`, not a handler's -99.
const E_PERM: i64 = -1;

/// `SYS_MMIO_MAP`: a0 = region index, a1 = access (`CapPerms` bits: READ, or
/// READ|WRITE). Maps exactly the table's range into the calling task's user
/// page table, read-only unless WRITE was asked, and returns its virtual
/// address.
///
/// Refusals, in order: an index above `u32::MAX` or outside the table, or any
/// other access word, `EINVAL`; WRITE on a read-only region, `EACCES`; no
/// `MmioRegion` capability for the index with the access asked, `-1`, recorded
/// as a capability denial. A mapping the page table cannot take is `-1`.
pub fn sys_mmio_map(a0: u64, a1: u64) -> i64 {
    let (index, region, writable) = match azos_ipc::mmio_cap::mmio_resolve(a0, a1) {
        Ok(r) => r,
        Err(e) => return e.errno().to_syscall_ret(),
    };
    if !cap_check(azos_abi::cap::CapKind::MmioRegion, index, writable) {
        return E_PERM;
    }
    match azos_sched::process::mmio_map_user(region.base, region.size, writable) {
        Some(va) => va as i64,
        None => -1,
    }
}
