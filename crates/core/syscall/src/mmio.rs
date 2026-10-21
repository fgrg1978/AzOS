// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `DOMAIN_MMIO_MAP`, the one way ring 3 maps device registers.
//!
//! The caller names a device of the hardware bus by its handle, not
//! an address; the bus decides the range, the capability whether it may be
//! written. See `crates/core/ipc/src/mmio_cap.rs` for the argument check.

use crate::handlers::*;

/// A capability refusal written at dispatch level returns -1, the value of
/// `dispatch.rs`'s `E_PERM`, not a handler's -99.
const E_PERM: i64 = -1;

/// `DOMAIN_MMIO_MAP`: a0 = device handle, a1 = access (`CapPerms` bits: READ,
/// or READ|WRITE). Maps exactly the device's register window into the calling
/// task's user page table, read-only unless WRITE was asked, and returns its
/// virtual address.
///
/// Refusals, in order: a handle above `u32::MAX`, naming no device or a device
/// a kernel driver owns or may still take, one whose probe failed, or one with
/// no window, or any other access word, `EINVAL`; no `Device` capability for the handle with the access asked
/// (WRITE needs a capability that carries WRITE), `-1`, recorded as a
/// capability denial. A mapping the page table cannot take is `-1`. The
/// mapping is booked with the bus before it is made: from then on no kernel
/// driver is bound to the device.
pub fn sys_mmio_map(a0: u64, a1: u64) -> i64 {
    let (index, _, writable) = match azos_ipc::mmio_cap::mmio_resolve(a0, a1) {
        Ok(r) => r,
        Err(e) => return e.errno().to_syscall_ret(),
    };
    if !cap_check(azos_abi::cap::ty::MMIO, index, writable) {
        return E_PERM;
    }
    let Some((base, size)) = azos_ipc::mmio_cap::mmio_claim(index) else {
        return azos_abi::error::Errno::EINVAL.to_syscall_ret();
    };
    match azos_sched::process::mmio_map_user(base as usize, size as usize, writable) {
        Some(va) => va as i64,
        None => {
            azos_ipc::mmio_cap::mmio_unclaim(index);
            -1
        }
    }
}
