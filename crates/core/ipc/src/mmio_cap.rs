// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cap<Device> over a device's register window.
//!
//! A capability over device registers names a DEVICE of the hardware bus
//! (`azos_drv_bus::hwbus`), never an address: its resource is the device's
//! bus handle (its slot index; devices are enumerated at boot and never
//! leave). The device's
//! window is whatever the enumerator found (a device-tree `reg`, a
//! virtio-mmio window, a PCI memory BAR); whether it may be mapped at all is
//! the bus's answer (`Bus::user_window`: no window, a kernel driver owns it
//! or may still take it, or its probe failed half-way, and it may not);
//! whether it may be written is the capability's permission, which the signed
//! topology chose. A mapping is booked with the bus ([`mmio_claim`]) before
//! it is made, and from then on no kernel driver is bound to that device.
//!
//! Two decisions live here, both pure given the bus so a host crate can
//! compile this file (`tests/host/topology-tests`):
//!
//! - [`mmio_grant_cap`], the topology minter: `"mmio.<selector>"` (the
//!   hardware bus's selector text: `dt:google,goldfish-rtc`, `pci:1af4:1041`,
//!   `virtio:2#1`) names a device by what it is, so a topology need not know
//!   the order a machine enumerated its hardware in. It refuses a selector no
//!   device matches, a device ring 3 may not map, and a grant no mapping
//!   could honour (without READ, or with a bit beyond READ|WRITE).
//! - [`mmio_resolve`], the argument check of `DOMAIN_MMIO_MAP`
//!   (`crates/core/syscall/src/mmio.rs`): the handle and access word a caller
//!   sent, turned into the window to map or the errno to return. The
//!   capability check follows it, in the syscall, against the handle.
//!
//! Lives in `crates/core/ipc/` beside `motor_cap.rs`: the bus is in
//! `azos_drv_bus`, which `ipc` already depends on.

use crate::cap::{targets, Cap, CapPerms};
use azos_abi::error::Errno;
use azos_drv_bus::hwbus;

/// Why `DOMAIN_MMIO_MAP`'s arguments were refused, before any capability check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MmioMapError {
    /// The handle is above `u32::MAX`, names no live device, or names one
    /// ring 3 may not map (no window, a kernel driver owns it or may still
    /// take it, or its probe failed).
    BadIndex,
    /// The access word is neither `READ` nor `READ | WRITE`.
    BadAccess,
}

impl MmioMapError {
    /// `EINVAL`: the call cannot mean what it says.
    pub const fn errno(self) -> Errno {
        Errno::EINVAL
    }
}

/// `DOMAIN_MMIO_MAP`'s access word (`a1`) is `CapPerms` bits: READ maps the
/// window read-only, READ|WRITE maps it writable. Every other value is
/// refused, so the word can grow without reinterpreting a value already in use.
const ACCESS_READ: u64 = CapPerms::READ.bits() as u64;
const ACCESS_RW: u64 = CapPerms::RW.bits() as u64;

/// Can a capability carrying `perms` be honoured by a mapping?
///
/// A user mapping of device registers is always readable (a RISC-V leaf with W
/// and without R is reserved) and never executable, so the grant carries READ
/// and nothing beyond READ|WRITE.
const fn grant_fits(perms: CapPerms) -> bool {
    let bits = perms.bits();
    bits & !CapPerms::RW.bits() == 0 && bits & CapPerms::READ.bits() != 0
}

/// Topology-loader entry: grant `tid` a `Cap<Device>` over the device
/// `selector` names.
///
/// The capability's resource is the device's bus handle. `None` when the
/// selector does not read, no device matches it, the device has no window
/// ring 3 may map, `perms` is a grant no mapping could honour, or the
/// cap-table is full.
pub fn mmio_grant_cap(
    tid: u32,
    selector: &str,
    perms: CapPerms,
) -> Option<Cap<targets::MmioRegion>> {
    if !grant_fits(perms) {
        return None;
    }
    let handle = hwbus::resolve(selector)?;
    hwbus::user_window(handle)?;
    crate::cap_store::grant::<targets::MmioRegion>(tid, perms, handle)
}

/// Check `DOMAIN_MMIO_MAP`'s arguments: `handle` (`a0`) and `access` (`a1`).
///
/// Returns the handle as the capability resource to check, the window
/// `(base, size)` and whether the mapping is writable. The handle is
/// range-checked as the whole 64-bit register: narrowing it first would make
/// `1 << 32` name device 0.
pub fn mmio_resolve(handle: u64, access: u64) -> Result<(u32, (u64, u64), bool), MmioMapError> {
    let writable = match access {
        ACCESS_READ => false,
        ACCESS_RW => true,
        _ => return Err(MmioMapError::BadAccess),
    };
    if handle > u32::MAX as u64 {
        return Err(MmioMapError::BadIndex);
    }
    let handle = handle as u32;
    let window = hwbus::user_window(handle).ok_or(MmioMapError::BadIndex)?;
    Ok((handle, window, writable))
}

/// Book the mapping `DOMAIN_MMIO_MAP` is about to make for the device
/// `handle` names, once the capability check passed: the window to map, or
/// `None` when the device is no longer one ring 3 may map. Pairs with
/// [`mmio_unclaim`] when the mapping fails.
pub fn mmio_claim(handle: u32) -> Option<(u64, u64)> {
    hwbus::claim_user_window(handle)
}

/// Give back the booking of [`mmio_claim`] for a mapping that was not made.
pub fn mmio_unclaim(handle: u32) {
    hwbus::unclaim_user_window(handle)
}
