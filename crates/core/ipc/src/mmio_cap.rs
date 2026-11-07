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

/// The kernel's answer to "may ring 3 hold device `handle`'s registers
/// writable, though the device masters the bus": an IOMMU confines it, or
/// Kconfig `DMA_RING3_WITHOUT_IOMMU` accepts that its driver is kernel-trust
/// (the answer is the kernel's to print and record). Unset: no.
static WRITABLE_MASTER: azos_sync::SpinLock<Option<fn(u32) -> bool>> = azos_sync::SpinLock::new(None);

/// Install the kernel's answer ([`WRITABLE_MASTER`]). Boot.
pub fn set_writable_master_policy(f: fn(u32) -> bool) {
    *WRITABLE_MASTER.lock() = Some(f);
}

/// Why a master's registers were refused (`Rule::Ring3Dma`, the record's third word).
pub(crate) const WHY_WINDOW: u64 = 4;

/// May `tid` be given registers or ports that point device `handle`, a bus
/// master, at memory: only a device ring 3 may have (`ring3_device`) and only
/// where the kernel's policy says so ([`set_writable_master_policy`]); unset,
/// no. A refusal is recorded with `why`, and `range` (the ports asked for, or
/// 0).
pub(crate) fn master_window_ok(handle: u32, ring3_device: bool, tid: u32, range: u64, why: u64) -> bool {
    let policy = *WRITABLE_MASTER.lock();
    if ring3_device && policy.is_some_and(|f| f(handle)) {
        return true;
    }
    azos_decision::record(azos_decision::Rule::Ring3Dma, azos_decision::Verdict::Refuse, handle, [u64::from(tid), range, why]);
    false
}

/// May a grant carrying `perms` be minted for device `handle`: one with
/// `WRITE` on a device that masters the bus only where the kernel's policy
/// says so (writing such a device's registers points it at any memory, and
/// that is the DMA authority `DEVICE_DMA_MAP` refuses alone).
fn writable_ok(handle: u32, tid: u32, perms: CapPerms) -> bool {
    if !perms.contains(CapPerms::WRITE) || hwbus::may_master_bus(handle) != Some(true) || cfg!(feature = "writable-master-canary") {
        return true;
    }
    master_window_ok(handle, true, tid, 0, WHY_WINDOW)
}

/// Topology-loader entry: grant `tid` a `Cap<Device>` over the device
/// `selector` names.
///
/// The capability's resource is the device's bus handle. `None` when the
/// selector does not read, no device matches it, the device has no window
/// ring 3 may map, `perms` is a grant no mapping could honour, `perms`
/// carries `WRITE` on a device that masters the bus and the kernel's policy
/// refuses it ([`set_writable_master_policy`]), or the cap-table is full.
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
    if !writable_ok(handle, tid, perms) {
        return None;
    }
    crate::cap_store::grant::<targets::MmioRegion>(tid, perms, handle)
}

/// The interrupt line of the device `selector` names, for a topology row
/// `"irq.<selector>"`: the line the bus found for it, so a row names the
/// device and not the number a machine wired it to. `None` for a selector no
/// device matches, a device with no line known, one ring 3 may not have
/// (a kernel driver owns it or may still take it, as for its window), and a
/// line a device ring 3 may not have raises too (a shared line).
pub fn mmio_device_line(selector: &str) -> Option<u32> {
    let h = hwbus::resolve(selector)?;
    hwbus::user_window(h)?;
    let line = hwbus::line_of(h)?;
    (mmio_line_free(line) || cfg!(feature = "irq-selector-shared-canary")).then_some(line)
}

/// May a topology row `"irq.<N>"` mint line `line`: no device a kernel
/// driver owns, or may still take, raises it.
pub fn mmio_line_free(line: u32) -> bool {
    hwbus::line_free_for_user(line)
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
