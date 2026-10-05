// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cap<MmioRegion> — RFC-0043.
//!
//! A capability over device registers names an index into the board's MMIO
//! region table (`azos_drv_base::platform::hw::MMIO_REGIONS`), never an
//! address. The table fixes the base, the size and whether ring 3 may write,
//! so neither the topology nor the caller chooses any of the three.
//!
//! Two decisions live here, both pure so a host crate can compile this file
//! (`tests/host/topology-tests`):
//!
//! - [`mmio_grant_cap`], the topology minter: it refuses an index outside the
//!   table, and a grant no mapping could honour — without READ, with a bit
//!   beyond READ|WRITE, or with WRITE over a read-only region.
//! - [`mmio_resolve`], the argument check of `SYS_MMIO_MAP`
//!   (`crates/core/syscall/src/mmio.rs`): the index and access word a caller sent,
//!   turned into the table entry to map or the errno to return. The
//!   capability check follows it, in the syscall, against the index.
//!
//! Lives in `crates/core/ipc/` beside `gpio_cap.rs` for the same reason: the table
//! is in `azos_drv_base`, and `drivers → ipc` would be a Cargo cycle.

use crate::cap::{targets, Cap, CapPerms};
use azos_abi::error::Errno;
use azos_drv_base::platform::{mmio_region, MmioRegion};

/// Why `SYS_MMIO_MAP`'s arguments were refused, before any capability check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MmioMapError {
    /// The index is above `u32::MAX` or outside the board's table.
    BadIndex,
    /// The access word is neither `READ` nor `READ | WRITE`.
    BadAccess,
    /// `WRITE` asked of a read-only region.
    ReadOnly,
}

impl MmioMapError {
    /// `EINVAL` for an index or access word the call cannot mean, `EACCES` for
    /// WRITE on a read-only region.
    pub const fn errno(self) -> Errno {
        match self {
            Self::BadIndex | Self::BadAccess => Errno::EINVAL,
            Self::ReadOnly => Errno::EACCES,
        }
    }
}

/// `SYS_MMIO_MAP`'s access word (`a1`) is `CapPerms` bits: READ maps the region
/// read-only, READ|WRITE maps it writable. Every other value is refused, so
/// the word can grow without reinterpreting a value already in use.
const ACCESS_READ: u64 = CapPerms::READ.bits() as u64;
const ACCESS_RW: u64 = CapPerms::RW.bits() as u64;

/// Can a capability carrying `perms` over `region` be honoured by a mapping?
///
/// A user mapping of device registers is always readable (a RISC-V leaf with W
/// and without R is reserved) and never executable, so the grant carries READ
/// and nothing beyond READ|WRITE, and WRITE needs a writable region.
const fn grant_fits(region: MmioRegion, perms: CapPerms) -> bool {
    let bits = perms.bits();
    bits & !CapPerms::RW.bits() == 0
        && bits & CapPerms::READ.bits() != 0
        && (bits & CapPerms::WRITE.bits() == 0 || region.writable)
}

/// Topology-loader entry: grant `tid` a `Cap<MmioRegion>` over region `index`.
///
/// The capability's resource is the index. `None` when the index is outside
/// the board's table (every index, on a board whose table is empty), when
/// `perms` is a grant no mapping of that region could honour, or when the
/// cap-table is full.
pub fn mmio_grant_cap(
    tid: u32,
    index: u32,
    perms: CapPerms,
) -> Option<Cap<targets::MmioRegion>> {
    let region = mmio_region(index)?;
    if !grant_fits(region, perms) {
        return None;
    }
    crate::cap_store::grant::<targets::MmioRegion>(tid, perms, index)
}

/// Check `SYS_MMIO_MAP`'s arguments: `index` (`a0`) and `access` (`a1`).
///
/// Returns the index as the capability resource to check, the region, and
/// whether the mapping is writable. The index is range-checked as the whole
/// 64-bit register: narrowing it first would make `1 << 32` name region 0.
pub fn mmio_resolve(index: u64, access: u64) -> Result<(u32, MmioRegion, bool), MmioMapError> {
    let writable = match access {
        ACCESS_READ => false,
        ACCESS_RW => true,
        _ => return Err(MmioMapError::BadAccess),
    };
    if index > u32::MAX as u64 {
        return Err(MmioMapError::BadIndex);
    }
    let index = index as u32;
    let region = mmio_region(index).ok_or(MmioMapError::BadIndex)?;
    if writable && !region.writable {
        return Err(MmioMapError::ReadOnly);
    }
    Ok((index, region, writable))
}
