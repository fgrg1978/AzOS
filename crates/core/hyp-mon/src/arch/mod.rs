// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The aarch64 low level of the monitor: the EL2 entry and vectors, the EL2
//! stage-1 identity map, the host stage-2 (F2) and the PSCI/SMC filter (F3).

pub mod entry;
pub mod mmu;
pub mod pin;
pub mod s2;
pub mod sync;
pub mod sysreg;

pub mod psci;

/// The monitor's own per-PE pool ceiling (a bound, not a detected count): a
/// hart id at or above it is parked rather than given a stack, the same shape
/// as the kernel's `MAX_HARTS`. Sized to the kernel's default `NR_CPUS`.
pub const MAX_PES: usize = 8;

/// 64 KiB EL2 stack per PE.
pub const STACK_SIZE: usize = 64 * 1024;

extern "C" {
    static _hyp_image_start: u8;
    static _hyp_image_end: u8;
}

/// The monitor image extent, as a physical range (identity-mapped, so a
/// PC-relative address is the PA), and the top of the permissive host stage-2.
/// The kernel narrows the RAM/MMIO ranges at the lock (F4); before then the
/// whole 40-bit IPA space is mapped identity with this one hole.
pub fn s2_hole() -> (u64, u64, u64) {
    let start = core::ptr::addr_of!(_hyp_image_start) as u64;
    let end = core::ptr::addr_of!(_hyp_image_end) as u64;
    (start, end - start, 1u64 << 40)
}
